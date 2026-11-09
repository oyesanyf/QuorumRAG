use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use clap::Args;
use quorum_contract::marketplace::{BuyerJurisdictionCertificate, EscrowReceiptToken, SanitizedTrainingRecord};
use reqwest::header::{HeaderMap, HeaderValue};

#[derive(Args, Debug, Clone)]
pub struct MarketplaceBuyerPullArgs {
    /// Seller daemon base URL
    #[arg(long = "seller-endpoint", visible_alias = "daemon-url", default_value = "http://127.0.0.1:3031")]
    pub seller_endpoint: String,

    /// Path to BuyerJurisdictionCertificate JSON file or raw JSON string
    #[arg(long = "cert-file", visible_alias = "cert")]
    pub cert_file: Option<String>,

    /// Specific batch ID to pull (queries latest preview if omitted)
    #[arg(long = "batch-id")]
    pub batch_id: Option<String>,

    /// Hardware TPM 2.0 endorsement key BLAKE3 hash to present in header
    #[arg(long)]
    pub tpm_hash: Option<String>,

    /// Caller IP to present in X-Quorum-Caller-IP header (must match cert egress CIDR)
    #[arg(long, default_value = "127.0.0.1")]
    pub caller_ip: String,

    /// Caller ASN to present in X-Quorum-Caller-ASN header
    #[arg(long)]
    pub caller_asn: Option<u32>,

    /// Amount in cents to pay for escrow unlock
    #[arg(long, default_value_t = 5000)]
    pub amount_paid_cents: u64,

    /// Output file path for downloaded watermarked JSONL data
    #[arg(short, long, default_value = "downloaded_batch.jsonl")]
    pub out: PathBuf,

    /// Automatically issue a 127.0.0.1/32 test certificate if --cert-file is omitted
    #[arg(long, default_value_t = true)]
    pub auto_issue_cert: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BuyerPullSummary {
    pub batch_id: String,
    pub records_downloaded: usize,
    pub total_bytes: usize,
    pub buyer_id: String,
    pub watermark_verified: bool,
    pub output_path: String,
}

pub async fn run_buyer_pull(args: &MarketplaceBuyerPullArgs) -> Result<BuyerPullSummary> {
    let client = reqwest::Client::new();
    let base_url = args.seller_endpoint.trim_end_matches('/');

    // 1. Obtain BuyerJurisdictionCertificate
    let cert: BuyerJurisdictionCertificate = if let Some(ref cert_source) = args.cert_file {
        if Path::new(cert_source).exists() {
            let data = std::fs::read_to_string(cert_source)
                .with_context(|| format!("Failed to read certificate file at {}", cert_source))?;
            serde_json::from_str(&data)
                .with_context(|| format!("Failed to parse certificate JSON from {}", cert_source))?
        } else {
            serde_json::from_str(cert_source)
                .context("Failed to parse raw certificate JSON string")?
        }
    } else if args.auto_issue_cert {
        println!("Requesting localhost test certificate from {}/api/v1/marketplace/test/issue-cert...", base_url);
        let issue_req = serde_json::json!({
            "buyer_id": "localhost-dev-buyer",
            "legal_entity_name": "Localhost Sovereign AI Lab",
            "authorized_egress_cidrs": [format!("{}/32", args.caller_ip)],
        });
        let resp = client
            .post(format!("{}/api/v1/marketplace/test/issue-cert", base_url))
            .header("X-Quorum-Caller-IP", &args.caller_ip)
            .json(&issue_req)
            .send()
            .await
            .context("Failed to contact daemon to issue test certificate")?;

        if !resp.status().is_success() {
            let err_text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Failed to auto-issue test certificate: {}", err_text);
        }

        let resp_json: serde_json::Value = resp.json().await.context("Failed to parse test cert JSON response")?;
        let cert_val = resp_json
            .get("cert")
            .or_else(|| resp_json.get("certificate"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        serde_json::from_value(cert_val)
            .context("Response did not contain valid BuyerJurisdictionCertificate in 'cert' or 'certificate' field")?
    } else {
        anyhow::bail!("No certificate provided (--cert-file) and --auto-issue-cert is false");
    };

    println!("Verified sovereign buyer certificate: buyer_id='{}', egress_cidrs={:?}", cert.buyer_id, cert.authorized_egress_cidrs);

    // 2. Discover or verify batch ID
    let batch_id = if let Some(ref bid) = args.batch_id {
        bid.clone()
    } else {
        let prev_resp = client
            .get(format!("{}/api/v1/marketplace/preview", base_url))
            .header("X-Quorum-Caller-IP", &args.caller_ip)
            .send()
            .await
            .context("Failed to fetch marketplace preview")?;

        if !prev_resp.status().is_success() {
            let err_text = prev_resp.text().await.unwrap_or_default();
            anyhow::bail!("Failed to fetch preview for batch discovery: {}", err_text);
        }

        let prev_json: serde_json::Value = prev_resp.json().await.context("Failed to parse preview JSON")?;
        prev_json["manifest"]["batch_id"]
            .as_str()
            .or_else(|| prev_json["batch_id"].as_str())
            .map(|s| s.to_string())
            .context("No active batch found in marketplace preview. Harvest a batch first.")?
    };

    println!("Targeting marketplace batch: {}", batch_id);

    // 3. Request Escrow Unlock Token
    let tpm_hash = args
        .tpm_hash
        .clone()
        .unwrap_or_else(|| cert.bound_tpm_pubkey_blake3.clone());

    let mut unlock_headers = HeaderMap::new();
    let caller_ip_hdr = HeaderValue::from_str(&args.caller_ip)
        .with_context(|| format!("Invalid X-Quorum-Caller-IP header value: '{}'", args.caller_ip))?;
    unlock_headers.insert("X-Quorum-Caller-IP", caller_ip_hdr);

    let tpm_hash_hdr = HeaderValue::from_str(&tpm_hash)
        .with_context(|| format!("Invalid X-Quorum-TPM-Pubkey-Blake3 header value: '{}'", tpm_hash))?;
    unlock_headers.insert("X-Quorum-TPM-Pubkey-Blake3", tpm_hash_hdr);

    if let Some(asn) = args.caller_asn {
        let asn_str = asn.to_string();
        let asn_hdr = HeaderValue::from_str(&asn_str)
            .with_context(|| format!("Invalid X-Quorum-Caller-ASN header value: '{}'", asn_str))?;
        unlock_headers.insert("X-Quorum-Caller-ASN", asn_hdr);
    }

    let unlock_payload = serde_json::json!({
        "batch_id": batch_id,
        "buyer_cert": cert,
        "amount_paid_cents": args.amount_paid_cents
    });

    println!("Submitting commit-and-reveal escrow unlock to {}/api/v1/marketplace/unlock...", base_url);
    let unlock_resp = client
        .post(format!("{}/api/v1/marketplace/unlock", base_url))
        .headers(unlock_headers.clone())
        .json(&unlock_payload)
        .send()
        .await
        .context("Failed to submit escrow unlock request")?;

    let unlock_status = unlock_resp.status();
    if !unlock_status.is_success() {
        let err_text = unlock_resp.text().await.unwrap_or_default();
        anyhow::bail!("Escrow unlock failed (status {}): {}", unlock_status, err_text);
    }

    let unlock_json: serde_json::Value = unlock_resp.json().await.context("Failed to parse unlock JSON response")?;
    let receipt: EscrowReceiptToken = serde_json::from_value(unlock_json["receipt_token"].clone())
        .context("Failed to deserialize EscrowReceiptToken from unlock response")?;

    println!("Escrow unlocked! Receipt token ID: {}, expires at: {}", receipt.receipt_id, receipt.expires_unix_secs);

    // 4. Download Watermarked Dataset
    let download_payload = serde_json::json!({
        "batch_id": batch_id,
        "buyer_cert": cert,
        "receipt_token": receipt
    });

    println!("Downloading watermarked dataset from {}/api/v1/marketplace/download...", base_url);
    let dl_resp = client
        .post(format!("{}/api/v1/marketplace/download", base_url))
        .headers(unlock_headers)
        .json(&download_payload)
        .send()
        .await
        .context("Failed to download dataset")?;

    let dl_status = dl_resp.status();
    if !dl_status.is_success() {
        let err_text = dl_resp.text().await.unwrap_or_default();
        anyhow::bail!("Download failed (status {}): {}", dl_status, err_text);
    }

    let dl_text = dl_resp.text().await.context("Failed to read downloaded dataset stream")?;
    let total_bytes = dl_text.as_bytes().len();

    let mut record_count = 0usize;
    let mut watermarked_found = false;

    for line in dl_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<SanitizedTrainingRecord>(trimmed) {
            record_count += 1;
            if rec.chosen_response.contains(&cert.buyer_id)
                || rec.rlm_trajectory.iter().any(|s| s.abstracted_takeaway.contains(&cert.buyer_id))
            {
                watermarked_found = true;
            }
        }
    }

    if let Some(parent) = args.out.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&args.out, &dl_text)
        .with_context(|| format!("Failed to write downloaded dataset to {:?}", args.out))?;

    let summary = BuyerPullSummary {
        batch_id: batch_id.clone(),
        records_downloaded: record_count,
        total_bytes,
        buyer_id: cert.buyer_id.clone(),
        watermark_verified: watermarked_found,
        output_path: args.out.display().to_string(),
    };

    println!("\n=== Marketplace Buyer Pull Successful ===");
    println!("Batch ID:           {}", summary.batch_id);
    println!("Records Downloaded: {}", summary.records_downloaded);
    println!("Total Bytes:        {} bytes", summary.total_bytes);
    println!("Buyer ID:           {}", summary.buyer_id);
    println!("Watermark Verified: {}", summary.watermark_verified);
    println!("Output File:        {}", summary.output_path);

    Ok(summary)
}
