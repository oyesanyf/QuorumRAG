use std::path::PathBuf;
use anyhow::{Context, Result};
use clap::Args;
use chrono::Utc;
use quorum_contract::marketplace::BuyerJurisdictionCertificate;

#[derive(Args, Debug, Clone)]
pub struct MarketplaceIssueCertArgs {
    /// Unique buyer identifier
    #[arg(long, default_value = "localhost-dev-buyer")]
    pub buyer_id: String,

    /// Legal entity name of the buyer organization
    #[arg(long, visible_alias = "buyer-org", default_value = "Localhost Sovereign AI Lab")]
    pub legal_name: String,

    /// ISO 3166-1 alpha-2 country of incorporation
    #[arg(long, default_value = "US")]
    pub country: String,

    /// Verified LEI, DUNS, or SAM.gov CAGE code
    #[arg(long, default_value = "549300USSOVEREIGN99")]
    pub lei: String,

    /// Authorized corporate egress CIDRs (can be repeated, default: 127.0.0.1/32)
    #[arg(long = "egress-cidr", visible_alias = "cidr", default_values_t = vec!["127.0.0.1/32".to_string()])]
    pub egress_cidrs: Vec<String>,

    /// BLAKE3 hex hash of the bound hardware TPM 2.0 endorsement key
    #[arg(long)]
    pub tpm_hash: Option<String>,

    /// 32-byte Ed25519 authority private signing seed in hex (defaults to standard test authority seed)
    #[arg(long)]
    pub authority_seed: Option<String>,

    /// Validity period in days
    #[arg(long, default_value_t = 365)]
    pub validity_days: i64,

    /// Output file path to write certificate JSON (prints to stdout if omitted)
    #[arg(short, long)]
    pub out: Option<PathBuf>,

    /// Attest FOCI / UBO verified clean (<10% foreign adversary control)
    #[arg(long, default_value_t = true)]
    pub foci_clean: bool,

    /// Attest DOJ 28 CFR Part 202 non-covered person
    #[arg(long, default_value_t = true)]
    pub part202_clean: bool,

    /// Accept binding non-redistribution covenant
    #[arg(long, default_value_t = true)]
    pub non_redistribution: bool,
}

fn parse_hex_32(s: &str) -> Result<[u8; 32]> {
    let clean = s.trim();
    if clean.len() != 64 {
        anyhow::bail!("Hex string must be exactly 64 characters (32 bytes)");
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let chunk = &clean[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(chunk, 16)
            .map_err(|e| anyhow::anyhow!("Invalid hex byte '{}': {}", chunk, e))?;
    }
    Ok(out)
}

pub fn run_issue_cert(args: &MarketplaceIssueCertArgs) -> Result<BuyerJurisdictionCertificate> {
    let now = Utc::now().timestamp();
    let expires = now + (args.validity_days.max(1) * 86400);

    let authority_seed: [u8; 32] = match &args.authority_seed {
        Some(seed_hex) => parse_hex_32(seed_hex)?,
        None => blake3::derive_key("QuorumRAG-Marketplace-AuthoritySeed-v1", &[0x42u8; 32]),
    };

    let bound_tpm = args
        .tpm_hash
        .clone()
        .unwrap_or_else(|| blake3::hash(b"localhost-dev-tpm-ek-primary").to_hex().to_string());

    let mut cert = BuyerJurisdictionCertificate {
        buyer_id: args.buyer_id.clone(),
        legal_entity_name: args.legal_name.clone(),
        incorporation_country_iso: args.country.to_uppercase(),
        lei_or_duns_id: args.lei.clone(),
        authorized_egress_cidrs: args.egress_cidrs.clone(),
        bound_tpm_pubkey_blake3: bound_tpm,
        foci_ubo_verified_clean: args.foci_clean,
        doj_part202_non_covered_person: args.part202_clean,
        non_redistribution_covenant_accepted: args.non_redistribution,
        expires_unix_secs: expires,
        issuer_ed25519_signature_hex: String::new(),
    };

    cert.sign_ed25519(&authority_seed)
        .map_err(|e| anyhow::anyhow!("Failed to sign BuyerJurisdictionCertificate: {}", e))?;

    let json_str = serde_json::to_string_pretty(&cert)
        .context("Failed to serialize BuyerJurisdictionCertificate to JSON")?;

    if let Some(ref out_path) = args.out {
        if let Some(parent) = out_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(out_path, &json_str)
            .with_context(|| format!("Failed to write certificate to {:?}", out_path))?;
        println!("Successfully issued sovereign buyer certificate to {:?}", out_path);
    } else {
        println!("{}", json_str);
    }

    Ok(cert)
}
