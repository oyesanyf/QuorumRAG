use clap::Parser;
use quorum_cli::commands::buyer_pull::{run_buyer_pull, MarketplaceBuyerPullArgs};
use quorum_cli::commands::issue_cert::{run_issue_cert, MarketplaceIssueCertArgs};
use quorum_cli::{Cli, Commands};
use quorum_contract::marketplace::BuyerJurisdictionCertificate;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn test_cli_marketplace_issue_cert_defaults() {
    let args = MarketplaceIssueCertArgs {
        buyer_id: "localhost-dev-buyer".to_string(),
        legal_name: "Localhost Sovereign AI Lab".to_string(),
        country: "US".to_string(),
        lei: "549300USSOVEREIGN99".to_string(),
        egress_cidrs: vec!["127.0.0.1/32".to_string()],
        tpm_hash: None,
        authority_seed: None,
        validity_days: 365,
        out: None,
        foci_clean: true,
        part202_clean: true,
        non_redistribution: true,
    };

    let cert = run_issue_cert(&args).expect("Should successfully issue cert");
    assert_eq!(cert.buyer_id, "localhost-dev-buyer");
    assert_eq!(cert.legal_entity_name, "Localhost Sovereign AI Lab");
    assert_eq!(cert.incorporation_country_iso, "US");
    assert_eq!(cert.authorized_egress_cidrs, vec!["127.0.0.1/32"]);
    assert!(cert.foci_ubo_verified_clean);
    assert!(cert.doj_part202_non_covered_person);
    assert!(cert.non_redistribution_covenant_accepted);
    assert!(!cert.issuer_ed25519_signature_hex.is_empty());
    assert!(!cert.bound_tpm_pubkey_blake3.is_empty());

    // Verify cryptographic signature against standard test authority seed
    let default_seed = blake3::derive_key("QuorumRAG-Marketplace-AuthoritySeed-v1", &[0x42u8; 32]);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&default_seed);
    assert!(cert.verify_ed25519(&signing_key.verifying_key().to_bytes()));
}

#[test]
fn test_cli_marketplace_issue_cert_file_output() {
    let tmp = NamedTempFile::new().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    let args = MarketplaceIssueCertArgs {
        buyer_id: "test-eval-org".to_string(),
        legal_name: "Evaluation Labs Inc".to_string(),
        country: "US".to_string(),
        lei: "TESTLEI123456789".to_string(),
        egress_cidrs: vec!["127.0.0.1/32".to_string(), "10.0.0.0/8".to_string()],
        tpm_hash: Some("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234".to_string()),
        authority_seed: None,
        validity_days: 90,
        out: Some(tmp_path.clone()),
        foci_clean: true,
        part202_clean: true,
        non_redistribution: true,
    };

    let cert = run_issue_cert(&args).expect("Should issue cert to file");
    assert_eq!(cert.authorized_egress_cidrs.len(), 2);

    let file_content = std::fs::read_to_string(&tmp_path).expect("File must exist");
    let loaded_cert: BuyerJurisdictionCertificate =
        serde_json::from_str(&file_content).expect("JSON must parse");
    assert_eq!(loaded_cert.buyer_id, "test-eval-org");
    assert_eq!(loaded_cert.authorized_egress_cidrs, vec!["127.0.0.1/32", "10.0.0.0/8"]);
}

#[test]
fn test_cli_clap_arg_parsing() {
    let parsed = Cli::try_parse_from([
        "quorum-cli",
        "marketplace-issue-cert",
        "--buyer-id",
        "cli-test-buyer",
        "--buyer-org",
        "CLI Test Org",
        "--egress-cidr",
        "127.0.0.1/32",
        "--validity-days",
        "180",
    ])
    .expect("Clap parse should succeed");

    match parsed.command {
        Commands::MarketplaceIssueCert(args) => {
            assert_eq!(args.buyer_id, "cli-test-buyer");
            assert_eq!(args.legal_name, "CLI Test Org");
            assert_eq!(args.egress_cidrs, vec!["127.0.0.1/32"]);
            assert_eq!(args.validity_days, 180);
        }
        _ => panic!("Expected MarketplaceIssueCert variant"),
    }

    let parsed_pull = Cli::try_parse_from([
        "quorum-cli",
        "marketplace-buyer-pull",
        "--seller-endpoint",
        "http://127.0.0.1:3031",
        "--batch-id",
        "batch-fixed-001",
        "--out",
        "custom_out.jsonl",
    ])
    .expect("Clap pull parse should succeed");

    match parsed_pull.command {
        Commands::MarketplaceBuyerPull(args) => {
            assert_eq!(args.seller_endpoint, "http://127.0.0.1:3031");
            assert_eq!(args.batch_id, Some("batch-fixed-001".to_string()));
            assert_eq!(args.out.to_string_lossy(), "custom_out.jsonl");
        }
        _ => panic!("Expected MarketplaceBuyerPull variant"),
    }
}

/// Adversarial Test 1: Invalid server URL / unreachable daemon endpoint
#[tokio::test]
async fn test_adversarial_buyer_pull_invalid_server_url() {
    let tmp_out = NamedTempFile::new().unwrap();
    let tmp_path = tmp_out.path().to_path_buf();

    let args = MarketplaceBuyerPullArgs {
        seller_endpoint: "http://127.0.0.1:1".to_string(),
        cert_file: None,
        batch_id: None,
        tpm_hash: None,
        caller_ip: "127.0.0.1".to_string(),
        caller_asn: None,
        amount_paid_cents: 5000,
        out: tmp_path,
        auto_issue_cert: true,
    };

    let result = run_buyer_pull(&args).await;
    assert!(result.is_err(), "run_buyer_pull must fail when server URL is unreachable");
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("Failed to contact daemon to issue test certificate")
            || err_msg.contains("connect"),
        "Error message must indicate connection failure, got: {}",
        err_msg
    );
}

/// Adversarial Test 2: Missing batch ID in marketplace preview
#[tokio::test]
async fn test_adversarial_buyer_pull_missing_batch_id() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let issue_args = MarketplaceIssueCertArgs {
        buyer_id: "localhost-dev-buyer".to_string(),
        legal_name: "Localhost Sovereign AI Lab".to_string(),
        country: "US".to_string(),
        lei: "549300USSOVEREIGN99".to_string(),
        egress_cidrs: vec!["127.0.0.1/32".to_string()],
        tpm_hash: None,
        authority_seed: None,
        validity_days: 365,
        out: None,
        foci_clean: true,
        part202_clean: true,
        non_redistribution: true,
    };
    let cert = run_issue_cert(&issue_args).expect("Should issue valid test cert");
    let cert_json = serde_json::to_string(&cert).expect("Serialize cert");

    // Empty preview manifest with NO active batch_id
    let empty_preview = "{\"manifest\":{},\"status\":\"empty\"}".to_string();
    let preview_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        empty_preview.len(),
        empty_preview
    );

    tokio::spawn(async move {
        // Connection 1: /api/v1/marketplace/preview
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(preview_resp.as_bytes()).await;
        }
    });

    let tmp_out = NamedTempFile::new().unwrap();
    let tmp_path = tmp_out.path().to_path_buf();

    let args = MarketplaceBuyerPullArgs {
        seller_endpoint: format!("http://127.0.0.1:{}", port),
        cert_file: Some(cert_json),
        batch_id: None, // Missing batch_id triggers preview query
        tpm_hash: None,
        caller_ip: "127.0.0.1".to_string(),
        caller_asn: None,
        amount_paid_cents: 5000,
        out: tmp_path,
        auto_issue_cert: false,
    };

    let result = run_buyer_pull(&args).await;
    assert!(result.is_err(), "Must fail when no active batch ID exists");
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("No active batch found in marketplace preview. Harvest a batch first."),
        "Error message must specify batch discovery failure, got: {}",
        err_msg
    );
}

/// Adversarial Test 3: Corrupted token receipt on unlock or download rejection
#[tokio::test]
async fn test_adversarial_buyer_pull_corrupted_token_receipt() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let issue_args = MarketplaceIssueCertArgs {
        buyer_id: "localhost-dev-buyer".to_string(),
        legal_name: "Localhost Sovereign AI Lab".to_string(),
        country: "US".to_string(),
        lei: "549300USSOVEREIGN99".to_string(),
        egress_cidrs: vec!["127.0.0.1/32".to_string()],
        tpm_hash: None,
        authority_seed: None,
        validity_days: 365,
        out: None,
        foci_clean: true,
        part202_clean: true,
        non_redistribution: true,
    };
    let cert = run_issue_cert(&issue_args).expect("Should issue valid test cert");
    let cert_json = serde_json::to_string(&cert).expect("Serialize cert");

    // Corrupted receipt token (invalid MAC signature)
    let corrupted_unlock_body = serde_json::json!({
        "status": "unlocked",
        "receipt_token": {
            "receipt_id": "rcpt-corrupt-001",
            "batch_id": "batch-adversarial-01",
            "batch_merkle_root_blake3": "0000000000000000000000000000000000000000000000000000000000000000",
            "buyer_id": "localhost-dev-buyer",
            "bound_tpm_pubkey_blake3": "0000000000000000000000000000000000000000000000000000000000000000",
            "amount_paid_cents": 5000,
            "issued_unix_secs": 1000,
            "expires_unix_secs": 9999999999i64,
            "keyed_blake3_mac_hex": "deadbeefcafebabedeadbeefcafebabe00000000000000000000000000000000"
        }
    })
    .to_string();

    let unlock_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        corrupted_unlock_body.len(),
        corrupted_unlock_body
    );

    // Download endpoint rejects corrupted token with 403 Forbidden
    let forbidden_body = "{\"error\":\"EscrowReceiptToken keyed BLAKE3 MAC verification failed\"}".to_string();
    let dl_forbidden_resp = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        forbidden_body.len(),
        forbidden_body
    );

    tokio::spawn(async move {
        // Connection 1: Unlock endpoint returns corrupted receipt token
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(unlock_resp.as_bytes()).await;
        }

        // Connection 2: Download endpoint rejects with 403
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(dl_forbidden_resp.as_bytes()).await;
        }
    });

    let tmp_out = NamedTempFile::new().unwrap();
    let tmp_path = tmp_out.path().to_path_buf();

    let args = MarketplaceBuyerPullArgs {
        seller_endpoint: format!("http://127.0.0.1:{}", port),
        cert_file: Some(cert_json),
        batch_id: Some("batch-adversarial-01".to_string()),
        tpm_hash: None,
        caller_ip: "127.0.0.1".to_string(),
        caller_asn: None,
        amount_paid_cents: 5000,
        out: tmp_path,
        auto_issue_cert: false,
    };

    let result = run_buyer_pull(&args).await;
    assert!(result.is_err(), "Must fail when receipt token is corrupted / download forbidden");
    let err_msg = format!("{:#}", result.unwrap_err());
    assert!(
        err_msg.contains("Download failed (status 403 Forbidden)")
            || err_msg.contains("keyed BLAKE3 MAC verification failed"),
        "Error message must specify download 403 failure, got: {}",
        err_msg
    );
}
