//! Adversarial CLI Tests for Milestone 3 Localhost Marketplace Testing Tools

use clap::Parser;
use quorum_cli::commands::buyer_pull::{run_buyer_pull, MarketplaceBuyerPullArgs};
use quorum_cli::commands::issue_cert::{run_issue_cert, MarketplaceIssueCertArgs};
use quorum_cli::{Cli, Commands};
use quorum_contract::marketplace::BuyerJurisdictionCertificate;
use std::path::PathBuf;
use tempfile::NamedTempFile;

#[test]
fn test_cli_issue_cert_with_127_0_0_1_and_crypto_signature() {
    let tmp = NamedTempFile::new().unwrap();
    let tmp_path = tmp.path().to_path_buf();

    let args = MarketplaceIssueCertArgs {
        buyer_id: "challenger-test-buyer".to_string(),
        legal_name: "Challenger Verification Lab".to_string(),
        country: "US".to_string(),
        lei: "549300CHALLENGER01".to_string(),
        egress_cidrs: vec!["127.0.0.1/32".to_string()],
        tpm_hash: None,
        authority_seed: None,
        validity_days: 90,
        out: Some(tmp_path.clone()),
        foci_clean: true,
        part202_clean: true,
        non_redistribution: true,
    };

    let cert = run_issue_cert(&args).expect("Certificate issuance should succeed");
    assert_eq!(cert.buyer_id, "challenger-test-buyer");
    assert_eq!(cert.authorized_egress_cidrs, vec!["127.0.0.1/32"]);
    assert!(!cert.issuer_ed25519_signature_hex.is_empty());

    // Verify cryptographic signature against standard test authority seed
    let default_seed = blake3::derive_key("QuorumRAG-Marketplace-AuthoritySeed-v1", &[0x42u8; 32]);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&default_seed);
    assert!(
        cert.verify_ed25519(&signing_key.verifying_key().to_bytes()),
        "Signature must verify against default test authority seed"
    );

    // Verify file content matches
    let content = std::fs::read_to_string(&tmp_path).unwrap();
    let file_cert: BuyerJurisdictionCertificate = serde_json::from_str(&content).unwrap();
    assert_eq!(file_cert.buyer_id, "challenger-test-buyer");
    assert_eq!(file_cert.authorized_egress_cidrs, vec!["127.0.0.1/32"]);
}

#[test]
fn test_cli_issue_cert_custom_seed_and_invalid_hex_handling() {
    // 1. Invalid hex seed length (must be 64 characters)
    let bad_len_args = MarketplaceIssueCertArgs {
        buyer_id: "bad-seed-buyer".to_string(),
        legal_name: "Lab".to_string(),
        country: "US".to_string(),
        lei: "LEI123".to_string(),
        egress_cidrs: vec!["127.0.0.1/32".to_string()],
        tpm_hash: None,
        authority_seed: Some("1234abcd".to_string()), // Too short
        validity_days: 30,
        out: None,
        foci_clean: true,
        part202_clean: true,
        non_redistribution: true,
    };
    let err_len = run_issue_cert(&bad_len_args);
    assert!(err_len.is_err());
    assert!(err_len.unwrap_err().to_string().contains("exactly 64 characters"));

    // 2. Invalid non-hex characters in seed
    let non_hex_args = MarketplaceIssueCertArgs {
        buyer_id: "non-hex-buyer".to_string(),
        legal_name: "Lab".to_string(),
        country: "US".to_string(),
        lei: "LEI123".to_string(),
        egress_cidrs: vec!["127.0.0.1/32".to_string()],
        tpm_hash: None,
        authority_seed: Some("zz".repeat(32)), // Invalid hex
        validity_days: 30,
        out: None,
        foci_clean: true,
        part202_clean: true,
        non_redistribution: true,
    };
    let err_hex = run_issue_cert(&non_hex_args);
    assert!(err_hex.is_err());
    assert!(err_hex.unwrap_err().to_string().contains("Invalid hex byte"));
}

#[tokio::test]
async fn test_cli_buyer_pull_negative_cert_file_validation() {
    // 1. Nonexistent cert file path must return clean error
    let args_missing_file = MarketplaceBuyerPullArgs {
        seller_endpoint: "http://127.0.0.1:3031".to_string(),
        cert_file: Some("nonexistent_cert_path_9999.json".to_string()),
        batch_id: None,
        tpm_hash: None,
        caller_ip: "127.0.0.1".to_string(),
        caller_asn: None,
        amount_paid_cents: 5000,
        out: PathBuf::from("dummy.jsonl"),
        auto_issue_cert: false,
    };
    let err_file = run_buyer_pull(&args_missing_file).await;
    assert!(err_file.is_err());

    // 2. Neither cert-file nor auto-issue enabled must fail immediately
    let args_no_cert = MarketplaceBuyerPullArgs {
        seller_endpoint: "http://127.0.0.1:3031".to_string(),
        cert_file: None,
        batch_id: None,
        tpm_hash: None,
        caller_ip: "127.0.0.1".to_string(),
        caller_asn: None,
        amount_paid_cents: 5000,
        out: PathBuf::from("dummy.jsonl"),
        auto_issue_cert: false,
    };
    let err_no_cert = run_buyer_pull(&args_no_cert).await;
    assert!(err_no_cert.is_err());
    assert!(err_no_cert.unwrap_err().to_string().contains("No certificate provided"));
}

#[test]
fn test_cli_subcommand_clap_parsing() {
    // Parse issue-cert with multiple egress CIDRs
    let cli = Cli::try_parse_from([
        "quorum-cli",
        "marketplace-issue-cert",
        "--buyer-id",
        "adv-buyer-42",
        "--egress-cidr",
        "127.0.0.1/32",
        "--egress-cidr",
        "10.0.0.0/16",
    ])
    .expect("Clap parse should succeed");

    match cli.command {
        Commands::MarketplaceIssueCert(args) => {
            assert_eq!(args.buyer_id, "adv-buyer-42");
            assert_eq!(args.egress_cidrs, vec!["127.0.0.1/32", "10.0.0.0/16"]);
        }
        _ => panic!("Expected MarketplaceIssueCert variant"),
    }
}
