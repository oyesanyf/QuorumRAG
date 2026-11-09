//! Empirical Adversarial Challenge Test Suite for Milestone 3
//! (Challenger 1 — Localhost Marketplace Testing Tools & Synthetic Gate)
//!
//! Stress-tests:
//! 1. `quorum-cli marketplace-buyer-pull` pull against seller endpoint & JSON schema consistency bug reproduction
//! 2. Layer 4 egress CIDR validation against `127.0.0.1` and negative tests (invalid CIDRs, spoofed caller IPs, missing signatures)
//! 3. 4-Stage `synthetic_gate`: low burstiness text, synthetic PDF producers, zero-width watermarks, 27 AI clichés, and nonce replay

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use quorum_contract::marketplace::{
    BuyerJurisdictionCertificate, EscrowReceiptToken, SanitizedTrainingRecord,
};
use quorum_coordinator::{
    cidr_contains_ip, is_blocked_foreign_adversary_ip, is_high_risk_datacenter_or_proxy_asn,
    verify_us_sovereign_buyer_against_domestic_evasion,
};
use quorum_daemon::handlers::synthetic_gate::{
    compute_mattr, compute_shannon_entropy, evaluate_stage1_statistics,
    inspect_file_provenance, is_invisible_watermark_char, scrub_and_scan_stage3_lexical,
    HumanTelemetryGuard, SyntheticGateConfig, KNOWN_SYNTHETIC_PDF_PRODUCERS,
    SYNTHETIC_CLICHE_PATTERNS,
};
use quorum_daemon::{build_router, DaemonState};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tempfile::{tempdir, TempDir};
use tower::ServiceExt;

async fn setup_test_app() -> (axum::Router, Arc<DaemonState>, TempDir) {
    let temp_dir = tempdir().expect("tempdir");
    let data_dir = temp_dir.path().to_path_buf();

    let storage_config = quorum_storage::StorageConfig::new(data_dir.clone());
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(storage_config)
            .await
            .expect("storage open"),
    );
    let classifier = Arc::new(quorum_classifier::FileTypeClassifier::new());
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> =
        Arc::new(quorum_contract::DeterministicOfflineEngine::new());
    let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
    let ingest_config = quorum_ingest::IngestConfig::default();

    let reindex_worker = Arc::new(quorum_ingest::ReindexWorker::new(
        ingest_config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    ));

    let drift_healer = Arc::new(quorum_ingest::DriftHealer::new(
        ingest_config.clone(),
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
        Arc::clone(&dedup),
    ));

    let node_seed = [0x42u8; 32];
    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(
            quorum_coordinator::PeerAclManager::default(),
        )),
        quorum_coordinator::CoordinatorConfig::default(),
        node_seed,
        "12D3KooWSovereignNodePrimary".to_string(),
    ));

    let coordinator = Arc::new(quorum_coordinator::QueryCoordinator::new(
        coordinator_engine,
        quorum_coordinator::CoordinatorConfig::default(),
    ));

    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    let state = Arc::new(DaemonState {
        start_time: Instant::now(),
        storage,
        coordinator,
        reindex_worker,
        drift_healer,
        classifier,
        embedder,
        dedup,
        swarm_handle: None,
        ingest_config,
        default_model_family: quorum_coordinator::SynthesisModelFamily::AutoFusion,
        port: 3031,
        host: "127.0.0.1".to_string(),
        data_dir,
        shutdown_notify,
        in_flight_queries: Arc::new(quorum_daemon::InFlightQueryRegistry::new()),
        sessions: quorum_daemon::ChatSessionRegistry::new(),
    });

    let router = build_router(Arc::clone(&state));
    (router, state, temp_dir)
}

async fn read_body_bytes(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .expect("collect body")
        .to_vec()
}

async fn read_body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = read_body_bytes(resp).await;
    serde_json::from_slice(&bytes).expect("valid json response")
}

// ---------------------------------------------------------------------------
// TEST 1: quorum-cli marketplace-buyer-pull schema check & bug reproduction
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_challenge_buyer_pull_auto_issue_cert_schema_key_bug() {
    let (app, _state, _td) = setup_test_app().await;

    // Hit POST /api/v1/marketplace/test/issue-cert
    let issue_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/test/issue-cert")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "buyer_id": "localhost-test-buyer",
                        "egress_cidr": "127.0.0.1/32"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(issue_res.status(), StatusCode::OK);
    let resp_json = read_body_json(issue_res).await;

    // EMPIRICAL DUAL-KEY REMEDIATION CONFIRMATION:
    // Verify both "cert" and "certificate" fields deserialize cleanly:
    assert!(
        !resp_json["cert"].is_null(),
        "Remediated: resp_json['cert'] is now populated for CLI/UI compatibility"
    );
    assert!(
        !resp_json["certificate"].is_null(),
        "resp_json['certificate'] is preserved for schema contract"
    );

    // Querying resp_json["cert"] succeeds:
    let parse_cert_field = serde_json::from_value::<BuyerJurisdictionCertificate>(resp_json["cert"].clone());
    assert!(
        parse_cert_field.is_ok(),
        "Querying 'cert' field must now succeed"
    );

    // Querying resp_json["certificate"] also succeeds:
    let parse_certificate_field =
        serde_json::from_value::<BuyerJurisdictionCertificate>(resp_json["certificate"].clone());
    assert!(
        parse_certificate_field.is_ok(),
        "Querying 'certificate' field succeeds"
    );
}

// ---------------------------------------------------------------------------
// TEST 2: Layer 4 Egress CIDR Validation, Spoofed IPs & Negative Scenarios
// ---------------------------------------------------------------------------
#[test]
fn test_challenge_cidr_contains_ip_adversarial_inputs() {
    // 1. Positive matches
    assert!(cidr_contains_ip("127.0.0.1/32", "127.0.0.1".parse().unwrap()));
    assert!(cidr_contains_ip("10.0.0.0/8", "10.254.1.2".parse().unwrap()));
    assert!(cidr_contains_ip("192.168.0.0/16", "192.168.1.100".parse().unwrap()));
    assert!(cidr_contains_ip("::1/128", "::1".parse().unwrap()));
    assert!(cidr_contains_ip("2001:db8::/32", "2001:db8:dead:beef::1".parse().unwrap()));

    // 2. Negative / Non-matching
    assert!(!cidr_contains_ip("127.0.0.1/32", "127.0.0.2".parse().unwrap()));
    assert!(!cidr_contains_ip("10.0.0.0/8", "11.0.0.1".parse().unwrap()));
    assert!(!cidr_contains_ip("192.168.1.0/24", "192.168.2.1".parse().unwrap()));

    // 3. Adversarial / Malformed CIDRs must fail closed (return false, never panic)
    assert!(!cidr_contains_ip("999.999.999.999/32", "127.0.0.1".parse().unwrap()));
    assert!(!cidr_contains_ip("127.0.0.1/33", "127.0.0.1".parse().unwrap()));
    assert!(!cidr_contains_ip("127.0.0.1/-1", "127.0.0.1".parse().unwrap()));
    assert!(!cidr_contains_ip("127.0.0.1/abc", "127.0.0.1".parse().unwrap()));
    assert!(!cidr_contains_ip("", "127.0.0.1".parse().unwrap()));
    assert!(!cidr_contains_ip("not-a-cidr", "127.0.0.1".parse().unwrap()));
    assert!(!cidr_contains_ip("127.0.0.1/99999999999999999", "127.0.0.1".parse().unwrap()));
    assert!(!cidr_contains_ip("::1/129", "::1".parse().unwrap()));
    assert!(!cidr_contains_ip("::1/-5", "::1".parse().unwrap()));
}

#[test]
fn test_challenge_domestic_evasion_layer4_and_spoofing() {
    let auth_seed = [0x55u8; 32];
    let tpm_hash = blake3::hash(b"localhost-tpm").to_hex().to_string();

    let mut cert = BuyerJurisdictionCertificate {
        buyer_id: "eval-buyer-01".to_string(),
        legal_entity_name: "Eval Org".to_string(),
        incorporation_country_iso: "US".to_string(),
        lei_or_duns_id: "549300USSOVEREIGN99".to_string(),
        authorized_egress_cidrs: vec!["127.0.0.1/32".to_string()],
        bound_tpm_pubkey_blake3: tpm_hash.clone(),
        foci_ubo_verified_clean: true,
        doj_part202_non_covered_person: true,
        non_redistribution_covenant_accepted: true,
        expires_unix_secs: 1_950_000_000,
        issuer_ed25519_signature_hex: String::new(),
    };
    cert.sign_ed25519(&auth_seed).unwrap();
    let auth_vk = SigningKey::from_bytes(&auth_seed).verifying_key().to_bytes();
    let allowed_us = vec!["US".to_string()];
    let now = 1_700_000_000i64;

    // 1. Caller IP 127.0.0.1 matches pinned CIDR 127.0.0.1/32
    let caller_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let ok_res = verify_us_sovereign_buyer_against_domestic_evasion(
        caller_ip,
        &[],
        None,
        Some(&tpm_hash),
        &cert,
        &auth_vk,
        &allowed_us,
        true,
        now,
    );
    assert!(ok_res.is_ok());

    // 2. Caller IP 127.0.0.2 does NOT match pinned 127.0.0.1/32 -> Layer 4 reject
    let spoof_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let err_res = verify_us_sovereign_buyer_against_domestic_evasion(
        spoof_ip,
        &[],
        None,
        Some(&tpm_hash),
        &cert,
        &auth_vk,
        &allowed_us,
        true,
        now,
    );
    assert!(err_res.is_err());
    assert!(err_res.unwrap_err().contains("Layer 4"));

    // 3. Caller IP 127.0.0.1, but forwarded proxy hop 203.0.113.50 is outside pinned CIDR -> Layer 4 reject
    let hop_ip: IpAddr = "203.0.113.50".parse().unwrap();
    let hop_err = verify_us_sovereign_buyer_against_domestic_evasion(
        caller_ip,
        &[hop_ip],
        None,
        Some(&tpm_hash),
        &cert,
        &auth_vk,
        &allowed_us,
        true,
        now,
    );
    assert!(hop_err.is_err());
    assert!(hop_err.unwrap_err().contains("Layer 4: forwarded proxy hop IP"));

    // 4. Missing cert signature (corrupted by 1 byte) -> Layer 3 signature reject
    let mut bad_sig_cert = cert.clone();
    bad_sig_cert.issuer_ed25519_signature_hex = "aa".repeat(64);
    let sig_err = verify_us_sovereign_buyer_against_domestic_evasion(
        caller_ip,
        &[],
        None,
        Some(&tpm_hash),
        &bad_sig_cert,
        &auth_vk,
        &allowed_us,
        true,
        now,
    );
    assert!(sig_err.is_err());
    assert!(sig_err.unwrap_err().contains("Layer 3: invalid authority Ed25519 signature"));

    // 5. Foreign adversary IP (e.g. 47.88.0.1 Alibaba Cloud block) -> Layer 2 reject
    assert!(is_blocked_foreign_adversary_ip("47.88.0.1".parse().unwrap()));

    // 6. Proxy / Hosting ASN (e.g. 14061 DigitalOcean) -> Layer 2 reject
    assert!(is_high_risk_datacenter_or_proxy_asn(14061));
}

// ---------------------------------------------------------------------------
// TEST 3: Synthetic Gate Stage 1 (Low burstiness, low entropy, low MATTR)
// ---------------------------------------------------------------------------
#[test]
fn test_challenge_synthetic_gate_stage1_adversarial_stress() {
    let config = SyntheticGateConfig::default();

    // Adversarial vector 1: Uniform monotonous sentences (CV = 0.0)
    // 6 sentences, each exactly 5 words -> std_dev = 0 -> burstiness CV = 0.0
    let robotic_text = "We process the incoming data. We analyze the incoming data. We review the incoming data. We sanitize the incoming data. We approve the incoming data. We complete the incoming data.";
    let s1_robotic = evaluate_stage1_statistics(robotic_text, &config);
    assert!(!s1_robotic.passed, "Robotic uniform text must fail Stage 1");
    assert!(s1_robotic.burstiness_cv < config.min_burstiness_cv);
    assert!(s1_robotic.rejection_reason.as_ref().unwrap().contains("Sentence burstiness CV"));

    // Adversarial vector 2: Highly repetitive character stream (low Shannon entropy < 3.0)
    let repetitive_entropy = "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeeeeeeeeffffffffffgggggggggg";
    let entropy_val = compute_shannon_entropy(repetitive_entropy);
    assert!(entropy_val < 3.0);
    let s1_entropy = evaluate_stage1_statistics(repetitive_entropy, &config);
    assert!(!s1_entropy.passed, "Low Shannon entropy must fail Stage 1");

    // Adversarial vector 3: Low MATTR (repetitive 200-word vocabulary)
    let repetitive_words = (0..60).map(|_| "token").collect::<Vec<_>>().join(" ");
    let mattr_val = compute_mattr(&repetitive_words, 20);
    assert!(mattr_val <= 0.10);

    // Baseline: Authentic human writing with varied sentence lengths (CV >= 0.30)
    let human_text = "Stop immediately. Then review the entire architectural framework across the network to verify that all invariants hold true without exception. All tests pass.";
    let s1_human = evaluate_stage1_statistics(human_text, &config);
    assert!(s1_human.passed, "Authentic human text must pass Stage 1");
    assert!(s1_human.burstiness_cv >= config.min_burstiness_cv);
}

// ---------------------------------------------------------------------------
// TEST 4: Synthetic Gate Stage 2 (File Provenance & Synthetic PDF/DOCX Producers)
// ---------------------------------------------------------------------------
#[test]
fn test_challenge_synthetic_gate_stage2_adversarial_stress() {
    let config = SyntheticGateConfig::default();

    // Test each known synthetic PDF generator signature
    for &producer in KNOWN_SYNTHETIC_PDF_PRODUCERS {
        let tmp = tempfile::Builder::new().suffix(".pdf").tempfile().unwrap();
        let fake_pdf_content = format!(
            "%PDF-1.4\n1 0 obj\n<< /Title (Test) /Producer ({}) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF",
            producer
        );
        std::fs::write(tmp.path(), fake_pdf_content.as_bytes()).unwrap();

        let rep = inspect_file_provenance(Some(tmp.path()), &config);
        assert!(
            !rep.passed,
            "Producer '{}' must be detected and rejected by Stage 2",
            producer
        );
        assert!(rep.is_synthetic_generator_detected);
        assert_eq!(rep.generator_signature.as_deref(), Some(producer));
    }

    // Test DOCX with revision 0 and synthetic generator
    let tmp_docx = tempfile::Builder::new().suffix(".docx").tempfile().unwrap();
    let fake_docx_content = "<cp:revision>0</cp:revision><totaltime>0</totaltime><producer>puppeteer</producer>";
    std::fs::write(tmp_docx.path(), fake_docx_content.as_bytes()).unwrap();
    let docx_rep = inspect_file_provenance(Some(tmp_docx.path()), &config);
    assert!(!docx_rep.passed, "DOCX with revision 0 must be rejected");

    // Clean text file
    let tmp_clean = tempfile::Builder::new().suffix(".txt").tempfile().unwrap();
    std::fs::write(tmp_clean.path(), b"Authentic document notes written by human developer.").unwrap();
    let clean_rep = inspect_file_provenance(Some(tmp_clean.path()), &config);
    assert!(clean_rep.passed, "Clean document must pass Stage 2");
}

// ---------------------------------------------------------------------------
// TEST 5: Synthetic Gate Stage 3 (Zero-Width Watermarks, Homoglyphs, 27 AI Clichés)
// ---------------------------------------------------------------------------
#[test]
fn test_challenge_synthetic_gate_stage3_adversarial_stress() {
    let config = SyntheticGateConfig::default();

    // 1. Invisible zero-width & steganographic watermark characters
    let watermark_chars = [
        '\u{200B}', // Zero-width space
        '\u{200C}', // Zero-width non-joiner
        '\u{200D}', // Zero-width joiner
        '\u{2060}', // Word joiner
        '\u{FEFF}', // Zero-width no-break space
        '\u{00AD}', // Soft hyphen
        '\u{200E}', // LTR mark
        '\u{200F}', // RTL mark
        '\u{202A}', // Embedding
        '\u{E0001}', // Unicode tag
    ];

    for c in watermark_chars {
        assert!(
            is_invisible_watermark_char(c),
            "Character U+{:04X} must be recognized as invisible watermark",
            c as u32
        );
        let sample = format!("Valid text{}with secret watermark.", c);
        let rep = scrub_and_scan_stage3_lexical(&sample, &config);
        assert!(
            !rep.passed,
            "Text containing U+{:04X} must fail Stage 3",
            c as u32
        );
        assert_eq!(rep.stripped_watermark_chars, 1);
        assert_eq!(rep.cleaned_text, "Valid textwith secret watermark.");
    }

    // 2. Mixed-script homoglyph injection
    let homoglyph_sample = "Checking user p\u{0430}ssword credentials."; // Cyrillic 'а'
    let rep_homo = scrub_and_scan_stage3_lexical(homoglyph_sample, &config);
    assert!(!rep_homo.passed, "Mixed-script homoglyphs must fail Stage 3");
    assert_eq!(rep_homo.mixed_script_homoglyphs_detected, 1);

    // 3. Exhaustive check of ALL 27 AI cliché patterns
    for &cliche in SYNTHETIC_CLICHE_PATTERNS {
        let sample = format!("The team will {} to explore architectural tradeoffs.", cliche);
        let rep_cliche = scrub_and_scan_stage3_lexical(&sample, &config);
        assert!(
            !rep_cliche.passed,
            "AI cliché pattern '{}' must trigger Stage 3 rejection",
            cliche
        );
        assert!(
            rep_cliche.cliche_matches.contains(&cliche.to_string()),
            "Cliche matches must list '{}'",
            cliche
        );
    }
}

// ---------------------------------------------------------------------------
// TEST 6: Synthetic Gate Stage 4 (Human Telemetry Nonces, Rate Limiting & Nonce Replay)
// ---------------------------------------------------------------------------
#[test]
fn test_challenge_synthetic_gate_stage4_adversarial_stress() {
    let node_seed = [0x77u8; 32];
    let mut config = SyntheticGateConfig::default();
    config.min_reading_ms_per_50_tokens = 100;
    config.rate_limit_per_minute = 12;
    config.rate_limit_burst = 3;

    let guard = HumanTelemetryGuard::new(&node_seed, config);

    // 1. Valid issuance with prior interaction offset
    let nonce = guard.issue_interaction_nonce_with_offset("traj-valid-01", 50, 5);
    let valid_rep = guard.verify_interaction_nonce(&nonce, "traj-valid-01", 50);
    assert!(valid_rep.passed, "Valid nonce with 5s reading time must pass");
    assert!(valid_rep.nonce_verified);

    // 2. Nonce tampering (corrupt MAC by 1 byte)
    let mut tampered_bytes = nonce.into_bytes();
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] = if tampered_bytes[last_idx] == b'a' { b'b' } else { b'a' };
    let tampered_nonce = String::from_utf8(tampered_bytes).unwrap();
    let tamper_rep = guard.verify_interaction_nonce(&tampered_nonce, "traj-valid-01", 50);
    assert!(!tamper_rep.passed, "Tampered nonce MAC must fail");
    assert!(!tamper_rep.nonce_verified);

    // 3. Trajectory ID mismatch
    let fresh_nonce = guard.issue_interaction_nonce_with_offset("traj-alpha", 50, 5);
    let mismatch_rep = guard.verify_interaction_nonce(&fresh_nonce, "traj-beta", 50);
    assert!(!mismatch_rep.passed, "Mismatched trajectory ID must fail");

    // 4. Future timestamp (in future > 10s)
    let future_ts = chrono::Utc::now().timestamp() + 300;
    let future_payload = format!("traj-future:{}:50", future_ts);
    let key = blake3::derive_key("QuorumRAG-HumanTelemetry-NonceKey-v1", &node_seed);
    let future_mac = blake3::keyed_hash(&key, future_payload.as_bytes()).to_hex().to_string();
    let future_nonce = format!("traj-future:{}:50:{}", future_ts, future_mac);
    let future_rep = guard.verify_interaction_nonce(&future_nonce, "traj-future", 50);
    assert!(!future_rep.passed, "Future timestamp must fail");
    assert!(future_rep.rejection_reason.as_ref().unwrap().contains("in the future"));

    // 5. Expired timestamp (> 24 hours)
    let expired_ts = chrono::Utc::now().timestamp() - 90000;
    let exp_payload = format!("traj-exp:{}:50", expired_ts);
    let exp_mac = blake3::keyed_hash(&key, exp_payload.as_bytes()).to_hex().to_string();
    let exp_nonce = format!("traj-exp:{}:50:{}", expired_ts, exp_mac);
    let exp_rep = guard.verify_interaction_nonce(&exp_nonce, "traj-exp", 50);
    assert!(!exp_rep.passed, "Expired timestamp must fail");
    assert!(exp_rep.rejection_reason.as_ref().unwrap().contains("expired"));

    // 6. Insufficient human reading time (< 100 ms per 50 tokens)
    // 500 tokens requires 1000 ms, offset 0 secs = elapsed 0 ms
    let fast_nonce = guard.issue_interaction_nonce_with_offset("traj-fast", 500, 0);
    let fast_rep = guard.verify_interaction_nonce(&fast_nonce, "traj-fast", 500);
    assert!(!fast_rep.passed, "Bot-speed response without reading time must fail");
    assert!(fast_rep.rejection_reason.as_ref().unwrap().contains("below human reading minimum"));

    // 7. EMPIRICAL CHALLENGE: Nonce Replay Vulnerability Investigation
    // Issue a valid nonce
    let replay_target = guard.issue_interaction_nonce_with_offset("traj-replay", 50, 5);
    let first_submission = guard.verify_interaction_nonce(&replay_target, "traj-replay", 50);
    assert!(first_submission.passed, "First submission of nonce must pass");

    // Second submission of the IDENTICAL nonce must fail:
    let second_submission = guard.verify_interaction_nonce(&replay_target, "traj-replay", 50);
    assert!(
        !second_submission.passed,
        "Second submission of the identical nonce must be rejected as replay"
    );
    assert!(
        second_submission
            .rejection_reason
            .as_ref()
            .unwrap()
            .contains("Nonce replay detected"),
        "Rejection reason must indicate replay detected"
    );
}

// ---------------------------------------------------------------------------
// TEST 7: Full End-to-End Escrow Pull & Watermark Verification via Daemon Endpoints
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_challenge_e2e_localhost_pull_and_watermark() {
    let (app, _state, _td) = setup_test_app().await;

    // 1. Opt-in with explicit consent
    let opt_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/opt-in")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "opt_in_enabled": true,
                        "user_consent_checked": true,
                        "consent_statement": "Challenger test opt-in agreement",
                        "opt_in_folders": ["D:\\Vault"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(opt_res.status(), StatusCode::OK);

    // 2. Harvest default batch
    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-challenger-01",
                        "auto_approve": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(harvest_res.status(), StatusCode::OK);

    // 3. Issue test certificate pinned to 127.0.0.1/32
    let cert_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/test/issue-cert")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "buyer_id": "challenger-buyer-01",
                        "egress_cidr": "127.0.0.1/32"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cert_res.status(), StatusCode::OK);
    let cert_json = read_body_json(cert_res).await;
    let cert: BuyerJurisdictionCertificate =
        serde_json::from_value(cert_json["certificate"].clone()).unwrap();

    // 4. Request preview from 127.0.0.1
    let prev_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/preview")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "127.0.0.1")
                .header("x-quorum-tpm-pubkey-blake3", &cert.bound_tpm_pubkey_blake3)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-challenger-01",
                        "buyer_cert": cert
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prev_res.status(), StatusCode::OK);
    let prev_json = read_body_json(prev_res).await;
    assert_eq!(prev_json["synthetic_contamination_filtered"], true);

    // 5. Escrow unlock
    let unlock_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/unlock")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "127.0.0.1")
                .header("x-quorum-tpm-pubkey-blake3", &cert.bound_tpm_pubkey_blake3)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-challenger-01",
                        "buyer_cert": cert,
                        "amount_paid_cents": 5000
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unlock_res.status(), StatusCode::OK);
    let receipt: EscrowReceiptToken =
        serde_json::from_slice(&read_body_bytes(unlock_res).await).unwrap();

    // 6. Download watermarked records
    let dl_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/download")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "127.0.0.1")
                .header("x-quorum-tpm-pubkey-blake3", &cert.bound_tpm_pubkey_blake3)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-challenger-01",
                        "buyer_cert": cert,
                        "receipt_token": receipt
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dl_res.status(), StatusCode::OK);
    let dl_bytes = read_body_bytes(dl_res).await;
    let dl_text = String::from_utf8(dl_bytes).unwrap();
    let records: Vec<SanitizedTrainingRecord> = dl_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert!(!records.is_empty());
    assert!(records[0].buyer_watermark_hex.is_some());
}
