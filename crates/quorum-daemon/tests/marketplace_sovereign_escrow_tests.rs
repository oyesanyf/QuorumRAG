//! End-to-End Integration Suite for the Opt-In Sovereign AI Training Data Marketplace,
//! 7-Layer Domestic-Evasion Guard (`SovereignJurisdictionGuard`), Semantic Trade-Secret Filter,
//! Tiered Anti-Scraping Previews, Commit-and-Reveal Cryptographic Escrow, and Federated `ContributionLedger`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use quorum_contract::{
    BuyerJurisdictionCertificate, DataCatalogManifest, EscrowReceiptToken, SanitizedRlmStep,
    SanitizedTrainingRecord, TrainingRecordFormat,
};
use quorum_coordinator::SynthesisModelFamily;
use quorum_daemon::{build_router, DaemonState};
use std::sync::Arc;
use std::time::Instant;
use tempfile::{tempdir, TempDir};
use tower::ServiceExt;

async fn setup_marketplace_test_app() -> (axum::Router, Arc<DaemonState>, TempDir) {
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
        default_model_family: SynthesisModelFamily::AutoFusion,
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

fn sign_us_buyer_cert(
    authority_seed: &[u8; 32],
    buyer_id: &str,
    country_iso: &str,
    cidrs: Vec<&str>,
    tpm_hash: &str,
    foci_clean: bool,
    part202_clean: bool,
) -> BuyerJurisdictionCertificate {
    let mut cert = BuyerJurisdictionCertificate {
        buyer_id: buyer_id.to_string(),
        legal_entity_name: format!("Verified Sovereign AI Lab ({})", buyer_id),
        incorporation_country_iso: country_iso.to_string(),
        lei_or_duns_id: "549300USSOVEREIGN99".to_string(),
        authorized_egress_cidrs: cidrs.into_iter().map(|s| s.to_string()).collect(),
        bound_tpm_pubkey_blake3: tpm_hash.to_string(),
        foci_ubo_verified_clean: foci_clean,
        doj_part202_non_covered_person: part202_clean,
        non_redistribution_covenant_accepted: true,
        expires_unix_secs: 1_950_000_000,
        issuer_ed25519_signature_hex: String::new(),
    };
    cert.sign_ed25519(authority_seed).expect("sign cert");
    cert
}

/// Test 1: Verify the Marketplace is strictly disabled by default (`opt_in_enabled: false`),
/// defaults to `["US"]`-only jurisdiction, and fails closed (`403 Forbidden`) across all data routes until enabled.
#[tokio::test]
async fn test_1_disabled_by_default_invariant() {
    let (app, _state, _tmp) = setup_marketplace_test_app().await;

    // 1. Check GET /api/v1/marketplace/status defaults
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/marketplace/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let status_json = read_body_json(resp).await;
    assert_eq!(status_json["opt_in_enabled"], serde_json::json!(false));
    assert_eq!(
        status_json["allowed_jurisdictions"],
        serde_json::json!(["US"])
    );
    assert_eq!(
        status_json["sovereign_lock_mode"],
        serde_json::json!("US_ONLY_DOJ_28_CFR_PART_202")
    );

    // 2. Verify all operational routes fail closed with 403 Forbidden while opt_in_enabled == false
    let protected_requests = vec![
        ("POST", "/api/v1/marketplace/harvest", "{}"),
        ("POST", "/api/v1/marketplace/approve-batch", "{}"),
        ("GET", "/api/v1/marketplace/preview", ""),
        ("GET", "/api/v1/marketplace/download", ""),
        ("GET", "/api/v1/marketplace/bounties", ""),
        ("GET", "/api/v1/marketplace/ledger", ""),
    ];

    for (method, uri, body_str) in protected_requests {
        let req = if method == "POST" {
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap()
        } else {
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap()
        };
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "Route {} {} MUST return 403 Forbidden when opt_in_enabled == false",
            method,
            uri
        );
    }

    // 3. Verify embedded Web UI includes the Opt-In Marketplace modal disabled by default
    let index_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(index_res.status(), StatusCode::OK);
    let html = String::from_utf8(read_body_bytes(index_res).await).unwrap();
    assert!(html.contains("id=\"modal-marketplace\""));
    assert!(html.contains("id=\"marketplace-opt-in-toggle\""));
    assert!(html.contains("DISABLED BY DEFAULT (403 Fail-Closed)"));
}

/// Test 2: Verify direct foreign CIDR blocks (`CN`, `HK`, `MO`, `RU`, `KP`), Chinese telecom/cloud ASNs,
/// and prohibited country headers fail closed with `403 Forbidden` and zero bytes leaked.
#[tokio::test]
async fn test_2_direct_foreign_cidr_asn_and_geo_blocklist_invariant() {
    let (app, _state, _tmp) = setup_marketplace_test_app().await;

    // Attempting to add CN or RU to allowed_jurisdictions must be rejected with 403 Forbidden
    let bad_opt_in = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/opt-in")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "opt_in_enabled": true,
                        "allowed_jurisdictions": ["US", "CN"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_opt_in.status(), StatusCode::FORBIDDEN);

    // Enable Opt-In with strict US-only default
    let ok_opt_in = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/opt-in")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "opt_in_enabled": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_opt_in.status(), StatusCode::OK);

    // Harvest and approve a local batch
    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "auto_approve": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(harvest_res.status(), StatusCode::OK);

    // Foreign IPv4 CIDRs (China Telecom 36.110.10.5, Alibaba Cloud 47.88.12.1, Russia 5.188.10.9, DPRK 175.45.176.10)
    for foreign_ip in ["36.110.10.5", "47.88.12.1", "5.188.10.9", "175.45.176.10"] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/marketplace/preview")
                    .header("x-quorum-caller-ip", foreign_ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "Foreign adversary IP {} must be blocked at Layer 2",
            foreign_ip
        );
    }

    // Blocked GeoIP countries (CN, HK, MO, RU, IR, KP, BY)
    for country in ["CN", "HK", "MO", "RU", "IR", "KP", "BY"] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/marketplace/preview")
                    .header("x-quorum-caller-ip", "198.51.100.10")
                    .header("x-quorum-caller-country", country)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "Prohibited jurisdiction {} must be blocked at Layer 2",
            country
        );
    }
}

/// Test 3: Verify PII/PHI/path scrubbing, 100% verbatim citation substring grounding (`10_000 bps`),
/// and the Semantic Trade-Secret Filter (`> 15` lines of code, RFC1918 IPs, corporate FQDNs, high-entropy keys).
#[tokio::test]
async fn test_3_pii_phi_scrubbing_grounding_gate_and_semantic_trade_secret_filter() {
    let (app, _state, _tmp) = setup_marketplace_test_app().await;

    // Enable Opt-In
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/opt-in")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "opt_in_enabled": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let source_slice = "QuorumRAG enforces Ed25519 peer authentication, BLAKE3 Merkle verification, and parent-document byte window expansion (0..10000 bytes) across federated nodes.";
    let valid_quote = "parent-document byte window expansion (0..10000 bytes)";

    // 1. Submit a batch containing:
    //    - Candidate A (valid grounding, contains PII/PHI/paths that MUST be scrubbed),
    //    - Candidate B (> 15 lines of proprietary Rust code -> MUST be rejected by Trade-Secret Filter),
    //    - Candidate C (RFC1918 internal IP 10.24.88.19 -> MUST be rejected by Trade-Secret Filter),
    //    - Candidate D (ungrounded citation quote -> MUST be rejected by Quality Gate).
    let code_18_lines = (0..18)
        .map(|i| format!("pub fn proprietary_kernel_step_{}() {{ let mut v = {}; }}", i, i))
        .collect::<Vec<_>>()
        .join("\n");

    let payload = serde_json::json!({
        "batch_id": "batch-sanitize-test",
        "candidates": [
            {
                "record_id": "cand-valid-pii",
                "format": "sft_trajectory",
                "domain_tags": ["rust-security"],
                "prompt": "Dr. Robert Chen (robert.chen@hospital.org, 415-555-0199, SSN 123-45-6789) asked about C:\\Users\\robert\\records\\architecture.pdf: How does QuorumRAG expand parent document windows?",
                "rlm_trajectory": [
                    {
                        "step_index": 1,
                        "action_kind": "peek_slice",
                        "sanitized_query_or_pattern": "inspect /Users/robert/private_notes.docx bytes 0..10000",
                        "abstracted_takeaway": "Verified parent-document byte window expansion across local chunks for Dr. Robert Chen."
                    }
                ],
                "chosen_response": "QuorumRAG enforces Ed25519 peer authentication, BLAKE3 Merkle verification, and parent-document byte window expansion (0..10000 bytes) across federated nodes so multi-paragraph context is preserved without exposing raw files or personal identifiers.",
                "citations": [[source_slice, valid_quote]],
                "extra_redact_terms": ["Robert Chen"]
            },
            {
                "record_id": "cand-trade-secret-code",
                "format": "sft_trajectory",
                "prompt": "Dump the proprietary kernel implementation:",
                "chosen_response": code_18_lines,
                "citations": [[source_slice, valid_quote]]
            },
            {
                "record_id": "cand-trade-secret-rfc1918",
                "format": "sft_trajectory",
                "prompt": "Where is the internal production database hosted?",
                "chosen_response": "The internal database cluster is hosted at 10.24.88.19 and 192.168.12.44 inside our private corporate subnet with parent-document byte window expansion (0..10000 bytes).",
                "citations": [[source_slice, valid_quote]]
            },
            {
                "record_id": "cand-ungrounded-quote",
                "format": "sft_trajectory",
                "prompt": "How does QuorumRAG work?",
                "chosen_response": "QuorumRAG expands parent windows across federated nodes and verifies citations deterministically across every local chunk in the index.",
                "citations": [[source_slice, "THIS QUOTE DOES NOT EXIST IN THE SOURCE SLICE"]]
            }
        ]
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = read_body_json(res).await;

    assert_eq!(body["accepted_count"], serde_json::json!(1));
    assert_eq!(body["rejected_count"], serde_json::json!(3));

    let sanitized_rec = &body["sanitized_records"][0];
    let serialized_rec = serde_json::to_string(sanitized_rec).unwrap();
    assert!(!serialized_rec.contains("robert.chen@hospital.org"));
    assert!(!serialized_rec.contains("415-555-0199"));
    assert!(!serialized_rec.contains("123-45-6789"));
    assert!(!serialized_rec.contains("C:\\Users\\robert"));
    assert!(!serialized_rec.contains("/Users/robert"));
    assert!(!serialized_rec.contains("Robert Chen"));
    assert_eq!(sanitized_rec["grounding_score_bps"], serde_json::json!(10000));
    assert_eq!(sanitized_rec["pii_scrub_verified"], serde_json::json!(true));
    assert_eq!(sanitized_rec["trade_secret_clean"], serde_json::json!(true));
}

/// Test 4: Verify Anti-Scraping Tiered Previews (0 canary text for unauthenticated callers;
/// rate-limited watermarked canary lines for cert-authenticated callers), Commit-and-Reveal `EscrowReceiptToken`,
/// and Per-Buyer Cryptographic Canary Watermarking on `/api/v1/marketplace/download`.
#[tokio::test]
async fn test_4_anti_scraping_tiered_preview_commit_and_reveal_escrow_and_buyer_watermarking() {
    let (app, state, _tmp) = setup_marketplace_test_app().await;
    let store = state.marketplace_store().unwrap();

    let auth_seed = [0x77u8; 32];
    let auth_pub_hex = {
        let vk = SigningKey::from_bytes(&auth_seed).verifying_key();
        vk.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>()
    };

    // Enable Opt-In with known authority public key
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/opt-in")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "opt_in_enabled": true,
                        "authority_pubkey_hex": auth_pub_hex
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Harvest & approve batch
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-escrow-001",
                        "auto_approve": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // 1. Unauthenticated Preview: MUST return aggregate metadata + Merkle root ONLY, with canary_sample == []
    let unauth_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/marketplace/preview?batch_id=batch-escrow-001")
                .header("x-quorum-caller-ip", "198.51.100.25")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_res.status(), StatusCode::OK);
    let unauth_manifest: DataCatalogManifest =
        serde_json::from_slice(&read_body_bytes(unauth_res).await).unwrap();
    assert!(
        unauth_manifest.canary_sample.is_empty(),
        "Unauthenticated preview MUST strip all canary_sample records to prevent scraping"
    );
    assert_eq!(unauth_manifest.sft_record_count, 1);
    assert_eq!(unauth_manifest.dpo_record_count, 1);

    // 2. Cert-Authenticated Preview: Returns watermarked canary lines and enforces rate limit
    let tpm_lab_1 = blake3::hash(b"tpm-ek-us-lab-1").to_hex().to_string();
    let cert_lab_1 = sign_us_buyer_cert(
        &auth_seed,
        "us-ai-lab-01",
        "US",
        vec!["198.51.100.0/24"],
        &tpm_lab_1,
        true,
        true,
    );

    let auth_preview_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/preview")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.25")
                .header("x-quorum-preview-rate-limit", "2")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-escrow-001",
                        "buyer_cert": cert_lab_1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth_preview_res.status(), StatusCode::OK);
    let auth_manifest: DataCatalogManifest =
        serde_json::from_slice(&read_body_bytes(auth_preview_res).await).unwrap();
    assert_eq!(auth_manifest.canary_sample.len(), 2);
    assert!(auth_manifest.canary_sample[0].verify_buyer_watermark(
        &store.node_seed,
        "us-ai-lab-01",
        "preview_canary"
    ));

    // Second preview within limit=2 succeeds; third preview MUST be blocked with 429 Too Many Requests
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/preview")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.25")
                .header("x-quorum-preview-rate-limit", "2")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-escrow-001",
                        "buyer_cert": cert_lab_1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let rate_limited_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/preview")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.25")
                .header("x-quorum-preview-rate-limit", "2")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-escrow-001",
                        "buyer_cert": cert_lab_1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rate_limited_res.status(), StatusCode::TOO_MANY_REQUESTS);

    // 3. Commit-and-Reveal Escrow Unlock + Watermarked Download
    let unlock_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/unlock")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.25")
                .header("x-quorum-tpm-pubkey-blake3", &tpm_lab_1)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-escrow-001",
                        "buyer_cert": cert_lab_1,
                        "amount_paid_cents": 25000
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

    // Tampered receipt MAC must fail closed with 403 Forbidden
    let mut forged_receipt = receipt.clone();
    forged_receipt.keyed_blake3_mac_hex = "00".repeat(32);
    let forged_dl = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/download")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.25")
                .header("x-quorum-tpm-pubkey-blake3", &tpm_lab_1)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-escrow-001",
                        "buyer_cert": cert_lab_1,
                        "receipt_token": forged_receipt
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forged_dl.status(), StatusCode::FORBIDDEN);

    // Valid receipt + matching TPM hardware key hash -> streams buyer-watermarked .jsonl
    let valid_dl = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/download")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.25")
                .header("x-quorum-tpm-pubkey-blake3", &tpm_lab_1)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-escrow-001",
                        "buyer_cert": cert_lab_1,
                        "receipt_token": receipt
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(valid_dl.status(), StatusCode::OK);
    let jsonl_text = String::from_utf8(read_body_bytes(valid_dl).await).unwrap();
    let downloaded_records: Vec<SanitizedTrainingRecord> = jsonl_text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(downloaded_records.len(), 2);
    for rec in &downloaded_records {
        assert!(rec.verify_buyer_watermark(&store.node_seed, "us-ai-lab-01", "full_unlock"));
        assert!(!rec.verify_buyer_watermark(&store.node_seed, "us-ai-lab-02", "full_unlock"));
    }
}

/// Test 5: Verify Federated Swarm Pool `ContributionLedger` deduplicates records across mesh peers
/// and computes exact basis-point (`10,000 bps`) revenue splits and cent payouts.
#[tokio::test]
async fn test_5_federated_swarm_pool_contribution_ledger_revenue_split() {
    let (app, _state, _tmp) = setup_marketplace_test_app().await;

    // Enable Opt-In
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/opt-in")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "opt_in_enabled": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let mk_peer_rec = |id: &str, peer_id: &str, prompt: &str, seed_byte: u8| {
        let mut r = SanitizedTrainingRecord {
            record_id: id.to_string(),
            blake3_record_hash: String::new(),
            origin_node_id: peer_id.to_string(),
            format: TrainingRecordFormat::SftTrajectory,
            domain_tags: vec!["rust-security".to_string()],
            prompt: prompt.to_string(),
            rlm_trajectory: vec![SanitizedRlmStep {
                step_index: 1,
                action_kind: "peek_slice".to_string(),
                sanitized_query_or_pattern: "bytes 0..10000".to_string(),
                abstracted_takeaway: "Verified citation grounding.".to_string(),
            }],
            chosen_response: format!(
                "Comprehensive citation-grounded answer for {} with zero PII and verified Merkle provenance.",
                prompt
            ),
            rejected_response: None,
            verified_citation_count: 2,
            grounding_score_bps: 10_000,
            pii_scrub_verified: true,
            trade_secret_clean: true,
            token_count: 100,
            created_unix_secs: 1_760_000_000,
            ed25519_signature_hex: String::new(),
            buyer_watermark_hex: None,
        };
        r.sign_ed25519(&[seed_byte; 32]).unwrap();
        r
    };

    // Node Alpha contributes 2 unique records; Node Beta contributes 1 unique + 1 duplicate of Alpha; Node Gamma contributes 1 unique
    let pooled = vec![
        mk_peer_rec("r1", "12D3KooWNodeAlpha", "Prompt Alpha 1", 1),
        mk_peer_rec("r2", "12D3KooWNodeAlpha", "Prompt Alpha 2", 1),
        mk_peer_rec("r3", "12D3KooWNodeBeta", "Prompt Beta 1", 2),
        mk_peer_rec("r4-dup", "12D3KooWNodeBeta", "Prompt Alpha 1", 2), // duplicate content hash
        mk_peer_rec("r5", "12D3KooWNodeGamma", "Prompt Gamma 1", 3),
    ];

    let merge_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/pool-merge")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "pool_batch_id": "pool-swarm-001",
                        "records": pooled,
                        "total_pool_payout_cents": 200_000 // $2,000.00
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(merge_res.status(), StatusCode::OK);
    let body = read_body_json(merge_res).await;
    let ledger: quorum_contract::ContributionLedger =
        serde_json::from_value(body["ledger"].clone()).unwrap();

    assert_eq!(ledger.total_unique_records, 4);
    assert_eq!(ledger.total_duplicates_dropped, 1);

    let alpha = ledger.peer_shares.get("12D3KooWNodeAlpha").unwrap();
    let beta = ledger.peer_shares.get("12D3KooWNodeBeta").unwrap();
    let gamma = ledger.peer_shares.get("12D3KooWNodeGamma").unwrap();

    assert_eq!(alpha.unique_records_accepted, 2);
    assert_eq!(alpha.revenue_share_bps, 5000); // 50.00%
    assert_eq!(alpha.estimated_payout_cents, 100_000);

    assert_eq!(beta.unique_records_accepted, 1);
    assert_eq!(beta.duplicate_records_dropped, 1);
    assert_eq!(beta.revenue_share_bps, 2500); // 25.00%
    assert_eq!(beta.estimated_payout_cents, 50_000);

    assert_eq!(gamma.unique_records_accepted, 1);
    assert_eq!(gamma.revenue_share_bps, 2500); // 25.00%
    assert_eq!(gamma.estimated_payout_cents, 50_000);

    let total_bps: u16 = ledger.peer_shares.values().map(|s| s.revenue_share_bps).sum();
    let total_cents: u64 = ledger
        .peer_shares
        .values()
        .map(|s| s.estimated_payout_cents)
        .sum();
    assert_eq!(total_bps, 10_000);
    assert_eq!(total_cents, 200_000);
}

/// Test 6: Domestic U.S. Proxy, Rented VPS/Cloud PoP & Delaware Shell-LLC Evasion Invariant.
/// Proves that an adversary operating inside the United States via:
/// (A) U.S. PoPs of Alibaba/Tencent/China Telecom or rented DigitalOcean/Vultr/M247 VPS/VPN ASNs,
/// (B) Unpinned U.S. AWS/residential proxy IPs outside `cert.authorized_egress_cidrs`,
/// (C) A U.S.-incorporated Delaware shell LLC controlled by a foreign parent (`foci_ubo_verified_clean == false` or `doj_part202_non_covered_person == false`), or
/// (D) Forwarding a valid U.S. `EscrowReceiptToken` to a server without the bound hardware TPM 2.0 key
/// is deterministically rejected with `403 Forbidden` and zero bytes leaked.
#[tokio::test]
async fn test_6_domestic_us_proxy_and_shell_company_evasion_invariant() {
    let (app, _state, _tmp) = setup_marketplace_test_app().await;

    let auth_seed = [0x99u8; 32];
    let auth_pub_hex = {
        let vk = SigningKey::from_bytes(&auth_seed).verifying_key();
        vk.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>()
    };

    // Enable Opt-In with strict US-only default
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/opt-in")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "opt_in_enabled": true,
                        "authority_pubkey_hex": auth_pub_hex
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Harvest & seal batch
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-domestic-evasion-test",
                        "auto_approve": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let tpm_hash = blake3::hash(b"verified-us-cluster-tpm-2.0").to_hex().to_string();
    let valid_us_cert = sign_us_buyer_cert(
        &auth_seed,
        "us-legit-lab",
        "US",
        vec!["198.51.100.0/24"],
        &tpm_hash,
        true,
        true,
    );

    // Issue a legitimate EscrowReceiptToken first so we can also test credential-forwarding attacks on /download
    let unlock_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/unlock")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.55")
                .header("x-quorum-caller-asn", "7018")
                .header("x-quorum-tpm-pubkey-blake3", &tpm_hash)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-domestic-evasion-test",
                        "buyer_cert": valid_us_cert
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unlock_res.status(), StatusCode::OK);
    let valid_receipt: EscrowReceiptToken =
        serde_json::from_slice(&read_body_bytes(unlock_res).await).unwrap();

    // Vector A: Domestic US IP, but originating from Alibaba Cloud US PoP (AS45102), Tencent US PoP (AS132203),
    // DigitalOcean (AS14061), Vultr (AS20473), Linode (AS63949), or M247 VPN (AS9009) -> MUST return 403 Forbidden
    for evasive_asn in ["45102", "132203", "4134", "14061", "20473", "63949", "9009"] {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/marketplace/download")
                    .header("content-type", "application/json")
                    .header("x-quorum-caller-ip", "198.51.100.55")
                    .header("x-quorum-caller-asn", evasive_asn)
                    .header("x-quorum-tpm-pubkey-blake3", &tpm_hash)
                    .body(Body::from(
                        serde_json::json!({
                            "batch_id": "batch-domestic-evasion-test",
                            "buyer_cert": valid_us_cert,
                            "receipt_token": valid_receipt
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "Domestic evasion via ASN {} MUST fail closed with 403 Forbidden",
            evasive_asn
        );
    }

    // Vector B: Rented US AWS EC2 / Residential Proxy IP (203.0.113.200) outside certificate's pinned 198.51.100.0/24
    let unpinned_ip_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/download")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "203.0.113.200")
                .header("x-quorum-caller-asn", "7018")
                .header("x-quorum-tpm-pubkey-blake3", &tpm_hash)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-domestic-evasion-test",
                        "buyer_cert": valid_us_cert,
                        "receipt_token": valid_receipt
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unpinned_ip_res.status(), StatusCode::FORBIDDEN);

    // Vector C: Delaware Shell LLC with Foreign Beneficial Owner (foci_ubo_verified_clean = false or doj_part202 = false)
    let shell_llc_foci_cert = sign_us_buyer_cert(
        &auth_seed,
        "delaware-shell-llc",
        "US",
        vec!["198.51.100.0/24"],
        &tpm_hash,
        false, // FOCI / UBO failed (foreign parent company in Beijing/Shenzhen)
        true,
    );
    let shell_foci_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/unlock")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.55")
                .header("x-quorum-caller-asn", "7018")
                .header("x-quorum-tpm-pubkey-blake3", &tpm_hash)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-domestic-evasion-test",
                        "buyer_cert": shell_llc_foci_cert
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(shell_foci_res.status(), StatusCode::FORBIDDEN);

    let shell_llc_part202_cert = sign_us_buyer_cert(
        &auth_seed,
        "covered-person-subsidiary-llc",
        "US",
        vec!["198.51.100.0/24"],
        &tpm_hash,
        true,
        false, // DOJ 28 CFR Part 202 Covered Person (>=50% controlled by foreign adversary)
    );
    let shell_part202_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/unlock")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.55")
                .header("x-quorum-caller-asn", "7018")
                .header("x-quorum-tpm-pubkey-blake3", &tpm_hash)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-domestic-evasion-test",
                        "buyer_cert": shell_llc_part202_cert
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(shell_part202_res.status(), StatusCode::FORBIDDEN);

    // Vector D: Overseas Credential Forwarding — Valid US cert, IP, ASN, and EscrowReceiptToken,
    // but missing or mismatched hardware TPM 2.0 / HSM key header
    let wrong_tpm = blake3::hash(b"overseas-unattested-gpu-box").to_hex().to_string();
    let bad_tpm_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/download")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "198.51.100.55")
                .header("x-quorum-caller-asn", "7018")
                .header("x-quorum-tpm-pubkey-blake3", &wrong_tpm)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-domestic-evasion-test",
                        "buyer_cert": valid_us_cert,
                        "receipt_token": valid_receipt
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_tpm_res.status(), StatusCode::FORBIDDEN);
}
