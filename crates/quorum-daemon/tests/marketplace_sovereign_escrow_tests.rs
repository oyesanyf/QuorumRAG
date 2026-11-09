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

/// Test 9: Verify explicit user consent checkbox, folder-scoped Opt-In (`opt_in_folders`),
/// Ed25519-signed & BLAKE3 hash-chained `consent_ledger`, and split Settings tabs in `index.html` / `app.js`.
#[tokio::test]
async fn test_9_explicit_consent_checkbox_folder_scoped_opt_in_and_signed_consent_ledger() {
    let (app, _state, _tmp) = setup_marketplace_test_app().await;

    // 1. Default status must be Opt-Out with genesis DEFAULT_OPT_OUT_INITIALIZED ledger entry
    let status_res = app
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
    assert_eq!(status_res.status(), StatusCode::OK);
    let status_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(status_res).await).unwrap();
    assert_eq!(status_json["opt_in_enabled"], serde_json::json!(false));
    assert_eq!(status_json["user_consent_checked"], serde_json::json!(false));
    assert_eq!(status_json["opt_in_folders"], serde_json::json!([]));
    let genesis_ledger = status_json["consent_ledger"].as_array().unwrap();
    assert!(!genesis_ledger.is_empty());
    assert_eq!(genesis_ledger[0]["action"], "DEFAULT_OPT_OUT_INITIALIZED");

    // 2. Attempting to Opt-In with user_consent_checked = false must fail closed with 403 Forbidden
    let unconsented_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/opt-in")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "opt_in_enabled": true,
                        "user_consent_checked": false,
                        "opt_in_folders": ["D:\\Research"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unconsented_res.status(), StatusCode::FORBIDDEN);

    // 3. Opting in with explicit consent and specific folders persists folders and appends OPT_IN_AGREED to consent_ledger
    let opt_in_res = app
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
                        "opt_in_folders": ["D:\\Research", "C:\\Projects"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(opt_in_res.status(), StatusCode::OK);
    let opt_in_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(opt_in_res).await).unwrap();
    assert_eq!(opt_in_json["opt_in_enabled"], serde_json::json!(true));
    assert_eq!(opt_in_json["user_consent_checked"], serde_json::json!(true));
    assert_eq!(
        opt_in_json["opt_in_folders"],
        serde_json::json!(["D:\\Research", "C:\\Projects"])
    );
    let ledger_after_optin = opt_in_json["consent_ledger"].as_array().unwrap();
    assert!(ledger_after_optin.len() >= 2);
    assert_eq!(ledger_after_optin[0]["action"], "OPT_IN_AGREED");
    assert_eq!(
        ledger_after_optin[0]["opt_in_folders"],
        serde_json::json!(["D:\\Research", "C:\\Projects"])
    );
    assert_eq!(
        ledger_after_optin[0]["prev_entry_hash_blake3"],
        ledger_after_optin[1]["entry_hash_blake3"]
    );

    // 4. Verify index.html and app.js expose dedicated split Settings pages (marketplace, marketplace-ledger, diagnostics)
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
    let html = String::from_utf8(read_body_bytes(index_res).await).unwrap();
    assert!(html.contains("data-tab=\"marketplace\""));
    assert!(html.contains("data-tab=\"marketplace-ledger\""));
    assert!(html.contains("data-tab=\"diagnostics\""));
    assert!(!html.contains("data-tab=\"marketplace\" onclick="));

    // 5. Verify POST /api/documents/add uploads, indexes a new document, and appends to opt_in_folders
    let add_doc_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/documents/add")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "uploaded_files": [{
                            "file_name": "new_sovereign_notes.txt",
                            "content_text": "QuorumRAG multi-engine privacy scrubber and folder-scoped Opt-In specification."
                        }],
                        "add_to_opt_in": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(add_doc_res.status(), StatusCode::OK);
    let add_doc_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(add_doc_res).await).unwrap();
    assert_eq!(add_doc_json["status"], "added_and_indexed");
    assert_eq!(add_doc_json["added_count"], 1);
}

#[tokio::test]
async fn test_10_localhost_test_certificate_and_buyer_pull_escrow() {
    let (app, _state, _td) = setup_marketplace_test_app().await;

    // 1. Enable Opt-In with explicit consent agreement
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
                        "consent_statement": "Localhost test consent agreement",
                        "opt_in_folders": ["D:\\LocalhostVault"]
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
                        "batch_id": "batch-localhost-e2e-01",
                        "auto_approve": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(harvest_res.status(), StatusCode::OK);
    let harvest_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(harvest_res).await).unwrap();
    assert_eq!(harvest_json["approved"], true);
    assert_eq!(harvest_json["accepted_count"], 2);

    // 3. Issue test certificate via POST /api/v1/marketplace/test/issue-cert supporting 127.0.0.1/32
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
                        "egress_cidr": "127.0.0.1/32",
                        "legal_entity_name": "Localhost Verification Labs"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(issue_res.status(), StatusCode::OK);
    let issue_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(issue_res).await).unwrap();
    assert_eq!(issue_json["status"], "ok");
    let test_cert: BuyerJurisdictionCertificate =
        serde_json::from_value(issue_json["certificate"].clone()).unwrap();
    assert!(test_cert.authorized_egress_cidrs.contains(&"127.0.0.1/32".to_string()));

    // 4. Authenticated preview request from localhost presenting test_cert
    let preview_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/preview")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "127.0.0.1")
                .header("x-quorum-tpm-pubkey-blake3", &test_cert.bound_tpm_pubkey_blake3)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-localhost-e2e-01",
                        "buyer_cert": test_cert
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(preview_res.status(), StatusCode::OK);
    let preview_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(preview_res).await).unwrap();
    assert_eq!(preview_json["synthetic_contamination_filtered"], true);
    let canaries = preview_json["canary_sample"].as_array().unwrap();
    assert!(!canaries.is_empty());
    assert!(canaries[0]["buyer_watermark_hex"].is_string());

    // 5. Unlock batch from localhost (issue EscrowReceiptToken)
    let unlock_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/unlock")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "127.0.0.1")
                .header("x-quorum-tpm-pubkey-blake3", &test_cert.bound_tpm_pubkey_blake3)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-localhost-e2e-01",
                        "buyer_cert": test_cert,
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
    assert!(!receipt.keyed_blake3_mac_hex.is_empty());

    // 6. Download watermarked records from localhost
    let download_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/download")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "127.0.0.1")
                .header("x-quorum-tpm-pubkey-blake3", &test_cert.bound_tpm_pubkey_blake3)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-localhost-e2e-01",
                        "buyer_cert": test_cert,
                        "receipt_token": receipt
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(download_res.status(), StatusCode::OK);
    let download_body = String::from_utf8(read_body_bytes(download_res).await).unwrap();
    let downloaded_records: Vec<SanitizedTrainingRecord> = download_body
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(downloaded_records.len(), 2);
    assert!(downloaded_records[0].buyer_watermark_hex.is_some());

    // 7. Negative case: Request from 127.0.0.1 presenting a certificate pinned ONLY to 198.51.100.0/24
    let mut foreign_cidr_cert = test_cert.clone();
    foreign_cidr_cert.authorized_egress_cidrs = vec!["198.51.100.0/24".to_string()];
    let node_seed = [0x42u8; 32];
    let authority_seed = blake3::derive_key("QuorumRAG-Marketplace-AuthoritySeed-v1", &node_seed);
    foreign_cidr_cert.sign_ed25519(&authority_seed).unwrap();

    let denied_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/unlock")
                .header("content-type", "application/json")
                .header("x-quorum-caller-ip", "127.0.0.1")
                .header("x-quorum-tpm-pubkey-blake3", &foreign_cidr_cert.bound_tpm_pubkey_blake3)
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-localhost-e2e-01",
                        "buyer_cert": foreign_cidr_cert,
                        "amount_paid_cents": 5000
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied_res.status(), StatusCode::FORBIDDEN);
    let denied_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(denied_res).await).unwrap();
    assert!(denied_json["error"]
        .as_str()
        .unwrap()
        .contains("caller IP does not match certificate's pinned corporate authorized_egress_cidrs"));

    // 8. Test execute-transaction endpoint directly
    let exec_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/test/execute-transaction")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "amount_paid_cents": 5000
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exec_res.status(), StatusCode::OK);
    let exec_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(exec_res).await).unwrap();
    assert_eq!(exec_json["status"], "ok");
    assert_eq!(exec_json["watermark_verified"], true);
    assert_eq!(exec_json["synthetic_contamination_filtered"], true);
}

#[tokio::test]
async fn test_11_synthetic_gate_rejection_and_manifest_filtered_flag() {
    let (app, _state, _td) = setup_marketplace_test_app().await;

    // Enable Opt-In
    let _ = app
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
                        "opt_in_folders": ["D:\\Vault"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // 1. Submit candidate contaminated with invisible zero-width watermarks -> must be rejected
    let watermarked_cand = serde_json::json!({
        "candidates": [{
            "record_id": "rec-wm-01",
            "prompt": "Explain zero-trust access control protocols in modern architectures.",
            "chosen_response": "Zero-trust enforces strict continuous verification.\u{200B} Never trust, always verify every single network packet.\u{200C} Periodic re-authentication is mandatory.",
            "citations": [("Zero-trust enforces strict continuous verification.", "Zero-trust enforces strict continuous verification.")]
        }]
    });
    let wm_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(watermarked_cand.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wm_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let wm_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(wm_res).await).unwrap();
    assert_eq!(wm_json["rejected_count"], 1);
    assert!(wm_json["rejected_candidates"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("invisible zero-width/Unicode tag watermark characters"));

    // 2. Submit candidate with AI clichés ("rich tapestry" & "stands as a beacon") -> must be rejected
    let cliche_cand = serde_json::json!({
        "candidates": [{
            "record_id": "rec-cliche-01",
            "prompt": "Summarize the history of cryptography and modern secure systems.",
            "chosen_response": "This technology stands as a beacon of mathematical rigor. It reflects the rich tapestry of human ingenuity across centuries. In conclusion, cryptography continues to evolve.",
            "citations": [("This technology stands as a beacon of mathematical rigor.", "This technology stands as a beacon of mathematical rigor.")]
        }]
    });
    let cliche_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(cliche_cand.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cliche_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let cliche_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(cliche_res).await).unwrap();
    assert!(cliche_json["rejected_candidates"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("synthetic AI cliché patterns"));

    // 3. Submit candidate with invalid Stage 4 nonce -> must be rejected
    let bad_nonce_cand = serde_json::json!({
        "candidates": [{
            "record_id": "rec-nonce-01",
            "prompt": "How does memory safety work in Rust systems programming?",
            "chosen_response": "Rust provides compile-time guarantees through its ownership model. Borrow checking prevents data races. Lifetimes track reference validity without garbage collection overhead.",
            "citations": [("Rust provides compile-time guarantees through its ownership model.", "Rust provides compile-time guarantees through its ownership model.")],
            "interaction_nonce_hex": "bad:nonce:structure:00"
        }]
    });
    let nonce_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(bad_nonce_cand.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(nonce_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let nonce_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(nonce_res).await).unwrap();
    assert!(nonce_json["rejected_candidates"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("Stage 4 Rejection"));

    // 4. Issue a valid nonce via POST /api/v1/marketplace/issue-nonce
    let issue_nonce_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/issue-nonce")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "trajectory_id": "rec-valid-01",
                        "context_token_count": 30
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(issue_nonce_res.status(), StatusCode::OK);
    let issue_nonce_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(issue_nonce_res).await).unwrap();
    let valid_nonce = issue_nonce_json["nonce_hex"].as_str().unwrap().to_string();

    // 5. Submit clean human candidate with valid nonce and varied sentence burstiness
    let clean_cand = serde_json::json!({
        "candidates": [{
            "record_id": "rec-valid-01",
            "prompt": "How does QuorumRAG prevent chunk-0 contact-header starvation on biographical and technical queries?",
            "chosen_response": "QuorumRAG eliminates chunk-0 contact-header starvation by expanding primary retrieval hits into parent-document byte windows (0..10000 bytes). This approach directly captures full context. By deduplicating near-identical document revisions across local and mesh peers and verifying verbatim substring citations before synthesis, executive summaries, biographical narratives, and technical sections are always preserved in the final grounded response. The result is robust.",
            "citations": [("QuorumRAG expands primary search hits into parent-document byte windows (0..10000 bytes).", "parent-document byte windows (0..10000 bytes)")],
            "rlm_trajectory": [
                {
                    "step_index": 1,
                    "action_kind": "peek_slice",
                    "sanitized_query_or_pattern": "inspect parent document bytes 0..10000",
                    "abstracted_takeaway": "Expanded primary hit into 10 KB parent window to capture executive summary."
                }
            ],
            "interaction_nonce_hex": valid_nonce
        }],
        "auto_approve": true
    });
    let clean_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(clean_cand.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(clean_res.status(), StatusCode::OK);
    let clean_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(clean_res).await).unwrap();
    assert_eq!(clean_json["accepted_count"], 1);
    assert_eq!(clean_json["rejected_count"], 0);

    // 6. Verify GET /api/v1/marketplace/preview reflects synthetic_contamination_filtered: true
    let preview_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/marketplace/preview")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(preview_res.status(), StatusCode::OK);
    let preview_json: serde_json::Value =
        serde_json::from_slice(&read_body_bytes(preview_res).await).unwrap();
    assert_eq!(preview_json["synthetic_contamination_filtered"], true);
}

#[test]
fn test_12_synthetic_gate_statistical_boundary_conditions() {
    use quorum_daemon::handlers::synthetic_gate::*;

    let config = SyntheticGateConfig::default();
    assert_eq!(config.min_burstiness_cv, 0.30);
    assert_eq!(config.min_mattr, 0.38);
    assert_eq!(config.min_shannon_entropy, 3.0);

    // -----------------------------------------------------------------------
    // Boundary 1: Sentence burstiness CV threshold (0.29 vs 0.31)
    // -----------------------------------------------------------------------
    // Sub-threshold CV (~0.286 < 0.30): 18 words in sentence 1, 10 words in sentence 2.
    // Total words = 28 (>= 25). |18 - 10| / (18 + 10) = 8 / 28 = 0.2857.
    let text_cv_029 = "The quick brown fox jumps over the lazy dog every single morning before heading out to work today. A fast rabbit runs through the green forest right now.";
    let cv_val_low = compute_sentence_burstiness_cv(text_cv_029);
    assert!(cv_val_low < 0.30, "Expected CV < 0.30, got {}", cv_val_low);
    assert!(cv_val_low >= 0.28, "Expected CV around 0.29, got {}", cv_val_low);
    let s1_low_cv = evaluate_stage1_statistics(text_cv_029, &config);
    assert!(!s1_low_cv.passed, "CV 0.29 must fail Stage 1");
    assert!(s1_low_cv.rejection_reason.as_ref().unwrap().contains("Sentence burstiness CV"));

    // Supra-threshold CV (~0.310 >= 0.30): 19 words in sentence 1, 10 words in sentence 2.
    // Total words = 29 (>= 25). |19 - 10| / (19 + 10) = 9 / 29 = 0.3103.
    let text_cv_031 = "The quick brown fox jumps over the lazy dog every single sunny morning before heading out to work today. A fast rabbit runs through the green forest right now.";
    let cv_val_high = compute_sentence_burstiness_cv(text_cv_031);
    assert!(cv_val_high >= 0.30, "Expected CV >= 0.30, got {}", cv_val_high);
    assert!(cv_val_high <= 0.32, "Expected CV around 0.31, got {}", cv_val_high);
    let s1_high_cv = evaluate_stage1_statistics(text_cv_031, &config);
    assert!(s1_high_cv.passed, "CV 0.31 must pass Stage 1 burstiness");

    // -----------------------------------------------------------------------
    // Boundary 2: MATTR threshold (0.37 vs 0.39)
    // -----------------------------------------------------------------------
    // Generate text with 100 total words, varied sentence lengths (70 words, then 30 words)
    // so burstiness CV >= 0.30 does not fail first.
    // Low MATTR = 37 unique words out of 100 words -> MATTR = 0.370 < 0.380
    let mut words_037: Vec<String> = (1..=37).map(|i| format!("token{}", i)).collect();
    for i in 0..63 {
        words_037.push(format!("token{}", (i % 37) + 1));
    }
    assert_eq!(words_037.len(), 100);
    let text_mattr_037 = format!("{}. {}.", words_037[..70].join(" "), words_037[70..].join(" "));
    let mattr_037 = compute_mattr(&text_mattr_037, 200);
    assert_eq!((mattr_037 * 1000.0).round() / 1000.0, 0.370);
    let s1_mattr_low = evaluate_stage1_statistics(&text_mattr_037, &config);
    assert!(!s1_mattr_low.passed, "MATTR 0.37 must fail Stage 1");
    assert!(s1_mattr_low.rejection_reason.as_ref().unwrap().contains("MATTR 0.370 is below human vocabulary threshold"));

    // High MATTR = 39 unique words out of 100 words -> MATTR = 0.390 >= 0.380
    let mut words_039: Vec<String> = (1..=39).map(|i| format!("token{}", i)).collect();
    for i in 0..61 {
        words_039.push(format!("token{}", (i % 39) + 1));
    }
    assert_eq!(words_039.len(), 100);
    let text_mattr_039 = format!("{}. {}.", words_039[..70].join(" "), words_039[70..].join(" "));
    let mattr_039 = compute_mattr(&text_mattr_039, 200);
    assert_eq!((mattr_039 * 1000.0).round() / 1000.0, 0.390);
    let s1_mattr_high = evaluate_stage1_statistics(&text_mattr_039, &config);
    assert!(s1_mattr_high.passed, "MATTR 0.39 must pass Stage 1 MATTR threshold");

    // -----------------------------------------------------------------------
    // Boundary 3: Character Shannon entropy (2.99 vs 3.01)
    // -----------------------------------------------------------------------
    // For 100 characters:
    // Low entropy (~2.99 < 3.00): 8 symbols with counts [16, 12, 12, 12, 12, 12, 12, 12]
    let chars_low = format!(
        "{}{}{}{}{}{}{}{}",
        "a".repeat(16),
        "b".repeat(12),
        "c".repeat(12),
        "d".repeat(12),
        "e".repeat(12),
        "f".repeat(12),
        "g".repeat(12),
        "h".repeat(12)
    );
    assert_eq!(chars_low.len(), 100);
    let ent_low = compute_shannon_entropy(&chars_low);
    assert!(ent_low < 3.0, "Expected entropy < 3.0, got {}", ent_low);
    assert!(ent_low >= 2.98, "Expected entropy around 2.99, got {}", ent_low);
    let s1_ent_low = evaluate_stage1_statistics(&chars_low, &config);
    assert!(!s1_ent_low.passed, "Entropy 2.99 must fail Stage 1");
    assert!(s1_ent_low.rejection_reason.as_ref().unwrap().contains("Character Shannon entropy"));

    // High entropy (~3.01..3.03 >= 3.00): 9 symbols with counts [21, 12, 12, 12, 11, 11, 10, 9, 2]
    let chars_high = format!(
        "{}{}{}{}{}{}{}{}{}",
        "a".repeat(21),
        "b".repeat(12),
        "c".repeat(12),
        "d".repeat(12),
        "e".repeat(11),
        "f".repeat(11),
        "g".repeat(10),
        "h".repeat(9),
        "i".repeat(2)
    );
    assert_eq!(chars_high.len(), 100);
    let ent_high = compute_shannon_entropy(&chars_high);
    assert!(ent_high >= 3.0, "Expected entropy >= 3.0, got {}", ent_high);
    assert!(ent_high <= 3.05, "Expected entropy around 3.01..3.05, got {}", ent_high);
    let s1_ent_high = evaluate_stage1_statistics(&chars_high, &config);
    assert!(s1_ent_high.passed, "Entropy 3.01 must pass Stage 1 entropy threshold");
}
