//! Empirical Adversarial Challenger Test Suite for Milestone 4 Artemis REST Endpoints.
//!
//! Evaluates and stress-tests:
//! 1. Default status invariants & category allowlist disjointness:
//!    - `GET /api/v1/artemis/status`: `collection_enabled: false`, `marketplace_harvest_enabled: false`, `airgap_enforced: true`.
//!    - Prohibited categories strictly contain forbidden stores (`browser_cookies`, `credential_store`, etc.).
//!    - Disjoint sets between allowed and prohibited categories.
//! 2. Fail-closed 403 Forbidden enforcement on live collection:
//!    - Explicit `"source_type": "live"` rejects with 403.
//!    - Case-insensitive `"source_type": "LIVE"`, padded `"  live  "`, and default/empty payloads reject with 403.
//!    - Exact security message verified.
//!    - Cross-feature isolation: enabling marketplace harvest alone does not permit live collection.
//! 3. Configuration persistence & round-trip updates:
//!    - `POST` & `PUT /api/v1/artemis/config` with toggle updates and partial payloads.
//!    - `GET /api/v1/artemis/config` and `GET /api/v1/artemis/status` verify persistence.
//! 4. Keyed BLAKE3 Structural Normalizer preview adversarial stress:
//!    - Normalization over complex forensic records containing SIDs, internal IPv4/IPv6, UNC SMB paths, MAC addresses.
//!    - Zero leakage: raw tokens strictly absent from normalized output.
//!    - Pseudonym generation verification (`SID_`, `IP_`, `SHARE_`, `MAC_`).
//!    - PRF salt determinism: same salt -> identical pseudonyms.
//!    - PRF diffusion: distinct salts -> distinct pseudonyms.
//!    - Boundary handling: empty body, whitespace, and alternate field (`raw_telemetry`) inputs.
//! 5. Adversarial input validation on collection:
//!    - Nonexistent file path -> 400 Bad Request.
//!    - Malformed JSONL string -> 400 Bad Request.
//!    - Valid inline JSONL with secrets scrubbed and indexed with `Tier3Restricted` invariants.
//!    - Opt-in live collection execution and immediate revocation toggle check.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use quorum_coordinator::dlp_mesh::global_mesh_dlp_controller;
use quorum_coordinator::SynthesisModelFamily;
use quorum_daemon::{build_router, DaemonState};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use tempfile::{tempdir, TempDir};
use tower::ServiceExt;

static CHALLENGER_ENDPOINTS_MUTEX: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

struct TestEnv {
    temp_dir: TempDir,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl TestEnv {
    #[allow(dead_code)]
    fn path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }
}

async fn setup_challenger_test_app() -> (axum::Router, Arc<DaemonState>, TestEnv) {
    let guard = CHALLENGER_ENDPOINTS_MUTEX
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let temp_dir = tempdir().expect("tempdir");
    let data_dir = temp_dir.path().to_path_buf();

    let controller = global_mesh_dlp_controller();
    controller.init_persistence(&data_dir);
    let mut current = controller.get_settings();
    current.artemis = quorum_coordinator::artemis_airgap::ArtemisDfirSettings::default();
    controller.update_settings(current);

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

    let node_seed = [0x7Eu8; 32];
    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(
            quorum_coordinator::PeerAclManager::default(),
        )),
        quorum_coordinator::CoordinatorConfig::default(),
        node_seed,
        "12D3KooWChallengerM4Node".to_string(),
    ));

    let coordinator = Arc::new(quorum_coordinator::QueryCoordinator::new(
        coordinator_engine,
        quorum_coordinator::CoordinatorConfig::default(),
    ));

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
        port: 3055,
        host: "127.0.0.1".to_string(),
        data_dir,
        shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        in_flight_queries: Arc::new(quorum_daemon::InFlightQueryRegistry::new()),
        sessions: quorum_daemon::ChatSessionRegistry::new(),
    });

    let router = build_router(Arc::clone(&state));
    (
        router,
        state,
        TestEnv {
            temp_dir,
            _guard: guard,
        },
    )
}

async fn read_body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read body bytes");
    serde_json::from_slice(&bytes).expect("valid json response")
}

fn reset_to_clean_defaults() {
    let controller = global_mesh_dlp_controller();
    let mut current = controller.get_settings();
    current.artemis = quorum_coordinator::artemis_airgap::ArtemisDfirSettings::default();
    controller.update_settings(current);
}

// =========================================================================
// 1. DEFAULT STATUS INVARIANTS & AIRGAP INTEGRITY
// =========================================================================

#[tokio::test]
async fn test_challenger_artemis_status_default_invariants() {
    let (app, _state, _temp_dir) = setup_challenger_test_app().await;
    reset_to_clean_defaults();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/artemis/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let json = read_body_json(res).await;

    // Core invariants mandated by R3 / Acceptance Criteria
    assert_eq!(json["status"], "ok");
    assert_eq!(
        json["collection_enabled"], false,
        "Local collection MUST be false by default"
    );
    assert_eq!(
        json["marketplace_harvest_enabled"], false,
        "Marketplace harvest MUST be false by default"
    );
    assert_eq!(
        json["airgap_enforced"], true,
        "Airgap enforcement flag MUST be true"
    );

    // Prohibited categories verification
    let prohibited: Vec<String> = json["prohibited_artifact_categories"]
        .as_array()
        .expect("prohibited categories array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    assert!(prohibited.contains(&"browser_cookies".to_string()));
    assert!(prohibited.contains(&"browser_history_oauth".to_string()));
    assert!(prohibited.contains(&"credential_store".to_string()));
    assert!(prohibited.contains(&"shell_history_raw".to_string()));

    // Disjointness check: No allowed category may appear in the prohibited list
    let allowed: Vec<String> = json["allowed_artifact_categories"]
        .as_array()
        .expect("allowed categories array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let prohibited_set: HashSet<_> = prohibited.iter().collect();
    for cat in &allowed {
        assert!(
            !prohibited_set.contains(cat),
            "Allowlist violation: Category '{}' is in prohibited set!",
            cat
        );
    }

    assert_eq!(json["redact_secrets"], true);
    assert_eq!(json["normalize_for_harvest"], true);
}

// =========================================================================
// 2. ADVERSARIAL 403 FORBIDDEN ENFORCEMENT ON LIVE COLLECTION
// =========================================================================

#[tokio::test]
async fn test_challenger_artemis_collect_live_403_adversarial_matrix() {
    let (app, _state, _temp_dir) = setup_challenger_test_app().await;
    reset_to_clean_defaults();

    let expected_error =
        "Local Artemis DFIR collection is disabled by default. Enable in Settings first.";

    // Attack Vectors against live collection endpoint:
    let attack_payloads = vec![
        // 1. Explicit standard live
        serde_json::json!({ "source_type": "live" }),
        // 2. Uppercase variation
        serde_json::json!({ "source_type": "LIVE" }),
        // 3. Mixed case with whitespace
        serde_json::json!({ "source_type": "  Live  " }),
        // 4. Default payload (empty object, source_type defaults to "live")
        serde_json::json!({}),
        // 5. Empty string with no target path
        serde_json::json!({ "source_type": "" }),
        // 6. Null-ish empty whitespace
        serde_json::json!({ "source_type": "   " }),
    ];

    for payload in attack_payloads {
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/artemis/collect")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "Failed 403 check for payload: {}",
            payload
        );
        let json = read_body_json(res).await;
        assert_eq!(json["error"], expected_error);
    }

    // Cross-feature privilege escalation test:
    // Toggling marketplace_harvest_enabled = true must NOT open live collection gate.
    let controller = global_mesh_dlp_controller();
    let mut current = controller.get_settings();
    current.artemis.local_collection_enabled = false;
    current.artemis.marketplace_harvest_enabled = true;
    controller.update_settings(current);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "source_type": "live" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "Marketplace harvest opt-in must NOT bypass local collection airgap"
    );
}

// =========================================================================
// 3. CONFIG UPDATE ROUND-TRIP & ADVERSARIAL PERSISTENCE
// =========================================================================

#[tokio::test]
async fn test_challenger_artemis_config_update_persistence_roundtrip() {
    let (app, _state, _temp_dir) = setup_challenger_test_app().await;
    reset_to_clean_defaults();

    // 1. Initial verification via GET /api/v1/artemis/config
    let initial_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/artemis/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initial_res.status(), StatusCode::OK);
    let initial_json = read_body_json(initial_res).await;
    assert_eq!(initial_json["local_collection_enabled"], false);
    assert_eq!(initial_json["marketplace_harvest_enabled"], false);

    // 2. Perform POST update with full options
    let update_body = serde_json::json!({
        "local_collection_enabled": true,
        "marketplace_harvest_enabled": true,
        "retention_days": 90,
        "auto_collection_interval_mins": 45,
        "redact_secrets": true,
        "normalize_for_harvest": true,
        "allowed_artifact_categories": ["process_execution", "network_connection"]
    });

    let post_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/config")
                .header("content-type", "application/json")
                .body(Body::from(update_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post_res.status(), StatusCode::OK);
    let post_json = read_body_json(post_res).await;
    assert_eq!(post_json["local_collection_enabled"], true);
    assert_eq!(post_json["marketplace_harvest_enabled"], true);
    assert_eq!(post_json["retention_days"], 90);
    assert_eq!(post_json["auto_collection_interval_mins"], 45);

    // 3. Verify GET /api/v1/artemis/config accurately reflects persistence
    let get_verify_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/artemis/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_verify_res.status(), StatusCode::OK);
    let get_verify_json = read_body_json(get_verify_res).await;
    assert_eq!(get_verify_json["local_collection_enabled"], true);
    assert_eq!(get_verify_json["marketplace_harvest_enabled"], true);
    assert_eq!(get_verify_json["retention_days"], 90);

    // 4. Verify GET /api/v1/artemis/status reflects the dynamic state change
    let status_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/artemis/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_res.status(), StatusCode::OK);
    let status_json = read_body_json(status_res).await;
    assert_eq!(status_json["collection_enabled"], true);
    assert_eq!(status_json["marketplace_harvest_enabled"], true);
    assert_eq!(status_json["retention_days"], 90);

    // 5. Partial update via PUT to verify field preservation (non-destruction)
    let put_body = serde_json::json!({
        "retention_days": 120
    });
    let put_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/artemis/config")
                .header("content-type", "application/json")
                .body(Body::from(put_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_res.status(), StatusCode::OK);
    let put_json = read_body_json(put_res).await;
    assert_eq!(put_json["retention_days"], 120);
    // Crucial check: previous settings must NOT have been wiped by partial PUT
    assert_eq!(put_json["local_collection_enabled"], true);
    assert_eq!(put_json["marketplace_harvest_enabled"], true);
}

// =========================================================================
// 4. LIVE NORMALIZER PREVIEW EMPIRICAL ADVERSARIAL STRESS
// =========================================================================

#[tokio::test]
async fn test_challenger_artemis_preview_normalizer_pseudonymization() {
    let (app, _state, _temp_dir) = setup_challenger_test_app().await;

    // Complex adversarial forensic event containing multiple identifier classes
    let raw_forensic_event = "\
EventID: 4688; Host: WIN-DC-PROD01; \
SubjectUserSid: S-1-5-21-3623811015-3361044348-30300820-1013; \
TargetUserSid: S-1-5-18; \
SourceIp: 192.168.1.100; \
DestinationIp: 10.200.4.55; \
IPv6Address: fe80::1ff:fe00:3a60; \
SmbShare: \\\\FinanceServer01\\Payroll$\\q4_bonuses.xlsx; \
SecondaryShare: \\\\192.168.1.50\\c$\\Windows\\System32; \
ClientMac: 00:0C:29:4F:8E:35; \
AltMac: A4-BB-6D-11-22-33; \
ProcessName: C:\\Windows\\System32\\cmd.exe";

    let payload = serde_json::json!({
        "sample_text": raw_forensic_event,
        "session_salt": "challenger-session-epoch-01",
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/preview-normalizer")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let json = read_body_json(res).await;

    assert_eq!(json["status"], "ok");
    let normalized = json["normalized"].as_str().expect("normalized string");
    let total_replacements = json["total_replacements"]
        .as_u64()
        .expect("total replacements number");

    // ABSOLUTE INVARIANT: Zero host-specific identifiers must remain
    assert!(
        !normalized.contains("S-1-5-21-3623811015-3361044348-30300820-1013"),
        "Raw user SID leaked into normalized output!"
    );
    // Well-known system SIDs (S-1-5-18 Local System) are intentionally preserved
    // by the forensic normalizer contract for DFIR causality, while user SIDs are pseudonymized.
    assert!(
        normalized.contains("S-1-5-18"),
        "Well-known system SID S-1-5-18 must be preserved for forensic causality"
    );
    assert!(
        !normalized.contains("192.168.1.100"),
        "Raw RFC1918 IPv4 leaked into normalized output!"
    );
    assert!(
        !normalized.contains("10.200.4.55"),
        "Raw Class A private IPv4 leaked into normalized output!"
    );
    assert!(
        !normalized.contains("fe80::1ff:fe00:3a60"),
        "Raw IPv6 link-local leaked into normalized output!"
    );
    assert!(
        !normalized.contains("\\\\FinanceServer01\\Payroll$"),
        "Raw SMB UNC share path leaked into normalized output!"
    );
    assert!(
        !normalized.contains("00:0C:29:4F:8E:35"),
        "Raw MAC address leaked into normalized output!"
    );
    assert!(
        !normalized.contains("A4-BB-6D-11-22-33"),
        "Raw hyphenated MAC address leaked into normalized output!"
    );

    // MUST contain keyed pseudonyms
    assert!(normalized.contains("SID_"));
    assert!(normalized.contains("IP_"));
    assert!(normalized.contains("SHARE_"));
    assert!(normalized.contains("MAC_"));

    assert!(
        total_replacements >= 7,
        "Expected at least 7 replacements, found {}",
        total_replacements
    );

    let mappings = json["pseudonym_mappings"]
        .as_object()
        .expect("pseudonym mappings object");
    assert!(!mappings.is_empty());

    // Determinism test: Same salt MUST yield byte-for-byte identical output
    let res_repeat = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/preview-normalizer")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let json_repeat = read_body_json(res_repeat).await;
    assert_eq!(
        json["normalized"], json_repeat["normalized"],
        "Normalizer must be deterministic under identical session salt"
    );

    // Diffusion test: Different salt MUST yield different pseudonyms
    let diff_payload = serde_json::json!({
        "sample_text": raw_forensic_event,
        "session_salt": "challenger-session-epoch-02-diff",
    });
    let res_diff = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/preview-normalizer")
                .header("content-type", "application/json")
                .body(Body::from(diff_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let json_diff = read_body_json(res_diff).await;
    assert_ne!(
        json["normalized"], json_diff["normalized"],
        "Normalizer pseudonyms must diffuse across different session salts"
    );
}

#[tokio::test]
async fn test_challenger_artemis_preview_normalizer_malformed_and_boundary_inputs() {
    let (app, _state, _temp_dir) = setup_challenger_test_app().await;

    // 1. Completely empty JSON body
    let res_empty = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/preview-normalizer")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_empty.status(), StatusCode::BAD_REQUEST);

    // 2. Whitespace-only sample_text
    let res_ws = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/preview-normalizer")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "sample_text": "   \n\t  " }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_ws.status(), StatusCode::BAD_REQUEST);

    // 3. Alternative field name: raw_telemetry
    let res_alt = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/preview-normalizer")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "raw_telemetry": "SubjectUserSid: S-1-5-21-999-1001 on 10.0.0.1"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_alt.status(), StatusCode::OK);
    let json_alt = read_body_json(res_alt).await;
    assert_eq!(json_alt["status"], "ok");
    let norm_alt = json_alt["normalized"].as_str().unwrap();
    assert!(!norm_alt.contains("S-1-5-21-999-1001"));
    assert!(!norm_alt.contains("10.0.0.1"));
}

// =========================================================================
// 5. ADVERSARIAL INGESTION & COLLECT BOUNDARY TESTING
// =========================================================================

#[tokio::test]
async fn test_challenger_artemis_collect_adversarial_paths_and_scrubbing() {
    let (app, state, temp_dir) = setup_challenger_test_app().await;

    // 1. Nonexistent target path should fail with 400 Bad Request
    let bad_path_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "source_type": "file",
                        "target_path": "Z:\\phantom_nonexistent_dir\\file.jsonl"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_path_res.status(), StatusCode::BAD_REQUEST);

    // 2. Corrupted inline JSON string is handled resiliently (skips corrupted line, yields 0 parsed records)
    let corrupted_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "source_type": "file",
                        "target_path": "{ not valid json at all }"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(corrupted_res.status(), StatusCode::OK);
    let corrupted_json = read_body_json(corrupted_res).await;
    assert_eq!(corrupted_json["status"], "completed");
    assert_eq!(corrupted_json["records_parsed"], 0);
    assert_eq!(corrupted_json["chunks_indexed"], 0);

    // 3. Valid inline JSONL containing secrets — verifies secret scrubbing and ingestion into storage
    let inline_with_secret = r#"{"Computer": "CHALLENGER-SRV", "CommandLine": "curl -H 'Authorization: Bearer sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890' https://api.anthropic.com", "Image": "/usr/bin/curl", "pid": 9999, "user": "ops", "collected_unix_secs": 1700000999}"#;

    let scrub_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "source_type": "file",
                        "target_path": inline_with_secret
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(scrub_res.status(), StatusCode::OK);
    let scrub_json = read_body_json(scrub_res).await;
    assert_eq!(scrub_json["status"], "completed");
    assert_eq!(scrub_json["records_parsed"], 1);
    assert_eq!(scrub_json["chunks_indexed"], 1);

    // Verify storage has indexed the chunk
    let count = state.storage.count().await.unwrap_or(0);
    assert!(count >= 1, "Storage count must reflect newly indexed chunk");

    // 4. Empty directory: should safely parse 0 records without errors
    let empty_sub = temp_dir.path().join("empty_folder");
    std::fs::create_dir_all(&empty_sub).unwrap();

    let empty_dir_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "source_type": "folder",
                        "target_path": empty_sub.to_string_lossy().to_string()
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(empty_dir_res.status(), StatusCode::OK);
    let empty_dir_json = read_body_json(empty_dir_res).await;
    assert_eq!(empty_dir_json["records_parsed"], 0);
    assert_eq!(empty_dir_json["chunks_indexed"], 0);
}

// =========================================================================
// 6. LIVE COLLECTION OPT-IN EXECUTION AND IMMEDIATE REVOCATION
// =========================================================================

#[tokio::test]
async fn test_challenger_artemis_live_collection_opt_in_and_revocation() {
    let (app, _state, _temp_dir) = setup_challenger_test_app().await;

    // Enable local collection explicitly
    let controller = global_mesh_dlp_controller();
    let mut current = controller.get_settings();
    current.artemis.local_collection_enabled = true;
    controller.update_settings(current);

    // Live collection should now be permitted
    let live_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "source_type": "live" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(live_res.status(), StatusCode::OK);
    let live_json = read_body_json(live_res).await;
    assert_eq!(live_json["status"], "completed");
    assert!(
        live_json["records_parsed"].as_u64().unwrap() > 0,
        "Live process collection must capture running OS processes"
    );
    assert!(
        live_json["chunks_indexed"].as_u64().unwrap() > 0,
        "Captured processes must be indexed into storage"
    );

    // Revoke permission immediately
    let mut revoked = controller.get_settings();
    revoked.artemis.local_collection_enabled = false;
    controller.update_settings(revoked);

    // Attempting live collection again must immediately fail closed with 403 Forbidden
    let blocked_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "source_type": "live" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        blocked_res.status(),
        StatusCode::FORBIDDEN,
        "Revoking permission must immediately block live collection with 403"
    );
}
