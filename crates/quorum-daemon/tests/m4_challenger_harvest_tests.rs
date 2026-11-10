//! Empirical Adversarial Challenge Test Harness for Milestone 4
//! Marketplace Harvest Pipeline Integration (`m4_challenger_harvest_tests.rs`).
//!
//! Evaluates and empirically stress-tests:
//! 1. 100% rejection of prohibited artifact categories (`BrowserCookies`, `CredentialStore`,
//!    `BrowserHistoryOAuth`, `ShellHistoryRaw`) and sensitive artifact paths.
//! 2. Proper structural normalization of allowed defensive telemetry (`ProcessExecution`, `SystemEventLog`)
//!    via `ForensicStructuralNormalizer` before batch manifest signing.
//! 3. Clean segregation of mixed batches: allowlisted records staged into signed batch manifests while
//!    prohibited records are segregated into `rejected_candidates`.
//! 4. Case-insensitive and mixed-format category evasion attempts.
//! 5. Fail-closed opt-in enforcement and domestic-evasion network perimeter guards.
//! 6. Keyed session isolation across distinct harvest batches.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use quorum_coordinator::dlp_mesh::global_mesh_dlp_controller;
use quorum_coordinator::SynthesisModelFamily;
use quorum_daemon::{build_router, DaemonState};
use std::sync::Arc;
use std::time::Instant;
use tempfile::{tempdir, TempDir};
use tower::ServiceExt;

static CHALLENGER_HARVEST_MUTEX: std::sync::OnceLock<tokio::sync::Mutex<()>> =
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

/// Spins up an isolated test daemon with genuine SQLite storage, DLP controller, and router.
async fn setup_challenger_daemon_app() -> (axum::Router, Arc<DaemonState>, TestEnv) {
    let guard = CHALLENGER_HARVEST_MUTEX
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

    let node_seed = [0x7Cu8; 32];
    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(
            quorum_coordinator::PeerAclManager::default(),
        )),
        quorum_coordinator::CoordinatorConfig::default(),
        node_seed,
        "12D3KooWChallengerNodeM4".to_string(),
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
        port: 3042,
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
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .expect("read body bytes");
    serde_json::from_slice(&bytes).expect("valid json response")
}

fn decode_hex(hex_str: &str) -> Vec<u8> {
    let clean = hex_str.trim();
    (0..clean.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= clean.len() {
                u8::from_str_radix(&clean[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect()
}

async fn enable_marketplace_opt_in(app: &axum::Router) {
    let opt_in = app
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
                        "consent_statement": "Explicit consent for empirical challenger verification."
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(opt_in.status(), StatusCode::OK);
}

/// Helper that crafts a well-formed defensive trajectory meeting all quality & grounding invariants.
fn make_defensive_telemetry_candidate(
    record_id: &str,
    domain_tags: Vec<&str>,
    host: &str,
    user: &str,
    sid: &str,
    ip: &str,
    mac: &str,
    smb_share: &str,
) -> serde_json::Value {
    let slice_evidence = format!(
        "Security audit log recorded Computer: {host} process powershell.exe with PID 5120 spawned by cmd.exe PID 1040 under user User: {user} with SID {sid}. The process established socket communication with internal target {ip} over port 445 via MAC address {mac} and accessed network share {smb_share} to stage defensive triage scripts."
    );
    let quote_evidence = format!(
        "powershell.exe with PID 5120 spawned by cmd.exe PID 1040 under user User: {user} with SID {sid}"
    );

    let prompt = format!(
        "Perform deep forensic triage on Computer: {host} regarding anomalous process execution where cmd.exe spawned powershell.exe for user User: {user} with account identifier {sid}. The operator observed outbound traffic to private endpoint {ip} using physical interface {mac} and directory traversal across SMB location {smb_share}. Analyze the defensive telemetry and summarize investigation findings."
    );

    let chosen_response = format!(
        "Forensic analysis of the security log on Computer: {host} reveals that powershell.exe with PID 5120 spawned by cmd.exe PID 1040 under user User: {user} with SID {sid}. Socket telemetry connects the workstation to internal endpoint {ip} on port 445 through interface {mac}, mounting share {smb_share}. The execution pattern indicates administrative script automation rather than malicious adversary persistence. Verify parent execution lineage."
    );

    serde_json::json!({
        "record_id": record_id,
        "domain_tags": domain_tags,
        "prompt": prompt,
        "rlm_trajectory": [
            {
                "step_index": 1,
                "action_kind": "inspect_evtx",
                "sanitized_query_or_pattern": format!("find EventID 4688 on Computer: {host} for User: {user}"),
                "abstracted_takeaway": format!("Correlated process creation event with socket bind to {ip}")
            },
            {
                "step_index": 2,
                "action_kind": "verify_grounding",
                "sanitized_query_or_pattern": format!("slice_text.contains(quote) on {smb_share}"),
                "abstracted_takeaway": "Verified 100% verbatim grounding of process telemetry and SMB path"
            }
        ],
        "chosen_response": chosen_response,
        "citations": [
            [slice_evidence, quote_evidence]
        ],
        "source_file_path": "artemis://windows/eventlog/Security.evtx"
    })
}

/// Helper that crafts a candidate in a prohibited category.
fn make_prohibited_candidate(
    record_id: &str,
    prohibited_tag: &str,
    source_file_path: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "record_id": record_id,
        "domain_tags": [prohibited_tag],
        "prompt": "Extract session cookies, authentication tokens, and stored credentials from browser and operating system stores.",
        "rlm_trajectory": [
            {
                "step_index": 1,
                "action_kind": "sqlite_read",
                "sanitized_query_or_pattern": "SELECT name, encrypted_value FROM cookies",
                "abstracted_takeaway": "Extracted persistent user authentication session tokens"
            }
        ],
        "chosen_response": "Extracted session cookies and OAuth access tokens for local account authentication.",
        "citations": [
            ["Cookie database contains session tokens for active accounts.", "session tokens for active accounts"]
        ],
        "source_file_path": source_file_path.unwrap_or("artemis://browser/cookies/default")
    })
}

// -----------------------------------------------------------------------------
// Test 1: 100% Rejection of Prohibited Artifact Categories & Sensitive Paths
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_challenge_prohibited_categories_100_percent_rejected() {
    let (app, _state, _temp_dir) = setup_challenger_daemon_app().await;
    enable_marketplace_opt_in(&app).await;

    // Build a batch with 8 prohibited candidates spanning tags and sensitive path patterns
    let candidates = vec![
        make_prohibited_candidate("cand_cookie_01", "browser_cookies", None),
        make_prohibited_candidate("cand_cred_02", "credential_store", None),
        make_prohibited_candidate("cand_oauth_03", "browser_history_oauth", None),
        make_prohibited_candidate("cand_shell_04", "shell_history_raw", None),
        make_prohibited_candidate(
            "cand_path_chrome_cookie",
            "process_execution", // Allowed tag but prohibited path!
            Some("/Users/victim/Library/Application Support/Google/Chrome/Default/Cookies"),
        ),
        make_prohibited_candidate(
            "cand_path_etc_shadow",
            "process_execution",
            Some("/etc/shadow"),
        ),
        make_prohibited_candidate(
            "cand_path_win_sam",
            "system_event_log",
            Some("C:\\Windows\\System32\\config\\SAM"),
        ),
        make_prohibited_candidate(
            "cand_path_consolehost",
            "process_execution",
            Some("C:\\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"),
        ),
    ];

    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-prohibited-challenge-01",
                        "candidates": candidates
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Since all candidates are prohibited, zero records can be sanitized or staged -> 422 Unprocessable Entity
    assert_eq!(harvest_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = read_body_json(harvest_res).await;

    assert_eq!(json["accepted_count"], 0);
    assert_eq!(json["rejected_count"], 8);
    assert_eq!(json["approved"], false);
    assert!(json["manifest"].is_null());

    let rejected = json["rejected_candidates"].as_array().expect("rejected_candidates array");
    assert_eq!(rejected.len(), 8);

    let rejected_ids: Vec<&str> = rejected
        .iter()
        .map(|r| r["record_id"].as_str().unwrap())
        .collect();

    assert!(rejected_ids.contains(&"cand_cookie_01"));
    assert!(rejected_ids.contains(&"cand_cred_02"));
    assert!(rejected_ids.contains(&"cand_oauth_03"));
    assert!(rejected_ids.contains(&"cand_shell_04"));
    assert!(rejected_ids.contains(&"cand_path_chrome_cookie"));
    assert!(rejected_ids.contains(&"cand_path_etc_shadow"));
    assert!(rejected_ids.contains(&"cand_path_win_sam"));
    assert!(rejected_ids.contains(&"cand_path_consolehost"));

    // Every rejection reason must explicitly cite Category Gate or sensitive artifact paths
    for r in rejected {
        let reason = r["reason"].as_str().unwrap();
        assert!(
            reason.contains("Category Gate") || reason.contains("prohibited"),
            "Expected Category Gate rejection reason, got: {}",
            reason
        );
    }
}

// -----------------------------------------------------------------------------
// Test 2: Allowed Defensive Telemetry Normalization & Batch Manifest Signing
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_challenge_allowed_defensive_telemetry_normalization_and_manifest_signing() {
    let (app, state, _temp_dir) = setup_challenger_daemon_app().await;
    enable_marketplace_opt_in(&app).await;

    let raw_host = "CORP-SEC-DC01";
    let raw_user = "svc_netdefense";
    let raw_sid = "S-1-5-21-3623811015-3361044348-30300820-1013";
    let raw_ip = "192.168.1.55";
    let raw_mac = "00:1A:2B:3C:4D:5E";
    let raw_smb = "\\\\DomainController\\Sysvol";

    let candidate = make_defensive_telemetry_candidate(
        "cand_allowed_sec_01",
        vec!["process_execution", "system_event_log"],
        raw_host,
        raw_user,
        raw_sid,
        raw_ip,
        raw_mac,
        raw_smb,
    );

    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-allowed-norm-01",
                        "candidates": [candidate],
                        "auto_approve": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = harvest_res.status();
    let json = read_body_json(harvest_res).await;
    assert_eq!(status, StatusCode::OK);

    // Must be accepted, 0 rejected
    assert_eq!(json["accepted_count"], 1);
    assert_eq!(json["rejected_count"], 0);
    assert_eq!(json["approved"], true);

    let records = json["sanitized_records"].as_array().expect("sanitized_records");
    assert_eq!(records.len(), 1);
    let record = &records[0];

    let prompt = record["prompt"].as_str().unwrap();
    let chosen = record["chosen_response"].as_str().unwrap();

    // 1. Rigorous check: Raw host, user, SID, IP, MAC, and SMB share MUST be 100% absent!
    assert!(!prompt.contains(raw_host), "Raw hostname leaked in prompt: {prompt}");
    assert!(!prompt.contains(raw_user), "Raw username leaked in prompt: {prompt}");
    assert!(!prompt.contains(raw_sid), "Raw SID leaked in prompt: {prompt}");
    assert!(!prompt.contains(raw_ip), "Raw RFC1918 IP leaked in prompt: {prompt}");
    assert!(!prompt.contains(raw_mac), "Raw MAC address leaked in prompt: {prompt}");
    assert!(!prompt.contains(raw_smb), "Raw SMB share leaked in prompt: {prompt}");

    assert!(!chosen.contains(raw_host), "Raw hostname leaked in response: {chosen}");
    assert!(!chosen.contains(raw_user), "Raw username leaked in response: {chosen}");
    assert!(!chosen.contains(raw_sid), "Raw SID leaked in response: {chosen}");
    assert!(!chosen.contains(raw_ip), "Raw RFC1918 IP leaked in response: {chosen}");
    assert!(!chosen.contains(raw_mac), "Raw MAC address leaked in response: {chosen}");
    assert!(!chosen.contains(raw_smb), "Raw SMB share leaked in response: {chosen}");

    // 2. Pseudonyms derived from keyed BLAKE3 MUST be present in prompt and response
    assert!(prompt.contains("HOST_"), "Expected HOST_ pseudonym in prompt");
    assert!(prompt.contains("USER_"), "Expected USER_ pseudonym in prompt");
    assert!(prompt.contains("SID_"), "Expected SID_ pseudonym in prompt");
    assert!(prompt.contains("IP_"), "Expected IP_ pseudonym in prompt");
    assert!(prompt.contains("MAC_"), "Expected MAC_ pseudonym in prompt");
    assert!(prompt.contains("SHARE_"), "Expected SHARE_ pseudonym in prompt");

    // 3. Manifest must be signed with valid Ed25519 signature
    let manifest_val = &json["manifest"];
    assert!(!manifest_val.is_null());
    assert_eq!(manifest_val["sft_record_count"], 1);

    let pubkey_hex = manifest_val["origin_pubkey_hex"].as_str().expect("origin_pubkey_hex");
    let sig_hex = manifest_val["manifest_signature_hex"].as_str().expect("manifest_signature_hex");
    assert!(!sig_hex.is_empty(), "Manifest signature must not be empty");

    let pubkey_bytes = decode_hex(pubkey_hex);
    let sig_bytes = decode_hex(sig_hex);
    let verifying_key = VerifyingKey::from_bytes(pubkey_bytes[..32].try_into().unwrap())
        .expect("valid VerifyingKey");
    let signature = Signature::from_slice(&sig_bytes).expect("valid Signature struct");

    let store = state.marketplace_store().expect("marketplace store");
    let staged = store.load_batch(Some("batch-allowed-norm-01")).expect("load_batch ok");
    assert!(staged.is_some(), "Batch must be persisted in SQLite staged_batches");
    let (manifest, enc_bytes, approved) = staged.unwrap();
    assert!(approved, "Batch was marked auto-approved");
    assert_eq!(manifest.sft_record_count, 1);
    assert!(
        verifying_key.verify(&manifest.canonical_signing_bytes(), &signature).is_ok(),
        "Ed25519 manifest signature must cryptographically verify"
    );

    let decrypted = store
        .decrypt_batch_records("batch-allowed-norm-01", &enc_bytes)
        .expect("decrypt staged records");
    assert_eq!(decrypted.len(), 1);
    assert_eq!(decrypted[0].record_id, "cand_allowed_sec_01");
}

// -----------------------------------------------------------------------------
// Test 3: Mixed Batch Segregation (Allowlisted vs Prohibited)
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_challenge_mixed_batch_segregation() {
    let (app, state, _temp_dir) = setup_challenger_daemon_app().await;
    enable_marketplace_opt_in(&app).await;

    // 2 allowlisted defensive candidates
    let allowed_1 = make_defensive_telemetry_candidate(
        "cand_allow_proc_101",
        vec!["process_execution"],
        "WS-ALPHA",
        "admin_alice",
        "S-1-5-21-11111-1001",
        "10.10.1.10",
        "02:00:00:00:00:01",
        "\\\\FileShare\\ProcLogs",
    );
    let allowed_2 = make_defensive_telemetry_candidate(
        "cand_allow_syslog_102",
        vec!["system_event_log"],
        "WS-BETA",
        "analyst_bob",
        "S-1-5-21-22222-1002",
        "10.10.1.20",
        "02:00:00:00:00:02",
        "\\\\FileShare\\SysLogs",
    );

    // 4 prohibited candidates
    let prohibited_1 = make_prohibited_candidate("cand_prohib_cookie_201", "browser_cookies", None);
    let prohibited_2 = make_prohibited_candidate("cand_prohib_cred_202", "credential_store", None);
    let prohibited_3 = make_prohibited_candidate("cand_prohib_oauth_203", "browser_history_oauth", None);
    let prohibited_4 = make_prohibited_candidate("cand_prohib_shell_204", "shell_history_raw", None);

    let batch_req = serde_json::json!({
        "batch_id": "batch-mixed-segregation-01",
        "candidates": [
            allowed_1,
            prohibited_1,
            allowed_2,
            prohibited_2,
            prohibited_3,
            prohibited_4
        ],
        "auto_approve": true
    });

    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(batch_req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(harvest_res.status(), StatusCode::OK);
    let json = read_body_json(harvest_res).await;

    // Segregation assertion: exactly 2 accepted, 4 rejected
    assert_eq!(json["accepted_count"], 2);
    assert_eq!(json["rejected_count"], 4);

    let rejected = json["rejected_candidates"].as_array().expect("rejected_candidates");
    assert_eq!(rejected.len(), 4);

    let rejected_ids: Vec<&str> = rejected
        .iter()
        .map(|r| r["record_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        rejected_ids,
        vec![
            "cand_prohib_cookie_201",
            "cand_prohib_cred_202",
            "cand_prohib_oauth_203",
            "cand_prohib_shell_204"
        ]
    );

    let sanitized = json["sanitized_records"].as_array().expect("sanitized_records");
    assert_eq!(sanitized.len(), 2);
    let accepted_ids: Vec<&str> = sanitized
        .iter()
        .map(|r| r["record_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        accepted_ids,
        vec!["cand_allow_proc_101", "cand_allow_syslog_102"]
    );

    // Manifest must accurately reflect 2 staged records
    let manifest = json["manifest"].as_object().expect("manifest");
    assert_eq!(manifest["sft_record_count"], 2);

    // Verify database state: only the 2 sanitized records exist in staged_batches
    let store = state.marketplace_store().expect("marketplace store");
    let staged = store.load_batch(Some("batch-mixed-segregation-01")).expect("staged batch");
    assert!(staged.is_some());
    let (manifest_db, enc_bytes, _) = staged.unwrap();
    assert_eq!(manifest_db.sft_record_count, 2);

    let decrypted = store
        .decrypt_batch_records("batch-mixed-segregation-01", &enc_bytes)
        .expect("decrypt staged records");
    assert_eq!(decrypted.len(), 2);
    let dec_ids: Vec<&str> = decrypted.iter().map(|r| r.record_id.as_str()).collect();
    assert_eq!(dec_ids, vec!["cand_allow_proc_101", "cand_allow_syslog_102"]);
}

// -----------------------------------------------------------------------------
// Test 4: Case-Insensitive & Variant Evasion Tag Filtering
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_challenge_category_tag_evasion_variants() {
    let (app, _state, _temp_dir) = setup_challenger_daemon_app().await;
    enable_marketplace_opt_in(&app).await;

    let evasion_candidates = vec![
        make_prohibited_candidate("cand_evade_case_1", "BrowserCookies", None),
        make_prohibited_candidate("cand_evade_case_2", "CREDENTIAL_STORE", None),
        make_prohibited_candidate("cand_evade_case_3", "bRoWsEr_HiStOrY_oAuTh", None),
        make_prohibited_candidate("cand_evade_case_4", "  shell_history_raw  ", None),
        make_prohibited_candidate("cand_evade_case_5", "prefix_browser_cookies_suffix", None),
    ];

    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-evasion-test-01",
                        "candidates": evasion_candidates
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(harvest_res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let json = read_body_json(harvest_res).await;

    assert_eq!(json["accepted_count"], 0);
    assert_eq!(json["rejected_count"], 5);

    let rejected = json["rejected_candidates"].as_array().expect("rejected_candidates");
    assert_eq!(rejected.len(), 5);
}

// -----------------------------------------------------------------------------
// Test 5: Default Opt-In Fail-Closed & Network Security Gate
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_challenge_opt_in_disabled_default_fail_closed() {
    let (app, _state, _temp_dir) = setup_challenger_daemon_app().await;
    // Note: NOT calling enable_marketplace_opt_in here!

    let candidate = make_defensive_telemetry_candidate(
        "cand_should_fail_optin",
        vec!["process_execution"],
        "TEST-HOST",
        "test_user",
        "S-1-5-21-999-1001",
        "10.0.0.1",
        "00:11:22:33:44:55",
        "\\\\Share\\test.txt",
    );

    let harvest_res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "candidates": [candidate]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Must strictly fail closed with 403 Forbidden
    assert_eq!(harvest_res.status(), StatusCode::FORBIDDEN);
    let json = read_body_json(harvest_res).await;
    let err = json["error"].as_str().expect("error message");
    assert!(err.contains("opt_in_enabled = false") || err.contains("disabled by default"));
}

// -----------------------------------------------------------------------------
// Test 6: Cross-Batch Session Isolation of Normalizer Pseudonyms
// -----------------------------------------------------------------------------
#[tokio::test]
async fn test_challenge_session_scoped_normalizer_isolation() {
    let (app, _state, _temp_dir) = setup_challenger_daemon_app().await;
    enable_marketplace_opt_in(&app).await;

    let target_ip = "192.168.100.77";

    // Batch Alpha
    let cand_alpha = make_defensive_telemetry_candidate(
        "cand_alpha_01",
        vec!["process_execution"],
        "ALPHA-HOST",
        "admin_alpha",
        "S-1-5-21-777-1001",
        target_ip,
        "00:11:22:33:44:55",
        "\\\\AlphaShare\\Logs",
    );
    let res_alpha = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-alpha-session-01",
                        "candidates": [cand_alpha]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_alpha.status(), StatusCode::OK);
    let json_alpha = read_body_json(res_alpha).await;
    let prompt_alpha = json_alpha["sanitized_records"][0]["prompt"].as_str().unwrap();

    // Batch Beta
    let cand_beta = make_defensive_telemetry_candidate(
        "cand_beta_01",
        vec!["process_execution"],
        "BETA-HOST",
        "admin_beta",
        "S-1-5-21-888-1002",
        target_ip,
        "00:11:22:33:44:66",
        "\\\\BetaShare\\Logs",
    );
    let res_beta = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/marketplace/harvest")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "batch_id": "batch-beta-session-02",
                        "candidates": [cand_beta]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res_beta.status(), StatusCode::OK);
    let json_beta = read_body_json(res_beta).await;
    let prompt_beta = json_beta["sanitized_records"][0]["prompt"].as_str().unwrap();

    // Extract the IP_ pseudonyms from both prompts
    let extract_ip_pseudo = |text: &str| -> String {
        let idx = text.find("IP_").expect("IP_ pseudonym found");
        let end = text[idx..]
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .map(|offset| idx + offset)
            .unwrap_or(text.len());
        text[idx..end].to_string()
    };

    let pseudo_alpha = extract_ip_pseudo(prompt_alpha);
    let pseudo_beta = extract_ip_pseudo(prompt_beta);

    assert_ne!(
        pseudo_alpha, pseudo_beta,
        "Session isolation failure: Same IP mapped to identical pseudonym across different batch sessions! alpha={pseudo_alpha}, beta={pseudo_beta}"
    );
}
