//! Integration & Adversarial Tests for Milestone M3 (`daemon-service-and-api`, F15–F16).

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use quorum_daemon::handlers::cloud_drives::{
    collect_filtered_initial_watch_dirs, collect_pass0_priority_user_roots,
    effective_ingest_max_file_size_bytes, expand_physical_watch_paths,
};
use quorum_daemon::handlers::media::{
    authorize_media_path, authorize_media_path_with_loopback, validate_media_path_syntax,
    MediaPathError,
};
use quorum_daemon::handlers::settings::{
    is_safe_single_folder_name, is_service_or_system_profile_path,
};
use quorum_daemon::{build_router, ChatSessionRegistry, DaemonState, InFlightQueryRegistry};
use quorum_types::{CloudDrivesSettings, DocumentChunk};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tower::ServiceExt;

static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(ref val) = self.prev {
            std::env::set_var(self.key, val);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

async fn make_test_state(data_dir: &Path) -> Arc<DaemonState> {
    make_test_state_with_watch_paths(data_dir, quorum_ingest::IngestConfig::default().watch_paths)
        .await
}

async fn make_test_state_with_watch_paths(
    data_dir: &Path,
    watch_paths: Vec<std::path::PathBuf>,
) -> Arc<DaemonState> {
    let controller = quorum_coordinator::global_mesh_dlp_controller();
    controller.init_persistence(data_dir);
    let _ = controller.update_cloud_drives_settings(CloudDrivesSettings::default());

    let storage_config = quorum_storage::StorageConfig::new(data_dir.to_path_buf());
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(storage_config)
            .await
            .expect("storage open"),
    );
    let classifier = Arc::new(quorum_classifier::FileTypeClassifier::new());
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> =
        Arc::new(quorum_contract::DeterministicOfflineEngine::new());
    let dedup = Arc::new(quorum_ingest::TwoLevelDedupEngine::new());
    let mut ingest_config = quorum_ingest::IngestConfig::default();
    ingest_config.max_file_size_bytes = 50 * 1024 * 1024;
    ingest_config.watch_paths = watch_paths;

    let dlp_gate: Arc<dyn quorum_types::DlpContentGate> =
        Arc::clone(&controller) as Arc<dyn quorum_types::DlpContentGate>;
    let reindex_worker = Arc::new(
        quorum_ingest::ReindexWorker::new(
            ingest_config.clone(),
            Arc::clone(&storage),
            Arc::clone(&classifier),
            Arc::clone(&embedder),
            Arc::clone(&dedup),
        )
        .with_dlp_gate(Arc::clone(&dlp_gate)),
    );
    let drift_healer = Arc::new(
        quorum_ingest::DriftHealer::new(
            ingest_config.clone(),
            Arc::clone(&storage),
            Arc::clone(&classifier),
            Arc::clone(&embedder),
            Arc::clone(&dedup),
        )
        .with_dlp_gate(dlp_gate)
        .with_reindex_barrier(&reindex_worker),
    );

    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(
            quorum_coordinator::PeerAclManager::default(),
        )),
        quorum_coordinator::CoordinatorConfig::default(),
        [0u8; 32],
        "cloud_drives_test_node".to_string(),
    ));
    let coordinator = Arc::new(quorum_coordinator::QueryCoordinator::new(
        coordinator_engine,
        quorum_coordinator::CoordinatorConfig::default(),
    ));

    Arc::new(DaemonState {
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
        data_dir: data_dir.to_path_buf(),
        shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        in_flight_queries: Arc::new(InFlightQueryRegistry::new()),
        sessions: ChatSessionRegistry::new(),
    })
}

async fn send_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let req_builder = Request::builder().method(method).uri(uri);
    let req = if let Some(v) = body {
        req_builder
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap()
    } else {
        req_builder.body(Body::empty()).unwrap()
    };
    let resp = app.clone().oneshot(req).await.expect("router oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 2 * 1024 * 1024).await.unwrap();
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| json!({}));
    (status, parsed)
}

fn find_drive<'a>(payload: &'a Value, id: &str) -> &'a Value {
    payload["drives"]
        .as_array()
        .expect("drives array")
        .iter()
        .find(|d| d["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("drive '{id}' not found in {payload}"))
}

#[tokio::test]
async fn test_get_cloud_drives_dto_contract_and_onedrive_provider_serialization() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let onedrive = profile.join("OneDrive");
    std::fs::create_dir_all(&onedrive).unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(state);

    let (status, payload) = send_json(&app, "GET", "/api/cloud-drives", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        payload["placeholder_mode"].as_str(),
        Some("locally_synced_only")
    );
    assert_eq!(payload["hydration_max_file_size_mb"].as_u64(), Some(25));
    assert!(payload["running_as_local_system"].is_boolean());
    assert!(payload.get("virtual_drive_guidance").is_some());
    if payload["running_as_local_system"].as_bool() == Some(true) {
        assert!(!payload["virtual_drive_guidance"]
            .as_str()
            .unwrap_or("")
            .trim()
            .is_empty());
    }

    let od = find_drive(&payload, "onedrive_personal");
    assert_eq!(od["provider"].as_str(), Some("onedrive"));
    assert_eq!(od["enabled"].as_bool(), Some(false));
    assert_eq!(od["access_tier"].as_u64(), Some(3));
    assert_eq!(od["mounted"].as_bool(), Some(true));
    assert_eq!(od["status"].as_str(), Some("mounted"));
    assert_eq!(od["status_label"].as_str(), Some("Mounted"));
    assert_eq!(od["shared_with_mesh"].as_bool(), Some(false));
}

#[tokio::test]
async fn test_cloud_drives_config_validation_actions_and_hydration_bounds() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let dropbox = profile.join("Dropbox");
    let custom = tmp.path().join("CustomCloud");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&custom).unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(state);

    // Unknown action -> 400
    let (st_unk_act, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({ "action": "invalid_action", "id": "dropbox" })),
    )
    .await;
    assert_eq!(st_unk_act, StatusCode::BAD_REQUEST);

    // Unknown id -> 404
    let (st_unk_id, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({ "action": "toggle_drive", "id": "not_a_cloud", "enabled": false })),
    )
    .await;
    assert_eq!(st_unk_id, StatusCode::NOT_FOUND);

    // Invalid paths & tiers -> 400
    for bad_path in [
        r"C:\cloud\..\secret",
        r"C:\cloud\%2e%2e\secret",
        r"C:\cloud\%252e%252e\secret",
        r"\\evil-server\share\cloud",
        r"\\?\UNC\evil\share",
        r"C:\cloud\file.txt:ads",
        "relative/path",
        "C:\\cloud\\file\0.txt",
    ] {
        let (st, _) = send_json(
            &app,
            "POST",
            "/api/cloud-drives/config",
            Some(json!({ "action": "add_folder", "id": "dropbox", "path": bad_path })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "must reject {bad_path}");
    }

    let (st_tier4, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({ "action": "set_tier", "id": "dropbox", "access_tier": 4 })),
    )
    .await;
    assert_eq!(st_tier4, StatusCode::BAD_REQUEST);

    // Omitting hydration_max_file_size_mb preserves 25 MB default
    let (st_hyd, hyd_body) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({ "action": "set_hydration", "placeholder_mode": "hydrate_on_demand" })),
    )
    .await;
    assert_eq!(st_hyd, StatusCode::OK);
    assert_eq!(
        hyd_body["placeholder_mode"].as_str(),
        Some("hydrate_on_demand")
    );
    assert_eq!(hyd_body["hydration_max_file_size_mb"].as_u64(), Some(25));

    // Zero MB and u64::MAX fail closed with 400
    let (st_zero, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 0
        })),
    )
    .await;
    assert_eq!(st_zero, StatusCode::BAD_REQUEST);

    let (st_max, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": u64::MAX
        })),
    )
    .await;
    assert_eq!(st_max, StatusCode::BAD_REQUEST);

    // Enabling an unmounted drive with no existing paths fails closed with 409
    let (st_unmounted, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({ "action": "toggle_drive", "id": "icloud_drive", "enabled": true })),
    )
    .await;
    assert_eq!(st_unmounted, StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_disable_purges_and_tier_sync_clears_cache_and_updates_drift_healer() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let dropbox = profile.join("Dropbox");
    let custom_sib = tmp.path().join("CustomDropboxExtra");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&custom_sib).unwrap();
    let doc_root = dropbox.join("alpha.txt");
    let doc_custom = custom_sib.join("beta.txt");
    std::fs::write(&doc_root, "alpha cloud token").unwrap();
    std::fs::write(&doc_custom, "beta custom token").unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;

    let dim = state.storage.config().vector_dimension;
    let chunk1 = DocumentChunk::new(
        "c1",
        "d1",
        doc_root.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.1f32; dim],
        "alpha cloud token",
        None,
    )
    .unwrap();
    let chunk2 = DocumentChunk::new(
        "c2",
        "d2",
        doc_custom.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.2f32; dim],
        "beta custom token",
        None,
    )
    .unwrap();
    state
        .storage
        .insert_chunks(&[chunk1, chunk2])
        .await
        .unwrap();

    let app = build_router(Arc::clone(&state));

    // Enable dropbox & add custom_sib
    let (st_en, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "access_tier": 3,
            "root_path": dropbox.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_en, StatusCode::OK);
    let (st_add, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": custom_sib.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_add, StatusCode::OK);

    // Tier change 3 -> 0 syncs storage, DriftHealer, and clears cache
    let (st_tier, tier_resp) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({ "action": "set_tier", "id": "dropbox", "access_tier": 0 })),
    )
    .await;
    assert_eq!(st_tier, StatusCode::OK);
    assert_eq!(
        find_drive(&tier_resp, "dropbox")["access_tier"].as_u64(),
        Some(0)
    );
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&doc_root.to_string_lossy())
            .unwrap(),
        Some(0)
    );
    assert!(
        state
            .drift_healer
            .config_snapshot()
            .await
            .access_tier_rules
            .iter()
            .any(|(_, t)| *t == 0),
        "DriftHealer must receive live updated access_tier_rules"
    );

    // remove_folder purges only custom_sib while leaving root_path intact
    let (st_rem, rem_resp) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "remove_folder",
            "id": "dropbox",
            "path": custom_sib.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_rem, StatusCode::OK);
    assert_eq!(rem_resp["purged_files"].as_u64(), Some(1));
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&doc_custom.to_string_lossy())
            .unwrap(),
        None
    );
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&doc_root.to_string_lossy())
            .unwrap(),
        Some(0)
    );

    // Disable dropbox purges remaining root_path
    let (st_dis, dis_resp) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false })),
    )
    .await;
    assert_eq!(st_dis, StatusCode::OK);
    assert_eq!(dis_resp["purged_files"].as_u64(), Some(1));
    assert!(dis_resp["purged_chunks"].as_u64().unwrap_or(0) >= 1);
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&doc_root.to_string_lossy())
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn test_browse_folders_traversal_rejected_and_root_preserved() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    std::fs::create_dir_all(profile.join("Documents")).unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(state);

    let (st_root, root_json) = send_json(&app, "GET", "/api/fs/browse-folders?path=", None).await;
    assert_eq!(st_root, StatusCode::OK);
    assert_eq!(root_json["current_path"].as_str(), Some(""));
    let root_serialized = root_json.to_string().to_ascii_lowercase();
    assert!(!root_serialized.contains("systemprofile"));
    assert!(!root_serialized.contains("localservice"));
    assert!(!root_serialized.contains("networkservice"));
    assert!(!root_serialized.contains("pure rust"));

    for bad_q in [
        "/api/fs/browse-folders?path=C%3A%5C%2e%2e%5CWindows",
        "/api/fs/browse-folders?path=%5C%5Cattacker%5Cshare",
        "/api/fs/browse-folders?path=relative_dir",
    ] {
        let (st_bad, _) = send_json(&app, "GET", bad_q, None).await;
        assert_eq!(st_bad, StatusCode::BAD_REQUEST, "must reject {bad_q}");
    }
}

#[tokio::test]
async fn test_media_syntax_hardening_and_loopback_vs_remote_cloud_drive_gating() {
    let _lock = TEST_LOCK.lock().await;
    assert_eq!(
        validate_media_path_syntax(r"\\attacker\share\file.txt"),
        Err(MediaPathError::Invalid)
    );
    assert_eq!(
        validate_media_path_syntax("//attacker/share/file.txt"),
        Err(MediaPathError::Invalid)
    );
    assert_eq!(
        validate_media_path_syntax(r"\\?\UNC\server\share\file.txt"),
        Err(MediaPathError::Invalid)
    );
    assert_eq!(
        validate_media_path_syntax(r"C:\safe\%252e%252e\secret.txt"),
        Err(MediaPathError::Invalid)
    );
    assert_eq!(
        validate_media_path_syntax("artemis://telemetry/process/1"),
        Err(MediaPathError::Invalid)
    );
    assert_eq!(
        validate_media_path_syntax("C:\\safe\\file.\u{202E}txt"),
        Err(MediaPathError::Invalid)
    );
    assert_eq!(
        validate_media_path_syntax(r"C:\safe\trailing."),
        Err(MediaPathError::Invalid)
    );

    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let dropbox = profile.join("Dropbox");
    std::fs::create_dir_all(&dropbox).unwrap();
    let cloud_file = dropbox.join("local_only.txt");
    std::fs::write(&cloud_file, "tier3 local cloud").unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let dim = state.storage.config().vector_dimension;
    let chunk = DocumentChunk::new(
        "mc1",
        "md1",
        cloud_file.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.3f32; dim],
        "tier3 local cloud",
        None,
    )
    .unwrap();
    state.storage.insert_chunks(&[chunk]).await.unwrap();

    let app = build_router(Arc::clone(&state));
    let (st_en, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "access_tier": 3,
            "root_path": dropbox.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_en, StatusCode::OK);

    // Enabled local-only cloud drive permitted on loopback, denied non-loopback
    assert!(
        authorize_media_path_with_loopback(&state, &cloud_file.to_string_lossy(), true).is_ok()
    );
    assert_eq!(
        authorize_media_path(&state, &cloud_file.to_string_lossy()),
        Err(MediaPathError::TierDenied)
    );

    // Disabled cloud drive denied even on loopback
    let (st_dis, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({ "action": "toggle_drive", "id": "dropbox", "enabled": false })),
    )
    .await;
    assert_eq!(st_dis, StatusCode::OK);
    assert_eq!(
        authorize_media_path_with_loopback(&state, &cloud_file.to_string_lossy(), true),
        Err(MediaPathError::TierDenied)
    );

    // artemis:// URIs fail closed with TierDenied (403) unless lexical/traversal invalid (400)
    assert_eq!(
        authorize_media_path_with_loopback(&state, "artemis://windows/eventlog/security", true),
        Err(MediaPathError::TierDenied)
    );
    assert_eq!(
        authorize_media_path_with_loopback(&state, "artemis://../secret", true),
        Err(MediaPathError::Invalid)
    );
}

#[tokio::test]
async fn test_relay_endpoint_loopback_path_validation_and_hermetic_override() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(Arc::clone(&state));

    // Non-loopback ConnectInfo -> 403
    let mut remote_req = Request::builder()
        .method("POST")
        .uri("/api/cloud-drives/relay/register")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "session_id": 1,
                "drives": [{ "id": "google_drive", "provider": "google_drive", "root_path": "G:\\My Drive", "virtual_drive": true, "readable": true }]
            })
            .to_string(),
        ))
        .unwrap();
    remote_req.extensions_mut().insert(ConnectInfo(
        "192.168.1.50:55555".parse::<SocketAddr>().unwrap(),
    ));
    let remote_resp = app.clone().oneshot(remote_req).await.unwrap();
    assert_eq!(remote_resp.status(), StatusCode::FORBIDDEN);

    // Invalid path in relay -> 400
    let (st_bad, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/relay/register",
        Some(json!({
            "session_id": 1,
            "drives": [{ "id": "google_drive", "provider": "google_drive", "root_path": "\\\\evil\\share", "virtual_drive": true, "readable": true }]
        })),
    )
    .await;
    assert_eq!(st_bad, StatusCode::BAD_REQUEST);

    // Hermetic override rejects relay registration and suppresses active_cloud_drive_relay
    let profile = tmp.path().join("Profile");
    std::fs::create_dir_all(&profile).unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );
    let (st_override, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/relay/register",
        Some(json!({
            "session_id": 1,
            "drives": [{ "id": "google_drive", "provider": "google_drive", "root_path": "G:\\My Drive", "virtual_drive": true, "readable": true }]
        })),
    )
    .await;
    assert_eq!(st_override, StatusCode::FORBIDDEN);
    assert!(state
        .active_cloud_drive_relay(Duration::from_secs(60))
        .is_none());
}

#[cfg(windows)]
#[tokio::test]
async fn test_win_native_local_system_sid_and_hermetic_session_probe() {
    let _lock = TEST_LOCK.lock().await;
    assert!(quorum_daemon::win_native::is_local_system_sid_str(
        "S-1-5-18"
    ));
    assert!(quorum_daemon::win_native::is_local_system_sid_str(
        " s-1-5-18 "
    ));
    assert!(!quorum_daemon::win_native::is_local_system_sid_str(
        "S-1-5-21-1000"
    ));

    assert_eq!(
        quorum_daemon::win_native::normalize_virtual_drive_mount_hint("G", Some("My Drive"))
            .as_deref(),
        Some(r"G:\My Drive")
    );
    assert_eq!(
        quorum_daemon::win_native::normalize_virtual_drive_mount_hint("G:\\", Some("My Drive"))
            .as_deref(),
        Some(r"G:\My Drive")
    );
    assert_eq!(
        quorum_daemon::win_native::normalize_virtual_drive_mount_hint("P:", None).as_deref(),
        Some(r"P:\")
    );
    assert_eq!(
        quorum_daemon::win_native::normalize_virtual_drive_mount_hint(r"\\evil\share", None),
        None
    );

    let _ = quorum_daemon::win_native::is_running_as_local_system();
    assert!(quorum_daemon::win_native::current_session_id().is_some());

    let tmp = tempdir().unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        tmp.path().to_string_lossy().as_ref(),
    );
    let probe = quorum_daemon::win_native::detect_interactive_session_virtual_drives();
    assert_eq!(probe.active_interactive_sessions, 0);
    assert!(probe.hints.is_empty());
}

#[tokio::test]
async fn test_remove_folder_unconfigured_returns_404_and_preserves_unrelated_docs() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let dropbox = profile.join("Dropbox");
    let local_docs = tmp.path().join("Documents");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&local_docs).unwrap();
    let doc_local = local_docs.join("notes.txt");
    std::fs::write(&doc_local, "local user notes").unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let dim = state.storage.config().vector_dimension;
    let local_chunk = DocumentChunk::new(
        "lc1",
        "ld1",
        doc_local.to_string_lossy().to_string(),
        1,
        1,
        0,
        vec![0.1f32; dim],
        "local user notes",
        None,
    )
    .unwrap();
    state.storage.insert_chunks(&[local_chunk]).await.unwrap();

    let app = build_router(Arc::clone(&state));
    let (st_en, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": dropbox.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_en, StatusCode::OK);

    // Unconfigured path -> 404 Not Found and 0 documents purged
    let (st_404, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "remove_folder",
            "id": "dropbox",
            "path": local_docs.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_404, StatusCode::NOT_FOUND);
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&doc_local.to_string_lossy())
            .unwrap(),
        Some(0)
    );

    let root_probe = if cfg!(windows) { r"C:\" } else { "/" };
    let (st_root_404, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "remove_folder",
            "id": "dropbox",
            "path": root_probe
        })),
    )
    .await;
    assert_eq!(st_root_404, StatusCode::NOT_FOUND);
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&doc_local.to_string_lossy())
            .unwrap(),
        Some(0)
    );
}

#[tokio::test]
async fn test_remove_folder_ancestor_of_active_root_preserves_active_child() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let cloud_parent = tmp.path().join("CloudParent");
    let child_dropbox = cloud_parent.join("Dropbox");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::create_dir_all(&child_dropbox).unwrap();
    let child_doc = child_dropbox.join("active_child.txt");
    std::fs::write(&child_doc, "active child content").unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let dim = state.storage.config().vector_dimension;
    let child_chunk = DocumentChunk::new(
        "cc1",
        "cd1",
        child_doc.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.2f32; dim],
        "active child content",
        None,
    )
    .unwrap();
    state.storage.insert_chunks(&[child_chunk]).await.unwrap();

    let app = build_router(Arc::clone(&state));
    let (st_en, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": child_dropbox.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_en, StatusCode::OK);

    let (st_add, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": cloud_parent.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_add, StatusCode::OK);

    // Removing the ancestor folder must NOT delete active child `CloudParent\Dropbox` chunks
    let (st_rem, rem_resp) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "remove_folder",
            "id": "dropbox",
            "path": cloud_parent.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_rem, StatusCode::OK);
    assert_eq!(rem_resp["purged_files"].as_u64(), Some(0));
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&child_doc.to_string_lossy())
            .unwrap(),
        Some(3)
    );
}

#[tokio::test]
async fn test_toggle_drive_normalized_root_and_disable_ignores_arbitrary_root() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let dropbox = profile.join("Dropbox");
    let unrelated = tmp.path().join("UnrelatedDocs");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&unrelated).unwrap();
    let doc_dropbox = dropbox.join("keep.txt");
    let doc_unrelated = unrelated.join("safe.txt");
    std::fs::write(&doc_dropbox, "dropbox keep").unwrap();
    std::fs::write(&doc_unrelated, "unrelated safe").unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let dim = state.storage.config().vector_dimension;
    let c1 = DocumentChunk::new(
        "tc1",
        "td1",
        doc_dropbox.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.1f32; dim],
        "dropbox keep",
        None,
    )
    .unwrap();
    let c2 = DocumentChunk::new(
        "tc2",
        "td2",
        doc_unrelated.to_string_lossy().to_string(),
        1,
        1,
        0,
        vec![0.2f32; dim],
        "unrelated safe",
        None,
    )
    .unwrap();
    state.storage.insert_chunks(&[c1, c2]).await.unwrap();

    let app = build_router(Arc::clone(&state));
    let (st_en, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": dropbox.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_en, StatusCode::OK);

    // Slash/trailing-slash/case variant on Windows must NOT trigger a purge
    let variant_root = if cfg!(windows) {
        format!(
            "{}/",
            dropbox
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_uppercase()
        )
    } else {
        format!("{}/", dropbox.to_string_lossy())
    };
    let (st_var, var_resp) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": true,
            "root_path": variant_root
        })),
    )
    .await;
    assert_eq!(st_var, StatusCode::OK);
    assert!(var_resp.get("purged_files").is_none());
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&doc_dropbox.to_string_lossy())
            .unwrap(),
        Some(3)
    );

    // Disabling with an unrelated `root_path` must ignore it and only purge prior drive paths
    let (st_dis, dis_resp) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "toggle_drive",
            "id": "dropbox",
            "enabled": false,
            "root_path": unrelated.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_dis, StatusCode::OK);
    assert_eq!(dis_resp["purged_files"].as_u64(), Some(1));
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&doc_dropbox.to_string_lossy())
            .unwrap(),
        None
    );
    assert_eq!(
        state
            .storage
            .indexed_path_min_tier(&doc_unrelated.to_string_lossy())
            .unwrap(),
        Some(0)
    );
}

#[tokio::test]
async fn test_drives_array_fallback_accepts_onedrive_and_validates_mounted_dir() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let onedrive = profile.join("OneDrive");
    std::fs::create_dir_all(&onedrive).unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(state);

    let (st_get, get_payload) = send_json(&app, "GET", "/api/cloud-drives", None).await;
    assert_eq!(st_get, StatusCode::OK);

    // Round-trip `drives` array containing `"provider": "onedrive"` enabling mounted OneDrive
    let mut drives_arr = get_payload["drives"].as_array().unwrap().clone();
    for d in &mut drives_arr {
        if d["id"].as_str() == Some("onedrive_personal") {
            assert_eq!(d["provider"].as_str(), Some("onedrive"));
            d["enabled"] = json!(true);
        }
    }
    let (st_post_ok, post_ok_body) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({ "drives": drives_arr })),
    )
    .await;
    assert_eq!(st_post_ok, StatusCode::OK);
    assert_eq!(
        find_drive(&post_ok_body, "onedrive_personal")["enabled"].as_bool(),
        Some(true)
    );

    // Enabling an unmounted drive via `drives` fallback fails closed with 409 Conflict
    let (st_conflict, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "drives": [{
                "id": "icloud_drive",
                "provider": "icloud_drive",
                "label": "iCloud Drive",
                "enabled": true,
                "root_path": null,
                "custom_paths": [],
                "access_tier": 3
            }]
        })),
    )
    .await;
    assert_eq!(st_conflict, StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_media_mixed_mount_unmounted_root_fails_closed_403() {
    let _lock = TEST_LOCK.lock().await;
    assert_eq!(
        validate_media_path_syntax("  C:\\safe\\file.txt  "),
        Err(MediaPathError::Invalid)
    );
    let overlong = format!("C:\\{}", "a".repeat(4100));
    assert_eq!(
        validate_media_path_syntax(&overlong),
        Err(MediaPathError::Invalid)
    );

    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let unmounted_root = tmp.path().join("UnmountedDropbox");
    let mounted_custom = tmp.path().join("MountedCustom");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::create_dir_all(&mounted_custom).unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let target_file = unmounted_root.join("doc.txt");
    let dim = state.storage.config().vector_dimension;
    let chunk = DocumentChunk::new(
        "mmc1",
        "mmd1",
        target_file.to_string_lossy().to_string(),
        1,
        1,
        3,
        vec![0.1f32; dim],
        "unmounted root doc",
        None,
    )
    .unwrap();
    state.storage.insert_chunks(&[chunk]).await.unwrap();

    let controller = quorum_coordinator::global_mesh_dlp_controller();
    let mut cfg = controller.get_cloud_drives_settings();
    cfg.drives.push(quorum_types::CloudDriveConfigEntry {
        id: "dropbox".to_string(),
        provider: quorum_types::CloudDriveProvider::Dropbox,
        label: "Dropbox".to_string(),
        enabled: true,
        root_path: Some(unmounted_root.to_string_lossy().to_string()),
        custom_paths: vec![mounted_custom.to_string_lossy().to_string()],
        access_tier: 3,
        account_kind: None,
    });
    controller.update_cloud_drives_settings(cfg).unwrap();

    assert_eq!(
        authorize_media_path_with_loopback(&state, &target_file.to_string_lossy(), true),
        Err(MediaPathError::TierDenied)
    );
}

#[tokio::test]
async fn test_settings_subfolder_and_service_profile_hardening_plus_hermetic_browse() {
    let _lock = TEST_LOCK.lock().await;
    assert!(!is_safe_single_folder_name("folder."));
    assert!(!is_safe_single_folder_name("sub\u{202E}txt"));
    assert!(!is_safe_single_folder_name("sub\x07dir"));
    assert!(!is_safe_single_folder_name("folder\n"));
    assert!(is_safe_single_folder_name("MyCloudFolder"));

    assert!(is_service_or_system_profile_path(r"C:\Temp\LocalService"));
    assert!(is_service_or_system_profile_path(r"C:\Temp\NetworkService"));
    assert!(is_service_or_system_profile_path(r"C:\Temp\Public"));
    assert!(is_service_or_system_profile_path(
        r"C:\Users\Public\Documents"
    ));

    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    std::fs::create_dir_all(profile.join("Documents")).unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(state);

    // Host physical drives must be suppressed under QUORUM_CLOUD_TEST_PROFILE_DIR
    let (st_root, root_json) = send_json(&app, "GET", "/api/fs/browse-folders?path=", None).await;
    assert_eq!(st_root, StatusCode::OK);
    assert_eq!(root_json["drives"].as_array().map(|a| a.len()), Some(0));

    // Trailing dot subfolder creation must be rejected with 400
    let profile_enc = profile.to_string_lossy().replace('\\', "%5C");
    let (st_dot, _) = send_json(
        &app,
        "GET",
        &format!("/api/fs/browse-folders?path={profile_enc}&create_subfolder=MyCloudFolder."),
        None,
    )
    .await;
    assert_eq!(st_dot, StatusCode::BAD_REQUEST);
}

#[test]
fn test_expand_physical_watch_paths_depth2_disabled_cloud_and_hydration_cap() {
    let tmp = tempdir().unwrap();
    let mock_drive = tmp.path().join("mock_drive_depth2");
    let work = mock_drive.join("Work");
    let disabled_dropbox = work.join("MyDisabledDropbox");
    let sibling = work.join("OtherProjects");
    std::fs::create_dir_all(&disabled_dropbox).unwrap();
    std::fs::create_dir_all(&sibling).unwrap();
    std::fs::write(disabled_dropbox.join("secret.txt"), "do not index").unwrap();
    std::fs::write(sibling.join("notes.txt"), "keep sibling").unwrap();

    let disabled_list = vec![disabled_dropbox.to_string_lossy().to_string()];
    let watch_paths = expand_physical_watch_paths(&[mock_drive.clone()], &disabled_list);

    assert!(
        watch_paths.contains(&sibling),
        "Sibling folder must remain watched: {watch_paths:?}"
    );
    assert!(
        !watch_paths.contains(&work),
        "Ancestor folder must be split rather than watched wholesale: {watch_paths:?}"
    );
    assert!(
        !watch_paths.contains(&disabled_dropbox),
        "Depth-2 disabled cloud root must NOT be watched: {watch_paths:?}"
    );

    let mut cfg = CloudDrivesSettings::default();
    assert_eq!(effective_ingest_max_file_size_bytes(&cfg), 50 * 1024 * 1024);
    cfg.hydration_max_file_size_mb = 100;
    assert_eq!(
        effective_ingest_max_file_size_bytes(&cfg),
        100 * 1024 * 1024
    );
}

#[tokio::test]
async fn test_runtime_hydration_cap_above_50mb_updates_workers_without_restart() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    std::fs::create_dir_all(&profile).unwrap();
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(Arc::clone(&state));

    let (st_raise, body_raise) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "set_hydration",
            "placeholder_mode": "hydrate_on_demand",
            "hydration_max_file_size_mb": 100
        })),
    )
    .await;
    assert_eq!(st_raise, StatusCode::OK);
    assert_eq!(
        state
            .reindex_worker
            .config_snapshot()
            .await
            .max_file_size_bytes,
        100 * 1024 * 1024
    );
    assert_eq!(
        state
            .drift_healer
            .config_snapshot()
            .await
            .max_file_size_bytes,
        100 * 1024 * 1024
    );
    assert!(
        body_raise
            .get("restart_required_for_cap_above_50mb")
            .is_none(),
        "Runtime >50 MB hydration cap must apply without restart: {body_raise}"
    );

    let (st_status, body_status) = send_json(&app, "GET", "/api/cloud-drives", None).await;
    assert_eq!(st_status, StatusCode::OK);
    assert!(body_status
        .get("restart_required_for_cap_above_50mb")
        .is_none());

    let (st_lower, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "set_hydration",
            "placeholder_mode": "locally_synced_only",
            "hydration_max_file_size_mb": 25
        })),
    )
    .await;
    assert_eq!(st_lower, StatusCode::OK);
    assert_eq!(
        state
            .reindex_worker
            .config_snapshot()
            .await
            .max_file_size_bytes,
        50 * 1024 * 1024
    );
    assert_eq!(
        state
            .drift_healer
            .config_snapshot()
            .await
            .max_file_size_bytes,
        50 * 1024 * 1024
    );
}

#[test]
fn test_initial_watch_dirs_and_pass0_exclude_disabled_nested_cloud_roots() {
    let tmp = tempdir().unwrap();
    let docs = tmp.path().join("Documents");
    let desktop = tmp.path().join("Desktop");
    let pictures = tmp.path().join("Pictures");
    let local_notes = docs.join("LocalNotes");
    let disabled_cloud = docs.join("MyDisabledCloud");
    let disabled_custom = pictures.join("DisabledCustomCloud");
    let shared_parent = tmp.path().join("SharedParent");
    let shared_local = shared_parent.join("TeamDocs");
    let disabled_in_shared = shared_parent.join("DisabledCloudInShared");

    for d in [
        &local_notes,
        &disabled_cloud,
        &desktop,
        &disabled_custom,
        &shared_local,
        &disabled_in_shared,
    ] {
        std::fs::create_dir_all(d).unwrap();
    }

    let disabled_roots = vec![
        disabled_cloud.to_string_lossy().to_string(),
        disabled_custom.to_string_lossy().to_string(),
        disabled_in_shared.to_string_lossy().to_string(),
    ];
    let user_roots = vec![pictures.clone(), desktop.clone(), docs.clone()];

    let pass0 = collect_pass0_priority_user_roots(&user_roots, None, &disabled_roots);
    assert!(!pass0.contains(&docs), "Documents must be split: {pass0:?}");
    assert!(
        !pass0.contains(&pictures),
        "Pictures must be split: {pass0:?}"
    );
    assert!(
        !pass0.contains(&disabled_cloud) && !pass0.contains(&disabled_custom),
        "Disabled nested cloud roots must be excluded from Pass 0: {pass0:?}"
    );
    assert!(
        pass0.contains(&local_notes),
        "Sibling LocalNotes kept: {pass0:?}"
    );
    assert!(pass0.contains(&desktop), "Desktop kept: {pass0:?}");
    let notes_idx = pass0.iter().position(|p| p == &local_notes).unwrap();
    let desktop_idx = pass0.iter().position(|p| p == &desktop).unwrap();
    assert!(
        notes_idx < desktop_idx,
        "Documents must precede Desktop in Pass 0"
    );

    let initial = collect_filtered_initial_watch_dirs(
        &user_roots,
        None,
        &[shared_parent.clone()],
        &[],
        &[],
        &[],
        &disabled_roots,
    );
    assert!(!initial.contains(&docs));
    assert!(!initial.contains(&shared_parent));
    assert!(!initial.contains(&disabled_cloud));
    assert!(!initial.contains(&disabled_custom));
    assert!(!initial.contains(&disabled_in_shared));
    assert!(initial.contains(&local_notes));
    assert!(initial.contains(&desktop));
    assert!(initial.contains(&shared_local));
}

#[tokio::test]
async fn test_rapid_toggle_enable_disable_drains_reindex_and_leaves_zero_chunks() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let dropbox = profile.join("Dropbox");
    std::fs::create_dir_all(&dropbox).unwrap();
    for i in 0..8 {
        std::fs::write(
            dropbox.join(format!("rapid_{i}.txt")),
            format!("TOKEN_RAPID_DAEMON_DRAIN_{i} synthetic rapid toggle document"),
        )
        .unwrap();
    }
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(Arc::clone(&state));

    for cycle in 0..3 {
        let (st_en, _) = send_json(
            &app,
            "POST",
            "/api/cloud-drives/config",
            Some(json!({
                "action": "toggle_drive",
                "id": "dropbox",
                "enabled": true,
                "root_path": dropbox.to_string_lossy()
            })),
        )
        .await;
        assert_eq!(st_en, StatusCode::OK, "enable failed on cycle {cycle}");

        let (st_dis, _) = send_json(
            &app,
            "POST",
            "/api/cloud-drives/config",
            Some(json!({
                "action": "toggle_drive",
                "id": "dropbox",
                "enabled": false
            })),
        )
        .await;
        assert_eq!(st_dis, StatusCode::OK, "disable failed on cycle {cycle}");
    }

    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    let remaining = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        remaining.is_empty(),
        "Rapid enable/disable cycles must drain reindex and leave 0 chunks in storage, found {}",
        remaining.len()
    );
    assert!(
        state.dedup.get_all_tracked_files().is_empty(),
        "Rapid enable/disable cycles must leave 0 tracked files in dedup catalog"
    );
}

#[tokio::test]
async fn test_relay_registration_and_session_only_status_transition_hermetic() {
    use quorum_daemon::handlers::cloud_drives::{
        build_cloud_drives_status_response_with_context, CloudDrivesStatusRuntimeContext,
    };
    use quorum_ingest::cloud_drives::DiscoveredCloudDrive;
    use quorum_types::{CloudDriveMountStatus, CloudDriveProvider};

    let _lock = TEST_LOCK.lock().await;
    let _env = EnvGuard::set("QUORUM_CLOUD_TEST_PROFILE_DIR", "");

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    ctrl.update_settings(Default::default());

    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(Arc::clone(&state));

    // Loopback POST /api/cloud-drives/relay/register -> 200 OK
    let (st_ok, body_ok) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/relay/register",
        Some(json!({
            "session_id": 2,
            "drives": [{
                "id": "google_drive",
                "provider": "google_drive",
                "root_path": "G:\\My Drive",
                "virtual_drive": true,
                "readable": true
            }]
        })),
    )
    .await;
    assert_eq!(st_ok, StatusCode::OK, "relay register failed: {body_ok}");
    assert_eq!(body_ok["ok"], json!(true));
    assert_eq!(body_ok["registered"], json!(1));
    assert_eq!(body_ok["session_id"], json!(2));

    let relay_snapshot = state
        .active_cloud_drive_relay(Duration::from_secs(60))
        .expect("relay snapshot should be stored");
    assert_eq!(relay_snapshot.session_id, Some(2));

    // Evaluate status response hermetically as LocalSystem in Session 0 with unmounted Google Drive
    let synthetic_unmounted_gd = DiscoveredCloudDrive {
        id: "google_drive".to_string(),
        provider: CloudDriveProvider::GoogleDrive,
        label: "Google Drive".to_string(),
        account_kind: None,
        detected: false,
        mounted: false,
        virtual_drive: true,
        root_path: None,
        detected_roots: Vec::new(),
    };
    let resp = build_cloud_drives_status_response_with_context(
        &state,
        CloudDrivesStatusRuntimeContext {
            local_system: true,
            session_zero: true,
            allow_session_only_eval: true,
            discovered: vec![synthetic_unmounted_gd],
            session_hints: Vec::new(),
            relay_snapshot: Some(relay_snapshot.clone()),
        },
        None,
        None,
    )
    .await;
    assert!(resp.running_as_local_system);
    assert!(resp.virtual_drive_guidance.is_some());

    let gd = resp
        .drives
        .iter()
        .find(|d| d.id == "google_drive")
        .expect("google_drive DTO");
    assert_eq!(gd.status, CloudDriveMountStatus::SessionOnly);
    assert_eq!(gd.status_label, "Session Only");
    assert!(gd.session_only);
    assert!(gd.virtual_drive);
    assert!(gd.detected);
    assert!(!gd.mounted);
    assert_eq!(gd.root_path.as_deref(), Some(r"G:\My Drive"));
    assert!(
        gd.session_guidance
            .as_deref()
            .is_some_and(|g| g.contains("quorum-desktop relay")),
        "unexpected session_guidance: {:?}",
        gd.session_guidance
    );

    // When Mirror mode mounts a local directory, Mounted takes precedence over SessionOnly
    let mirror_gd = tmp.path().join("GoogleDriveMirror");
    std::fs::create_dir_all(&mirror_gd).unwrap();
    let synthetic_mounted_gd = DiscoveredCloudDrive {
        id: "google_drive".to_string(),
        provider: CloudDriveProvider::GoogleDrive,
        label: "Google Drive".to_string(),
        account_kind: None,
        detected: true,
        mounted: true,
        virtual_drive: false,
        root_path: Some(mirror_gd.clone()),
        detected_roots: vec![mirror_gd.clone()],
    };
    let resp_mounted = build_cloud_drives_status_response_with_context(
        &state,
        CloudDrivesStatusRuntimeContext {
            local_system: true,
            session_zero: true,
            allow_session_only_eval: true,
            discovered: vec![synthetic_mounted_gd],
            session_hints: Vec::new(),
            relay_snapshot: Some(relay_snapshot),
        },
        None,
        None,
    )
    .await;
    let gd_mounted = resp_mounted
        .drives
        .iter()
        .find(|d| d.id == "google_drive")
        .expect("mounted google_drive DTO");
    assert_eq!(gd_mounted.status, CloudDriveMountStatus::Mounted);
    assert_eq!(gd_mounted.status_label, "Mounted");
    assert!(gd_mounted.mounted);
    assert!(!gd_mounted.session_only);
}

#[tokio::test]
async fn test_post_reindex_split_folder_direct_file_never_crawls_disabled_cloud_root() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let docs = profile.join("Documents");
    let dropbox = docs.join("Dropbox");
    std::fs::create_dir_all(&dropbox).unwrap();

    let notes_file = docs.join("notes.txt");
    let secret_file = dropbox.join("secret.txt");
    std::fs::write(&notes_file, "TOKEN_SPLIT_DOC_NOTES allowed local file").unwrap();
    std::fs::write(
        &secret_file,
        "TOKEN_SPLIT_DROPBOX_SECRET must never be indexed",
    )
    .unwrap();

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    {
        let mut s = quorum_coordinator::dlp_mesh::PersistedDaemonSettings::default();
        s.cloud_drives.drives = vec![quorum_types::CloudDriveConfigEntry {
            id: "dropbox".to_string(),
            provider: quorum_types::CloudDriveProvider::Dropbox,
            label: "Dropbox".to_string(),
            enabled: false,
            root_path: Some(dropbox.to_string_lossy().to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        }];
        ctrl.update_settings(s);
    }

    let disabled_roots = quorum_daemon::handlers::cloud_drives::collect_disabled_cloud_roots(
        &ctrl,
        &quorum_ingest::discover_cloud_drives(),
    );
    let initial_watch_dirs = collect_filtered_initial_watch_dirs(
        &[docs.clone()],
        None,
        &[],
        &[],
        &[],
        &[],
        &disabled_roots,
    );
    assert!(
        initial_watch_dirs.contains(&notes_file),
        "Direct file inside split Documents folder must be in initial_watch_dirs: {initial_watch_dirs:?}"
    );
    assert!(
        !initial_watch_dirs.contains(&docs),
        "Split Documents folder itself must NOT be in initial_watch_dirs: {initial_watch_dirs:?}"
    );
    state.reindex_worker.add_watch_paths(&initial_watch_dirs);
    assert!(
        !state.reindex_worker.all_watch_paths().contains(&docs),
        "add_watch_paths must NOT collapse notes.txt into Documents"
    );

    let app = build_router(Arc::clone(&state));
    let (st, body) = send_json(&app, "POST", "/api/reindex", Some(json!({}))).await;
    assert!(
        st == StatusCode::OK || st == StatusCode::ACCEPTED,
        "POST /api/reindex failed: {st} {body}"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(prog) = state.reindex_worker.get_progress().await {
            if prog.phase == quorum_ingest::ReindexPhase::Completed {
                break;
            }
            assert_ne!(prog.phase, quorum_ingest::ReindexPhase::Failed);
        }
        assert!(Instant::now() < deadline, "POST /api/reindex timed out");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let chunks = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        chunks.iter().any(|c| c
            .file_path
            .eq_ignore_ascii_case(&notes_file.to_string_lossy())),
        "Allowed direct file Documents\\notes.txt must be indexed"
    );
    assert!(
        !chunks.iter().any(|c| c
            .file_path
            .eq_ignore_ascii_case(&secret_file.to_string_lossy())),
        "Disabled nested Documents\\Dropbox\\secret.txt must have 0 chunks in storage"
    );
}

#[tokio::test]
async fn test_post_documents_add_blocks_disabled_cloud_and_splits_ancestor_without_recursive_watch()
{
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let docs = profile.join("Documents");
    let work = docs.join("Work");
    let dropbox = docs.join("Dropbox");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&dropbox).unwrap();

    let notes_file = docs.join("notes.txt");
    let work_file = work.join("allowed.txt");
    let secret_file = dropbox.join("secret.txt");
    std::fs::write(&notes_file, "TOKEN_DOC_ADD_NOTES allowed local file").unwrap();
    std::fs::write(&work_file, "TOKEN_DOC_ADD_WORK allowed sibling subdir file").unwrap();
    std::fs::write(
        &secret_file,
        "TOKEN_DOC_ADD_DROPBOX_SECRET must never be indexed",
    )
    .unwrap();

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    {
        let mut s = quorum_coordinator::dlp_mesh::PersistedDaemonSettings::default();
        s.cloud_drives.drives = vec![quorum_types::CloudDriveConfigEntry {
            id: "dropbox".to_string(),
            provider: quorum_types::CloudDriveProvider::Dropbox,
            label: "Dropbox".to_string(),
            enabled: false,
            root_path: Some(dropbox.to_string_lossy().to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        }];
        ctrl.update_settings(s);
    }

    let mut rt_cfg = state.ingest_config.clone();
    rt_cfg.watch_paths.clear();
    let (_watcher_rx, watcher_handle) = quorum_ingest::FilesystemWatcher::new(rt_cfg)
        .start_watching()
        .expect("start watcher");
    let watcher_arc = Arc::new(watcher_handle);
    state.set_fs_watcher(Arc::clone(&watcher_arc));

    let app = build_router(Arc::clone(&state));

    // 1. Direct disabled cloud file must fail closed with 409 Conflict and watch/index nothing
    let (st_secret, body_secret) = send_json(
        &app,
        "POST",
        "/api/documents/add",
        Some(json!({ "local_paths": [secret_file.to_string_lossy()] })),
    )
    .await;
    assert_eq!(
        st_secret,
        StatusCode::CONFLICT,
        "Disabled cloud file must fail closed with 409: {body_secret}"
    );
    assert!(
        watcher_arc.watched_paths().is_empty(),
        "Watcher must remain empty after 409: {:?}",
        watcher_arc.watched_paths()
    );
    assert!(
        state.reindex_worker.all_watch_paths().is_empty(),
        "ReindexWorker watch paths must remain empty after 409"
    );

    // 2. Direct file inside strict ancestor Documents must index notes.txt without recursive-watching Documents
    let (st_notes, body_notes) = send_json(
        &app,
        "POST",
        "/api/documents/add",
        Some(json!({ "local_paths": [notes_file.to_string_lossy()] })),
    )
    .await;
    assert_eq!(
        st_notes,
        StatusCode::OK,
        "Allowed file Documents\\notes.txt failed: {body_notes}"
    );
    let watched_after_notes = watcher_arc.watched_paths();
    assert!(
        !watched_after_notes.contains(&docs) && !watched_after_notes.contains(&dropbox),
        "FilesystemWatcher must NOT watch strict ancestor Documents or disabled Dropbox: {watched_after_notes:?}"
    );
    let rw_after_notes = state.reindex_worker.all_watch_paths();
    assert!(
        !rw_after_notes.contains(&docs) && !rw_after_notes.contains(&dropbox),
        "ReindexWorker must NOT hold Documents or Dropbox: {rw_after_notes:?}"
    );

    // 3. Passing ancestor directory Documents must split into [notes.txt, Work], never watch Documents or Dropbox, and leave 0 chunks for secret.txt
    let (st_docs, body_docs) = send_json(
        &app,
        "POST",
        "/api/documents/add",
        Some(json!({ "local_paths": [docs.to_string_lossy()] })),
    )
    .await;
    assert_eq!(
        st_docs,
        StatusCode::OK,
        "Permitted split Documents failed: {body_docs}"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let chunks = state.storage.scan_all_chunks().await.unwrap();
        let has_notes = chunks.iter().any(|c| {
            c.file_path
                .eq_ignore_ascii_case(&notes_file.to_string_lossy())
        });
        let has_work = chunks.iter().any(|c| {
            c.file_path
                .eq_ignore_ascii_case(&work_file.to_string_lossy())
        });
        if has_notes && has_work {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for split Documents targets to index; chunks={}",
            chunks.len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let watched_final = watcher_arc.watched_paths();
    assert!(
        watched_final.contains(&work),
        "Permitted sibling subdir Work should be watched: {watched_final:?}"
    );
    assert!(
        !watched_final.contains(&docs) && !watched_final.contains(&dropbox),
        "Documents and Dropbox must NEVER be in watcher.watched_paths(): {watched_final:?}"
    );
    let rw_final = state.reindex_worker.all_watch_paths();
    assert!(
        !rw_final.contains(&docs) && !rw_final.contains(&dropbox),
        "Documents and Dropbox must NEVER be in reindex_worker.all_watch_paths(): {rw_final:?}"
    );

    let chunks = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        !chunks.iter().any(|c| c
            .file_path
            .eq_ignore_ascii_case(&secret_file.to_string_lossy())),
        "Disabled Documents\\Dropbox\\secret.txt must have 0 chunks in storage"
    );
}

#[tokio::test]
async fn test_post_reindex_explicit_disabled_target_returns_409_and_never_crawls_watch_paths() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let docs = profile.join("Documents");
    let dropbox = docs.join("Dropbox");
    let other_local = tmp.path().join("OtherLocal");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&other_local).unwrap();

    let secret_file = dropbox.join("secret.txt");
    let other_file = other_local.join("other.txt");
    std::fs::write(&secret_file, "TOKEN_REINDEX_SECRET must never be crawled").unwrap();
    std::fs::write(
        &other_file,
        "TOKEN_REINDEX_OTHER unrelated watch path must not be crawled on explicit disabled target",
    )
    .unwrap();

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    state.reindex_worker.add_watch_paths(&[other_local.clone()]);

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    {
        let mut s = quorum_coordinator::dlp_mesh::PersistedDaemonSettings::default();
        s.cloud_drives.drives = vec![quorum_types::CloudDriveConfigEntry {
            id: "dropbox".to_string(),
            provider: quorum_types::CloudDriveProvider::Dropbox,
            label: "Dropbox".to_string(),
            enabled: false,
            root_path: Some(dropbox.to_string_lossy().to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        }];
        ctrl.update_settings(s);
    }

    let app = build_router(Arc::clone(&state));
    let (st, body) = send_json(
        &app,
        "POST",
        "/api/reindex",
        Some(json!({ "target_paths": [dropbox.to_string_lossy()] })),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "Explicit disabled target_paths must fail closed with 409: {body}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let chunks = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        chunks.is_empty(),
        "Explicit disabled target_paths must neither crawl disabled drive nor fall back to watch_paths; found {} chunks",
        chunks.len()
    );
}

#[tokio::test]
async fn test_onedrive_personal_relay_does_not_contaminate_unmounted_onedrive_business() {
    use quorum_daemon::handlers::cloud_drives::{
        build_cloud_drives_status_response_with_context, CloudDrivesStatusRuntimeContext,
    };
    use quorum_daemon::state::{CloudDriveRelaySnapshot, RelayedCloudDriveEntry};
    use quorum_ingest::cloud_drives::DiscoveredCloudDrive;
    use quorum_types::{CloudDriveMountStatus, CloudDriveProvider};

    let _lock = TEST_LOCK.lock().await;
    let _env = EnvGuard::set("QUORUM_CLOUD_TEST_PROFILE_DIR", "");

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    ctrl.update_settings(Default::default());

    let tmp = tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;

    let synthetic_od_personal = DiscoveredCloudDrive {
        id: "onedrive_personal".to_string(),
        provider: CloudDriveProvider::OneDrive,
        label: "OneDrive (Personal)".to_string(),
        account_kind: Some("personal".to_string()),
        detected: false,
        mounted: false,
        virtual_drive: false,
        root_path: None,
        detected_roots: Vec::new(),
    };
    let synthetic_od_business = DiscoveredCloudDrive {
        id: "onedrive_business".to_string(),
        provider: CloudDriveProvider::OneDrive,
        label: "OneDrive (Business)".to_string(),
        account_kind: Some("business".to_string()),
        detected: false,
        mounted: false,
        virtual_drive: false,
        root_path: None,
        detected_roots: Vec::new(),
    };

    let relay_snapshot = CloudDriveRelaySnapshot {
        session_id: Some(2),
        drives: vec![RelayedCloudDriveEntry {
            id: "onedrive_personal".to_string(),
            provider: "onedrive".to_string(),
            root_path: r"O:\OneDrivePersonal".to_string(),
            virtual_drive: true,
            readable: true,
        }],
        updated_at: Instant::now(),
    };

    let resp = build_cloud_drives_status_response_with_context(
        &state,
        CloudDrivesStatusRuntimeContext {
            local_system: true,
            session_zero: true,
            allow_session_only_eval: true,
            discovered: vec![synthetic_od_personal, synthetic_od_business],
            session_hints: Vec::new(),
            relay_snapshot: Some(relay_snapshot),
        },
        None,
        None,
    )
    .await;

    let personal = resp
        .drives
        .iter()
        .find(|d| d.id == "onedrive_personal")
        .expect("onedrive_personal DTO");
    assert_eq!(personal.status, CloudDriveMountStatus::SessionOnly);
    assert!(personal.session_only);
    assert_eq!(personal.root_path.as_deref(), Some(r"O:\OneDrivePersonal"));

    let business = resp
        .drives
        .iter()
        .find(|d| d.id == "onedrive_business")
        .expect("onedrive_business DTO");
    assert_eq!(business.status, CloudDriveMountStatus::NotDetected);
    assert!(!business.session_only);
    assert!(
        business.root_path.is_none(),
        "Unmounted onedrive_business must NOT inherit onedrive_personal's root_path: {:?}",
        business.root_path
    );
}

struct CwdGuard {
    prev: std::path::PathBuf,
}

impl CwdGuard {
    fn set(target: &Path) -> Self {
        let prev = std::env::current_dir().expect("current_dir");
        std::env::set_current_dir(target).expect("set_current_dir");
        Self { prev }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.prev);
    }
}

fn create_dir_link_or_junction(link: &Path, target: &Path) -> bool {
    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_dir(target, link).is_ok() {
            return true;
        }
        std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
}

#[tokio::test]
async fn test_post_documents_add_non_canonical_rel_verbatim_and_symlink_ancestors_never_leak_disabled_cloud(
) {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let docs = profile.join("Documents");
    let desktop = profile.join("Desktop");
    let work = docs.join("Work");
    let dropbox = docs.join("Dropbox");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&desktop).unwrap();
    std::fs::create_dir_all(&dropbox).unwrap();

    let notes_file = docs.join("notes.txt");
    let work_file = work.join("allowed.txt");
    let secret_file = dropbox.join("secret.txt");
    std::fs::write(&notes_file, "TOKEN_M5_NC_NOTES allowed local file").unwrap();
    std::fs::write(&work_file, "TOKEN_M5_NC_WORK allowed sibling subdir file").unwrap();
    std::fs::write(
        &secret_file,
        "TOKEN_M5_NC_SECRET disabled dropbox secret must never be indexed",
    )
    .unwrap();

    let link_to_docs = tmp.path().join("LinkToDocs");
    let link_to_dropbox = tmp.path().join("LinkToDropbox");
    assert!(
        create_dir_link_or_junction(&link_to_docs, &docs),
        "Failed to create symlink/junction to Documents"
    );
    assert!(
        create_dir_link_or_junction(&link_to_dropbox, &dropbox),
        "Failed to create symlink/junction to Dropbox"
    );

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    {
        let mut s = quorum_coordinator::dlp_mesh::PersistedDaemonSettings::default();
        s.cloud_drives.drives = vec![quorum_types::CloudDriveConfigEntry {
            id: "dropbox".to_string(),
            provider: quorum_types::CloudDriveProvider::Dropbox,
            label: "Dropbox".to_string(),
            enabled: false,
            root_path: Some(dropbox.to_string_lossy().to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        }];
        ctrl.update_settings(s);
    }

    let mut rt_cfg = state.ingest_config.clone();
    rt_cfg.watch_paths.clear();
    let (_watcher_rx, watcher_handle) = quorum_ingest::FilesystemWatcher::new(rt_cfg)
        .start_watching()
        .expect("start watcher");
    let watcher_arc = Arc::new(watcher_handle);
    state.set_fs_watcher(Arc::clone(&watcher_arc));

    let app = build_router(Arc::clone(&state));

    // A. Direct non-canonical disabled cloud variants must fail closed (409/400)
    {
        let _cwd = CwdGuard::set(&work);
        for bad_target in [
            "..\\Dropbox".to_string(),
            format!("//?/{}", dropbox.to_string_lossy().replace('\\', "/")),
            link_to_dropbox.to_string_lossy().to_string(),
        ] {
            let (st, body) = send_json(
                &app,
                "POST",
                "/api/documents/add",
                Some(json!({ "local_paths": [bad_target], "add_to_opt_in": true })),
            )
            .await;
            assert!(
                st == StatusCode::CONFLICT || st == StatusCode::BAD_REQUEST,
                "Disabled cloud variant must fail closed (409/400), got {st}: {body}"
            );
        }
    }
    {
        let _cwd = CwdGuard::set(tmp.path());
        let (st, body) = send_json(
            &app,
            "POST",
            "/api/documents/add",
            Some(json!({ "local_paths": ["Profile\\Documents\\Dropbox"], "add_to_opt_in": true })),
        )
        .await;
        assert!(
            st == StatusCode::CONFLICT || st == StatusCode::BAD_REQUEST,
            "Relative disabled cloud path must fail closed (409/400), got {st}: {body}"
        );
    }

    // B. Non-canonical strict-ancestor variants (`Work\..`, `..\Documents`, `//?/.../Documents`,
    // relative `Profile\Documents`, and `symlink -> Documents`) with `add_to_opt_in: true`
    let work_dotdot = format!("{}\\..", work.to_string_lossy());
    let verbatim_docs = format!("//?/{}", docs.to_string_lossy().replace('\\', "/"));
    let link_docs_str = link_to_docs.to_string_lossy().to_string();

    for variant in [work_dotdot, verbatim_docs, link_docs_str] {
        let (st, body) = send_json(
            &app,
            "POST",
            "/api/documents/add",
            Some(json!({ "local_paths": [variant], "add_to_opt_in": true })),
        )
        .await;
        assert_ne!(
            st,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected 500: {body}"
        );
    }
    {
        let _cwd = CwdGuard::set(&desktop);
        let (st, body) = send_json(
            &app,
            "POST",
            "/api/documents/add",
            Some(json!({ "local_paths": ["..\\Documents"], "add_to_opt_in": true })),
        )
        .await;
        assert_ne!(
            st,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected 500: {body}"
        );
    }
    {
        let _cwd = CwdGuard::set(tmp.path());
        let (st, body) = send_json(
            &app,
            "POST",
            "/api/documents/add",
            Some(json!({ "local_paths": ["Profile\\Documents"], "add_to_opt_in": true })),
        )
        .await;
        assert_ne!(
            st,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected 500: {body}"
        );
    }

    // Wait briefly for permitted sibling Work/notes indexing to settle
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let chunks = state.storage.scan_all_chunks().await.unwrap();
        let has_notes = chunks.iter().any(|c| {
            c.file_path
                .eq_ignore_ascii_case(&notes_file.to_string_lossy())
        });
        let has_work = chunks.iter().any(|c| {
            c.file_path
                .eq_ignore_ascii_case(&work_file.to_string_lossy())
        });
        if has_notes && has_work {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for split Documents siblings to index; chunks={}",
            chunks.len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let chunks = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        !chunks
            .iter()
            .any(|c| c.file_path.to_ascii_lowercase().contains("secret.txt")),
        "Disabled Documents\\Dropbox\\secret.txt must have 0 chunks in storage!"
    );

    let docs_lower = docs.to_string_lossy().to_ascii_lowercase();
    let dropbox_lower = dropbox.to_string_lossy().to_ascii_lowercase();
    let link_docs_lower = link_to_docs.to_string_lossy().to_ascii_lowercase();

    for wp in watcher_arc.watched_paths() {
        let s = wp.to_string_lossy().to_ascii_lowercase();
        assert!(
            s != docs_lower
                && !s.contains(&dropbox_lower)
                && !s.contains(&link_docs_lower)
                && !s.contains(".."),
            "Forbidden path found in watcher.watched_paths(): {s}"
        );
    }
    for rw in state.reindex_worker.all_watch_paths() {
        let s = rw.to_string_lossy().to_ascii_lowercase();
        assert!(
            s != docs_lower
                && !s.contains(&dropbox_lower)
                && !s.contains(&link_docs_lower)
                && !s.contains(".."),
            "Forbidden path found in reindex_worker.all_watch_paths(): {s}"
        );
    }
    if let Ok(store) = state.marketplace_store() {
        if let Ok(cfg) = store.get_config() {
            for f in &cfg.opt_in_folders {
                let s = f.to_ascii_lowercase();
                assert!(
                    s != docs_lower
                        && !s.contains(&dropbox_lower)
                        && !s.contains(&link_docs_lower)
                        && !s.contains("..")
                        && !s.starts_with("//?/")
                        && f != "Profile\\Documents",
                    "Forbidden uncanonicalized/ancestor/disabled path persisted in opt_in_folders: {f}"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_post_reindex_non_canonical_traversal_verbatim_relative_and_symlink_blocked() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let docs = profile.join("Documents");
    let work = docs.join("Work");
    let dropbox = docs.join("Dropbox");
    let other_local = tmp.path().join("OtherLocal");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&other_local).unwrap();

    let secret_file = dropbox.join("secret.txt");
    let other_file = other_local.join("other.txt");
    std::fs::write(&secret_file, "TOKEN_REIDX_NC_SECRET must never be indexed").unwrap();
    std::fs::write(&other_file, "TOKEN_REIDX_NC_OTHER unrelated watch path").unwrap();

    let link_to_dropbox = tmp.path().join("LinkToDropbox");
    assert!(
        create_dir_link_or_junction(&link_to_dropbox, &dropbox),
        "Failed to create symlink/junction to Dropbox"
    );

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    state.reindex_worker.add_watch_paths(&[other_local.clone()]);

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    {
        let mut s = quorum_coordinator::dlp_mesh::PersistedDaemonSettings::default();
        s.cloud_drives.drives = vec![quorum_types::CloudDriveConfigEntry {
            id: "dropbox".to_string(),
            provider: quorum_types::CloudDriveProvider::Dropbox,
            label: "Dropbox".to_string(),
            enabled: false,
            root_path: Some(dropbox.to_string_lossy().to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        }];
        ctrl.update_settings(s);
    }

    let mut rt_cfg = state.ingest_config.clone();
    rt_cfg.watch_paths.clear();
    let (_watcher_rx, watcher_handle) = quorum_ingest::FilesystemWatcher::new(rt_cfg)
        .start_watching()
        .expect("start watcher");
    let watcher_arc = Arc::new(watcher_handle);
    state.set_fs_watcher(Arc::clone(&watcher_arc));

    let app = build_router(Arc::clone(&state));

    let work_traversal = format!("{}\\..\\Dropbox", work.to_string_lossy());
    let verbatim_dropbox = format!("//?/{}", dropbox.to_string_lossy().replace('\\', "/"));
    let link_dropbox_str = link_to_dropbox.to_string_lossy().to_string();

    for bad_target in [work_traversal, verbatim_dropbox, link_dropbox_str] {
        let (st, body) = send_json(
            &app,
            "POST",
            "/api/reindex",
            Some(json!({ "target_paths": [bad_target] })),
        )
        .await;
        assert!(
            st == StatusCode::CONFLICT || st == StatusCode::BAD_REQUEST,
            "POST /api/reindex must fail closed (409/400) on disabled non-canonical target, got {st}: {body}"
        );
    }

    {
        let _cwd = CwdGuard::set(&work);
        let (st, body) = send_json(
            &app,
            "POST",
            "/api/reindex",
            Some(json!({ "target_paths": ["..\\Dropbox"] })),
        )
        .await;
        assert!(
            st == StatusCode::CONFLICT || st == StatusCode::BAD_REQUEST,
            "POST /api/reindex must fail closed on ..\\Dropbox, got {st}: {body}"
        );
    }

    {
        let _cwd = CwdGuard::set(tmp.path());
        let (st, body) = send_json(
            &app,
            "POST",
            "/api/reindex",
            Some(json!({ "target_paths": ["Profile\\Documents\\Dropbox"] })),
        )
        .await;
        assert!(
            st == StatusCode::CONFLICT || st == StatusCode::BAD_REQUEST,
            "POST /api/reindex must fail closed on relative Profile\\Documents\\Dropbox, got {st}: {body}"
        );
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        watcher_arc.watched_paths().is_empty(),
        "Watcher must remain empty after blocked /api/reindex calls: {:?}",
        watcher_arc.watched_paths()
    );
    let chunks = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        chunks.is_empty(),
        "Disabled Dropbox secret.txt (and unrelated watch_paths) must have 0 chunks; found {}",
        chunks.len()
    );
}

#[tokio::test]
async fn test_post_reindex_empty_body_with_only_disabled_watch_paths_never_falls_back_to_config() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let docs = profile.join("Documents");
    let dropbox = docs.join("Dropbox");
    std::fs::create_dir_all(&dropbox).unwrap();

    let secret_file = dropbox.join("secret.txt");
    std::fs::write(
        &secret_file,
        "TOKEN_REIDX_EMPTY_FALLBACK_SECRET must never be crawled",
    )
    .unwrap();

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state_with_watch_paths(&data_dir, vec![dropbox.clone()]).await;

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    {
        let mut s = quorum_coordinator::dlp_mesh::PersistedDaemonSettings::default();
        s.cloud_drives.drives = vec![quorum_types::CloudDriveConfigEntry {
            id: "dropbox".to_string(),
            provider: quorum_types::CloudDriveProvider::Dropbox,
            label: "Dropbox".to_string(),
            enabled: false,
            root_path: Some(dropbox.to_string_lossy().to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        }];
        ctrl.update_settings(s);
    }

    let app = build_router(Arc::clone(&state));
    let (st, body) = send_json(&app, "POST", "/api/reindex", Some(json!({}))).await;
    assert_eq!(
        st,
        StatusCode::CONFLICT,
        "POST /api/reindex {{}} with only disabled watch_paths must fail closed with 409: {body}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let chunks = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        chunks.is_empty(),
        "POST /api/reindex {{}} must NEVER fall back to config.watch_paths and index disabled Dropbox; found {}",
        chunks.len()
    );
}

#[tokio::test]
async fn test_post_mesh_shared_folders_blocks_disabled_cloud_and_splits_ancestor_without_recursive_watch(
) {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let docs = profile.join("Documents");
    let work = docs.join("Work");
    let dropbox = docs.join("Dropbox");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&dropbox).unwrap();

    let notes_file = docs.join("notes.txt");
    let work_file = work.join("allowed.txt");
    let secret_file = dropbox.join("secret.txt");
    std::fs::write(&notes_file, "TOKEN_SF_NOTES allowed local file").unwrap();
    std::fs::write(&work_file, "TOKEN_SF_WORK allowed sibling subdir file").unwrap();
    std::fs::write(
        &secret_file,
        "TOKEN_SF_SECRET disabled dropbox secret must never be indexed",
    )
    .unwrap();

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    {
        let mut s = quorum_coordinator::dlp_mesh::PersistedDaemonSettings::default();
        s.cloud_drives.drives = vec![quorum_types::CloudDriveConfigEntry {
            id: "dropbox".to_string(),
            provider: quorum_types::CloudDriveProvider::Dropbox,
            label: "Dropbox".to_string(),
            enabled: false,
            root_path: Some(dropbox.to_string_lossy().to_string()),
            custom_paths: Vec::new(),
            access_tier: 3,
            account_kind: None,
        }];
        ctrl.update_settings(s);
    }

    let mut rt_cfg = state.ingest_config.clone();
    rt_cfg.watch_paths.clear();
    let (_watcher_rx, watcher_handle) = quorum_ingest::FilesystemWatcher::new(rt_cfg)
        .start_watching()
        .expect("start watcher");
    let watcher_arc = Arc::new(watcher_handle);
    state.set_fs_watcher(Arc::clone(&watcher_arc));

    let app = build_router(Arc::clone(&state));

    // 1. Adding disabled Documents\Dropbox directly to shared-folders must NEVER watch, queue, index, or share over mesh
    let (st_db, body_db) = send_json(
        &app,
        "POST",
        "/api/mesh/shared-folders",
        Some(json!({
            "action": "add",
            "path": dropbox.to_string_lossy(),
            "enabled": true,
            "access_tier": 0
        })),
    )
    .await;
    assert!(
        st_db == StatusCode::OK || st_db == StatusCode::CONFLICT,
        "Unexpected status when adding disabled Dropbox to shared-folders: {st_db} {body_db}"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        watcher_arc.watched_paths().is_empty(),
        "Disabled Dropbox must NOT be watched after /api/mesh/shared-folders: {:?}",
        watcher_arc.watched_paths()
    );
    assert!(
        state.reindex_worker.all_watch_paths().is_empty(),
        "Disabled Dropbox must NOT enter reindex_worker.all_watch_paths(): {:?}",
        state.reindex_worker.all_watch_paths()
    );
    assert!(
        state.storage.scan_all_chunks().await.unwrap().is_empty(),
        "Disabled Dropbox must have 0 chunks indexed after /api/mesh/shared-folders"
    );
    assert!(
        ctrl.check_file_shared_with_mesh(&secret_file.to_string_lossy())
            .is_none(),
        "Disabled Dropbox must remain blocked from mesh sharing even if added to shared_folders"
    );

    // 2. Adding traversal path must fail closed with 400
    let (st_trav, body_trav) = send_json(
        &app,
        "POST",
        "/api/mesh/shared-folders",
        Some(json!({
            "action": "add",
            "path": format!("{}\\..\\Dropbox", work.to_string_lossy()),
            "enabled": true,
            "access_tier": 0
        })),
    )
    .await;
    assert_eq!(
        st_trav,
        StatusCode::BAD_REQUEST,
        "Traversal path in shared-folders must return 400 Bad Request: {body_trav}"
    );

    // 3. Adding permitted ancestor Documents splits cleanly without watching Documents/Dropbox or indexing secret.txt
    let (st_docs, body_docs) = send_json(
        &app,
        "POST",
        "/api/mesh/shared-folders",
        Some(json!({
            "action": "add",
            "path": docs.to_string_lossy(),
            "enabled": true,
            "access_tier": 0
        })),
    )
    .await;
    assert_eq!(
        st_docs,
        StatusCode::OK,
        "Adding permitted ancestor Documents failed: {body_docs}"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let chunks = state.storage.scan_all_chunks().await.unwrap();
        let has_notes = chunks.iter().any(|c| {
            c.file_path
                .eq_ignore_ascii_case(&notes_file.to_string_lossy())
        });
        let has_work = chunks.iter().any(|c| {
            c.file_path
                .eq_ignore_ascii_case(&work_file.to_string_lossy())
        });
        if has_notes && has_work {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Timed out waiting for shared-folders split Documents siblings to index; chunks={}",
            chunks.len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let watched = watcher_arc.watched_paths();
    assert!(
        watched.contains(&work),
        "Permitted sibling Work must be watched: {watched:?}"
    );
    assert!(
        !watched.contains(&docs) && !watched.contains(&dropbox),
        "Documents and Dropbox must NEVER be in watcher.watched_paths(): {watched:?}"
    );
    let rw = state.reindex_worker.all_watch_paths();
    assert!(
        !rw.contains(&docs) && !rw.contains(&dropbox),
        "Documents and Dropbox must NEVER be in reindex_worker.all_watch_paths(): {rw:?}"
    );
    let chunks = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        !chunks.iter().any(|c| c
            .file_path
            .eq_ignore_ascii_case(&secret_file.to_string_lossy())),
        "Disabled Documents\\Dropbox\\secret.txt must have 0 chunks in storage!"
    );
}

#[tokio::test]
async fn test_cloud_drives_config_rejects_disabled_symlink_and_ancestor_and_filters_restart() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let gdrive = profile.join("GoogleDrive");
    let docs = profile.join("Documents");
    let work = docs.join("Work");
    let dropbox = docs.join("Dropbox");
    let appdata_db = profile.join("AppData").join("Local").join("Dropbox");
    std::fs::create_dir_all(&gdrive).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&appdata_db).unwrap();
    std::fs::write(
        appdata_db.join("info.json"),
        json!({ "personal": { "path": dropbox.to_string_lossy() } }).to_string(),
    )
    .unwrap();
    #[cfg(not(windows))]
    {
        let posix_db = profile.join(".dropbox");
        std::fs::create_dir_all(&posix_db).unwrap();
        std::fs::write(
            posix_db.join("info.json"),
            json!({ "personal": { "path": dropbox.to_string_lossy() } }).to_string(),
        )
        .unwrap();
    }

    let gdoc = gdrive.join("gdoc.txt");
    let work_file = work.join("allowed.txt");
    let notes_file = docs.join("notes.txt");
    let secret_file = dropbox.join("secret.txt");
    std::fs::write(&gdoc, "TOKEN_R5_GDOC allowed google drive").unwrap();
    std::fs::write(&work_file, "TOKEN_R5_WORK allowed sibling").unwrap();
    std::fs::write(&notes_file, "TOKEN_R5_NOTES allowed doc").unwrap();
    std::fs::write(
        &secret_file,
        "TOKEN_R5_SECRET disabled dropbox must never index",
    )
    .unwrap();

    let link_to_dropbox = tmp.path().join("LinkToDropbox");
    let link_to_docs = tmp.path().join("LinkToDocs");
    assert!(
        create_dir_link_or_junction(&link_to_dropbox, &dropbox),
        "Failed to create symlink/junction to Dropbox"
    );
    assert!(
        create_dir_link_or_junction(&link_to_docs, &docs),
        "Failed to create symlink/junction to Documents"
    );

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);

    let mut rt_cfg = state.ingest_config.clone();
    rt_cfg.watch_paths.clear();
    let (_watcher_rx, watcher_handle) = quorum_ingest::FilesystemWatcher::new(rt_cfg)
        .start_watching()
        .expect("start watcher");
    let watcher_arc = Arc::new(watcher_handle);
    state.set_fs_watcher(Arc::clone(&watcher_arc));

    let app = build_router(Arc::clone(&state));

    // Reconcile & enable google_drive
    let (st_get, _) = send_json(&app, "GET", "/api/cloud-drives", None).await;
    assert_eq!(st_get, StatusCode::OK);
    let (st_en, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "toggle_drive",
            "id": "google_drive",
            "enabled": true,
            "root_path": gdrive.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_en, StatusCode::OK);

    // 1. `add_folder` on enabled google_drive with junction->Dropbox, Dropbox, junction->Documents, Documents, or Profile must return 409 Conflict and NOT persist!
    for blocked_target in [
        link_to_dropbox.to_string_lossy().to_string(),
        dropbox.to_string_lossy().to_string(),
        link_to_docs.to_string_lossy().to_string(),
        docs.to_string_lossy().to_string(),
        profile.to_string_lossy().to_string(),
    ] {
        let (st, body) = send_json(
            &app,
            "POST",
            "/api/cloud-drives/config",
            Some(json!({
                "action": "add_folder",
                "id": "google_drive",
                "path": blocked_target
            })),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::CONFLICT,
            "add_folder must fail closed with 409 for {blocked_target}: {body}"
        );
    }

    // 2. `toggle_drive`, `set_root`, and `drives` bulk fallback must also fail closed with 409
    let (st_tog, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "toggle_drive",
            "id": "google_drive",
            "enabled": true,
            "root_path": link_to_dropbox.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_tog, StatusCode::CONFLICT);

    let (st_set, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "set_root",
            "id": "google_drive",
            "root_path": docs.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_set, StatusCode::CONFLICT);

    let (st_bulk, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "drives": [{
                "id": "google_drive",
                "provider": "google_drive",
                "label": "Google Drive",
                "enabled": true,
                "root_path": gdrive.to_string_lossy(),
                "custom_paths": [link_to_dropbox.to_string_lossy()],
                "access_tier": 3
            }, {
                "id": "dropbox",
                "provider": "dropbox",
                "label": "Dropbox",
                "enabled": false,
                "root_path": dropbox.to_string_lossy(),
                "custom_paths": [],
                "access_tier": 3
            }]
        })),
    )
    .await;
    assert_eq!(st_bulk, StatusCode::CONFLICT);

    // Verify custom_paths was never persisted on google_drive
    let cd_after = ctrl.get_cloud_drives_settings();
    let gd_entry = cd_after
        .drives
        .iter()
        .find(|d| d.id == "google_drive")
        .expect("google_drive entry");
    assert!(
        gd_entry.custom_paths.is_empty(),
        "Rejected paths must never be persisted to custom_paths: {:?}",
        gd_entry.custom_paths
    );

    // 3. Defense-in-depth restart simulation: even if legacy polluted custom_paths exist in settings,
    // collect_enabled_cloud_paths_filtered + collect_filtered_initial_watch_dirs never return Dropbox or unsplit Documents!
    {
        let mut polluted = ctrl.get_cloud_drives_settings();
        if let Some(gd) = polluted.drives.iter_mut().find(|d| d.id == "google_drive") {
            gd.custom_paths = vec![
                link_to_dropbox.to_string_lossy().to_string(),
                docs.to_string_lossy().to_string(),
            ];
        }
        ctrl.update_cloud_drives_settings(polluted).unwrap();
    }
    let discovered = quorum_ingest::discover_cloud_drives();
    let disabled_roots =
        quorum_daemon::handlers::cloud_drives::collect_disabled_cloud_roots(&ctrl, &discovered);
    let enabled_paths = quorum_daemon::handlers::cloud_drives::collect_enabled_cloud_paths_filtered(
        &ctrl,
        &disabled_roots,
    );
    let initial_watch = collect_filtered_initial_watch_dirs(
        &[],
        None,
        &[],
        &[],
        &enabled_paths,
        &[],
        &disabled_roots,
    );
    let dropbox_canon =
        quorum_daemon::handlers::cloud_drives::canonicalize_for_cloud_filter(&dropbox).unwrap();
    let docs_canon =
        quorum_daemon::handlers::cloud_drives::canonicalize_for_cloud_filter(&docs).unwrap();
    assert!(
        !initial_watch.contains(&dropbox_canon) && !initial_watch.contains(&docs_canon),
        "Restart watch dirs must never contain disabled Dropbox or unsplit Documents: {initial_watch:?}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    let chunks = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        !chunks
            .iter()
            .any(|c| c.file_path.to_ascii_lowercase().contains("secret.txt")),
        "Disabled Dropbox secret.txt must have 0 chunks!"
    );
}

#[tokio::test]
async fn test_drift_healer_and_filtered_watch_paths_never_index_disabled_nested_cloud_root() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let docs = profile.join("Documents");
    let work = docs.join("Work");
    let dropbox = docs.join("Dropbox");
    let appdata_db = profile.join("AppData").join("Local").join("Dropbox");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&appdata_db).unwrap();
    std::fs::write(
        appdata_db.join("info.json"),
        json!({ "personal": { "path": dropbox.to_string_lossy() } }).to_string(),
    )
    .unwrap();
    #[cfg(not(windows))]
    {
        let posix_db = profile.join(".dropbox");
        std::fs::create_dir_all(&posix_db).unwrap();
        std::fs::write(
            posix_db.join("info.json"),
            json!({ "personal": { "path": dropbox.to_string_lossy() } }).to_string(),
        )
        .unwrap();
    }

    let work_file = work.join("allowed.txt");
    let notes_file = docs.join("notes.txt");
    let secret_file = dropbox.join("secret.txt");
    std::fs::write(&work_file, "TOKEN_DRIFT_WORK allowed work file").unwrap();
    std::fs::write(&notes_file, "TOKEN_DRIFT_NOTES allowed doc file").unwrap();
    std::fs::write(&secret_file, "TOKEN_DRIFT_SECRET disabled dropbox secret").unwrap();

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    // First verify startup watch_dir filtering matches main.rs:280-286
    let discovered = quorum_ingest::discover_cloud_drives();
    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    ctrl.update_settings(Default::default());
    quorum_daemon::handlers::cloud_drives::reconcile_discovered_cloud_drives(&ctrl, &discovered);
    let disabled_roots =
        quorum_daemon::handlers::cloud_drives::collect_disabled_cloud_roots(&ctrl, &discovered);
    let mut filtered_cli_watch = Vec::new();
    quorum_daemon::handlers::cloud_drives::push_watch_root_excluding_disabled(
        &docs,
        &disabled_roots,
        &mut filtered_cli_watch,
    );
    let docs_canon =
        quorum_daemon::handlers::cloud_drives::canonicalize_for_cloud_filter(&docs).unwrap();
    let dropbox_canon =
        quorum_daemon::handlers::cloud_drives::canonicalize_for_cloud_filter(&dropbox).unwrap();
    assert!(!filtered_cli_watch.contains(&docs_canon));
    assert!(!filtered_cli_watch.contains(&dropbox_canon));

    // Even if DriftHealer started with unfiltered ancestor `docs`, POST /api/drift/fix must sync & exclude disabled Dropbox
    let state = make_test_state_with_watch_paths(&data_dir, vec![docs.clone()]).await;
    let app = build_router(Arc::clone(&state));
    let (st, body) = send_json(&app, "POST", "/api/drift/fix", Some(json!({}))).await;
    assert_eq!(st, StatusCode::OK, "POST /api/drift/fix failed: {body}");

    let chunks = state.storage.scan_all_chunks().await.unwrap();
    assert!(
        chunks.iter().any(|c| c
            .file_path
            .eq_ignore_ascii_case(&work_file.to_string_lossy())),
        "Allowed Documents\\Work\\allowed.txt must be indexed by DriftHealer"
    );
    assert!(
        !chunks.iter().any(|c| c
            .file_path
            .eq_ignore_ascii_case(&secret_file.to_string_lossy())),
        "Disabled Documents\\Dropbox\\secret.txt must have 0 chunks after POST /api/drift/fix!"
    );
}

#[tokio::test]
async fn test_dynamically_created_cloud_folder_reconciles_in_shared_folders_and_dlp_test() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    std::fs::create_dir_all(&profile).unwrap();

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );

    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;

    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    let prev_settings = ctrl.get_settings();
    struct SettingsRestore(quorum_coordinator::dlp_mesh::PersistedDaemonSettings);
    impl Drop for SettingsRestore {
        fn drop(&mut self) {
            quorum_coordinator::global_mesh_dlp_controller().update_settings(self.0.clone());
        }
    }
    let _restore = SettingsRestore(prev_settings);
    {
        let mut s = quorum_coordinator::dlp_mesh::PersistedDaemonSettings::default();
        s.mesh.p2p_enabled = true;
        s.mesh.require_explicit_folder_share = false;
        ctrl.update_settings(s);
    }

    let app = build_router(Arc::clone(&state));

    // Dynamically create Profile\Documents\Dropbox + info.json AFTER daemon startup, before GET /api/cloud-drives
    let dropbox = profile.join("Documents").join("Dropbox");
    let appdata_db = profile.join("AppData").join("Local").join("Dropbox");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&appdata_db).unwrap();
    std::fs::write(
        appdata_db.join("info.json"),
        json!({ "personal": { "path": dropbox.to_string_lossy() } }).to_string(),
    )
    .unwrap();
    #[cfg(not(windows))]
    {
        let posix_db = profile.join(".dropbox");
        std::fs::create_dir_all(&posix_db).unwrap();
        std::fs::write(
            posix_db.join("info.json"),
            json!({ "personal": { "path": dropbox.to_string_lossy() } }).to_string(),
        )
        .unwrap();
    }
    let secret_file = dropbox.join("secret.txt");
    std::fs::write(&secret_file, "clean non-secret text").unwrap();

    let (st_sf, _) = send_json(
        &app,
        "POST",
        "/api/mesh/shared-folders",
        Some(json!({
            "action": "add",
            "path": dropbox.to_string_lossy(),
            "enabled": true,
            "access_tier": 0
        })),
    )
    .await;
    assert_eq!(st_sf, StatusCode::OK);

    let (st_dlp, dlp_body) = send_json(
        &app,
        "POST",
        "/api/dlp/test",
        Some(json!({
            "text": "clean non-secret text",
            "file_path": secret_file.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_dlp, StatusCode::OK);
    assert_eq!(
        dlp_body["folder_shared_with_mesh"].as_bool(),
        Some(false),
        "Dynamically created un-enabled Dropbox must NEVER be folder_shared_with_mesh: {dlp_body}"
    );
    assert_eq!(
        dlp_body["effective_mesh_allowed"].as_bool(),
        Some(false),
        "Dynamically created un-enabled Dropbox must NEVER be effective_mesh_allowed: {dlp_body}"
    );
    assert!(
        ctrl.check_file_shared_with_mesh(&secret_file.to_string_lossy())
            .is_none(),
        "check_file_shared_with_mesh must fail closed (None) on unreconciled/disabled Dropbox"
    );
}

#[tokio::test]
async fn t5_bulk_drives_roundtrip_disabled_drive_retaining_custom_paths_succeeds() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let dropbox = profile.join("Dropbox");
    let custom_docs = tmp.path().join("CustomDocs");
    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&custom_docs).unwrap();

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(Arc::clone(&state));

    // Add custom_docs while dropbox is disabled, then re-add (idempotent)
    let (st_add1, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": custom_docs.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_add1, StatusCode::OK);

    let (st_add2, _) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": custom_docs.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(
        st_add2,
        StatusCode::OK,
        "Repeated add_folder on disabled drive must be idempotent 200 OK"
    );

    // GET /api/cloud-drives -> POST /api/cloud-drives/config { "drives": [...] } roundtrip
    let (st_get, snapshot) = send_json(&app, "GET", "/api/cloud-drives", None).await;
    assert_eq!(st_get, StatusCode::OK);
    let (st_bulk, bulk_body) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "placeholder_mode": snapshot["placeholder_mode"],
            "hydration_max_file_size_mb": snapshot["hydration_max_file_size_mb"],
            "drives": snapshot["drives"]
        })),
    )
    .await;
    assert_eq!(
        st_bulk,
        StatusCode::OK,
        "Bulk drives roundtrip with disabled drive retaining custom_paths must succeed: {bulk_body}"
    );
    let db = find_drive(&bulk_body, "dropbox");
    assert_eq!(db["enabled"].as_bool(), Some(false));
    assert!(!db["custom_paths"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn t5_non_system_users_subdirectory_and_profile_root_consistency() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let project_users = tmp.path().join("Work").join("Users").join("MyProject");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::create_dir_all(&project_users).unwrap();
    std::fs::write(project_users.join("proj.txt"), "TOKEN_USERS_PROJECT clean").unwrap();

    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let app = build_router(Arc::clone(&state));

    // Non-system *\Users\MyProject must be permitted across marketplace/opt-in, mesh/shared-folders, and add_folder
    let (st_mkt, body_mkt) = send_json(
        &app,
        "POST",
        "/api/v1/marketplace/opt-in",
        Some(json!({
            "opt_in_enabled": true,
            "user_consent_checked": true,
            "consent_statement": "Consent for Work\\Users\\MyProject",
            "opt_in_folders": [project_users.to_string_lossy()]
        })),
    )
    .await;
    assert_eq!(
        st_mkt,
        StatusCode::OK,
        "marketplace/opt-in failed: {body_mkt}"
    );

    let (st_sf, body_sf) = send_json(
        &app,
        "POST",
        "/api/mesh/shared-folders",
        Some(json!({
            "action": "add",
            "path": project_users.to_string_lossy(),
            "enabled": true,
            "access_tier": 0
        })),
    )
    .await;
    assert_eq!(st_sf, StatusCode::OK, "shared-folders failed: {body_sf}");

    let (st_add, body_add) = send_json(
        &app,
        "POST",
        "/api/cloud-drives/config",
        Some(json!({
            "action": "add_folder",
            "id": "dropbox",
            "path": project_users.to_string_lossy()
        })),
    )
    .await;
    assert_eq!(st_add, StatusCode::OK, "add_folder failed: {body_add}");

    // Actual active profile root must fail closed with 409 across all endpoints
    for (route, body) in [
        (
            "/api/cloud-drives/config",
            json!({ "action": "add_folder", "id": "dropbox", "path": profile.to_string_lossy() }),
        ),
        (
            "/api/v1/marketplace/opt-in",
            json!({
                "opt_in_enabled": true,
                "user_consent_checked": true,
                "consent_statement": "Profile root check",
                "opt_in_folders": [profile.to_string_lossy()]
            }),
        ),
        (
            "/api/documents/add",
            json!({ "local_paths": [profile.to_string_lossy()] }),
        ),
        (
            "/api/reindex",
            json!({ "target_paths": [profile.to_string_lossy()] }),
        ),
        (
            "/api/mesh/shared-folders",
            json!({ "action": "add", "path": profile.to_string_lossy(), "enabled": true, "access_tier": 0 }),
        ),
    ] {
        let (st, resp_body) = send_json(&app, "POST", route, Some(body)).await;
        assert_eq!(
            st,
            StatusCode::CONFLICT,
            "{route} must reject active profile root with 409: {resp_body}"
        );
    }
}

#[tokio::test]
async fn t5_marketplace_opt_in_splits_strict_ancestor_and_blocks_only_cloud_parent() {
    let _lock = TEST_LOCK.lock().await;
    let tmp = tempdir().unwrap();
    let profile = tmp.path().join("Profile");
    let parent_cloud = profile.join("ParentCloud");
    let dropbox = parent_cloud.join("Dropbox");
    let sibling_dir = parent_cloud.join("SiblingNotes");
    let only_cloud_parent = profile.join("OnlyCloudParent");
    let onedrive = only_cloud_parent.join("OneDrive");
    let appdata_db = profile.join("AppData").join("Local").join("Dropbox");

    std::fs::create_dir_all(&dropbox).unwrap();
    std::fs::create_dir_all(&sibling_dir).unwrap();
    std::fs::create_dir_all(&onedrive).unwrap();
    std::fs::create_dir_all(&appdata_db).unwrap();
    std::fs::write(
        appdata_db.join("info.json"),
        json!({ "personal": { "path": dropbox.to_string_lossy() } }).to_string(),
    )
    .unwrap();
    #[cfg(not(windows))]
    {
        let posix_db = profile.join(".dropbox");
        std::fs::create_dir_all(&posix_db).unwrap();
        std::fs::write(
            posix_db.join("info.json"),
            json!({ "personal": { "path": dropbox.to_string_lossy() } }).to_string(),
        )
        .unwrap();
    }
    std::fs::write(sibling_dir.join("notes.txt"), "sibling notes").unwrap();
    std::fs::write(dropbox.join("secret.txt"), "dropbox secret").unwrap();

    // Plant OnlyCloudParent/OneDrive as disabled cloud drive in settings
    let _env = EnvGuard::set(
        "QUORUM_CLOUD_TEST_PROFILE_DIR",
        profile.to_string_lossy().as_ref(),
    );
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let state = make_test_state(&data_dir).await;
    let ctrl = quorum_coordinator::global_mesh_dlp_controller();
    {
        let mut s = ctrl.get_cloud_drives_settings();
        s.drives
            .push(quorum_types::CloudDriveConfigEntry::new_disabled(
                "custom_od",
                quorum_types::CloudDriveProvider::OneDrive,
                "OneDrive Custom",
                Some(onedrive.to_string_lossy().to_string()),
                Some("personal".to_string()),
            ));
        ctrl.update_cloud_drives_settings(s).unwrap();
    }
    let app = build_router(Arc::clone(&state));

    // OnlyCloudParent contains only disabled OneDrive -> must reject 409
    let (st_only, _) = send_json(
        &app,
        "POST",
        "/api/v1/marketplace/opt-in",
        Some(json!({
            "opt_in_enabled": true,
            "user_consent_checked": true,
            "consent_statement": "Consent",
            "opt_in_folders": [only_cloud_parent.to_string_lossy()]
        })),
    )
    .await;
    assert_eq!(st_only, StatusCode::CONFLICT);

    // ParentCloud contains Dropbox (disabled) + SiblingNotes -> splits to SiblingNotes only
    let (st_parent, body_parent) = send_json(
        &app,
        "POST",
        "/api/v1/marketplace/opt-in",
        Some(json!({
            "opt_in_enabled": true,
            "user_consent_checked": true,
            "consent_statement": "Consent",
            "opt_in_folders": [parent_cloud.to_string_lossy()]
        })),
    )
    .await;
    assert_eq!(st_parent, StatusCode::OK, "opt-in failed: {body_parent}");
    let persisted = body_parent["opt_in_folders"].as_array().unwrap();
    assert!(
        persisted.iter().any(|v| v
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("siblingnotes")),
        "Persisted opt_in_folders must retain SiblingNotes: {persisted:?}"
    );
    assert!(
        !persisted.iter().any(|v| v
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("dropbox")),
        "Persisted opt_in_folders must NOT include disabled Dropbox: {persisted:?}"
    );
    assert!(
        !persisted.iter().any(|v| {
            let s = v.as_str().unwrap_or("").to_ascii_lowercase();
            s.ends_with("parentcloud")
        }),
        "Persisted opt_in_folders must NOT store unsplit strict ancestor ParentCloud: {persisted:?}"
    );
}
