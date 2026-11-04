//! Milestone M13 Mesh REST Endpoints & TPM Hardware Attestation Integration Tests

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use quorum_coordinator::SynthesisModelFamily;
use quorum_daemon::handlers::mesh::{enqueue_pending_join, PendingJoinDto};
use quorum_daemon::{build_router, DaemonState};
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tower::ServiceExt;

async fn setup_test_app() -> axum::Router {
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

    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(
            quorum_coordinator::PeerAclManager::default(),
        )),
        quorum_coordinator::CoordinatorConfig::default(),
        [0u8; 32],
        "adversarial_test".to_string(),
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

    build_router(state)
}

#[tokio::test]
async fn test_mesh_tpm_status_endpoint() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .uri("/api/mesh/tpm/status")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(json["tpm_version"], "2.0");
    assert!(json["pcr_composite_digest"].is_string());
    assert_eq!(json["pcr_composite_digest"].as_str().unwrap().len(), 64);
    assert!(json["pcr_values"]["0"].is_string());
    assert!(json["pcr_values"]["7"].is_string());
    assert!(json["pcr_values"]["16"].is_string());
    assert!(json["rot_badge"].is_string());

    // Alias /api/tpm/status must also return OK
    let req_alias = Request::builder()
        .uri("/api/tpm/status")
        .body(Body::empty())
        .unwrap();
    let resp_alias = app.oneshot(req_alias).await.unwrap();
    assert_eq!(resp_alias.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_mesh_topology_endpoint() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .uri("/api/mesh/topology")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert!(json["local_node"].is_object());
    assert!(json["local_node"]["rot_badge"].is_string());
    assert_eq!(json["local_node"]["access_tier"], 3);
    assert!(json["peers"].is_array());

    // Aliases
    let req_top = Request::builder()
        .uri("/api/topology")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.clone().oneshot(req_top).await.unwrap().status(), StatusCode::OK);

    let req_peers = Request::builder()
        .uri("/api/peers")
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(req_peers).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn test_mesh_bootstrap_peers_endpoint() {
    let app = setup_test_app().await;

    // 1. GET bootstrap-peers
    let req_get = Request::builder()
        .uri("/api/mesh/bootstrap-peers")
        .body(Body::empty())
        .unwrap();
    let resp_get = app.clone().oneshot(req_get).await.unwrap();
    assert_eq!(resp_get.status(), StatusCode::OK);

    // 2. POST with invalid multiaddress must fail with 400 Bad Request
    let req_bad = Request::builder()
        .method("POST")
        .uri("/api/mesh/bootstrap-peers")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"peers": ["invalid_multiaddress_format"]}"#))
        .unwrap();
    let resp_bad = app.clone().oneshot(req_bad).await.unwrap();
    assert_eq!(resp_bad.status(), StatusCode::BAD_REQUEST);

    // 3. POST with valid multiaddresses must succeed
    let req_good = Request::builder()
        .method("POST")
        .uri("/api/mesh/bootstrap-peers")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            r#"{"peers": ["/ip4/10.0.0.12/tcp/3032", "/dns4/mesh.duckdns.org/tcp/3032"], "dial_now": false}"#,
        ))
        .unwrap();
    let resp_good = app.oneshot(req_good).await.unwrap();
    assert_eq!(resp_good.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_mesh_pending_joins_and_tpm_1_2_ban() {
    let app = setup_test_app().await;

    // Enqueue a legacy TPM 1.2 peer and a valid TPM 2.0 peer
    let legacy_peer_id = "12D3KooWLegacyTpm12Candidate";
    let valid_peer_id = "12D3KooWValidTpm20Candidate";

    enqueue_pending_join(PendingJoinDto {
        peer_id: legacy_peer_id.to_string(),
        multiaddr: "/ip4/192.168.1.50/tcp/3032".to_string(),
        address: "192.168.1.50:3032".to_string(),
        host_ip: "192.168.1.50".to_string(),
        port: 3032,
        transport: "tcp".to_string(),
        reputation_score: 0.4,
        reputation_label: "Low".to_string(),
        alerts_verified: 0,
        false_positives: 0,
        discovered_at: "2026-11-02T16:00:00Z".to_string(),
        discovered_date_time: "2026-11-02 16:00".to_string(),
        os: "Windows 7".to_string(),
        is_patched: false,
        os_supported: false,
        attestation_verified: false,
        attestation_state: "Legacy TPM 1.2".to_string(),
        tpm_version: "1.2".to_string(),
        tpm_badge: "TPM 1.2 (Legacy Banned)".to_string(),
        attestation_mode: "Legacy".to_string(),
        tpm_1_2_banned: true,
        is_tpm_banned: true,
        status: "pending".to_string(),
    });

    enqueue_pending_join(PendingJoinDto {
        peer_id: valid_peer_id.to_string(),
        multiaddr: "/ip4/192.168.1.51/tcp/3032".to_string(),
        address: "192.168.1.51:3032".to_string(),
        host_ip: "192.168.1.51".to_string(),
        port: 3032,
        transport: "tcp".to_string(),
        reputation_score: 0.95,
        reputation_label: "Trusted".to_string(),
        alerts_verified: 10,
        false_positives: 0,
        discovered_at: "2026-11-02T16:00:00Z".to_string(),
        discovered_date_time: "2026-11-02 16:00".to_string(),
        os: "Windows 11".to_string(),
        is_patched: true,
        os_supported: true,
        attestation_verified: true,
        attestation_state: "TPM 2.0 Hardware RoT Verified".to_string(),
        tpm_version: "2.0".to_string(),
        tpm_badge: "TPM 2.0 (Hardware Attested)".to_string(),
        attestation_mode: "TPM 2.0".to_string(),
        tpm_1_2_banned: false,
        is_tpm_banned: false,
        status: "pending".to_string(),
    });

    // 1. GET /api/mesh/pending-joins must return both
    let req_list = Request::builder()
        .uri("/api/mesh/pending-joins")
        .body(Body::empty())
        .unwrap();
    let resp_list = app.clone().oneshot(req_list).await.unwrap();
    assert_eq!(resp_list.status(), StatusCode::OK);

    // 2. Attempt to allow legacy TPM 1.2 peer MUST return 400 Bad Request
    let req_allow_legacy = Request::builder()
        .method("POST")
        .uri(format!("/api/mesh/pending-joins/{}/allow", legacy_peer_id))
        .body(Body::empty())
        .unwrap();
    let resp_allow_legacy = app.clone().oneshot(req_allow_legacy).await.unwrap();
    assert_eq!(
        resp_allow_legacy.status(),
        StatusCode::BAD_REQUEST,
        "Legacy TPM 1.2 peers must be strictly blocked!"
    );

    // 3. Allow valid TPM 2.0 peer MUST return 200 OK
    let req_allow_valid = Request::builder()
        .method("POST")
        .uri(format!("/api/mesh/pending-joins/{}/allow", valid_peer_id))
        .body(Body::empty())
        .unwrap();
    let resp_allow_valid = app.clone().oneshot(req_allow_valid).await.unwrap();
    assert_eq!(resp_allow_valid.status(), StatusCode::OK);

    // 4. Deny legacy peer
    let req_deny = Request::builder()
        .method("POST")
        .uri(format!("/api/mesh/pending-joins/{}/deny", legacy_peer_id))
        .body(Body::empty())
        .unwrap();
    let resp_deny = app.clone().oneshot(req_deny).await.unwrap();
    assert_eq!(resp_deny.status(), StatusCode::OK);

    // 5. Clear queue
    let req_clear = Request::builder()
        .method("POST")
        .uri("/api/mesh/pending-joins/clear")
        .body(Body::empty())
        .unwrap();
    let resp_clear = app.oneshot(req_clear).await.unwrap();
    assert_eq!(resp_clear.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_mesh_quarantined_peers_endpoint() {
    let app = setup_test_app().await;

    let req_list = Request::builder()
        .uri("/api/mesh/quarantined-peers")
        .body(Body::empty())
        .unwrap();
    let resp_list = app.clone().oneshot(req_list).await.unwrap();
    assert_eq!(resp_list.status(), StatusCode::OK);

    // Attempt releasing non-existent peer returns 404
    let req_rel = Request::builder()
        .method("POST")
        .uri("/api/mesh/quarantined-peers/nonexistent_peer/release")
        .body(Body::empty())
        .unwrap();
    let resp_rel = app.oneshot(req_rel).await.unwrap();
    assert_eq!(resp_rel.status(), StatusCode::NOT_FOUND);
}
