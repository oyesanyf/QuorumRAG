use axum::http::StatusCode;
use clap::Parser;
use quorum_daemon::{build_router, Cli, Commands, DaemonState};
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tower::ServiceExt; // for oneshot

#[test]
fn test_cli_parsing_default_and_flags() {
    // 1. Default CLI arguments
    let cli = Cli::parse_from(["quorumrag"]);
    assert_eq!(cli.port, 3030);
    assert_eq!(cli.host, "0.0.0.0");
    assert!(!cli.no_browser, "Default should not disable browser");
    assert!(cli.command.is_none());

    // 2. Headless/no-browser CLI flag
    let cli_headless = Cli::parse_from(["quorumrag", "--no-browser", "--port", "8080"]);
    assert!(cli_headless.no_browser);
    assert_eq!(cli_headless.port, 8080);

    // 3. Reindex subcommand
    let cli_reindex = Cli::parse_from(["quorumrag", "reindex", "--full", "--batch-size", "128"]);
    match cli_reindex.command {
        Some(Commands::Reindex { full, batch_size, .. }) => {
            assert!(full);
            assert_eq!(batch_size, 128);
        }
        _ => panic!("Expected Reindex subcommand"),
    }

    // 4. Fix-drift subcommand
    let cli_drift = Cli::parse_from(["quorumrag", "fix-drift", "--dry-run", "--drift-type", "merkle_state"]);
    match cli_drift.command {
        Some(Commands::FixDrift { dry_run, drift_type }) => {
            assert!(dry_run);
            assert_eq!(drift_type, Some("merkle_state".to_string()));
        }
        _ => panic!("Expected FixDrift subcommand"),
    }
}

#[tokio::test]
async fn test_daemon_server_routes_and_health() {
    let temp_dir = tempdir().expect("tempdir");
    let data_dir = temp_dir.path().to_path_buf();

    let storage_config = quorum_storage::StorageConfig::new(data_dir.clone());
    let storage = Arc::new(quorum_storage::StorageEngine::open(storage_config).await.expect("storage open"));
    let classifier = Arc::new(quorum_classifier::FileTypeClassifier::new());
    let embedder: Arc<dyn quorum_contract::EmbeddingGenerator> = Arc::new(quorum_contract::DeterministicOfflineEngine::new());
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
        Arc::new(tokio::sync::RwLock::new(quorum_coordinator::PeerAclManager::default())),
        quorum_coordinator::CoordinatorConfig::default(),
        [0u8; 32],
        "local_test".to_string(),
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
        default_model_family: quorum_coordinator::SynthesisModelFamily::AutoFusion,
        port: 3030,
        host: "127.0.0.1".to_string(),
        data_dir,
        shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        in_flight_queries: Arc::new(quorum_daemon::InFlightQueryRegistry::new()),
        sessions: quorum_daemon::ChatSessionRegistry::new(),
    });

    let app = build_router(state);

    // Test GET /
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test GET /api/health
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let health_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(health_json["status"], "healthy");
    assert!(!health_json["contract_hash"].as_str().unwrap().is_empty());

    // Test GET /api/models
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/models")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test POST /api/langextract
    let req_body = serde_json::json!({
        "text": "pub struct RrfCombiner;\nimpl RrfCombiner { pub fn compute_rrf_score() {} }"
    });
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/langextract")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let lx_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(lx_json["consensus_passed"], true);

    // Test POST /api/shutdown
    let response = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/shutdown")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
