//! Adversarial Integration & Endpoint Stress Tests for Feature 43:
//! CLI and REST `/api/cache/recache` and `/api/cache/stats` endpoints.

use axum::http::{Request, StatusCode};
use clap::Parser;
use quorum_daemon::{build_router, Cli, Commands, DaemonState};
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tower::ServiceExt;

/// Helper to build a test DaemonState and router.
async fn create_test_daemon() -> (axum::Router, Arc<DaemonState>, tempfile::TempDir) {
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

    let app = build_router(Arc::clone(&state));
    (app, state, temp_dir)
}

#[tokio::test]
async fn test_rest_cache_stats_and_recache_endpoints() {
    let (app, state, _dir) = create_test_daemon().await;

    // 1. Initial GET /api/cache/stats
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/cache/stats")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let stats: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(stats["status"], "ok");
    assert_eq!(stats["cache_epoch"], 1);
    assert_eq!(stats["hits"], 0);
    assert_eq!(stats["misses"], 0);
    assert_eq!(stats["cached_queries"], 0);
    assert_eq!(stats["cached_embeddings"], 0);

    // 2. Pre-populate some items in coordinator cache
    state.coordinator.cache_manager.embedding_cache.insert(&[0x11; 32], "test embedding text", vec![0.1; 768]);
    state.coordinator.cache_manager.query_cache.insert(
        "sample query",
        quorum_storage::SearchMode::Hybrid,
        quorum_coordinator::SynthesisModelFamily::AutoFusion,
        1,
        1,
        Vec::new(),
        "prompt".to_string(),
        Some("response".to_string()),
        Vec::new(),
        None,
        None,
    );

    // Verify stats updated
    let resp_after_insert = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/cache/stats")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes2 = axum::body::to_bytes(resp_after_insert.into_body(), 64 * 1024).await.unwrap();
    let stats2: serde_json::Value = serde_json::from_slice(&bytes2).unwrap();
    assert_eq!(stats2["cached_queries"], 1);
    assert_eq!(stats2["cached_embeddings"], 1);

    // 3. POST /api/cache/recache with clear: true, warm: true
    let req_body = serde_json::json!({
        "clear": true,
        "warm": true
    });
    let recache_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/cache/recache")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(recache_resp.status(), StatusCode::OK);
    let bytes3 = axum::body::to_bytes(recache_resp.into_body(), 64 * 1024).await.unwrap();
    let recache_json: serde_json::Value = serde_json::from_slice(&bytes3).unwrap();

    assert_eq!(recache_json["status"], "ok");
    assert!(recache_json["cache_epoch"].as_u64().unwrap() >= 2);
    assert!(recache_json["cleared_entries"].as_u64().unwrap() >= 2, "Cleared entries must count both query and embedding cache");

    // 4. Verify /api/health includes cache block
    let health_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(health_resp.status(), StatusCode::OK);
    let bytes_health = axum::body::to_bytes(health_resp.into_body(), 64 * 1024).await.unwrap();
    let health_json: serde_json::Value = serde_json::from_slice(&bytes_health).unwrap();
    assert!(health_json.get("cache").is_some(), "/api/health must expose cache telemetry");
    assert_eq!(health_json["cache"]["cache_epoch"], recache_json["cache_epoch"]);
}

#[test]
fn test_cli_parsing_recache_subcommand() {
    // 1. quorumrag recache --clear --warm
    let cli_full = Cli::parse_from(["quorumrag", "recache", "--clear", "--warm"]);
    match cli_full.command {
        Some(Commands::Recache { clear, warm }) => {
            assert!(clear, "clear flag must be true");
            assert!(warm, "warm flag must be true");
        }
        _ => panic!("Expected Recache subcommand with flags"),
    }

    // 2. quorumrag recache (defaults)
    let cli_default = Cli::parse_from(["quorumrag", "recache"]);
    match cli_default.command {
        Some(Commands::Recache { clear, warm }) => {
            assert!(!clear, "clear default must be false");
            assert!(!warm, "warm default must be false");
        }
        _ => panic!("Expected Recache subcommand with defaults"),
    }
}
