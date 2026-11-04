//! Empirical Challenger Test Suite for QuorumRAG Web API & Static Asset Routing
//!
//! Evaluates:
//! 1. Static asset routing:
//!    - `/assets/styles.css`, `/styles.css`, `/assets/app.js`, `/app.js`, `/langextract.html`, `/favicon.svg`
//!    - SPA fallback returning `index.html` on unknown routes with `StatusCode::OK`
//! 2. API routes:
//!    - `/api/health`: 200 OK and valid JSON
//!    - `/api/chat`: POST request handling, error handling on malformed JSON
//!    - `/api/shutdown`: verify endpoint responds and triggers notify

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use quorum_coordinator::SynthesisModelFamily;
use quorum_daemon::{build_router, DaemonState};
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tower::ServiceExt;

async fn setup_test_app() -> (axum::Router, Arc<tokio::sync::Notify>) {
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
        port: 3030,
        host: "127.0.0.1".to_string(),
        data_dir,
        shutdown_notify: Arc::clone(&shutdown_notify),
        in_flight_queries: Arc::new(quorum_daemon::InFlightQueryRegistry::new()),
        sessions: quorum_daemon::ChatSessionRegistry::new(),
    });

    (build_router(state), shutdown_notify)
}

#[tokio::test]
async fn challenge_api_health() {
    let (app, _) = setup_test_app().await;

    let req = Request::builder()
        .uri("/api/health")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.expect("health request");
    assert_eq!(response.status(), StatusCode::OK);

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(content_type.contains("application/json"), "Expected json, got: {}", content_type);

    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");

    assert_eq!(json["status"], "healthy");
    assert_eq!(json["version"], "0.1.0");
    assert!(json["contract_hash"].is_string());
    assert!(!json["contract_hash"].as_str().unwrap().is_empty());
    assert!(json["storage"].is_object());
    assert!(json["hardware"].is_object());
}

#[tokio::test]
async fn challenge_api_chat_valid_and_malformed() {
    let (app, _) = setup_test_app().await;

    // 1. Valid POST /api/chat
    let valid_payload = serde_json::json!({
        "prompt": "What is QuorumRAG?",
        "model_family": "AutoFusion",
        "top_k": 4
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/chat")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&valid_payload).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.expect("valid chat");
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(ct.contains("text/event-stream"));

    // 2. Malformed JSON POST /api/chat (syntax error: unclosed brace)
    let malformed_req = Request::builder()
        .method("POST")
        .uri("/api/chat")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"{\"prompt\": \"broken json".to_vec()))
        .unwrap();

    let resp_malformed = app.clone().oneshot(malformed_req).await.expect("malformed chat");
    // Axum Json extractor returns 400 or 422 for malformed json
    assert!(
        resp_malformed.status() == StatusCode::BAD_REQUEST
            || resp_malformed.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Malformed JSON must return 400 or 422, got: {:?}",
        resp_malformed.status()
    );

    // 3. Completely invalid body (random garbage bytes)
    let garbage_req = Request::builder()
        .method("POST")
        .uri("/api/chat")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(vec![0xFF, 0xFE, 0xFD, 0x00, 0x12]))
        .unwrap();

    let resp_garbage = app.clone().oneshot(garbage_req).await.expect("garbage chat");
    assert!(
        resp_garbage.status() == StatusCode::BAD_REQUEST
            || resp_garbage.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Garbage bytes must return 400 or 422, got: {:?}",
        resp_garbage.status()
    );
}

#[tokio::test]
async fn challenge_api_shutdown_endpoint() {
    let (app, shutdown_notify) = setup_test_app().await;

    // Verify notify is triggered upon calling POST /api/shutdown
    let shutdown_signal = Arc::clone(&shutdown_notify);
    let notified_tracker = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let tracker_clone = Arc::clone(&notified_tracker);

    tokio::spawn(async move {
        shutdown_signal.notified().await;
        tracker_clone.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    // Give background task a moment to register notification listener
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/shutdown")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.expect("shutdown request");
    assert_eq!(resp.status(), StatusCode::OK);

    // Wait briefly and verify notification was received
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        notified_tracker.load(std::sync::atomic::Ordering::SeqCst),
        "POST /api/shutdown must trigger shutdown_notify.notify_one()"
    );
}

#[tokio::test]
async fn challenge_static_assets_routing() {
    let (app, _) = setup_test_app().await;

    // Test assets via /assets/ prefix
    let test_assets = [
        ("/assets/styles.css", "text/css"),
        ("/assets/app.js", "javascript"),
        ("/assets/langextract.html", "text/html"),
        ("/assets/favicon.svg", "image/svg+xml"),
    ];

    for (path, expected_mime) in test_assets {
        let req = Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.expect("asset request");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Path '{}' must return 200 OK, got: {:?}",
            path,
            resp.status()
        );

        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.contains(expected_mime),
            "Path '{}' expected MIME '{}', got: '{}'",
            path,
            expected_mime,
            ct
        );

        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read asset body");
        assert!(!body_bytes.is_empty(), "Path '{}' returned empty body", path);
    }
}

#[tokio::test]
async fn challenge_static_assets_direct_and_spa_fallback() {
    let (app, _) = setup_test_app().await;

    // Check direct paths without /assets/ prefix on app
    let direct_assets = [
        ("/styles.css", "text/css"),
        ("/app.js", "javascript"),
        ("/langextract.html", "text/html"),
        ("/favicon.svg", "image/svg+xml"),
    ];

    for (path, expected_mime) in direct_assets {
        let req = Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.expect("direct request");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Direct route '{}' on daemon router must return StatusCode::OK, got: {:?}",
            path,
            resp.status()
        );
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.contains(expected_mime),
            "Direct route '{}' expected MIME '{}', got: '{}'",
            path,
            expected_mime,
            ct
        );
    }

    // Check SPA fallback on arbitrary routes returns 200 OK with index.html and text/html
    for spa_path in ["/unknown/spa/route/123", "/chat/456"] {
        let req = Request::builder()
            .uri(spa_path)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.expect("spa request");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "SPA route '{}' on daemon router must return StatusCode::OK (fallback to index.html), got: {:?}",
            spa_path,
            resp.status()
        );
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.contains("text/html"),
            "SPA route '{}' expected MIME 'text/html', got: '{}'",
            spa_path,
            ct
        );
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .expect("read body");
        let html = String::from_utf8_lossy(&body_bytes);
        assert!(
            html.contains("QuorumRAG"),
            "SPA fallback for '{}' must return index.html content",
            spa_path
        );
    }
}

