//! Empirical Adversarial Stress Suite for QuorumRAG Daemon Endpoints
//!
//! Areas Covered:
//! 1. Endpoint Concurrency Stress (simultaneous /api/health, /api/models, /api/query)
//! 2. SSE Streaming Protocol & Syntax Assertions (text/event-stream, data: line format, AgenticTelemetryEvent parsing)
//! 3. Google LangExtract Standalone Visualizer Integrity & Pastel Spans
//! 4. Fail-Closed Path Traversal Gating on /api/langextract and /api/langextract/visualize

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use futures_util::future::join_all;
use quorum_coordinator::{AgenticTelemetryEvent, SynthesisModelFamily};
use quorum_daemon::{build_router, DaemonState};
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tower::ServiceExt;

async fn setup_test_app() -> axum::Router {
    setup_test_app_with_state().await.0
}

async fn setup_test_app_with_state() -> (axum::Router, Arc<DaemonState>) {
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
        shutdown_notify: Arc::new(tokio::sync::Notify::new()),
        in_flight_queries: Arc::new(quorum_daemon::InFlightQueryRegistry::new()),
        sessions: quorum_daemon::ChatSessionRegistry::new(),
    });

    (build_router(Arc::clone(&state)), state)
}

// ============================================================================
// 1. ENDPOINT CONCURRENCY STRESS
// ============================================================================

#[tokio::test]
async fn test_endpoint_concurrency_stress() {
    let app = setup_test_app().await;

    // Dispatch 30 simultaneous requests across health, models, and query endpoints
    let mut tasks = Vec::new();
    for i in 0..30 {
        let app_clone = app.clone();
        let task = tokio::spawn(async move {
            let req = match i % 3 {
                0 => Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
                1 => Request::builder()
                    .uri("/api/models")
                    .body(Body::empty())
                    .unwrap(),
                _ => {
                    let body = serde_json::json!({
                        "prompt": format!("Concurrent query test prompt {}", i),
                        "model_family": "AutoFusion"
                    });
                    Request::builder()
                        .method("POST")
                        .uri("/api/query")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap()
                }
            };

            let response = app_clone.oneshot(req).await.expect("Request execution");
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "Request {} failed with status: {:?}",
                i,
                response.status()
            );
        });
        tasks.push(task);
    }

    let results = join_all(tasks).await;
    for (idx, res) in results.into_iter().enumerate() {
        assert!(res.is_ok(), "Task {} panicked or failed", idx);
    }
}

// ============================================================================
// 2. SSE STREAMING PROTOCOL & SYNTAX STRESS
// ============================================================================

#[tokio::test]
async fn test_chat_sse_stream_format_and_event_types() {
    let app = setup_test_app().await;

    let chat_payload = serde_json::json!({
        "prompt": "How does Reciprocal Rank Fusion combine vector and BM25 scores?",
        "model_family": "Glm4Agentic",
        "top_k": 4
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/chat")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&chat_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(req).await.expect("Execute chat request");
    assert_eq!(response.status(), StatusCode::OK);

    // Verify Content-Type is text/event-stream
    let ct = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .expect("Content-Type header");
    assert!(
        ct.starts_with("text/event-stream"),
        "Expected text/event-stream, got: {}",
        ct
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("Read SSE stream bytes");
    let stream_text = String::from_utf8_lossy(&body_bytes);

    // Parse lines according to SSE specification
    let mut data_events = Vec::new();
    for line in stream_text.lines() {
        if line.starts_with("data:") {
            let data_str = line.trim_start_matches("data:").trim();
            if !data_str.is_empty() {
                // Must deserialize into valid AgenticTelemetryEvent
                let event: AgenticTelemetryEvent = serde_json::from_str(data_str)
                    .unwrap_or_else(|e| panic!("Failed to parse SSE event JSON '{}': {}", data_str, e));
                data_events.push(event);
            }
        }
    }

    assert!(
        !data_events.is_empty(),
        "SSE stream must produce at least one data: event"
    );

    // Verify token deltas or stage transitions were emitted
    let has_token_or_state = data_events.iter().any(|e| {
        matches!(
            e,
            AgenticTelemetryEvent::TokenDelta { .. }
                | AgenticTelemetryEvent::StateTransition { .. }
                | AgenticTelemetryEvent::ExecutionFinished { .. }
        )
    });
    assert!(
        has_token_or_state,
        "SSE stream must contain TokenDelta, StateTransition, or ExecutionFinished events"
    );
}

#[tokio::test]
async fn test_chat_sse_empty_prompt_emits_error_cleanly() {
    let app = setup_test_app().await;

    let empty_payload = serde_json::json!({
        "prompt": "   ",
        "model_family": "AutoFusion"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/chat")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&empty_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(req).await.expect("Execute chat request");
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("Read SSE stream bytes");
    let stream_text = String::from_utf8_lossy(&body_bytes);

    // Verify error event was emitted gracefully
    assert!(
        stream_text.contains("ExecutionError") || stream_text.contains("empty"),
        "Empty prompt must yield ExecutionError event without panicking"
    );
}

#[tokio::test]
async fn test_chat_stream_compat_get_endpoint() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/chat/stream?prompt=test%20query&model_family=AutoFusion")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.expect("Execute GET stream compat");
    assert_eq!(response.status(), StatusCode::OK);

    let ct = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        ct.starts_with("text/event-stream"),
        "GET /api/chat/stream must return text/event-stream, got: {}",
        ct
    );
}

// ============================================================================
// 3. GOOGLE LANGEXTRACT VISUALIZER & GROUNDING ACCURACY
// ============================================================================

#[tokio::test]
async fn test_langextract_visualizer_html_integrity() {
    let app = setup_test_app().await;

    let rust_code = r#"
pub struct RrfCombiner;
impl RrfCombiner {
    pub fn compute_rrf_score(rank: usize) -> f32 {
        1.0 / (60.0 + rank as f32)
    }
}
"#;

    let req_body = serde_json::json!({
        "text": rust_code
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/langextract/visualize")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let response = app.oneshot(req).await.expect("Execute visualize request");
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("Read HTML body");
    let html = String::from_utf8_lossy(&body_bytes);

    // 1. Must be complete standalone HTML
    assert!(html.contains("<!DOCTYPE html>"), "Must declare <!DOCTYPE html>");
    assert!(html.contains("<html") && html.contains("</html>"), "Must have html tags");
    assert!(html.contains("<head>") && html.contains("</head>"), "Must have head tags");
    assert!(html.contains("<body>") && html.contains("</body>"), "Must have body tags");

    // 2. Must contain embedded styling
    assert!(html.contains("<style>"), "Must have embedded style block");

    // 3. Must contain pastel highlight color codes
    let has_pastel = html.contains("#D2E3FC") || html.contains("#FFE082") || html.contains("#C8E6C9");
    assert!(has_pastel, "Must contain pastel entity highlight color codes");

    // 4. Must contain mark spans with data-idx attribute
    assert!(
        html.contains("<mark class=\"lx-span\"") && html.contains("data-idx="),
        "Must contain <mark class=\"lx-span\" data-idx=\"...\"> highlight spans"
    );

    // 5. Must escape HTML tags in text to prevent XSS
    let xss_test_code = "fn evil() { let _x = \"<script>alert('xss')</script>\"; }";
    let xss_req_body = serde_json::json!({ "text": xss_test_code });
    let xss_req = Request::builder()
        .method("POST")
        .uri("/api/langextract/visualize")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&xss_req_body).unwrap()))
        .unwrap();

    let xss_resp = setup_test_app().await.oneshot(xss_req).await.unwrap();
    let xss_bytes = axum::body::to_bytes(xss_resp.into_body(), 1024 * 1024).await.unwrap();
    let xss_html = String::from_utf8_lossy(&xss_bytes);

    assert!(
        !xss_html.contains("<script>alert"),
        "Raw unescaped script tag leaked into visualizer HTML!"
    );
    assert!(
        xss_html.contains("&lt;script&gt;alert"),
        "Script tag must be safely HTML escaped"
    );
}

// ============================================================================
// 4. FAIL-CLOSED DIRECTORY TRAVERSAL GATING ON LANGEXTRACT
// ============================================================================

#[tokio::test]
async fn test_langextract_directory_traversal_blocked_fail_closed() {
    let app = setup_test_app().await;

    let traversal_paths = [
        "../../Cargo.toml",
        "/../../etc/passwd",
        "..\\..\\Cargo.toml",
        "subdir/../../../windows/win.ini",
    ];

    for path in traversal_paths {
        // Test POST /api/langextract
        let req_body = serde_json::json!({
            "file_path": path
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/langextract")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(req).await.expect("Execute request");
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "Path '{}' on /api/langextract must return 403 Forbidden, got: {:?}",
            path,
            response.status()
        );

        // Test POST /api/langextract/visualize
        let req_vis = Request::builder()
            .method("POST")
            .uri("/api/langextract/visualize")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
            .unwrap();

        let response_vis = app.clone().oneshot(req_vis).await.expect("Execute request");
        assert_eq!(
            response_vis.status(),
            StatusCode::FORBIDDEN,
            "Path '{}' on /api/langextract/visualize must return 403 Forbidden, got: {:?}",
            path,
            response_vis.status()
        );
    }
}

#[tokio::test]
async fn test_chat_cancel_endpoint_and_index_status_alias() {
    let (app, state) = setup_test_app_with_state().await;

    // 1. Nonexistent query_id -> returns 200 OK with cancelled: false
    let cancel_req_nonexistent = serde_json::json!({
        "query_id": "test-query-nonexistent-1234"
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/chat/cancel")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&cancel_req_nonexistent).unwrap()))
        .unwrap();

    let response = app.clone().oneshot(req).await.expect("Execute cancel request");
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let cancel_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(cancel_json["status"], "cancelled");
    assert_eq!(cancel_json["query_id"], "test-query-nonexistent-1234");
    assert_eq!(
        cancel_json["cancelled"], false,
        "Nonexistent query_id must return cancelled: false without panicking"
    );

    // 2. Active query_id -> returns 200 OK with cancelled: true and backend task terminates immediately
    let active_id = "test-active-live-query-9876";
    let (entry, guard) = state.in_flight_queries.register(active_id.to_string());
    let bg_task = tokio::spawn(async move {
        let _guard = guard;
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    });
    entry.set_abort_handle(bg_task.abort_handle());
    assert!(!bg_task.is_finished(), "Task must be active prior to cancellation");

    let cancel_req_active = serde_json::json!({
        "query_id": active_id
    });
    let req_active = Request::builder()
        .method("POST")
        .uri("/api/chat/cancel")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&cancel_req_active).unwrap()))
        .unwrap();

    let resp_active = app.clone().oneshot(req_active).await.expect("Execute active cancel");
    assert_eq!(resp_active.status(), StatusCode::OK);
    let active_bytes = axum::body::to_bytes(resp_active.into_body(), usize::MAX)
        .await
        .unwrap();
    let active_json: serde_json::Value = serde_json::from_slice(&active_bytes).unwrap();
    assert_eq!(active_json["status"], "cancelled");
    assert_eq!(active_json["query_id"], active_id);
    assert_eq!(
        active_json["cancelled"], true,
        "Active query_id must return cancelled: true"
    );

    // Wait a brief moment for tokio abort handle to terminate background task and drop guard
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert!(
        bg_task.is_finished(),
        "Backend background query task must terminate immediately upon cancellation"
    );
    assert!(entry.token.is_cancelled());

    // Subsequent cancel on the same query ID must now return cancelled: false (clean eviction)
    let req_after = Request::builder()
        .method("POST")
        .uri("/api/chat/cancel")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&cancel_req_active).unwrap()))
        .unwrap();
    let resp_after = app.clone().oneshot(req_after).await.unwrap();
    assert_eq!(resp_after.status(), StatusCode::OK);
    let after_bytes = axum::body::to_bytes(resp_after.into_body(), usize::MAX).await.unwrap();
    let after_json: serde_json::Value = serde_json::from_slice(&after_bytes).unwrap();
    assert_eq!(
        after_json["cancelled"], false,
        "Subsequent cancel must return cancelled: false as guard was evicted"
    );

    // 3. Test GET /api/index/status route alias
    let req_idx = Request::builder()
        .method("GET")
        .uri("/api/index/status")
        .body(Body::empty())
        .unwrap();

    let resp_idx = app.clone().oneshot(req_idx).await.expect("Execute index status request");
    assert_eq!(resp_idx.status(), StatusCode::OK);
    let idx_bytes = axum::body::to_bytes(resp_idx.into_body(), usize::MAX)
        .await
        .unwrap();
    let idx_json: serde_json::Value = serde_json::from_slice(&idx_bytes).unwrap();
    assert!(idx_json.get("percent").is_some(), "percent field missing");
    assert!(idx_json["percent"].is_number(), "percent must be numeric");
    assert!(idx_json.get("phase").is_some(), "phase field missing");
    assert!(idx_json["phase"].is_string(), "phase must be string");
    assert!(idx_json.get("files_scanned").is_some(), "files_scanned field missing");
    assert!(idx_json["files_scanned"].is_number(), "files_scanned must be integer");
    assert!(idx_json.get("files_total_estimated").is_some(), "files_total_estimated field missing");
    assert!(idx_json["files_total_estimated"].is_number(), "files_total_estimated must be integer");
    assert!(idx_json.get("total_stored_chunks").is_some(), "total_stored_chunks field missing");
    assert!(idx_json["total_stored_chunks"].is_number(), "total_stored_chunks must be integer");

    // 4. Test GET /api/reindex/status matches exact schema
    let req_reidx = Request::builder()
        .method("GET")
        .uri("/api/reindex/status")
        .body(Body::empty())
        .unwrap();

    let resp_reidx = app.clone().oneshot(req_reidx).await.expect("Execute reindex status request");
    assert_eq!(resp_reidx.status(), StatusCode::OK);
    let reidx_bytes = axum::body::to_bytes(resp_reidx.into_body(), usize::MAX).await.unwrap();
    let reidx_json: serde_json::Value = serde_json::from_slice(&reidx_bytes).unwrap();
    assert_eq!(reidx_json["phase"], idx_json["phase"]);
    assert_eq!(reidx_json["percent"], idx_json["percent"]);
    assert_eq!(reidx_json["files_scanned"], idx_json["files_scanned"]);
    assert_eq!(reidx_json["files_total_estimated"], idx_json["files_total_estimated"]);
    assert_eq!(reidx_json["total_stored_chunks"], idx_json["total_stored_chunks"]);
}

#[tokio::test]
async fn test_in_flight_registry_500_concurrency_and_zero_leak_stress() {
    let registry = Arc::new(quorum_daemon::InFlightQueryRegistry::new());

    // Concurrently register 500 active query IDs with active background tasks
    let mut tasks = Vec::new();
    let mut query_ids = Vec::new();

    for i in 0..500 {
        let qid = format!("concurrency-query-{:04}", i);
        query_ids.push(qid.clone());
        let (entry, guard) = registry.register(qid);

        let handle = tokio::spawn(async move {
            let _guard = guard;
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        });
        entry.set_abort_handle(handle.abort_handle());
        tasks.push(handle);
    }

    // Verify all 500 are running
    for t in &tasks {
        assert!(!t.is_finished(), "Task must be active before abort");
    }

    // Concurrently abort all 500 queries across 10 parallel worker tasks
    let mut abort_workers = Vec::new();
    for chunk in query_ids.chunks(50) {
        let reg = Arc::clone(&registry);
        let ids: Vec<String> = chunk.to_vec();
        abort_workers.push(tokio::spawn(async move {
            for id in ids {
                let cancelled = reg.cancel(&id);
                assert!(cancelled, "Cancel must return true for active query {}", id);
            }
        }));
    }

    for w in abort_workers {
        w.await.expect("Abort worker panicked");
    }

    // Wait a brief window for tokio aborts and guard drops to process
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;

    // Verify that every background query task terminated immediately
    for (i, t) in tasks.iter().enumerate() {
        assert!(
            t.is_finished(),
            "Background task {} must be finished after abort",
            i
        );
    }

    // Assert registry is completely empty (zero lingering entries, zero leaks)
    assert_eq!(
        registry.cancel_all(),
        0,
        "Registry must be completely empty with 0 active handles after all guards dropped"
    );
}

#[tokio::test]
async fn test_client_disconnect_token_streaming_and_agentic_loop_stress() {
    use quorum_coordinator::{
        DeterministicOfflineSynthesisEngine, QueryCoordinator, CoordinatorConfig,
        LocalOnlyDispatcher, PeerAclManager, ScatterGatherEngine, StorageSearcher,
    };
    use quorum_types::{DocumentChunk, ScoredChunk};
    use tokio::sync::mpsc;

    // 1. Test offline_engine token streaming loop disconnect response
    let (tx, rx) = mpsc::channel::<AgenticTelemetryEvent>(32);
    // Drop receiver immediately to simulate client TCP/HTTP disconnect
    drop(rx);
    assert!(tx.is_closed(), "tx must be closed when rx is dropped");

    let chunk = DocumentChunk::new(
        "test_c1",
        "doc_disconnect",
        "C:/docs/report.txt",
        1,
        20,
        0,
        vec![0.1; 768],
        "This is a lengthy document content with many distinct words to ensure the streaming loop would take multiple iterations if not aborted immediately upon client disconnect.",
        None,
    )
    .expect("valid chunk");
    let scored = ScoredChunk::new(chunk, 0.95, "local", false);

    let start = std::time::Instant::now();
    let (body, _citations) = DeterministicOfflineSynthesisEngine::synthesize_with_history(
        "lengthy document report",
        "lengthy document report",
        &[],
        &[scored],
        "glm4:9b",
        Some(&tx),
    );
    let elapsed = start.elapsed();

    // Verify token streaming broke out immediately (<60ms) instead of sleeping for each word
    assert!(
        elapsed < std::time::Duration::from_millis(60),
        "Streaming loop must terminate immediately upon tx.is_closed(), took: {:?}",
        elapsed
    );
    assert!(!body.is_empty(), "Body must contain synthesized text");

    // 2. Test AgenticStateGraph loop disconnect response
    let temp_dir = tempdir().expect("tempdir");
    let data_dir = temp_dir.path().to_path_buf();
    let storage_config = quorum_storage::StorageConfig::new(data_dir);
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(storage_config)
            .await
            .expect("storage open"),
    );

    let coordinator_engine = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageSearcher>,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0u8; 32],
        "disconnect_test".to_string(),
    ));

    let coordinator = QueryCoordinator::new(
        coordinator_engine,
        CoordinatorConfig::default(),
    );

    let (tx2, rx2) = mpsc::channel::<AgenticTelemetryEvent>(32);
    drop(rx2); // Client disconnect before/during execution

    let graph_start = std::time::Instant::now();
    let result = coordinator
        .query_agentic_with_history(
            "test query disconnect",
            vec![],
            SynthesisModelFamily::AutoFusion,
            10,
            Some(tx2),
        )
        .await;

    let graph_elapsed = graph_start.elapsed();
    assert!(
        result.is_ok(),
        "query_agentic_with_history must return Ok on client disconnect without panicking: {:?}",
        result
    );
    assert!(
        graph_elapsed < std::time::Duration::from_millis(500),
        "Agentic graph must break on tx.is_closed() within 500ms, took: {:?}",
        graph_elapsed
    );
}
