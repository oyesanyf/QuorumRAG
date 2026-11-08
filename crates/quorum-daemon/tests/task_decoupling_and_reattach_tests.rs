use axum::http::StatusCode;
use quorum_coordinator::telemetry::AgenticTelemetryEvent;
use quorum_daemon::{
    build_router, ChatHistoryStore, DaemonState, InFlightQueryRegistry, DEFAULT_TASK_GRACE_PERIOD,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tower::ServiceExt;

async fn create_test_state() -> (Arc<DaemonState>, tempfile::TempDir) {
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
        in_flight_queries: Arc::new(InFlightQueryRegistry::new()),
        sessions: quorum_daemon::ChatSessionRegistry::new(),
    });

    (state, temp_dir)
}

#[tokio::test]
async fn test_in_flight_registry_active_task_buffering_and_broadcast() {
    let registry = InFlightQueryRegistry::new();

    // 1. Register task (keep _guard alive so task is not marked completed early)
    let (task, _guard) = registry.register_task(
        "q-buff-1".to_string(),
        "s-buff-1".to_string(),
        "What is Quorum consensus?".to_string(),
        "AutoFusion".to_string(),
    );

    assert_eq!(task.query_id, "q-buff-1");
    assert_eq!(task.session_id, "s-buff-1");
    assert!(!task.is_completed());
    assert!(!task.is_cancelled());

    // 2. Buffer events in event_log
    let ev1 = AgenticTelemetryEvent::TokenDelta {
        delta: "Quorum ".to_string(),
    };
    let ev2 = AgenticTelemetryEvent::TokenDelta {
        delta: "consensus ".to_string(),
    };
    task.event_log.lock().unwrap().push(ev1.clone());
    task.event_log.lock().unwrap().push(ev2.clone());

    // 3. Atomically snapshot and subscribe
    let (snapshot, mut rx) = task.snapshot_and_subscribe();
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[0], ev1);
    assert_eq!(snapshot[1], ev2);

    // 4. Send future event via broadcaster
    let ev3 = AgenticTelemetryEvent::TokenDelta {
        delta: "is fault-tolerant.".to_string(),
    };
    task.event_log.lock().unwrap().push(ev3.clone());
    task.broadcaster.send(ev3.clone()).expect("broadcast send");

    let received = rx.recv().await.expect("broadcast recv");
    assert_eq!(received, ev3);

    // 5. Lookups by session_id and query_id
    assert!(registry.get_by_session_id("s-buff-1").is_some());
    assert!(registry.get_by_query_id("q-buff-1").is_some());
    assert_eq!(registry.list_active().len(), 1);

    // 6. Complete task and test grace period retention
    task.mark_completed();
    assert!(task.is_completed());
    assert_eq!(registry.list_active().len(), 0); // Not listed as active

    // Still accessible via session_id during grace window
    assert!(registry.get_by_session_id("s-buff-1").is_some());

    // Prune stale with standard grace period does not remove it immediately
    registry.prune_stale_default();
    assert!(registry.get_by_session_id("s-buff-1").is_some());

    assert!(DEFAULT_TASK_GRACE_PERIOD >= Duration::from_secs(30));
}

#[tokio::test]
async fn test_sqlite_chat_history_record_pending_and_cancellation() {
    let temp_dir = tempdir().expect("tempdir");
    let db_path = temp_dir.path().join("chat_history.db");
    let store = ChatHistoryStore::open(&db_path).expect("open store");

    // 1. Record pending turn
    store
        .record_pending_turn("s-sqlite-1", "Explain Byzantine fault tolerance", "AutoFusion")
        .expect("record pending");

    let detail = store
        .get_session("s-sqlite-1")
        .expect("query detail")
        .expect("session exists");

    assert_eq!(detail.session.session_id, "s-sqlite-1");
    assert_eq!(detail.messages.len(), 2);
    assert_eq!(detail.messages[0].role, "user");
    assert_eq!(detail.messages[0].content, "Explain Byzantine fault tolerance");
    assert_eq!(detail.messages[1].role, "assistant");
    assert_eq!(detail.messages[1].content, "");

    // 2. Mark turn cancelled
    store
        .mark_turn_cancelled("s-sqlite-1", None)
        .expect("mark cancelled");

    let detail_cancelled = store
        .get_session("s-sqlite-1")
        .expect("query detail")
        .expect("session exists");

    assert_eq!(detail_cancelled.messages.len(), 2);
    assert_eq!(
        detail_cancelled.messages[1].content,
        "*[Generation stopped by user]*"
    );

    // 3. Prompt regeneration: recording pending turn with same prompt resets trailing assistant turn
    store
        .record_pending_turn("s-sqlite-1", "Explain Byzantine fault tolerance", "AutoFusion")
        .expect("record pending regen");

    let detail_regen = store
        .get_session("s-sqlite-1")
        .expect("query detail")
        .expect("session exists");

    assert_eq!(
        detail_regen.messages.len(),
        2,
        "Regeneration must not create duplicate user turns"
    );
    assert_eq!(detail_regen.messages[1].content, "");

    // 4. Successful completion via record_turn updates the empty placeholder in-place
    store
        .record_turn(
            "s-sqlite-1",
            "Explain Byzantine fault tolerance",
            "BFT allows a distributed system to reach consensus despite arbitrary node failures.",
            &[],
            "12D3KooWNode1",
            "AutoFusion",
        )
        .expect("record final turn");

    let detail_final = store
        .get_session("s-sqlite-1")
        .expect("query detail")
        .expect("session exists");

    assert_eq!(detail_final.messages.len(), 2);
    assert_eq!(
        detail_final.messages[1].content,
        "BFT allows a distributed system to reach consensus despite arbitrary node failures."
    );
}

#[tokio::test]
async fn test_active_chat_tasks_endpoint_and_reattach_flow() {
    let (state, _dir) = create_test_state().await;
    let app = build_router(state.clone());

    // 1. GET /api/chat/active returns empty array initially
    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/chat/active")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let tasks = body["active_tasks"].as_array().unwrap();
    assert!(tasks.is_empty());

    // 2. Register an active task in state.in_flight_queries (keep _guard alive)
    let (task, _guard) = state.in_flight_queries.register_task(
        "q-reattach-1".to_string(),
        "s-reattach-1".to_string(),
        "Tell me about decentralized networks".to_string(),
        "AutoFusion".to_string(),
    );

    // Buffer initial token delta
    let ev1 = AgenticTelemetryEvent::TokenDelta {
        delta: "Decentralized networks ".to_string(),
    };
    task.event_log.lock().unwrap().push(ev1);

    // 3. GET /api/chat/active now returns the running task
    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/chat/active")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let tasks = body["active_tasks"].as_array().unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0]["session_id"], "s-reattach-1");
    assert_eq!(tasks[0]["query_id"], "q-reattach-1");
    assert_eq!(tasks[0]["prompt"], "Tell me about decentralized networks");

    // 4. GET /api/chat/attach/:session_id returns SSE stream containing snapshot and live events
    let task_clone = Arc::clone(&task);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let ev2 = AgenticTelemetryEvent::TokenDelta {
            delta: "operate without a central authority.".to_string(),
        };
        task_clone.event_log.lock().unwrap().push(ev2.clone());
        let _ = task_clone.broadcaster.send(ev2);

        tokio::time::sleep(Duration::from_millis(50)).await;
        let ev_final = AgenticTelemetryEvent::FinalAnswer {
            content: "Decentralized networks operate without a central authority.".to_string(),
        };
        task_clone.event_log.lock().unwrap().push(ev_final.clone());
        let _ = task_clone.broadcaster.send(ev_final);

        let ev_finished = AgenticTelemetryEvent::ExecutionFinished {
            total_hops: 1,
            total_duration_ms: 100,
            total_tokens: 30,
            final_state: quorum_coordinator::types::AgenticStateName::SynthesizeWithCitations,
            model_name: "AutoFusion".to_string(),
            responder_peer_id: "local".to_string(),
            peer_diagnostics: None,
        };
        task_clone.event_log.lock().unwrap().push(ev_finished.clone());
        let _ = task_clone.broadcaster.send(ev_finished);

        task_clone.mark_completed();
    });

    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/chat/attach/s-reattach-1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "text/event-stream"
    );

    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let sse_text = String::from_utf8_lossy(&bytes);

    assert!(
        sse_text.contains("token_delta"),
        "Stream should contain token_delta events"
    );
    assert!(
        sse_text.contains("Decentralized networks"),
        "Stream should contain snapshot event"
    );
    assert!(
        sse_text.contains("operate without a central authority"),
        "Stream should contain live broadcast event"
    );
}

#[tokio::test]
async fn test_cancel_chat_by_session_id_and_cleanup() {
    let (state, _dir) = create_test_state().await;
    let app = build_router(state.clone());

    // Register active task (keep _guard alive)
    let (task, _guard) = state.in_flight_queries.register_task(
        "q-cancel-1".to_string(),
        "s-cancel-1".to_string(),
        "Long running task to cancel".to_string(),
        "AutoFusion".to_string(),
    );

    // Record pending turn in SQLite history
    let db_path = state.data_dir.join("chat_history.db");
    let store = ChatHistoryStore::open(&db_path).expect("open store");
    store
        .record_pending_turn(
            "s-cancel-1",
            "Long running task to cancel",
            "AutoFusion",
        )
        .expect("record pending");

    // Cancel via POST /api/chat/cancel with session_id
    let cancel_payload = serde_json::json!({
        "session_id": "s-cancel-1"
    });

    let res = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/chat/cancel")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&cancel_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["status"], "cancelled");
    assert_eq!(json["session_id"], "s-cancel-1");

    // Task cancellation state
    assert!(task.is_cancelled());

    // SQLite history turn updated
    let detail = store
        .get_session("s-cancel-1")
        .expect("get detail")
        .expect("exists");
    assert_eq!(detail.messages.len(), 2);
    assert_eq!(
        detail.messages[1].content,
        "*[Generation stopped by user]*"
    );
}

#[tokio::test]
async fn test_chat_sse_handler_pending_turn_and_client_disconnect() {
    let (state, _dir) = create_test_state().await;
    let app = build_router(state.clone());

    let session_id = "s-disconnect-test-1".to_string();
    let query_id = "q-disconnect-test-1".to_string();
    let prompt_text = "What is the capital of France?".to_string();

    let chat_payload = serde_json::json!({
        "query_id": query_id,
        "session_id": session_id,
        "prompt": prompt_text,
        "model_family": "AutoFusion",
        "top_k": 4
    });

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/chat")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::to_vec(&chat_payload).unwrap(),
        ))
        .unwrap();

    let response = app.clone().oneshot(req).await.expect("Execute chat request");
    assert_eq!(response.status(), StatusCode::OK);

    // 1. Immediately verify that SQLite history has recorded the pending turn
    let db_path = state.data_dir.join("chat_history.db");
    let store = ChatHistoryStore::open(&db_path).expect("open store");
    let detail = store
        .get_session(&session_id)
        .expect("get detail")
        .expect("session exists immediately");

    assert_eq!(detail.session.session_id, session_id);
    assert_eq!(detail.messages.len(), 2);
    assert_eq!(detail.messages[0].role, "user");
    assert_eq!(detail.messages[0].content, prompt_text);
    assert_eq!(detail.messages[1].role, "assistant");
    assert_eq!(detail.messages[1].content, "");

    // 2. Verify active task is registered in in_flight_queries
    assert!(state
        .in_flight_queries
        .get_by_session_id(&session_id)
        .is_some());

    // 3. Simulate browser disconnect: drop the response body stream immediately
    drop(response);

    // 4. Query /api/chat/active: verify the task is still running after client dropped connection
    let active_tasks = state.in_flight_queries.list_active();
    assert!(
        active_tasks.iter().any(|t| t.session_id == session_id),
        "Background task must continue running after client disconnect"
    );

    // 5. Query /api/chat/attach/:session_id: verify another client/tab can attach to the running task
    let attach_req = axum::http::Request::builder()
        .uri(format!("/api/chat/attach/{}", session_id))
        .body(axum::body::Body::empty())
        .unwrap();

    let attach_res = app.oneshot(attach_req).await.expect("attach request");
    assert_eq!(attach_res.status(), StatusCode::OK);
    let ct = attach_res
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(ct, "text/event-stream");
}
