//! Integration tests for SQLite Chat History persistence, WAL checkpointing,
//! single-session deletion, user-initiated Clear All, and error recovery.

use axum::http::StatusCode;
use quorum_daemon::{build_router, DaemonState};
use quorum_daemon::chat_history_db::ChatHistoryStore;
use quorum_types::Citation;
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tower::ServiceExt;

fn sample_citation(peer: &str, file: &str, snippet: &str) -> Citation {
    Citation {
        peer_id: peer.to_string(),
        file_path: file.to_string(),
        line_start: 1,
        line_end: 25,
        score: 0.94,
        snippet: snippet.to_string(),
        node_id: Some(peer.to_string()),
        is_external_node: peer != "local",
        origin_label: Some(if peer == "local" { "local".to_string() } else { "mesh".to_string() }),
        node_alias: None,
        verbatim_quote: None,
        byte_range: None,
        grounding_rationale: None,
    }
}

#[test]
fn test_sqlite_chat_history_durability_across_reloads_after_checkpoint() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("chat_history.db");

    // Phase 1: Open store, record multiple sessions with citations
    {
        let store = ChatHistoryStore::open(&db_path).expect("open store");

        let cit1 = sample_citation("12D3KooWPeerA", "D:\\docs\\Quantum_Cryptography.pdf", "Post-quantum lattice signatures");
        store
            .record_turn(
                "session-alpha",
                "Explain lattice-based post-quantum cryptography",
                "Lattice-based cryptography relies on the hardness of lattice problems [1].",
                &[cit1],
                "12D3KooWPeerA",
                "AutoFusion",
            )
            .expect("record turn 1");

        let cit2 = sample_citation("local", "D:\\docs\\Zero_Trust_Architecture.docx", "Microsegmentation and least privilege");
        store
            .record_turn(
                "session-beta",
                "What is zero trust microsegmentation?",
                "Zero trust enforces perimeter-less continuous verification [1].",
                &[cit2],
                "local",
                "Gemma4_26b",
            )
            .expect("record turn 2");

        // Flush and truncate WAL
        store.checkpoint().expect("WAL checkpoint");
    }

    // Phase 2: Simulate daemon process exit and restart by reopening from disk
    {
        let reopened = ChatHistoryStore::open(&db_path).expect("reopen store");

        let sessions = reopened.list_sessions(10).expect("list sessions");
        assert_eq!(sessions.len(), 2, "Both sessions must persist across reopen");

        let alpha = reopened
            .get_session("session-alpha")
            .expect("query session-alpha")
            .expect("session-alpha must exist");
        assert_eq!(alpha.session.title, "Explain lattice-based post-quantum cryptography");
        assert_eq!(alpha.messages.len(), 2);
        assert_eq!(alpha.messages[0].role, "user");
        assert_eq!(alpha.messages[1].role, "assistant");
        assert_eq!(alpha.messages[1].citations.len(), 1);
        assert_eq!(alpha.messages[1].citations[0].peer_id, "12D3KooWPeerA");

        let beta = reopened
            .get_session("session-beta")
            .expect("query session-beta")
            .expect("session-beta must exist");
        assert_eq!(beta.session.model_family, "Gemma4_26b");
        assert_eq!(beta.messages.len(), 2);
        assert_eq!(beta.messages[1].responder_peer_id, "local");
    }
}

#[test]
fn test_single_session_deletion_preserves_other_sessions() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("chat_history.db");

    let store = ChatHistoryStore::open(&db_path).expect("open store");

    store
        .record_turn("sess-1", "Prompt 1", "Answer 1", &[], "local", "AutoFusion")
        .expect("record sess-1");
    store
        .record_turn("sess-2", "Prompt 2", "Answer 2", &[], "local", "AutoFusion")
        .expect("record sess-2");
    store
        .record_turn("sess-3", "Prompt 3", "Answer 3", &[], "local", "AutoFusion")
        .expect("record sess-3");

    assert_eq!(store.list_sessions(10).expect("list").len(), 3);

    // Delete single session sess-2
    let deleted = store.delete_session("sess-2").expect("delete sess-2");
    assert!(deleted, "delete_session must return true for existing session");

    // Verify sess-2 is gone
    assert!(store.get_session("sess-2").expect("query").is_none());

    // Verify sess-1 and sess-3 remain completely intact
    let remaining = store.list_sessions(10).expect("list remaining");
    assert_eq!(remaining.len(), 2);
    let ids: Vec<String> = remaining.into_iter().map(|s| s.session_id).collect();
    assert!(ids.contains(&"sess-1".to_string()));
    assert!(ids.contains(&"sess-3".to_string()));
    assert!(!ids.contains(&"sess-2".to_string()));

    let s1 = store.get_session("sess-1").expect("s1").expect("s1 detail");
    assert_eq!(s1.messages[0].content, "Prompt 1");
    assert_eq!(s1.messages[1].content, "Answer 1");
}

#[test]
fn test_delete_all_sessions_clears_database_cleanly_and_immediately() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("chat_history.db");

    let store = ChatHistoryStore::open(&db_path).expect("open store");

    for i in 1..=5 {
        let sid = format!("sess-{i}");
        store
            .record_turn(&sid, &format!("Question {i}"), &format!("Response {i}"), &[], "local", "AutoFusion")
            .expect("record");
    }

    assert_eq!(store.list_sessions(10).expect("list").len(), 5);

    // User-initiated Clear All
    let deleted_count = store.delete_all_sessions().expect("delete all");
    assert_eq!(deleted_count, 5);

    // Verify database is completely empty
    assert!(store.list_sessions(10).expect("list").is_empty());
    assert!(store.get_session("sess-1").expect("query").is_none());

    // Checkpoint after clear all
    store.checkpoint().expect("checkpoint");

    // Reopen and confirm it remains clean
    let reopened = ChatHistoryStore::open(&db_path).expect("reopen store");
    assert!(reopened.list_sessions(10).expect("list").is_empty());
}

#[test]
fn test_record_cancelled_turn_replaces_empty_assistant_placeholder() {
    let tmp = tempdir().expect("tempdir");
    let db_path = tmp.path().join("chat_history.db");

    let store = ChatHistoryStore::open(&db_path).expect("open store");

    // User initiates query; pending turn recorded with empty assistant response
    store
        .record_pending_turn("sess-err-1", "Calculate high-dimensional homomorphic encryption keys", "AutoFusion")
        .expect("record pending");

    let before = store.get_session("sess-err-1").expect("query").expect("exists");
    assert_eq!(before.messages.len(), 2);
    assert_eq!(before.messages[0].role, "user");
    assert_eq!(before.messages[1].role, "assistant");
    assert_eq!(before.messages[1].content, "");

    // Query aborts or errors; record_cancelled_turn called
    store
        .record_cancelled_turn("sess-err-1", "*[Query execution stopped: backend node offline]*")
        .expect("record cancelled");

    let after = store.get_session("sess-err-1").expect("query").expect("exists");
    assert_eq!(after.messages.len(), 2);
    assert_eq!(after.messages[1].content, "*[Query execution stopped: backend node offline]*");
}

#[tokio::test]
async fn test_rest_api_single_and_clear_all_deletion() {
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

    let app = build_router(state.clone());

    // Record two sessions via history store directly
    let store = state.history_store().expect("history store");
    store.record_turn("s-api-1", "Query 1", "Answer 1", &[], "local", "AutoFusion").unwrap();
    store.record_turn("s-api-2", "Query 2", "Answer 2", &[], "local", "AutoFusion").unwrap();

    // Verify GET /api/history returns both
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/history")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap(),
    )
    .unwrap();
    assert_eq!(body["sessions"].as_array().unwrap().len(), 2);

    // Delete single session s-api-1 via DELETE /api/history/s-api-1
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/api/history/s-api-1")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify only s-api-2 remains
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/history")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap(),
    )
    .unwrap();
    assert_eq!(body["sessions"].as_array().unwrap().len(), 1);
    assert_eq!(body["sessions"][0]["session_id"], "s-api-2");

    // Delete ALL sessions via DELETE /api/history
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("DELETE")
                .uri("/api/history")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify 0 sessions remain
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/history")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap(),
    )
    .unwrap();
    assert!(body["sessions"].as_array().unwrap().is_empty());
}
