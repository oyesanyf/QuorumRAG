//! Empirical Challenger Test Suite for QuorumRAG Preferences & Settings Contract (Milestone M11)
//!
//! Validates:
//! 1. `/api/preferences` accepts both GET and POST requests.
//! 2. GET `/api/preferences` returns 200 OK and valid JSON matching GET `/api/settings`.
//! 3. POST `/api/preferences` correctly deserializes and persists `ChatGptUiSettings` / `UiPreferencesConfig`:
//!    - `max_output_tokens` (256 up to 262144)
//!    - `agentic_loop_enabled` (and alias `agentic_loop_chaining`)
//!    - `agentic_chunk_size` (and alias `agentic_loop_chunk_size`)
//!    - `agentic_strategy`
//!    - `deep_research_iterative_rag` (and alias `deep_research`)
//!    - `parent_document_retrieval` (and alias `parent_doc_retrieval`)
//!    - `map_reduce_fact_extraction` (and alias `map_reduce`)
//! 4. Invariant verification of `UiPreferencesConfig` defaults:
//!    - `max_output_tokens` == 262144
//!    - `agentic_loop_enabled` == true
//!    - `agentic_chunk_size` == 4096
//!    - `agentic_strategy` == "auto_continuation"
//!    - `deep_research_iterative_rag` == true
//!    - `parent_document_retrieval` == true
//!    - `map_reduce_fact_extraction` == true
//! 5. Robust error handling on malformed JSON and type mismatches (400/422 without 500 panics).

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use quorum_coordinator::{
    ChatGptUiSettings, SynthesisModelFamily, UiPreferencesConfig,
};
use quorum_daemon::{build_router, DaemonState};
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tower::ServiceExt;

async fn setup_challenge_app() -> axum::Router {
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
        "preferences_challenge".to_string(),
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

    build_router(state)
}

#[tokio::test]
async fn test_ui_preferences_strict_defaults_invariants() {
    let defaults = UiPreferencesConfig::default();

    // Verify all 7 mandatory invariants
    assert_eq!(defaults.max_output_tokens, 262144, "Default max_output_tokens must be 262144");
    assert!(defaults.agentic_loop_enabled, "Default agentic_loop_enabled must be true");
    assert_eq!(defaults.agentic_chunk_size, 4096, "Default agentic_chunk_size must be 4096");
    assert_eq!(defaults.agentic_strategy, "auto_continuation", "Default agentic_strategy must be auto_continuation");
    assert!(defaults.deep_research_iterative_rag, "Default deep_research_iterative_rag must be true");
    assert!(defaults.parent_document_retrieval, "Default parent_document_retrieval must be true");
    assert!(defaults.map_reduce_fact_extraction, "Default map_reduce_fact_extraction must be true");

    // Verify all 10 dropdown budget options round-trip without corruption
    let token_budgets = [256, 512, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144];
    for budget in token_budgets {
        let mut custom = defaults.clone();
        custom.max_output_tokens = budget;
        let serialized = serde_json::to_string(&custom).expect("serialize custom budget");
        let deserialized: UiPreferencesConfig = serde_json::from_str(&serialized).expect("deserialize custom budget");
        assert_eq!(deserialized.max_output_tokens, budget);
    }
}

#[tokio::test]
async fn test_api_preferences_get_and_post_lifecycle() {
    let app = setup_challenge_app().await;

    // 1. GET /api/preferences must return 200 OK and valid JSON
    let get_req = Request::builder()
        .uri("/api/preferences")
        .body(Body::empty())
        .unwrap();

    let get_resp = app.clone().oneshot(get_req).await.expect("GET /api/preferences");
    assert_eq!(get_resp.status(), StatusCode::OK);

    let get_ct = get_resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(get_ct.contains("application/json"), "Expected JSON content-type");

    let body_bytes = axum::body::to_bytes(get_resp.into_body(), 1024 * 1024)
        .await
        .expect("read GET body");
    let get_json: serde_json::Value = serde_json::from_slice(&body_bytes).expect("parse JSON");
    assert_eq!(get_json["status"], "ok");
    assert!(get_json["ui"].is_object());

    // Verify default fields in GET response
    let ui = &get_json["ui"];
    assert_eq!(ui["max_output_tokens"], 262144);
    assert_eq!(ui["agentic_loop_enabled"], true);
    assert_eq!(ui["agentic_chunk_size"], 4096);
    assert_eq!(ui["agentic_strategy"], "auto_continuation");
    assert_eq!(ui["deep_research_iterative_rag"], true);
    assert_eq!(ui["parent_document_retrieval"], true);
    assert_eq!(ui["map_reduce_fact_extraction"], true);

    // Compare with GET /api/settings
    let settings_req = Request::builder()
        .uri("/api/settings")
        .body(Body::empty())
        .unwrap();
    let settings_resp = app.clone().oneshot(settings_req).await.expect("GET /api/settings");
    assert_eq!(settings_resp.status(), StatusCode::OK);
    let settings_bytes = axum::body::to_bytes(settings_resp.into_body(), 1024 * 1024).await.unwrap();
    let settings_json: serde_json::Value = serde_json::from_slice(&settings_bytes).unwrap();
    assert_eq!(settings_json["ui"]["max_output_tokens"], ui["max_output_tokens"]);
    assert_eq!(settings_json["ui"]["agentic_strategy"], ui["agentic_strategy"]);

    // 2. POST /api/preferences with canonical fields
    let post_payload = serde_json::json!({
        "ui": {
            "max_output_tokens": 65536,
            "agentic_loop_enabled": false,
            "agentic_chunk_size": 2048,
            "agentic_strategy": "iterative_sections",
            "deep_research_iterative_rag": false,
            "parent_document_retrieval": false,
            "map_reduce_fact_extraction": false
        }
    });

    let post_req = Request::builder()
        .method("POST")
        .uri("/api/preferences")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&post_payload).unwrap()))
        .unwrap();

    let post_resp = app.clone().oneshot(post_req).await.expect("POST /api/preferences");
    assert_eq!(post_resp.status(), StatusCode::OK);

    let post_bytes = axum::body::to_bytes(post_resp.into_body(), 1024 * 1024).await.unwrap();
    let post_json: serde_json::Value = serde_json::from_slice(&post_bytes).unwrap();
    assert_eq!(post_json["status"], "ok");
    assert_eq!(post_json["ui"]["max_output_tokens"], 65536);
    assert_eq!(post_json["ui"]["agentic_loop_enabled"], false);
    assert_eq!(post_json["ui"]["agentic_chunk_size"], 2048);
    assert_eq!(post_json["ui"]["agentic_strategy"], "iterative_sections");
    assert_eq!(post_json["ui"]["deep_research_iterative_rag"], false);
    assert_eq!(post_json["ui"]["parent_document_retrieval"], false);
    assert_eq!(post_json["ui"]["map_reduce_fact_extraction"], false);

    // Follow-up GET /api/preferences confirms update persistence
    let get_after_post = Request::builder()
        .uri("/api/preferences")
        .body(Body::empty())
        .unwrap();
    let get_after_resp = app.clone().oneshot(get_after_post).await.unwrap();
    let after_bytes = axum::body::to_bytes(get_after_resp.into_body(), 1024 * 1024).await.unwrap();
    let after_json: serde_json::Value = serde_json::from_slice(&after_bytes).unwrap();
    assert_eq!(after_json["ui"]["max_output_tokens"], 65536);
    assert_eq!(after_json["ui"]["deep_research_iterative_rag"], false);
    assert_eq!(after_json["ui"]["parent_document_retrieval"], false);
    assert_eq!(after_json["ui"]["map_reduce_fact_extraction"], false);

    // 3. POST /api/preferences with aliases
    let alias_payload = serde_json::json!({
        "ui": {
            "max_output_tokens": 131072,
            "agentic_loop_chaining": true,
            "agentic_loop_chunk_size": 8192,
            "agentic_strategy": "map_reduce",
            "deep_research": true,
            "parent_doc_retrieval": true,
            "map_reduce": true
        }
    });

    let alias_post_req = Request::builder()
        .method("POST")
        .uri("/api/preferences")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&alias_payload).unwrap()))
        .unwrap();

    let alias_post_resp = app.clone().oneshot(alias_post_req).await.unwrap();
    assert_eq!(alias_post_resp.status(), StatusCode::OK);

    let alias_bytes = axum::body::to_bytes(alias_post_resp.into_body(), 1024 * 1024).await.unwrap();
    let alias_json: serde_json::Value = serde_json::from_slice(&alias_bytes).unwrap();
    assert_eq!(alias_json["ui"]["max_output_tokens"], 131072);
    assert_eq!(alias_json["ui"]["agentic_loop_enabled"], true);
    assert_eq!(alias_json["ui"]["agentic_chunk_size"], 8192);
    assert_eq!(alias_json["ui"]["agentic_strategy"], "map_reduce");
    assert_eq!(alias_json["ui"]["deep_research_iterative_rag"], true);
    assert_eq!(alias_json["ui"]["parent_document_retrieval"], true);
    assert_eq!(alias_json["ui"]["map_reduce_fact_extraction"], true);

    // Follow-up GET /api/settings sees same alias-updated fields
    let settings_after_alias = Request::builder()
        .uri("/api/settings")
        .body(Body::empty())
        .unwrap();
    let s_after_resp = app.clone().oneshot(settings_after_alias).await.unwrap();
    let s_after_bytes = axum::body::to_bytes(s_after_resp.into_body(), 1024 * 1024).await.unwrap();
    let s_after_json: serde_json::Value = serde_json::from_slice(&s_after_bytes).unwrap();
    assert_eq!(s_after_json["ui"]["max_output_tokens"], 131072);
    assert_eq!(s_after_json["ui"]["agentic_loop_enabled"], true);
    assert_eq!(s_after_json["ui"]["agentic_chunk_size"], 8192);
    assert_eq!(s_after_json["ui"]["deep_research_iterative_rag"], true);
    assert_eq!(s_after_json["ui"]["parent_document_retrieval"], true);
    assert_eq!(s_after_json["ui"]["map_reduce_fact_extraction"], true);

    // Reset settings back to defaults for subsequent test runs
    let reset_payload = serde_json::json!({
        "ui": ChatGptUiSettings::default()
    });
    let reset_req = Request::builder()
        .method("POST")
        .uri("/api/preferences")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&reset_payload).unwrap()))
        .unwrap();
    let reset_resp = app.clone().oneshot(reset_req).await.unwrap();
    assert_eq!(reset_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_api_preferences_adversarial_malformed_and_type_mismatch() {
    let app = setup_challenge_app().await;

    // 1. Malformed syntax JSON must return 400 or 422
    let malformed_req = Request::builder()
        .method("POST")
        .uri("/api/preferences")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"{\"ui\": { broken json".to_vec()))
        .unwrap();

    let malformed_resp = app.clone().oneshot(malformed_req).await.unwrap();
    assert!(
        malformed_resp.status() == StatusCode::BAD_REQUEST
            || malformed_resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Malformed JSON must return 400 or 422, got: {:?}",
        malformed_resp.status()
    );

    // 2. Type mismatch (string for max_output_tokens)
    let mismatch_req = Request::builder()
        .method("POST")
        .uri("/api/preferences")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "ui": {
                    "max_output_tokens": "invalid_string_tokens"
                }
            }))
            .unwrap(),
        ))
        .unwrap();

    let mismatch_resp = app.clone().oneshot(mismatch_req).await.unwrap();
    assert!(
        mismatch_resp.status() == StatusCode::BAD_REQUEST
            || mismatch_resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Type mismatch must return 400 or 422, got: {:?}",
        mismatch_resp.status()
    );

    // 3. Partial update with empty ui {} does not panic and succeeds
    let empty_ui_req = Request::builder()
        .method("POST")
        .uri("/api/preferences")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&serde_json::json!({ "ui": {} })).unwrap()))
        .unwrap();

    let empty_resp = app.clone().oneshot(empty_ui_req).await.unwrap();
    assert_eq!(empty_resp.status(), StatusCode::OK);
}
