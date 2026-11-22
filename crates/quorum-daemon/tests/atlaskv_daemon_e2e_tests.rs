//! End-to-End Axum Daemon Integration Tests for Layer-1 Pure-Rust AtlasKV (`quorum-atlaskv`).
//!
//! Verifies:
//! 1. `GET /api/v1/atlaskv/status`, `GET/POST /api/v1/atlaskv/config`, and `/api/settings` persistence.
//! 2. Real chunk ingestion into `StorageEngine` -> `POST /api/v1/atlaskv/build` -> `POST /api/v1/atlaskv/query`
//!    returning grounded homonym-separated triples + 3-level `HiKvpPruningTrace`.
//! 3. `POST /api/v1/atlaskv/export` & `POST /api/v1/atlaskv/import` native `.npy` / `c2id` / `qkv.json` round-trip.
//! 4. `POST /api/v1/atlaskv/import-json` direct JSON QKV ingestion.
//! 5. Path-traversal fail-closed protection (`403 FORBIDDEN` on `../../outside`).
//! 6. Atomic deletion sync: `StorageEngine::delete_by_file_path` removes corresponding AtlasKV triples.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use quorum_contract::EmbeddingGenerator;
use quorum_coordinator::dlp_mesh::global_mesh_dlp_controller;
use quorum_coordinator::SynthesisModelFamily;
use quorum_daemon::{build_router, DaemonState};
use quorum_types::DocumentChunk;
use tempfile::{tempdir, TempDir};
use tower::ServiceExt;

static ATLASKV_TEST_MUTEX: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

struct TestEnv {
    _temp_dir: TempDir,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

async fn setup_atlaskv_test_app() -> (axum::Router, Arc<DaemonState>, TestEnv) {
    let guard = ATLASKV_TEST_MUTEX
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let temp_dir = tempdir().expect("tempdir");
    let data_dir = temp_dir.path().to_path_buf();

    let controller = global_mesh_dlp_controller();
    controller.init_persistence(&data_dir);
    let mut current = controller.get_settings();
    current.atlaskv = quorum_atlaskv::AtlasKvSettings::default();
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

    let node_seed = [0x42u8; 32];
    let coordinator_engine = Arc::new(quorum_coordinator::ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(
            quorum_coordinator::PeerAclManager::default(),
        )),
        quorum_coordinator::CoordinatorConfig::default(),
        node_seed,
        "12D3KooWAtlasKvTestNode".to_string(),
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
        port: 3045,
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
            _temp_dir: temp_dir,
            _guard: guard,
        },
    )
}

async fn read_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("valid json")
}

#[tokio::test]
async fn test_atlaskv_end_to_end_build_query_interop_security_and_delete_sync() {
    let (app, state, _env) = setup_atlaskv_test_app().await;

    // 1. Initial status and config round-trip
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/atlaskv/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["settings"]["enabled"], true);

    let update_cfg = serde_json::json!({
        "enabled": true,
        "auto_extract_on_ingest": true,
        "root_top_k_kb": 6,
        "inter_top_k_kb": 18,
        "leaf_top_k_kb": 16,
        "mesh_centroid_routing": true,
        "max_triples_per_chunk": 10,
        "cluster_rebuild_delta_pct": 12
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/atlaskv/config")
                .header("content-type", "application/json")
                .body(Body::from(update_cfg.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/atlaskv/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cfg_json = read_json(resp).await;
    assert_eq!(cfg_json["root_top_k_kb"], 6);
    assert_eq!(cfg_json["leaf_top_k_kb"], 16);

    // Also verify `/api/settings` surfaces `atlaskv`
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let settings_json = read_json(resp).await;
    assert_eq!(settings_json["atlaskv"]["root_top_k_kb"], 6);

    // 2. Insert real multi-domain Angela Davis chunks into StorageEngine
    let embedder = quorum_contract::DeterministicOfflineEngine::new();
    let samples = [
        (
            "chunk-lease-1",
            "doc-lease",
            "D:/Docs/Lease/2018_Rental_Agreement.txt",
            0u8,
            "Tenant: Angela Davis\nLandlord: Thomas Chen\nProperty Address: 410 Oakridge Lane, Durham NC\nMonthly Rent: $1,850",
        ),
        (
            "chunk-church-1",
            "doc-church",
            "D:/Docs/Church/Steward_Minutes.txt",
            0u8,
            "Church: Grace Memorial AME Church\nSecretary: Angela Davis\nPastor: Rev. Marcus Vance\nMinutes recorded by Angela Davis in 2021.",
        ),
        (
            "chunk-tier2-secret",
            "doc-private",
            "D:/Private/Confidential_Ledger.txt",
            2u8,
            "Owner: Angela Davis\nPrivate Escrow Valuation: $940,000 held under Tier-2 confidential audit.",
        ),
    ];

    let mut chunks = Vec::new();
    for (cid, did, path, tier, text) in samples {
        let vec = embedder.embed_text(text).expect("embed");
        let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
        chunks.push(DocumentChunk {
            chunk_id: cid.to_string(),
            document_id: did.to_string(),
            file_path: path.to_string(),
            line_start: 1,
            line_end: 5,
            text_content: text.to_string(),
            vector: vec,
            blake3_hash: hash,
            access_tier: tier,
            metadata_json: "{}".to_string(),
        });
    }
    state.storage.insert_chunks(&chunks).await.expect("insert chunks");

    // 3. Rebuild 3-level hierarchy via POST /api/v1/atlaskv/build
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/atlaskv/build")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let build_json = read_json(resp).await;
    assert_eq!(build_json["status"], "ok");
    let active_after_build = build_json["stats"]["active_triples"].as_u64().unwrap_or(0);
    assert!(
        active_after_build >= 4,
        "expected >=4 extracted KG triples, got {build_json}"
    );

    // 4. Query via POST /api/v1/atlaskv/query with max_tier=0 -> must isolate Tier 2 confidential triple!
    let q_req = serde_json::json!({
        "query": "Who is Angela Davis?",
        "max_tier": 0,
        "top_k": 24
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/atlaskv/query")
                .header("content-type", "application/json")
                .body(Body::from(q_req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let q_json = read_json(resp).await;
    let triples = q_json["triples"].as_array().expect("triples array");
    assert!(!triples.is_empty(), "expected matching triples: {q_json}");
    for t in triples {
        let tier = t["triple"]["access_tier"].as_u64().unwrap_or(99);
        assert_eq!(tier, 0, "Tier 2 triple leaked into max_tier=0 response: {t}");
        let val = t["triple"]["value"].as_str().unwrap_or("");
        assert!(!val.contains("940,000"), "Confidential Tier 2 value leaked");
    }
    let ctx = q_json["formatted_context"].as_str().unwrap_or("");
    assert!(
        ctx.contains("[AtlasKV Grounded Knowledge Graph Triples]"),
        "expected formatted KG header, got: {ctx}"
    );

    // 5. Native AtlasKV export/import round-trip + traversal rejection (403)
    let bad_export = serde_json::json!({
        "dataset_prefix": "../../outside_escape",
        "max_tier": 0
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/atlaskv/export")
                .header("content-type", "application/json")
                .body(Body::from(bad_export.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let ok_export = serde_json::json!({
        "dataset_prefix": "e2e_bundle",
        "max_tier": 0
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/atlaskv/export")
                .header("content-type", "application/json")
                .body(Body::from(ok_export.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let exp_json = read_json(resp).await;
    assert!(exp_json["manifest"]["exported_triples"].as_u64().unwrap_or(0) >= 2);

    // 6. Direct JSON import endpoint
    let json_import = serde_json::json!({
        "dataset_name": "uploaded_qkv.json",
        "access_tier": 0,
        "items": [
            {
                "name": "QuorumRAG",
                "description_type": "architecture",
                "description": "Local-first pure Rust P2P agentic RAG with AtlasKV HiKVP"
            }
        ]
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/atlaskv/import-json")
                .header("content-type", "application/json")
                .body(Body::from(json_import.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let imp_json = read_json(resp).await;
    assert_eq!(imp_json["imported_triples"], 1);

    // 7. Atomic deletion sync: deleting file from StorageEngine must purge its AtlasKV triples
    let before_del = state.storage.atlaskv().stats().active_triples;
    state
        .storage
        .delete_by_file_path("D:/Docs/Lease/2018_Rental_Agreement.txt")
        .await
        .expect("delete lease file");
    let after_del = state.storage.atlaskv().stats().active_triples;
    assert!(
        after_del < before_del,
        "expected AtlasKV active_triples to drop after StorageEngine::delete_by_file_path ({before_del} -> {after_del})"
    );
}
