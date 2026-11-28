//! REST API handlers for QuorumRAG's pure-Rust Layer-1 AtlasKV Knowledge Graph & HiKVP engine.
//!
//! Endpoints:
//! - `GET /api/v1/atlaskv/status`: Live triple counts, 3-level hierarchy stats, disk/RAM footprint, and config.
//! - `GET / POST /api/v1/atlaskv/config`: Read/persist `PersistedDaemonSettings::atlaskv`.
//! - `POST /api/v1/atlaskv/build`: Extract grounded KG2KV triples from indexed local storage & rebuild 3-level hierarchy.
//! - `POST /api/v1/atlaskv/query`: Execute sublinear 3-level HiKVP query and inspect provenance & pruning trace.
//! - `POST /api/v1/atlaskv/export`: Export native `HKUST-KnowComp/AtlasKV` `.npy` / `c2id` / `qkv.json` files (path-contained).
//! - `POST /api/v1/atlaskv/import`: Import native AtlasKV `.npy` / `qkv.json` files (path-contained).
//! - `POST /api/v1/atlaskv/import-json`: Direct JSON triple batch upload from native WebUI `<input type="file">`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use quorum_atlaskv::{
    derive_display_title, export_atlaskv_dataset, format_grounded_kg_context,
    import_atlaskv_dataset, infer_chunk_subject_anchor, is_generic_heading, parse_chunk_order_key,
    validate_access_tier, validate_safe_relative_path, AtlasKvError, AtlasKvQkvItem,
    AtlasKvSettings, Kg2KvExtractor, Kg2KvExtractorConfig, KgSourceChunk, KgTripleRecord,
};
use quorum_contract::{DeterministicOfflineEngine, EmbeddingGenerator};
use quorum_coordinator::{artemis_airgap, global_mesh_dlp_controller};

use crate::state::DaemonState;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AtlasKvQueryRequest {
    pub query: String,
    #[serde(default)]
    pub max_tier: u8,
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    #[serde(default)]
    pub allowed_folders: Option<Vec<String>>,
}

fn default_top_k() -> usize {
    24
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasKvInteropRequest {
    /// Safe single-segment or relative prefix under `<storage_path>/.atlaskv/interop/`.
    pub dataset_prefix: String,
    #[serde(default)]
    pub max_tier: u8,
    #[serde(default)]
    pub rebuild_after_import: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtlasKvJsonImportRequest {
    pub dataset_name: String,
    #[serde(default)]
    pub access_tier: u8,
    pub items: Vec<AtlasKvQkvItem>,
}

fn interop_base_dir(state: &DaemonState) -> PathBuf {
    state.storage.config().atlaskv_path().join("interop")
}

/// `GET /api/v1/atlaskv/status`
pub async fn atlaskv_status_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let stats = state.storage.atlaskv().stats();
    let settings = global_mesh_dlp_controller()
        .settings
        .read()
        .map(|s| s.atlaskv.clone())
        .unwrap_or_default();

    Json(serde_json::json!({
        "status": "ok",
        "stats": stats,
        "settings": settings,
    }))
}

/// `GET /api/v1/atlaskv/config`
pub async fn atlaskv_get_config_handler() -> impl IntoResponse {
    let settings = global_mesh_dlp_controller()
        .settings
        .read()
        .map(|s| s.atlaskv.clone())
        .unwrap_or_default();
    Json(settings)
}

/// `POST /api/v1/atlaskv/config`
pub async fn atlaskv_update_config_handler(
    Json(payload): Json<AtlasKvSettings>,
) -> impl IntoResponse {
    let sanitized = AtlasKvSettings {
        enabled: payload.enabled,
        auto_extract_on_ingest: payload.auto_extract_on_ingest,
        root_top_k_kb: payload.root_top_k_kb.clamp(1, 512),
        inter_top_k_kb: payload.inter_top_k_kb.clamp(1, 1024),
        leaf_top_k_kb: payload.leaf_top_k_kb.clamp(1, 512),
        mesh_centroid_routing: payload.mesh_centroid_routing,
        max_triples_per_chunk: payload.max_triples_per_chunk.clamp(1, 64),
        cluster_rebuild_delta_pct: payload.cluster_rebuild_delta_pct.clamp(1, 100),
    };

    let ctrl = global_mesh_dlp_controller();
    if let Ok(mut guard) = ctrl.settings.write() {
        guard.atlaskv = sanitized.clone();
    }
    ctrl.save_to_disk();

    Json(serde_json::json!({
        "status": "ok",
        "settings": sanitized,
    }))
}

/// `POST /api/v1/atlaskv/build`
/// Extracts grounded KG2KV triples from currently indexed chunks and rebuilds the 3-level
/// `Root -> Inter1 -> Leaf` Spherical K-Means++ hierarchy.
pub async fn atlaskv_build_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let chunks = match state.storage.scan_all_chunks().await {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Failed to scan indexed chunks: {e}") })),
            )
                .into_response();
        }
    };

    let atlaskv = state.storage.atlaskv();
    let cfg = global_mesh_dlp_controller()
        .settings
        .read()
        .map(|s| s.atlaskv.clone())
        .unwrap_or_default();
    let forensics_enabled = artemis_airgap::is_forensics_enabled();
    let dim = atlaskv.config().embedding_dim;

    let reindex_worker_for_filter = Arc::clone(&state.reindex_worker);
    let res = tokio::task::spawn_blocking(move || {
        let extractor = Kg2KvExtractor::new(Kg2KvExtractorConfig {
            max_triples_per_chunk: cfg.max_triples_per_chunk,
            forensics_enabled,
            ..Default::default()
        });
        let embedder = DeterministicOfflineEngine::new();
        let mut ordered_indices: Vec<usize> = (0..chunks.len()).collect();
        ordered_indices.sort_by_key(|&idx| {
            let ch = &chunks[idx];
            (
                ch.document_id.clone(),
                ch.access_tier,
                parse_chunk_order_key(&ch.chunk_id, &ch.metadata_json, ch.line_start, idx),
            )
        });

        let mut doc_active_subjects: HashMap<(String, u8), String> = HashMap::new();
        let mut triples = Vec::new();
        let mut key_vecs = Vec::new();
        let mut val_vecs = Vec::new();

        for idx in ordered_indices {
            let ch = &chunks[idx];
            if reindex_worker_for_filter.is_path_blocked(std::path::Path::new(&ch.file_path)) {
                continue;
            }
            if !forensics_enabled
                && Kg2KvExtractor::is_airgap_forensics_chunk(&ch.file_path, &ch.metadata_json)
            {
                continue;
            }
            let doc_key = (
                if ch.document_id.is_empty() {
                    ch.file_path.clone()
                } else {
                    ch.document_id.clone()
                },
                ch.access_tier,
            );
            let prior_subject = doc_active_subjects.get(&doc_key).cloned();
            let current_anchor =
                infer_chunk_subject_anchor(&ch.text_content, &ch.metadata_json, &ch.file_path);
            if let Some(ref anchor) = current_anchor {
                doc_active_subjects.insert(doc_key.clone(), anchor.clone());
            }
            let resolved_subject = current_anchor.or(prior_subject.clone());

            let src = KgSourceChunk {
                chunk_id: ch.chunk_id.clone(),
                document_id: ch.document_id.clone(),
                file_path: ch.file_path.clone(),
                line_start: ch.line_start,
                line_end: ch.line_end,
                access_tier: ch.access_tier,
                text_content: ch.text_content.clone(),
                metadata_json: ch.metadata_json.clone(),
                resolved_subject,
            };
            if let Ok(extracted) = extractor.extract_from_chunk(&src) {
                if prior_subject.is_none() && !doc_active_subjects.contains_key(&doc_key) {
                    let stem_title = derive_display_title(&ch.file_path);
                    if let Some(first_ent) = extracted.first().map(|r| r.entity.clone()) {
                        if !first_ent.eq_ignore_ascii_case(&stem_title)
                            && !is_generic_heading(&first_ent)
                        {
                            doc_active_subjects.insert(doc_key.clone(), first_ent);
                        }
                    }
                }
                for rec in extracted {
                    let kv = if ch.vector.len() == dim {
                        ch.vector.clone()
                    } else {
                        embedder
                            .embed_text(&rec.key_string)
                            .unwrap_or_else(|_| vec![0.0; dim])
                    };
                    let vv = if ch.vector.len() == dim {
                        ch.vector.clone()
                    } else {
                        embedder
                            .embed_text(&rec.value)
                            .unwrap_or_else(|_| vec![0.0; dim])
                    };
                    triples.push(rec);
                    key_vecs.push(kv);
                    val_vecs.push(vv);
                }
            }
        }

        let inserted = if !triples.is_empty() {
            atlaskv.insert_triples(&triples, &key_vecs, &val_vecs)?
        } else {
            0
        };
        let stats = atlaskv.rebuild_hierarchy()?;
        Ok::<_, AtlasKvError>((inserted, stats))
    })
    .await;

    match res {
        Ok(Ok((inserted, stats))) => Json(serde_json::json!({
            "status": "ok",
            "inserted_triples": inserted,
            "stats": stats,
        }))
        .into_response(),
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Build worker failed: {e}") })),
        )
            .into_response(),
    }
}

/// `POST /api/v1/atlaskv/query`
pub async fn atlaskv_query_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<AtlasKvQueryRequest>,
) -> impl IntoResponse {
    if payload.query.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "query must not be empty" })),
        )
            .into_response();
    }
    if let Err(e) = validate_access_tier(payload.max_tier) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    let embedder = DeterministicOfflineEngine::new();
    let q_vec = match embedder.embed_text(&payload.query) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Embedding failed: {e}") })),
            )
                .into_response();
        }
    };

    let atlaskv = state.storage.atlaskv();
    let settings_snapshot = global_mesh_dlp_controller()
        .settings
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let local_policy = artemis_airgap::resolve_local_retrieval_policy(
        &settings_snapshot,
        payload.max_tier,
        &[payload.query.as_str()],
    );
    let effective_max_tier = local_policy.local_access_tier;
    let top_k = payload.top_k.clamp(1, 256);
    let allowed = payload.allowed_folders;

    let res = tokio::task::spawn_blocking(move || {
        atlaskv.hikvp_search(&q_vec, effective_max_tier, top_k, allowed.as_deref())
    })
    .await;

    match res {
        Ok(Ok((mut triples, trace))) => {
            triples.retain(|t| local_policy.permits_local_triple(&t.triple));
            let formatted_context = format_grounded_kg_context(&triples);
            Json(serde_json::json!({
                "status": "ok",
                "triples": triples,
                "trace": trace,
                "formatted_context": formatted_context,
            }))
            .into_response()
        }
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Query worker failed: {e}") })),
        )
            .into_response(),
    }
}

/// `POST /api/v1/atlaskv/export`
pub async fn atlaskv_export_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<AtlasKvInteropRequest>,
) -> impl IntoResponse {
    let base = interop_base_dir(&state);
    if let Err(AtlasKvError::PathTraversal(msg)) =
        validate_safe_relative_path(&base, &payload.dataset_prefix)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response();
    }
    if let Err(e) = validate_access_tier(payload.max_tier) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    let atlaskv = state.storage.atlaskv();
    let prefix = payload.dataset_prefix;
    let max_tier = payload.max_tier;
    let res = tokio::task::spawn_blocking(move || {
        export_atlaskv_dataset(&atlaskv, &base, &prefix, max_tier)
    })
    .await;

    match res {
        Ok(Ok(manifest)) => Json(serde_json::json!({
            "status": "ok",
            "manifest": manifest,
        }))
        .into_response(),
        Ok(Err(AtlasKvError::PathTraversal(msg))) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Export worker failed: {e}") })),
        )
            .into_response(),
    }
}

/// `POST /api/v1/atlaskv/import`
pub async fn atlaskv_import_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<AtlasKvInteropRequest>,
) -> impl IntoResponse {
    let base = interop_base_dir(&state);
    if let Err(AtlasKvError::PathTraversal(msg)) =
        validate_safe_relative_path(&base, &payload.dataset_prefix)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response();
    }
    if let Err(e) = validate_access_tier(payload.max_tier) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }

    let atlaskv = state.storage.atlaskv();
    let prefix = payload.dataset_prefix;
    let tier = payload.max_tier;
    let rebuild = payload.rebuild_after_import;
    let res = tokio::task::spawn_blocking(move || {
        let imported = import_atlaskv_dataset(&atlaskv, &base, &prefix, tier)?;
        let stats = if rebuild {
            atlaskv.rebuild_hierarchy()?
        } else {
            atlaskv.stats()
        };
        Ok::<_, AtlasKvError>((imported, stats))
    })
    .await;

    match res {
        Ok(Ok((imported, stats))) => Json(serde_json::json!({
            "status": "ok",
            "imported_triples": imported,
            "stats": stats,
        }))
        .into_response(),
        Ok(Err(AtlasKvError::PathTraversal(msg))) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response(),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("Import worker failed: {e}") })),
        )
            .into_response(),
    }
}

/// `POST /api/v1/atlaskv/import-json`
/// Accepts AtlasKV `*_qkv.json` records directly from the WebUI native `<input type="file">`.
pub async fn atlaskv_import_json_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<AtlasKvJsonImportRequest>,
) -> impl IntoResponse {
    if let Err(e) = validate_access_tier(payload.access_tier) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response();
    }
    if payload.items.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "items array must not be empty" })),
        )
            .into_response();
    }

    let atlaskv = state.storage.atlaskv();
    let dim = atlaskv.config().embedding_dim;
    let dataset_name = payload
        .dataset_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect::<String>();
    let dataset_name = if dataset_name.is_empty() {
        "imported_kg".to_string()
    } else {
        dataset_name
    };
    let tier = payload.access_tier;
    let items = payload.items;

    let res = tokio::task::spawn_blocking(move || {
        let embedder = DeterministicOfflineEngine::new();
        let mut records = Vec::with_capacity(items.len());
        let mut kvecs = Vec::with_capacity(items.len());
        let mut vvecs = Vec::with_capacity(items.len());

        for (idx, item) in items.iter().enumerate() {
            let rec = KgTripleRecord::new(
                &item.name,
                &item.description_type,
                &item.description,
                format!("atlaskv:{}:{}", dataset_name, idx),
                format!("atlaskv:{}:chunk:{}", dataset_name, idx),
                item.file_path
                    .clone()
                    .unwrap_or_else(|| format!("atlaskv://{}.json", dataset_name)),
                item.line_start.unwrap_or(1),
                item.line_end.unwrap_or(1),
                item.work_cluster_id
                    .clone()
                    .unwrap_or_else(|| dataset_name.clone()),
                tier,
                "local",
            )?;
            let kv = embedder
                .embed_text(&rec.key_string)
                .unwrap_or_else(|_| vec![0.0; dim]);
            let vv = embedder
                .embed_text(&rec.value)
                .unwrap_or_else(|_| vec![0.0; dim]);
            records.push(rec);
            kvecs.push(kv);
            vvecs.push(vv);
        }
        let inserted = atlaskv.insert_triples(&records, &kvecs, &vvecs)?;
        let stats = atlaskv.rebuild_hierarchy()?;
        Ok::<_, AtlasKvError>((inserted, stats))
    })
    .await;

    match res {
        Ok(Ok((inserted, stats))) => Json(serde_json::json!({
            "status": "ok",
            "imported_triples": inserted,
            "stats": stats,
        }))
        .into_response(),
        Ok(Err(e)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("JSON import worker failed: {e}") })),
        )
            .into_response(),
    }
}
