use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use crate::state::DaemonState;
use quorum_ingest::ReindexOptions;

/// Payload to trigger reindexing via `POST /api/reindex`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReindexRequest {
    /// Optional specific directories to reindex.
    pub target_paths: Option<Vec<PathBuf>>,

    /// Bypass mtime and Level-1 BLAKE3 catalogs, re-verifying all files.
    pub full_rebuild: Option<bool>,

    /// Force re-embedding all chunks even if Level-2 hash matches.
    pub force_reembed: Option<bool>,

    /// Batch size for writes.
    pub batch_size: Option<usize>,
}

/// Start background reindexer: `POST /api/reindex`.
pub async fn start_reindex_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<ReindexRequest>,
) -> impl IntoResponse {
    let options = ReindexOptions {
        target_paths: payload
            .target_paths
            .unwrap_or_else(|| state.ingest_config.watch_paths.clone()),
        full_rebuild: payload.full_rebuild.unwrap_or(false),
        force_reembed: payload.force_reembed.unwrap_or(false),
        batch_size: payload.batch_size.unwrap_or(64),
        num_threads: 0,
        dry_run: false,
    };

    info!(
        targets = ?options.target_paths,
        full = options.full_rebuild,
        "Received POST /api/reindex request"
    );

    match state.reindex_worker.start_reindex(options).await {
        Ok(task_id) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": "started",
                "task_id": task_id.to_string(),
                "message": "Reindex worker task started in background"
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "status": "error",
                "message": e.to_string()
            })),
        )
            .into_response(),
    }
}

/// Retrieve live reindex progress: `GET /api/reindex/status`.
pub async fn reindex_status_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let total_stored_chunks = state.storage.count().await.unwrap_or(0);
    let watched_paths: Vec<String> = state
        .ingest_config
        .watch_paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    match state.reindex_worker.get_progress().await {
        Some(progress) => {
            let mut val = serde_json::to_value(&progress).unwrap_or_default();
            if let Some(obj) = val.as_object_mut() {
                let pct = if progress.files_total_estimated > 0 {
                    ((progress.files_scanned as f64 / progress.files_total_estimated as f64) * 100.0)
                        .clamp(0.0, 100.0)
                } else if matches!(progress.phase, quorum_ingest::ReindexPhase::Completed) || total_stored_chunks > 0 {
                    100.0
                } else {
                    0.0
                };
                obj.insert("percent".to_string(), serde_json::json!(pct));
                obj.insert("total_stored_chunks".to_string(), serde_json::json!(total_stored_chunks));
                obj.insert("continuous_mode".to_string(), serde_json::json!(true));
                obj.insert("watched_paths".to_string(), serde_json::json!(watched_paths));
            }
            Json(val).into_response()
        }
        None => {
            let pct = if total_stored_chunks > 0 { 100.0 } else { 0.0 };
            let phase = if total_stored_chunks > 0 { "completed" } else { "scanning_filesystem" };
            Json(serde_json::json!({
                "phase": phase,
                "percent": pct,
                "files_scanned": 0,
                "files_total_estimated": 0,
                "files_indexed": 0,
                "files_skipped_unmodified": 0,
                "chunks_newly_embedded": 0,
                "chunks_reused_from_cache": 0,
                "total_stored_chunks": total_stored_chunks,
                "continuous_mode": true,
                "watched_paths": watched_paths,
                "message": if total_stored_chunks > 0 { "Index active and up to date." } else { "Continuous background indexer initializing..." }
            }))
            .into_response()
        }
    }
}

/// Cancel active reindex task: `POST /api/reindex/cancel`.
pub async fn cancel_reindex_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let cancelled = state.reindex_worker.cancel_reindex();
    Json(serde_json::json!({
        "status": "cancel_requested",
        "cancelled": cancelled
    }))
}
