use axum::extract::{Json, State};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

use crate::state::DaemonState;

/// Request payload for `POST /api/cache/recache`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecacheRequest {
    /// If true, completely evicts all cached queries and embeddings.
    #[serde(default)]
    pub clear: bool,

    /// If true, immediately runs pre-warming routine for hot queries and document chunks.
    #[serde(default)]
    pub warm: bool,
}

/// Response payload for `POST /api/cache/recache`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecacheResponse {
    pub status: String,
    pub cache_epoch: u64,
    pub cleared_entries: usize,
    pub warmed_entries: usize,
    pub duration_ms: u64,
}

/// Response payload for `GET /api/cache/stats`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CacheStatsResponse {
    pub status: String,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f32,
    pub cached_queries: usize,
    pub cached_embeddings: usize,
    pub cache_epoch: u64,
}

/// POST /api/cache/recache - Triggers cache invalidation, epoch bump, and optional warming.
pub async fn recache_handler(
    State(state): State<Arc<DaemonState>>,
    payload: Option<Json<RecacheRequest>>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    let req = payload.map(|p| p.0).unwrap_or_default();
    info!(clear = req.clear, warm = req.warm, "Executing POST /api/cache/recache");

    let embedder = quorum_contract::DeterministicOfflineEngine::new();
    let resp = state
        .coordinator
        .cache_manager
        .recache(
            Some(&state.storage),
            Some(&embedder),
            req.clear,
            req.warm,
        )
        .await;

    let duration_ms = start.elapsed().as_millis() as u64;

    Json(RecacheResponse {
        status: resp.status,
        cache_epoch: resp.cache_epoch,
        cleared_entries: resp.cleared_entries,
        warmed_entries: resp.warmed_entries,
        duration_ms,
    })
}

/// GET /api/cache/stats - Returns live telemetry for QueryCache and EmbeddingCache.
pub async fn cache_stats_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let stats = state.coordinator.cache_stats();
    Json(CacheStatsResponse {
        status: "ok".to_string(),
        hits: stats.hits,
        misses: stats.misses,
        hit_rate: stats.hit_rate,
        cached_queries: stats.cached_queries,
        cached_embeddings: stats.cached_embeddings,
        cache_epoch: stats.cache_epoch,
    })
}
