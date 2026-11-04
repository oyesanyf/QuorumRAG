use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

use crate::handlers::{cache, chat, drift, export, health, langextract, media, mesh, reindex, settings};
use crate::state::DaemonState;

/// Constructs the complete Axum 0.7 web server Router.
pub fn build_router(state: Arc<DaemonState>) -> axum::Router {
    axum::Router::new()
        // Embedded Web UI
        .route("/", get(serve_index))
        .route("/assets/*path", get(serve_asset))
        .route("/favicon.ico", get(serve_favicon))

        // Chat & Query Endpoints (SSE streaming & JSON)
        .route("/api/chat", post(chat::chat_sse_handler))
        .route("/api/chat/stream", get(chat_stream_compat_handler))
        .route("/api/chat/cancel", post(chat::cancel_chat_handler))
        .route("/api/chat/spellcheck", post(chat::spellcheck_handler))
        .route("/api/query", post(chat::query_handler))

        // Multimodal media streaming, system viewer launch, and PDF/DOCX export
        .route("/api/media", get(media::serve_media_handler))
        .route("/api/open-file", post(media::open_file_handler))
        .route("/api/export", post(export::export_handler))

        // ChatGPT Settings, OshoosiClaw P2P Mesh, Shared Folders & HIPAA PHI DLP Endpoints
        .route("/api/settings", get(settings::get_settings_handler).post(settings::update_settings_handler))
        .route("/api/preferences", get(settings::get_settings_handler).post(settings::update_settings_handler))
        .route("/api/mesh/status", get(settings::mesh_status_handler))
        .route("/api/mesh/config", post(settings::update_mesh_config_handler))
        .route("/api/mesh/shared-folders", post(settings::manage_shared_folders_handler))
        .route("/api/mesh/browse-folders", get(settings::browse_folders_handler))
        .route("/api/dlp/status", get(settings::dlp_status_handler))
        .route("/api/dlp/policy", post(settings::update_dlp_policy_handler))
        .route("/api/dlp/test", post(settings::test_dlp_inspection_handler))
        .route("/api/endpoints/probe", post(settings::probe_endpoint_handler))

        // OshoosiClaw Mesh Network & TPM 2.0 Hardware RoT Endpoints
        .route("/api/mesh/tpm/status", get(mesh::get_tpm_status_handler))
        .route("/api/tpm/status", get(mesh::get_tpm_status_handler))
        .route("/api/mesh/topology", get(mesh::get_mesh_topology_handler))
        .route("/api/topology", get(mesh::get_mesh_topology_handler))
        .route("/api/peers", get(mesh::get_mesh_topology_handler))
        .route("/api/mesh/peers", get(mesh::get_mesh_topology_handler))
        .route("/api/mesh/bootstrap-peers", get(mesh::get_bootstrap_peers_handler).post(mesh::post_bootstrap_peers_handler))
        .route("/mesh/bootstrap-peers", get(mesh::get_bootstrap_peers_handler).post(mesh::post_bootstrap_peers_handler))
        .route("/api/mesh/pending-joins", get(mesh::get_pending_joins_handler))
        .route("/api/pending-joins", get(mesh::get_pending_joins_handler))
        .route("/api/mesh/pending-joins/clear", post(mesh::clear_pending_joins_handler))
        .route("/api/pending-joins/clear", post(mesh::clear_pending_joins_handler))
        .route("/api/mesh/pending-joins/:peer_id/allow", post(mesh::allow_pending_join_handler))
        .route("/api/pending-joins/:peer_id/allow", post(mesh::allow_pending_join_handler))
        .route("/api/mesh/pending-joins/:peer_id/deny", post(mesh::deny_pending_join_handler))
        .route("/api/pending-joins/:peer_id/deny", post(mesh::deny_pending_join_handler))
        .route("/api/mesh/quarantined-peers", get(mesh::get_quarantined_peers_handler))
        .route("/api/quarantined-peers", get(mesh::get_quarantined_peers_handler))
        .route("/api/mesh/quarantined-peers/:peer_id/release", post(mesh::release_quarantined_peer_handler))
        .route("/api/quarantined-peers/:peer_id/release", post(mesh::release_quarantined_peer_handler))

        // Cache Management Endpoints
        .route("/api/cache/recache", post(cache::recache_handler))
        .route("/api/cache/stats", get(cache::cache_stats_handler))

        // Reindex Worker Endpoints
        .route("/api/reindex", post(reindex::start_reindex_handler))
        .route("/api/reindex/status", get(reindex::reindex_status_handler))
        .route("/api/index/status", get(reindex::reindex_status_handler))
        .route("/api/reindex/cancel", post(reindex::cancel_reindex_handler))

        // Drift Healing Endpoints
        .route("/api/drift/fix", post(drift::fix_drift_handler))
        .route("/api/drift/status", get(drift::drift_status_handler))

        // Google LangExtract Endpoints
        .route("/api/langextract", post(langextract::extract_handler))
        .route("/api/langextract/visualize", post(langextract::visualize_handler))

        // Health & Models Telemetry
        .route("/api/health", get(health::health_handler))
        .route("/api/models", get(health::models_handler))
        .route("/api/models/pull", post(health::pull_model_handler))

        // Graceful Shutdown Endpoint
        .route("/api/shutdown", post(shutdown_handler))

        // SPA Fallback & Direct Static Asset Resolution
        .fallback(quorum_ui::static_handler)

        .layer(CorsLayer::permissive())
        .with_state(state)
}

/// GET / - Serves embedded ChatGPT-like interface.
async fn serve_index() -> impl IntoResponse {
    (
        [(
            header::CACHE_CONTROL,
            "no-store, no-cache, must-revalidate, max-age=0",
        )],
        Html(quorum_ui::get_index_html()),
    )
}

/// GET /assets/*path - Serves embedded static assets.
async fn serve_asset(Path(path): Path<String>) -> Response {
    if let Some((bytes, mime)) = quorum_ui::get_asset(&path) {
        (
            [
                (header::CONTENT_TYPE, mime),
                (
                    header::CACHE_CONTROL,
                    "no-store, no-cache, must-revalidate, max-age=0",
                ),
            ],
            bytes,
        )
            .into_response()
    } else {
        (StatusCode::NOT_FOUND, "Asset not found").into_response()
    }
}

/// GET /favicon.ico - Serves favicon.
async fn serve_favicon() -> Response {
    if let Some((bytes, mime)) = quorum_ui::get_asset("favicon.svg") {
        ([(header::CONTENT_TYPE, mime)], bytes).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// GET /api/chat/stream?prompt=... query compatibility endpoint (matching test_web_endpoints.rs).
async fn chat_stream_compat_handler(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let prompt = params.get("prompt").cloned().unwrap_or_default();
    let family = params.get("model_family").cloned();
    let req = chat::ChatRequest {
        prompt,
        search_mode: None,
        model_family: family,
        top_k: Some(12),
        access_tier: Some(0),
        history: Vec::new(),
        query_id: None,
        session_id: None,
        seen_chunk_ids: Vec::new(),
        bypass_cache: false,
    };
    chat::chat_sse_handler(State(state), axum::Json(req)).await
}

/// POST /api/shutdown - Triggers graceful daemon shutdown.
async fn shutdown_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    tracing::info!("Received /api/shutdown request; notifying shutdown listener");
    state.shutdown_notify.notify_one();
    (StatusCode::OK, "Shutdown initiated").into_response()
}
