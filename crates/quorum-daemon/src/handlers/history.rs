//! REST endpoints for persistent SQLite Chat History (`GET/POST/DELETE /api/history`).

use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use quorum_types::Citation;
use serde::Deserialize;
use std::sync::Arc;

use crate::state::DaemonState;

/// Optional client-side turn save payload (`POST /api/history`).
#[derive(Debug, Clone, Deserialize)]
pub struct SaveHistoryTurnRequest {
    pub session_id: String,
    pub prompt: String,
    pub answer: String,
    #[serde(default)]
    pub citations: Vec<Citation>,
    #[serde(default)]
    pub responder_peer_id: String,
    #[serde(default)]
    pub model_family: String,
}

/// `GET /api/history` — Lists all persisted chat sessions ordered by `updated_at DESC`.
pub async fn list_history_handler(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    match state.history_store() {
        Ok(store) => match store.list_sessions(250) {
            Ok(sessions) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "sessions": sessions,
                })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Failed to list chat history: {e}") })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// `GET /api/history/:session_id` — Loads all messages and source citations for a single session.
pub async fn get_history_session_handler(
    State(state): State<Arc<DaemonState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    match state.history_store() {
        Ok(store) => match store.get_session(&session_id) {
            Ok(Some(detail)) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "session": detail.session,
                    "messages": detail.messages,
                })),
            )
                .into_response(),
            Ok(None) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "Conversation not found" })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Failed to load conversation: {e}") })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// `POST /api/history` — Persists or updates a turn in `<data_dir>/chat_history.db`.
pub async fn save_history_turn_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<SaveHistoryTurnRequest>,
) -> impl IntoResponse {
    match state.history_store() {
        Ok(store) => match store.record_turn(
            &payload.session_id,
            &payload.prompt,
            &payload.answer,
            &payload.citations,
            &payload.responder_peer_id,
            &payload.model_family,
        ) {
            Ok(()) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "session_id": payload.session_id,
                })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Failed to persist chat turn: {e}") })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// `DELETE /api/history/:session_id` — Deletes a single conversation from SQLite + memory registry.
pub async fn delete_history_session_handler(
    State(state): State<Arc<DaemonState>>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    state.sessions.remove_session(&session_id);
    match state.history_store() {
        Ok(store) => match store.delete_session(&session_id) {
            Ok(deleted) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "session_id": session_id,
                    "deleted": deleted,
                })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Failed to delete conversation: {e}") })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

/// `DELETE /api/history` — Deletes ALL conversations from SQLite + memory registry.
pub async fn delete_all_history_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    state.sessions.clear_all_sessions();
    match state.history_store() {
        Ok(store) => match store.delete_all_sessions() {
            Ok(deleted_count) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "ok",
                    "deleted_count": deleted_count,
                })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("Failed to clear chat history: {e}") })),
            )
                .into_response(),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}
