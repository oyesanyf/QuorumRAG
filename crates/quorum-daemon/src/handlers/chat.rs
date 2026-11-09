use axum::extract::{Json, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info};

use crate::state::DaemonState;
use quorum_coordinator::{AgenticTelemetryEvent, ChatTurnMessage, SynthesisModelFamily};
use quorum_storage::SearchMode;

/// Request payload for `/api/chat` and `/api/query`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    /// User prompt query string.
    #[serde(alias = "query")]
    pub prompt: String,

    /// Optional search mode override: Keyword, Vector, Hybrid (default: Hybrid).
    pub search_mode: Option<SearchMode>,

    /// Model family selector: AutoFusion, Glm4Agentic, Qwen25Code, GemmaProse.
    pub model_family: Option<String>,

    /// Top candidate chunks count (default: 12).
    pub top_k: Option<usize>,

    /// Authorized upper bound access tier (0=Public..3=Restricted, default: 0).
    pub access_tier: Option<u8>,

    /// Multi-turn conversation history (`[{ "role": "user" | "assistant", "content": "..." }]`).
    #[serde(default)]
    pub history: Vec<ChatTurnMessage>,

    /// Optional client query ID for in-flight cancellation tracking.
    pub query_id: Option<String>,

    /// Optional session identifier for multi-turn continuation deduplication state tracking.
    pub session_id: Option<String>,

    /// Previously served chunk IDs from this chat session (negative filter).
    #[serde(default)]
    pub seen_chunk_ids: Vec<String>,

    /// Optional flag to bypass query cache (e.g. when Regenerate is clicked).
    #[serde(default)]
    pub bypass_cache: bool,
}

/// Request payload for `/api/chat/cancel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelChatRequest {
    pub query_id: Option<String>,
    pub session_id: Option<String>,
}

/// In-flight chat query cancellation handler: `POST /api/chat/cancel`.
pub async fn cancel_chat_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<CancelChatRequest>,
) -> impl IntoResponse {
    let (cancelled, _qid, sid) = if let Some(ref qid) = payload.query_id {
        let sid = state.in_flight_queries.get_by_query_id(qid).map(|t| t.session_id.clone());
        let res = state.in_flight_queries.cancel(qid);
        (res, Some(qid.clone()), sid)
    } else if let Some(ref sid) = payload.session_id {
        let qid = state.in_flight_queries.get_by_session_id(sid).map(|t| t.query_id.clone());
        let res = state.in_flight_queries.cancel_session(sid);
        (res, qid, Some(sid.clone()))
    } else {
        let count = state.in_flight_queries.cancel_all();
        (count > 0, None, None)
    };

    if cancelled {
        if let Some(ref session_id) = sid {
            if let Ok(hist_store) = state.history_store() {
                let _ = hist_store.record_cancelled_turn(session_id, "*[Generation stopped by user]*");
            }
        }
    }

    info!(
        query_id = ?payload.query_id,
        session_id = ?payload.session_id,
        cancelled,
        "Chat query cancellation requested via /api/chat/cancel"
    );

    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "status": "cancelled",
            "cancelled": cancelled,
            "query_id": payload.query_id,
            "session_id": payload.session_id
        })),
    )
}

/// Returns active running chat tasks: `GET /api/chat/active`.
pub async fn active_chat_tasks_handler(
    State(state): State<Arc<DaemonState>>,
) -> impl IntoResponse {
    let tasks = state.in_flight_queries.list_active();
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "active_tasks": tasks,
        })),
    )
}

/// Builds an SSE stream from an `ActiveChatTask` that first replays all snapshot events
/// and then streams live broadcast events until terminal completion.
pub fn create_chat_task_sse_stream(
    task: Arc<crate::state::ActiveChatTask>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let (sse_tx, sse_rx) = tokio::sync::mpsc::channel::<Result<Event, Infallible>>(2048);
    let (snapshot, mut broadcast_rx) = task.snapshot_and_subscribe();
    let is_already_done = task.completed.load(std::sync::atomic::Ordering::SeqCst);

    tokio::spawn(async move {
        // 1. Replay buffered events from snapshot
        for event in snapshot {
            let is_terminal = matches!(
                event,
                AgenticTelemetryEvent::ExecutionFinished { .. }
                    | AgenticTelemetryEvent::ExecutionError { .. }
            );
            let json_line = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
            if sse_tx.send(Ok(Event::default().data(json_line))).await.is_err() {
                return;
            }
            if is_terminal {
                return;
            }
        }

        if is_already_done {
            return;
        }

        // 2. Stream live events from broadcast channel
        loop {
            match broadcast_rx.recv().await {
                Ok(event) => {
                    let is_terminal = matches!(
                        event,
                        AgenticTelemetryEvent::ExecutionFinished { .. }
                            | AgenticTelemetryEvent::ExecutionError { .. }
                    );
                    let json_line = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
                    if sse_tx.send(Ok(Event::default().data(json_line))).await.is_err() {
                        return;
                    }
                    if is_terminal {
                        return;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!("SSE client broadcast receiver lagged by {} events", skipped);
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return;
                }
            }
        }
    });

    let stream = ReceiverStream::new(sse_rx);
    Sse::new(stream).keep_alive(KeepAlive::default().interval(Duration::from_secs(15)))
}

/// Live SSE Re-Attach endpoint: `GET /api/chat/attach/:session_id`.
pub async fn chat_sse_attach_handler(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> axum::response::Response {
    if let Some(task) = state.in_flight_queries.get_by_session_id(&session_id) {
        info!(session_id = %session_id, query_id = %task.query_id, "Re-attaching SSE stream to chat task");
        create_chat_task_sse_stream(task).into_response()
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": "not_found",
                "message": format!("No active or recent chat task found for session '{}'", session_id),
                "session_id": session_id,
            })),
        )
            .into_response()
    }
}

/// SSE Streaming chat endpoint: `POST /api/chat`.
/// Emits live Agentic State Graph events, GLM selection telemetry, token deltas, and citations.
pub async fn chat_sse_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<ChatRequest>,
) -> impl IntoResponse {
    let query_id = payload
        .query_id
        .clone()
        .unwrap_or_else(|| format!("q-{}", uuid::Uuid::new_v4()));
    let session_id = payload
        .session_id
        .clone()
        .unwrap_or_else(|| format!("s-{}", uuid::Uuid::new_v4()));

    let prompt = payload.prompt.trim().to_string();
    let history = payload.history;
    let top_k = payload.top_k.unwrap_or(32).clamp(24, 50);
    let _access_tier = payload.access_tier.unwrap_or(0);

    let family = match payload.model_family.as_deref() {
        Some("Glm4Agentic") | Some("glm4") | Some("glm-4") | Some("glm4:9b") => SynthesisModelFamily::Glm4Agentic,
        Some("Qwen25Code") | Some("qwen") | Some("qwen2.5") | Some("qwen2.5:32b") | Some("qwen2.5:14b") | Some("qwen2.5:7b") | Some("qwen2.5:3b") | Some("qwen2.5:1.5b") => SynthesisModelFamily::Qwen25Code,
        Some("Gemma4_26b") | Some("gemma4_26b") | Some("gemma4:26b") | Some("gemma4") => SynthesisModelFamily::Gemma4_26b,
        Some("GemmaProse") | Some("gemma") | Some("gemma3") | Some("gemma2:9b") | Some("gemma2:2b") | Some("gemma3:4b") => SynthesisModelFamily::GemmaProse,
        Some("AutoFusion") | Some("auto_fusion") => SynthesisModelFamily::AutoFusion,
        _ => state.default_model_family,
    };
    let model_label = format!("{:?}", family);

    info!(
        query_id = %query_id,
        session_id = %session_id,
        prompt = %prompt,
        history_turns = history.len(),
        model_family = %model_label,
        "Received /api/chat SSE streaming request"
    );

    // Save pending turn in SQLite immediately so mid-flight refresh preserves session and prompt
    if let Ok(hist_store) = state.history_store() {
        if let Err(e) = hist_store.record_pending_turn(&session_id, &prompt, &model_label) {
            error!("Failed to record pending chat turn to SQLite: {}", e);
        }
    }

    let (task, in_flight_guard) = state.in_flight_queries.register_task(
        query_id.clone(),
        session_id.clone(),
        prompt.clone(),
        model_label.clone(),
    );

    let (task_tx, mut task_rx) = tokio::sync::mpsc::channel::<AgenticTelemetryEvent>(16384);
    let collector_task = {
        let task = Arc::clone(&task);
        tokio::spawn(async move {
            while let Some(event) = task_rx.recv().await {
                task.record_event(event);
            }
            // Ensure a terminal event exists in the event log if coordinator aborted without one
            let has_terminal = {
                let log = task.event_log.lock().unwrap();
                log.iter().any(|e| matches!(e,
                    AgenticTelemetryEvent::ExecutionFinished { .. } |
                    AgenticTelemetryEvent::ExecutionError { .. }
                ))
            };
            if !has_terminal {
                task.record_event(AgenticTelemetryEvent::ExecutionError {
                    failed_state: quorum_coordinator::types::AgenticStateName::SynthesizeWithCitations,
                    error_message: "Query execution stopped".to_string(),
                    fallback_action: "Terminated in-flight stream".to_string(),
                });
            }
        })
    };

    let coordinator = Arc::clone(&state.coordinator);
    let bypass_cache = payload.bypass_cache;
    let prompt_lower = prompt.to_ascii_lowercase();
    let is_continuation_or_exclusion =
        quorum_coordinator::DeterministicOfflineSynthesisEngine::is_continuation_query(&prompt_lower)
            || quorum_coordinator::DeterministicOfflineSynthesisEngine::is_exclusion_query(&prompt_lower);

    let session_seen = if is_continuation_or_exclusion {
        let mut seen = state.sessions.get_seen_chunks(&session_id);
        for id in payload.seen_chunk_ids {
            seen.insert(id);
        }
        seen
    } else {
        std::collections::HashSet::new()
    };
    let sessions_registry = state.sessions.clone();
    let session_id_task = session_id.clone();
    let state_for_history = Arc::clone(&state);

    let query_task = {
        let task = Arc::clone(&task);
        let task_tx = task_tx.clone();
        tokio::spawn(async move {
            let _guard = in_flight_guard;
            if prompt.is_empty() {
                let _ = task_tx
                    .send(AgenticTelemetryEvent::ExecutionError {
                        failed_state: quorum_coordinator::types::AgenticStateName::ClassifyIntent,
                        error_message: "Prompt query string cannot be empty".to_string(),
                        fallback_action: "Aborting execution".to_string(),
                    })
                    .await;
                drop(task_tx);
                let _ = collector_task.await;
                task.mark_completed();
                return;
            }

            if bypass_cache {
                let _ = coordinator.cache_manager.query_cache.clear();
            }

            match coordinator
                .query_agentic_with_history_and_session(&prompt, history, family, top_k, session_seen, Some(task_tx.clone()))
                .await
            {
                Ok(_result) => {
                    let newly_seen: Vec<String> = _result
                        .chunks
                        .iter()
                        .map(|c| c.chunk.chunk_id.clone())
                        .collect();
                    sessions_registry.record_seen_chunks(&session_id_task, &newly_seen);

                    if let Ok(hist_store) = state_for_history.history_store() {
                        let responder_peer = if coordinator.engine.sender_peer_id.trim().is_empty() {
                            "local"
                        } else {
                            coordinator.engine.sender_peer_id.as_str()
                        };
                        if let Err(e) = hist_store.record_turn(
                            &session_id_task,
                            &prompt,
                            &_result.synthesis_prompt,
                            &_result.sources_cited,
                            responder_peer,
                            &model_label,
                        ) {
                            error!("Failed to persist chat turn to SQLite history: {}", e);
                        }
                    }
                }
                Err(e) => {
                    if !task.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                        error!("Error in query_agentic_with_history: {}", e);
                        let _ = task_tx
                            .send(AgenticTelemetryEvent::ExecutionError {
                                failed_state: quorum_coordinator::types::AgenticStateName::SynthesizeWithCitations,
                                error_message: e.to_string(),
                                fallback_action: "Returned partial graph state".to_string(),
                            })
                            .await;
                    }
                }
            }
            drop(task_tx);
            let _ = collector_task.await;
            task.mark_completed();
        })
    };

    task.set_abort_handle(query_task.abort_handle());

    let local_peer_id = if state.coordinator.engine.sender_peer_id.trim().is_empty() {
        "local".to_string()
    } else {
        state.coordinator.engine.sender_peer_id.clone()
    };
    let connected_peers: Vec<String> = {
        let registry = quorum_coordinator::mesh::global_peer_health_registry();
        registry.snapshot().keys().cloned().collect()
    };
    let mesh_peers_str = connected_peers.join(", ");
    let mut contributing = connected_peers.clone();
    if !contributing.contains(&local_peer_id) {
        contributing.push(local_peer_id.clone());
    }
    let contributing_str = contributing.join(", ");

    let mut headers = axum::http::HeaderMap::new();
    if let Ok(val) = axum::http::HeaderValue::from_str(&local_peer_id) {
        headers.insert("x-quorum-local-peer-id", val);
    }
    if !mesh_peers_str.is_empty() {
        if let Ok(val) = axum::http::HeaderValue::from_str(&mesh_peers_str) {
            headers.insert("x-quorum-mesh-peers", val);
        }
    }
    if !contributing_str.is_empty() {
        if let Ok(val) = axum::http::HeaderValue::from_str(&contributing_str) {
            headers.insert("x-quorum-contributing-peers", val);
        }
    }

    (headers, create_chat_task_sse_stream(task)).into_response()
}

/// One-shot query endpoint: `POST /api/query`.
/// Returns structured JSON `QueryResult` for REST and programmatic consumers.
pub async fn query_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<ChatRequest>,
) -> impl IntoResponse {
    let prompt = payload.prompt.trim();
    info!(prompt, "Received /api/query request");
    if prompt.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Prompt cannot be empty" })),
        )
            .into_response();
    }

    let top_k = payload.top_k.unwrap_or(32).clamp(24, 50);
    let family = match payload.model_family.as_deref() {
        Some("Glm4Agentic") | Some("glm4") | Some("glm-4") | Some("glm4:9b") => SynthesisModelFamily::Glm4Agentic,
        Some("Qwen25Code") | Some("qwen") | Some("qwen2.5") | Some("qwen2.5:32b") | Some("qwen2.5:14b") | Some("qwen2.5:7b") | Some("qwen2.5:3b") | Some("qwen2.5:1.5b") => SynthesisModelFamily::Qwen25Code,
        Some("Gemma4_26b") | Some("gemma4_26b") | Some("gemma4:26b") | Some("gemma4") => SynthesisModelFamily::Gemma4_26b,
        Some("GemmaProse") | Some("gemma") | Some("gemma3") | Some("gemma2:9b") | Some("gemma2:2b") | Some("gemma3:4b") => SynthesisModelFamily::GemmaProse,
        Some("AutoFusion") | Some("auto_fusion") => SynthesisModelFamily::AutoFusion,
        _ => state.default_model_family,
    };

    let session_id = payload
        .session_id
        .clone()
        .unwrap_or_else(|| format!("s-{}", uuid::Uuid::new_v4()));
    let prompt_lower = prompt.to_ascii_lowercase();
    let is_continuation_or_exclusion =
        quorum_coordinator::DeterministicOfflineSynthesisEngine::is_continuation_query(&prompt_lower)
            || quorum_coordinator::DeterministicOfflineSynthesisEngine::is_exclusion_query(&prompt_lower);

    let session_seen = if is_continuation_or_exclusion {
        let mut seen = state.sessions.get_seen_chunks(&session_id);
        for id in payload.seen_chunk_ids {
            seen.insert(id);
        }
        seen
    } else {
        std::collections::HashSet::new()
    };

    match state
        .coordinator
        .query_agentic_with_history_and_session(prompt, payload.history, family, top_k, session_seen, None)
        .await
    {
        Ok(result) => {
            let newly_seen: Vec<String> = result
                .chunks
                .iter()
                .map(|c| c.chunk.chunk_id.clone())
                .collect();
            state.sessions.record_seen_chunks(&session_id, &newly_seen);
            let local_peer_id = if state.coordinator.engine.sender_peer_id.trim().is_empty() {
                "local".to_string()
            } else {
                state.coordinator.engine.sender_peer_id.clone()
            };
            if let Ok(hist_store) = state.history_store() {
                let _ = hist_store.record_turn(
                    &session_id,
                    prompt,
                    &result.synthesis_prompt,
                    &result.sources_cited,
                    &local_peer_id,
                    &format!("{:?}", family),
                );
            }

            let mut contributing_peers: std::collections::HashSet<String> = std::collections::HashSet::new();
            contributing_peers.insert(local_peer_id.clone());
            for c in &result.chunks {
                if !c.source_peer.is_empty() && c.source_peer != "local" {
                    contributing_peers.insert(c.source_peer.clone());
                }
            }
            for cit in &result.sources_cited {
                if !cit.peer_id.is_empty() && cit.peer_id != "local" {
                    contributing_peers.insert(cit.peer_id.clone());
                }
            }
            let contributing_str = contributing_peers.into_iter().collect::<Vec<_>>().join(", ");

            let connected_peers: Vec<String> = {
                let registry = quorum_coordinator::mesh::global_peer_health_registry();
                registry.snapshot().keys().cloned().collect()
            };
            let mesh_peers_str = connected_peers.join(", ");

            let mut headers = axum::http::HeaderMap::new();
            if let Ok(val) = axum::http::HeaderValue::from_str(&local_peer_id) {
                headers.insert("x-quorum-local-peer-id", val);
            }
            if !contributing_str.is_empty() {
                if let Ok(val) = axum::http::HeaderValue::from_str(&contributing_str) {
                    headers.insert("x-quorum-contributing-peers", val);
                }
            }
            if !mesh_peers_str.is_empty() {
                if let Ok(val) = axum::http::HeaderValue::from_str(&mesh_peers_str) {
                    headers.insert("x-quorum-mesh-peers", val);
                }
            }

            (headers, Json(result)).into_response()
        }
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Request payload for `POST /api/chat/spellcheck`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpellcheckRequest {
    pub text: String,
    #[serde(default = "default_true")]
    pub use_llm: bool,
}

fn default_true() -> bool {
    true
}

/// Response payload for `POST /api/chat/spellcheck`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpellcheckResponse {
    pub original: String,
    pub corrected: String,
    pub changed: bool,
    pub engine: String,
}

/// Spellchecks chat box text using deterministic typo correction + local Ollama LLM (`qwen2.5:1.5b`).
/// Never uses the LLM to answer queries—strictly corrects spelling errors in the chat input box.
pub async fn spellcheck_handler(Json(payload): Json<SpellcheckRequest>) -> impl IntoResponse {
    let raw = payload.text;
    let use_llm = payload.use_llm;
    let raw_clone = raw.clone();

    let (corrected, engine) = tokio::task::spawn_blocking(move || {
        quorum_coordinator::DeterministicOfflineSynthesisEngine::correct_query_spelling(
            &raw_clone, use_llm,
        )
    })
    .await
    .unwrap_or_else(|_| (raw.clone(), "fallback".to_string()));

    let changed = corrected.trim() != raw.trim();
    Json(SpellcheckResponse {
        original: raw,
        corrected,
        changed,
        engine,
    })
}
