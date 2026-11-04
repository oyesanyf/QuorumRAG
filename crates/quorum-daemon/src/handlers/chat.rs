use axum::extract::{Json, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use futures_util::StreamExt;
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
}

/// In-flight chat query cancellation handler: `POST /api/chat/cancel`.
pub async fn cancel_chat_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<CancelChatRequest>,
) -> impl IntoResponse {
    let cancelled = if let Some(ref qid) = payload.query_id {
        state.in_flight_queries.cancel(qid)
    } else {
        state.in_flight_queries.cancel_all() > 0
    };

    info!(
        query_id = ?payload.query_id,
        cancelled,
        "Chat query cancellation requested via /api/chat/cancel"
    );

    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "status": "cancelled",
            "cancelled": cancelled,
            "query_id": payload.query_id
        })),
    )
}

/// SSE Streaming chat endpoint: `POST /api/chat`.
/// Emits live Agentic State Graph events, GLM selection telemetry, token deltas, and citations.
pub async fn chat_sse_handler(
    State(state): State<Arc<DaemonState>>,
    Json(payload): Json<ChatRequest>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let query_id = payload
        .query_id
        .clone()
        .unwrap_or_else(|| format!("q-{}", uuid::Uuid::new_v4()));

    info!(
        query_id = %query_id,
        prompt = %payload.prompt,
        history_turns = payload.history.len(),
        "Received /api/chat SSE streaming request"
    );

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

    let (tx, rx) = tokio::sync::mpsc::channel::<AgenticTelemetryEvent>(16384);
    let coordinator = Arc::clone(&state.coordinator);
    let bypass_cache = payload.bypass_cache;
    let (in_flight_entry, in_flight_guard) = state.in_flight_queries.register(query_id);
    let task_token = in_flight_entry.token.clone();
    let task_tx = tx.clone();

    let session_id = payload
        .session_id
        .clone()
        .unwrap_or_else(|| format!("s-{}", uuid::Uuid::new_v4()));
    let mut session_seen = state.sessions.get_seen_chunks(&session_id);
    for id in payload.seen_chunk_ids {
        session_seen.insert(id);
    }
    let sessions_registry = state.sessions.clone();
    let session_id_task = session_id.clone();

    let join_handle = tokio::spawn(async move {
        let _guard = in_flight_guard;
        if prompt.is_empty() {
            let _ = task_tx
                .send(AgenticTelemetryEvent::ExecutionError {
                    failed_state: quorum_coordinator::types::AgenticStateName::ClassifyIntent,
                    error_message: "Prompt query string cannot be empty".to_string(),
                    fallback_action: "Aborting execution".to_string(),
                })
                .await;
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
                // TokenDelta events and trailing CitationEmitted + ExecutionFinished events
                // have already been streamed in real time by AgenticStateGraphRunner.
            }
            Err(e) => {
                if !task_token.is_cancelled() && !task_tx.is_closed() {
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
    });

    in_flight_entry.set_abort_handle(join_handle.abort_handle());

    let stream = ReceiverStream::new(rx).map(|event| {
        let json_line = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
        Ok::<Event, Infallible>(Event::default().data(json_line))
    });

    Sse::new(stream).keep_alive(KeepAlive::default().interval(Duration::from_secs(15)))
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
    let mut session_seen = state.sessions.get_seen_chunks(&session_id);
    for id in payload.seen_chunk_ids {
        session_seen.insert(id);
    }

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
            Json(result).into_response()
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
