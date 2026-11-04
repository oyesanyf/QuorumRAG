use crate::types::{AgenticStateName, QueryIntentType, RelevanceGrade, SynthesisModelFamily};
use quorum_storage::SearchMode;
use quorum_types::Citation;
use serde::{Deserialize, Serialize};

/// Live Server-Sent Events (SSE) telemetry data schema for agentic state machine transitions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", content = "data")]
pub enum AgenticTelemetryEvent {
    /// State machine transitioned to a new node
    #[serde(rename = "state_transition")]
    StateTransition {
        from_state: AgenticStateName,
        to_state: AgenticStateName,
        hop: usize,
        timestamp_ms: u64,
    },
    /// Query intent classified and routing rationale
    #[serde(rename = "intent_classified")]
    IntentClassified {
        intent: QueryIntentType,
        search_mode: SearchMode,
        model_family: SynthesisModelFamily,
        model_name: String,
        routing_rationale: String,
        is_retrieval_required: bool,
    },
    /// Host hardware resources probed
    #[serde(rename = "hardware_probed")]
    HardwareProbed {
        free_ram_gb: f64,
        free_vram_mb: u64,
        gpu_name: Option<String>,
        selected_tier: String,
    },
    /// Retrieval finished for a hop
    #[serde(rename = "retrieval_completed")]
    RetrievalCompleted {
        hop: usize,
        query: String,
        search_mode: SearchMode,
        retrieved_count: usize,
        local_count: usize,
        remote_count: usize,
        latency_ms: u64,
    },
    /// Relevance grading outcome
    #[serde(rename = "relevance_graded")]
    RelevanceGraded {
        hop: usize,
        grade: RelevanceGrade,
        score: f32,
        reasoning: String,
        will_rewrite: bool,
    },
    /// Query rewritten for the next retrieval hop
    #[serde(rename = "query_rewritten")]
    QueryRewritten {
        hop: usize,
        original_query: String,
        rewritten_query: String,
        rewrite_strategy: String,
    },
    /// LLM synthesis initiated
    #[serde(rename = "synthesis_started")]
    SynthesisStarted {
        model_name: String,
        model_family: SynthesisModelFamily,
        context_chunks_count: usize,
        estimated_prompt_tokens: usize,
    },
    /// Streaming token delta for live typing effect
    #[serde(rename = "token_delta")]
    TokenDelta {
        delta: String,
    },
    /// Final post-processed answer (repeat/meta/hallucination guards applied). Clients must replace the
    /// streamed token text with this content, since guards run after streaming.
    #[serde(rename = "final_answer")]
    FinalAnswer {
        content: String,
    },
    /// Grounded source citation emitted
    #[serde(rename = "citation")]
    CitationEmitted {
        citation: Citation,
    },
    /// Execution completed
    #[serde(rename = "execution_finished")]
    ExecutionFinished {
        total_hops: usize,
        total_duration_ms: u64,
        total_tokens: usize,
        final_state: AgenticStateName,
        model_name: String,
    },
    /// Fail-closed error reporting
    #[serde(rename = "execution_error")]
    ExecutionError {
        failed_state: AgenticStateName,
        error_message: String,
        fallback_action: String,
    },
    /// Cache telemetry emitted when query check completes
    #[serde(rename = "cache_telemetry")]
    CacheTelemetry {
        cache_hit: bool,
        cache_epoch: u64,
        cached_queries: usize,
        cached_embeddings: usize,
        hits: u64,
        misses: u64,
        hit_rate: f32,
    },
}

impl AgenticTelemetryEvent {
    /// Formats the event into an SSE compliant message line (`data: <json>\n\n`).
    pub fn to_sse_line(&self) -> String {
        format!(
            "data: {}\n\n",
            serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
        )
    }
}
