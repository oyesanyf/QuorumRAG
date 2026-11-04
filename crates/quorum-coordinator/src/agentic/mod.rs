pub mod classify;
pub mod grade;
pub mod retrieve;
pub mod rewrite;
pub mod synthesize;

use crate::hardware::HardwareTelemetry;
use crate::scatter_gather::ScatterGatherEngine;
use crate::telemetry::AgenticTelemetryEvent;
use crate::types::*;
pub use classify::ClassifyIntentNode;
pub use grade::GradeRelevanceNode;
pub use retrieve::RetrieveMeshNode;
pub use rewrite::{ContinuationFacetExtractor, RewriteContinuationNode, RewriteQueryNode};
pub use synthesize::SynthesizeWithCitationsNode;
pub use crate::types::AgenticGraphState;
use tokio::sync::mpsc::Sender;
use std::sync::Arc;
use crate::cache::CacheManager;
use quorum_contract::EmbeddingGenerator;

pub struct AgenticStateGraphRunner {
    pub max_hops: usize,
    pub relevance_threshold: f32,
    pub cache_manager: Arc<CacheManager>,
}

impl Default for AgenticStateGraphRunner {
    fn default() -> Self {
        Self {
            max_hops: 3,
            relevance_threshold: 0.60,
            cache_manager: Arc::new(CacheManager::default()),
        }
    }
}

impl AgenticStateGraphRunner {
    pub fn new(max_hops: usize, relevance_threshold: f32) -> Self {
        Self {
            max_hops,
            relevance_threshold,
            cache_manager: Arc::new(CacheManager::default()),
        }
    }

    pub fn with_cache_manager(mut self, cache_manager: Arc<CacheManager>) -> Self {
        self.cache_manager = cache_manager;
        self
    }

    /// Executes the LangGraph-style state graph with live SSE telemetry and mathematical termination guarantee.
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        &self,
        prompt: &str,
        requested_family: SynthesisModelFamily,
        engine: &ScatterGatherEngine,
        vector: &[f32],
        access_tier: u8,
        top_k: usize,
        telemetry_tx: Option<Sender<AgenticTelemetryEvent>>,
    ) -> Result<AgenticGraphState, String> {
        self.run_with_history(
            prompt,
            Vec::new(),
            requested_family,
            engine,
            vector,
            access_tier,
            top_k,
            telemetry_tx,
        )
        .await
    }

    /// Executes the LangGraph-style state graph with multi-turn conversation history support.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_with_history(
        &self,
        prompt: &str,
        history: Vec<ChatTurnMessage>,
        requested_family: SynthesisModelFamily,
        engine: &ScatterGatherEngine,
        vector: &[f32],
        access_tier: u8,
        top_k: usize,
        telemetry_tx: Option<Sender<AgenticTelemetryEvent>>,
    ) -> Result<AgenticGraphState, String> {
        self.run_with_history_and_session(
            prompt,
            history,
            requested_family,
            engine,
            vector,
            access_tier,
            top_k,
            std::collections::HashSet::new(),
            telemetry_tx,
        )
        .await
    }

    /// Executes the LangGraph-style state graph with multi-turn conversation history and session seen chunks.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_with_history_and_session(
        &self,
        prompt: &str,
        history: Vec<ChatTurnMessage>,
        requested_family: SynthesisModelFamily,
        engine: &ScatterGatherEngine,
        vector: &[f32],
        access_tier: u8,
        top_k: usize,
        seen_chunk_ids: std::collections::HashSet<String>,
        telemetry_tx: Option<Sender<AgenticTelemetryEvent>>,
    ) -> Result<AgenticGraphState, String> {
        let corrected_prompt =
            crate::offline_engine::DeterministicOfflineSynthesisEngine::correct_spelling(prompt);
        let prompt_lower = corrected_prompt.trim().to_ascii_lowercase();
        let is_continuation = prompt_lower == "continue"
            || prompt_lower.starts_with("continue ")
            || prompt_lower.contains("tell me more")
            || prompt_lower.contains("go on")
            || prompt_lower.contains("what else");
        // Server-side last-topic memory: if a continuation ("continue", "tell me more") arrives without any client
        // history (e.g. the previous turn was a regenerate after a network error), continue the last real topic
        // instead of searching the index for the literal word "continue".
        let mut history = history;
        if is_continuation {
            let has_user_turn = history.iter().any(|t| t.role.eq_ignore_ascii_case("user"));
            if !has_user_turn {
                if let Ok(guard) = last_turn_memory().lock() {
                    if !guard.0.trim().is_empty() {
                        history.push(ChatTurnMessage {
                            role: "user".to_string(),
                            content: guard.0.clone(),
                        });
                        if !guard.1.trim().is_empty() {
                            history.push(ChatTurnMessage {
                                role: "assistant".to_string(),
                                content: guard.1.clone(),
                            });
                        }
                        tracing::info!(topic = %guard.0, "Continuation without client history: restored last topic from server memory");
                    }
                }
            }
        } else if let Ok(mut guard) = last_turn_memory().lock() {
            *guard = (corrected_prompt.clone(), String::new());
        }
        let mut state_name = AgenticStateName::ClassifyIntent;
        let mut graph_state =
            AgenticGraphState::new(&corrected_prompt, requested_family, self.max_hops)
                .with_seen_chunks(seen_chunk_ids)
                .with_conversation_history(history);
        let mut cache_key_query = graph_state.current_query.clone();
        let mut rewritten_vector: Option<Vec<f32>> = None;

        let hw = HardwareTelemetry::probe();
        if let Some(ref tx) = telemetry_tx {
            let _ = tx
                .send(AgenticTelemetryEvent::HardwareProbed {
                    free_ram_gb: hw.free_ram_gb,
                    free_vram_mb: hw.free_vram_mb,
                    gpu_name: hw.gpu_name.clone(),
                    selected_tier: format!(
                        "RAM: {:.1}GB free, VRAM: {}MB",
                        hw.free_ram_gb, hw.free_vram_mb
                    ),
                })
                .await;
        }

        let grader = GradeRelevanceNode {
            relevance_threshold: self.relevance_threshold,
        };

        loop {
            if let Some(ref tx) = telemetry_tx {
                if tx.is_closed() {
                    tracing::info!("Telemetry channel closed by client disconnect; terminating AgenticStateGraph loop");
                    return Ok(graph_state);
                }
            }

            match state_name {
                AgenticStateName::ClassifyIntent => {
                    ClassifyIntentNode::execute(&mut graph_state, &hw);
                    cache_key_query = graph_state.current_query.clone();

                    let epoch = engine.local_storage.index_epoch();
                    let maybe_cached = if is_continuation {
                        None
                    } else {
                        self.cache_manager.query_cache.get(
                            &cache_key_query,
                            graph_state.search_mode,
                            graph_state.model_family,
                            access_tier,
                            epoch,
                        )
                    };

                    let cache_hit = maybe_cached.is_some();
                    let telem = self.cache_manager.telemetry(cache_hit);

                    if let Some(ref tx) = telemetry_tx {
                        let _ = tx
                            .send(AgenticTelemetryEvent::CacheTelemetry {
                                cache_hit,
                                cache_epoch: telem.cache_epoch,
                                cached_queries: telem.cached_queries,
                                cached_embeddings: telem.cached_embeddings,
                                hits: telem.hits,
                                misses: telem.misses,
                                hit_rate: telem.hit_rate,
                            })
                            .await;
                    }

                    if let Some(cached) = maybe_cached {
                        // FAST PATH: Short-circuit entire retrieval, grading, rewrite, and synthesis!
                        graph_state.retrieved_chunks = cached.chunks.clone();
                        graph_state.synthesized_response = cached.synthesized_response.clone();
                        graph_state.citations = cached.citations.clone();
                        graph_state.query_metadata_filters = cached.query_metadata_filters.clone();
                        graph_state.langextract_result = cached.langextract_result.clone();
                        if let Some(ref res) = graph_state.langextract_result {
                            graph_state.extracted_questions = res
                                .verified_extractions
                                .iter()
                                .filter(|e| e.extraction_class == "question")
                                .map(|e| e.extraction_text.clone())
                                .collect();
                            graph_state.extracted_entities = res
                                .verified_extractions
                                .iter()
                                .filter(|e| e.extraction_class != "question")
                                .cloned()
                                .collect();
                        }

                        if let Some(ref tx) = telemetry_tx {
                            // 1. Stream response text FIRST so citations appear strictly AFTER the response
                            if let Some(ref resp_text) = graph_state.synthesized_response {
                                for word in resp_text.split_inclusive(' ') {
                                    if tx.is_closed() {
                                        break;
                                    }
                                    let _ = tx
                                        .send(AgenticTelemetryEvent::TokenDelta {
                                            delta: word.to_string(),
                                        })
                                        .await;
                                    tokio::time::sleep(tokio::time::Duration::from_millis(6)).await;
                                }
                            }

                            if tx.is_closed() {
                                return Ok(graph_state);
                            }

                            // 2. Emit SOURCES citations AFTER all response tokens have been sent
                            for cit in &graph_state.citations {
                                let _ = tx
                                    .send(AgenticTelemetryEvent::CitationEmitted {
                                        citation: cit.clone(),
                                    })
                                    .await;
                            }

                            let _ = tx
                                .send(AgenticTelemetryEvent::StateTransition {
                                    from_state: AgenticStateName::ClassifyIntent,
                                    to_state: AgenticStateName::Complete,
                                    hop: 0,
                                    timestamp_ms: graph_state.start_time.elapsed().as_millis() as u64,
                                })
                                .await;

                            let _ = tx
                                .send(AgenticTelemetryEvent::ExecutionFinished {
                                    total_hops: 0,
                                    total_duration_ms: graph_state.start_time.elapsed().as_millis() as u64,
                                    total_tokens: graph_state
                                        .synthesized_response
                                        .as_ref()
                                        .map(|s| s.len() / 4)
                                        .unwrap_or(0),
                                    final_state: AgenticStateName::Complete,
                                    model_name: graph_state.selected_model_tag.clone(),
                                })
                                .await;
                        }

                        return Ok(graph_state);
                    }

                    if is_continuation {
                        let orig_q = graph_state.current_query.clone();
                        let _ = crate::agentic::rewrite::RewriteContinuationNode::execute(&mut graph_state);
                        let embedder = quorum_contract::DeterministicOfflineEngine::new();
                        if let Ok(fresh) = embedder.embed_text(&graph_state.current_query) {
                            rewritten_vector = Some(fresh);
                        }
                        if let Some(ref tx) = telemetry_tx {
                            let _ = tx
                                .send(AgenticTelemetryEvent::QueryRewritten {
                                    hop: graph_state.hop_count,
                                    original_query: orig_q,
                                    rewritten_query: graph_state.current_query.clone(),
                                    rewrite_strategy: "continuation_facet_expansion".to_string(),
                                })
                                .await;
                        }
                    }

                    if let Some(ref tx) = telemetry_tx {
                        let _ = tx
                            .send(AgenticTelemetryEvent::IntentClassified {
                                intent: graph_state.intent.unwrap_or(QueryIntentType::LocalDocumentSearch),
                                search_mode: graph_state.search_mode,
                                model_family: graph_state.model_family,
                                model_name: graph_state.selected_model_tag.clone(),
                                routing_rationale: graph_state.routing_rationale.clone(),
                                is_retrieval_required: true,
                            })
                            .await;

                        let _ = tx
                            .send(AgenticTelemetryEvent::StateTransition {
                                from_state: AgenticStateName::ClassifyIntent,
                                to_state: AgenticStateName::RetrieveMesh,
                                hop: graph_state.hop_count,
                                timestamp_ms: graph_state.start_time.elapsed().as_millis() as u64,
                            })
                            .await;
                    }
                    state_name = AgenticStateName::RetrieveMesh;
                }

                AgenticStateName::RetrieveMesh => {
                    let start = std::time::Instant::now();
                    let effective_vec = rewritten_vector.as_deref().unwrap_or(vector);
                    RetrieveMeshNode::execute(
                        &mut graph_state,
                        engine,
                        effective_vec,
                        access_tier,
                        top_k,
                    )
                    .await;
                    let latency = start.elapsed().as_millis() as u64;

                    if let Some(ref tx) = telemetry_tx {
                        let local_count = graph_state.retrieved_chunks.iter().filter(|c| !c.is_remote).count();
                        let remote_count = graph_state.retrieved_chunks.iter().filter(|c| c.is_remote).count();

                        let _ = tx
                            .send(AgenticTelemetryEvent::RetrievalCompleted {
                                hop: graph_state.hop_count,
                                query: graph_state.current_query.clone(),
                                search_mode: graph_state.search_mode,
                                retrieved_count: graph_state.retrieved_chunks.len(),
                                local_count,
                                remote_count,
                                latency_ms: latency,
                            })
                            .await;

                        let _ = tx
                            .send(AgenticTelemetryEvent::StateTransition {
                                from_state: AgenticStateName::RetrieveMesh,
                                to_state: AgenticStateName::GradeRelevance,
                                hop: graph_state.hop_count,
                                timestamp_ms: graph_state.start_time.elapsed().as_millis() as u64,
                            })
                            .await;
                    }
                    state_name = AgenticStateName::GradeRelevance;
                }

                AgenticStateName::GradeRelevance => {
                    let (grade, will_rewrite) = grader.execute(&mut graph_state);

                    if let Some(ref tx) = telemetry_tx {
                        let _ = tx
                            .send(AgenticTelemetryEvent::RelevanceGraded {
                                hop: graph_state.hop_count,
                                grade: grade.clone(),
                                score: grade.score,
                                reasoning: grade.reasoning,
                                will_rewrite,
                            })
                            .await;
                    }

                    if will_rewrite {
                        if let Some(ref tx) = telemetry_tx {
                            let _ = tx
                                .send(AgenticTelemetryEvent::StateTransition {
                                    from_state: AgenticStateName::GradeRelevance,
                                    to_state: AgenticStateName::RewriteQuery,
                                    hop: graph_state.hop_count,
                                    timestamp_ms: graph_state.start_time.elapsed().as_millis() as u64,
                                })
                                .await;
                        }
                        state_name = AgenticStateName::RewriteQuery;
                    } else {
                        if let Some(ref tx) = telemetry_tx {
                            let _ = tx
                                .send(AgenticTelemetryEvent::StateTransition {
                                    from_state: AgenticStateName::GradeRelevance,
                                    to_state: AgenticStateName::SynthesizeWithCitations,
                                    hop: graph_state.hop_count,
                                    timestamp_ms: graph_state.start_time.elapsed().as_millis() as u64,
                                })
                                .await;
                        }
                        state_name = AgenticStateName::SynthesizeWithCitations;
                    }
                }

                AgenticStateName::RewriteQuery => {
                    match RewriteQueryNode::execute(&mut graph_state) {
                        Ok(rewritten) => {
                            if let Some(ref tx) = telemetry_tx {
                                let _ = tx
                                    .send(AgenticTelemetryEvent::QueryRewritten {
                                        hop: graph_state.hop_count,
                                        original_query: graph_state.original_prompt.clone(),
                                        rewritten_query: rewritten,
                                        rewrite_strategy: "Context disambiguation hop".to_string(),
                                    })
                                    .await;

                                let _ = tx
                                    .send(AgenticTelemetryEvent::StateTransition {
                                        from_state: AgenticStateName::RewriteQuery,
                                        to_state: AgenticStateName::RetrieveMesh,
                                        hop: graph_state.hop_count,
                                        timestamp_ms: graph_state.start_time.elapsed().as_millis() as u64,
                                    })
                                    .await;
                            }
                            state_name = AgenticStateName::RetrieveMesh;
                        }
                        Err(_) => {
                            // Cycle detected - break out to synthesis
                            state_name = AgenticStateName::SynthesizeWithCitations;
                        }
                    }
                }

                AgenticStateName::SynthesizeWithCitations => {
                    if let Some(ref tx) = telemetry_tx {
                        if tx.is_closed() {
                            return Ok(graph_state);
                        }
                        let _ = tx
                            .send(AgenticTelemetryEvent::SynthesisStarted {
                                model_name: graph_state.selected_model_tag.clone(),
                                model_family: graph_state.model_family,
                                context_chunks_count: graph_state.retrieved_chunks.len(),
                                estimated_prompt_tokens: 300,
                            })
                            .await;
                    }

                    let is_multi_thread = tokio::runtime::Handle::try_current()
                        .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
                        .unwrap_or(false);

                    if is_multi_thread {
                        tokio::task::block_in_place(|| {
                            SynthesizeWithCitationsNode::execute(
                                &mut graph_state,
                                telemetry_tx.as_ref(),
                            );
                        });
                    } else {
                        SynthesizeWithCitationsNode::execute(
                            &mut graph_state,
                            telemetry_tx.as_ref(),
                        );
                    }

                    if let Ok(mut guard) = last_turn_memory().lock() {
                        let answer: String = graph_state
                            .synthesized_response
                            .as_deref()
                            .unwrap_or("")
                            .chars()
                            .take(4000)
                            .collect();
                        if is_continuation {
                            if !guard.1.is_empty() {
                                guard.1.push_str("\n\n");
                            }
                            guard.1.push_str(&answer);
                        } else {
                            guard.1 = answer;
                        }
                    }

                    // Insert into QueryCache (skip caching continuation turns so "tell me more" always generates fresh follow-ups)
                    if !is_continuation {
                        let epoch = engine.local_storage.index_epoch();
                        self.cache_manager.query_cache.insert(
                            &cache_key_query,
                            graph_state.search_mode,
                            graph_state.model_family,
                            access_tier,
                            epoch,
                            graph_state.retrieved_chunks.clone(),
                            crate::offline_engine::DeterministicOfflineSynthesisEngine::build_synthesis_prompt(
                                &graph_state.original_prompt,
                                &graph_state.retrieved_chunks,
                            ),
                            graph_state.synthesized_response.clone(),
                            graph_state.citations.clone(),
                            graph_state.langextract_result.clone(),
                            graph_state.query_metadata_filters.clone(),
                        );
                    }

                    if let Some(ref tx) = telemetry_tx {
                        // Emit SOURCES citations strictly AFTER all TokenDelta events have completed
                        for cit in &graph_state.citations {
                            let _ = tx
                                .send(AgenticTelemetryEvent::CitationEmitted {
                                    citation: cit.clone(),
                                })
                                .await;
                        }

                        let _ = tx
                            .send(AgenticTelemetryEvent::ExecutionFinished {
                                total_hops: graph_state.hop_count,
                                total_duration_ms: graph_state.start_time.elapsed().as_millis() as u64,
                                total_tokens: graph_state
                                    .synthesized_response
                                    .as_ref()
                                    .map(|s| s.len() / 4)
                                    .unwrap_or(0),
                                final_state: AgenticStateName::Complete,
                                model_name: graph_state.selected_model_tag.clone(),
                            })
                            .await;
                    }

                    return Ok(graph_state);
                }

                AgenticStateName::Complete | AgenticStateName::Failed => {
                    return Ok(graph_state);
                }
            }
        }
    }
}

/// Process-wide memory of the last non-continuation user prompt and its synthesized answer, used only as a fallback
/// when a continuation request arrives without client-side conversation history.
fn last_turn_memory() -> &'static std::sync::Mutex<(String, String)> {
    static MEM: std::sync::OnceLock<std::sync::Mutex<(String, String)>> = std::sync::OnceLock::new();
    MEM.get_or_init(|| std::sync::Mutex::new((String::new(), String::new())))
}
