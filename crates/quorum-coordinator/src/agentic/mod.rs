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
use crate::rlm_orchestrator::{RlmDepthAwareSemaphore, RlmParentSliceCache};
use quorum_contract::EmbeddingGenerator;

pub struct AgenticStateGraphRunner {
    pub max_hops: usize,
    pub relevance_threshold: f32,
    pub cache_manager: Arc<CacheManager>,
    pub rlm_semaphore: Arc<RlmDepthAwareSemaphore>,
    pub rlm_slice_cache: Arc<RlmParentSliceCache>,
    pub memo_config: crate::memo_protocol::MemoProtocolConfig,
}

impl Default for AgenticStateGraphRunner {
    fn default() -> Self {
        Self {
            max_hops: 3,
            relevance_threshold: 0.60,
            cache_manager: Arc::new(CacheManager::default()),
            rlm_semaphore: Arc::new(RlmDepthAwareSemaphore::default_depth_aware()),
            rlm_slice_cache: Arc::new(RlmParentSliceCache::new()),
            memo_config: crate::memo_protocol::MemoProtocolConfig::default(),
        }
    }
}

impl AgenticStateGraphRunner {
    pub fn new(max_hops: usize, relevance_threshold: f32) -> Self {
        Self {
            max_hops,
            relevance_threshold,
            cache_manager: Arc::new(CacheManager::default()),
            rlm_semaphore: Arc::new(RlmDepthAwareSemaphore::default_depth_aware()),
            rlm_slice_cache: Arc::new(RlmParentSliceCache::new()),
            memo_config: crate::memo_protocol::MemoProtocolConfig::default(),
        }
    }

    pub fn with_cache_manager(mut self, cache_manager: Arc<CacheManager>) -> Self {
        self.cache_manager = cache_manager;
        self
    }

    pub fn with_rlm_semaphore(mut self, rlm_semaphore: Arc<RlmDepthAwareSemaphore>) -> Self {
        self.rlm_semaphore = rlm_semaphore;
        self
    }

    pub fn with_rlm_slice_cache(mut self, rlm_slice_cache: Arc<RlmParentSliceCache>) -> Self {
        self.rlm_slice_cache = rlm_slice_cache;
        self
    }

    pub fn with_memo_config(mut self, memo_config: crate::memo_protocol::MemoProtocolConfig) -> Self {
        self.memo_config = memo_config;
        self
    }

    fn is_local_non_dfir_chunk(sc: &quorum_types::ScoredChunk) -> bool {
        !sc.is_remote
            && (sc.source_peer.is_empty() || sc.source_peer.eq_ignore_ascii_case("local"))
            && !crate::artemis_airgap::is_artemis_dfir_chunk(&sc.chunk)
    }

    async fn emit_memo_telemetry(
        telemetry_tx: Option<&Sender<AgenticTelemetryEvent>>,
        state: &AgenticGraphState,
    ) {
        if let Some(tx) = telemetry_tx {
            let (active_candidates, pruned_candidates) = state
                .entity_streak_tracker
                .as_ref()
                .map(|t| (t.active_candidate_count(), t.pruned_candidate_count()))
                .unwrap_or((0, 0));
            let _ = tx
                .send(AgenticTelemetryEvent::MemoStageEvent {
                    stage: state.memo_stage,
                    hop: state.hop_count,
                    active_candidates,
                    pruned_candidates,
                    pinned_entities: state.pinned_entities.clone(),
                })
                .await;
        }
    }

    /// Runs live Stage-3 `SelfRagCritique` verification against a loopback Ollama endpoint,
    /// performing at most 1 bounded corrective synthesis retry + deterministic grounded repair
    /// if `!critique.is_grounded || !critique.answers_all_sub_questions`, and returns
    /// `cache_eligible: bool` (`false` whenever ungroundedness persists so `QueryCache` is never poisoned).
    pub async fn apply_self_rag_critique_gate(
        graph_state: &mut AgenticGraphState,
        ollama_url: &str,
        telemetry_tx: Option<&Sender<AgenticTelemetryEvent>>,
    ) -> bool {
        if graph_state.memo_stage == crate::memo_protocol::MemoStage::Bypassed
            || graph_state.selected_model_tag.trim().is_empty()
            || !crate::typed_extractor::is_loopback_endpoint(ollama_url)
        {
            return true;
        }
        let has_local_chunks = graph_state
            .retrieved_chunks
            .iter()
            .any(Self::is_local_non_dfir_chunk);
        if !has_local_chunks {
            return true;
        }
        let Some(draft_ans) = graph_state.synthesized_response.clone() else {
            return true;
        };

        let local_evidence: String = graph_state
            .retrieved_chunks
            .iter()
            .enumerate()
            .filter(|(_, sc)| Self::is_local_non_dfir_chunk(sc))
            .take(3)
            .map(|(idx, sc)| {
                format!(
                    "[{}] {}",
                    idx + 1,
                    sc.chunk.text_content.chars().take(350).collect::<String>()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let extractor = crate::typed_extractor::TypedStructuredExtractor::<
            crate::typed_extractor::SelfRagCritique,
        >::new(
            ollama_url,
            graph_state.selected_model_tag.clone(),
            "Verify whether the draft answer is strictly grounded in retrieved local citations and addresses all sub-questions.",
        )
        .with_timeout(std::time::Duration::from_secs(4));

        let critique_prompt = format!(
            "Question: {}\nLocal Excerpts:\n{}\nDraft Answer:\n{}",
            graph_state.original_prompt,
            local_evidence,
            draft_ans.chars().take(2400).collect::<String>()
        );

        let Ok(critique) = extractor.extract_ollama_async(&critique_prompt).await else {
            return true;
        };

        if critique.is_grounded && critique.answers_all_sub_questions {
            tracing::debug!(
                is_grounded = critique.is_grounded,
                answers_all_sub_questions = critique.answers_all_sub_questions,
                confidence = critique.confidence,
                "MeMo Stage-3 SelfRagCritique audit passed"
            );
            return true;
        }

        tracing::warn!(
            is_grounded = critique.is_grounded,
            answers_all_sub_questions = critique.answers_all_sub_questions,
            unsupported = ?critique.unsupported_claims,
            missing_refs = ?critique.missing_document_refs,
            confidence = critique.confidence,
            "MeMo Stage-3 SelfRagCritique flagged ungrounded or incomplete draft; running bounded corrective synthesis"
        );
        Self::emit_memo_telemetry(telemetry_tx, graph_state).await;

        let mut note_parts: Vec<String> = Vec::new();
        if !critique.unsupported_claims.is_empty() {
            note_parts.push(format!(
                "Remove or abstain from unsupported claims: {}",
                critique.unsupported_claims.join("; ")
            ));
        }
        if !critique.missing_document_refs.is_empty() {
            let ref_list = critique
                .missing_document_refs
                .iter()
                .map(|r| format!("[{r}]"))
                .collect::<Vec<_>>()
                .join(", ");
            note_parts.push(format!(
                "Include grounded evidence from missing document refs: {ref_list}"
            ));
        }
        let corrective_note = if note_parts.is_empty() {
            "Strictly cite only facts verbatim-grounded in retrieved local excerpts and answer every sub-question.".to_string()
        } else {
            format!("[SelfRagCritique Corrective Directive] {}", note_parts.join(" | "))
        };

        let is_multi_thread = tokio::runtime::Handle::try_current()
            .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
            .unwrap_or(false);
        if is_multi_thread {
            tokio::task::block_in_place(|| {
                SynthesizeWithCitationsNode::execute_draft_with_note(
                    graph_state,
                    Some(&corrective_note),
                    None,
                );
            });
        } else {
            SynthesizeWithCitationsNode::execute_draft_with_note(
                graph_state,
                Some(&corrective_note),
                None,
            );
        }

        let mut final_critique = critique;
        if let Some(ref revised_ans) = graph_state.synthesized_response {
            let revised_prompt = format!(
                "Question: {}\nLocal Excerpts:\n{}\nDraft Answer:\n{}",
                graph_state.original_prompt,
                local_evidence,
                revised_ans.chars().take(2400).collect::<String>()
            );
            if let Ok(rev_critique) = extractor.extract_ollama_async(&revised_prompt).await {
                if rev_critique.is_grounded && rev_critique.answers_all_sub_questions {
                    tracing::info!("MeMo Stage-3 corrective synthesis passed SelfRagCritique");
                    return true;
                }
                final_critique = rev_critique;
            }
        }

        SynthesizeWithCitationsNode::repair_ungrounded_draft_deterministically(
            graph_state,
            &final_critique.unsupported_claims,
            &final_critique.missing_document_refs,
        );
        false
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
                    let settings_snapshot = crate::dlp_mesh::global_mesh_dlp_controller().get_settings();
                    let p2p_active =
                        settings_snapshot.mesh.p2p_enabled && engine.mesh_dispatcher.peer_count() > 0;
                    let cache_policy = crate::artemis_airgap::resolve_local_retrieval_policy(
                        &settings_snapshot,
                        access_tier,
                        &[&graph_state.original_prompt, &cache_key_query],
                    );
                    let query_targets_forensics =
                        crate::artemis_airgap::is_forensic_query_text(&cache_key_query);
                    let maybe_cached = if is_continuation {
                        None
                    } else {
                        self.cache_manager
                            .query_cache
                            .get_with_mesh_requirement(
                                &cache_key_query,
                                graph_state.search_mode,
                                graph_state.model_family,
                                cache_policy.local_access_tier,
                                epoch,
                                p2p_active,
                            )
                            .filter(|cached| {
                                let resp_txt = cached.synthesized_response.as_deref().unwrap_or_default();
                                if cache_policy.allow_artemis_local {
                                    !resp_txt.contains("forensics subsystem is currently disabled")
                                        && !cached
                                            .synthesis_prompt
                                            .contains("forensics subsystem is currently disabled")
                                        && cached
                                            .chunks
                                            .iter()
                                            .all(|c| cache_policy.permits_local_scored_chunk(c))
                                } else {
                                    cached.chunks.iter().all(|c| {
                                        !crate::artemis_airgap::is_artemis_dfir_chunk(&c.chunk)
                                            && cache_policy.permits_local_scored_chunk(c)
                                    }) && !resp_txt.to_ascii_lowercase().contains("artemis://")
                                        && !cached
                                            .synthesis_prompt
                                            .to_ascii_lowercase()
                                            .contains("artemis://")
                                        && (!query_targets_forensics
                                            || resp_txt
                                                .contains("forensics subsystem is currently disabled"))
                                }
                            })
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
                            // 1. Stream response text FIRST so citations appear strictly AFTER the response.
                            // Emitted instantaneously without sleep delay on cache hits (<5ms response).
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

                            let responder_peer_id = if engine.sender_peer_id.trim().is_empty() {
                                "local".to_string()
                            } else {
                                engine.sender_peer_id.clone()
                            };
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
                                    responder_peer_id,
                                    peer_diagnostics: graph_state.peer_diagnostics.clone(),
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

                    let is_forensic = crate::offline_engine::ForensicQueryIntent::detect(
                        &graph_state.original_prompt,
                    )
                    .is_some()
                        || crate::offline_engine::ForensicQueryIntent::detect(
                            &graph_state.current_query,
                        )
                        .is_some()
                        || crate::artemis_airgap::is_forensic_query_text(
                            &graph_state.current_query,
                        );
                    if let Some(ref plan) = graph_state.adaptive_plan {
                        if crate::memo_protocol::should_engage_memo_protocol(
                            &self.memo_config,
                            graph_state.intent,
                            plan,
                            is_forensic,
                            is_continuation,
                        ) {
                            graph_state.memo_stage =
                                crate::memo_protocol::MemoStage::Stage1Grounding;
                            Self::emit_memo_telemetry(telemetry_tx.as_ref(), &graph_state).await;
                        } else {
                            graph_state.memo_stage = crate::memo_protocol::MemoStage::Bypassed;
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

                    // Launch AtlasKV 3-level HiKVP pruning + MeMo entity surfacing concurrently off the async runtime thread
                    let settings_snapshot =
                        crate::dlp_mesh::global_mesh_dlp_controller().get_settings();
                    let atlaskv_cfg = settings_snapshot.atlaskv.clone();
                    let local_policy = crate::artemis_airgap::resolve_local_retrieval_policy(
                        &settings_snapshot,
                        access_tier,
                        &[&graph_state.original_prompt, &graph_state.current_query],
                    );
                    let local_kv_tier = local_policy.local_access_tier;
                    let is_deep_graph = graph_state
                        .adaptive_plan
                        .as_ref()
                        .map(|p| p.depth == crate::adaptive_rag::RetrievalDepth::DeepGraph)
                        .unwrap_or(false);
                    let surface_cap = self.memo_config.stage1_max_subqueries.max(1);
                    let mut surface_entities: Vec<String> = Vec::new();
                    if !graph_state.pinned_entities.is_empty() {
                        for pinned in &graph_state.pinned_entities {
                            let clean = crate::memo_protocol::UncertainAnswerStreakTracker::entity_lookup_name(pinned).to_string();
                            if !clean.is_empty()
                                && !surface_entities.iter().any(|e| e.eq_ignore_ascii_case(&clean))
                            {
                                surface_entities.push(clean);
                            }
                            if surface_entities.len() >= surface_cap {
                                break;
                            }
                        }
                    }
                    if surface_entities.len() < surface_cap {
                        if let Some(ref tracker) = graph_state.entity_streak_tracker {
                            for cand in tracker.candidates.values() {
                                if !cand.pruned && cand.confirmed_hits == 0 {
                                    let clean = cand.canonical_name.trim();
                                    if !clean.is_empty()
                                        && !surface_entities
                                            .iter()
                                            .any(|e| e.eq_ignore_ascii_case(clean))
                                    {
                                        surface_entities.push(clean.to_string());
                                    }
                                    if surface_entities.len() >= surface_cap {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if surface_entities.is_empty() {
                        if let Some(ref subj) = graph_state
                            .adaptive_plan
                            .as_ref()
                            .and_then(|p| p.primary_subject.clone())
                        {
                            if !subj.trim().is_empty() {
                                surface_entities.push(subj.trim().to_string());
                            }
                        }
                        for ext in &graph_state.extracted_entities {
                            let clean = ext.extraction_text.trim();
                            if clean.len() >= 2
                                && !surface_entities.iter().any(|e| e.eq_ignore_ascii_case(clean))
                            {
                                surface_entities.push(clean.to_string());
                            }
                            if surface_entities.len() >= surface_cap {
                                break;
                            }
                        }
                    }
                    let atlaskv_fut = {
                        let store_opt = engine.local_storage.atlaskv();
                        let qvec = effective_vec.to_vec();
                        let leaf_k = if is_deep_graph {
                            atlaskv_cfg.leaf_top_k_kb.max(12)
                        } else {
                            atlaskv_cfg.leaf_top_k_kb.max(1)
                        };
                        let enabled = atlaskv_cfg.enabled;
                        async move {
                            let store = if enabled { store_opt? } else { return None };
                            tokio::task::spawn_blocking(move || {
                                let hikvp_res =
                                    store.hikvp_search(&qvec, local_kv_tier, leaf_k, None);
                                let hikvp_ok = hikvp_res.is_ok();
                                let (mut triples, trace) = hikvp_res
                                    .unwrap_or_else(|_| {
                                        (Vec::new(), quorum_atlaskv::HiKvpPruningTrace::default())
                                    });
                                if !surface_entities.is_empty() {
                                    let mut seen_tid: std::collections::HashSet<u64> =
                                        triples.iter().map(|t| t.triple.triple_id).collect();
                                    for ent in &surface_entities {
                                        if let Ok(surface_hits) = store.query_entity_surface(
                                            ent,
                                            local_kv_tier,
                                            leaf_k,
                                            None,
                                        ) {
                                            for t in surface_hits {
                                                if seen_tid.insert(t.triple.triple_id) {
                                                    triples.push(t);
                                                }
                                            }
                                        }
                                    }
                                }
                                if hikvp_ok || !triples.is_empty() {
                                    Some((triples, trace))
                                } else {
                                    None
                                }
                            })
                            .await
                            .ok()
                            .flatten()
                        }
                    };

                    let (_, atlaskv_res) = tokio::join!(
                        RetrieveMeshNode::execute(
                            &mut graph_state,
                            engine,
                            effective_vec,
                            access_tier,
                            top_k,
                        ),
                        atlaskv_fut
                    );
                    let latency = start.elapsed().as_millis() as u64;

                    if let Some((mut kg_triples, kg_trace)) = atlaskv_res {
                        kg_triples.retain(|t| local_policy.permits_local_triple(&t.triple));
                        let formatted_kg = quorum_atlaskv::format_grounded_kg_context(&kg_triples);
                        let injected = kg_triples.len();
                        graph_state.atlaskv_triples = kg_triples;
                        graph_state.atlaskv_context = formatted_kg;

                        if let Some(ref tx) = telemetry_tx {
                            let _ = tx
                                .send(AgenticTelemetryEvent::AtlasKvPruned {
                                    root_scanned: kg_trace.root_selected,
                                    inter_scanned: kg_trace.inter_scanned,
                                    leaf_selected: kg_trace.leaf_selected,
                                    triples_injected: injected,
                                    used_hierarchy: kg_trace.used_hierarchy,
                                    elapsed_ms: kg_trace.elapsed_us / 1000,
                                })
                                .await;
                        }
                    }

                    if graph_state.hop_count == 0
                        && graph_state.memo_stage
                            == crate::memo_protocol::MemoStage::Stage1Grounding
                    {
                        let sub_qs: Vec<String> = graph_state
                            .adaptive_plan
                            .as_ref()
                            .map(|p| p.sub_questions.clone())
                            .filter(|v| !v.is_empty())
                            .unwrap_or_else(|| vec![graph_state.current_query.clone()]);
                        let mut clues = crate::memo_protocol::build_stage1_clue_probes(
                            &sub_qs,
                            &graph_state.retrieved_chunks,
                            &graph_state.atlaskv_triples,
                            self.memo_config.stage1_max_subqueries,
                        );
                        let daemon_active = crate::dlp_mesh::global_mesh_dlp_controller()
                            .settings_file_path
                            .read()
                            .map(|p| p.is_some())
                            .unwrap_or(false);
                        let has_local_chunks = graph_state
                            .retrieved_chunks
                            .iter()
                            .any(Self::is_local_non_dfir_chunk);
                        if daemon_active
                            && self.memo_config.use_live_llm_probes
                            && !graph_state.selected_model_tag.is_empty()
                            && has_local_chunks
                            && crate::offline_engine::DeterministicOfflineSynthesisEngine::is_ollama_endpoint_reachable()
                        {
                            let ollama_url = if settings_snapshot.ui.ollama_url.trim().is_empty() {
                                "http://127.0.0.1:11434".to_string()
                            } else {
                                settings_snapshot.ui.ollama_url.trim().to_string()
                            };
                            if crate::typed_extractor::is_loopback_endpoint(&ollama_url) {
                                let extractor = crate::typed_extractor::TypedStructuredExtractor::<
                                    crate::memo_protocol::Stage1ClueProbeOutput,
                                >::new(
                                    ollama_url,
                                    graph_state.selected_model_tag.clone(),
                                    "Extract atomic grounded clues and candidate entity names for a single Stage-1 sub-question.",
                                )
                                .with_timeout(std::time::Duration::from_secs(2));
                                let local_snippet: String = graph_state
                                    .retrieved_chunks
                                    .iter()
                                    .filter(|sc| Self::is_local_non_dfir_chunk(sc))
                                    .take(2)
                                    .map(|c| c.chunk.text_content.chars().take(400).collect::<String>())
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                if let Some(first_uncertain) = clues.iter_mut().find(|p| p.is_uncertain) {
                                    let probe_prompt = format!(
                                        "Sub-question: {}\nLocal Excerpts:\n{}",
                                        first_uncertain.sub_question, local_snippet
                                    );
                                    if let Ok(out) = extractor.extract_ollama_async(&probe_prompt).await {
                                        crate::memo_protocol::apply_live_stage1_probe_output(
                                            first_uncertain,
                                            out,
                                            false,
                                        );
                                    }
                                }
                            }
                        }
                        let max_s2_turns = self
                            .memo_config
                            .stage2_max_turns
                            .min(graph_state.max_hops.max(1));
                        let mut tracker =
                            crate::memo_protocol::UncertainAnswerStreakTracker::new(
                                max_s2_turns,
                                self.memo_config.stage2_uncertain_streak_limit,
                            );
                        tracker.seed_from_stage1(
                            &clues,
                            &graph_state.retrieved_chunks,
                            &graph_state.atlaskv_triples,
                        );
                        graph_state.stage1_clues = clues;
                        graph_state.pinned_entities = tracker.pinned_entities.clone();
                        graph_state.entity_streak_tracker = Some(tracker);
                        graph_state.memo_stage =
                            crate::memo_protocol::MemoStage::Stage2EntityIdentification;
                        Self::emit_memo_telemetry(telemetry_tx.as_ref(), &graph_state).await;
                    }

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
                                peer_diagnostics: graph_state.peer_diagnostics.clone(),
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
                    let (grade, mut will_rewrite) = grader.execute(&mut graph_state);

                    if will_rewrite
                        && graph_state.memo_stage
                            == crate::memo_protocol::MemoStage::Stage2EntityIdentification
                    {
                        let daemon_active = crate::dlp_mesh::global_mesh_dlp_controller()
                            .settings_file_path
                            .read()
                            .map(|p| p.is_some())
                            .unwrap_or(false);
                        let has_local_chunks = graph_state
                            .retrieved_chunks
                            .iter()
                            .any(Self::is_local_non_dfir_chunk);
                        let live_pin_decision = if daemon_active
                            && self.memo_config.use_live_llm_probes
                            && !graph_state.selected_model_tag.is_empty()
                            && has_local_chunks
                            && crate::offline_engine::DeterministicOfflineSynthesisEngine::is_ollama_endpoint_reachable()
                        {
                            let settings_snapshot =
                                crate::dlp_mesh::global_mesh_dlp_controller().get_settings();
                            let ollama_url = if settings_snapshot.ui.ollama_url.trim().is_empty() {
                                "http://127.0.0.1:11434".to_string()
                            } else {
                                settings_snapshot.ui.ollama_url.trim().to_string()
                            };
                            if crate::typed_extractor::is_loopback_endpoint(&ollama_url) {
                                let candidate_summary = graph_state
                                    .entity_streak_tracker
                                    .as_ref()
                                    .map(|t| {
                                        t.candidates
                                            .values()
                                            .filter(|c| !c.pruned)
                                            .map(|c| {
                                                format!(
                                                    "{}[cluster={}, streak={}/{}, hits={}]",
                                                    c.canonical_name,
                                                    c.domain_cluster.as_deref().unwrap_or("general"),
                                                    c.consecutive_uncertain_streak,
                                                    t.streak_limit,
                                                    c.confirmed_hits
                                                )
                                            })
                                            .collect::<Vec<_>>()
                                            .join("; ")
                                    })
                                    .unwrap_or_default();
                                let local_snippet: String = graph_state
                                    .retrieved_chunks
                                    .iter()
                                    .filter(|sc| Self::is_local_non_dfir_chunk(sc))
                                    .take(2)
                                    .map(|c| c.chunk.text_content.chars().take(300).collect::<String>())
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                let extractor = crate::typed_extractor::TypedStructuredExtractor::<
                                    crate::memo_protocol::Stage2EntityPinDecision,
                                >::new(
                                    ollama_url,
                                    graph_state.selected_model_tag.clone(),
                                    "Select Stage-2 candidate entities to pin or probe next based on local evidence.",
                                )
                                .with_timeout(std::time::Duration::from_secs(2));
                                let pin_prompt = format!(
                                    "Question: {}\nCandidates: {}\nLocal Excerpts:\n{}",
                                    graph_state.original_prompt, candidate_summary, local_snippet
                                );
                                extractor.extract_ollama_async(&pin_prompt).await.ok()
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        if let Some(ref mut tracker) = graph_state.entity_streak_tracker {
                            let live_probe_hint = live_pin_decision.and_then(|decision| {
                                crate::memo_protocol::apply_live_stage2_pin_decision(
                                    tracker, decision,
                                )
                            });
                            match tracker.begin_stage2_turn() {
                                crate::memo_protocol::Stage2TurnDirective::SkipToStage3 {
                                    ..
                                } => {
                                    will_rewrite = false;
                                    graph_state.memo_stage =
                                        crate::memo_protocol::MemoStage::Stage3AnswerSeeking;
                                    graph_state.active_stage2_directive = None;
                                }
                                mut dir @ crate::memo_protocol::Stage2TurnDirective::ContinueProbe {
                                    ..
                                } => {
                                    if let Some(ref hint) = live_probe_hint {
                                        if let crate::memo_protocol::Stage2TurnDirective::ContinueProbe {
                                            ref mut probe_query,
                                            ..
                                        } = dir
                                        {
                                            if !probe_query
                                                .to_ascii_lowercase()
                                                .contains(&hint.to_ascii_lowercase())
                                            {
                                                *probe_query = format!("{} {}", probe_query, hint);
                                            }
                                        }
                                    }
                                    graph_state.active_stage2_directive = Some(dir);
                                }
                            }
                        }
                        Self::emit_memo_telemetry(telemetry_tx.as_ref(), &graph_state).await;
                    } else if !will_rewrite
                        && graph_state.memo_stage
                            == crate::memo_protocol::MemoStage::Stage2EntityIdentification
                    {
                        graph_state.memo_stage =
                            crate::memo_protocol::MemoStage::Stage3AnswerSeeking;
                        graph_state.active_stage2_directive = None;
                        Self::emit_memo_telemetry(telemetry_tx.as_ref(), &graph_state).await;
                    }

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
                            let embedder = quorum_contract::DeterministicOfflineEngine::new();
                            if let Ok(fresh) = embedder.embed_text(&rewritten) {
                                rewritten_vector = Some(fresh);
                            }
                            let rewrite_strategy = if graph_state.memo_stage
                                == crate::memo_protocol::MemoStage::Stage2EntityIdentification
                            {
                                "memo_stage2_entity_probe".to_string()
                            } else {
                                "Context disambiguation hop".to_string()
                            };
                            if let Some(ref tx) = telemetry_tx {
                                let _ = tx
                                    .send(AgenticTelemetryEvent::QueryRewritten {
                                        hop: graph_state.hop_count,
                                        original_query: graph_state.original_prompt.clone(),
                                        rewritten_query: rewritten,
                                        rewrite_strategy,
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
                    let settings_snapshot =
                        crate::dlp_mesh::global_mesh_dlp_controller().get_settings();
                    let synth_policy = crate::artemis_airgap::resolve_local_retrieval_policy(
                        &settings_snapshot,
                        access_tier,
                        &[&graph_state.original_prompt, &graph_state.current_query],
                    );

                    if !matches!(
                        graph_state.memo_stage,
                        crate::memo_protocol::MemoStage::Bypassed
                            | crate::memo_protocol::MemoStage::Stage3AnswerSeeking
                            | crate::memo_protocol::MemoStage::Complete
                    ) {
                        graph_state.memo_stage =
                            crate::memo_protocol::MemoStage::Stage3AnswerSeeking;
                        Self::emit_memo_telemetry(telemetry_tx.as_ref(), &graph_state).await;
                    }

                    if graph_state.memo_stage != crate::memo_protocol::MemoStage::Bypassed {
                        crate::memo_protocol::prune_distractor_chunks_for_stage3(&mut graph_state);
                    }

                    // Live Concurrent RLM Parent-Document Enrichment: concurrently expand local chunks
                    // into surrounding parent-document byte windows and regex-grep uncovered query terms
                    // plus Stage-2 pinned entities bounded by RlmDepthAwareSemaphore over a JoinSet.
                    let stage3_targets: Vec<String> = graph_state
                        .pinned_entities
                        .iter()
                        .take(self.memo_config.stage3_max_seek_queries.max(1))
                        .cloned()
                        .collect();
                    crate::rlm_orchestrator::RlmOrchestrator::enrich_retrieved_chunks_with_parent_rlm_concurrent_with_targets(
                        &graph_state.current_query,
                        &mut graph_state.retrieved_chunks,
                        Arc::clone(&engine.local_storage),
                        synth_policy.local_access_tier,
                        Arc::clone(&self.rlm_semaphore),
                        Some(Arc::clone(&self.rlm_slice_cache)),
                        &stage3_targets,
                    )
                    .await;

                    let installed = crate::offline_engine::DeterministicOfflineSynthesisEngine::probe_installed_ollama_models_default();
                    if !installed.is_empty() {
                        let verified_tag = crate::offline_engine::DeterministicOfflineSynthesisEngine::resolve_ollama_model_tag(
                            &graph_state.selected_model_tag,
                            &hw,
                            &installed,
                        );
                        graph_state.selected_model_tag = verified_tag;
                    }

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

                    // Layer 1 Pre-Synthesis Entity Domain Clustering (general across all entities/homonyms)
                    let q_low = graph_state.current_query.to_ascii_lowercase();
                    let is_entity_or_profile_query = crate::offline_engine::DeterministicOfflineSynthesisEngine::is_profile_or_role_query(&graph_state.current_query)
                        || q_low.starts_with("who ")
                        || q_low.contains("who is")
                        || q_low.contains("who was")
                        || q_low.contains("tell me about")
                        || !graph_state.extracted_entities.is_empty();
                    if is_entity_or_profile_query && graph_state.retrieved_chunks.len() > 1 {
                        let mut clusters: std::collections::BTreeMap<&'static str, Vec<quorum_types::ScoredChunk>> =
                            std::collections::BTreeMap::new();
                        for chunk in &graph_state.retrieved_chunks {
                            let label = crate::answer_orchestrator::classify_entity_domain_cluster(
                                &chunk.chunk.file_path,
                                &chunk.chunk.text_content,
                            );
                            clusters.entry(label).or_default().push(chunk.clone());
                        }
                        if clusters.len() > 1 {
                            let mut clustered_chunks = Vec::new();
                            for (idx, (label, mut items)) in clusters.into_iter().enumerate() {
                                for item in &mut items {
                                    let mut meta_val = serde_json::from_str::<serde_json::Value>(&item.chunk.metadata_json)
                                        .unwrap_or_else(|_| serde_json::json!({}));
                                    if let Some(obj) = meta_val.as_object_mut() {
                                        obj.insert("entity_cluster".to_string(), serde_json::json!(label));
                                        obj.insert("entity_cluster_index".to_string(), serde_json::json!(idx + 1));
                                    }
                                    item.chunk.metadata_json = meta_val.to_string();
                                }
                                clustered_chunks.extend(items);
                            }
                            graph_state.retrieved_chunks = clustered_chunks;
                        }
                    }

                    let is_multi_thread = tokio::runtime::Handle::try_current()
                        .map(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
                        .unwrap_or(false);

                    if is_multi_thread {
                        tokio::task::block_in_place(|| {
                            SynthesizeWithCitationsNode::execute_draft(
                                &mut graph_state,
                                telemetry_tx.as_ref(),
                            );
                        });
                    } else {
                        SynthesizeWithCitationsNode::execute_draft(
                            &mut graph_state,
                            telemetry_tx.as_ref(),
                        );
                    }

                    let daemon_active = crate::dlp_mesh::global_mesh_dlp_controller()
                        .settings_file_path
                        .read()
                        .map(|p| p.is_some())
                        .unwrap_or(false);
                    let has_local_chunks = graph_state
                        .retrieved_chunks
                        .iter()
                        .any(Self::is_local_non_dfir_chunk);
                    let mut cache_eligible = true;
                    if daemon_active
                        && self.memo_config.use_live_llm_probes
                        && graph_state.memo_stage != crate::memo_protocol::MemoStage::Bypassed
                        && !installed.is_empty()
                        && !graph_state.selected_model_tag.is_empty()
                        && has_local_chunks
                        && crate::offline_engine::DeterministicOfflineSynthesisEngine::is_ollama_endpoint_reachable()
                    {
                        let ollama_url = if settings_snapshot.ui.ollama_url.trim().is_empty() {
                            "http://127.0.0.1:11434".to_string()
                        } else {
                            settings_snapshot.ui.ollama_url.trim().to_string()
                        };
                        cache_eligible = Self::apply_self_rag_critique_gate(
                            &mut graph_state,
                            &ollama_url,
                            telemetry_tx.as_ref(),
                        )
                        .await;
                    }

                    SynthesizeWithCitationsNode::emit_final_answer(
                        &graph_state,
                        telemetry_tx.as_ref(),
                    );

                    if graph_state.memo_stage != crate::memo_protocol::MemoStage::Bypassed {
                        graph_state.memo_stage = crate::memo_protocol::MemoStage::Complete;
                        Self::emit_memo_telemetry(telemetry_tx.as_ref(), &graph_state).await;
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

                    // Insert into QueryCache (skip caching continuation turns and ungrounded SelfRagCritique drafts)
                    if !is_continuation && cache_eligible {
                        let epoch = engine.local_storage.index_epoch();
                        self.cache_manager.query_cache.insert(
                            &cache_key_query,
                            graph_state.search_mode,
                            graph_state.model_family,
                            synth_policy.local_access_tier,
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

                        let responder_peer_id = if engine.sender_peer_id.trim().is_empty() {
                            "local".to_string()
                        } else {
                            engine.sender_peer_id.clone()
                        };

                        if let Some(ref mut diag) = graph_state.peer_diagnostics {
                            for cit in &graph_state.citations {
                                if !cit.peer_id.is_empty() && cit.peer_id != "local" && !diag.contributing_peer_ids.contains(&cit.peer_id) {
                                    diag.contributing_peer_ids.push(cit.peer_id.clone());
                                }
                            }
                        } else if graph_state.citations.iter().any(|c| !c.peer_id.is_empty() && c.peer_id != "local") {
                            let mut contributing = Vec::new();
                            for cit in &graph_state.citations {
                                if !cit.peer_id.is_empty() && cit.peer_id != "local" && !contributing.contains(&cit.peer_id) {
                                    contributing.push(cit.peer_id.clone());
                                }
                            }
                            graph_state.peer_diagnostics = Some(quorum_types::FederatedPeerDiagnostics {
                                connected_peers_count: contributing.len(),
                                connected_peer_ids: contributing.clone(),
                                queried_peers_count: contributing.len(),
                                peer_outcomes: Vec::new(),
                                summary_reason: None,
                                contributing_peer_ids: contributing,
                            });
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
                                responder_peer_id,
                                peer_diagnostics: graph_state.peer_diagnostics.clone(),
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
