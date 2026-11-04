use crate::agentic::AgenticStateGraphRunner;
use crate::cache::CacheManager;
use crate::config::CoordinatorConfig;
use crate::error::CoordinatorError;
use crate::offline_engine::DeterministicOfflineSynthesisEngine;
use crate::scatter_gather::ScatterGatherEngine;
use crate::telemetry::AgenticTelemetryEvent;
use crate::types::{AgenticGraphState, ChatTurnMessage, SynthesisModelFamily};
use quorum_contract::EmbeddingGenerator;
use quorum_storage::{SearchMode, StorageEngine};
use quorum_types::{CacheTelemetry, Citation, QueryResult};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

pub struct QueryCoordinator {
    pub engine: Arc<ScatterGatherEngine>,
    pub config: CoordinatorConfig,
    pub cache_manager: Arc<CacheManager>,
    pub agentic_runner: AgenticStateGraphRunner,
}

impl QueryCoordinator {
    pub fn new(engine: Arc<ScatterGatherEngine>, config: CoordinatorConfig) -> Self {
        let cache_manager = Arc::new(CacheManager::default());
        let agentic_runner = AgenticStateGraphRunner::new(3, 0.60)
            .with_cache_manager(Arc::clone(&cache_manager));
        Self {
            engine,
            config,
            cache_manager,
            agentic_runner,
        }
    }

    pub fn with_cache_manager(
        engine: Arc<ScatterGatherEngine>,
        config: CoordinatorConfig,
        cache_manager: Arc<CacheManager>,
    ) -> Self {
        let agentic_runner = AgenticStateGraphRunner::new(3, 0.60)
            .with_cache_manager(Arc::clone(&cache_manager));
        Self {
            engine,
            config,
            cache_manager,
            agentic_runner,
        }
    }

    /// Return live cache telemetry.
    pub fn cache_stats(&self) -> CacheTelemetry {
        self.cache_manager.telemetry(false)
    }

    /// Increment cache epoch counter.
    pub fn cache_bump_epoch(&self) -> u64 {
        self.cache_manager.advance_epoch()
    }

    /// Clear all query and embedding cache entries.
    pub fn cache_clear_all(&self) -> (u64, usize) {
        let epoch = self.cache_manager.advance_epoch();
        let cleared = self.cache_manager.query_cache.clear() + self.cache_manager.embedding_cache.clear();
        (epoch, cleared)
    }

    /// Pre-warm embeddings into the cache from storage.
    pub async fn cache_prewarm(&self, storage: &StorageEngine) -> Result<usize, CoordinatorError> {
        let embedder = quorum_contract::DeterministicOfflineEngine::new();
        let resp = self.cache_manager.recache(Some(storage), Some(&embedder), false, true).await;
        Ok(resp.warmed_entries)
    }

    /// Fast single-pass scatter-gather retrieval across local storage and federated peers.
    pub async fn query(&self, prompt: &str, top_k: usize) -> Result<QueryResult, CoordinatorError> {
        let start = std::time::Instant::now();
        let epoch = self.engine.local_storage.index_epoch();
        let access_tier = self.config.default_peer_access_tier;

        // Check QueryCache
        if let Some(cached) = self.cache_manager.query_cache.get(
            prompt,
            SearchMode::Hybrid,
            SynthesisModelFamily::AutoFusion,
            access_tier,
            epoch,
        ) {
            let execution_time_ms = start.elapsed().as_millis() as u64;
            return Ok(QueryResult {
                chunks: cached.chunks.clone(),
                synthesis_prompt: cached.synthesis_prompt.clone(),
                execution_time_ms,
                sources_cited: cached.citations.clone(),
                cache_hit: true,
                cache_epoch: epoch,
            });
        }

        let embedder = quorum_contract::DeterministicOfflineEngine::new();
        let contract_hash = embedder.contract_hash();
        let vector = if let Some(cached_vec) = self.cache_manager.embedding_cache.get(&contract_hash, prompt) {
            cached_vec
        } else {
            let fresh = embedder.embed_text(prompt).unwrap_or_else(|_| vec![0.0; 768]);
            self.cache_manager.embedding_cache.insert(&contract_hash, prompt, fresh.clone());
            fresh
        };

        let (chunks, _volatile, _) = self
            .engine
            .execute_query(
                prompt,
                &vector,
                access_tier,
                top_k,
            )
            .await;

        let synthesis_prompt =
            DeterministicOfflineSynthesisEngine::build_synthesis_prompt(prompt, &chunks);
        let sources_cited: Vec<Citation> = chunks.iter().map(|c| c.to_citation()).collect();
        let execution_time_ms = start.elapsed().as_millis() as u64;

        // Insert into QueryCache
        self.cache_manager.query_cache.insert(
            prompt,
            SearchMode::Hybrid,
            SynthesisModelFamily::AutoFusion,
            access_tier,
            epoch,
            chunks.clone(),
            synthesis_prompt.clone(),
            None,
            sources_cited.clone(),
            None,
            None,
        );

        Ok(QueryResult {
            chunks,
            synthesis_prompt,
            execution_time_ms,
            sources_cited,
            cache_hit: false,
            cache_epoch: epoch,
        })
    }

    /// Executes iterative multi-hop retrieval and synthesis via LangGraph-style Agentic State Graph.
    pub async fn query_agentic(
        &self,
        prompt: &str,
        family: SynthesisModelFamily,
        top_k: usize,
        telemetry_tx: Option<Sender<AgenticTelemetryEvent>>,
    ) -> Result<QueryResult, CoordinatorError> {
        self.query_agentic_with_history(prompt, Vec::new(), family, top_k, telemetry_tx)
            .await
    }

    /// Executes iterative multi-hop retrieval and synthesis with multi-turn conversation history and session seen chunks.
    pub async fn query_agentic_with_history_and_session(
        &self,
        prompt: &str,
        history: Vec<ChatTurnMessage>,
        family: SynthesisModelFamily,
        top_k: usize,
        seen_chunk_ids: std::collections::HashSet<String>,
        telemetry_tx: Option<Sender<AgenticTelemetryEvent>>,
    ) -> Result<QueryResult, CoordinatorError> {
        let start = std::time::Instant::now();
        tracing::info!(prompt, seen_count = seen_chunk_ids.len(), "Starting query_agentic_with_history_and_session");
        let embed_query = AgenticGraphState::expand_followup_query(prompt, &history);
        let embedder = quorum_contract::DeterministicOfflineEngine::new();
        let contract_hash = embedder.contract_hash();
        let vector = if let Some(cached_vec) = self.cache_manager.embedding_cache.get(&contract_hash, &embed_query) {
            cached_vec
        } else {
            let fresh = embedder.embed_text(&embed_query).unwrap_or_else(|_| vec![0.0; 768]);
            self.cache_manager.embedding_cache.insert(&contract_hash, &embed_query, fresh.clone());
            fresh
        };

        let epoch = self.engine.local_storage.index_epoch();
        let hits_before = self.cache_manager.telemetry(false).hits;

        let final_state = self
            .agentic_runner
            .run_with_history_and_session(
                prompt,
                history,
                family,
                &self.engine,
                &vector,
                self.config.default_peer_access_tier,
                top_k,
                seen_chunk_ids,
                telemetry_tx,
            )
            .await
            .map_err(CoordinatorError::GraphError)?;

        let was_cached = self.cache_manager.telemetry(false).hits > hits_before;

        let synthesis_prompt = final_state
            .synthesized_response
            .unwrap_or_else(|| DeterministicOfflineSynthesisEngine::build_synthesis_prompt(prompt, &final_state.retrieved_chunks));

        let execution_time_ms = start.elapsed().as_millis() as u64;

        Ok(QueryResult {
            chunks: final_state.retrieved_chunks,
            synthesis_prompt,
            execution_time_ms,
            sources_cited: final_state.citations,
            cache_hit: was_cached,
            cache_epoch: epoch,
        })
    }

    /// Executes iterative multi-hop retrieval and synthesis with multi-turn conversation history.
    pub async fn query_agentic_with_history(
        &self,
        prompt: &str,
        history: Vec<ChatTurnMessage>,
        family: SynthesisModelFamily,
        top_k: usize,
        telemetry_tx: Option<Sender<AgenticTelemetryEvent>>,
    ) -> Result<QueryResult, CoordinatorError> {
        self.query_agentic_with_history_and_session(
            prompt,
            history,
            family,
            top_k,
            std::collections::HashSet::new(),
            telemetry_tx,
        )
        .await
    }
}
