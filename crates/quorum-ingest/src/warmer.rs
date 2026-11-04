//! Cache Pre-Warming Engine for QuorumRAG.
//!
//! Pre-warms hot chunk embeddings and canonical query representations
//! following reindexing or manual recache operations, eliminating cold-start latency.

use std::sync::Arc;
use std::time::Instant;
use serde::{Deserialize, Serialize};

use crate::dedup::TwoLevelDedupEngine;
use quorum_contract::EmbeddingGenerator;
use quorum_storage::StorageEngine;

/// Configuration for cache pre-warming pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmConfig {
    /// Maximum number of hot queries to execute during warming pass.
    pub max_warm_queries: usize,
    /// Maximum number of recent file chunks to pre-embed.
    pub max_warm_chunks: usize,
    /// Access tier to use for warming searches (default 1 = Internal).
    pub warm_tier: u8,
    /// Search candidate limit during warming (default 10).
    pub top_k: usize,
}

impl Default for WarmConfig {
    fn default() -> Self {
        Self {
            max_warm_queries: 50,
            max_warm_chunks: 500,
            warm_tier: 1,
            top_k: 10,
        }
    }
}

/// Telemetry metrics produced by a cache warming run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheWarmReport {
    /// Target epoch for which caches were primed.
    pub target_epoch: u64,
    /// Number of distinct chunk embeddings added to Level-2 / Embedding cache.
    pub warmed_embeddings: usize,
    /// Number of hot queries executed to prime Tantivy, LanceDB, and QueryCache.
    pub warmed_queries: usize,
    /// Total duration of the warming pass in milliseconds.
    pub duration_ms: u64,
}

/// Pre-warming supervisor.
pub struct CacheWarmer {
    storage: Arc<StorageEngine>,
    embedder: Arc<dyn EmbeddingGenerator>,
    dedup: Arc<TwoLevelDedupEngine>,
    config: WarmConfig,
}

impl CacheWarmer {
    pub fn new(
        storage: Arc<StorageEngine>,
        embedder: Arc<dyn EmbeddingGenerator>,
        dedup: Arc<TwoLevelDedupEngine>,
        config: WarmConfig,
    ) -> Self {
        Self {
            storage,
            embedder,
            dedup,
            config,
        }
    }

    /// Executes the full pre-warming routine:
    /// 1. Pre-warms hot chunk embeddings into Level-2 cache.
    /// 2. Executes search on canonical seed queries to warm LanceDB table pages & Tantivy readers.
    pub async fn warm_top_candidates(&self) -> CacheWarmReport {
        let start = Instant::now();
        let target_epoch = self.storage.index_epoch();
        let mut warmed_embeddings = 0;
        let mut warmed_queries = 0;

        // 1. Pre-warm Chunk Embeddings from Storage
        if let Ok(chunks) = self.storage.scan_all_chunks().await {
            let chunks_to_warm = chunks.into_iter().take(self.config.max_warm_chunks);
            for chunk in chunks_to_warm {
                if !self.dedup.cache().has_chunk(&chunk.blake3_hash) {
                    if !chunk.vector.is_empty() {
                        self.dedup.cache().insert(chunk.blake3_hash.clone(), chunk.vector.clone());
                        warmed_embeddings += 1;
                    } else if let Ok(vec) = self.embedder.embed_text(&chunk.text_content) {
                        self.dedup.cache().insert(chunk.blake3_hash.clone(), vec);
                        warmed_embeddings += 1;
                    }
                }
            }
        }

        // 2. Pre-warm Hot Canonical Search Queries
        let seed_queries = self.generate_seed_queries().await;
        for query in seed_queries.into_iter().take(self.config.max_warm_queries) {
            if let Ok(vec) = self.embedder.embed_text(&query) {
                // Execute hybrid search to prime Tantivy readers & LanceDB buffers
                let _ = self.storage.search_hybrid(
                    &query,
                    &vec,
                    self.config.warm_tier,
                    self.config.top_k,
                ).await;
                warmed_queries += 1;
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;

        CacheWarmReport {
            target_epoch,
            warmed_embeddings,
            warmed_queries,
            duration_ms,
        }
    }

    /// Synthesizes seed queries from active files and structural topics in the catalog.
    async fn generate_seed_queries(&self) -> Vec<String> {
        let tracked = self.dedup.get_all_tracked_files();
        let mut seeds = Vec::with_capacity(tracked.len() + 8);

        // Core structural queries
        seeds.push("overview of project architecture".to_string());
        seeds.push("main entrypoint and configuration".to_string());
        seeds.push("error handling and logging".to_string());
        seeds.push("api endpoints and handlers".to_string());

        // File-specific seed queries for top 10 tracked files
        for path in tracked.into_iter().take(10) {
            if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
                seeds.push(format!("how is {} implemented", file_name));
            }
        }

        seeds
    }
}
