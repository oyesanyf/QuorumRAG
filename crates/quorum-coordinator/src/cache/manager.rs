//! Unified CacheManager coordinating EmbeddingCache, QueryCache, atomic epochs,
//! and live telemetry for QuorumRAG.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quorum_contract::EmbeddingGenerator;
use quorum_storage::StorageEngine;
use quorum_types::{CacheTelemetry, RecacheResponse};
use crate::cache::embedding_cache::EmbeddingCache;
use crate::cache::query_cache::QueryCache;

pub struct CacheManager {
    pub query_cache: Arc<QueryCache>,
    pub embedding_cache: Arc<EmbeddingCache>,
    pub cache_epoch: Arc<AtomicU64>,
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new(1000, Duration::from_secs(3600), 10000, Duration::from_secs(86400))
    }
}

impl CacheManager {
    pub fn new(
        query_capacity: usize,
        query_ttl: Duration,
        embedding_capacity: usize,
        embedding_ttl: Duration,
    ) -> Self {
        Self {
            query_cache: Arc::new(QueryCache::new(query_capacity, query_ttl)),
            embedding_cache: Arc::new(EmbeddingCache::new(embedding_capacity, embedding_ttl)),
            cache_epoch: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Return current atomic cache epoch.
    #[inline]
    pub fn epoch(&self) -> u64 {
        self.cache_epoch.load(Ordering::SeqCst)
    }

    /// Set atomic cache epoch to a specific value.
    pub fn set_epoch(&self, epoch: u64) {
        self.cache_epoch.store(epoch, Ordering::SeqCst);
    }

    /// Advance epoch counter, immediately and atomically invalidating all prior QueryCache entries.
    pub fn advance_epoch(&self) -> u64 {
        self.cache_epoch.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Invalidate cache due to index changes, reindexing, or file watcher modification.
    pub fn invalidate(&self) -> u64 {
        let new_epoch = self.advance_epoch();
        self.query_cache.clear();
        new_epoch
    }

    /// Collect aggregated cache telemetry.
    pub fn telemetry(&self, latest_hit: bool) -> CacheTelemetry {
        let (q_hits, q_misses, q_count) = self.query_cache.stats();
        let (e_hits, e_misses, e_count) = self.embedding_cache.stats();
        let total_hits = q_hits.saturating_add(e_hits);
        let total_misses = q_misses.saturating_add(e_misses);
        let epoch = self.epoch();

        CacheTelemetry::new(
            latest_hit,
            total_hits,
            total_misses,
            q_count,
            e_count,
            epoch,
        )
    }

    /// Executes the full re-cache process: flushes stale caches, increments epoch,
    /// and optionally warms hot embeddings from storage.
    pub async fn recache(
        &self,
        storage: Option<&StorageEngine>,
        embedder: Option<&dyn EmbeddingGenerator>,
        clear: bool,
        warm: bool,
    ) -> RecacheResponse {
        let start = Instant::now();
        let mut cleared_entries = 0;
        let mut warmed_entries = 0;

        if clear {
            cleared_entries += self.query_cache.clear();
            cleared_entries += self.embedding_cache.clear();
        }

        let new_epoch = if let Some(storage_engine) = storage {
            storage_engine.bump_index_epoch("manual_recache").unwrap_or_else(|_| self.advance_epoch())
        } else {
            self.advance_epoch()
        };
        self.set_epoch(new_epoch);

        if warm {
            if let (Some(storage_engine), Some(embed_engine)) = (storage, embedder) {
                if let Ok(chunks) = storage_engine.get_all_chunks(100).await {
                    let contract_hash = embed_engine.contract_hash();
                    for chunk in chunks {
                        if self.embedding_cache.get(&contract_hash, &chunk.text_content).is_none() {
                            self.embedding_cache.insert(
                                &contract_hash,
                                &chunk.text_content,
                                chunk.vector,
                            );
                            warmed_entries += 1;
                        }
                    }
                }
            }
        }

        RecacheResponse {
            status: "ok".to_string(),
            cache_epoch: new_epoch,
            cleared_entries,
            warmed_entries,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }
}
