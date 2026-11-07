//! Thread-safe LRU/TTL QueryCache holding candidate chunks, synthesis, citations,
//! and enforcing ZeroizeOnDrop zero-trust unpinned chunk security rules.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use quorum_storage::SearchMode;
use quorum_types::{Citation, ScoredChunk};
use crate::cache::key::derive_query_cache_key;
use crate::langextract::ConsensusExtractionResult;
use crate::types::SynthesisModelFamily;

/// Cached query payload holding retrieval candidates and synthesized response.
///
/// Implements `Drop` to explicitly zeroize plaintext in remote unpinned chunks
/// to prevent unpinned sensitive data from persisting in heap or swap memory.
#[derive(Clone)]
pub struct CachedQueryEntry {
    pub key: [u8; 32],
    pub chunks: Vec<ScoredChunk>,
    pub synthesis_prompt: String,
    pub synthesized_response: Option<String>,
    pub citations: Vec<Citation>,
    pub langextract_result: Option<ConsensusExtractionResult>,
    pub query_metadata_filters: Option<BTreeMap<String, String>>,
    pub access_tier: u8,
    pub index_epoch: u64,
    pub created_at: Instant,
    pub has_remote_unpinned: bool,
}

impl Drop for CachedQueryEntry {
    fn drop(&mut self) {
        // Enforce ZeroizeOnDrop zero-trust memory invariants:
        // When a cached query containing remote unpinned peer chunks is dropped or evicted,
        // explicitly wipe the chunk text buffers with zeroes.
        if self.has_remote_unpinned {
            for chunk in &mut self.chunks {
                if chunk.is_remote {
                    chunk.chunk.text_content.zeroize();
                }
            }
        }
    }
}

pub struct QueryCache {
    capacity: usize,
    ttl: Duration,
    map: RwLock<HashMap<[u8; 32], CachedQueryEntry>>,
    order: RwLock<VecDeque<[u8; 32]>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl QueryCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity: capacity.max(10),
            ttl,
            map: RwLock::new(HashMap::with_capacity(capacity.min(500))),
            order: RwLock::new(VecDeque::with_capacity(capacity.min(500))),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Probe the cache for an exact match under identical query, search mode,
    /// model family, access tier, and index epoch.
    pub fn get(
        &self,
        query: &str,
        search_mode: SearchMode,
        model_family: SynthesisModelFamily,
        access_tier: u8,
        index_epoch: u64,
    ) -> Option<CachedQueryEntry> {
        self.get_with_mesh_requirement(
            query,
            search_mode,
            model_family,
            access_tier,
            index_epoch,
            false,
        )
    }

    /// Probe the cache while optionally requiring at least one external mesh peer citation/chunk
    /// so local-only entries cached before LAN peers connected never mask live mesh results.
    pub fn get_with_mesh_requirement(
        &self,
        query: &str,
        search_mode: SearchMode,
        model_family: SynthesisModelFamily,
        access_tier: u8,
        index_epoch: u64,
        require_external_citation: bool,
    ) -> Option<CachedQueryEntry> {
        let key = derive_query_cache_key(query, search_mode, model_family, access_tier, index_epoch);

        {
            let map = self.map.read().ok()?;
            if let Some(entry) = map.get(&key) {
                let mesh_ok = !require_external_citation
                    || entry.citations.iter().any(|c| c.is_external_node)
                    || entry.chunks.iter().any(|c| c.is_remote);
                // Assert epoch consistency, TTL freshness, and mesh coverage
                if entry.index_epoch == index_epoch
                    && entry.created_at.elapsed() <= self.ttl
                    && mesh_ok
                {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(entry.clone());
                }
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Store query result into cache, evicting oldest entries on capacity limit.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &self,
        query: &str,
        search_mode: SearchMode,
        model_family: SynthesisModelFamily,
        access_tier: u8,
        index_epoch: u64,
        chunks: Vec<ScoredChunk>,
        synthesis_prompt: String,
        synthesized_response: Option<String>,
        citations: Vec<Citation>,
        langextract_result: Option<ConsensusExtractionResult>,
        query_metadata_filters: Option<BTreeMap<String, String>>,
    ) {
        let key = derive_query_cache_key(query, search_mode, model_family, access_tier, index_epoch);
        let has_remote_unpinned = chunks.iter().any(|c| c.is_remote);

        let entry = CachedQueryEntry {
            key,
            chunks,
            synthesis_prompt,
            synthesized_response,
            citations,
            langextract_result,
            query_metadata_filters,
            access_tier,
            index_epoch,
            created_at: Instant::now(),
            has_remote_unpinned,
        };

        if let Ok(mut map) = self.map.write() {
            if let Ok(mut order) = self.order.write() {
                if !map.contains_key(&key) && map.len() >= self.capacity {
                    while let Some(old_key) = order.pop_front() {
                        if map.remove(&old_key).is_some() {
                            break;
                        }
                    }
                }
                map.insert(key, entry);
                order.push_back(key);
            }
        }
    }

    /// Clear all query cache entries immediately.
    pub fn clear(&self) -> usize {
        let mut count = 0;
        if let Ok(mut map) = self.map.write() {
            count = map.len();
            map.clear();
        }
        if let Ok(mut order) = self.order.write() {
            order.clear();
        }
        count
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let count = self.map.read().map(|m| m.len()).unwrap_or(0);
        (hits, misses, count)
    }
}
