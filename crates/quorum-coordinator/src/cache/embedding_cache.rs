//! Thread-safe LRU/TTL dense vector cache for Gemma embeddings.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use crate::cache::key::derive_embedding_cache_key;

struct EmbeddingEntry {
    vector: Vec<f32>,
    created_at: Instant,
}

pub struct EmbeddingCache {
    capacity: usize,
    ttl: Duration,
    map: RwLock<HashMap<[u8; 32], EmbeddingEntry>>,
    order: RwLock<VecDeque<[u8; 32]>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl EmbeddingCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity: capacity.max(10),
            ttl,
            map: RwLock::new(HashMap::with_capacity(capacity.min(1000))),
            order: RwLock::new(VecDeque::with_capacity(capacity.min(1000))),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Retrieve a cached embedding vector if present and unexpired.
    pub fn get(&self, contract_hash: &[u8; 32], raw_text: &str) -> Option<Vec<f32>> {
        let key = derive_embedding_cache_key(contract_hash, raw_text);

        // Read phase
        {
            let map = self.map.read().ok()?;
            if let Some(entry) = map.get(&key) {
                if entry.created_at.elapsed() <= self.ttl {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(entry.vector.clone());
                }
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert or update an embedding vector with LRU capacity enforcement.
    pub fn insert(&self, contract_hash: &[u8; 32], raw_text: &str, vector: Vec<f32>) {
        let key = derive_embedding_cache_key(contract_hash, raw_text);
        let entry = EmbeddingEntry {
            vector,
            created_at: Instant::now(),
        };

        if let Ok(mut map) = self.map.write() {
            if let Ok(mut order) = self.order.write() {
                if !map.contains_key(&key) && map.len() >= self.capacity {
                    // Evict oldest
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

    /// Clear all cached vectors.
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
