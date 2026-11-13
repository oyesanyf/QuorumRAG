//! StorageEngine providing unified vector storage, Tantivy BM25, and hybrid RRF search.
//!
//! # Invariant: Absolute Arrow Isolation
//! All Apache Arrow, LanceDB, and Tantivy types are strictly private.
//! Callers interact solely with pure domain types (`DocumentChunk`, `ScoredChunk`, `StorageError`).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use quorum_types::{DocumentChunk, ScoredChunk};
use serde::{Deserialize, Serialize};

use crate::config::StorageConfig;
use crate::document_catalog::{DocumentCatalog, DocumentCatalogEntry};
use crate::error::StorageError;
use crate::tantivy_fts::{DistinctWorkHit, TantivyFtsIndex};
use crate::vector_store::VectorStore;

/// Search execution mode for storage queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchMode {
    /// Tantivy BM25 lexical / keyword search.
    Keyword,
    /// LanceDB dense vector similarity search.
    Vector,
    /// Combined BM25 + Vector with Reciprocal Rank Fusion.
    Hybrid,
}

/// Unified query descriptor for `StorageEngine::search`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageSearchQuery {
    /// Execution mode.
    pub mode: SearchMode,
    /// Text query string for Keyword or Hybrid search.
    pub text: Option<String>,
    /// Dense query vector for Vector or Hybrid search.
    pub vector: Option<Vec<f32>>,
    /// Upper bound on authorized access tier (0=Public..3=Restricted).
    pub max_tier: u8,
    /// Maximum number of top candidate chunks to return.
    pub top_k: usize,
    /// Optional chunk IDs to exclude (negative filter) from retrieval candidates.
    #[serde(default)]
    pub exclude_chunk_ids: Vec<String>,
}

impl StorageSearchQuery {
    /// Creates a vector similarity search query.
    pub fn vector(vector: Vec<f32>, max_tier: u8, top_k: usize) -> Self {
        Self {
            mode: SearchMode::Vector,
            text: None,
            vector: Some(vector),
            max_tier,
            top_k,
            exclude_chunk_ids: Vec::new(),
        }
    }

    /// Creates a Tantivy BM25 keyword search query.
    pub fn keyword(text: impl Into<String>, max_tier: u8, top_k: usize) -> Self {
        Self {
            mode: SearchMode::Keyword,
            text: Some(text.into()),
            vector: None,
            max_tier,
            top_k,
            exclude_chunk_ids: Vec::new(),
        }
    }

    /// Creates a hybrid (Vector + BM25 + RRF) search query.
    pub fn hybrid(text: impl Into<String>, vector: Vec<f32>, max_tier: u8, top_k: usize) -> Self {
        Self {
            mode: SearchMode::Hybrid,
            text: Some(text.into()),
            vector: Some(vector),
            max_tier,
            top_k,
            exclude_chunk_ids: Vec::new(),
        }
    }

    /// Attaches an exclusion list of chunk IDs to skip during search.
    pub fn with_exclusion(mut self, exclude: Vec<String>) -> Self {
        self.exclude_chunk_ids = exclude;
        self
    }
}

/// Results and metrics from storage compaction.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionStats {
    /// Number of small Lance parquet fragments consolidated.
    pub fragments_removed: usize,
    /// Number of consolidated fragments generated.
    pub fragments_added: usize,
    /// Number of obsolete version snapshots cleaned up.
    pub old_versions_pruned: usize,
    /// Whether Tantivy segments were merged.
    pub tantivy_segments_merged: bool,
}

/// Persistent storage metadata for cache coherence and index synchronization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageMetadata {
    /// Monotonically increasing epoch counter for cache coherence.
    pub index_epoch: u64,
    /// UTC timestamp of the last epoch modification.
    pub last_epoch_bump_utc: DateTime<Utc>,
    /// Source of the last bump ("init", "reindex", "drift_healer", "watcher", "recache").
    pub last_bump_reason: String,
    /// Cumulative count of write/delete transactions committed.
    pub mutation_count: u64,
}

impl Default for StorageMetadata {
    fn default() -> Self {
        Self {
            index_epoch: 1,
            last_epoch_bump_utc: Utc::now(),
            last_bump_reason: "init".to_string(),
            mutation_count: 0,
        }
    }
}

/// Production-grade embedded storage engine for QuorumRAG.
pub struct StorageEngine {
    config: StorageConfig,
    vector_store: Arc<VectorStore>,
    fts_index: Arc<TantivyFtsIndex>,
    catalog: Arc<DocumentCatalog>,
    index_epoch: Arc<AtomicU64>,
    metadata_lock: Arc<Mutex<StorageMetadata>>,
    is_neural: Arc<AtomicBool>,
}

impl StorageEngine {
    /// Opens or creates the embedded LanceDB vector table, co-located Tantivy FTS index, and SQLite document catalog.
    pub async fn open(config: impl Into<StorageConfig>) -> Result<Self, StorageError> {
        let cfg = config.into();
        let vector_store = Arc::new(VectorStore::open(&cfg).await?);
        let fts_index = Arc::new(TantivyFtsIndex::open(&cfg.tantivy_path())?);
        let catalog = Arc::new(DocumentCatalog::open(&cfg.document_catalog_path())?);

        // Load or initialize metadata
        let meta_path = cfg.metadata_path();
        let metadata = if meta_path.exists() {
            match std::fs::read_to_string(&meta_path) {
                Ok(content) => serde_json::from_str::<StorageMetadata>(&content).unwrap_or_default(),
                Err(_) => StorageMetadata::default(),
            }
        } else {
            let default_meta = StorageMetadata::default();
            let _ = std::fs::create_dir_all(&cfg.storage_path);
            if let Ok(content) = serde_json::to_string_pretty(&default_meta) {
                let _ = std::fs::write(&meta_path, content);
            }
            default_meta
        };

        let index_epoch = Arc::new(AtomicU64::new(metadata.index_epoch));
        let metadata_lock = Arc::new(Mutex::new(metadata));
        let is_neural = Arc::new(AtomicBool::new(false));

        Ok(Self {
            config: cfg,
            vector_store,
            fts_index,
            catalog,
            index_epoch,
            metadata_lock,
            is_neural,
        })
    }

    /// Returns the active index epoch for deterministic query cache key derivation.
    /// Fast lock-free atomic load: ~10ns.
    #[inline]
    pub fn index_epoch(&self) -> u64 {
        self.index_epoch.load(Ordering::Acquire)
    }

    /// Atomically increments the index epoch, persists metadata to disk, and returns the new epoch.
    pub fn bump_index_epoch(&self, reason: &str) -> Result<u64, StorageError> {
        let mut meta = self.metadata_lock.lock();
        let new_epoch = self.index_epoch.fetch_add(1, Ordering::SeqCst) + 1;
        meta.index_epoch = new_epoch;
        meta.last_epoch_bump_utc = chrono::Utc::now();
        meta.last_bump_reason = reason.to_string();
        meta.mutation_count = meta.mutation_count.saturating_add(1);

        self.persist_metadata(&meta)?;

        tracing::info!(
            epoch = new_epoch,
            reason = reason,
            "Storage index_epoch incremented"
        );

        Ok(new_epoch)
    }

    /// Explicitly resets or sets the index epoch (used during recache with clear).
    pub fn set_index_epoch(&self, epoch: u64, reason: &str) -> Result<u64, StorageError> {
        let mut meta = self.metadata_lock.lock();
        self.index_epoch.store(epoch, Ordering::SeqCst);
        meta.index_epoch = epoch;
        meta.last_epoch_bump_utc = chrono::Utc::now();
        meta.last_bump_reason = reason.to_string();

        self.persist_metadata(&meta)?;

        tracing::info!(
            epoch = epoch,
            reason = reason,
            "Storage index_epoch explicitly set"
        );

        Ok(epoch)
    }

    /// Returns current storage metadata snapshot.
    pub fn metadata(&self) -> StorageMetadata {
        self.metadata_lock.lock().clone()
    }

    /// Atomically writes metadata using atomic replace semantics.
    fn persist_metadata(&self, meta: &StorageMetadata) -> Result<(), StorageError> {
        let path = self.config.metadata_path();
        let tmp_path = path.with_extension("tmp");

        let content = serde_json::to_string_pretty(meta).map_err(|e| {
            StorageError::Io {
                path: path.clone(),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            }
        })?;

        std::fs::write(&tmp_path, content).map_err(|e| StorageError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;

        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
        std::fs::rename(&tmp_path, &path).map_err(|e| StorageError::Io {
            path: path.clone(),
            source: e,
        })?;

        Ok(())
    }

    /// Inserts document chunks with automatic per-document chunk_id deduplication.
    pub async fn insert_chunks(&self, chunks: &[DocumentChunk]) -> Result<usize, StorageError> {
        if chunks.is_empty() {
            return Ok(0);
        }

        let mut unique_chunks: Vec<DocumentChunk> = Vec::with_capacity(chunks.len());
        let mut seen_chunk_ids: HashSet<String> = HashSet::with_capacity(chunks.len());

        for chunk in chunks {
            if seen_chunk_ids.contains(&chunk.chunk_id) {
                continue;
            }
            if self.fts_index.has_chunk_id(&chunk.chunk_id).unwrap_or(false) {
                continue;
            }
            seen_chunk_ids.insert(chunk.chunk_id.clone());
            unique_chunks.push(chunk.clone());
        }

        if unique_chunks.is_empty() {
            return Ok(0);
        }

        let count = self.vector_store.insert_chunks(&unique_chunks).await?;
        let fts_for_write = Arc::clone(&self.fts_index);
        let chunks_for_fts = unique_chunks.clone();
        let _ = tokio::task::spawn_blocking(move || fts_for_write.index_chunks(&chunks_for_fts))
            .await
            .map_err(|e| StorageError::Tantivy(format!("Tantivy index blocking task failed: {e}")))??;

        // Automatically hydrate document catalog for ingested files
        let _ = self.catalog.hydrate_from_chunks(&unique_chunks);

        Ok(count)
    }

    /// Dense vector ANN search with access-tier SQL pre-filtering (bounded to 450ms for low-latency responsiveness).
    pub async fn search_vector(
        &self,
        vector: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Result<Vec<ScoredChunk>, StorageError> {
        match tokio::time::timeout(
            std::time::Duration::from_millis(450),
            self.vector_store.search_vector(vector, max_tier, top_k),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Tantivy BM25 keyword search with access-tier filtering.
    pub async fn search_text(
        &self,
        query: &str,
        max_tier: u8,
        top_k: usize,
    ) -> Result<Vec<ScoredChunk>, StorageError> {
        let fts = Arc::clone(&self.fts_index);
        let q = query.to_string();
        let mut hits = tokio::task::spawn_blocking(move || fts.search(&q, max_tier, top_k))
            .await
            .map_err(|e| StorageError::Tantivy(format!("Tantivy search blocking task failed: {e}")))??;
        prioritize_media_intent(query, &mut hits);
        prioritize_forensic_intent(query, &mut hits);
        Ok(hits)
    }

    /// Hybrid search combining vector search and BM25 full-text search with negative chunk exclusion filtering.
    /// Skips chunks in `exclude_chunk_ids` while allowing unseen chunks from the same document.
    pub async fn search_hybrid_with_exclusion(
        &self,
        text: &str,
        vector: &[f32],
        max_tier: u8,
        top_k: usize,
        exclude_chunk_ids: &[String],
    ) -> Result<Vec<ScoredChunk>, StorageError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }

        let exclude_set: HashSet<&str> = exclude_chunk_ids.iter().map(|s| s.as_str()).collect();
        let candidate_limit = (top_k + exclude_chunk_ids.len()).saturating_mul(2).clamp(16, 256);
        let (text_hits, vector_hits) = if !vector.is_empty() && vector.iter().any(|&v| v != 0.0) {
            let (text_res, vector_res) = tokio::join!(
                self.search_text(text, max_tier, candidate_limit),
                self.search_vector(vector, max_tier, candidate_limit),
            );
            (text_res?, vector_res.unwrap_or_default())
        } else {
            (self.search_text(text, max_tier, candidate_limit).await?, Vec::new())
        };

        let mut rrf_map: HashMap<String, (f32, DocumentChunk)> = HashMap::new();

        // Only include vector hits that have positive cosine similarity and are not excluded
        let relevant_vector_hits: Vec<ScoredChunk> = vector_hits
            .into_iter()
            .filter(|s| s.score > 0.0 && !exclude_set.contains(s.chunk.chunk_id.as_str()))
            .collect();

        let (text_weight, vector_weight) = if self.is_neural() {
            (1.0f32, 1.0f32)
        } else {
            (1.0f32, 0.05f32)
        };

        let mut current_rank = 1;
        for (i, scored) in relevant_vector_hits.iter().enumerate() {
            if i > 0 && (scored.score - relevant_vector_hits[i - 1].score).abs() > 1e-6 {
                current_rank = i + 1;
            }
            let rrf = vector_weight / (60.0 + current_rank as f32);
            let entry = rrf_map
                .entry(scored.chunk.chunk_id.clone())
                .or_insert((0.0, scored.chunk.clone()));
            entry.0 += rrf;
        }

        // Only include text hits with positive scores and not excluded
        let relevant_text_hits: Vec<ScoredChunk> = text_hits
            .into_iter()
            .filter(|s| s.score > 0.0 && !exclude_set.contains(s.chunk.chunk_id.as_str()))
            .collect();

        let mut current_rank = 1;
        for (i, scored) in relevant_text_hits.iter().enumerate() {
            if i > 0 && (scored.score - relevant_text_hits[i - 1].score).abs() > 1e-6 {
                current_rank = i + 1;
            }
            let rrf = text_weight / (60.0 + current_rank as f32);
            let entry = rrf_map
                .entry(scored.chunk.chunk_id.clone())
                .or_insert((0.0, scored.chunk.clone()));
            entry.0 += rrf;
        }

        let mut combined: Vec<ScoredChunk> = rrf_map
            .into_iter()
            .map(|(_id, (score, chunk))| ScoredChunk::new(chunk, score, "local", false))
            .collect();

        combined.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.chunk.chunk_id.cmp(&b.chunk.chunk_id))
                .then_with(|| a.chunk.blake3_hash.cmp(&b.chunk.blake3_hash))
        });
        prioritize_media_intent(text, &mut combined);
        prioritize_forensic_intent(text, &mut combined);
        combined.truncate(top_k);

        Ok(combined)
    }

    /// Exposes standalone Reciprocal Rank Fusion ($k=60.0$) combining dense and sparse hits.
    pub fn reciprocal_rank_fusion(
        vector_hits: Vec<ScoredChunk>,
        text_hits: Vec<ScoredChunk>,
        k: f32,
        dense_weight: f32,
        sparse_weight: f32,
        exclude_chunk_ids: &[String],
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let exclude_set: HashSet<&str> = exclude_chunk_ids.iter().map(|s| s.as_str()).collect();
        let mut rrf_map: HashMap<String, (f32, DocumentChunk)> = HashMap::new();

        let mut current_rank = 1;
        for (i, scored) in vector_hits.iter().enumerate() {
            if exclude_set.contains(scored.chunk.chunk_id.as_str()) {
                continue;
            }
            if i > 0 && (scored.score - vector_hits[i - 1].score).abs() > 1e-6 {
                current_rank = i + 1;
            }
            let rrf = dense_weight / (k + current_rank as f32);
            let entry = rrf_map
                .entry(scored.chunk.chunk_id.clone())
                .or_insert_with(|| (0.0, scored.chunk.clone()));
            entry.0 += rrf;
        }

        let mut current_rank = 1;
        for (i, scored) in text_hits.iter().enumerate() {
            if exclude_set.contains(scored.chunk.chunk_id.as_str()) {
                continue;
            }
            if i > 0 && (scored.score - text_hits[i - 1].score).abs() > 1e-6 {
                current_rank = i + 1;
            }
            let rrf = sparse_weight / (k + current_rank as f32);
            let entry = rrf_map
                .entry(scored.chunk.chunk_id.clone())
                .or_insert_with(|| (0.0, scored.chunk.clone()));
            entry.0 += rrf;
        }

        let mut combined: Vec<ScoredChunk> = rrf_map
            .into_iter()
            .map(|(_id, (score, chunk))| ScoredChunk::new(chunk, score, "local", false))
            .collect();

        combined.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.chunk.chunk_id.cmp(&b.chunk.chunk_id))
                .then_with(|| a.chunk.blake3_hash.cmp(&b.chunk.blake3_hash))
        });

        combined.truncate(top_k);
        combined
    }

    /// Hybrid search combining vector search and BM25 full-text search via Reciprocal Rank Fusion (RRF).
    pub async fn search_hybrid(
        &self,
        text: &str,
        vector: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Result<Vec<ScoredChunk>, StorageError> {
        self.search_hybrid_with_exclusion(text, vector, max_tier, top_k, &[]).await
    }

    /// Unified search dispatcher switching on `SearchMode`.
    pub async fn search(&self, query: &StorageSearchQuery) -> Result<Vec<ScoredChunk>, StorageError> {
        match query.mode {
            SearchMode::Vector => {
                let vec = query.vector.as_deref().ok_or_else(|| {
                    StorageError::InvalidQuery("Vector search mode requires query.vector".into())
                })?;
                let mut hits = self.search_vector(vec, query.max_tier, query.top_k + query.exclude_chunk_ids.len()).await?;
                if !query.exclude_chunk_ids.is_empty() {
                    let exclude_set: HashSet<&str> = query.exclude_chunk_ids.iter().map(|s| s.as_str()).collect();
                    hits.retain(|h| !exclude_set.contains(h.chunk.chunk_id.as_str()));
                    hits.truncate(query.top_k);
                }
                Ok(hits)
            }
            SearchMode::Keyword => {
                let text = query.text.as_deref().ok_or_else(|| {
                    StorageError::InvalidQuery("Keyword search mode requires query.text".into())
                })?;
                let mut hits = self.search_text(text, query.max_tier, query.top_k + query.exclude_chunk_ids.len()).await?;
                if !query.exclude_chunk_ids.is_empty() {
                    let exclude_set: HashSet<&str> = query.exclude_chunk_ids.iter().map(|s| s.as_str()).collect();
                    hits.retain(|h| !exclude_set.contains(h.chunk.chunk_id.as_str()));
                    hits.truncate(query.top_k);
                }
                Ok(hits)
            }
            SearchMode::Hybrid => {
                let text = query.text.as_deref().unwrap_or("");
                let empty_vec = vec![0.0; self.config.vector_dimension];
                let vec = query.vector.as_deref().unwrap_or(&empty_vec);
                if query.exclude_chunk_ids.is_empty() {
                    self.search_hybrid(text, vec, query.max_tier, query.top_k).await
                } else {
                    self.search_hybrid_with_exclusion(text, vec, query.max_tier, query.top_k, &query.exclude_chunk_ids).await
                }
            }
        }
    }

    /// Lowest access tier of chunks indexed for exactly this `file_path`, or `None` if unindexed.
    /// Used to gate media streaming so only indexed files can ever be served.
    pub fn indexed_path_min_tier(&self, file_path: &str) -> Result<Option<u8>, StorageError> {
        self.fts_index.indexed_path_min_tier(file_path)
    }

    /// Checks if a chunk's BLAKE3 hash already exists in storage.
    pub async fn has_chunk_hash(&self, blake3_hash: &str) -> Result<bool, StorageError> {
        if self.fts_index.has_chunk_hash(blake3_hash)? {
            return Ok(true);
        }
        self.vector_store.has_chunk_hash(blake3_hash).await
    }

    /// Checks if a chunk's ID already exists in storage (Tantivy BM25 inverted index fast path, falling back to LanceDB).
    pub async fn has_chunk_id(&self, chunk_id: &str) -> Result<bool, StorageError> {
        if self.fts_index.has_chunk_id(chunk_id)? {
            return Ok(true);
        }
        self.vector_store.has_chunk_id(chunk_id).await
    }

    /// Lists all file identities stored in the SQLite Document Catalog for fast startup hydration.
    pub fn list_catalog_file_identities(&self) -> Result<Vec<crate::document_catalog::CatalogFileIdentity>, StorageError> {
        self.catalog.list_all_file_identities()
    }

    /// Deletes all chunks matching the specified source `file_path`.
    pub async fn delete_by_file_path(&self, file_path: &str) -> Result<usize, StorageError> {
        let lance_deleted = self.vector_store.delete_by_file_path(file_path).await?;
        let tantivy_deleted = self.fts_index.delete_by_file_path(file_path)?;
        let _ = self.catalog.delete_by_file_path(file_path);
        Ok(lance_deleted.max(tantivy_deleted))
    }

    /// Removes existing chunks for several files at once (used before re-inserting re-indexed files,
    /// so a reindex replaces stale chunks instead of duplicating them).
    pub async fn delete_by_file_paths(&self, file_paths: &[String]) -> Result<(), StorageError> {
        if file_paths.is_empty() {
            return Ok(());
        }
        let existing_paths: Vec<String> = file_paths
            .iter()
            .filter(|p| self.fts_index.has_file_path(p))
            .cloned()
            .collect();
        if existing_paths.is_empty() {
            return Ok(());
        }
        self.vector_store.delete_by_file_paths(&existing_paths).await?;
        for p in &existing_paths {
            let _ = self.fts_index.delete_by_file_path(p);
            let _ = self.catalog.delete_by_file_path(p);
        }
        Ok(())
    }

    /// O(1) check whether `chunk_id` is already indexed in Tantivy.
    pub fn has_chunk_id_in_fts(&self, chunk_id: &str) -> bool {
        self.fts_index.has_chunk_id(chunk_id).unwrap_or(false)
    }

    /// Fast FST dictionary scan of all unique `file_path` strings currently indexed in Tantivy.
    pub fn list_indexed_file_paths_in_fts(&self) -> HashSet<String> {
        self.fts_index.list_indexed_file_paths()
    }

    /// Performs maintenance: compacts small Lance files, cleans up older snapshots, and merges Tantivy segments.
    pub async fn compact(&self) -> Result<CompactionStats, StorageError> {
        let (frags_rem, frags_add, versions_pruned) = self
            .vector_store
            .optimize()
            .await
            .unwrap_or((0, 0, 0));

        let fts = Arc::clone(&self.fts_index);
        let fts_res = tokio::task::spawn_blocking(move || fts.compact())
            .await
            .map_err(|e| StorageError::Tantivy(format!("Tantivy compact blocking task failed: {e}")))
            .and_then(|r| r);

        Ok(CompactionStats {
            fragments_removed: frags_rem,
            fragments_added: frags_add,
            old_versions_pruned: versions_pruned,
            tantivy_segments_merged: fts_res.is_ok(),
        })
    }

    /// Total number of stored chunks.
    pub async fn count(&self) -> Result<usize, StorageError> {
        self.vector_store.count().await
    }

    /// Whether storage is currently empty.
    pub async fn is_empty(&self) -> Result<bool, StorageError> {
        Ok(self.count().await? == 0)
    }

    /// Clones configuration options.
    pub fn config(&self) -> &StorageConfig {
        &self.config
    }

    /// Returns all chunks stored in LanceDB.
    pub async fn scan_all_chunks(&self) -> Result<Vec<DocumentChunk>, StorageError> {
        self.vector_store.scan_all_chunks().await
    }

    /// Returns up to `limit` chunks stored in LanceDB.
    pub async fn get_all_chunks(&self, limit: usize) -> Result<Vec<DocumentChunk>, StorageError> {
        let chunks = self.vector_store.scan_all_chunks().await?;
        if chunks.len() > limit {
            Ok(chunks.into_iter().take(limit).collect())
        } else {
            Ok(chunks)
        }
    }

    /// Returns a map of `chunk_id -> blake3_hash` for all chunks in LanceDB.
    pub async fn get_lance_chunk_catalog(&self) -> Result<HashMap<String, String>, StorageError> {
        let chunks = self.vector_store.scan_all_chunks().await?;
        let mut map = HashMap::with_capacity(chunks.len());
        for chunk in chunks {
            map.insert(chunk.chunk_id, chunk.blake3_hash);
        }
        Ok(map)
    }

    /// Returns a map of `chunk_id -> blake3_hash` for all chunks in Tantivy.
    pub fn get_tantivy_chunk_catalog(&self) -> Result<HashMap<String, String>, StorageError> {
        let chunks = self.fts_index.scan_all_chunks()?;
        let mut map = HashMap::with_capacity(chunks.len());
        for chunk in chunks {
            map.insert(chunk.chunk_id, chunk.blake3_hash);
        }
        Ok(map)
    }

    /// Retrieves specific chunks by their IDs via point lookups.
    ///
    /// Queries the Tantivy BM25 inverted index first for sub-millisecond point lookup,
    /// and only falls back to LanceDB predicate pushdown for any chunk IDs not found in Tantivy.
    pub async fn get_chunks_by_ids(&self, chunk_ids: &[String]) -> Result<Vec<DocumentChunk>, StorageError> {
        if chunk_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Fast path: query Tantivy inverted index (sub-millisecond O(K) lookup)
        let fts = Arc::clone(&self.fts_index);
        let ids_owned = chunk_ids.to_vec();
        let mut chunks = tokio::task::spawn_blocking(move || fts.get_chunks_by_ids(&ids_owned, true))
            .await
            .map_err(|e| StorageError::Tantivy(format!("Tantivy point-lookup blocking task failed: {e}")))??;
        if chunks.len() >= chunk_ids.len() {
            return Ok(chunks);
        }

        // Check which chunk IDs are missing from Tantivy (e.g. drift or Lance-only records)
        let found_ids: HashSet<&str> = chunks.iter().map(|c| c.chunk_id.as_str()).collect();
        let missing_ids: Vec<String> = chunk_ids
            .iter()
            .filter(|id| !found_ids.contains(id.as_str()))
            .cloned()
            .collect();

        if !missing_ids.is_empty() {
            let lance_chunks = self.vector_store.get_chunks_by_ids(&missing_ids).await?;
            chunks.extend(lance_chunks);
        }

        Ok(chunks)
    }

    /// Retrieves specific chunks from Tantivy by their IDs via inverted-index point lookup.
    pub fn get_chunks_from_tantivy(&self, chunk_ids: &[String]) -> Result<Vec<DocumentChunk>, StorageError> {
        self.fts_index.get_chunks_by_ids(chunk_ids, true)
    }

    /// Inserts chunks exclusively into LanceDB (used during Tantivy -> LanceDB drift repair).
    pub async fn insert_into_lance_only(&self, chunks: &[DocumentChunk]) -> Result<usize, StorageError> {
        self.vector_store.insert_chunks(chunks).await
    }

    /// Inserts chunks exclusively into Tantivy (used during LanceDB -> Tantivy drift repair).
    pub fn insert_into_tantivy_only(&self, chunks: &[DocumentChunk]) -> Result<usize, StorageError> {
        self.fts_index.index_chunks(chunks)
    }

    /// Updates or replaces a single chunk record across both LanceDB and Tantivy.
    pub async fn update_chunk_record(&self, chunk: &DocumentChunk) -> Result<(), StorageError> {
        let _ = self.vector_store.delete_by_chunk_id(&chunk.chunk_id).await?;
        let _ = self.fts_index.delete_by_chunk_id(&chunk.chunk_id)?;
        self.vector_store.insert_chunks(std::slice::from_ref(chunk)).await?;
        self.fts_index.index_chunks(std::slice::from_ref(chunk))?;
        Ok(())
    }

    /// Updates the access_tier of an existing chunk atomically across both stores.
    pub async fn update_chunk_access_tier(&self, chunk_id: &str, new_tier: u8) -> Result<(), StorageError> {
        let chunks = self.get_chunks_by_ids(&[chunk_id.to_string()]).await?;
        if let Some(mut chunk) = chunks.into_iter().next() {
            chunk.access_tier = new_tier;
            self.update_chunk_record(&chunk).await?;
        }
        Ok(())
    }

    /// Deletes a chunk by its chunk_id across both stores.
    pub async fn delete_by_chunk_id(&self, chunk_id: &str) -> Result<usize, StorageError> {
        let l = self.vector_store.delete_by_chunk_id(chunk_id).await?;
        let t = self.fts_index.delete_by_chunk_id(chunk_id)?;
        Ok(l.max(t))
    }

    /// Reference to the SQLite Document Catalog.
    pub fn catalog(&self) -> &DocumentCatalog {
        &self.catalog
    }

    /// Fast scan of all stored chunks without decoding vector_bytes.
    pub fn scan_all_chunks_fast(&self) -> Result<Vec<DocumentChunk>, StorageError> {
        self.fts_index.scan_all_chunks_fast()
    }

    /// Sets whether the active embedding engine is neural (vs deterministic offline).
    pub fn set_neural_engine(&self, neural: bool) {
        self.is_neural.store(neural, Ordering::Release);
    }

    /// Whether the active embedding engine is neural.
    pub fn is_neural(&self) -> bool {
        self.is_neural.load(Ordering::Acquire)
    }

    /// Enumerates distinct works from Tantivy BM25 collapsed by work_cluster_id.
    pub fn enumerate_distinct_works(
        &self,
        query_text: &str,
        max_tier: u8,
        max_hits: usize,
    ) -> Result<Vec<DistinctWorkHit>, StorageError> {
        self.fts_index.enumerate_distinct_works(query_text, max_tier, max_hits)
    }

    /// Finds documents in the SQLite Document Catalog matching a query.
    pub fn catalog_find_documents(&self, query: &str, limit: usize) -> Result<Vec<DocumentCatalogEntry>, StorageError> {
        self.catalog.catalog_find_documents(query, limit)
    }

    /// Extended document search in the SQLite Document Catalog with kind filter.
    pub fn catalog_find_documents_extended(
        &self,
        query: &str,
        doc_kinds: Option<&[&str]>,
        max_tier: u8,
        limit: usize,
    ) -> Result<Vec<DocumentCatalogEntry>, StorageError> {
        self.catalog.catalog_find_documents_extended(query, doc_kinds, max_tier, limit)
    }

    /// Hydrates the SQLite Document Catalog from stored chunks if empty.
    pub async fn hydrate_document_catalog_if_needed(&self) -> Result<usize, StorageError> {
        self.catalog.hydrate_document_catalog_if_needed(self)
    }

    /// Optimizes LanceDB indices specifically.
    pub async fn optimize_indices(&self) -> Result<(), StorageError> {
        self.vector_store.optimize_indices().await
    }

    /// Persists a full unchunked parent document record alongside chunk indices.
    pub fn upsert_parent_document(
        &self,
        doc: &quorum_types::IngestedParentDocument,
        access_tier: u8,
    ) -> Result<(), StorageError> {
        self.catalog.upsert_parent_document(doc, access_tier)
    }

    /// Loads an authorized full parent document by `document_id` or `file_path`.
    /// If the document was indexed prior to v0.6.3 and has no cached row in `parent_documents`,
    /// automatically reconstructs the ordered full parent text from Tantivy chunks and caches it.
    pub fn load_parent_document(
        &self,
        doc_id_or_path: &str,
        max_tier: u8,
    ) -> Result<Option<quorum_types::IngestedParentDocument>, StorageError> {
        if let Some((doc, tier)) = self.catalog.get_parent_document(doc_id_or_path)? {
            if tier <= max_tier {
                return Ok(Some(doc));
            }
            return Ok(None);
        }

        if let Some((reconstructed, tier)) = self.fts_index.reconstruct_parent_document(doc_id_or_path)? {
            let _ = self.catalog.upsert_parent_document(&reconstructed, tier);
            if tier <= max_tier {
                return Ok(Some(reconstructed));
            }
        }
        Ok(None)
    }

    /// RLM environment action: reads a UTF-8 character-boundary-safe byte slice `[start_byte..end_byte]`
    /// from the full parent document (clamped to 32 KiB per slice).
    pub fn peek_slice(
        &self,
        doc_id_or_path: &str,
        start_byte: usize,
        end_byte: usize,
        max_tier: u8,
    ) -> Result<Option<String>, StorageError> {
        const MAX_SLICE_BYTES: usize = 32_768;
        let Some(doc) = self.load_parent_document(doc_id_or_path, max_tier)? else {
            return Ok(None);
        };
        let text = &doc.full_text;
        if text.is_empty() {
            return Ok(Some(String::new()));
        }

        let mut safe_start = start_byte.min(text.len());
        while safe_start > 0 && !text.is_char_boundary(safe_start) {
            safe_start -= 1;
        }
        let requested_end = end_byte.max(safe_start).min(safe_start.saturating_add(MAX_SLICE_BYTES));
        let mut safe_end = requested_end.min(text.len());
        while safe_end < text.len() && !text.is_char_boundary(safe_end) {
            safe_end += 1;
        }
        Ok(Some(text[safe_start..safe_end].to_string()))
    }

    /// RLM environment action: executes a bounded, DFA-limited case-insensitive regex grep
    /// across the full parent document and returns byte spans plus surrounding context windows.
    pub fn regex_grep(
        &self,
        doc_id_or_path: &str,
        pattern: &str,
        max_matches: usize,
        max_tier: u8,
    ) -> Result<Vec<quorum_types::RegexMatchSpan>, StorageError> {
        let trimmed_pat = pattern.trim();
        if trimmed_pat.is_empty() {
            return Ok(Vec::new());
        }
        let Some(doc) = self.load_parent_document(doc_id_or_path, max_tier)? else {
            return Ok(Vec::new());
        };

        let compiled = regex::RegexBuilder::new(trimmed_pat)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 20)
            .build()
            .or_else(|_| {
                regex::RegexBuilder::new(&regex::escape(trimmed_pat))
                    .case_insensitive(true)
                    .size_limit(1 << 20)
                    .dfa_size_limit(1 << 20)
                    .build()
            })
            .map_err(|e| StorageError::InvalidQuery(format!("Invalid RLM regex '{}': {}", trimmed_pat, e)))?;

        let cap = max_matches.clamp(1, 64);
        let text = &doc.full_text;
        let mut spans = Vec::new();
        for m in compiled.find_iter(text).take(cap) {
            let mut ctx_start = m.start().saturating_sub(240);
            while ctx_start > 0 && !text.is_char_boundary(ctx_start) {
                ctx_start -= 1;
            }
            let mut ctx_end = (m.end() + 240).min(text.len());
            while ctx_end < text.len() && !text.is_char_boundary(ctx_end) {
                ctx_end += 1;
            }
            spans.push(quorum_types::RegexMatchSpan {
                doc_id: doc.doc_id.clone(),
                source_path: doc.source_path.clone(),
                start_byte: m.start(),
                end_byte: m.end(),
                matched_text: m.as_str().to_string(),
                context_window: text[ctx_start..ctx_end].to_string(),
            });
        }
        Ok(spans)
    }

    /// Expands a retrieved chunk's text into a wider `[start_byte..end_byte]` window from its full
    /// parent document (`±window_bytes`), preserving surrounding table rows, headers, and dates
    /// that were split across chunk boundaries.
    pub fn expand_parent_window(
        &self,
        doc_id_or_path: &str,
        anchor_text: &str,
        window_bytes: usize,
        max_tier: u8,
    ) -> Result<Option<(usize, usize, String, Option<String>, Option<String>)>, StorageError> {
        let Some(doc) = self.load_parent_document(doc_id_or_path, max_tier)? else {
            return Ok(None);
        };
        let full = &doc.full_text;
        if full.is_empty() {
            return Ok(None);
        }

        let clean_anchor = crate::tantivy_fts_anchor_probe(anchor_text);
        let (match_start, match_end) = if !clean_anchor.is_empty() {
            if let Some(pos) = full.find(clean_anchor) {
                (pos, (pos + anchor_text.len()).min(full.len()))
            } else {
                // Try a shorter 48-char probe from the middle of clean_anchor
                let probe: String = clean_anchor.chars().take(48).collect();
                if !probe.is_empty() {
                    if let Some(pos) = full.find(&probe) {
                        (pos, (pos + anchor_text.len()).min(full.len()))
                    } else {
                        (0, anchor_text.len().min(full.len()))
                    }
                } else {
                    (0, anchor_text.len().min(full.len()))
                }
            }
        } else {
            (0, anchor_text.len().min(full.len()))
        };

        // Window expansion bounds: clamp requested window to [256, 32768] bytes.
        let half = window_bytes.clamp(256, 32768);

        // Head-match anchoring: when the anchor match is in Chunk 0 or within the first 2500 bytes
        // of the parent document, anchor win_start at byte 0 and expand win_end to at least
        // 10000 bytes (or window_bytes if larger), bounded by parent document length and match_end.
        let (mut win_start, mut win_end) = if match_start <= 2500 {
            let target_end = window_bytes
                .max(10000)
                .max(match_end)
                .clamp(256, 32768)
                .min(full.len());
            (0, target_end)
        } else {
            let s = match_start.saturating_sub(half);
            let e = match_end.saturating_add(half).min(full.len());
            (s, e)
        };

        while win_start > 0 && !full.is_char_boundary(win_start) {
            win_start -= 1;
        }
        while win_end < full.len() && !full.is_char_boundary(win_end) {
            win_end += 1;
        }

        Ok(Some((
            win_start,
            win_end,
            full[win_start..win_end].to_string(),
            doc.title,
            doc.author,
        )))
    }
}

/// When the question explicitly asks for a modality ("pictures of ...", "the song ..."),
/// move chunks produced by that media indexer ahead of other hits, preserving relative order.
/// Chunks of other modalities are kept (never dropped) so documents still ground the answer.
pub(crate) fn prioritize_media_intent(query: &str, hits: &mut Vec<ScoredChunk>) {
    let intent = crate::query_framing::detect_media_intent(query);
    let Some(prefix) = crate::query_framing::media_content_prefix(intent) else {
        return;
    };
    let (mut media, rest): (Vec<ScoredChunk>, Vec<ScoredChunk>) = std::mem::take(hits)
        .into_iter()
        .partition(|h| h.chunk.text_content.trim_start().starts_with(prefix));
    media.extend(rest);
    *hits = media;
}

/// When the question explicitly asks for DNS telemetry/traffic, prioritize matching DNS records
/// and filter out unrelated CodeIntegrity/Defender block logs to avoid retrieval drift.
pub(crate) fn prioritize_forensic_intent(query: &str, hits: &mut Vec<ScoredChunk>) {
    let p_intent = crate::query_framing::detect_protocol_forensic_intent(query);
    if p_intent == crate::query_framing::ProtocolIntent::Dns {
        let (mut dns_hits, mut rest): (Vec<ScoredChunk>, Vec<ScoredChunk>) = std::mem::take(hits)
            .into_iter()
            .partition(|h| {
                let meta = &h.chunk.metadata_json;
                let text = &h.chunk.text_content;
                let file = &h.chunk.file_path;
                let matches_meta = meta.contains("\"port\":53")
                    || meta.contains("\"port\": 53")
                    || meta.contains("\"protocol\":\"UDP\"")
                    || meta.contains("\"protocol\": \"UDP\"")
                    || meta.contains("\"event_id\":22")
                    || meta.contains("\"event_id\": 22")
                    || meta.contains("Microsoft-Windows-DNS-Client")
                    || meta.contains("dns_query");
                let matches_text = file.contains("/dns/")
                    || file.contains("sysmon_dns")
                    || file.contains("dns_client")
                    || text.starts_with("DnsQuery [")
                    || text.contains("port=53")
                    || text.contains("port 53")
                    || text.contains("sysmon/operational', event_id=22")
                    || text.contains("dnscache");
                let is_unrelated = file.contains("codeintegrity")
                    || text.contains("CodeIntegrity")
                    || text.contains("blocked process");
                (matches_meta || matches_text) && !is_unrelated
            });
        rest.retain(|h| {
            !h.chunk.file_path.contains("codeintegrity")
                && !h.chunk.text_content.contains("CodeIntegrity")
        });
        dns_hits.extend(rest);
        *hits = dns_hits;
    }
}
