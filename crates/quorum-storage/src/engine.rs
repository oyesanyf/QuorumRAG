//! StorageEngine providing unified vector storage, Tantivy BM25, and hybrid RRF search.
//!
//! # Invariant: Absolute Arrow Isolation
//! All Apache Arrow, LanceDB, and Tantivy types are strictly private.
//! Callers interact solely with pure domain types (`DocumentChunk`, `ScoredChunk`, `StorageError`).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use quorum_types::{DocumentChunk, ScoredChunk};
use serde::{Deserialize, Serialize};

use crate::config::StorageConfig;
use crate::error::StorageError;
use crate::tantivy_fts::TantivyFtsIndex;
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
    index_epoch: Arc<AtomicU64>,
    metadata_lock: Arc<Mutex<StorageMetadata>>,
}

impl StorageEngine {
    /// Opens or creates the embedded LanceDB vector table and co-located Tantivy FTS index.
    pub async fn open(config: impl Into<StorageConfig>) -> Result<Self, StorageError> {
        let cfg = config.into();
        let vector_store = Arc::new(VectorStore::open(&cfg).await?);
        let fts_index = Arc::new(TantivyFtsIndex::open(&cfg.tantivy_path())?);

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

        Ok(Self {
            config: cfg,
            vector_store,
            fts_index,
            index_epoch,
            metadata_lock,
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

    /// Inserts document chunks with automatic Level-2 BLAKE3 deduplication.
    pub async fn insert_chunks(&self, chunks: &[DocumentChunk]) -> Result<usize, StorageError> {
        if chunks.is_empty() {
            return Ok(0);
        }

        let mut unique_chunks: Vec<DocumentChunk> = Vec::with_capacity(chunks.len());
        let mut seen_hashes: HashSet<String> = HashSet::with_capacity(chunks.len());

        for chunk in chunks {
            if seen_hashes.contains(&chunk.blake3_hash) {
                continue;
            }
            if self.fts_index.has_chunk_hash(&chunk.blake3_hash).unwrap_or(false) {
                continue;
            }
            seen_hashes.insert(chunk.blake3_hash.clone());
            unique_chunks.push(chunk.clone());
        }

        if unique_chunks.is_empty() {
            return Ok(0);
        }

        let count = self.vector_store.insert_chunks(&unique_chunks).await?;
        let _ = self.fts_index.index_chunks(&unique_chunks)?;

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
        let mut hits = self.fts_index.search(query, max_tier, top_k)?;
        prioritize_media_intent(query, &mut hits);
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
        let text_hits = self.search_text(text, max_tier, candidate_limit).await?;
        let vector_hits = self
            .search_vector(vector, max_tier, candidate_limit)
            .await
            .unwrap_or_default();

        let mut rrf_map: HashMap<String, (f32, DocumentChunk)> = HashMap::new();

        // Only include vector hits that have positive cosine similarity and are not excluded
        let relevant_vector_hits: Vec<ScoredChunk> = vector_hits
            .into_iter()
            .filter(|s| s.score > 0.0 && !exclude_set.contains(s.chunk.chunk_id.as_str()))
            .collect();

        let mut current_rank = 1;
        for (i, scored) in relevant_vector_hits.iter().enumerate() {
            if i > 0 && (scored.score - relevant_vector_hits[i - 1].score).abs() > 1e-6 {
                current_rank = i + 1;
            }
            let rrf = 1.0 / (60.0 + current_rank as f32);
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
            let rrf = 1.0 / (60.0 + current_rank as f32);
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
        });
        prioritize_media_intent(text, &mut combined);
        combined.truncate(top_k);

        Ok(combined)
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

    /// Deletes all chunks matching the specified source `file_path`.
    pub async fn delete_by_file_path(&self, file_path: &str) -> Result<usize, StorageError> {
        let lance_deleted = self.vector_store.delete_by_file_path(file_path).await?;
        let tantivy_deleted = self.fts_index.delete_by_file_path(file_path)?;
        Ok(lance_deleted.max(tantivy_deleted))
    }

    /// Removes existing chunks for several files at once (used before re-inserting re-indexed files,
    /// so a reindex replaces stale chunks instead of duplicating them).
    pub async fn delete_by_file_paths(&self, file_paths: &[String]) -> Result<(), StorageError> {
        if file_paths.is_empty() {
            return Ok(());
        }
        self.vector_store.delete_by_file_paths(file_paths).await?;
        for p in file_paths {
            self.fts_index.delete_by_file_path(p)?;
        }
        Ok(())
    }

    /// Performs maintenance: compacts small Lance files, cleans up older snapshots, and merges Tantivy segments.
    pub async fn compact(&self) -> Result<CompactionStats, StorageError> {
        let (frags_rem, frags_add, versions_pruned) = self
            .vector_store
            .optimize()
            .await
            .unwrap_or((0, 0, 0));

        let fts_res = self.fts_index.compact();

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

    /// Retrieves specific chunks from LanceDB by their IDs.
    pub async fn get_chunks_by_ids(&self, chunk_ids: &[String]) -> Result<Vec<DocumentChunk>, StorageError> {
        let id_set: HashSet<&str> = chunk_ids.iter().map(|s| s.as_str()).collect();
        let all_chunks = self.vector_store.scan_all_chunks().await?;
        Ok(all_chunks.into_iter().filter(|c| id_set.contains(c.chunk_id.as_str())).collect())
    }

    /// Retrieves specific chunks from Tantivy by their IDs.
    pub fn get_chunks_from_tantivy(&self, chunk_ids: &[String]) -> Result<Vec<DocumentChunk>, StorageError> {
        let id_set: HashSet<&str> = chunk_ids.iter().map(|s| s.as_str()).collect();
        let all_chunks = self.fts_index.scan_all_chunks()?;
        Ok(all_chunks.into_iter().filter(|c| id_set.contains(c.chunk_id.as_str())).collect())
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
        let all_chunks = self.vector_store.scan_all_chunks().await?;
        if let Some(mut chunk) = all_chunks.into_iter().find(|c| c.chunk_id == chunk_id) {
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
