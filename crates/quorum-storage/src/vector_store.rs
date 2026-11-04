//! LanceDB vector table storage.
//!
//! # Invariant: Absolute Arrow Isolation
//! All types and internal LanceDB dependencies are strictly `pub(crate)`.

use std::fs::create_dir_all;
use std::sync::Arc;

use futures::StreamExt;
use lancedb::index::vector::IvfPqIndexBuilder;
use lancedb::index::Index;
use lancedb::query::{ExecutableQuery, QueryBase};
use lancedb::table::OptimizeAction;
use lancedb::{Connection, DistanceType, Table};
use quorum_types::{DocumentChunk, ScoredChunk};
use tokio::sync::RwLock;

use crate::arrow_interop::{chunks_to_record_batch, extract_scored_chunks};
use crate::config::StorageConfig;
use crate::error::StorageError;

/// LanceDB vector table storage engine.
pub(crate) struct VectorStore {
    table: Arc<RwLock<Table>>,
    _db: Connection,
    config: StorageConfig,
    ivf_index_built: std::sync::atomic::AtomicBool,
}

impl VectorStore {
    /// Opens or initializes the LanceDB connection and table.
    pub(crate) async fn open(config: &StorageConfig) -> Result<Self, StorageError> {
        let lance_dir = config.lance_path();
        create_dir_all(&lance_dir).map_err(|e| StorageError::Io {
            path: lance_dir.clone(),
            source: e,
        })?;

        let uri = lance_dir.to_string_lossy().to_string();
        let db = lancedb::connect(&uri)
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Connect error: {}", e)))?;

        let table_names = db
            .table_names()
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Failed to list tables: {}", e)))?;

        let table = if table_names.contains(&config.table_name) {
            db.open_table(&config.table_name)
                .execute()
                .await
                .map_err(|e| StorageError::Lance(format!("Open table error: {}", e)))?
        } else {
            let empty_batch = chunks_to_record_batch(&[], config.vector_dimension)?;
            db.create_table(&config.table_name, vec![empty_batch])
                .execute()
                .await
                .map_err(|e| StorageError::Lance(format!("Create table error: {}", e)))?
        };

        // An IVF_PQ index persisted by a previous run must be detected, otherwise the first insert
        // after every restart would retrain the whole vector index over the full table.
        let has_vector_index = table
            .list_indices()
            .await
            .map(|ix| ix.iter().any(|i| i.columns.iter().any(|c| c == "vector")))
            .unwrap_or(false);

        Ok(Self {
            table: Arc::new(RwLock::new(table)),
            _db: db,
            config: config.clone(),
            ivf_index_built: std::sync::atomic::AtomicBool::new(has_vector_index),
        })
    }

    /// Appends new chunks into the vector table.
    pub(crate) async fn insert_chunks(&self, chunks: &[DocumentChunk]) -> Result<usize, StorageError> {
        if chunks.is_empty() {
            return Ok(0);
        }

        let batch = chunks_to_record_batch(chunks, self.config.vector_dimension)?;
        let table = self.table.read().await;
        table
            .add(vec![batch])
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Failed to add batch: {}", e)))?;

        let count = chunks.len();
        drop(table);

        // Auto-index at most once when crossing threshold (never rebuild IVF_PQ on every batch!)
        if !self.ivf_index_built.load(std::sync::atomic::Ordering::Relaxed) {
            let total_rows = self.count().await.unwrap_or(0);
            if total_rows >= self.config.auto_index_threshold {
                self.ivf_index_built.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = self.create_ivf_pq_index().await;
            }
        }

        Ok(count)
    }

    /// Searches for nearest vectors with access-tier SQL pre-filtering (`access_tier <= max_tier`).
    pub(crate) async fn search_vector(
        &self,
        vector: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Result<Vec<ScoredChunk>, StorageError> {
        if top_k == 0 {
            return Ok(Vec::new());
        }

        let table = self.table.read().await;
        let mut stream = table
            .query()
            .nearest_to(vector)
            .map_err(|e| StorageError::Lance(format!("Invalid nearest_to query: {}", e)))?
            .only_if(format!("access_tier <= {}", max_tier))
            .limit(top_k)
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Query execution failed: {}", e)))?;

        let mut all_scored = Vec::new();
        while let Some(batch_result) = stream.next().await {
            let batch = batch_result.map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let scored = extract_scored_chunks(&batch, self.config.vector_dimension, Some(vector))?;
            all_scored.extend(scored);
        }

        all_scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.chunk.chunk_id.cmp(&b.chunk.chunk_id))
        });
        all_scored.truncate(top_k);

        Ok(all_scored)
    }

    /// Checks if a chunk hash already exists in LanceDB.
    pub(crate) async fn has_chunk_hash(&self, blake3_hash: &str) -> Result<bool, StorageError> {
        let table = self.table.read().await;
        let escaped = blake3_hash.replace('\'', "''");
        let count = table
            .count_rows(Some(format!("blake3_hash = '{}'", escaped)))
            .await
            .map_err(|e| StorageError::Lance(format!("Count rows error: {}", e)))?;
        Ok(count > 0)
    }

    /// Deletes all chunks associated with `file_path`.
    pub(crate) async fn delete_by_file_path(&self, file_path: &str) -> Result<usize, StorageError> {
        let table = self.table.read().await;
        let escaped = file_path.replace('\'', "''");
        let filter = format!("file_path = '{}'", escaped);
        let before_count = table.count_rows(Some(filter.clone())).await.unwrap_or(0);
        table
            .delete(&filter)
            .await
            .map_err(|e| StorageError::Lance(format!("Delete error: {}", e)))?;
        Ok(before_count)
    }

    /// Deletes all chunks for any of `file_paths` with a single `IN (...)` predicate.
    pub(crate) async fn delete_by_file_paths(&self, file_paths: &[String]) -> Result<(), StorageError> {
        if file_paths.is_empty() {
            return Ok(());
        }
        let list = file_paths
            .iter()
            .map(|p| format!("'{}'", p.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(", ");
        let table = self.table.read().await;
        table
            .delete(&format!("file_path IN ({list})"))
            .await
            .map_err(|e| StorageError::Lance(format!("Delete error: {}", e)))?;
        Ok(())
    }

    /// Creates an IVF_PQ index over the vector column using Cosine distance.
    pub(crate) async fn create_ivf_pq_index(&self) -> Result<(), StorageError> {
        let table = self.table.read().await;
        let num_rows = table.count_rows(None).await.unwrap_or(0);
        if num_rows < 256 {
            // IVF_PQ requires adequate training rows
            return Ok(());
        }

        let builder = IvfPqIndexBuilder::default()
            .distance_type(DistanceType::Cosine);

        table
            .create_index(&["vector"], Index::IvfPq(builder))
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Create IVF_PQ index error: {}", e)))?;

        Ok(())
    }

    /// Optimizes and compacts LanceDB fragments and prunes older versions.
    pub(crate) async fn optimize(&self) -> Result<(usize, usize, usize), StorageError> {
        let table = self.table.read().await;
        let stats = table
            .optimize(OptimizeAction::All)
            .await
            .map_err(|e| StorageError::Compaction(format!("Optimization failed: {}", e)))?;

        let fragments_removed = stats.compaction.as_ref().map_or(0, |c| c.fragments_removed);
        let fragments_added = stats.compaction.as_ref().map_or(0, |c| c.fragments_added);
        let old_versions_pruned = stats.prune.as_ref().map_or(0, |p| p.old_versions as usize);

        Ok((fragments_removed, fragments_added, old_versions_pruned))
    }

    /// Returns the total number of rows in the table.
    pub(crate) async fn count(&self) -> Result<usize, StorageError> {
        let table = self.table.read().await;
        table
            .count_rows(None)
            .await
            .map_err(|e| StorageError::Lance(format!("Count rows error: {}", e)))
    }

    /// Scans all chunks from the vector table.
    pub(crate) async fn scan_all_chunks(&self) -> Result<Vec<DocumentChunk>, StorageError> {
        let table = self.table.read().await;
        let mut stream = table
            .query()
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Scan query failed: {}", e)))?;

        let mut chunks = Vec::new();
        while let Some(batch_result) = stream.next().await {
            let batch = batch_result.map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let batch_chunks = crate::arrow_interop::record_batch_to_chunks(&batch, self.config.vector_dimension)?;
            chunks.extend(batch_chunks);
        }
        Ok(chunks)
    }

    /// Deletes a specific chunk by its chunk_id.
    pub(crate) async fn delete_by_chunk_id(&self, chunk_id: &str) -> Result<usize, StorageError> {
        let table = self.table.read().await;
        let escaped = chunk_id.replace('\'', "''");
        let filter = format!("chunk_id = '{}'", escaped);
        let before_count = table.count_rows(Some(filter.clone())).await.unwrap_or(0);
        table
            .delete(&filter)
            .await
            .map_err(|e| StorageError::Lance(format!("Delete error: {}", e)))?;
        Ok(before_count)
    }
}

