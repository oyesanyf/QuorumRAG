//! LanceDB vector table storage.
//!
//! # Invariant: Absolute Arrow Isolation
//! All types and internal LanceDB dependencies are strictly `pub(crate)`.

use std::fs::create_dir_all;
use std::sync::Arc;

use arrow_array::cast::AsArray;
use arrow_array::types::UInt8Type;
use arrow_array::Array;
use futures::StreamExt;
use lancedb::index::vector::{IvfHnswSqIndexBuilder, IvfPqIndexBuilder};
use lancedb::index::Index;
use lancedb::query::{ExecutableQuery, QueryBase, Select};
use lancedb::table::OptimizeAction;
use lancedb::{Connection, DistanceType, Table};
use quorum_types::{DocumentChunk, ScoredChunk};
use sysinfo::{MemoryRefreshKind, RefreshKind, System};
use tokio::sync::RwLock;

/// Minimum runtime available RAM (16 GiB) required to prefer `IVF_HNSW_SQ` over `IVF_PQ`.
pub(crate) const IVF_HNSW_SQ_MIN_AVAILABLE_RAM_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Adaptive LanceDB vector ANN index strategy chosen strictly from runtime available RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VectorIndexStrategy {
    /// Higher-recall HNSW + Scalar Quantization for hosts with >= 16 GiB free RAM.
    IvfHnswSq,
    /// Low-RAM Product Quantization for laptops and constrained nodes (< 16 GiB free RAM).
    IvfPq,
}

/// Selects `IVF_HNSW_SQ` when runtime available RAM >= 16 GiB, otherwise `IVF_PQ`.
#[inline]
pub(crate) fn select_adaptive_vector_index_strategy(
    available_ram_bytes: u64,
) -> VectorIndexStrategy {
    if available_ram_bytes >= IVF_HNSW_SQ_MIN_AVAILABLE_RAM_BYTES {
        VectorIndexStrategy::IvfHnswSq
    } else {
        VectorIndexStrategy::IvfPq
    }
}

fn current_available_ram_bytes() -> u64 {
    let sys =
        System::new_with_specifics(RefreshKind::new().with_memory(MemoryRefreshKind::everything()));
    let avail = sys.available_memory();
    if avail > 0 {
        avail
    } else {
        sys.free_memory()
    }
}

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
    pub(crate) async fn insert_chunks(
        &self,
        chunks: &[DocumentChunk],
    ) -> Result<usize, StorageError> {
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
        if !self
            .ivf_index_built
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            let total_rows = self.count().await.unwrap_or(0);
            if total_rows >= self.config.auto_index_threshold {
                self.ivf_index_built
                    .store(true, std::sync::atomic::Ordering::Relaxed);
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
            let batch = batch_result
                .map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
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

    /// Checks if a chunk_id exists in LanceDB table via row count.
    pub(crate) async fn has_chunk_id(&self, chunk_id: &str) -> Result<bool, StorageError> {
        let table = self.table.read().await;
        let escaped = chunk_id.replace('\'', "''");
        let count = table
            .count_rows(Some(format!("chunk_id = '{}'", escaped)))
            .await
            .map_err(|e| StorageError::Lance(format!("Count rows error: {}", e)))?;
        Ok(count > 0)
    }

    /// Deletes all chunks associated with `file_path` (matching exact or Windows slash/case-normalized paths).
    pub(crate) async fn delete_by_file_path(&self, file_path: &str) -> Result<usize, StorageError> {
        let table = self.table.read().await;
        let escaped = file_path.replace('\'', "''");
        let filter = format!("file_path = '{}'", escaped);
        let before_count = table.count_rows(Some(filter.clone())).await.unwrap_or(0);
        if before_count > 0 {
            table
                .delete(&filter)
                .await
                .map_err(|e| StorageError::Lance(format!("Delete error: {}", e)))?;
            return Ok(before_count);
        }

        let target_key = crate::file_path_compare_key(file_path);
        let mut stream = table
            .query()
            .select(Select::columns(&["file_path"]))
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("File path scan query failed: {}", e)))?;

        let mut matching_set = std::collections::HashSet::new();
        while let Some(batch_result) = stream.next().await {
            let batch = batch_result
                .map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let path_col = batch
                .column_by_name("file_path")
                .ok_or_else(|| StorageError::Schema("Missing 'file_path' column".into()))?
                .as_string::<i32>();
            for i in 0..batch.num_rows() {
                if path_col.is_null(i) {
                    continue;
                }
                let raw_fp = path_col.value(i);
                if crate::file_path_compare_key(raw_fp) == target_key {
                    matching_set.insert(raw_fp.to_string());
                }
            }
        }
        if matching_set.is_empty() {
            return Ok(0);
        }

        let mut matching_paths: Vec<String> = matching_set.into_iter().collect();
        matching_paths.sort();
        let mut deleted_rows = 0usize;
        for batch in matching_paths.chunks(256) {
            let list = batch
                .iter()
                .map(|p| format!("'{}'", p.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(", ");
            let del = table
                .delete(&format!("file_path IN ({list})"))
                .await
                .map_err(|e| StorageError::Lance(format!("Normalized file delete error: {}", e)))?;
            deleted_rows = deleted_rows.saturating_add(del.num_deleted_rows as usize);
        }
        Ok(deleted_rows)
    }

    /// Deletes all chunks for any of `file_paths` (matching exact or Windows slash/case-normalized paths).
    pub(crate) async fn delete_by_file_paths(
        &self,
        file_paths: &[String],
    ) -> Result<(), StorageError> {
        if file_paths.is_empty() {
            return Ok(());
        }
        let target_keys: std::collections::HashSet<String> = file_paths
            .iter()
            .map(|p| crate::file_path_compare_key(p))
            .collect();
        let table = self.table.read().await;
        let mut stream = table
            .query()
            .select(Select::columns(&["file_path"]))
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("File paths scan query failed: {}", e)))?;

        let mut matching_set = std::collections::HashSet::new();
        while let Some(batch_result) = stream.next().await {
            let batch = batch_result
                .map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let path_col = batch
                .column_by_name("file_path")
                .ok_or_else(|| StorageError::Schema("Missing 'file_path' column".into()))?
                .as_string::<i32>();
            for i in 0..batch.num_rows() {
                if path_col.is_null(i) {
                    continue;
                }
                let raw_fp = path_col.value(i);
                if target_keys.contains(&crate::file_path_compare_key(raw_fp)) {
                    matching_set.insert(raw_fp.to_string());
                }
            }
        }
        if matching_set.is_empty() {
            return Ok(());
        }

        let mut matching_paths: Vec<String> = matching_set.into_iter().collect();
        matching_paths.sort();
        for batch in matching_paths.chunks(256) {
            let list = batch
                .iter()
                .map(|p| format!("'{}'", p.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(", ");
            table
                .delete(&format!("file_path IN ({list})"))
                .await
                .map_err(|e| StorageError::Lance(format!("Delete error: {}", e)))?;
        }
        Ok(())
    }

    /// Deletes all chunks whose raw `file_path` matches `prefix` on strict component boundaries.
    pub(crate) async fn delete_by_path_prefix(&self, prefix: &str) -> Result<usize, StorageError> {
        let norm_prefix = quorum_types::normalize_prefix_for_match(prefix)?;
        let table = self.table.read().await;
        let mut stream = table
            .query()
            .select(Select::columns(&["file_path"]))
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Prefix scan query failed: {}", e)))?;

        let mut matching_set = std::collections::HashSet::new();
        while let Some(batch_result) = stream.next().await {
            let batch = batch_result
                .map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let path_col = batch
                .column_by_name("file_path")
                .ok_or_else(|| StorageError::Schema("Missing 'file_path' column".into()))?
                .as_string::<i32>();
            for i in 0..batch.num_rows() {
                if path_col.is_null(i) {
                    continue;
                }
                let raw_fp = path_col.value(i);
                if quorum_types::path_matches_prefix(raw_fp, &norm_prefix).unwrap_or(false) {
                    matching_set.insert(raw_fp.to_string());
                }
            }
        }

        if matching_set.is_empty() {
            return Ok(0);
        }

        let mut matching_paths: Vec<String> = matching_set.into_iter().collect();
        matching_paths.sort();

        let mut deleted_rows = 0usize;
        for batch in matching_paths.chunks(256) {
            let list = batch
                .iter()
                .map(|p| format!("'{}'", p.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(", ");
            let del = table
                .delete(&format!("file_path IN ({list})"))
                .await
                .map_err(|e| StorageError::Lance(format!("Prefix delete error: {}", e)))?;
            deleted_rows = deleted_rows.saturating_add(del.num_deleted_rows as usize);
        }

        Ok(deleted_rows)
    }

    /// Updates `access_tier` in-place for all LanceDB chunks whose raw `file_path` matches
    /// `prefix` on strict component boundaries.
    pub(crate) async fn update_access_tier_by_path_prefix(
        &self,
        prefix: &str,
        new_tier: u8,
    ) -> Result<usize, StorageError> {
        quorum_types::AccessTier::from_u8(new_tier)?;
        let norm_prefix = quorum_types::normalize_prefix_for_match(prefix)?;
        let table = self.table.read().await;
        let mut stream = table
            .query()
            .select(Select::columns(&["file_path", "access_tier"]))
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Prefix tier scan query failed: {}", e)))?;

        let mut matching_set = std::collections::HashSet::new();
        while let Some(batch_result) = stream.next().await {
            let batch = batch_result
                .map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let path_col = batch
                .column_by_name("file_path")
                .ok_or_else(|| StorageError::Schema("Missing 'file_path' column".into()))?
                .as_string::<i32>();
            let tier_col = batch
                .column_by_name("access_tier")
                .ok_or_else(|| StorageError::Schema("Missing 'access_tier' column".into()))?
                .as_primitive::<UInt8Type>();
            for i in 0..batch.num_rows() {
                if path_col.is_null(i) || tier_col.is_null(i) {
                    continue;
                }
                if tier_col.value(i) == new_tier {
                    continue;
                }
                let raw_fp = path_col.value(i);
                if quorum_types::path_matches_prefix(raw_fp, &norm_prefix).unwrap_or(false) {
                    matching_set.insert(raw_fp.to_string());
                }
            }
        }

        if matching_set.is_empty() {
            return Ok(0);
        }

        let mut matching_paths: Vec<String> = matching_set.into_iter().collect();
        matching_paths.sort();

        let mut updated_rows = 0usize;
        for batch in matching_paths.chunks(256) {
            let list = batch
                .iter()
                .map(|p| format!("'{}'", p.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(", ");
            let upd = table
                .update()
                .only_if(format!(
                    "file_path IN ({list}) AND access_tier != {new_tier}"
                ))
                .column("access_tier", new_tier.to_string())
                .execute()
                .await
                .map_err(|e| {
                    StorageError::Lance(format!("Prefix access_tier update error: {}", e))
                })?;
            updated_rows = updated_rows.saturating_add(upd.rows_updated as usize);
        }

        Ok(updated_rows)
    }

    /// Creates scalar pre-filter indices (including `blake3_hash` BTree for O(log N) dedup)
    /// and an adaptive vector ANN index (`IVF_HNSW_SQ` on >= 16 GiB free RAM, `IVF_PQ` below).
    pub(crate) async fn create_ivf_pq_index(&self) -> Result<(), StorageError> {
        self.create_adaptive_indices_for_ram(current_available_ram_bytes())
            .await
    }

    pub(crate) async fn create_adaptive_indices_for_ram(
        &self,
        available_ram_bytes: u64,
    ) -> Result<(), StorageError> {
        let table = self.table.read().await;

        // 1. Create scalar pre-filter indices (Bitmap on access_tier; BTree on file_path, chunk_id, blake3_hash)
        let _ = table
            .create_index(&["access_tier"], Index::Bitmap(Default::default()))
            .execute()
            .await;
        let _ = table
            .create_index(&["file_path"], Index::BTree(Default::default()))
            .execute()
            .await;
        let _ = table
            .create_index(&["chunk_id"], Index::BTree(Default::default()))
            .execute()
            .await;
        let _ = table
            .create_index(&["blake3_hash"], Index::BTree(Default::default()))
            .execute()
            .await;

        let num_rows = table.count_rows(None).await.unwrap_or(0);
        if num_rows < 256 {
            // Vector ANN index requires adequate training rows
            return Ok(());
        }

        // 2. Dynamic partition sizing based on square root of row count
        let num_partitions = ((num_rows as f64).sqrt().round() as u32).clamp(16, 1024);
        let strategy = select_adaptive_vector_index_strategy(available_ram_bytes);

        match strategy {
            VectorIndexStrategy::IvfHnswSq => {
                let hnsw_builder = IvfHnswSqIndexBuilder::default()
                    .distance_type(DistanceType::Cosine)
                    .num_partitions(num_partitions);
                match table
                    .create_index(&["vector"], Index::IvfHnswSq(hnsw_builder))
                    .execute()
                    .await
                {
                    Ok(_) => {
                        tracing::info!(
                            num_rows,
                            num_partitions,
                            available_ram_gb = available_ram_bytes / (1024 * 1024 * 1024),
                            "Created adaptive LanceDB IVF_HNSW_SQ vector index + blake3_hash BTree index"
                        );
                    }
                    Err(hnsw_err) => {
                        tracing::warn!(
                            error = %hnsw_err,
                            "IVF_HNSW_SQ index creation failed; falling back cleanly to IVF_PQ"
                        );
                        let pq_builder = IvfPqIndexBuilder::default()
                            .distance_type(DistanceType::Cosine)
                            .num_partitions(num_partitions);
                        table
                            .create_index(&["vector"], Index::IvfPq(pq_builder))
                            .execute()
                            .await
                            .map_err(|e| {
                                StorageError::Lance(format!(
                                    "Create IVF_PQ fallback index error: {}",
                                    e
                                ))
                            })?;
                    }
                }
            }
            VectorIndexStrategy::IvfPq => {
                let pq_builder = IvfPqIndexBuilder::default()
                    .distance_type(DistanceType::Cosine)
                    .num_partitions(num_partitions);
                table
                    .create_index(&["vector"], Index::IvfPq(pq_builder))
                    .execute()
                    .await
                    .map_err(|e| {
                        StorageError::Lance(format!("Create IVF_PQ index error: {}", e))
                    })?;
                tracing::info!(
                    num_rows,
                    num_partitions,
                    available_ram_gb = available_ram_bytes / (1024 * 1024 * 1024),
                    "Created low-RAM LanceDB IVF_PQ vector index + blake3_hash BTree index"
                );
            }
        }

        Ok(())
    }

    /// Optimizes and compacts LanceDB fragments and prunes older versions.
    pub(crate) async fn optimize(&self) -> Result<(usize, usize, usize), StorageError> {
        let table = self.table.read().await;
        let stats = table
            .optimize(OptimizeAction::All)
            .await
            .map_err(|e| StorageError::Compaction(format!("Optimization failed: {}", e)))?;

        // Prune versions older than 5 minutes
        let prune_action = OptimizeAction::Prune {
            older_than: chrono::TimeDelta::try_seconds(300),
            delete_unverified: None,
            error_if_tagged_old_versions: None,
        };
        let _ = table.optimize(prune_action).await;

        let fragments_removed = stats.compaction.as_ref().map_or(0, |c| c.fragments_removed);
        let fragments_added = stats.compaction.as_ref().map_or(0, |c| c.fragments_added);
        let old_versions_pruned = stats.prune.as_ref().map_or(0, |p| p.old_versions as usize);

        Ok((fragments_removed, fragments_added, old_versions_pruned))
    }

    /// Optimizes indices specifically.
    pub(crate) async fn optimize_indices(&self) -> Result<(), StorageError> {
        let table = self.table.read().await;
        table
            .optimize(OptimizeAction::Index(Default::default()))
            .await
            .map_err(|e| StorageError::Compaction(format!("Index optimization failed: {}", e)))?;
        Ok(())
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
            let batch = batch_result
                .map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let batch_chunks =
                crate::arrow_interop::record_batch_to_chunks(&batch, self.config.vector_dimension)?;
            chunks.extend(batch_chunks);
        }
        Ok(chunks)
    }

    /// Retrieves specific chunks from the vector table by their chunk_ids using SQL predicate pushdown.
    pub(crate) async fn get_chunks_by_ids(
        &self,
        chunk_ids: &[String],
    ) -> Result<Vec<DocumentChunk>, StorageError> {
        if chunk_ids.is_empty() {
            return Ok(Vec::new());
        }

        let list = chunk_ids
            .iter()
            .map(|id| format!("'{}'", id.replace('\'', "''")))
            .collect::<Vec<_>>()
            .join(", ");
        let predicate = format!("chunk_id IN ({list})");

        let table = self.table.read().await;
        let mut stream = table
            .query()
            .only_if(predicate)
            .limit(chunk_ids.len())
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Get chunks query failed: {}", e)))?;

        let mut chunks = Vec::with_capacity(chunk_ids.len());
        while let Some(batch_result) = stream.next().await {
            let batch = batch_result
                .map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let batch_chunks =
                crate::arrow_interop::record_batch_to_chunks(&batch, self.config.vector_dimension)?;
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

    /// Retrieves a specific chunk matching both `(chunk_id, file_path)` (normalizing Windows slash/case variants).
    pub(crate) async fn get_chunk_by_id_and_file_path(
        &self,
        chunk_id: &str,
        file_path: &str,
    ) -> Result<Option<DocumentChunk>, StorageError> {
        let escaped_id = chunk_id.replace('\'', "''");
        let escaped_path = file_path.replace('\'', "''");
        let predicate = format!(
            "chunk_id = '{}' AND file_path = '{}'",
            escaped_id, escaped_path
        );

        let table = self.table.read().await;
        let mut stream = table
            .query()
            .only_if(predicate)
            .limit(1)
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Get chunk by (id, path) failed: {}", e)))?;

        while let Some(batch_result) = stream.next().await {
            let batch = batch_result
                .map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let batch_chunks =
                crate::arrow_interop::record_batch_to_chunks(&batch, self.config.vector_dimension)?;
            if let Some(chunk) = batch_chunks.into_iter().next() {
                return Ok(Some(chunk));
            }
        }
        drop(table);

        let target_key = crate::file_path_compare_key(file_path);
        let candidates = self.get_chunks_for_id(chunk_id).await?;
        Ok(candidates
            .into_iter()
            .find(|c| crate::file_path_compare_key(&c.file_path) == target_key))
    }

    /// Retrieves all copies matching `chunk_id` across distinct `file_path`s.
    pub(crate) async fn get_chunks_for_id(
        &self,
        chunk_id: &str,
    ) -> Result<Vec<DocumentChunk>, StorageError> {
        let escaped = chunk_id.replace('\'', "''");
        let predicate = format!("chunk_id = '{}'", escaped);

        let table = self.table.read().await;
        let mut stream = table
            .query()
            .only_if(predicate)
            .execute()
            .await
            .map_err(|e| StorageError::Lance(format!("Get chunks for id failed: {}", e)))?;

        let mut chunks = Vec::new();
        while let Some(batch_result) = stream.next().await {
            let batch = batch_result
                .map_err(|e| StorageError::Lance(format!("RecordBatch stream error: {}", e)))?;
            let batch_chunks =
                crate::arrow_interop::record_batch_to_chunks(&batch, self.config.vector_dimension)?;
            chunks.extend(batch_chunks);
        }
        Ok(chunks)
    }

    /// Deletes a specific chunk matching both `(chunk_id, file_path)`, preserving sibling copies.
    pub(crate) async fn delete_by_chunk_id_and_file_path(
        &self,
        chunk_id: &str,
        file_path: &str,
    ) -> Result<usize, StorageError> {
        let escaped_id = chunk_id.replace('\'', "''");
        let escaped_path = file_path.replace('\'', "''");
        let filter = format!(
            "chunk_id = '{}' AND file_path = '{}'",
            escaped_id, escaped_path
        );
        {
            let table = self.table.read().await;
            let before_count = table.count_rows(Some(filter.clone())).await.unwrap_or(0);
            if before_count > 0 {
                table
                    .delete(&filter)
                    .await
                    .map_err(|e| StorageError::Lance(format!("Delete error: {}", e)))?;
                return Ok(before_count);
            }
        }

        let target_key = crate::file_path_compare_key(file_path);
        let candidates = self.get_chunks_for_id(chunk_id).await?;
        let mut matching_paths: Vec<String> = candidates
            .into_iter()
            .filter(|c| crate::file_path_compare_key(&c.file_path) == target_key)
            .map(|c| c.file_path)
            .collect();
        matching_paths.sort();
        matching_paths.dedup();
        if matching_paths.is_empty() {
            return Ok(0);
        }

        let table = self.table.read().await;
        let mut deleted = 0usize;
        for batch in matching_paths.chunks(256) {
            let list = batch
                .iter()
                .map(|p| format!("'{}'", p.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(", ");
            let del = table
                .delete(&format!(
                    "chunk_id = '{}' AND file_path IN ({list})",
                    escaped_id
                ))
                .await
                .map_err(|e| StorageError::Lance(format!("Delete error: {}", e)))?;
            deleted = deleted.saturating_add(del.num_deleted_rows as usize);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn adaptive_vector_index_strategy_selects_hnsw_sq_above_16gb_and_pq_below() {
        let gib = 1024u64 * 1024 * 1024;
        assert_eq!(
            select_adaptive_vector_index_strategy(2 * gib),
            VectorIndexStrategy::IvfPq
        );
        assert_eq!(
            select_adaptive_vector_index_strategy(16 * gib - 1),
            VectorIndexStrategy::IvfPq
        );
        assert_eq!(
            select_adaptive_vector_index_strategy(16 * gib),
            VectorIndexStrategy::IvfHnswSq
        );
        assert_eq!(
            select_adaptive_vector_index_strategy(186 * gib),
            VectorIndexStrategy::IvfHnswSq
        );
    }

    #[tokio::test]
    async fn adaptive_index_builds_blake3_btree_and_vector_indices_for_both_ram_tiers() {
        for (label, sim_ram) in [
            ("low_ram_ivf_pq", 4u64 * 1024 * 1024 * 1024),
            ("high_ram_ivf_hnsw_sq", 64u64 * 1024 * 1024 * 1024),
        ] {
            let tmp = TempDir::new().unwrap();
            let cfg = StorageConfig::new(tmp.path())
                .with_vector_dimension(16)
                .with_auto_index_threshold(10_000);
            let store = VectorStore::open(&cfg).await.unwrap();

            let mut chunks = Vec::with_capacity(300);
            for i in 0..300usize {
                let mut vec = vec![0.05f32; 16];
                vec[i % 16] = 1.0;
                let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
                for x in &mut vec {
                    *x /= norm;
                }
                chunks.push(
                    DocumentChunk::new(
                        format!("doc:{i}"),
                        format!("doc_{}", i % 10),
                        format!("folder/file_{}.txt", i % 10),
                        1,
                        5,
                        0,
                        vec,
                        format!("Adaptive index test payload {label} row {i}"),
                        None,
                    )
                    .unwrap(),
                );
            }
            store.insert_chunks(&chunks).await.unwrap();
            store
                .create_adaptive_indices_for_ram(sim_ram)
                .await
                .expect("create adaptive indices");

            let indices = store.table.read().await.list_indices().await.unwrap();
            assert!(
                indices
                    .iter()
                    .any(|idx| idx.columns.iter().any(|c| c == "blake3_hash")),
                "{label}: expected BTree index on blake3_hash, got {:?}",
                indices
            );
            assert!(
                indices
                    .iter()
                    .any(|idx| idx.columns.iter().any(|c| c == "vector")),
                "{label}: expected vector ANN index on vector, got {:?}",
                indices
            );
            assert!(store.has_chunk_hash(&chunks[42].blake3_hash).await.unwrap());
            let hits = store.search_vector(&chunks[42].vector, 0, 5).await.unwrap();
            assert!(!hits.is_empty());
        }
    }
}
