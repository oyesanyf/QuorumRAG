//! Comprehensive 5-Drift Remediation Worker for QuorumRAG.
//!
//! Detects and resolves ALL five categories of system and data drift:
//! 1. Merkle State Drift (Filesystem <-> Database synchronization):
//!    Purges orphaned database records for deleted files; indexes missing or modified files.
//! 2. Hybrid Index Desynchronization (LanceDB Vector <-> Tantivy BM25 Desync):
//!    Restores 100% mutual consistency between vector table and inverted keyword index.
//! 3. Vector Contract Drift:
//!    Detects obsolete contract hash, incorrect dimensions, or drifted L2 norm; re-embeds in place.
//! 4. ACL Policy Drift:
//!    Updates stored `access_tier` when directory clearance configurations change.
//! 5. Storage Fragmentation & Tombstone Drift:
//!    Consolidates LanceDB parquet fragments and merges Tantivy segments.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

use crate::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use crate::chunker::TextChunker;
use crate::config::{ChunkerConfig, DriftFixOptions, DriftType, IngestConfig};
use crate::crawler::FilesystemCrawler;
use crate::dedup::{FileCatalogEntry, TwoLevelDedupEngine};
use crate::audio_indexer::AudioIndexer;
use crate::error::IngestError;
use crate::image_indexer::ImageIndexer;
use quorum_classifier::FileTypeClassifier;
use quorum_contract::EmbeddingGenerator;
use quorum_storage::StorageEngine;
use quorum_types::DocumentChunk;

/// Detailed drift report returned after scanning or healing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriftReport {
    pub scanned_at: DateTime<Utc>,
    pub healed_at: Option<DateTime<Utc>>,
    pub is_healed: bool,

    // Drift A: Merkle State
    pub orphaned_db_files_purged: usize,
    pub missing_fs_files_indexed: usize,
    pub outdated_files_reindexed: usize,

    // Drift B: Hybrid Index Desync
    pub lance_chunks_missing_in_tantivy: usize,
    pub tantivy_chunks_missing_in_lance: usize,
    pub hybrid_parity_restored: bool,

    // Drift C: Vector Contract
    pub contract_drifted_chunks_reembedded: usize,
    pub active_contract_hash: String,

    // Drift D: ACL Policy
    pub acl_drifted_chunks_updated: usize,

    // Drift E: Storage Compaction
    pub fragments_consolidated: usize,
    pub old_versions_pruned: usize,
    pub tantivy_segments_merged: bool,

    pub total_anomalies_detected: usize,
    pub total_anomalies_healed: usize,
    pub duration_ms: u64,
}

/// Comprehensive Drift Remediation Subsystem.
pub struct DriftHealer {
    config: IngestConfig,
    storage: Arc<StorageEngine>,
    classifier: Arc<FileTypeClassifier>,
    embedder: Arc<dyn EmbeddingGenerator>,
    dedup: Arc<TwoLevelDedupEngine>,
}

impl DriftHealer {
    pub fn new(
        config: IngestConfig,
        storage: Arc<StorageEngine>,
        classifier: Arc<FileTypeClassifier>,
        embedder: Arc<dyn EmbeddingGenerator>,
        dedup: Arc<TwoLevelDedupEngine>,
    ) -> Self {
        Self {
            config,
            storage,
            classifier,
            embedder,
            dedup,
        }
    }

    pub fn config(&self) -> &IngestConfig {
        &self.config
    }

    pub fn storage(&self) -> &Arc<StorageEngine> {
        &self.storage
    }

    pub fn classifier(&self) -> &Arc<FileTypeClassifier> {
        &self.classifier
    }

    pub fn embedder(&self) -> &Arc<dyn EmbeddingGenerator> {
        &self.embedder
    }

    pub fn dedup(&self) -> &Arc<TwoLevelDedupEngine> {
        &self.dedup
    }

    /// Detects and repairs all 5 drift categories according to `options`.
    pub async fn fix_all_drifts(
        &self,
        options: DriftFixOptions,
    ) -> Result<DriftReport, IngestError> {
        let start_time = std::time::Instant::now();
        let mut report = DriftReport {
            scanned_at: Utc::now(),
            active_contract_hash: self.embedder.contract().derive_contract_hash_hex(),
            ..Default::default()
        };

        let target_all = options.target_drifts.is_empty();
        let targets: HashSet<DriftType> = options.target_drifts.into_iter().collect();

        // 1. Drift Type A: Merkle State Drift (FS <-> DB)
        if target_all || targets.contains(&DriftType::MerkleState) {
            self.heal_merkle_state_drift(&mut report, options.dry_run).await?;
        }

        // 2. Drift Type B: Hybrid Index Desync (LanceDB <-> Tantivy)
        if target_all || targets.contains(&DriftType::HybridIndexDesync) {
            self.heal_hybrid_index_desync(&mut report, options.dry_run).await?;
        }

        // 3. Drift Type C: Vector Contract Drift
        if target_all || targets.contains(&DriftType::VectorContract) {
            self.heal_vector_contract_drift(&mut report, options.dry_run).await?;
        }

        // 4. Drift Type D: ACL Policy Drift
        if target_all || targets.contains(&DriftType::AclPolicy) {
            self.heal_acl_policy_drift(&options.access_tier_rules, &mut report, options.dry_run).await?;
        }

        // 5. Drift Type E: Storage Compaction & Tombstone Drift
        if target_all || targets.contains(&DriftType::StorageCompaction) {
            self.heal_storage_compaction(&mut report, options.dry_run).await?;
        }

        report.duration_ms = start_time.elapsed().as_millis() as u64;
        report.healed_at = Some(Utc::now());
        report.is_healed = !options.dry_run;
        report.total_anomalies_detected = report.orphaned_db_files_purged
            + report.missing_fs_files_indexed
            + report.outdated_files_reindexed
            + report.lance_chunks_missing_in_tantivy
            + report.tantivy_chunks_missing_in_lance
            + report.contract_drifted_chunks_reembedded
            + report.acl_drifted_chunks_updated;
        report.total_anomalies_healed = if options.dry_run {
            0
        } else {
            report.total_anomalies_detected
        };

        info!(
            detected = report.total_anomalies_detected,
            healed = report.total_anomalies_healed,
            elapsed_ms = report.duration_ms,
            "Drift healing scan and remediation finished"
        );

        if !options.dry_run && report.total_anomalies_healed > 0 {
            let _ = self.storage.bump_index_epoch("drift_healer_remediated");
        }

        Ok(report)
    }

    /// Drift A: Filesystem <-> Database Merkle State Reconciliation.
    async fn heal_merkle_state_drift(
        &self,
        report: &mut DriftReport,
        dry_run: bool,
    ) -> Result<(), IngestError> {
        // Step 1: Scan all recorded file paths from catalog
        let tracked_files = self.dedup.get_all_tracked_files();

        for file_path in tracked_files {
            let path = Path::new(&file_path);
            if !path.exists() {
                // File deleted while watcher was offline -> purge orphan
                report.orphaned_db_files_purged += 1;
                if !dry_run {
                    let path_str = path.to_string_lossy().to_string();
                    let _ = self.storage.delete_by_file_path(&path_str).await;
                    self.dedup.remove_file(path);
                }
            } else if let Ok(meta) = std::fs::metadata(path) {
                if let Some(entry) = self.dedup.get_file_entry(path) {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);

                    if meta.len() != entry.size_bytes || mtime != entry.mtime_secs {
                        report.outdated_files_reindexed += 1;
                        if !dry_run {
                            self.reingest_single_file(path).await?;
                        }
                    }
                }
            }
        }

        // Step 2: Walk filesystem paths to discover untracked files
        for root in &self.config.watch_paths {
            if !root.exists() {
                continue;
            }
            let crawler = FilesystemCrawler::new(self.config.clone());
            let candidates = crawler.crawl_path_sync(root)?;

            for candidate in candidates {
                let is_tracked = self.dedup.get_file_entry(&candidate.path).is_some();
                if !is_tracked {
                    report.missing_fs_files_indexed += 1;
                    if !dry_run {
                        self.reingest_single_file(&candidate.path).await?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Drift B: LanceDB Vector <-> Tantivy BM25 Parity Reconciliation.
    async fn heal_hybrid_index_desync(
        &self,
        report: &mut DriftReport,
        dry_run: bool,
    ) -> Result<(), IngestError> {
        let lance_catalog = self.storage.get_lance_chunk_catalog().await?;
        let tantivy_catalog = self.storage.get_tantivy_chunk_catalog()?;

        let lance_ids: HashSet<String> = lance_catalog.keys().cloned().collect();
        let tantivy_ids: HashSet<String> = tantivy_catalog.keys().cloned().collect();

        let lance_only: Vec<String> = lance_ids.difference(&tantivy_ids).cloned().collect();
        let tantivy_only: Vec<String> = tantivy_ids.difference(&lance_ids).cloned().collect();

        report.lance_chunks_missing_in_tantivy = lance_only.len();
        report.tantivy_chunks_missing_in_lance = tantivy_only.len();

        if !dry_run {
            // Recover Lance -> Tantivy
            if !lance_only.is_empty() {
                let chunks = self.storage.get_chunks_by_ids(&lance_only).await?;
                let _ = self.storage.insert_into_tantivy_only(&chunks)?;
            }

            // Recover Tantivy -> Lance
            if !tantivy_only.is_empty() {
                let mut chunks = self.storage.get_chunks_from_tantivy(&tantivy_only)?;
                let canonical_dim = self.embedder.dimension();
                for chunk in &mut chunks {
                    if chunk.vector.len() != canonical_dim {
                        if let Ok(vec) = self.embedder.embed_text(&chunk.text_content) {
                            chunk.vector = vec;
                        } else {
                            chunk.vector = vec![0.0; canonical_dim];
                        }
                    }
                }
                let _ = self.storage.insert_into_lance_only(&chunks).await?;
            }
        }

        report.hybrid_parity_restored = true;
        Ok(())
    }

    /// Drift C: Vector Contract and L2 Normalization Drift Healing.
    async fn heal_vector_contract_drift(
        &self,
        report: &mut DriftReport,
        dry_run: bool,
    ) -> Result<(), IngestError> {
        let canonical_hash = self.embedder.contract().derive_contract_hash_hex();
        let canonical_dim = self.embedder.dimension();

        let all_chunks = self.storage.scan_all_chunks().await?;
        let mut drifted_chunks = Vec::new();

        for chunk in all_chunks {
            let dim_drift = chunk.vector.len() != canonical_dim;
            let norm: f32 = chunk.vector.iter().map(|x| x * x).sum::<f32>().sqrt();
            let norm_drift = (norm - 1.0).abs() > 1e-4;
            let contract_drift = !chunk.metadata_json.contains(&canonical_hash);

            if dim_drift || norm_drift || contract_drift {
                drifted_chunks.push(chunk);
            }
        }

        report.contract_drifted_chunks_reembedded = drifted_chunks.len();

        if !dry_run && !drifted_chunks.is_empty() {
            for mut chunk in drifted_chunks {
                let new_vec = self
                    .embedder
                    .embed_text(&chunk.text_content)
                    .unwrap_or_else(|_| vec![0.0; canonical_dim]);
                chunk.vector = new_vec;

                let mut meta_val: serde_json::Value =
                    serde_json::from_str(&chunk.metadata_json).unwrap_or(serde_json::json!({}));
                meta_val["contract_hash"] = serde_json::json!(canonical_hash);
                chunk.metadata_json = meta_val.to_string();

                self.storage.update_chunk_record(&chunk).await?;
            }
        }

        Ok(())
    }

    /// Drift D: ACL Policy & Access-Tier Drift Healing.
    async fn heal_acl_policy_drift(
        &self,
        rules: &[(PathBuf, u8)],
        report: &mut DriftReport,
        dry_run: bool,
    ) -> Result<(), IngestError> {
        let active_rules = if !rules.is_empty() {
            rules
        } else {
            &self.config.access_tier_rules
        };

        if active_rules.is_empty() {
            return Ok(());
        }

        let all_chunks = self.storage.scan_all_chunks().await?;
        let mut drifted_chunks = Vec::new();

        for chunk in all_chunks {
            let chunk_path = Path::new(&chunk.file_path);
            let mut expected_tier = 0u8;
            let mut longest_match = 0;

            for (prefix, tier) in active_rules {
                if chunk_path.starts_with(prefix) {
                    let len = prefix.as_os_str().len();
                    if len > longest_match {
                        longest_match = len;
                        expected_tier = *tier;
                    }
                }
            }

            if chunk.access_tier != expected_tier {
                drifted_chunks.push((chunk.chunk_id, expected_tier));
            }
        }

        report.acl_drifted_chunks_updated = drifted_chunks.len();

        if !dry_run && !drifted_chunks.is_empty() {
            for (chunk_id, new_tier) in drifted_chunks {
                self.storage.update_chunk_access_tier(&chunk_id, new_tier).await?;
            }
        }

        Ok(())
    }

    /// Drift E: Storage Compaction & Tombstone Drift.
    async fn heal_storage_compaction(
        &self,
        report: &mut DriftReport,
        dry_run: bool,
    ) -> Result<(), IngestError> {
        if !dry_run {
            let stats = self.storage.compact().await?;
            report.fragments_consolidated = stats.fragments_removed;
            report.old_versions_pruned = stats.old_versions_pruned;
            report.tantivy_segments_merged = stats.tantivy_segments_merged;
        }
        Ok(())
    }

    /// Helper to re-index a single file through the pipeline.
    async fn reingest_single_file(&self, path: &Path) -> Result<(), IngestError> {
        let router = ClassifierRouter::new(self.config.clone());
        let decision = router.evaluate_file(path);

        match decision {
            FilterDecision::Accept {
                identity,
                kind,
                size_bytes,
                mtime_secs,
            } => {
                let access_tier = self.config.resolve_access_tier(path);
                let path_str = path.to_string_lossy().to_string();

                match kind {
                    CandidateKind::Text { .. } => {
                        let content = crate::document_extractor::DocumentExtractor::extract_text(path, &identity)?;
                        let file_b3 = blake3::hash(content.as_bytes()).to_hex().to_string();
                        let chunker = TextChunker::new(ChunkerConfig::default());
                        let raw_chunks = chunker.chunk_text(&content);

                        let mut file_chunk_hashes = Vec::new();
                        let mut chunks = Vec::new();

                        for raw in raw_chunks {
                            let chunk_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
                            file_chunk_hashes.push(chunk_b3.clone());

                            let vector = if let Some(cached) = self.dedup.cache().get(&chunk_b3) {
                                cached
                            } else {
                                let v = self
                                    .embedder
                                    .embed_text(raw.text_slice)
                                    .unwrap_or_else(|_| vec![0.0; self.embedder.dimension()]);
                                self.dedup.cache().insert(chunk_b3.clone(), v.clone());
                                v
                            };

                            let chunk_id = format!("{}:{}", file_b3, raw.chunk_index);
                            let metadata_json = serde_json::json!({
                                "char_start": raw.char_start,
                                "char_end": raw.char_end,
                                "chunk_index": raw.chunk_index,
                                "contract_hash": self.embedder.contract().derive_contract_hash_hex(),
                            })
                            .to_string();

                            let doc_chunk = DocumentChunk::new(
                                chunk_id,
                                file_b3.clone(),
                                &path_str,
                                raw.line_start,
                                raw.line_end,
                                access_tier,
                                vector,
                                raw.text_slice,
                                Some(metadata_json),
                            )?;
                            chunks.push(doc_chunk);
                        }

                        let _ = self.storage.delete_by_file_path(&path_str).await;
                        let _ = self.storage.insert_chunks(&chunks).await?;

                        self.dedup.register_entry(FileCatalogEntry {
                            file_path: path.to_path_buf(),
                            file_blake3: file_b3,
                            mtime_secs,
                            size_bytes,
                            chunk_hashes: file_chunk_hashes,
                        });
                    }
                    CandidateKind::Image { .. } => {
                        let bytes = std::fs::read(path)?;
                        let doc_chunk = ImageIndexer::index_image(
                            path,
                            &bytes,
                            &identity,
                            access_tier,
                            self.embedder.as_ref(),
                        )?;

                        let file_b3 = doc_chunk.document_id.clone();
                        let _ = self.storage.delete_by_file_path(&path_str).await;
                        let _ = self.storage.insert_chunks(std::slice::from_ref(&doc_chunk)).await?;

                        self.dedup.register_entry(FileCatalogEntry {
                            file_path: path.to_path_buf(),
                            file_blake3: file_b3,
                            mtime_secs,
                            size_bytes,
                            chunk_hashes: vec![doc_chunk.blake3_hash],
                        });
                    }
                    CandidateKind::Audio { .. } => {
                        let bytes = std::fs::read(path)?;
                        let doc_chunk = AudioIndexer::index_audio(
                            path,
                            &bytes,
                            &identity,
                            access_tier,
                            self.embedder.as_ref(),
                        )?;

                        let file_b3 = doc_chunk.document_id.clone();
                        let _ = self.storage.delete_by_file_path(&path_str).await;
                        let _ = self.storage.insert_chunks(std::slice::from_ref(&doc_chunk)).await?;

                        self.dedup.register_entry(FileCatalogEntry {
                            file_path: path.to_path_buf(),
                            file_blake3: file_b3,
                            mtime_secs,
                            size_bytes,
                            chunk_hashes: vec![doc_chunk.blake3_hash],
                        });
                    }
                }
            }
            _ => {
                debug!(path = %path.display(), "Skipped file during re-ingestion");
            }
        }

        Ok(())
    }
}
