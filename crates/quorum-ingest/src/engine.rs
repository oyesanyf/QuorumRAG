//! Unified Ingestion Engine Supervisor for QuorumRAG.
//!
//! Orchestrates the high-capacity crawler, real-time OS watcher, two-level BLAKE3
//! deduplication, Google Magika content inspection, image indexer, dedicated reindexer,
//! and 5-drift remediation worker into a single high-throughput supervisor.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::audio_indexer::AudioIndexer;
use crate::chunker::TextChunker;
use crate::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use crate::config::{ChunkerConfig, DriftFixOptions, IngestConfig, ReindexOptions};
use crate::dedup::{DedupAction, FileCatalogEntry, Level1DedupCatalog, TwoLevelDedupEngine};
use crate::document_extractor::DocumentExtractor;
use crate::drift_healer::DriftHealer;
use crate::error::IngestError;
use crate::image_indexer::ImageIndexer;
use crate::reindex::ReindexWorker;
use crate::watcher::{FilesystemWatcher, WatcherEvent, WatcherHandle};
use quorum_classifier::FileTypeClassifier;
use quorum_contract::EmbeddingGenerator;
use quorum_storage::StorageEngine;
use quorum_types::DocumentChunk;

/// High-throughput unified IngestEngine.
#[derive(Clone)]
pub struct IngestEngine {
    config: Arc<tokio::sync::RwLock<IngestConfig>>,
    storage: Arc<StorageEngine>,
    classifier: Arc<FileTypeClassifier>,
    embedder: Arc<dyn EmbeddingGenerator>,
    dedup: Arc<TwoLevelDedupEngine>,
    reindex_worker: Arc<ReindexWorker>,
    drift_healer: Arc<DriftHealer>,
    chunker: TextChunker,
    router: ClassifierRouter,
    dlp_gate: Arc<tokio::sync::RwLock<Option<Arc<dyn quorum_types::DlpContentGate>>>>,
    is_running: Arc<AtomicBool>,
}

impl IngestEngine {
    pub fn new(
        config: IngestConfig,
        storage: Arc<StorageEngine>,
        classifier: Arc<FileTypeClassifier>,
        embedder: Arc<dyn EmbeddingGenerator>,
    ) -> Result<Self, IngestError> {
        let dedup = Arc::new(TwoLevelDedupEngine::new());
        let reindex_worker = Arc::new(ReindexWorker::new(
            config.clone(),
            Arc::clone(&storage),
            Arc::clone(&classifier),
            Arc::clone(&embedder),
            Arc::clone(&dedup),
        ));
        let drift_healer = Arc::new(
            DriftHealer::new(
                config.clone(),
                Arc::clone(&storage),
                Arc::clone(&classifier),
                Arc::clone(&embedder),
                Arc::clone(&dedup),
            )
            .with_reindex_barrier(&reindex_worker),
        );
        let chunker = TextChunker::new(ChunkerConfig::default());
        let router = ClassifierRouter::new(config.clone());

        Ok(Self {
            config: Arc::new(tokio::sync::RwLock::new(config)),
            storage,
            classifier,
            embedder,
            dedup,
            reindex_worker,
            drift_healer,
            chunker,
            router,
            dlp_gate: Arc::new(tokio::sync::RwLock::new(None)),
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Attaches a fail-closed `DlpContentGate` across `IngestEngine`, `ReindexWorker`, and `DriftHealer`.
    pub fn with_dlp_gate(mut self, gate: Arc<dyn quorum_types::DlpContentGate>) -> Self {
        self.dlp_gate = Arc::new(tokio::sync::RwLock::new(Some(Arc::clone(&gate))));
        self.reindex_worker.set_dlp_gate_try(Arc::clone(&gate));
        self.drift_healer.set_dlp_gate_try(gate);
        self
    }

    pub async fn config_snapshot(&self) -> IngestConfig {
        self.config.read().await.clone()
    }

    pub async fn set_dlp_gate(&self, gate: Option<Arc<dyn quorum_types::DlpContentGate>>) {
        *self.dlp_gate.write().await = gate.clone();
        self.reindex_worker.set_dlp_gate(gate.clone()).await;
        self.drift_healer.set_dlp_gate(gate).await;
    }

    pub async fn update_placeholder_policy(&self, policy: quorum_types::CloudPlaceholderPolicy) {
        self.config.write().await.placeholder_policy = policy;
        self.reindex_worker.update_placeholder_policy(policy).await;
        self.drift_healer.update_placeholder_policy(policy).await;
    }

    pub async fn update_max_file_size_bytes(&self, max_file_size_bytes: u64) {
        let bounded = max_file_size_bytes.max(1);
        self.config.write().await.max_file_size_bytes = bounded;
        self.reindex_worker
            .update_max_file_size_bytes(bounded)
            .await;
        self.drift_healer.update_max_file_size_bytes(bounded).await;
    }

    pub async fn update_access_tier_rules(
        &self,
        rules: Vec<(std::path::PathBuf, u8)>,
    ) -> Result<(), IngestError> {
        let mut normalized = Vec::with_capacity(rules.len());
        for (prefix, tier) in &rules {
            quorum_types::AccessTier::from_u8(*tier)?;
            let norm = quorum_types::normalize_prefix_for_match(&prefix.to_string_lossy())?;
            normalized.push((std::path::PathBuf::from(norm), *tier));
        }
        self.config.write().await.access_tier_rules = normalized;
        self.reindex_worker
            .update_access_tier_rules(rules.clone())
            .await?;
        self.drift_healer.update_access_tier_rules(rules).await?;
        Ok(())
    }

    pub async fn remove_watch_paths(&self, paths: &[std::path::PathBuf]) {
        let prefixes: Vec<std::path::PathBuf> = paths
            .iter()
            .filter(|p| {
                !crate::config::normalize_path_for_prefix(p)
                    .as_os_str()
                    .is_empty()
            })
            .cloned()
            .collect();
        if !prefixes.is_empty() {
            self.config.write().await.watch_paths.retain(|w| {
                !prefixes
                    .iter()
                    .any(|r| crate::config::path_matches_prefix(w, r))
            });
        }
        self.reindex_worker.remove_watch_paths(paths).await;
        self.drift_healer.remove_watch_paths(paths).await;
    }

    pub fn storage(&self) -> &Arc<StorageEngine> {
        &self.storage
    }

    pub fn dedup(&self) -> &Arc<TwoLevelDedupEngine> {
        &self.dedup
    }

    pub fn reindex_worker(&self) -> &Arc<ReindexWorker> {
        &self.reindex_worker
    }

    pub fn drift_healer(&self) -> &Arc<DriftHealer> {
        &self.drift_healer
    }

    /// Ingests a single file synchronously: verifies blocked prefixes, size, Magika category,
    /// Level-1 catalog, Level-2 chunk cache, SecretScrubber + DlpContentGate, and writes to storage
    /// under `commit_gate.read().await`.
    pub async fn ingest_file(
        &self,
        path: &Path,
    ) -> Result<Option<Vec<DocumentChunk>>, IngestError> {
        let task_purge_epoch = self.reindex_worker.current_purge_epoch();
        if self.reindex_worker.is_path_blocked(path) {
            return Err(IngestError::Cancelled);
        }

        let cfg_snapshot = self.config.read().await.clone();
        let dlp_gate = self.dlp_gate.read().await.clone();
        let decision = self.router.evaluate_file_with_config(path, &cfg_snapshot);

        let (identity, kind, size_bytes, mtime_secs) = match decision {
            FilterDecision::Accept {
                identity,
                kind,
                size_bytes,
                mtime_secs,
            } => (identity, kind, size_bytes, mtime_secs),
            _ => return Ok(None),
        };

        let placeholder_policy = cfg_snapshot.placeholder_policy;

        // Level-1 Evaluation
        let precomputed_file_b3 = match self.dedup.evaluate_file_with_policy(
            path,
            mtime_secs,
            size_bytes,
            placeholder_policy,
        )? {
            DedupAction::Unchanged { .. } => {
                return Ok(Some(Vec::new()));
            }
            DedupAction::MovedOrRenamed {
                old_path,
                new_path,
                file_blake3,
                ..
            } => {
                let _commit_guard = self.reindex_worker.acquire_commit_read_guard().await;
                let old_key = old_path.to_string_lossy().to_string();
                let _ = self.storage.delete_by_file_path(&old_key).await;
                self.dedup.remove_file(&old_path);
                if self.reindex_worker.current_purge_epoch() != task_purge_epoch
                    || self.reindex_worker.is_path_blocked(path)
                    || self.reindex_worker.is_path_blocked(&new_path)
                {
                    return Err(IngestError::Cancelled);
                }
                info!(old = %old_path.display(), new = %new_path.display(), "Detected moved/renamed file; purging old path and re-indexing under new path/tier (L2 vector cache reused)");
                Some(file_blake3)
            }
            DedupAction::ModifiedOrNew { file_blake3, .. } => Some(file_blake3),
        };

        if self.reindex_worker.current_purge_epoch() != task_purge_epoch
            || self.reindex_worker.is_path_blocked(path)
        {
            return Err(IngestError::Cancelled);
        }

        let access_tier = cfg_snapshot.resolve_access_tier(path);
        let path_str = path.to_string_lossy().to_string();

        let ext_permit = crate::thread_pool::IngestThreadPool::shared()
            .permit_tiers()
            .acquire_extraction()
            .await?;

        if self.reindex_worker.current_purge_epoch() != task_purge_epoch
            || self.reindex_worker.is_path_blocked(path)
        {
            return Err(IngestError::Cancelled);
        }

        let chunks = match kind {
            CandidateKind::Text { .. } => {
                let path_buf = path.to_path_buf();
                let identity = identity.clone();
                let chunker = self.chunker.clone();
                let embedder = Arc::clone(&self.embedder);
                let dedup_cache = self.dedup.cache().clone();
                let path_str_c = path_str.clone();
                let dlp_gate_c = dlp_gate.clone();

                let (content, file_b3, doc_chunks, file_chunk_hashes, parent_doc_opt) =
                    crate::thread_pool::IngestThreadPool::shared()
                        .spawn_blocking_pinned(ext_permit, move || -> Result<_, IngestError> {
                            let raw_content = DocumentExtractor::extract_text_with_policy(
                                &path_buf,
                                &identity,
                                placeholder_policy,
                            )?;
                            if raw_content.is_empty() {
                                return Ok((raw_content, String::new(), Vec::new(), Vec::new(), None));
                            }

                            let content = crate::secret_scrubber::sanitize_and_gate_text(
                                &path_str_c,
                                &raw_content,
                                access_tier,
                                dlp_gate_c.as_deref(),
                            )
                            .map_err(|reason| IngestError::DlpBlocked {
                                path: path_buf.clone(),
                                reason,
                            })?;

                            let file_b3 = match precomputed_file_b3 {
                                Some(b3) => b3,
                                None => Level1DedupCatalog::hash_file_stream_with_policy(
                                    &path_buf,
                                    placeholder_policy,
                                )
                                .unwrap_or_else(|_| blake3::hash(content.as_bytes()).to_hex().to_string()),
                            };
                            let raw_chunks = chunker.chunk_text_structure_aware(&content);

                            let mut file_chunk_hashes = Vec::with_capacity(raw_chunks.len());
                            let mut doc_chunks = Vec::with_capacity(raw_chunks.len());
                            let mut resolved_meta = crate::chunker::resolve_document_metadata_with_policy(
                                &path_buf,
                                &content,
                                placeholder_policy,
                            );
                            crate::secret_scrubber::sanitize_and_gate_resolved_metadata(
                                &path_str_c,
                                &mut resolved_meta,
                                access_tier,
                                dlp_gate_c.as_deref(),
                            )
                            .map_err(|reason| IngestError::DlpBlocked {
                                path: path_buf.clone(),
                                reason,
                            })?;
                            let header = crate::chunker::format_contextual_header_from_meta(&resolved_meta);

                            let parent_doc_opt = if !raw_chunks.is_empty() {
                                let mut pdoc = DocumentExtractor::build_ingested_parent_document_with_policy(
                                    &path_buf,
                                    &file_b3,
                                    &file_b3,
                                    &content,
                                    mtime_secs,
                                    size_bytes,
                                    None,
                                    placeholder_policy,
                                );
                                crate::secret_scrubber::sanitize_and_gate_parent_document(
                                    &mut pdoc,
                                    access_tier,
                                    dlp_gate_c.as_deref(),
                                )
                                .map_err(|reason| IngestError::DlpBlocked {
                                    path: path_buf.clone(),
                                    reason,
                                })?;
                                Some(pdoc)
                            } else {
                                None
                            };

                            for raw in raw_chunks {
                                let raw_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
                                let chunk_content = crate::chunker::prepend_contextual_header_with_section(
                                    &header,
                                    &raw.section_path,
                                    raw.text_slice,
                                );
                                let _chunk_b3 = DocumentChunk::compute_blake3_hash(&chunk_content);
                                file_chunk_hashes.push(raw_b3.clone());

                                // Level-2 Evaluation
                                let vector = if let Some(cached) = dedup_cache.get(&raw_b3) {
                                    cached
                                } else {
                                    let vec = embedder
                                        .embed_text(raw.text_slice)
                                        .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                                    dedup_cache.insert(raw_b3.clone(), vec.clone());
                                    vec
                                };

                                let chunk_id = format!("{}:{}", file_b3, raw.chunk_index);
                                let metadata_json = serde_json::json!({
                                    "char_start": raw.char_start,
                                    "char_end": raw.char_end,
                                    "chunk_index": raw.chunk_index,
                                    "contract_hash": embedder.contract().derive_contract_hash_hex(),
                                    "parent_doc_id": file_b3.clone(),
                                    "parent_chunk_id": format!("{}:p{}", file_b3, raw.parent_chunk_index),
                                    "heading_path": raw.section_path,
                                    "section_path": raw.section_path,
                                    "section_title": raw.section_title,
                                    "section_hierarchy": raw.section_hierarchy,
                                    "section_level": raw.section_level,
                                    "source_path": path_str_c.clone(),
                                })
                                .to_string();

                                let doc_chunk = DocumentChunk::new(
                                    chunk_id,
                                    file_b3.clone(),
                                    &path_str_c,
                                    raw.line_start,
                                    raw.line_end,
                                    access_tier,
                                    vector,
                                    &chunk_content,
                                    Some(metadata_json),
                                )?;
                                doc_chunks.push(doc_chunk);
                            }

                            Ok((content, file_b3, doc_chunks, file_chunk_hashes, parent_doc_opt))
                        })
                        .await??;

                if content.is_empty() {
                    return Ok(Some(Vec::new()));
                }

                if self.reindex_worker.current_purge_epoch() != task_purge_epoch
                    || self.reindex_worker.is_path_blocked(path)
                {
                    return Err(IngestError::Cancelled);
                }

                let _commit_permit = crate::thread_pool::IngestThreadPool::shared()
                    .permit_tiers()
                    .acquire_storage_commit()
                    .await?;
                let _commit_guard = self.reindex_worker.acquire_commit_read_guard().await;
                if self.reindex_worker.current_purge_epoch() != task_purge_epoch
                    || self.reindex_worker.is_path_blocked(path)
                {
                    return Err(IngestError::Cancelled);
                }

                let _ = self.storage.delete_by_file_path(&path_str).await;
                if !doc_chunks.is_empty() {
                    let _ = self.storage.insert_chunks(&doc_chunks).await?;
                    if let Some(ref parent_doc) = parent_doc_opt {
                        let _ = self.storage.upsert_parent_document(parent_doc, access_tier);
                    }
                }

                self.dedup.register_entry(FileCatalogEntry {
                    file_path: path.to_path_buf(),
                    file_blake3: file_b3,
                    mtime_secs,
                    size_bytes,
                    chunk_hashes: file_chunk_hashes,
                });

                doc_chunks
            }
            CandidateKind::Image { .. } => {
                let path_buf = path.to_path_buf();
                let identity = identity.clone();
                let embedder = Arc::clone(&self.embedder);
                let path_str_c = path_str.clone();
                let dlp_gate_c = dlp_gate.clone();

                let image_res = crate::thread_pool::IngestThreadPool::shared()
                    .spawn_blocking_pinned(ext_permit, move || -> Result<_, IngestError> {
                        let bytes = crate::cloud_drives::read_bytes_with_placeholder_policy(
                            &path_buf,
                            placeholder_policy,
                        )?;
                        let mut doc_chunk = ImageIndexer::index_image_with_policy(
                            &path_buf,
                            &bytes,
                            &identity,
                            access_tier,
                            embedder.as_ref(),
                            placeholder_policy,
                        )?;
                        let gated_text = crate::secret_scrubber::sanitize_and_gate_text(
                            &path_str_c,
                            &doc_chunk.text_content,
                            access_tier,
                            dlp_gate_c.as_deref(),
                        )
                        .map_err(|reason| IngestError::DlpBlocked {
                            path: path_buf.clone(),
                            reason,
                        })?;
                        doc_chunk.metadata_json =
                            crate::secret_scrubber::sanitize_and_gate_metadata_json(
                                &path_str_c,
                                &doc_chunk.metadata_json,
                                access_tier,
                                dlp_gate_c.as_deref(),
                            )
                            .map_err(|reason| {
                                IngestError::DlpBlocked {
                                    path: path_buf.clone(),
                                    reason,
                                }
                            })?;
                        if gated_text != doc_chunk.text_content {
                            doc_chunk.text_content = gated_text;
                            doc_chunk.blake3_hash =
                                DocumentChunk::compute_blake3_hash(&doc_chunk.text_content);
                            doc_chunk.vector = embedder
                                .embed_text(&doc_chunk.text_content)
                                .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                        }
                        let file_b3 = doc_chunk.document_id.clone();
                        Ok((doc_chunk, file_b3))
                    })
                    .await?;
                let (doc_chunk, file_b3) = match image_res {
                    Ok(pair) => pair,
                    Err(IngestError::TypeError(
                        quorum_types::TypeError::ContentSafetyBlocked(reason),
                    )) => {
                        let _commit_guard = self.reindex_worker.acquire_commit_read_guard().await;
                        let _ = self.storage.delete_by_file_path(&path_str).await;
                        self.dedup.remove_file(path);
                        return Err(IngestError::TypeError(
                            quorum_types::TypeError::ContentSafetyBlocked(reason),
                        ));
                    }
                    Err(e) => return Err(e),
                };

                if self.reindex_worker.current_purge_epoch() != task_purge_epoch
                    || self.reindex_worker.is_path_blocked(path)
                {
                    return Err(IngestError::Cancelled);
                }

                let _commit_permit = crate::thread_pool::IngestThreadPool::shared()
                    .permit_tiers()
                    .acquire_storage_commit()
                    .await?;
                let _commit_guard = self.reindex_worker.acquire_commit_read_guard().await;
                if self.reindex_worker.current_purge_epoch() != task_purge_epoch
                    || self.reindex_worker.is_path_blocked(path)
                {
                    return Err(IngestError::Cancelled);
                }

                let _ = self.storage.delete_by_file_path(&path_str).await;
                let _ = self
                    .storage
                    .insert_chunks(std::slice::from_ref(&doc_chunk))
                    .await?;
                let parent_doc = DocumentExtractor::build_ingested_parent_document_with_policy(
                    path,
                    &file_b3,
                    &file_b3,
                    &doc_chunk.text_content,
                    mtime_secs,
                    size_bytes,
                    Some(quorum_types::DocumentFormat::ImageFile),
                    placeholder_policy,
                );
                let _ = self
                    .storage
                    .upsert_parent_document(&parent_doc, access_tier);

                self.dedup.register_entry(FileCatalogEntry {
                    file_path: path.to_path_buf(),
                    file_blake3: file_b3,
                    mtime_secs,
                    size_bytes,
                    chunk_hashes: vec![doc_chunk.blake3_hash.clone()],
                });

                vec![doc_chunk]
            }
            CandidateKind::Audio { .. } => {
                let path_buf = path.to_path_buf();
                let identity = identity.clone();
                let embedder = Arc::clone(&self.embedder);
                let path_str_c = path_str.clone();
                let dlp_gate_c = dlp_gate.clone();

                let (doc_chunk, file_b3) = crate::thread_pool::IngestThreadPool::shared()
                    .spawn_blocking_pinned(ext_permit, move || -> Result<_, IngestError> {
                        let bytes = crate::cloud_drives::read_bytes_with_placeholder_policy(
                            &path_buf,
                            placeholder_policy,
                        )?;
                        let mut doc_chunk = AudioIndexer::index_audio_with_policy(
                            &path_buf,
                            &bytes,
                            &identity,
                            access_tier,
                            embedder.as_ref(),
                            placeholder_policy,
                        )?;
                        let gated_text = crate::secret_scrubber::sanitize_and_gate_text(
                            &path_str_c,
                            &doc_chunk.text_content,
                            access_tier,
                            dlp_gate_c.as_deref(),
                        )
                        .map_err(|reason| IngestError::DlpBlocked {
                            path: path_buf.clone(),
                            reason,
                        })?;
                        doc_chunk.metadata_json =
                            crate::secret_scrubber::sanitize_and_gate_metadata_json(
                                &path_str_c,
                                &doc_chunk.metadata_json,
                                access_tier,
                                dlp_gate_c.as_deref(),
                            )
                            .map_err(|reason| {
                                IngestError::DlpBlocked {
                                    path: path_buf.clone(),
                                    reason,
                                }
                            })?;
                        if gated_text != doc_chunk.text_content {
                            doc_chunk.text_content = gated_text;
                            doc_chunk.blake3_hash =
                                DocumentChunk::compute_blake3_hash(&doc_chunk.text_content);
                            doc_chunk.vector = embedder
                                .embed_text(&doc_chunk.text_content)
                                .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                        }
                        let file_b3 = doc_chunk.document_id.clone();
                        Ok((doc_chunk, file_b3))
                    })
                    .await??;

                if self.reindex_worker.current_purge_epoch() != task_purge_epoch
                    || self.reindex_worker.is_path_blocked(path)
                {
                    return Err(IngestError::Cancelled);
                }

                let _commit_permit = crate::thread_pool::IngestThreadPool::shared()
                    .permit_tiers()
                    .acquire_storage_commit()
                    .await?;
                let _commit_guard = self.reindex_worker.acquire_commit_read_guard().await;
                if self.reindex_worker.current_purge_epoch() != task_purge_epoch
                    || self.reindex_worker.is_path_blocked(path)
                {
                    return Err(IngestError::Cancelled);
                }

                let _ = self.storage.delete_by_file_path(&path_str).await;
                let _ = self
                    .storage
                    .insert_chunks(std::slice::from_ref(&doc_chunk))
                    .await?;

                self.dedup.register_entry(FileCatalogEntry {
                    file_path: path.to_path_buf(),
                    file_blake3: file_b3,
                    mtime_secs,
                    size_bytes,
                    chunk_hashes: vec![doc_chunk.blake3_hash.clone()],
                });

                vec![doc_chunk]
            }
        };

        Ok(Some(chunks))
    }

    /// Handles a real-time event from the OS watcher.
    pub async fn handle_watcher_event(&self, event: WatcherEvent) -> Result<bool, IngestError> {
        let mut storage_mutated = false;

        match event {
            WatcherEvent::Create(path) | WatcherEvent::Modify(path) => {
                if path.is_file() {
                    match self.ingest_file(&path).await {
                        Ok(Some(chunks)) if !chunks.is_empty() => storage_mutated = true,
                        Ok(_) | Err(IngestError::Cancelled) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            WatcherEvent::Remove(path) => {
                let path_str = path.to_string_lossy().to_string();
                let mut count = self.storage.delete_by_file_path(&path_str).await?;
                self.dedup.remove_file(&path);

                // Handle directory deletion: purge all tracked children under path (boundary-safe)
                let tracked = self.dedup.get_all_tracked_files();
                for tracked_file in tracked {
                    if crate::config::path_matches_prefix(&tracked_file, &path) {
                        let tracked_str = tracked_file.to_string_lossy().to_string();
                        let c = self
                            .storage
                            .delete_by_file_path(&tracked_str)
                            .await
                            .unwrap_or(0);
                        count += c;
                    }
                }
                self.dedup.remove_by_prefix(&path);

                if count > 0 {
                    storage_mutated = true;
                }
                debug!(path = %path.display(), count, "Removed deleted file or directory from storage and catalog");
            }
            WatcherEvent::Rename { from, to } => {
                if to.is_dir() {
                    // Directory Rename:
                    // 1. Delete all chunks and catalog entries with old path prefix (boundary-safe)
                    let tracked = self.dedup.get_all_tracked_files();
                    for tracked_file in tracked {
                        if crate::config::path_matches_prefix(&tracked_file, &from) {
                            let old_str = tracked_file.to_string_lossy().to_string();
                            let c = self
                                .storage
                                .delete_by_file_path(&old_str)
                                .await
                                .unwrap_or(0);
                            if c > 0 {
                                storage_mutated = true;
                            }
                        }
                    }
                    self.dedup.remove_by_prefix(&from);

                    // 2. Recursively index all files under the new directory path using work-stealing parallel discovery
                    let files_to_index = {
                        let (tx_files, rx_files) = std::sync::mpsc::channel();
                        let walker = ignore::WalkBuilder::new(&to)
                            .hidden(false)
                            .ignore(false)
                            .git_global(false)
                            .git_ignore(false)
                            .git_exclude(false)
                            .build_parallel();
                        walker.run(move || {
                            let tx_files = tx_files.clone();
                            Box::new(move |res| {
                                if let Ok(entry) = res {
                                    if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                                        let _ = tx_files.send(entry.into_path());
                                    }
                                }
                                ignore::WalkState::Continue
                            })
                        });
                        rx_files.into_iter().collect::<Vec<_>>()
                    };

                    for new_file_path in files_to_index {
                        match self.ingest_file(&new_file_path).await {
                            Ok(Some(chunks)) if !chunks.is_empty() => storage_mutated = true,
                            Ok(_) | Err(IngestError::Cancelled) => {}
                            Err(e) => return Err(e),
                        }
                    }
                } else {
                    // Single File Rename:
                    let from_str = from.to_string_lossy().to_string();
                    let count = self.storage.delete_by_file_path(&from_str).await?;
                    self.dedup.remove_file(&from);
                    if count > 0 {
                        storage_mutated = true;
                    }
                    if to.is_file() {
                        match self.ingest_file(&to).await {
                            Ok(Some(chunks)) if !chunks.is_empty() => storage_mutated = true,
                            Ok(_) | Err(IngestError::Cancelled) => {}
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
            WatcherEvent::QueueOverflow { root, details } => {
                warn!(root = %root.display(), details = %details, "Watcher queue overflow detected; scheduling drift remediation");
                let healer = Arc::clone(&self.drift_healer);
                tokio::spawn(async move {
                    let _ = healer.fix_all_drifts(DriftFixOptions::default()).await;
                });
            }
        }

        if storage_mutated {
            let _ = self
                .storage
                .bump_index_epoch("watcher_filesystem_mutation")?;
        }

        Ok(storage_mutated)
    }

    /// Starts the real-time continuous ingestion daemon with OS watcher and periodic drift healer.
    pub async fn start_daemon(&self) -> Result<WatcherHandle, IngestError> {
        self.is_running.store(true, Ordering::SeqCst);
        let cfg_snapshot = self.config.read().await.clone();

        // 1. Initial crawl across watch paths
        for root in &cfg_snapshot.watch_paths {
            if root.exists() {
                let _ = self
                    .reindex_worker
                    .run_reindex_sync(ReindexOptions {
                        target_paths: vec![root.clone()],
                        full_rebuild: false,
                        ..Default::default()
                    })
                    .await;
            }
        }

        // 2. Start OS watcher
        let watcher = FilesystemWatcher::new(cfg_snapshot.clone());
        let (mut event_rx, handle) = watcher.start_watching()?;

        // 3. Spawn background event loop sharing live config, dedup, and dlp_gate
        let is_running = Arc::clone(&self.is_running);
        let engine_for_events = self.clone();

        tokio::spawn(async move {
            while is_running.load(Ordering::SeqCst) {
                tokio::select! {
                    maybe_event = event_rx.recv() => {
                        match maybe_event {
                            Some(event) => {
                                if let Err(e) = engine_for_events.handle_watcher_event(event).await {
                                    warn!("Error handling watcher event: {}", e);
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        // 4. Spawn periodic drift healer if configured
        if let Some(interval_secs) = cfg_snapshot.auto_drift_heal_interval_secs {
            let healer = Arc::clone(&self.drift_healer);
            let is_running = Arc::clone(&self.is_running);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
                while is_running.load(Ordering::SeqCst) {
                    interval.tick().await;
                    let _ = healer.fix_all_drifts(DriftFixOptions::default()).await;
                }
            });
        }

        Ok(handle)
    }

    /// Graceful shutdown of the ingestion engine.
    pub fn shutdown(&self) {
        self.is_running.store(false, Ordering::SeqCst);
        self.reindex_worker.cancel_reindex();
    }
}
