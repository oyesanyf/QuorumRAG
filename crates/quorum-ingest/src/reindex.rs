//! Dedicated Reindexing Worker for QuorumRAG.
//!
//! Traverses target directories supporting both incremental (`mtime` + Level 1 BLAKE3
//! comparison -> 0 neural calls for untouched/renamed files) and full rebuild (`--full`) modes.
//! Provides asynchronous background task management, cooperative cancellation, and live telemetry.

use chrono::{DateTime, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use crate::classifier_router::CandidateKind;
use crate::chunker::TextChunker;
use crate::config::{ChunkerConfig, IngestConfig, ReindexOptions};
use crate::crawler::{DiscoveredCandidate, FilesystemCrawler};
use crate::dedup::{DedupAction, FileCatalogEntry, Level1DedupCatalog, TwoLevelDedupEngine};
use crate::document_extractor::DocumentExtractor;
use crate::audio_indexer::AudioIndexer;
use crate::error::IngestError;
use crate::image_indexer::ImageIndexer;
use quorum_classifier::FileTypeClassifier;
use quorum_contract::EmbeddingGenerator;
use quorum_storage::StorageEngine;
use quorum_types::DocumentChunk;

/// Current execution phase of the reindex worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReindexPhase {
    Idle,
    ScanningFilesystem,
    ChunkingAndVectorizing,
    WritingToStorage,
    CompactingIndexes,
    Completed,
    Failed,
    Cancelled,
}

/// Live telemetry and progress statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReindexProgress {
    pub task_id: Uuid,
    pub phase: ReindexPhase,
    pub full_rebuild: bool,
    pub files_scanned: usize,
    pub files_total_estimated: usize,
    pub files_indexed: usize,
    pub files_skipped_unmodified: usize,
    pub files_failed: usize,
    pub chunks_reused_from_cache: usize,
    pub chunks_newly_embedded: usize,
    pub bytes_processed: u64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub elapsed_secs: u64,
    pub error_message: Option<String>,
}

/// Dedicated Reindex Worker.
pub struct ReindexWorker {
    config: IngestConfig,
    storage: Arc<StorageEngine>,
    classifier: Arc<FileTypeClassifier>,
    embedder: Arc<dyn EmbeddingGenerator>,
    dedup: Arc<TwoLevelDedupEngine>,
    active_task: Arc<RwLock<Option<ReindexProgress>>>,
    cancel_flag: Arc<AtomicBool>,
}

impl ReindexWorker {
    pub fn new(
        mut config: IngestConfig,
        storage: Arc<StorageEngine>,
        classifier: Arc<FileTypeClassifier>,
        embedder: Arc<dyn EmbeddingGenerator>,
        dedup: Arc<TwoLevelDedupEngine>,
    ) -> Self {
        let storage_path = storage.config().storage_path.clone();
        if !config.excluded_paths.iter().any(|p| p == &storage_path) {
            config.excluded_paths.push(storage_path);
        }
        if let Some(ref cat_path) = config.dedup_catalog_path {
            if let Some(parent) = cat_path.parent() {
                let parent_buf = parent.to_path_buf();
                if !parent_buf.as_os_str().is_empty() && !config.excluded_paths.iter().any(|p| p == &parent_buf) {
                    config.excluded_paths.push(parent_buf);
                }
            }
        }
        Self {
            config,
            storage,
            classifier,
            embedder,
            dedup,
            active_task: Arc::new(RwLock::new(None)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
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

    /// Triggers an asynchronous reindex task, returning immediately with a task UUID.
    pub async fn start_reindex(&self, options: ReindexOptions) -> Result<Uuid, IngestError> {
        let mut active = self.active_task.write().await;
        if let Some(ref current) = *active {
            if matches!(
                current.phase,
                ReindexPhase::ScanningFilesystem
                    | ReindexPhase::ChunkingAndVectorizing
                    | ReindexPhase::WritingToStorage
                    | ReindexPhase::CompactingIndexes
            ) {
                return Err(IngestError::TaskAlreadyRunning(
                    "Reindexing task already in progress".into(),
                ));
            }
        }

        let task_id = Uuid::new_v4();
        self.cancel_flag.store(false, Ordering::SeqCst);

        let initial_progress = ReindexProgress {
            task_id,
            phase: ReindexPhase::ScanningFilesystem,
            full_rebuild: options.full_rebuild,
            files_scanned: 0,
            files_total_estimated: 0,
            files_indexed: 0,
            files_skipped_unmodified: 0,
            files_failed: 0,
            chunks_reused_from_cache: 0,
            chunks_newly_embedded: 0,
            bytes_processed: 0,
            started_at: Utc::now(),
            completed_at: None,
            elapsed_secs: 0,
            error_message: None,
        };
        *active = Some(initial_progress);
        drop(active);

        let worker_config = self.config.clone();
        let worker_storage = Arc::clone(&self.storage);
        let worker_classifier = Arc::clone(&self.classifier);
        let worker_embedder = Arc::clone(&self.embedder);
        let worker_dedup = Arc::clone(&self.dedup);
        let worker_progress = Arc::clone(&self.active_task);
        let cancel_flag = Arc::clone(&self.cancel_flag);

        tokio::spawn(async move {
            let res = Self::execute_pipeline(
                worker_config,
                options,
                task_id,
                worker_storage,
                worker_classifier,
                worker_embedder,
                worker_dedup,
                worker_progress.clone(),
                cancel_flag,
            )
            .await;

            let mut final_lock = worker_progress.write().await;
            if let Some(ref mut prog) = *final_lock {
                prog.completed_at = Some(Utc::now());
                prog.elapsed_secs = (Utc::now() - prog.started_at).num_seconds().max(0) as u64;
                match res {
                    Ok(_) => prog.phase = ReindexPhase::Completed,
                    Err(IngestError::Cancelled) => prog.phase = ReindexPhase::Cancelled,
                    Err(e) => {
                        prog.phase = ReindexPhase::Failed;
                        prog.error_message = Some(e.to_string());
                    }
                }
            }
        });

        Ok(task_id)
    }

    /// Delete previously stored chunks for every file in this batch so re-indexed files are replaced,
    /// not duplicated (e.g. an image re-indexed with new GPS/location metadata).
    async fn replace_existing_file_chunks(storage: &StorageEngine, batch: &[DocumentChunk]) {
        let mut paths: Vec<String> = batch.iter().map(|c| c.file_path.clone()).collect();
        paths.sort();
        paths.dedup();
        if let Err(e) = storage.delete_by_file_paths(&paths).await {
            warn!("Failed to remove stale chunks before reindex insert: {}", e);
        }
    }

    /// Scans stored chunks, identifies legacy image chunks lacking OCR text,
    /// re-indexes them using ImageIndexer, and replaces them in storage
    /// preserving the exact chunk ID formula {file_b3}:img:0 without re-downloading.
    pub async fn upgrade_legacy_image_chunks(&self) -> Result<usize, IngestError> {
        let all_chunks = self.storage.scan_all_chunks().await?;
        let mut upgraded_count = 0;

        for chunk in &all_chunks {
            let is_image = chunk.chunk_id.ends_with(":img:0")
                || chunk.text_content.trim_start().starts_with("[Image Document:");
            if !is_image {
                continue;
            }

            // Upgrade legacy image chunks missing either OCR text or Multimodal Vision caption
            let has_ocr = chunk.text_content.contains("[OCR Text]");
            let has_vision = chunk.text_content.contains("[Visual Description]");
            if has_ocr && has_vision {
                continue;
            }

            let file_path = std::path::Path::new(&chunk.file_path);
            if !file_path.exists() {
                continue;
            }

            let bytes = match std::fs::read(file_path) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Verify file hash matches document_id
            let file_b3 = blake3::hash(&bytes).to_hex().to_string();
            if file_b3 != chunk.document_id {
                // File content changed on disk; normal reindexer will handle it
                continue;
            }

            let identity = match self.classifier.classify_file(file_path) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let access_tier = self.config.resolve_access_tier(file_path);

            if let Ok(upgraded_chunk) = ImageIndexer::index_image(
                file_path,
                &bytes,
                &identity,
                access_tier,
                self.embedder.as_ref(),
            ) {
                // Ensure chunk_id and document_id are strictly preserved
                assert_eq!(upgraded_chunk.chunk_id, chunk.chunk_id);
                assert_eq!(upgraded_chunk.document_id, chunk.document_id);

                // Collect other chunks sharing this file_path so they are retained across replacement
                let other_chunks: Vec<DocumentChunk> = all_chunks
                    .iter()
                    .filter(|c| c.file_path == chunk.file_path && c.chunk_id != chunk.chunk_id)
                    .cloned()
                    .collect();

                // Replace stale chunk in LanceDB and Tantivy
                Self::replace_existing_file_chunks(&self.storage, std::slice::from_ref(&upgraded_chunk)).await;
                let mut chunks_to_insert = vec![upgraded_chunk.clone()];
                chunks_to_insert.extend(other_chunks);
                self.storage.insert_chunks(&chunks_to_insert).await?;

                let mtime_secs = std::fs::metadata(file_path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let parent_doc = DocumentExtractor::build_ingested_parent_document(
                    file_path,
                    &upgraded_chunk.document_id,
                    &upgraded_chunk.document_id,
                    &upgraded_chunk.text_content,
                    mtime_secs,
                    bytes.len() as u64,
                    Some(quorum_types::DocumentFormat::ImageFile),
                );
                let _ = self.storage.upsert_parent_document(&parent_doc, access_tier);

                self.dedup.register_entry(FileCatalogEntry {
                    file_path: file_path.to_path_buf(),
                    file_blake3: file_b3,
                    mtime_secs,
                    size_bytes: bytes.len() as u64,
                    chunk_hashes: vec![upgraded_chunk.blake3_hash],
                });

                upgraded_count += 1;
            }
        }

        if upgraded_count > 0 {
            let _ = self.storage.bump_index_epoch("image_chunks_ocr_upgraded");
        }

        Ok(upgraded_count)
    }

    /// Scans stored chunks at daemon startup for `.docx`, `.odt`, `.xlsx`, `.pptx`, or `.pdf` files
    /// that were previously indexed via degraded fallbacks (e.g. raw PKZIP central directory XML
    /// filenames `[Content_Types].xml` / `word/document.xml` or body-less PDF trailer metadata),
    /// re-extracts them using the native Rust `DocumentExtractor`, and replaces them in storage.
    pub async fn upgrade_degraded_document_chunks(&self) -> Result<usize, IngestError> {
        let all_chunks = self.storage.scan_all_chunks().await?;
        let mut degraded_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

        for chunk in &all_chunks {
            if DocumentExtractor::is_degraded_document_chunk(&chunk.file_path, &chunk.text_content) {
                degraded_paths.insert(chunk.file_path.clone());
            }
        }

        if degraded_paths.is_empty() {
            return Ok(0);
        }

        let chunker = TextChunker::new(ChunkerConfig::default());
        let mut upgraded_files = 0usize;

        for path_str in degraded_paths {
            let file_path = std::path::Path::new(&path_str);
            if !file_path.exists() {
                continue;
            }
            let identity = match self.classifier.classify_file(file_path) {
                Ok(id) => id,
                Err(_) => continue,
            };
            let content = match DocumentExtractor::extract_text(file_path, &identity) {
                Ok(c) if !c.trim().is_empty() => c,
                _ => continue,
            };
            if DocumentExtractor::is_degraded_document_chunk(&path_str, &content) {
                continue;
            }

            let access_tier = self.config.resolve_access_tier(file_path);
            let file_b3 = Level1DedupCatalog::hash_file_stream(file_path)
                .unwrap_or_else(|_| blake3::hash(content.as_bytes()).to_hex().to_string());
            let raw_chunks = chunker.chunk_text_structure_aware(&content);
            if raw_chunks.is_empty() {
                continue;
            }

            let header = crate::chunker::build_contextual_header(file_path, &content);
            let contract_hash = self.embedder.contract().derive_contract_hash_hex();
            let mut file_chunk_hashes = Vec::with_capacity(raw_chunks.len());
            let mut doc_chunks = Vec::with_capacity(raw_chunks.len());

            for raw in raw_chunks {
                let raw_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
                let chunk_content = crate::chunker::prepend_contextual_header_with_section(
                    &header,
                    &raw.section_path,
                    raw.text_slice,
                );
                file_chunk_hashes.push(raw_b3.clone());

                let vector = if let Some(cached) = self.dedup.cache().get(&raw_b3) {
                    cached
                } else {
                    let vec = self
                        .embedder
                        .embed_text(raw.text_slice)
                        .unwrap_or_else(|_| vec![0.0; self.embedder.dimension()]);
                    self.dedup.cache().insert(raw_b3, vec.clone());
                    vec
                };

                let chunk_id = format!("{}:{}", file_b3, raw.chunk_index);
                let metadata_json = serde_json::json!({
                    "char_start": raw.char_start,
                    "char_end": raw.char_end,
                    "chunk_index": raw.chunk_index,
                    "contract_hash": contract_hash,
                    "parent_doc_id": file_b3.clone(),
                    "parent_chunk_id": format!("{}:p{}", file_b3, raw.parent_chunk_index),
                    "heading_path": raw.section_path,
                    "section_path": raw.section_path,
                    "section_title": raw.section_title,
                    "section_hierarchy": raw.section_hierarchy,
                    "section_level": raw.section_level,
                    "source_path": path_str.clone(),
                })
                .to_string();

                if let Ok(dc) = DocumentChunk::new(
                    chunk_id,
                    file_b3.clone(),
                    &path_str,
                    raw.line_start,
                    raw.line_end,
                    access_tier,
                    vector,
                    &chunk_content,
                    Some(metadata_json),
                ) {
                    doc_chunks.push(dc);
                }
            }

            if doc_chunks.is_empty() {
                continue;
            }

            let _ = self.storage.delete_by_file_path(&path_str).await;
            self.storage.insert_chunks(&doc_chunks).await?;
            let upgraded_mtime = std::fs::metadata(file_path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let upgraded_size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(content.len() as u64);
            let parent_doc = DocumentExtractor::build_ingested_parent_document(
                file_path,
                &file_b3,
                &file_b3,
                &content,
                upgraded_mtime,
                upgraded_size,
                None,
            );
            let _ = self.storage.upsert_parent_document(&parent_doc, access_tier);

            if let Ok(meta) = std::fs::metadata(file_path) {
                let mtime_secs = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                self.dedup.register_entry(FileCatalogEntry {
                    file_path: file_path.to_path_buf(),
                    file_blake3: file_b3,
                    mtime_secs,
                    size_bytes: meta.len(),
                    chunk_hashes: file_chunk_hashes,
                });
            }
            upgraded_files += 1;
        }

        if upgraded_files > 0 {
            if let Some(ref cat_path) = self.config.dedup_catalog_path {
                let _ = self.dedup.save_catalog_to_file(cat_path);
            }
            let _ = self.storage.bump_index_epoch("degraded_doc_chunks_upgraded");
            info!(
                upgraded_files,
                "Self-healed degraded DOCX/PDF chunks using native Rust extractor"
            );
        }

        Ok(upgraded_files)
    }


    /// Cooperative cancellation of an ongoing reindex task.
    pub fn cancel_reindex(&self) -> bool {
        self.cancel_flag.store(true, Ordering::SeqCst);
        true
    }

    /// Fetches the latest live progress of the reindex worker.
    pub async fn get_progress(&self) -> Option<ReindexProgress> {
        let lock = self.active_task.read().await;
        lock.clone()
    }

    /// Synchronous reindex execution (used by CLI commands or unit tests).
    pub async fn run_reindex_sync(&self, options: ReindexOptions) -> Result<ReindexProgress, IngestError> {
        let task_id = Uuid::new_v4();
        self.cancel_flag.store(false, Ordering::SeqCst);

        let initial_progress = ReindexProgress {
            task_id,
            phase: ReindexPhase::ScanningFilesystem,
            full_rebuild: options.full_rebuild,
            files_scanned: 0,
            files_total_estimated: 0,
            files_indexed: 0,
            files_skipped_unmodified: 0,
            files_failed: 0,
            chunks_reused_from_cache: 0,
            chunks_newly_embedded: 0,
            bytes_processed: 0,
            started_at: Utc::now(),
            completed_at: None,
            elapsed_secs: 0,
            error_message: None,
        };

        let progress_state = Arc::new(RwLock::new(Some(initial_progress)));

        Self::execute_pipeline(
            self.config.clone(),
            options,
            task_id,
            Arc::clone(&self.storage),
            Arc::clone(&self.classifier),
            Arc::clone(&self.embedder),
            Arc::clone(&self.dedup),
            progress_state.clone(),
            Arc::clone(&self.cancel_flag),
        )
        .await?;

        let mut lock = progress_state.write().await;
        let mut final_prog = lock.take().ok_or_else(|| {
            IngestError::WatcherError("reindex finished without a progress record".into())
        })?;
        final_prog.phase = ReindexPhase::Completed;
        final_prog.completed_at = Some(Utc::now());
        final_prog.elapsed_secs = (Utc::now() - final_prog.started_at).num_seconds().max(0) as u64;

        Ok(final_prog)
    }

    /// Internal execution loop for reindexing.
    #[allow(clippy::too_many_arguments)]
    async fn execute_pipeline(
        mut config: IngestConfig,
        options: ReindexOptions,
        _task_id: Uuid,
        storage: Arc<StorageEngine>,
        _classifier: Arc<FileTypeClassifier>,
        embedder: Arc<dyn EmbeddingGenerator>,
        dedup: Arc<TwoLevelDedupEngine>,
        progress: Arc<RwLock<Option<ReindexProgress>>>,
        cancel_flag: Arc<AtomicBool>,
    ) -> Result<(), IngestError> {
        // RAII guard to ensure bulk indexing is restored when this reindex pass terminates
        struct BulkIndexReset;
        impl Drop for BulkIndexReset {
            fn drop(&mut self) {
                crate::image_indexer::ImageIndexer::set_bulk_indexing(false);
            }
        }
        crate::image_indexer::ImageIndexer::set_bulk_indexing(true);
        let _bulk_reset = BulkIndexReset;

        // Hydrate deduplication state from SQLite document catalog before processing candidates
        if let Err(e) = dedup.hydrate_from_catalog(&storage) {
            warn!("Failed to hydrate dedup catalog from document_catalog.db: {}", e);
        }

        let storage_path = storage.config().storage_path.clone();
        if !config.excluded_paths.iter().any(|p| p == &storage_path) {
            config.excluded_paths.push(storage_path);
        }
        if let Some(ref cat_path) = config.dedup_catalog_path {
            if let Some(parent) = cat_path.parent() {
                let parent_buf = parent.to_path_buf();
                if !parent_buf.as_os_str().is_empty() && !config.excluded_paths.iter().any(|p| p == &parent_buf) {
                    config.excluded_paths.push(parent_buf);
                }
            }
        }

        let raw_targets = if !options.target_paths.is_empty() {
            options.target_paths.clone()
        } else {
            config.watch_paths.clone()
        };

        if raw_targets.is_empty() {
            info!("No target paths configured for reindexing");
            return Ok(());
        }

        let targets = Self::expand_drive_roots(&raw_targets);
        let targets: Vec<std::path::PathBuf> = targets
            .into_iter()
            .filter(|t| !config.excluded_paths.iter().any(|ex| t == ex || t.starts_with(ex)))
            .collect();
        let chunker = TextChunker::new(ChunkerConfig::default());

        // Phase 1: Decoupled Upfront Discovery across all target slices (Unified work-stealing parallel crawl)
        let crawler = Arc::new(FilesystemCrawler::new(config.clone()));
        let crawler_c = Arc::clone(&crawler);
        let targets_c = targets.clone();
        let all_candidates = tokio::task::spawn_blocking(move || {
            crate::throttling::set_background_thread_priority();
            let res = crawler_c.crawl_multi_root_sync(&targets_c);
            crate::throttling::end_background_thread_priority();
            res
        })
        .await
        .map_err(|e| IngestError::Io(std::io::Error::other(format!("Crawler task join failed: {}", e))))??;
        {
            let mut lock = progress.write().await;
            if let Some(ref mut p) = *lock {
                p.files_total_estimated = all_candidates.len();
            }
        }

        // Transition to Phase 2: Chunking & Vectorizing with total candidate count fixed
        {
            let mut lock = progress.write().await;
            if let Some(ref mut p) = *lock {
                p.files_total_estimated = all_candidates.len();
                p.phase = ReindexPhase::ChunkingAndVectorizing;
            }
        }

        let catalog_path = config
            .dedup_catalog_path
            .as_ref()
            .cloned()
            .unwrap_or_else(|| storage.config().storage_path.join("dedup_catalog.json"));

        let concurrency = if options.num_threads > 0 {
            options.num_threads.clamp(1, 64)
        } else {
            std::thread::available_parallelism()
                .map(|n| (n.get() * 2).clamp(8, 32))
                .unwrap_or(16)
        };
        let permit_tiers = crate::thread_pool::IngestPermitTiers::new(concurrency);
        let thread_pool = crate::thread_pool::IngestThreadPool::shared();

        let mut batch_chunks: Vec<DocumentChunk> = Vec::with_capacity(options.batch_size.max(64));
        let mut batch_parents: Vec<(quorum_types::IngestedParentDocument, u8)> = Vec::with_capacity(options.batch_size.max(64));

        let mut futures = FuturesUnordered::new();
        let mut candidate_iter = all_candidates.into_iter();
        let mut last_catalog_save = std::time::Instant::now();

        loop {
            if cancel_flag.load(Ordering::SeqCst) {
                return Err(IngestError::Cancelled);
            }

            // Fill concurrency slots up to capacity
            while futures.len() < concurrency {
                let Some(candidate) = candidate_iter.next() else { break };

                let path = candidate.path.clone();
                let access_tier = config.resolve_access_tier(&path);

                // Level-1 Evaluation: skip unmodified unless full_rebuild is forced
                let mut precomputed_file_b3 = None;
                if !options.full_rebuild {
                    if let Ok(action) = dedup.evaluate_file(&path, candidate.mtime_secs, candidate.size_bytes) {
                        match action {
                            DedupAction::Unchanged { .. } => {
                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.files_scanned += 1;
                                    p.files_skipped_unmodified += 1;
                                    p.bytes_processed += candidate.size_bytes;
                                }
                                if last_catalog_save.elapsed() >= std::time::Duration::from_secs(30) {
                                    let _ = dedup.save_catalog_to_file(&catalog_path);
                                    last_catalog_save = std::time::Instant::now();
                                }
                                continue;
                            }
                            DedupAction::MovedOrRenamed { old_path, new_path, file_blake3, chunk_hashes } => {
                                info!(old = %old_path.display(), new = %new_path.display(), "Detected moved/renamed file during reindex; updating path with 0 re-embeddings");
                                dedup.register_entry(FileCatalogEntry {
                                    file_path: new_path,
                                    file_blake3,
                                    mtime_secs: candidate.mtime_secs,
                                    size_bytes: candidate.size_bytes,
                                    chunk_hashes,
                                });
                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.files_scanned += 1;
                                    p.files_indexed += 1;
                                    p.bytes_processed += candidate.size_bytes;
                                }
                                if last_catalog_save.elapsed() >= std::time::Duration::from_secs(30) {
                                    let _ = dedup.save_catalog_to_file(&catalog_path);
                                    last_catalog_save = std::time::Instant::now();
                                }
                                continue;
                            }
                            DedupAction::ModifiedOrNew { file_blake3, .. } => {
                                precomputed_file_b3 = Some(file_blake3);
                                // Proceed to chunking and vectorization
                            }
                        }
                    }
                }

                let permit = permit_tiers.acquire_extraction().await?;
                let embedder_c = Arc::clone(&embedder);
                let dedup_c = Arc::clone(&dedup);
                let storage_c = Arc::clone(&storage);
                let chunker_c = chunker.clone();
                let force_reembed = options.force_reembed;
                let full_rebuild = options.full_rebuild;

                futures.push(thread_pool.spawn_blocking_pinned(permit, move || {
                    process_candidate_sync(
                        candidate,
                        access_tier,
                        force_reembed || full_rebuild,
                        storage_c,
                        embedder_c,
                        dedup_c,
                        chunker_c,
                        precomputed_file_b3,
                    )
                }));
            }

            if futures.is_empty() {
                break;
            }

            // Await next completed candidate with 45s timeout to prevent thread-pool deadlocks
            match tokio::time::timeout(std::time::Duration::from_secs(45), futures.next()).await {
                Ok(Some(join_res)) => {
                    match join_res {
                        Ok(outcome) => match outcome {
                            CandidateOutcome::AlreadyIndexedInFts {
                                catalog_entry,
                                size_bytes,
                            } => {
                                dedup.register_entry(catalog_entry);
                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.files_scanned += 1;
                                    p.files_skipped_unmodified += 1;
                                    p.bytes_processed += size_bytes;
                                }
                            }
                            CandidateOutcome::Processed {
                                chunks,
                                parent_doc,
                                catalog_entry,
                                size_bytes,
                                chunks_reused,
                                chunks_new,
                            } => {
                                dedup.register_entry(catalog_entry);
                                if let Some(parent) = parent_doc {
                                    batch_parents.push(parent);
                                }
                                batch_chunks.extend(chunks);

                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.files_scanned += 1;
                                    p.files_indexed += 1;
                                    p.bytes_processed += size_bytes;
                                    p.chunks_reused_from_cache += chunks_reused;
                                    p.chunks_newly_embedded += chunks_new;
                                }
                            }
                            CandidateOutcome::Failed { path, error } => {
                                warn!("Failed to process '{}': {}", path.display(), error);
                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.files_scanned += 1;
                                    p.files_failed += 1;
                                }
                            }
                        },
                        Err(e) => {
                            warn!("Blocking reindex worker task failed: {}", e);
                            let mut lock = progress.write().await;
                            if let Some(ref mut p) = *lock {
                                p.files_scanned += 1;
                                p.files_failed += 1;
                            }
                        }
                    }

                    if last_catalog_save.elapsed() >= std::time::Duration::from_secs(30) {
                        let _ = dedup.save_catalog_to_file(&catalog_path);
                        last_catalog_save = std::time::Instant::now();
                    }

                    // If micro-batch is full, flush to storage
                    if batch_chunks.len() >= options.batch_size {
                        if !options.dry_run {
                            let _commit_permit = permit_tiers.acquire_storage_commit().await?;
                            Self::replace_existing_file_chunks(&storage, &batch_chunks).await;
                            let _ = storage.insert_chunks(&batch_chunks).await?;
                            for (pdoc, ptier) in batch_parents.drain(..) {
                                let _ = storage.upsert_parent_document(&pdoc, ptier);
                            }
                            let _ = dedup.save_catalog_to_file(&catalog_path);
                            last_catalog_save = std::time::Instant::now();
                            let _ = storage.bump_index_epoch("reindex_micro_batch");
                        } else {
                            batch_parents.clear();
                        }
                        batch_chunks.clear();
                        tokio::task::yield_now().await;
                    }
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {
                    warn!("Candidate extraction task timed out after 45s; continuing pipeline");
                    let mut lock = progress.write().await;
                    if let Some(ref mut p) = *lock {
                        p.files_scanned += 1;
                        p.files_failed += 1;
                    }
                    if last_catalog_save.elapsed() >= std::time::Duration::from_secs(30) {
                        let _ = dedup.save_catalog_to_file(&catalog_path);
                        last_catalog_save = std::time::Instant::now();
                    }
                }
            }
        }

        // Flush remaining micro-batch
        if !batch_chunks.is_empty() && !options.dry_run {
            let _commit_permit = permit_tiers.acquire_storage_commit().await?;
            Self::replace_existing_file_chunks(&storage, &batch_chunks).await;
            let _ = storage.insert_chunks(&batch_chunks).await?;
            for (pdoc, ptier) in batch_parents.drain(..) {
                let _ = storage.upsert_parent_document(&pdoc, ptier);
            }
            let _ = dedup.save_catalog_to_file(&catalog_path);
            let _ = storage.bump_index_epoch("reindex_final_flush");
            batch_chunks.clear();
        } else if !batch_parents.is_empty() && !options.dry_run {
            let _commit_permit = permit_tiers.acquire_storage_commit().await?;
            for (pdoc, ptier) in batch_parents.drain(..) {
                let _ = storage.upsert_parent_document(&pdoc, ptier);
            }
            let _ = dedup.save_catalog_to_file(&catalog_path);
        }

        // Compaction phase if full rebuild
        if options.full_rebuild && !options.dry_run {
            let mut lock = progress.write().await;
            if let Some(ref mut p) = *lock {
                p.phase = ReindexPhase::CompactingIndexes;
            }
            drop(lock);
            let _ = storage.compact().await;
        }

        // Cache coherence hook: bump index_epoch if any mutations occurred
        let has_mutated = {
            let lock = progress.read().await;
            lock.as_ref()
                .map(|p| p.files_indexed > 0 || p.chunks_newly_embedded > 0 || options.full_rebuild)
                .unwrap_or(false)
        };

        if has_mutated && !options.dry_run {
            let reason = if options.full_rebuild {
                "reindex_full_rebuild"
            } else {
                "reindex_completed"
            };
            let _ = storage.bump_index_epoch(reason)?;

            let catalog_path = config
                .dedup_catalog_path
                .as_ref()
                .cloned()
                .unwrap_or_else(|| storage.config().storage_path.join("dedup_catalog.json"));
            if let Err(e) = dedup.save_catalog_to_file(&catalog_path) {
                warn!("Failed to auto-save dedup catalog after reindex pass: {}", e);
            } else {
                info!(
                    path = %catalog_path.display(),
                    tracked_files = dedup.catalog().read().map(|c| c.len()).unwrap_or(0),
                    "Auto-saved Level-1 dedup catalog to disk after reindex pass"
                );
            }
        } else if !options.dry_run {
            let _ = dedup.save_catalog_to_file(&catalog_path);
        }

        Ok(())
    }

    /// Expands drive roots (e.g., `D:\`, `C:\`) into incremental top-level slices so user documents
    /// are indexed and searchable within seconds rather than waiting for a multi-terabyte full-drive walk.
    pub fn expand_drive_roots(raw_targets: &[ std::path::PathBuf ]) -> Vec<std::path::PathBuf> {
        const SKIP_DIRS: &[&str] = &[
            "$recycle.bin",
            "system volume information",
            "windows",
            "program files",
            "program files (x86)",
            "programdata",
            "recovery",
            "perflogs",
            "msocache",
            "config.msi",
            "appdata",
            "node_modules",
            "target",
            "osoosi_target",
            "python311",
            "docker",
            "chrome_temp_profile",
            ".git",
            ".cargo",
            ".rustup",
            "__pycache__",
            ".venv",
            "venv",
            ".tmp.driveupload",
            ".pytest_cache",
            ".lance",
            "lance",
            ".tantivy",
            "tantivy",
            ".quorumrag-live-data",
            "storage",
            "quorumrag",
            ".quorumrag",
        ];

        let mut expanded = Vec::new();
        for target in raw_targets {
            let is_drive_root = target.parent().is_none()
                || target.to_string_lossy().len() <= 3
                || target.file_name().map(|n| {
                    let s = n.to_string_lossy();
                    s.starts_with(".tmp") || s.starts_with("tmp") || s.contains("mock_drive") || s.contains("test")
                }).unwrap_or(false);
            if !is_drive_root {
                expanded.push(target.clone());
                continue;
            }

            let Ok(entries) = std::fs::read_dir(target) else {
                expanded.push(target.clone());
                continue;
            };

            let mut top_priority_slices = Vec::new();
            let mut priority_slices = Vec::new();
            let mut normal_slices = Vec::new();

            for entry in entries.flatten() {
                let path = entry.path();
                let name_lower = entry
                    .file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase();
                if SKIP_DIRS.contains(&name_lower.as_str()) {
                    continue;
                }

                // Expand large workspace containers (`femi`, `harfile`, `users`) one level further
                if path.is_dir() && matches!(name_lower.as_str(), "femi" | "harfile" | "users") {
                    if let Ok(sub_entries) = std::fs::read_dir(&path) {
                        for sub in sub_entries.flatten() {
                            let sub_path = sub.path();
                            let sub_name = sub.file_name().to_string_lossy().to_ascii_lowercase();
                            if SKIP_DIRS.contains(&sub_name.as_str()) {
                                continue;
                            }
                            if matches!(
                                sub_name.as_str(),
                                "resume" | "transctipts" | "transcripts" | "school" | "wow" | "tax"
                            ) {
                                top_priority_slices.insert(0, sub_path);
                            } else if sub_name.contains("mechanistic_interpretability") {
                                let probe_dir = sub_path.join("probe_and_tools");
                                if probe_dir.is_dir() {
                                    top_priority_slices.push(probe_dir.clone());
                                    if let Ok(sub_children) = std::fs::read_dir(&sub_path) {
                                        for child in sub_children.flatten() {
                                            let child_path = child.path();
                                            if child_path != probe_dir {
                                                priority_slices.push(child_path);
                                            }
                                        }
                                    }
                                } else {
                                    priority_slices.push(sub_path);
                                }
                            } else if sub_name.contains("quorumrag") {
                                priority_slices.push(sub_path);
                            } else {
                                normal_slices.push(sub_path);
                            }
                        }
                        continue;
                    }
                }

                if matches!(
                    name_lower.as_str(),
                    "school" | "articles" | "rules" | "documents"
                ) || path.is_file()
                {
                    top_priority_slices.push(path);
                } else {
                    normal_slices.push(path);
                }
            }

            expanded.extend(top_priority_slices);
            expanded.extend(priority_slices);
            expanded.extend(normal_slices);
        }

        let mut seen = std::collections::HashSet::new();
        expanded.retain(|p| seen.insert(p.clone()));

        if expanded.is_empty() {
            raw_targets.to_vec()
        } else {
            expanded
        }
    }
}

/// Internal candidate outcome from multithreaded processing task.
enum CandidateOutcome {
    AlreadyIndexedInFts {
        catalog_entry: FileCatalogEntry,
        size_bytes: u64,
    },
    Processed {
        chunks: Vec<DocumentChunk>,
        parent_doc: Option<(quorum_types::IngestedParentDocument, u8)>,
        catalog_entry: FileCatalogEntry,
        size_bytes: u64,
        chunks_reused: usize,
        chunks_new: usize,
    },
    Failed {
        path: std::path::PathBuf,
        error: String,
    },
}

fn process_candidate_sync(
    candidate: DiscoveredCandidate,
    access_tier: u8,
    force_reembed: bool,
    storage: Arc<StorageEngine>,
    embedder: Arc<dyn EmbeddingGenerator>,
    dedup: Arc<TwoLevelDedupEngine>,
    chunker: TextChunker,
    precomputed_file_b3: Option<String>,
) -> CandidateOutcome {
    let path = &candidate.path;
    match candidate.kind {
        CandidateKind::Text { .. } => {
            let content = match DocumentExtractor::extract_text(path, &candidate.file_identity) {
                Ok(c) => c,
                Err(e) => {
                    return CandidateOutcome::Failed {
                        path: path.clone(),
                        error: format!("Failed to read file: {}", e),
                    };
                }
            };

            let file_b3 = match precomputed_file_b3 {
                Some(b3) => b3,
                None => Level1DedupCatalog::hash_file_stream(path)
                    .unwrap_or_else(|_| blake3::hash(content.as_bytes()).to_hex().to_string()),
            };
            if !force_reembed && storage.has_chunk_id_in_fts(&format!("{}:0", file_b3)) {
                return CandidateOutcome::AlreadyIndexedInFts {
                    catalog_entry: FileCatalogEntry {
                        file_path: path.clone(),
                        file_blake3: file_b3,
                        mtime_secs: candidate.mtime_secs,
                        size_bytes: candidate.size_bytes,
                        chunk_hashes: Vec::new(),
                    },
                    size_bytes: candidate.size_bytes,
                };
            }
            let raw_chunks = chunker.chunk_text_structure_aware(&content);
            let mut file_chunk_hashes = Vec::with_capacity(raw_chunks.len());
            let path_str = path.to_string_lossy().to_string();
            let header = crate::chunker::build_contextual_header(path, &content);

            let mut chunks = Vec::with_capacity(raw_chunks.len());
            let mut chunks_reused = 0;
            let mut chunks_new = 0;

            for raw in raw_chunks {
                let raw_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
                let chunk_content = crate::chunker::prepend_contextual_header_with_section(
                    &header,
                    &raw.section_path,
                    raw.text_slice,
                );
                let chunk_b3 = DocumentChunk::compute_blake3_hash(&chunk_content);
                file_chunk_hashes.push(raw_b3.clone());

                let vector = if !force_reembed {
                    if let Some(existing_vec) = dedup.cache().get(&raw_b3) {
                        chunks_reused += 1;
                        existing_vec
                    } else {
                        let vec = embedder
                            .embed_text(raw.text_slice)
                            .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                        dedup.cache().insert(raw_b3.clone(), vec.clone());
                        chunks_new += 1;
                        vec
                    }
                } else {
                    let vec = embedder
                        .embed_text(&chunk_content)
                        .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                    dedup.cache().insert(chunk_b3.clone(), vec.clone());
                    chunks_new += 1;
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
                    "source_path": path_str.clone(),
                })
                .to_string();

                if let Ok(doc_chunk) = DocumentChunk::new(
                    chunk_id,
                    file_b3.clone(),
                    &path_str,
                    raw.line_start,
                    raw.line_end,
                    access_tier,
                    vector,
                    &chunk_content,
                    Some(metadata_json),
                ) {
                    chunks.push(doc_chunk);
                }
            }

            let parent_doc = if !content.is_empty() {
                Some((
                    DocumentExtractor::build_ingested_parent_document(
                        path,
                        &file_b3,
                        &file_b3,
                        &content,
                        candidate.mtime_secs,
                        candidate.size_bytes,
                        None,
                    ),
                    access_tier,
                ))
            } else {
                None
            };

            let catalog_entry = FileCatalogEntry {
                file_path: path.clone(),
                file_blake3: file_b3,
                mtime_secs: candidate.mtime_secs,
                size_bytes: candidate.size_bytes,
                chunk_hashes: file_chunk_hashes,
            };

            CandidateOutcome::Processed {
                chunks,
                parent_doc,
                catalog_entry,
                size_bytes: candidate.size_bytes,
                chunks_reused,
                chunks_new,
            }
        }
        CandidateKind::Image { .. } => {
            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    return CandidateOutcome::Failed {
                        path: path.clone(),
                        error: format!("Failed to read image file: {}", e),
                    };
                }
            };

            let img_b3 = match precomputed_file_b3 {
                Some(b3) => b3,
                None => blake3::hash(&bytes).to_hex().to_string(),
            };
            if !force_reembed && (storage.has_chunk_id_in_fts(&format!("{}:img:0", img_b3)) || storage.has_chunk_id_in_fts(&format!("{}:image:0", img_b3))) {
                return CandidateOutcome::AlreadyIndexedInFts {
                    catalog_entry: FileCatalogEntry {
                        file_path: path.clone(),
                        file_blake3: img_b3,
                        mtime_secs: candidate.mtime_secs,
                        size_bytes: candidate.size_bytes,
                        chunk_hashes: Vec::new(),
                    },
                    size_bytes: candidate.size_bytes,
                };
            }

            match ImageIndexer::index_image(
                path,
                &bytes,
                &candidate.file_identity,
                access_tier,
                embedder.as_ref(),
            ) {
                Ok(doc_chunk) => {
                    let file_b3 = doc_chunk.document_id.clone();
                    let parent_doc = Some((
                        DocumentExtractor::build_ingested_parent_document(
                            path,
                            &file_b3,
                            &file_b3,
                            &doc_chunk.text_content,
                            candidate.mtime_secs,
                            candidate.size_bytes,
                            Some(quorum_types::DocumentFormat::ImageFile),
                        ),
                        access_tier,
                    ));
                    let catalog_entry = FileCatalogEntry {
                        file_path: path.clone(),
                        file_blake3: file_b3,
                        mtime_secs: candidate.mtime_secs,
                        size_bytes: candidate.size_bytes,
                        chunk_hashes: vec![doc_chunk.blake3_hash.clone()],
                    };
                    CandidateOutcome::Processed {
                        chunks: vec![doc_chunk],
                        parent_doc,
                        catalog_entry,
                        size_bytes: candidate.size_bytes,
                        chunks_reused: 0,
                        chunks_new: 1,
                    }
                }
                Err(e) => CandidateOutcome::Failed {
                    path: path.clone(),
                    error: format!("Failed to index image: {}", e),
                },
            }
        }
        CandidateKind::Audio { .. } => {
            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    return CandidateOutcome::Failed {
                        path: path.clone(),
                        error: format!("Failed to read audio file: {}", e),
                    };
                }
            };

            match AudioIndexer::index_audio(
                path,
                &bytes,
                &candidate.file_identity,
                access_tier,
                embedder.as_ref(),
            ) {
                Ok(doc_chunk) => {
                    let file_b3 = doc_chunk.document_id.clone();
                    let catalog_entry = FileCatalogEntry {
                        file_path: path.clone(),
                        file_blake3: file_b3,
                        mtime_secs: candidate.mtime_secs,
                        size_bytes: candidate.size_bytes,
                        chunk_hashes: vec![doc_chunk.blake3_hash.clone()],
                    };
                    CandidateOutcome::Processed {
                        chunks: vec![doc_chunk],
                        parent_doc: None,
                        catalog_entry,
                        size_bytes: candidate.size_bytes,
                        chunks_reused: 0,
                        chunks_new: 1,
                    }
                }
                Err(e) => CandidateOutcome::Failed {
                    path: path.clone(),
                    error: format!("Failed to index audio: {}", e),
                },
            }
        }
    }
}
