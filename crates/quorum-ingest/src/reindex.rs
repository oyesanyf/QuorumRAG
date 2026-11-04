//! Dedicated Reindexing Worker for QuorumRAG.
//!
//! Traverses target directories supporting both incremental (`mtime` + Level 1 BLAKE3
//! comparison -> 0 neural calls for untouched/renamed files) and full rebuild (`--full`) modes.
//! Provides asynchronous background task management, cooperative cancellation, and live telemetry.

use chrono::{DateTime, Utc};
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
use crate::dedup::{DedupAction, FileCatalogEntry, TwoLevelDedupEngine};
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
        let mut final_prog = lock.take().unwrap();
        final_prog.phase = ReindexPhase::Completed;
        final_prog.completed_at = Some(Utc::now());
        final_prog.elapsed_secs = (Utc::now() - final_prog.started_at).num_seconds().max(0) as u64;

        Ok(final_prog)
    }

    /// Internal execution loop for reindexing.
    #[allow(clippy::too_many_arguments)]
    async fn execute_pipeline(
        config: IngestConfig,
        options: ReindexOptions,
        _task_id: Uuid,
        storage: Arc<StorageEngine>,
        _classifier: Arc<FileTypeClassifier>,
        embedder: Arc<dyn EmbeddingGenerator>,
        dedup: Arc<TwoLevelDedupEngine>,
        progress: Arc<RwLock<Option<ReindexProgress>>>,
        cancel_flag: Arc<AtomicBool>,
    ) -> Result<(), IngestError> {
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
        let chunker = TextChunker::new(ChunkerConfig::default());

        // Phase 1: Decoupled Upfront Discovery across all target slices
        let mut all_candidates: Vec<DiscoveredCandidate> = Vec::new();
        let mut seen_paths: std::collections::HashSet<std::path::PathBuf> = std::collections::HashSet::new();

        for target in &targets {
            if !target.exists() {
                warn!("Target path does not exist, skipping: {}", target.display());
                continue;
            }

            if cancel_flag.load(Ordering::SeqCst) {
                return Err(IngestError::Cancelled);
            }

            let cfg_clone = config.clone();
            let target_clone = target.clone();
            let candidates = tokio::task::spawn_blocking(move || {
                crate::throttling::set_background_thread_priority();
                let crawler = FilesystemCrawler::new(cfg_clone);
                crawler.crawl_path_sync(&target_clone)
            })
            .await
            .map_err(|e| IngestError::Io(std::io::Error::other(format!("Crawl task panicked: {}", e))))??;

            for candidate in candidates {
                if seen_paths.insert(candidate.path.clone()) {
                    all_candidates.push(candidate);
                }
            }

            {
                let mut lock = progress.write().await;
                if let Some(ref mut p) = *lock {
                    p.files_total_estimated = all_candidates.len();
                }
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

        let mut batch_chunks: Vec<DocumentChunk> = Vec::with_capacity(options.batch_size);

        for candidate in all_candidates {
            if cancel_flag.load(Ordering::SeqCst) {
                return Err(IngestError::Cancelled);
            }

                // Cooperative multitasking yield point
                tokio::task::yield_now().await;

                {
                    let mut lock = progress.write().await;
                    if let Some(ref mut p) = *lock {
                        p.files_scanned += 1;
                        p.bytes_processed += candidate.size_bytes;
                    }
                }

                let path = &candidate.path;
                let access_tier = config.resolve_access_tier(path);

                // Level-1 Evaluation: skip unmodified unless full_rebuild is forced
                if !options.full_rebuild {
                    if let Ok(action) = dedup.evaluate_file(path, candidate.mtime_secs, candidate.size_bytes) {
                        match action {
                            DedupAction::Unchanged { .. } => {
                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.files_skipped_unmodified += 1;
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
                                    p.files_indexed += 1;
                                }
                                continue;
                            }
                            DedupAction::ModifiedOrNew { .. } => {
                                // Proceed to chunking and vectorization
                            }
                        }
                    }
                }

                // File is new, modified, or full rebuild was requested
                match candidate.kind {
                    CandidateKind::Text { .. } => {
                        let content = match DocumentExtractor::extract_text(path, &candidate.file_identity) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!("Failed to read file '{}': {}", path.display(), e);
                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.files_failed += 1;
                                }
                                continue;
                            }
                        };

                        let file_b3 = blake3::hash(content.as_bytes()).to_hex().to_string();
                        let mut file_chunk_hashes = Vec::new();

                        let raw_chunks = chunker.chunk_text(&content);
                        let path_str = path.to_string_lossy().to_string();

                        for raw in raw_chunks {
                            if raw.chunk_index > 0 && raw.chunk_index % 8 == 0 {
                                tokio::task::yield_now().await;
                            }

                            let chunk_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
                            file_chunk_hashes.push(chunk_b3.clone());

                            // Level-2 Evaluation: reuse cached vector if available
                            let vector = if !options.force_reembed {
                                if let Some(existing_vec) = dedup.cache().get(&chunk_b3) {
                                    let mut lock = progress.write().await;
                                    if let Some(ref mut p) = *lock {
                                        p.chunks_reused_from_cache += 1;
                                    }
                                    existing_vec
                                } else {
                                    let vec = embedder
                                        .embed_text(raw.text_slice)
                                        .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                                    dedup.cache().insert(chunk_b3.clone(), vec.clone());
                                    let mut lock = progress.write().await;
                                    if let Some(ref mut p) = *lock {
                                        p.chunks_newly_embedded += 1;
                                    }
                                    vec
                                }
                            } else {
                                let vec = embedder
                                    .embed_text(raw.text_slice)
                                    .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                                dedup.cache().insert(chunk_b3.clone(), vec.clone());
                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.chunks_newly_embedded += 1;
                                }
                                vec
                            };

                            let chunk_id = format!("{}:{}", file_b3, raw.chunk_index);
                            let metadata_json = serde_json::json!({
                                "char_start": raw.char_start,
                                "char_end": raw.char_end,
                                "chunk_index": raw.chunk_index,
                                "contract_hash": embedder.contract().derive_contract_hash_hex(),
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
                                raw.text_slice,
                                Some(metadata_json),
                            ) {
                                batch_chunks.push(doc_chunk);
                            }
                        }

                        // Register in Level-1 catalog
                        dedup.register_entry(FileCatalogEntry {
                            file_path: path.clone(),
                            file_blake3: file_b3,
                            mtime_secs: candidate.mtime_secs,
                            size_bytes: candidate.size_bytes,
                            chunk_hashes: file_chunk_hashes,
                        });
                    }
                    CandidateKind::Image { .. } => {
                        let bytes = match std::fs::read(path) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("Failed to read image file '{}': {}", path.display(), e);
                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.files_failed += 1;
                                }
                                continue;
                            }
                        };

                        if let Ok(doc_chunk) = ImageIndexer::index_image(
                            path,
                            &bytes,
                            &candidate.file_identity,
                            access_tier,
                            embedder.as_ref(),
                        ) {
                            let file_b3 = doc_chunk.document_id.clone();
                            dedup.register_entry(FileCatalogEntry {
                                file_path: path.clone(),
                                file_blake3: file_b3,
                                mtime_secs: candidate.mtime_secs,
                                size_bytes: candidate.size_bytes,
                                chunk_hashes: vec![doc_chunk.blake3_hash.clone()],
                            });
                            batch_chunks.push(doc_chunk);
                            let mut lock = progress.write().await;
                            if let Some(ref mut p) = *lock {
                                p.chunks_newly_embedded += 1;
                            }
                        }
                    }
                    CandidateKind::Audio { .. } => {
                        let bytes = match std::fs::read(path) {
                            Ok(b) => b,
                            Err(e) => {
                                warn!("Failed to read audio file '{}': {}", path.display(), e);
                                let mut lock = progress.write().await;
                                if let Some(ref mut p) = *lock {
                                    p.files_failed += 1;
                                }
                                continue;
                            }
                        };

                        if let Ok(doc_chunk) = AudioIndexer::index_audio(
                            path,
                            &bytes,
                            &candidate.file_identity,
                            access_tier,
                            embedder.as_ref(),
                        ) {
                            let file_b3 = doc_chunk.document_id.clone();
                            dedup.register_entry(FileCatalogEntry {
                                file_path: path.clone(),
                                file_blake3: file_b3,
                                mtime_secs: candidate.mtime_secs,
                                size_bytes: candidate.size_bytes,
                                chunk_hashes: vec![doc_chunk.blake3_hash.clone()],
                            });
                            batch_chunks.push(doc_chunk);
                            let mut lock = progress.write().await;
                            if let Some(ref mut p) = *lock {
                                p.chunks_newly_embedded += 1;
                            }
                        }
                    }
                }

                // If micro-batch is full, flush to storage
                if batch_chunks.len() >= options.batch_size {
                    if !options.dry_run {
                        Self::replace_existing_file_chunks(&storage, &batch_chunks).await;
                        let _ = storage.insert_chunks(&batch_chunks).await?;
                        let _ = storage.bump_index_epoch("reindex_micro_batch");
                    }
                    batch_chunks.clear();
                    tokio::task::yield_now().await;
                }

                let mut lock = progress.write().await;
                if let Some(ref mut p) = *lock {
                    p.files_indexed += 1;
                }
            }

            // Flush remaining micro-batch
            if !batch_chunks.is_empty() && !options.dry_run {
                Self::replace_existing_file_chunks(&storage, &batch_chunks).await;
                let _ = storage.insert_chunks(&batch_chunks).await?;
                let _ = storage.bump_index_epoch("reindex_final_flush");
                batch_chunks.clear();
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
            ".tantivy",
            ".quorumrag-live-data",
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
