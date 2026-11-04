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

use crate::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use crate::chunker::TextChunker;
use crate::config::{ChunkerConfig, DriftFixOptions, IngestConfig, ReindexOptions};
use crate::dedup::{DedupAction, FileCatalogEntry, TwoLevelDedupEngine};
use crate::document_extractor::DocumentExtractor;
use crate::drift_healer::DriftHealer;
use crate::audio_indexer::AudioIndexer;
use crate::error::IngestError;
use crate::image_indexer::ImageIndexer;
use crate::reindex::ReindexWorker;
use crate::watcher::{FilesystemWatcher, WatcherEvent, WatcherHandle};
use quorum_classifier::FileTypeClassifier;
use quorum_contract::EmbeddingGenerator;
use quorum_storage::StorageEngine;
use quorum_types::DocumentChunk;

/// High-throughput unified IngestEngine.
pub struct IngestEngine {
    config: IngestConfig,
    storage: Arc<StorageEngine>,
    classifier: Arc<FileTypeClassifier>,
    embedder: Arc<dyn EmbeddingGenerator>,
    dedup: Arc<TwoLevelDedupEngine>,
    reindex_worker: Arc<ReindexWorker>,
    drift_healer: Arc<DriftHealer>,
    chunker: TextChunker,
    router: ClassifierRouter,
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
        let drift_healer = Arc::new(DriftHealer::new(
            config.clone(),
            Arc::clone(&storage),
            Arc::clone(&classifier),
            Arc::clone(&embedder),
            Arc::clone(&dedup),
        ));
        let chunker = TextChunker::new(ChunkerConfig::default());
        let router = ClassifierRouter::new(config.clone());

        Ok(Self {
            config,
            storage,
            classifier,
            embedder,
            dedup,
            reindex_worker,
            drift_healer,
            chunker,
            router,
            is_running: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn config(&self) -> &IngestConfig {
        &self.config
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

    /// Ingests a single file synchronously: verifies size, Magika category, Level-1 catalog,
    /// Level-2 chunk cache, and writes to storage. Returns the produced chunks if accepted.
    pub async fn ingest_file(&self, path: &Path) -> Result<Option<Vec<DocumentChunk>>, IngestError> {
        let decision = self.router.evaluate_file(path);

        let (identity, kind, size_bytes, mtime_secs) = match decision {
            FilterDecision::Accept {
                identity,
                kind,
                size_bytes,
                mtime_secs,
            } => (identity, kind, size_bytes, mtime_secs),
            _ => return Ok(None),
        };

        // Level-1 Evaluation
        match self.dedup.evaluate_file(path, mtime_secs, size_bytes)? {
            DedupAction::Unchanged { .. } => {
                return Ok(Some(Vec::new()));
            }
            DedupAction::MovedOrRenamed { old_path, new_path, file_blake3, chunk_hashes } => {
                info!(old = %old_path.display(), new = %new_path.display(), "Detected moved/renamed file; updating catalog path with 0 re-embeddings");
                self.dedup.register_entry(FileCatalogEntry {
                    file_path: new_path,
                    file_blake3,
                    mtime_secs,
                    size_bytes,
                    chunk_hashes,
                });
                return Ok(Some(Vec::new()));
            }
            DedupAction::ModifiedOrNew { .. } => {
                // Proceed to chunking and embedding
            }
        }

        let access_tier = self.config.resolve_access_tier(path);
        let path_str = path.to_string_lossy().to_string();

        let chunks = match kind {
            CandidateKind::Text { .. } => {
                let content = DocumentExtractor::extract_text(path, &identity)?;
                if content.is_empty() {
                    return Ok(Some(Vec::new()));
                }

                let file_b3 = blake3::hash(content.as_bytes()).to_hex().to_string();
                let raw_chunks = self.chunker.chunk_text(&content);

                let mut file_chunk_hashes = Vec::with_capacity(raw_chunks.len());
                let mut doc_chunks = Vec::with_capacity(raw_chunks.len());

                for raw in raw_chunks {
                    let chunk_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
                    file_chunk_hashes.push(chunk_b3.clone());

                    // Level-2 Evaluation
                    let vector = if let Some(cached) = self.dedup.cache().get(&chunk_b3) {
                        cached
                    } else {
                        let vec = self
                            .embedder
                            .embed_text(raw.text_slice)
                            .unwrap_or_else(|_| vec![0.0; self.embedder.dimension()]);
                        self.dedup.cache().insert(chunk_b3.clone(), vec.clone());
                        vec
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
                    doc_chunks.push(doc_chunk);
                }

                let _ = self.storage.delete_by_file_path(&path_str).await;
                if !doc_chunks.is_empty() {
                    let _ = self.storage.insert_chunks(&doc_chunks).await?;
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
                    chunk_hashes: vec![doc_chunk.blake3_hash.clone()],
                });

                vec![doc_chunk]
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
                    if let Some(chunks) = self.ingest_file(&path).await? {
                        if !chunks.is_empty() {
                            storage_mutated = true;
                        }
                    }
                }
            }
            WatcherEvent::Remove(path) => {
                let path_str = path.to_string_lossy().to_string();
                let mut count = self.storage.delete_by_file_path(&path_str).await?;
                self.dedup.remove_file(&path);

                // Handle directory deletion: purge all tracked children under path
                let tracked = self.dedup.get_all_tracked_files();
                for tracked_file in tracked {
                    if tracked_file.starts_with(&path) {
                        let tracked_str = tracked_file.to_string_lossy().to_string();
                        let c = self.storage.delete_by_file_path(&tracked_str).await.unwrap_or(0);
                        self.dedup.remove_file(&tracked_file);
                        count += c;
                    }
                }

                if count > 0 {
                    storage_mutated = true;
                }
                debug!(path = %path.display(), count, "Removed deleted file or directory from storage and catalog");
            }
            WatcherEvent::Rename { from, to } => {
                if to.is_dir() {
                    // Directory Rename:
                    // 1. Delete all chunks and catalog entries with old path prefix
                    let tracked = self.dedup.get_all_tracked_files();
                    for tracked_file in tracked {
                        if tracked_file.starts_with(&from) {
                            let old_str = tracked_file.to_string_lossy().to_string();
                            let c = self.storage.delete_by_file_path(&old_str).await.unwrap_or(0);
                            self.dedup.remove_file(&tracked_file);
                            if c > 0 {
                                storage_mutated = true;
                            }
                        }
                    }

                    // 2. Recursively index all files under the new directory path
                    for entry in walkdir::WalkDir::new(&to).into_iter().filter_map(|e| e.ok()) {
                        if entry.file_type().is_file() {
                            let new_file_path = entry.into_path();
                            if let Some(chunks) = self.ingest_file(&new_file_path).await? {
                                if !chunks.is_empty() {
                                    storage_mutated = true;
                                }
                            }
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
                        if let Some(chunks) = self.ingest_file(&to).await? {
                            if !chunks.is_empty() {
                                storage_mutated = true;
                            }
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
            let _ = self.storage.bump_index_epoch("watcher_filesystem_mutation")?;
        }

        Ok(storage_mutated)
    }

    /// Starts the real-time continuous ingestion daemon with OS watcher and periodic drift healer.
    pub async fn start_daemon(&self) -> Result<WatcherHandle, IngestError> {
        self.is_running.store(true, Ordering::SeqCst);

        // 1. Initial crawl across watch paths
        for root in &self.config.watch_paths {
            if root.exists() {
                let _ = self.reindex_worker.run_reindex_sync(ReindexOptions {
                    target_paths: vec![root.clone()],
                    full_rebuild: false,
                    ..Default::default()
                }).await;
            }
        }

        // 2. Start OS watcher
        let watcher = FilesystemWatcher::new(self.config.clone());
        let (mut event_rx, handle) = watcher.start_watching()?;

        // 3. Spawn background event loop
        let is_running = Arc::clone(&self.is_running);
        let storage = Arc::clone(&self.storage);
        let config = self.config.clone();
        let classifier = Arc::clone(&self.classifier);
        let embedder = Arc::clone(&self.embedder);

        tokio::spawn(async move {
            let engine = IngestEngine::new(config, storage, classifier, embedder);
            if let Ok(eng) = engine {
                while is_running.load(Ordering::SeqCst) {
                    tokio::select! {
                        maybe_event = event_rx.recv() => {
                            match maybe_event {
                                Some(event) => {
                                    if let Err(e) = eng.handle_watcher_event(event).await {
                                        warn!("Error handling watcher event: {}", e);
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }
            }
        });

        // 4. Spawn periodic drift healer if configured
        if let Some(interval_secs) = self.config.auto_drift_heal_interval_secs {
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
