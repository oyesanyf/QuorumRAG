//! Dedicated Reindexing Worker for QuorumRAG.
//!
//! Traverses target directories supporting both incremental (`mtime` + Level 1 BLAKE3
//! comparison -> 0 neural calls for untouched/renamed files) and full rebuild (`--full`) modes.
//! Provides asynchronous background task management, cooperative cancellation, and live telemetry.

use chrono::{DateTime, Utc};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use crate::audio_indexer::AudioIndexer;
use crate::chunker::TextChunker;
use crate::classifier_router::CandidateKind;
use crate::config::{ChunkerConfig, IngestConfig, ReindexOptions};
use crate::crawler::{DiscoveredCandidate, FilesystemCrawler};
use crate::dedup::{DedupAction, FileCatalogEntry, Level1DedupCatalog, TwoLevelDedupEngine};
use crate::document_extractor::DocumentExtractor;
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

/// Dedicated low-priority Tokio runtime for continuous background indexing (`ReindexWorker::start_reindex`).
///
/// Isolating background LanceDB/DataFusion/Tantivy/SQLite pipeline futures onto a separate
/// low-priority runtime guarantees that foreground Axum HTTP endpoints (`/`, `/api/health`,
/// `/api/cache/stats`, `/api/reindex/status`, `/api/fs/browse-folders`, `/api/cloud-drives`,
/// folder toggles, and interactive RAG chat) are never starved under multi-million-chunk indexing.
/// Returns `None` (falling back to the active Tokio runtime) if OS thread creation is restricted,
/// ensuring zero panic/abort paths from entry-reachable handlers.
fn background_ingest_runtime() -> Option<&'static tokio::runtime::Runtime> {
    static BG_RUNTIME: std::sync::OnceLock<Option<tokio::runtime::Runtime>> =
        std::sync::OnceLock::new();
    BG_RUNTIME
        .get_or_init(|| {
            let workers = std::thread::available_parallelism()
                .map(|n| (n.get() / 4).clamp(2, 6))
                .unwrap_or(2);
            match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .max_blocking_threads(16)
                .thread_name("quorum-bg-ingest")
                .on_thread_start(|| {
                    crate::throttling::set_background_thread_priority();
                })
                .enable_all()
                .build()
            {
                Ok(rt) => Some(rt),
                Err(err) => {
                    warn!(
                        error = %err,
                        "Failed to initialize dedicated background ingest Tokio runtime; falling back to ambient runtime"
                    );
                    None
                }
            }
        })
        .as_ref()
}

fn spawn_background_ingest<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    if let Some(rt) = background_ingest_runtime() {
        rt.spawn(future);
    } else {
        tokio::spawn(future);
    }
}

/// Guard that decrements `in_flight_tasks` and wakes `task_done_notify` on any exit or panic.
struct InFlightTaskGuard {
    in_flight: Arc<AtomicUsize>,
    notify: Arc<tokio::sync::Notify>,
}

impl Drop for InFlightTaskGuard {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

/// Dedicated Reindex Worker.
pub struct ReindexWorker {
    config: Arc<RwLock<IngestConfig>>,
    storage: Arc<StorageEngine>,
    classifier: Arc<FileTypeClassifier>,
    embedder: Arc<dyn EmbeddingGenerator>,
    dedup: Arc<TwoLevelDedupEngine>,
    active_task: Arc<RwLock<Option<ReindexProgress>>>,
    cancel_flag: Arc<AtomicBool>,
    cancel_tx: Arc<tokio::sync::watch::Sender<u64>>,
    purge_epoch: Arc<AtomicU64>,
    blocked_prefixes: Arc<std::sync::RwLock<Vec<String>>>,
    task_done_notify: Arc<tokio::sync::Notify>,
    in_flight_tasks: Arc<AtomicUsize>,
    commit_gate: Arc<tokio::sync::RwLock<()>>,
    static_watch_paths: Arc<std::sync::RwLock<Vec<std::path::PathBuf>>>,
    dynamic_watch_paths: Arc<std::sync::RwLock<Vec<std::path::PathBuf>>>,
    pending_priority_paths: Arc<tokio::sync::Mutex<Vec<std::path::PathBuf>>>,
    dlp_gate: Arc<RwLock<Option<Arc<dyn quorum_types::DlpContentGate>>>>,
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
            if !cat_path.as_os_str().is_empty()
                && !config.excluded_paths.iter().any(|p| p == cat_path)
            {
                config.excluded_paths.push(cat_path.clone());
            }
        }
        let initial_watch = config.watch_paths.clone();
        Self {
            config: Arc::new(RwLock::new(config)),
            storage,
            classifier,
            embedder,
            dedup,
            active_task: Arc::new(RwLock::new(None)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            cancel_tx: Arc::new(tokio::sync::watch::channel(0u64).0),
            purge_epoch: Arc::new(AtomicU64::new(0)),
            blocked_prefixes: Arc::new(std::sync::RwLock::new(Vec::new())),
            task_done_notify: Arc::new(tokio::sync::Notify::new()),
            in_flight_tasks: Arc::new(AtomicUsize::new(0)),
            commit_gate: Arc::new(tokio::sync::RwLock::new(())),
            static_watch_paths: Arc::new(std::sync::RwLock::new(initial_watch)),
            dynamic_watch_paths: Arc::new(std::sync::RwLock::new(Vec::new())),
            pending_priority_paths: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            dlp_gate: Arc::new(RwLock::new(None)),
        }
    }

    /// Attaches an optional fail-closed `DlpContentGate` (builder helper).
    pub fn with_dlp_gate(self, gate: Arc<dyn quorum_types::DlpContentGate>) -> Self {
        Self {
            dlp_gate: Arc::new(RwLock::new(Some(gate))),
            ..self
        }
    }

    pub(crate) fn set_dlp_gate_try(&self, gate: Arc<dyn quorum_types::DlpContentGate>) {
        if let Ok(mut guard) = self.dlp_gate.try_write() {
            *guard = Some(gate);
        }
    }

    /// Returns a cloned snapshot of the current live `IngestConfig`.
    pub async fn config_snapshot(&self) -> IngestConfig {
        self.config.read().await.clone()
    }

    /// Dynamically updates the active `DlpContentGate`.
    pub async fn set_dlp_gate(&self, gate: Option<Arc<dyn quorum_types::DlpContentGate>>) {
        *self.dlp_gate.write().await = gate;
    }

    /// Dynamically updates `placeholder_policy` on the live `IngestConfig`.
    pub async fn update_placeholder_policy(&self, policy: quorum_types::CloudPlaceholderPolicy) {
        self.config.write().await.placeholder_policy = policy;
    }

    /// Dynamically updates `max_file_size_bytes` on the live `IngestConfig`.
    pub async fn update_max_file_size_bytes(&self, max_file_size_bytes: u64) {
        self.config.write().await.max_file_size_bytes = max_file_size_bytes.max(1);
    }

    /// Dynamically validates and replaces `access_tier_rules` fail-closed (`0..=3` & valid paths).
    pub async fn update_access_tier_rules(
        &self,
        rules: Vec<(std::path::PathBuf, u8)>,
    ) -> Result<(), IngestError> {
        let mut normalized_rules = Vec::with_capacity(rules.len());
        for (prefix, tier) in rules {
            quorum_types::AccessTier::from_u8(tier)?;
            let norm = quorum_types::normalize_prefix_for_match(&prefix.to_string_lossy())?;
            normalized_rules.push((std::path::PathBuf::from(norm), tier));
        }
        self.config.write().await.access_tier_rules = normalized_rules;
        Ok(())
    }

    /// Dynamically updates the normalized list of blocked (e.g., disabled cloud-drive) path
    /// prefixes enforced across watch registration, target filtering, and storage commits.
    pub fn update_blocked_prefixes(&self, prefixes: Vec<String>) {
        let mut clean = Vec::with_capacity(prefixes.len());
        for p in prefixes {
            if let Ok(norm) = quorum_types::normalize_prefix_for_match(&p) {
                if !clean.contains(&norm) {
                    clean.push(norm);
                }
            }
        }
        if let Ok(mut guard) = self.blocked_prefixes.write() {
            *guard = clean;
        }
    }

    /// Returns a snapshot of the currently blocked normalized prefixes.
    pub fn blocked_prefixes_snapshot(&self) -> Vec<String> {
        self.blocked_prefixes
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Returns the current monotonic purge epoch counter.
    pub fn current_purge_epoch(&self) -> u64 {
        self.purge_epoch.load(Ordering::SeqCst)
    }

    #[inline]
    fn is_path_str_blocked(raw: &str, blocked: &[String]) -> bool {
        !blocked.is_empty()
            && blocked
                .iter()
                .any(|pref| quorum_types::path_matches_prefix(raw, pref).unwrap_or(false))
    }

    /// Returns true if `path` (or its canonical target) resides under any blocked prefix.
    pub fn is_path_blocked(&self, path: &std::path::Path) -> bool {
        let blocked = self.blocked_prefixes_snapshot();
        if blocked.is_empty() {
            return false;
        }
        let raw = path.to_string_lossy();
        if Self::is_path_str_blocked(&raw, &blocked) {
            return true;
        }
        if let Ok(canon) = std::fs::canonicalize(path) {
            let cs = canon.to_string_lossy();
            let stripped = cs.strip_prefix(r"\\?\").unwrap_or(&cs);
            if Self::is_path_str_blocked(stripped, &blocked) {
                return true;
            }
        }
        false
    }

    /// Dynamically registers new directories or file paths to be watched and included in continuous reindexing.
    pub fn add_watch_paths(&self, paths: &[std::path::PathBuf]) {
        let blocked = self.blocked_prefixes_snapshot();
        let static_guard = self.static_watch_paths.read().ok();
        if let Ok(mut guard) = self.dynamic_watch_paths.write() {
            for p in paths {
                if p.as_os_str().is_empty()
                    || Self::is_path_str_blocked(&p.to_string_lossy(), &blocked)
                {
                    continue;
                }
                let watch_target = p.clone();
                let in_static = static_guard
                    .as_ref()
                    .map(|sg| sg.iter().any(|existing| existing == &watch_target))
                    .unwrap_or(false);
                if !guard.iter().any(|existing| existing == &watch_target) && !in_static {
                    guard.push(watch_target);
                }
            }
        }
    }

    /// Dynamically removes watch paths (and any matching descendants in `pending_priority_paths`)
    /// using normalized component-boundary prefix matching.
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
        if prefixes.is_empty() {
            return;
        }

        {
            let mut cfg = self.config.write().await;
            cfg.watch_paths.retain(|w| {
                !prefixes
                    .iter()
                    .any(|r| crate::config::path_matches_prefix(w, r))
            });
        }
        if let Ok(mut sg) = self.static_watch_paths.write() {
            sg.retain(|w| {
                !prefixes
                    .iter()
                    .any(|r| crate::config::path_matches_prefix(w, r))
            });
        }
        if let Ok(mut dg) = self.dynamic_watch_paths.write() {
            dg.retain(|w| {
                !prefixes
                    .iter()
                    .any(|r| crate::config::path_matches_prefix(w, r))
            });
        }
        {
            let mut pending = self.pending_priority_paths.lock().await;
            pending.retain(|p| {
                !prefixes
                    .iter()
                    .any(|r| crate::config::path_matches_prefix(p, r))
            });
        }
    }

    /// Returns dynamically added watch paths.
    pub fn dynamic_watch_paths(&self) -> Vec<std::path::PathBuf> {
        self.dynamic_watch_paths
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Returns the union of static `config.watch_paths` and dynamically registered watch paths.
    pub fn all_watch_paths(&self) -> Vec<std::path::PathBuf> {
        let mut all = self
            .static_watch_paths
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();
        for p in self.dynamic_watch_paths() {
            if !all.iter().any(|existing| existing == &p) {
                all.push(p);
            }
        }
        all
    }

    /// Immediately triggers reindexing for `paths` if idle, or injects `paths` into the active pass's
    /// priority queue so newly uploaded/watched folders are indexed immediately without being dropped.
    pub async fn trigger_paths(&self, paths: Vec<std::path::PathBuf>) -> Result<Uuid, IngestError> {
        let clean_paths: Vec<std::path::PathBuf> = paths
            .into_iter()
            .filter(|p| !p.as_os_str().is_empty() && p.exists() && !self.is_path_blocked(p))
            .collect();
        if clean_paths.is_empty() {
            return Err(IngestError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No existing target paths to trigger",
            )));
        }
        self.add_watch_paths(&clean_paths);

        {
            let active = self.active_task.read().await;
            if let Some(ref current) = *active {
                if matches!(
                    current.phase,
                    ReindexPhase::ScanningFilesystem
                        | ReindexPhase::ChunkingAndVectorizing
                        | ReindexPhase::WritingToStorage
                        | ReindexPhase::CompactingIndexes
                ) {
                    let mut pending = self.pending_priority_paths.lock().await;
                    for p in clean_paths {
                        if !self.is_path_blocked(&p)
                            && !pending.iter().any(|existing| existing == &p)
                        {
                            pending.push(p);
                        }
                    }
                    return Ok(current.task_id);
                }
            }
        }

        self.start_reindex(ReindexOptions {
            target_paths: clean_paths,
            full_rebuild: false,
            force_reembed: false,
            batch_size: 64,
            num_threads: 0,
            dry_run: false,
        })
        .await
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
        struct TaskDoneGuard {
            in_flight: Arc<AtomicUsize>,
            notify: Arc<tokio::sync::Notify>,
        }
        impl Drop for TaskDoneGuard {
            fn drop(&mut self) {
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                self.notify.notify_waiters();
            }
        }
        self.in_flight_tasks.fetch_add(1, Ordering::SeqCst);
        let done_guard = TaskDoneGuard {
            in_flight: Arc::clone(&self.in_flight_tasks),
            notify: Arc::clone(&self.task_done_notify),
        };

        let task_purge_epoch = self.purge_epoch.load(Ordering::SeqCst);
        let cancel_baseline_seq = *self.cancel_tx.borrow();

        let mut active = self.active_task.write().await;
        if self.purge_epoch.load(Ordering::SeqCst) != task_purge_epoch {
            return Err(IngestError::Cancelled);
        }
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

        if self.purge_epoch.load(Ordering::SeqCst) != task_purge_epoch {
            return Err(IngestError::Cancelled);
        }

        let task_id = Uuid::new_v4();
        self.cancel_flag.store(false, Ordering::SeqCst);

        if !options.target_paths.is_empty() {
            self.add_watch_paths(&options.target_paths);
        }

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

        let config_lock = Arc::clone(&self.config);
        let dlp_gate_lock = Arc::clone(&self.dlp_gate);
        let dynamic_watch_lock = Arc::clone(&self.dynamic_watch_paths);
        let worker_storage = Arc::clone(&self.storage);
        let worker_classifier = Arc::clone(&self.classifier);
        let worker_embedder = Arc::clone(&self.embedder);
        let worker_dedup = Arc::clone(&self.dedup);
        let worker_progress = Arc::clone(&self.active_task);
        let cancel_flag = Arc::clone(&self.cancel_flag);
        let cancel_tx = Arc::clone(&self.cancel_tx);
        let purge_epoch = Arc::clone(&self.purge_epoch);
        let blocked_prefixes_lock = Arc::clone(&self.blocked_prefixes);
        let commit_gate = Arc::clone(&self.commit_gate);
        let pending_priority = Arc::clone(&self.pending_priority_paths);

        spawn_background_ingest(async move {
            let _done_guard = done_guard;
            let cancel_rx_check = cancel_tx.subscribe();

            let mut loop_options = options;
            loop {
                let res = Self::execute_pipeline(
                    Arc::clone(&config_lock),
                    Arc::clone(&dlp_gate_lock),
                    Arc::clone(&dynamic_watch_lock),
                    Arc::clone(&blocked_prefixes_lock),
                    loop_options.clone(),
                    task_id,
                    Arc::clone(&worker_storage),
                    Arc::clone(&worker_classifier),
                    Arc::clone(&worker_embedder),
                    Arc::clone(&worker_dedup),
                    worker_progress.clone(),
                    Arc::clone(&cancel_flag),
                    cancel_tx.subscribe(),
                    cancel_baseline_seq,
                    Arc::clone(&purge_epoch),
                    task_purge_epoch,
                    Arc::clone(&pending_priority),
                    Arc::clone(&commit_gate),
                )
                .await;

                let leftover_priority: Vec<std::path::PathBuf> = {
                    let mut g = pending_priority.lock().await;
                    std::mem::take(&mut *g)
                };
                let mut final_lock = worker_progress.write().await;

                if res.is_ok()
                    && !Self::is_pipeline_cancelled(
                        &cancel_flag,
                        &cancel_rx_check,
                        cancel_baseline_seq,
                        &purge_epoch,
                        task_purge_epoch,
                    )
                    && !leftover_priority.is_empty()
                {
                    if let Some(ref mut prog) = *final_lock {
                        prog.files_total_estimated =
                            prog.files_total_estimated.max(prog.files_scanned);
                        prog.phase = ReindexPhase::ScanningFilesystem;
                    }
                    drop(final_lock);
                    loop_options.target_paths = leftover_priority;
                    loop_options.full_rebuild = false;
                    loop_options.force_reembed = false;
                    continue;
                }

                if let Some(ref mut prog) = *final_lock {
                    prog.files_total_estimated = prog.files_total_estimated.max(prog.files_scanned);
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
                break;
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

    fn enter_in_flight_task(&self) -> InFlightTaskGuard {
        self.in_flight_tasks.fetch_add(1, Ordering::SeqCst);
        InFlightTaskGuard {
            in_flight: Arc::clone(&self.in_flight_tasks),
            notify: Arc::clone(&self.task_done_notify),
        }
    }

    pub(crate) async fn acquire_commit_read_guard(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.commit_gate.read().await
    }

    #[inline]
    fn is_upgrade_cancelled(
        cancel_rx: &tokio::sync::watch::Receiver<u64>,
        baseline_seq: u64,
        purge_epoch: &AtomicU64,
        task_purge_epoch: u64,
    ) -> bool {
        *cancel_rx.borrow() != baseline_seq
            || purge_epoch.load(Ordering::SeqCst) != task_purge_epoch
    }

    async fn wait_upgrade_cancelled(
        cancel_rx: &mut tokio::sync::watch::Receiver<u64>,
        baseline_seq: u64,
        purge_epoch: &AtomicU64,
        task_purge_epoch: u64,
    ) {
        loop {
            if *cancel_rx.borrow_and_update() != baseline_seq
                || purge_epoch.load(Ordering::SeqCst) != task_purge_epoch
            {
                return;
            }
            if cancel_rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Scans stored chunks, identifies legacy image chunks lacking OCR text,
    /// re-indexes them using ImageIndexer, and replaces them in storage
    /// preserving the exact chunk ID formula {file_b3}:img:0 without re-downloading.
    pub async fn upgrade_legacy_image_chunks(&self) -> Result<usize, IngestError> {
        let _done_guard = self.enter_in_flight_task();
        let task_purge_epoch = self.purge_epoch.load(Ordering::SeqCst);
        let mut cancel_rx = self.cancel_tx.subscribe();
        let cancel_baseline_seq = *cancel_rx.borrow();

        if Self::is_upgrade_cancelled(
            &cancel_rx,
            cancel_baseline_seq,
            &self.purge_epoch,
            task_purge_epoch,
        ) {
            return Err(IngestError::Cancelled);
        }

        let all_chunks = self.storage.scan_all_chunks().await?;
        if Self::is_upgrade_cancelled(
            &cancel_rx,
            cancel_baseline_seq,
            &self.purge_epoch,
            task_purge_epoch,
        ) {
            return Err(IngestError::Cancelled);
        }

        let cfg_snapshot = self.config.read().await.clone();
        let dlp_gate = self.dlp_gate.read().await.clone();
        let mut upgraded_count = 0;

        for chunk in &all_chunks {
            if Self::is_upgrade_cancelled(
                &cancel_rx,
                cancel_baseline_seq,
                &self.purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }

            let is_image = chunk.chunk_id.ends_with(":img:0")
                || chunk
                    .text_content
                    .trim_start()
                    .starts_with("[Image Document:");
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
            if self.is_path_blocked(file_path) || !file_path.exists() {
                continue;
            }

            let classifier_c = Arc::clone(&self.classifier);
            let embedder_c = Arc::clone(&self.embedder);
            let dlp_gate_c = dlp_gate.clone();
            let file_path_buf = file_path.to_path_buf();
            let chunk_id = chunk.chunk_id.clone();
            let chunk_doc_id = chunk.document_id.clone();
            let chunk_file_path = chunk.file_path.clone();
            let placeholder_policy = cfg_snapshot.placeholder_policy;
            let access_tier = cfg_snapshot.resolve_access_tier(file_path);

            enum LegacyImageUpgradeAction {
                Upgraded(
                    DocumentChunk,
                    String,
                    u64,
                    i64,
                    quorum_types::IngestedParentDocument,
                ),
                PurgeExplicit(String),
            }

            let blocking_fut = tokio::task::spawn_blocking(move || {
                let bytes = match crate::cloud_drives::read_bytes_with_placeholder_policy(
                    &file_path_buf,
                    placeholder_policy,
                ) {
                    Ok(b) => b,
                    Err(_) => return None,
                };

                // Verify file hash matches document_id
                let file_b3 = blake3::hash(&bytes).to_hex().to_string();
                if file_b3 != chunk_doc_id {
                    // File content changed on disk; normal reindexer will handle it
                    return None;
                }

                let identity = match classifier_c.classify_file(&file_path_buf) {
                    Ok(i) => i,
                    Err(_) => return None,
                };
                let mut upgraded_chunk = match ImageIndexer::index_image_with_policy(
                    &file_path_buf,
                    &bytes,
                    &identity,
                    access_tier,
                    embedder_c.as_ref(),
                    placeholder_policy,
                ) {
                    Ok(c) => c,
                    Err(quorum_types::TypeError::ContentSafetyBlocked(reason)) => {
                        return Some(LegacyImageUpgradeAction::PurgeExplicit(reason));
                    }
                    Err(_) => return None,
                };

                // Ensure chunk_id and document_id are strictly preserved
                assert_eq!(upgraded_chunk.chunk_id, chunk_id);
                assert_eq!(upgraded_chunk.document_id, chunk_doc_id);

                let gated_text = crate::secret_scrubber::sanitize_and_gate_text(
                    &chunk_file_path,
                    &upgraded_chunk.text_content,
                    access_tier,
                    dlp_gate_c.as_deref(),
                )
                .ok()?;
                let gated_meta_json = crate::secret_scrubber::sanitize_and_gate_metadata_json(
                    &chunk_file_path,
                    &upgraded_chunk.metadata_json,
                    access_tier,
                    dlp_gate_c.as_deref(),
                )
                .ok()?;
                upgraded_chunk.metadata_json = gated_meta_json;
                if gated_text != upgraded_chunk.text_content {
                    upgraded_chunk.text_content = gated_text;
                    upgraded_chunk.blake3_hash =
                        DocumentChunk::compute_blake3_hash(&upgraded_chunk.text_content);
                    upgraded_chunk.vector = embedder_c
                        .embed_text(&upgraded_chunk.text_content)
                        .unwrap_or_else(|_| vec![0.0; embedder_c.dimension()]);
                }

                let mtime_secs = std::fs::metadata(&file_path_buf)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let parent_doc = DocumentExtractor::build_ingested_parent_document_with_policy(
                    &file_path_buf,
                    &upgraded_chunk.document_id,
                    &upgraded_chunk.document_id,
                    &upgraded_chunk.text_content,
                    mtime_secs,
                    bytes.len() as u64,
                    Some(quorum_types::DocumentFormat::ImageFile),
                    placeholder_policy,
                );

                Some(LegacyImageUpgradeAction::Upgraded(
                    upgraded_chunk,
                    file_b3,
                    bytes.len() as u64,
                    mtime_secs,
                    parent_doc,
                ))
            });

            let action = tokio::select! {
                biased;
                _ = Self::wait_upgrade_cancelled(
                    &mut cancel_rx,
                    cancel_baseline_seq,
                    &self.purge_epoch,
                    task_purge_epoch,
                ) => {
                    return Err(IngestError::Cancelled);
                }
                join_res = blocking_fut => match join_res {
                    Ok(Some(res)) => res,
                    Ok(None) | Err(_) => continue,
                }
            };

            let built = match action {
                LegacyImageUpgradeAction::Upgraded(c, b3, len, mt, pdoc) => (c, b3, len, mt, pdoc),
                LegacyImageUpgradeAction::PurgeExplicit(reason) => {
                    warn!(
                        path = %file_path.display(),
                        reason = %reason,
                        "Purging explicit/pornographic legacy image chunk from index"
                    );
                    let _commit_guard = self.commit_gate.read().await;
                    let _ = self.storage.delete_by_file_path(&chunk.file_path).await;
                    self.dedup.remove_file(file_path);
                    continue;
                }
            };

            if Self::is_upgrade_cancelled(
                &cancel_rx,
                cancel_baseline_seq,
                &self.purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            if self.is_path_blocked(file_path) {
                continue;
            }

            let (upgraded_chunk, file_b3, size_bytes, mtime_secs, parent_doc) = built;
            let other_chunks: Vec<DocumentChunk> = all_chunks
                .iter()
                .filter(|c| c.file_path == chunk.file_path && c.chunk_id != chunk.chunk_id)
                .cloned()
                .collect();

            let _commit_permit = crate::thread_pool::IngestThreadPool::shared()
                .permit_tiers()
                .acquire_storage_commit()
                .await?;
            let _commit_guard = self.commit_gate.read().await;
            if Self::is_upgrade_cancelled(
                &cancel_rx,
                cancel_baseline_seq,
                &self.purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            if self.is_path_blocked(file_path) {
                continue;
            }

            // Replace stale chunk in LanceDB and Tantivy
            Self::replace_existing_file_chunks(
                &self.storage,
                std::slice::from_ref(&upgraded_chunk),
            )
            .await;
            let mut chunks_to_insert = vec![upgraded_chunk.clone()];
            chunks_to_insert.extend(other_chunks);
            self.storage.insert_chunks(&chunks_to_insert).await?;

            let _ = self
                .storage
                .upsert_parent_document(&parent_doc, access_tier);

            self.dedup.register_entry(FileCatalogEntry {
                file_path: file_path.to_path_buf(),
                file_blake3: file_b3,
                mtime_secs,
                size_bytes,
                chunk_hashes: vec![upgraded_chunk.blake3_hash],
            });

            upgraded_count += 1;
        }

        if upgraded_count > 0 {
            let _commit_guard = self.commit_gate.read().await;
            if Self::is_upgrade_cancelled(
                &cancel_rx,
                cancel_baseline_seq,
                &self.purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            let _ = self.storage.bump_index_epoch("image_chunks_ocr_upgraded");
        }

        Ok(upgraded_count)
    }

    /// Scans stored chunks at daemon startup for `.docx`, `.odt`, `.xlsx`, `.pptx`, or `.pdf` files
    /// that were previously indexed via degraded fallbacks (e.g. raw PKZIP central directory XML
    /// filenames `[Content_Types].xml` / `word/document.xml` or body-less PDF trailer metadata),
    /// re-extracts them using the native Rust `DocumentExtractor`, and replaces them in storage.
    pub async fn upgrade_degraded_document_chunks(&self) -> Result<usize, IngestError> {
        let _done_guard = self.enter_in_flight_task();
        let task_purge_epoch = self.purge_epoch.load(Ordering::SeqCst);
        let mut cancel_rx = self.cancel_tx.subscribe();
        let cancel_baseline_seq = *cancel_rx.borrow();

        if Self::is_upgrade_cancelled(
            &cancel_rx,
            cancel_baseline_seq,
            &self.purge_epoch,
            task_purge_epoch,
        ) {
            return Err(IngestError::Cancelled);
        }

        let all_chunks = self.storage.scan_all_chunks().await?;
        if Self::is_upgrade_cancelled(
            &cancel_rx,
            cancel_baseline_seq,
            &self.purge_epoch,
            task_purge_epoch,
        ) {
            return Err(IngestError::Cancelled);
        }

        let mut degraded_paths: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();

        for chunk in &all_chunks {
            if self.is_path_blocked(std::path::Path::new(&chunk.file_path)) {
                continue;
            }
            if DocumentExtractor::is_degraded_document_chunk(&chunk.file_path, &chunk.text_content)
            {
                degraded_paths.insert(chunk.file_path.clone());
            }
        }

        if degraded_paths.is_empty() {
            return Ok(0);
        }

        let cfg_snapshot = self.config.read().await.clone();
        let dlp_gate = self.dlp_gate.read().await.clone();
        let chunker = TextChunker::new(ChunkerConfig::default());
        let mut upgraded_files = 0usize;

        for path_str in degraded_paths {
            if Self::is_upgrade_cancelled(
                &cancel_rx,
                cancel_baseline_seq,
                &self.purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }

            let file_path = std::path::Path::new(&path_str);
            if self.is_path_blocked(file_path) || !file_path.exists() {
                continue;
            }
            if crate::cloud_drives::ensure_open_allowed_for_placeholder(
                file_path,
                cfg_snapshot.placeholder_policy,
            )
            .is_err()
            {
                continue;
            }

            let classifier_c = Arc::clone(&self.classifier);
            let embedder_c = Arc::clone(&self.embedder);
            let dedup_c = Arc::clone(&self.dedup);
            let purge_epoch_c = Arc::clone(&self.purge_epoch);
            let dlp_gate_c = dlp_gate.clone();
            let chunker_c = chunker.clone();
            let file_path_buf = file_path.to_path_buf();
            let path_str_c = path_str.clone();
            let placeholder_policy = cfg_snapshot.placeholder_policy;
            let access_tier = cfg_snapshot.resolve_access_tier(file_path);

            let blocking_fut = tokio::task::spawn_blocking(move || {
                let identity = classifier_c.classify_file(&file_path_buf).ok()?;
                let raw_content = match DocumentExtractor::extract_text_with_policy(
                    &file_path_buf,
                    &identity,
                    placeholder_policy,
                ) {
                    Ok(c) if !c.trim().is_empty() => c,
                    _ => return None,
                };
                if DocumentExtractor::is_degraded_document_chunk(&path_str_c, &raw_content) {
                    return None;
                }

                let content = crate::secret_scrubber::sanitize_and_gate_text(
                    &path_str_c,
                    &raw_content,
                    access_tier,
                    dlp_gate_c.as_deref(),
                )
                .ok()?;

                let file_b3 = Level1DedupCatalog::hash_file_stream_with_policy(
                    &file_path_buf,
                    placeholder_policy,
                )
                .unwrap_or_else(|_| blake3::hash(content.as_bytes()).to_hex().to_string());
                let raw_chunks = chunker_c.chunk_text_structure_aware(&content);
                if raw_chunks.is_empty() {
                    return None;
                }

                let mut resolved_meta = crate::chunker::resolve_document_metadata_with_policy(
                    &file_path_buf,
                    &content,
                    placeholder_policy,
                );
                crate::secret_scrubber::sanitize_and_gate_resolved_metadata(
                    &path_str_c,
                    &mut resolved_meta,
                    access_tier,
                    dlp_gate_c.as_deref(),
                )
                .ok()?;

                let file_meta = std::fs::metadata(&file_path_buf).ok();
                let upgraded_mtime = file_meta
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let upgraded_size = file_meta
                    .as_ref()
                    .map(|m| m.len())
                    .unwrap_or(content.len() as u64);
                let mut parent_doc = DocumentExtractor::build_ingested_parent_document_with_policy(
                    &file_path_buf,
                    &file_b3,
                    &file_b3,
                    &content,
                    upgraded_mtime,
                    upgraded_size,
                    None,
                    placeholder_policy,
                );
                crate::secret_scrubber::sanitize_and_gate_parent_document(
                    &mut parent_doc,
                    access_tier,
                    dlp_gate_c.as_deref(),
                )
                .ok()?;

                let header = crate::chunker::format_contextual_header_from_meta(&resolved_meta);
                let contract_hash = embedder_c.contract().derive_contract_hash_hex();
                let mut file_chunk_hashes = Vec::with_capacity(raw_chunks.len());
                let mut doc_chunks = Vec::with_capacity(raw_chunks.len());

                for raw in raw_chunks {
                    if purge_epoch_c.load(Ordering::SeqCst) != task_purge_epoch {
                        return None;
                    }
                    let raw_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
                    let chunk_content = crate::chunker::prepend_contextual_header_with_section(
                        &header,
                        &raw.section_path,
                        raw.text_slice,
                    );
                    file_chunk_hashes.push(raw_b3.clone());

                    let vector = if let Some(cached) = dedup_c.cache().get(&raw_b3) {
                        cached
                    } else {
                        let vec = embedder_c
                            .embed_text(raw.text_slice)
                            .unwrap_or_else(|_| vec![0.0; embedder_c.dimension()]);
                        dedup_c.cache().insert(raw_b3, vec.clone());
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
                        "doc_title": resolved_meta.title,
                        "doc_author": resolved_meta.author,
                        "doc_revision": resolved_meta.revision,
                        "heading_path": raw.section_path,
                        "section_path": raw.section_path,
                        "section_title": raw.section_title,
                        "section_hierarchy": raw.section_hierarchy,
                        "section_level": raw.section_level,
                        "source_path": path_str_c.clone(),
                    })
                    .to_string();

                    if let Ok(dc) = DocumentChunk::new(
                        chunk_id,
                        file_b3.clone(),
                        &path_str_c,
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
                    return None;
                }

                Some((
                    doc_chunks,
                    parent_doc,
                    file_b3,
                    file_chunk_hashes,
                    file_meta.map(|m| (upgraded_mtime, m.len())),
                ))
            });

            let built = tokio::select! {
                biased;
                _ = Self::wait_upgrade_cancelled(
                    &mut cancel_rx,
                    cancel_baseline_seq,
                    &self.purge_epoch,
                    task_purge_epoch,
                ) => {
                    return Err(IngestError::Cancelled);
                }
                join_res = blocking_fut => match join_res {
                    Ok(Some(res)) => res,
                    Ok(None) | Err(_) => continue,
                }
            };

            if Self::is_upgrade_cancelled(
                &cancel_rx,
                cancel_baseline_seq,
                &self.purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            if self.is_path_blocked(file_path) {
                continue;
            }

            let (doc_chunks, parent_doc, file_b3, file_chunk_hashes, catalog_meta) = built;

            let _commit_permit = crate::thread_pool::IngestThreadPool::shared()
                .permit_tiers()
                .acquire_storage_commit()
                .await?;
            let _commit_guard = self.commit_gate.read().await;
            if Self::is_upgrade_cancelled(
                &cancel_rx,
                cancel_baseline_seq,
                &self.purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            if self.is_path_blocked(file_path) {
                continue;
            }

            let _ = self.storage.delete_by_file_path(&path_str).await;
            self.storage.insert_chunks(&doc_chunks).await?;
            let _ = self
                .storage
                .upsert_parent_document(&parent_doc, access_tier);

            if let Some((mtime_secs, size_bytes)) = catalog_meta {
                self.dedup.register_entry(FileCatalogEntry {
                    file_path: file_path.to_path_buf(),
                    file_blake3: file_b3,
                    mtime_secs,
                    size_bytes,
                    chunk_hashes: file_chunk_hashes,
                });
            }
            upgraded_files += 1;
        }

        if upgraded_files > 0 {
            let _commit_guard = self.commit_gate.read().await;
            if Self::is_upgrade_cancelled(
                &cancel_rx,
                cancel_baseline_seq,
                &self.purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            if let Some(ref cat_path) = cfg_snapshot.dedup_catalog_path {
                let _ = self.dedup.save_catalog_to_file(cat_path);
            }
            let _ = self
                .storage
                .bump_index_epoch("degraded_doc_chunks_upgraded");
            info!(
                upgraded_files,
                "Self-healed degraded DOCX/PDF chunks using native Rust extractor"
            );
        }

        Ok(upgraded_files)
    }

    #[inline]
    fn is_pipeline_cancelled(
        cancel_flag: &AtomicBool,
        cancel_rx: &tokio::sync::watch::Receiver<u64>,
        baseline_seq: u64,
        purge_epoch: &AtomicU64,
        task_purge_epoch: u64,
    ) -> bool {
        cancel_flag.load(Ordering::SeqCst)
            || *cancel_rx.borrow() != baseline_seq
            || purge_epoch.load(Ordering::SeqCst) != task_purge_epoch
    }

    async fn wait_pipeline_cancelled(
        cancel_flag: &AtomicBool,
        cancel_rx: &mut tokio::sync::watch::Receiver<u64>,
        baseline_seq: u64,
        purge_epoch: &AtomicU64,
        task_purge_epoch: u64,
    ) {
        loop {
            if cancel_flag.load(Ordering::SeqCst)
                || *cancel_rx.borrow_and_update() != baseline_seq
                || purge_epoch.load(Ordering::SeqCst) != task_purge_epoch
            {
                return;
            }
            if cancel_rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Cooperative cancellation of an ongoing reindex task.
    pub fn cancel_reindex(&self) -> bool {
        self.cancel_flag.store(true, Ordering::SeqCst);
        self.cancel_tx.send_modify(|seq| *seq = seq.wrapping_add(1));
        true
    }

    /// Acquires an exclusive storage/dedup purge barrier serialized against all
    /// `ReindexWorker` batch storage commits so prefix purges cannot interleave with
    /// late chunk, parent-document, or dedup-catalog writes.
    pub async fn acquire_purge_barrier(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.commit_gate.write().await
    }

    /// Returns shared purge-barrier synchronization handles (`purge_epoch`, `blocked_prefixes`,
    /// `commit_gate`) so sibling workers such as `DriftHealer` serialize storage/dedup commits
    /// against prefix purges and observe monotonic purge epochs immediately.
    pub fn purge_barrier_handles(
        &self,
    ) -> (
        Arc<AtomicU64>,
        Arc<std::sync::RwLock<Vec<String>>>,
        Arc<RwLock<()>>,
    ) {
        (
            Arc::clone(&self.purge_epoch),
            Arc::clone(&self.blocked_prefixes),
            Arc::clone(&self.commit_gate),
        )
    }

    /// Cancels all ongoing reindex tasks (including concurrent `run_reindex_sync` calls)
    /// and waits up to `timeout` for every in-flight worker to reach a terminal state so
    /// subsequent storage/dedup purges cannot race with an in-flight batch write.
    pub async fn cancel_and_drain(&self, timeout: std::time::Duration) -> bool {
        self.purge_epoch.fetch_add(1, Ordering::SeqCst);
        self.cancel_flag.store(true, Ordering::SeqCst);
        self.cancel_tx.send_modify(|seq| *seq = seq.wrapping_add(1));
        let is_active = |phase: ReindexPhase| {
            matches!(
                phase,
                ReindexPhase::ScanningFilesystem
                    | ReindexPhase::ChunkingAndVectorizing
                    | ReindexPhase::WritingToStorage
                    | ReindexPhase::CompactingIndexes
            )
        };
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.task_done_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let shared_running = {
                let guard = self.active_task.read().await;
                guard.as_ref().is_some_and(|p| is_active(p.phase))
            };
            let any_in_flight = self.in_flight_tasks.load(Ordering::SeqCst) > 0;
            if !shared_running && !any_in_flight {
                return true;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let _ = tokio::time::timeout(
                remaining.min(std::time::Duration::from_millis(50)),
                notified,
            )
            .await;
        }
    }

    /// Fetches the latest live progress of the reindex worker.
    pub async fn get_progress(&self) -> Option<ReindexProgress> {
        let lock = self.active_task.read().await;
        lock.clone()
    }

    /// Synchronous reindex execution (used by CLI commands, `POST /api/documents/add`, or unit tests).
    pub async fn run_reindex_sync(
        &self,
        options: ReindexOptions,
    ) -> Result<ReindexProgress, IngestError> {
        let task_id = Uuid::new_v4();

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

        struct SyncTaskDoneGuard {
            in_flight: Arc<AtomicUsize>,
            notify: Arc<tokio::sync::Notify>,
        }
        impl Drop for SyncTaskDoneGuard {
            fn drop(&mut self) {
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                self.notify.notify_waiters();
            }
        }
        self.in_flight_tasks.fetch_add(1, Ordering::SeqCst);
        let _done_guard = SyncTaskDoneGuard {
            in_flight: Arc::clone(&self.in_flight_tasks),
            notify: Arc::clone(&self.task_done_notify),
        };

        let task_purge_epoch = self.purge_epoch.load(Ordering::SeqCst);
        let cancel_baseline_seq = *self.cancel_tx.borrow();

        // If no background task is currently running in `self.active_task`, publish live progress
        // directly to `self.active_task` so `GET /api/reindex/status` and the sidebar UI update in real time.
        let use_shared_active = {
            let mut active_guard = self.active_task.write().await;
            if self.purge_epoch.load(Ordering::SeqCst) != task_purge_epoch {
                return Err(IngestError::Cancelled);
            }
            let is_busy = active_guard.as_ref().is_some_and(|c| {
                matches!(
                    c.phase,
                    ReindexPhase::ScanningFilesystem
                        | ReindexPhase::ChunkingAndVectorizing
                        | ReindexPhase::WritingToStorage
                        | ReindexPhase::CompactingIndexes
                )
            });
            if !is_busy {
                if self.purge_epoch.load(Ordering::SeqCst) != task_purge_epoch {
                    return Err(IngestError::Cancelled);
                }
                self.cancel_flag.store(false, Ordering::SeqCst);
                *active_guard = Some(initial_progress.clone());
                true
            } else {
                false
            }
        };

        if !options.target_paths.is_empty() {
            self.add_watch_paths(&options.target_paths);
        }

        let progress_state = if use_shared_active {
            Arc::clone(&self.active_task)
        } else {
            Arc::new(RwLock::new(Some(initial_progress)))
        };

        let pending_queue = if use_shared_active {
            Arc::clone(&self.pending_priority_paths)
        } else {
            Arc::new(tokio::sync::Mutex::new(Vec::new()))
        };

        let cancel_rx_check = self.cancel_tx.subscribe();
        let mut loop_options = options;
        let final_res = loop {
            let res = Self::execute_pipeline(
                Arc::clone(&self.config),
                Arc::clone(&self.dlp_gate),
                Arc::clone(&self.dynamic_watch_paths),
                Arc::clone(&self.blocked_prefixes),
                loop_options.clone(),
                task_id,
                Arc::clone(&self.storage),
                Arc::clone(&self.classifier),
                Arc::clone(&self.embedder),
                Arc::clone(&self.dedup),
                progress_state.clone(),
                Arc::clone(&self.cancel_flag),
                self.cancel_tx.subscribe(),
                cancel_baseline_seq,
                Arc::clone(&self.purge_epoch),
                task_purge_epoch,
                Arc::clone(&pending_queue),
                Arc::clone(&self.commit_gate),
            )
            .await;

            if use_shared_active
                && res.is_ok()
                && !Self::is_pipeline_cancelled(
                    &self.cancel_flag,
                    &cancel_rx_check,
                    cancel_baseline_seq,
                    &self.purge_epoch,
                    task_purge_epoch,
                )
            {
                let leftover_priority: Vec<std::path::PathBuf> = {
                    let mut g = pending_queue.lock().await;
                    std::mem::take(&mut *g)
                };
                if !leftover_priority.is_empty() {
                    let mut lock = progress_state.write().await;
                    if let Some(ref mut prog) = *lock {
                        prog.files_total_estimated =
                            prog.files_total_estimated.max(prog.files_scanned);
                        prog.phase = ReindexPhase::ScanningFilesystem;
                    }
                    drop(lock);
                    loop_options.target_paths = leftover_priority;
                    loop_options.full_rebuild = false;
                    loop_options.force_reembed = false;
                    continue;
                }
            }
            break res;
        };

        let mut lock = progress_state.write().await;
        let mut final_prog = lock.clone().ok_or_else(|| {
            IngestError::WatcherError("reindex finished without a progress record".into())
        })?;
        final_prog.files_total_estimated = final_prog
            .files_total_estimated
            .max(final_prog.files_scanned);
        final_prog.completed_at = Some(Utc::now());
        final_prog.elapsed_secs = (Utc::now() - final_prog.started_at).num_seconds().max(0) as u64;
        match &final_res {
            Ok(_) => final_prog.phase = ReindexPhase::Completed,
            Err(IngestError::Cancelled) => final_prog.phase = ReindexPhase::Cancelled,
            Err(e) => {
                final_prog.phase = ReindexPhase::Failed;
                final_prog.error_message = Some(e.to_string());
            }
        }
        if use_shared_active {
            *lock = Some(final_prog.clone());
        } else {
            *lock = None;
        }
        drop(lock);
        drop(_done_guard);

        final_res?;
        Ok(final_prog)
    }

    /// Internal execution loop for reindexing.
    #[allow(clippy::too_many_arguments)]
    async fn execute_pipeline(
        config_lock: Arc<RwLock<IngestConfig>>,
        dlp_gate_lock: Arc<RwLock<Option<Arc<dyn quorum_types::DlpContentGate>>>>,
        dynamic_watch_lock: Arc<std::sync::RwLock<Vec<std::path::PathBuf>>>,
        blocked_prefixes_lock: Arc<std::sync::RwLock<Vec<String>>>,
        options: ReindexOptions,
        _task_id: Uuid,
        storage: Arc<StorageEngine>,
        _classifier: Arc<FileTypeClassifier>,
        embedder: Arc<dyn EmbeddingGenerator>,
        dedup: Arc<TwoLevelDedupEngine>,
        progress: Arc<RwLock<Option<ReindexProgress>>>,
        cancel_flag: Arc<AtomicBool>,
        mut cancel_rx: tokio::sync::watch::Receiver<u64>,
        cancel_baseline_seq: u64,
        purge_epoch: Arc<AtomicU64>,
        task_purge_epoch: u64,
        pending_priority_paths: Arc<tokio::sync::Mutex<Vec<std::path::PathBuf>>>,
        commit_gate: Arc<tokio::sync::RwLock<()>>,
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

        if Self::is_pipeline_cancelled(
            &cancel_flag,
            &cancel_rx,
            cancel_baseline_seq,
            &purge_epoch,
            task_purge_epoch,
        ) {
            return Err(IngestError::Cancelled);
        }

        // Hydrate deduplication state from SQLite document catalog off the async executor
        {
            let dedup_h = Arc::clone(&dedup);
            let storage_h = Arc::clone(&storage);
            match tokio::task::spawn_blocking(move || {
                crate::throttling::set_background_thread_priority();
                let res = dedup_h.hydrate_from_catalog(&storage_h);
                crate::throttling::end_background_thread_priority();
                res
            })
            .await
            {
                Ok(Err(e)) => {
                    warn!(
                        "Failed to hydrate dedup catalog from document_catalog.db: {}",
                        e
                    );
                }
                Err(e) => {
                    warn!("Dedup catalog hydration join error: {}", e);
                }
                Ok(Ok(_)) => {}
            }
        }

        let mut config = config_lock.read().await.clone();
        if let Ok(dyn_guard) = dynamic_watch_lock.read() {
            for p in dyn_guard.iter() {
                if !config.watch_paths.iter().any(|existing| existing == p) {
                    config.watch_paths.push(p.clone());
                }
            }
        }

        let storage_path = storage.config().storage_path.clone();
        if !config.excluded_paths.iter().any(|p| p == &storage_path) {
            config.excluded_paths.push(storage_path);
        }
        if let Some(ref cat_path) = config.dedup_catalog_path {
            if !cat_path.as_os_str().is_empty()
                && !config.excluded_paths.iter().any(|p| p == cat_path)
            {
                config.excluded_paths.push(cat_path.clone());
            }
        }
        let blocked_initial = blocked_prefixes_lock
            .read()
            .map(|g| g.clone())
            .unwrap_or_default();
        for bp in &blocked_initial {
            let bp_pb = std::path::PathBuf::from(bp);
            if !config.excluded_paths.iter().any(|ex| ex == &bp_pb) {
                config.excluded_paths.push(bp_pb);
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

        let targets_raw = raw_targets.clone();
        let targets = tokio::task::spawn_blocking(move || Self::expand_drive_roots(&targets_raw))
            .await
            .unwrap_or(raw_targets);
        let targets: Vec<std::path::PathBuf> = targets
            .into_iter()
            .filter(|t| {
                !config
                    .excluded_paths
                    .iter()
                    .any(|ex| crate::config::path_matches_prefix(t, ex))
                    && !Self::is_path_str_blocked(&t.to_string_lossy(), &blocked_initial)
            })
            .collect();
        if targets.is_empty() {
            return Ok(());
        }
        let chunker = TextChunker::new(ChunkerConfig::default());

        // Phase 1: Decoupled Upfront Discovery across all target slices (Unified work-stealing parallel crawl)
        let crawler = Arc::new(FilesystemCrawler::new(config.clone()));
        let crawler_c = Arc::clone(&crawler);
        let targets_c = targets.clone();
        if Self::is_pipeline_cancelled(
            &cancel_flag,
            &cancel_rx,
            cancel_baseline_seq,
            &purge_epoch,
            task_purge_epoch,
        ) {
            return Err(IngestError::Cancelled);
        }
        let crawl_fut = tokio::task::spawn_blocking(move || {
            crate::throttling::set_background_thread_priority();
            let res = crawler_c.crawl_multi_root_sync(&targets_c);
            crate::throttling::end_background_thread_priority();
            res
        });
        let all_candidates = tokio::select! {
            biased;
            _ = Self::wait_pipeline_cancelled(&cancel_flag, &mut cancel_rx, cancel_baseline_seq, &purge_epoch, task_purge_epoch) => {
                return Err(IngestError::Cancelled);
            }
            join_res = crawl_fut => {
                join_res
                    .map_err(|e| IngestError::Io(std::io::Error::other(format!("Crawler task join failed: {}", e))))??
            }
        };
        if Self::is_pipeline_cancelled(
            &cancel_flag,
            &cancel_rx,
            cancel_baseline_seq,
            &purge_epoch,
            task_purge_epoch,
        ) {
            return Err(IngestError::Cancelled);
        }

        let mut candidate_queue: std::collections::VecDeque<DiscoveredCandidate> =
            all_candidates.into_iter().collect();

        // Transition to Phase 2: Chunking & Vectorizing with total candidate count fixed
        {
            let mut lock = progress.write().await;
            if let Some(ref mut p) = *lock {
                if p.files_scanned == 0 {
                    p.files_total_estimated = candidate_queue.len();
                } else {
                    p.files_total_estimated =
                        (p.files_total_estimated + candidate_queue.len()).max(p.files_scanned);
                }
                p.phase = ReindexPhase::ChunkingAndVectorizing;
            }
        }

        let catalog_path = config
            .dedup_catalog_path
            .as_ref()
            .cloned()
            .unwrap_or_else(|| storage.config().storage_path.join("dedup_catalog.json"));

        let thread_pool = crate::thread_pool::IngestThreadPool::shared();
        let concurrency = if options.num_threads > 0 {
            options.num_threads.clamp(1, 64)
        } else {
            thread_pool.thread_count().clamp(2, 8)
        };
        let permit_tiers = crate::thread_pool::IngestPermitTiers::new(concurrency);

        let mut batch_chunks: Vec<DocumentChunk> = Vec::with_capacity(options.batch_size.max(64));
        let mut batch_parents: Vec<(quorum_types::IngestedParentDocument, u8)> =
            Vec::with_capacity(options.batch_size.max(64));
        let mut batch_catalog_entries: Vec<FileCatalogEntry> =
            Vec::with_capacity(options.batch_size.max(64));

        let mut futures = FuturesUnordered::new();
        let mut last_catalog_save = std::time::Instant::now();
        let mut committed_any_non_blocked = false;
        let mut unchanged_streak: usize = 0;

        loop {
            if Self::is_pipeline_cancelled(
                &cancel_flag,
                &cancel_rx,
                cancel_baseline_seq,
                &purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }

            // Drain any priority paths dynamically added via watcher or folder upload while running
            let newly_queued_paths: Vec<std::path::PathBuf> = {
                let mut g = pending_priority_paths.lock().await;
                std::mem::take(&mut *g)
            };
            if !newly_queued_paths.is_empty() {
                let blocked_now = blocked_prefixes_lock
                    .read()
                    .map(|g| g.clone())
                    .unwrap_or_default();
                let mut live_cfg = config_lock.read().await.clone();
                for bp in &blocked_now {
                    let bp_pb = std::path::PathBuf::from(bp);
                    if !live_cfg.excluded_paths.iter().any(|ex| ex == &bp_pb) {
                        live_cfg.excluded_paths.push(bp_pb);
                    }
                }
                let newly_queued_for_expand = newly_queued_paths.clone();
                let expanded_raw = tokio::task::spawn_blocking(move || {
                    Self::expand_drive_roots(&newly_queued_for_expand)
                })
                .await
                .unwrap_or(newly_queued_paths);
                let expanded_priority: Vec<std::path::PathBuf> = expanded_raw
                    .into_iter()
                    .filter(|t| {
                        !live_cfg
                            .excluded_paths
                            .iter()
                            .any(|ex| crate::config::path_matches_prefix(t, ex))
                            && !Self::is_path_str_blocked(&t.to_string_lossy(), &blocked_now)
                    })
                    .collect();
                if !expanded_priority.is_empty() {
                    let crawler_p = Arc::new(FilesystemCrawler::new(live_cfg));
                    if let Ok(Ok(priority_candidates)) = tokio::task::spawn_blocking(move || {
                        crawler_p.crawl_multi_root_sync(&expanded_priority)
                    })
                    .await
                    {
                        if !priority_candidates.is_empty() {
                            let added_count = priority_candidates.len();
                            for cand in priority_candidates.into_iter().rev() {
                                candidate_queue.push_front(cand);
                            }
                            let mut lock = progress.write().await;
                            if let Some(ref mut p) = *lock {
                                p.files_total_estimated += added_count;
                            }
                        }
                    }
                }
            }

            // Fill concurrency slots up to capacity
            while futures.len() < concurrency {
                let Some(candidate) = candidate_queue.pop_front() else {
                    break;
                };

                let path = candidate.path.clone();
                let blocked_now = blocked_prefixes_lock
                    .read()
                    .map(|g| g.clone())
                    .unwrap_or_default();
                if Self::is_path_str_blocked(&path.to_string_lossy(), &blocked_now) {
                    continue;
                }
                let (access_tier, placeholder_policy) = {
                    let live_cfg = config_lock.read().await;
                    (
                        live_cfg.resolve_access_tier(&path),
                        live_cfg.placeholder_policy,
                    )
                };
                let dlp_gate = dlp_gate_lock.read().await.clone();

                // Level-1 Zero-I/O Fast Path: skip unmodified files purely from in-memory metadata.
                // Any fast-path miss (requiring disk read + BLAKE3 streaming) runs off the Tokio
                // runtime inside the low-priority core-pinned `IngestThreadPool`.
                if !options.full_rebuild
                    && dedup
                        .check_unchanged_fast(&path, candidate.mtime_secs, candidate.size_bytes)
                        .is_some()
                {
                    let mut lock = progress.write().await;
                    if let Some(ref mut p) = *lock {
                        p.files_scanned += 1;
                        p.files_total_estimated = p.files_total_estimated.max(p.files_scanned);
                        p.files_skipped_unmodified += 1;
                        p.bytes_processed += candidate.size_bytes;
                    }
                    drop(lock);
                    unchanged_streak = unchanged_streak.wrapping_add(1);
                    if unchanged_streak % 64 == 0 {
                        tokio::task::yield_now().await;
                    }
                    continue;
                }
                unchanged_streak = 0;

                let permit = permit_tiers.acquire_extraction().await?;
                let permit_slot = Arc::new(std::sync::Mutex::new(Some(permit)));
                let permit_slot_c = Arc::clone(&permit_slot);

                let embedder_c = Arc::clone(&embedder);
                let dedup_c = Arc::clone(&dedup);
                let storage_c = Arc::clone(&storage);
                let chunker_c = chunker.clone();
                let force_reembed = options.force_reembed;
                let full_rebuild = options.full_rebuild;
                let path_for_timeout = path.clone();

                let blocking_fut = thread_pool.spawn_task(move || {
                    let outcome = process_candidate_sync(
                        candidate,
                        access_tier,
                        placeholder_policy,
                        dlp_gate,
                        force_reembed || full_rebuild,
                        !full_rebuild,
                        storage_c,
                        embedder_c,
                        dedup_c,
                        chunker_c,
                        None,
                    );
                    if let Ok(mut guard) = permit_slot_c.lock() {
                        drop(guard.take());
                    }
                    outcome
                });

                // Per-candidate 45s timeout so a single hung file is removed from `futures` and counted once
                futures.push(async move {
                    match tokio::time::timeout(std::time::Duration::from_secs(45), blocking_fut).await {
                        Ok(join_res) => join_res,
                        Err(_) => {
                            // Guard against permit abandonment: reclaim and drop extraction permit immediately
                            if let Ok(mut guard) = permit_slot.lock() {
                                if let Some(abandoned_permit) = guard.take() {
                                    tracing::warn!(
                                        path = %path_for_timeout.display(),
                                        "Reclaimed abandoned extraction permit after 45s candidate timeout"
                                    );
                                    drop(abandoned_permit);
                                }
                            }
                            Ok(CandidateOutcome::Failed {
                                path: path_for_timeout,
                                error: "Candidate extraction task timed out after 45s".to_string(),
                            })
                        }
                    }
                });
            }

            if futures.is_empty() {
                let has_more_priority = !pending_priority_paths.lock().await.is_empty();
                if has_more_priority {
                    continue;
                }
                break;
            }

            if Self::is_pipeline_cancelled(
                &cancel_flag,
                &cancel_rx,
                cancel_baseline_seq,
                &purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            let next_join_res = tokio::select! {
                biased;
                _ = Self::wait_pipeline_cancelled(&cancel_flag, &mut cancel_rx, cancel_baseline_seq, &purge_epoch, task_purge_epoch) => {
                    return Err(IngestError::Cancelled);
                }
                res = futures.next() => res,
            };
            if Self::is_pipeline_cancelled(
                &cancel_flag,
                &cancel_rx,
                cancel_baseline_seq,
                &purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }

            if let Some(join_res) = next_join_res {
                match join_res {
                    Ok(outcome) => match outcome {
                        CandidateOutcome::Unchanged { size_bytes } => {
                            let mut lock = progress.write().await;
                            if let Some(ref mut p) = *lock {
                                p.files_scanned += 1;
                                p.files_total_estimated =
                                    p.files_total_estimated.max(p.files_scanned);
                                p.files_skipped_unmodified += 1;
                                p.bytes_processed += size_bytes;
                            }
                        }
                        CandidateOutcome::AlreadyIndexedInFts {
                            catalog_entry,
                            size_bytes,
                        } => {
                            batch_catalog_entries.push(catalog_entry);
                            let mut lock = progress.write().await;
                            if let Some(ref mut p) = *lock {
                                p.files_scanned += 1;
                                p.files_total_estimated =
                                    p.files_total_estimated.max(p.files_scanned);
                                p.files_skipped_unmodified += 1;
                                p.bytes_processed += size_bytes;
                            }
                        }
                        CandidateOutcome::Processed {
                            chunks,
                            parent_doc,
                            catalog_entry,
                            moved_from_path,
                            size_bytes,
                            chunks_reused,
                            chunks_new,
                        } => {
                            if let Some(old_path) = moved_from_path {
                                let _commit_guard = commit_gate.read().await;
                                if Self::is_pipeline_cancelled(
                                    &cancel_flag,
                                    &cancel_rx,
                                    cancel_baseline_seq,
                                    &purge_epoch,
                                    task_purge_epoch,
                                ) {
                                    return Err(IngestError::Cancelled);
                                }
                                let old_key = old_path.to_string_lossy().to_string();
                                let _ = storage.delete_by_file_path(&old_key).await;
                                dedup.remove_file(&old_path);
                                info!(old = %old_path.display(), new = %catalog_entry.file_path.display(), "Detected moved/renamed file during reindex; purging old path and re-indexing under new path/tier (L2 vector cache reused)");
                            }
                            batch_catalog_entries.push(catalog_entry);
                            if let Some(parent) = parent_doc {
                                batch_parents.push(parent);
                            }
                            batch_chunks.extend(chunks);

                            let mut lock = progress.write().await;
                            if let Some(ref mut p) = *lock {
                                p.files_scanned += 1;
                                p.files_total_estimated =
                                    p.files_total_estimated.max(p.files_scanned);
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
                                p.files_total_estimated =
                                    p.files_total_estimated.max(p.files_scanned);
                                p.files_failed += 1;
                            }
                        }
                        CandidateOutcome::ContentSafetyBlocked { path, reason } => {
                            warn!(
                                path = %path.display(),
                                reason = %reason,
                                "Blocked explicit/pornographic image during reindex and purging any prior index entry"
                            );
                            let path_key = path.to_string_lossy().to_string();
                            let _ = storage.delete_by_file_path(&path_key).await;
                            dedup.remove_file(&path);
                            let mut lock = progress.write().await;
                            if let Some(ref mut p) = *lock {
                                p.files_scanned += 1;
                                p.files_total_estimated =
                                    p.files_total_estimated.max(p.files_scanned);
                                p.files_skipped_unmodified += 1;
                            }
                        }
                    },
                    Err(e) => {
                        warn!("Blocking reindex worker task failed: {}", e);
                        let mut lock = progress.write().await;
                        if let Some(ref mut p) = *lock {
                            p.files_scanned += 1;
                            p.files_total_estimated = p.files_total_estimated.max(p.files_scanned);
                            p.files_failed += 1;
                        }
                    }
                }

                if last_catalog_save.elapsed() >= std::time::Duration::from_secs(30) {
                    let _commit_guard = commit_gate.read().await;
                    if Self::is_pipeline_cancelled(
                        &cancel_flag,
                        &cancel_rx,
                        cancel_baseline_seq,
                        &purge_epoch,
                        task_purge_epoch,
                    ) {
                        return Err(IngestError::Cancelled);
                    }
                    let blocked_now = blocked_prefixes_lock
                        .read()
                        .map(|g| g.clone())
                        .unwrap_or_default();
                    for entry in batch_catalog_entries.drain(..) {
                        if !Self::is_path_str_blocked(
                            &entry.file_path.to_string_lossy(),
                            &blocked_now,
                        ) {
                            dedup.register_entry(entry);
                        }
                    }
                    let dedup_save = Arc::clone(&dedup);
                    let cat_path_save = catalog_path.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::throttling::set_background_thread_priority();
                        let res = dedup_save.save_catalog_to_file(&cat_path_save);
                        crate::throttling::end_background_thread_priority();
                        res
                    })
                    .await;
                    last_catalog_save = std::time::Instant::now();
                }

                // If micro-batch is full, flush to storage under commit_gate + cancellation + blocked-prefix check
                if batch_chunks.len() >= options.batch_size {
                    if Self::is_pipeline_cancelled(
                        &cancel_flag,
                        &cancel_rx,
                        cancel_baseline_seq,
                        &purge_epoch,
                        task_purge_epoch,
                    ) {
                        return Err(IngestError::Cancelled);
                    }
                    if !options.dry_run {
                        let _commit_permit = permit_tiers.acquire_storage_commit().await?;
                        let _commit_guard = commit_gate.read().await;
                        if Self::is_pipeline_cancelled(
                            &cancel_flag,
                            &cancel_rx,
                            cancel_baseline_seq,
                            &purge_epoch,
                            task_purge_epoch,
                        ) {
                            return Err(IngestError::Cancelled);
                        }
                        let blocked_now = blocked_prefixes_lock
                            .read()
                            .map(|g| g.clone())
                            .unwrap_or_default();
                        batch_chunks
                            .retain(|c| !Self::is_path_str_blocked(&c.file_path, &blocked_now));
                        batch_parents.retain(|(p, _)| {
                            !Self::is_path_str_blocked(&p.source_path, &blocked_now)
                        });
                        batch_catalog_entries.retain(|e| {
                            !Self::is_path_str_blocked(&e.file_path.to_string_lossy(), &blocked_now)
                        });
                        if !batch_chunks.is_empty()
                            || !batch_parents.is_empty()
                            || !batch_catalog_entries.is_empty()
                        {
                            if !batch_chunks.is_empty() {
                                Self::replace_existing_file_chunks(&storage, &batch_chunks).await;
                                let _ = storage.insert_chunks(&batch_chunks).await?;
                                committed_any_non_blocked = true;
                            }
                            if !batch_parents.is_empty() {
                                let parents_to_save = std::mem::take(&mut batch_parents);
                                let storage_p = Arc::clone(&storage);
                                let _ = tokio::task::spawn_blocking(move || {
                                    crate::throttling::set_background_thread_priority();
                                    for (pdoc, ptier) in parents_to_save {
                                        let _ = storage_p.upsert_parent_document(&pdoc, ptier);
                                    }
                                    crate::throttling::end_background_thread_priority();
                                })
                                .await;
                            }
                            for entry in batch_catalog_entries.drain(..) {
                                dedup.register_entry(entry);
                            }
                            // Throttle full dedup_catalog.json serialization to every 30s (plus final flush)
                            // so 65k+ file catalogs do not thrash disk I/O on every micro-batch.
                            if last_catalog_save.elapsed() >= std::time::Duration::from_secs(30) {
                                let dedup_save = Arc::clone(&dedup);
                                let cat_path_save = catalog_path.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    crate::throttling::set_background_thread_priority();
                                    let res = dedup_save.save_catalog_to_file(&cat_path_save);
                                    crate::throttling::end_background_thread_priority();
                                    res
                                })
                                .await;
                                last_catalog_save = std::time::Instant::now();
                            }
                            let _ = storage.bump_index_epoch("reindex_micro_batch");
                        }
                    } else {
                        batch_parents.clear();
                        batch_catalog_entries.clear();
                    }
                    batch_chunks.clear();
                    tokio::task::yield_now().await;
                }
            } else {
                break;
            }
        }

        // Flush remaining micro-batch under commit_gate + cancellation + blocked-prefix check
        if Self::is_pipeline_cancelled(
            &cancel_flag,
            &cancel_rx,
            cancel_baseline_seq,
            &purge_epoch,
            task_purge_epoch,
        ) {
            return Err(IngestError::Cancelled);
        }
        if !options.dry_run
            && (!batch_chunks.is_empty()
                || !batch_parents.is_empty()
                || !batch_catalog_entries.is_empty())
        {
            let _commit_permit = permit_tiers.acquire_storage_commit().await?;
            let _commit_guard = commit_gate.read().await;
            if Self::is_pipeline_cancelled(
                &cancel_flag,
                &cancel_rx,
                cancel_baseline_seq,
                &purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            let blocked_now = blocked_prefixes_lock
                .read()
                .map(|g| g.clone())
                .unwrap_or_default();
            batch_chunks.retain(|c| !Self::is_path_str_blocked(&c.file_path, &blocked_now));
            batch_parents.retain(|(p, _)| !Self::is_path_str_blocked(&p.source_path, &blocked_now));
            batch_catalog_entries.retain(|e| {
                !Self::is_path_str_blocked(&e.file_path.to_string_lossy(), &blocked_now)
            });
            if !batch_chunks.is_empty()
                || !batch_parents.is_empty()
                || !batch_catalog_entries.is_empty()
            {
                if !batch_chunks.is_empty() {
                    Self::replace_existing_file_chunks(&storage, &batch_chunks).await;
                    let _ = storage.insert_chunks(&batch_chunks).await?;
                    batch_chunks.clear();
                    committed_any_non_blocked = true;
                }
                if !batch_parents.is_empty() {
                    let parents_to_save = std::mem::take(&mut batch_parents);
                    let storage_p = Arc::clone(&storage);
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::throttling::set_background_thread_priority();
                        for (pdoc, ptier) in parents_to_save {
                            let _ = storage_p.upsert_parent_document(&pdoc, ptier);
                        }
                        crate::throttling::end_background_thread_priority();
                    })
                    .await;
                }
                for entry in batch_catalog_entries.drain(..) {
                    dedup.register_entry(entry);
                }
                let dedup_save = Arc::clone(&dedup);
                let cat_path_save = catalog_path.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    crate::throttling::set_background_thread_priority();
                    let res = dedup_save.save_catalog_to_file(&cat_path_save);
                    crate::throttling::end_background_thread_priority();
                    res
                })
                .await;
                let _ = storage.bump_index_epoch("reindex_final_flush");
            }
        } else {
            batch_chunks.clear();
            batch_parents.clear();
            batch_catalog_entries.clear();
        }

        // Compaction phase if full rebuild
        if options.full_rebuild && !options.dry_run {
            if Self::is_pipeline_cancelled(
                &cancel_flag,
                &cancel_rx,
                cancel_baseline_seq,
                &purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            let mut lock = progress.write().await;
            if let Some(ref mut p) = *lock {
                p.phase = ReindexPhase::CompactingIndexes;
            }
            drop(lock);
            let _ = storage.compact().await;
        }

        // Cache coherence hook: bump index_epoch if any non-blocked mutations occurred
        let has_mutated = committed_any_non_blocked && {
            let lock = progress.read().await;
            lock.as_ref()
                .map(|p| p.files_indexed > 0 || p.chunks_newly_embedded > 0 || options.full_rebuild)
                .unwrap_or(false)
        };

        if !options.dry_run {
            let _commit_guard = commit_gate.read().await;
            if Self::is_pipeline_cancelled(
                &cancel_flag,
                &cancel_rx,
                cancel_baseline_seq,
                &purge_epoch,
                task_purge_epoch,
            ) {
                return Err(IngestError::Cancelled);
            }
            if has_mutated || (options.full_rebuild && committed_any_non_blocked) {
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
                let dedup_save = Arc::clone(&dedup);
                let cat_path_save = catalog_path.clone();
                let save_res = tokio::task::spawn_blocking(move || {
                    crate::throttling::set_background_thread_priority();
                    let res = dedup_save.save_catalog_to_file(&cat_path_save);
                    crate::throttling::end_background_thread_priority();
                    res
                })
                .await
                .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
                if let Err(e) = save_res {
                    warn!(
                        "Failed to auto-save dedup catalog after reindex pass: {}",
                        e
                    );
                } else {
                    info!(
                        path = %catalog_path.display(),
                        tracked_files = dedup.catalog().read().map(|c| c.len()).unwrap_or(0),
                        "Auto-saved Level-1 dedup catalog to disk after reindex pass"
                    );
                }
            } else {
                let dedup_save = Arc::clone(&dedup);
                let cat_path_save = catalog_path.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    crate::throttling::set_background_thread_priority();
                    let res = dedup_save.save_catalog_to_file(&cat_path_save);
                    crate::throttling::end_background_thread_priority();
                    res
                })
                .await;
            }
        }

        Ok(())
    }

    /// Expands drive roots (e.g., `D:\`, `C:\`) into incremental top-level slices so user documents
    /// are indexed and searchable within seconds rather than waiting for a multi-terabyte full-drive walk.
    pub fn expand_drive_roots(raw_targets: &[std::path::PathBuf]) -> Vec<std::path::PathBuf> {
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
            "documents and settings",
            "all users",
            "default user",
            "default",
            "$winreagent",
        ];

        let mut expanded = Vec::new();
        for target in raw_targets {
            let is_drive_root = target.parent().is_none()
                || target.to_string_lossy().len() <= 3
                || target
                    .file_name()
                    .map(|n| {
                        let s = n.to_string_lossy();
                        s.starts_with(".tmp")
                            || s.starts_with("tmp")
                            || s.contains("mock_drive")
                            || s.contains("test")
                    })
                    .unwrap_or(false);
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
                if entry.file_type().map_or(false, |ft| ft.is_symlink()) {
                    continue;
                }
                let path = entry.path();
                let name_lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if SKIP_DIRS.contains(&name_lower.as_str()) {
                    continue;
                }
                if path.is_dir() && std::fs::read_dir(&path).is_err() {
                    continue;
                }

                // Expand large workspace containers (`femi`, `harfile`, `users`) one level further
                if path.is_dir() && matches!(name_lower.as_str(), "femi" | "harfile" | "users") {
                    if let Ok(sub_entries) = std::fs::read_dir(&path) {
                        for sub in sub_entries.flatten() {
                            if sub.file_type().map_or(false, |ft| ft.is_symlink()) {
                                continue;
                            }
                            let sub_path = sub.path();
                            let sub_name = sub.file_name().to_string_lossy().to_ascii_lowercase();
                            if SKIP_DIRS.contains(&sub_name.as_str()) {
                                continue;
                            }
                            if sub_path.is_dir() && std::fs::read_dir(&sub_path).is_err() {
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
    Unchanged {
        size_bytes: u64,
    },
    AlreadyIndexedInFts {
        catalog_entry: FileCatalogEntry,
        size_bytes: u64,
    },
    Processed {
        chunks: Vec<DocumentChunk>,
        parent_doc: Option<(quorum_types::IngestedParentDocument, u8)>,
        catalog_entry: FileCatalogEntry,
        moved_from_path: Option<std::path::PathBuf>,
        size_bytes: u64,
        chunks_reused: usize,
        chunks_new: usize,
    },
    Failed {
        path: std::path::PathBuf,
        error: String,
    },
    ContentSafetyBlocked {
        path: std::path::PathBuf,
        reason: String,
    },
}

#[allow(clippy::too_many_arguments)]
fn process_candidate_sync(
    candidate: DiscoveredCandidate,
    access_tier: u8,
    placeholder_policy: quorum_types::CloudPlaceholderPolicy,
    dlp_gate: Option<Arc<dyn quorum_types::DlpContentGate>>,
    force_reembed: bool,
    eval_level1_dedup: bool,
    storage: Arc<StorageEngine>,
    embedder: Arc<dyn EmbeddingGenerator>,
    dedup: Arc<TwoLevelDedupEngine>,
    chunker: TextChunker,
    mut precomputed_file_b3: Option<String>,
) -> CandidateOutcome {
    let path = &candidate.path;
    let path_str = path.to_string_lossy().to_string();
    let mut moved_from_path: Option<std::path::PathBuf> = None;

    if eval_level1_dedup && precomputed_file_b3.is_none() {
        if let Ok(action) = dedup.evaluate_file_with_policy(
            path,
            candidate.mtime_secs,
            candidate.size_bytes,
            placeholder_policy,
        ) {
            match action {
                DedupAction::Unchanged { .. } => {
                    return CandidateOutcome::Unchanged {
                        size_bytes: candidate.size_bytes,
                    };
                }
                DedupAction::MovedOrRenamed {
                    old_path,
                    file_blake3,
                    ..
                } => {
                    moved_from_path = Some(old_path);
                    precomputed_file_b3 = Some(file_blake3);
                }
                DedupAction::ModifiedOrNew { file_blake3, .. } => {
                    precomputed_file_b3 = Some(file_blake3);
                }
            }
        }
    }
    match candidate.kind {
        CandidateKind::Text { .. } => {
            let raw_content = match DocumentExtractor::extract_text_with_policy(
                path,
                &candidate.file_identity,
                placeholder_policy,
            ) {
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
                None => Level1DedupCatalog::hash_file_stream_with_policy(path, placeholder_policy)
                    .unwrap_or_else(|_| blake3::hash(raw_content.as_bytes()).to_hex().to_string()),
            };
            if !force_reembed
                && storage.has_chunk_id_for_file_in_fts(&format!("{}:0", file_b3), &path_str)
            {
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

            let content = match crate::secret_scrubber::sanitize_and_gate_text(
                &path_str,
                &raw_content,
                access_tier,
                dlp_gate.as_deref(),
            ) {
                Ok(sanitized) => sanitized,
                Err(reason) => {
                    return CandidateOutcome::Failed {
                        path: path.clone(),
                        error: format!("Blocked by DLP policy: {reason}"),
                    };
                }
            };

            let raw_chunks = chunker.chunk_text_structure_aware(&content);
            let mut file_chunk_hashes = Vec::with_capacity(raw_chunks.len());
            let mut resolved_meta = crate::chunker::resolve_document_metadata_with_policy(
                path,
                &content,
                placeholder_policy,
            );
            if let Err(reason) = crate::secret_scrubber::sanitize_and_gate_resolved_metadata(
                &path_str,
                &mut resolved_meta,
                access_tier,
                dlp_gate.as_deref(),
            ) {
                return CandidateOutcome::Failed {
                    path: path.clone(),
                    error: format!("Blocked by DLP policy: {reason}"),
                };
            }
            let parent_doc = if !content.is_empty() {
                let mut pdoc = DocumentExtractor::build_ingested_parent_document_with_policy(
                    path,
                    &file_b3,
                    &file_b3,
                    &content,
                    candidate.mtime_secs,
                    candidate.size_bytes,
                    None,
                    placeholder_policy,
                );
                if let Err(reason) = crate::secret_scrubber::sanitize_and_gate_parent_document(
                    &mut pdoc,
                    access_tier,
                    dlp_gate.as_deref(),
                ) {
                    return CandidateOutcome::Failed {
                        path: path.clone(),
                        error: format!("Blocked by DLP policy: {reason}"),
                    };
                }
                Some((pdoc, access_tier))
            } else {
                None
            };
            let header = crate::chunker::format_contextual_header_from_meta(&resolved_meta);

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
                    "doc_title": resolved_meta.title,
                    "doc_author": resolved_meta.author,
                    "doc_revision": resolved_meta.revision,
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
                moved_from_path,
                size_bytes: candidate.size_bytes,
                chunks_reused,
                chunks_new,
            }
        }
        CandidateKind::Image { .. } => {
            let bytes = match crate::cloud_drives::read_bytes_with_placeholder_policy(
                path,
                placeholder_policy,
            ) {
                Ok(b) => b,
                Err(e) => {
                    return CandidateOutcome::Failed {
                        path: path.clone(),
                        error: format!("Failed to read image file: {}", e),
                    };
                }
            };

            // Enforce zero-tolerance pornography/explicit image filter BEFORE the AlreadyIndexedInFts
            // short-circuit so previously indexed explicit images are actively purged from storage.
            if let crate::content_safety::ContentSafetyDecision::Blocked { reason, .. } =
                crate::content_safety::evaluate_image_safety(path, &bytes)
            {
                return CandidateOutcome::ContentSafetyBlocked {
                    path: path.clone(),
                    reason,
                };
            }

            let img_b3 = match precomputed_file_b3 {
                Some(b3) => b3,
                None => blake3::hash(&bytes).to_hex().to_string(),
            };
            if !force_reembed
                && (storage.has_chunk_id_for_file_in_fts(&format!("{}:img:0", img_b3), &path_str)
                    || storage
                        .has_chunk_id_for_file_in_fts(&format!("{}:image:0", img_b3), &path_str))
            {
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

            match ImageIndexer::index_image_with_policy(
                path,
                &bytes,
                &candidate.file_identity,
                access_tier,
                embedder.as_ref(),
                placeholder_policy,
            ) {
                Ok(mut doc_chunk) => {
                    let gated_text = match crate::secret_scrubber::sanitize_and_gate_text(
                        &path_str,
                        &doc_chunk.text_content,
                        access_tier,
                        dlp_gate.as_deref(),
                    ) {
                        Ok(s) => s,
                        Err(reason) => {
                            return CandidateOutcome::Failed {
                                path: path.clone(),
                                error: format!("Blocked by DLP policy: {reason}"),
                            };
                        }
                    };
                    doc_chunk.metadata_json =
                        match crate::secret_scrubber::sanitize_and_gate_metadata_json(
                            &path_str,
                            &doc_chunk.metadata_json,
                            access_tier,
                            dlp_gate.as_deref(),
                        ) {
                            Ok(m) => m,
                            Err(reason) => {
                                return CandidateOutcome::Failed {
                                    path: path.clone(),
                                    error: format!("Blocked by DLP policy: {reason}"),
                                };
                            }
                        };
                    if gated_text != doc_chunk.text_content {
                        doc_chunk.text_content = gated_text;
                        doc_chunk.blake3_hash =
                            DocumentChunk::compute_blake3_hash(&doc_chunk.text_content);
                        doc_chunk.vector = embedder
                            .embed_text(&doc_chunk.text_content)
                            .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                    }
                    let file_b3 = doc_chunk.document_id.clone();
                    let parent_doc = Some((
                        DocumentExtractor::build_ingested_parent_document_with_policy(
                            path,
                            &file_b3,
                            &file_b3,
                            &doc_chunk.text_content,
                            candidate.mtime_secs,
                            candidate.size_bytes,
                            Some(quorum_types::DocumentFormat::ImageFile),
                            placeholder_policy,
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
                        moved_from_path,
                        size_bytes: candidate.size_bytes,
                        chunks_reused: 0,
                        chunks_new: 1,
                    }
                }
                Err(quorum_types::TypeError::ContentSafetyBlocked(reason)) => {
                    CandidateOutcome::ContentSafetyBlocked {
                        path: path.clone(),
                        reason,
                    }
                }
                Err(e) => CandidateOutcome::Failed {
                    path: path.clone(),
                    error: format!("Failed to index image: {}", e),
                },
            }
        }
        CandidateKind::Audio { .. } => {
            let bytes = match crate::cloud_drives::read_bytes_with_placeholder_policy(
                path,
                placeholder_policy,
            ) {
                Ok(b) => b,
                Err(e) => {
                    return CandidateOutcome::Failed {
                        path: path.clone(),
                        error: format!("Failed to read audio file: {}", e),
                    };
                }
            };

            match AudioIndexer::index_audio_with_policy(
                path,
                &bytes,
                &candidate.file_identity,
                access_tier,
                embedder.as_ref(),
                placeholder_policy,
            ) {
                Ok(mut doc_chunk) => {
                    let gated_text = match crate::secret_scrubber::sanitize_and_gate_text(
                        &path_str,
                        &doc_chunk.text_content,
                        access_tier,
                        dlp_gate.as_deref(),
                    ) {
                        Ok(s) => s,
                        Err(reason) => {
                            return CandidateOutcome::Failed {
                                path: path.clone(),
                                error: format!("Blocked by DLP policy: {reason}"),
                            };
                        }
                    };
                    doc_chunk.metadata_json =
                        match crate::secret_scrubber::sanitize_and_gate_metadata_json(
                            &path_str,
                            &doc_chunk.metadata_json,
                            access_tier,
                            dlp_gate.as_deref(),
                        ) {
                            Ok(m) => m,
                            Err(reason) => {
                                return CandidateOutcome::Failed {
                                    path: path.clone(),
                                    error: format!("Blocked by DLP policy: {reason}"),
                                };
                            }
                        };
                    if gated_text != doc_chunk.text_content {
                        doc_chunk.text_content = gated_text;
                        doc_chunk.blake3_hash =
                            DocumentChunk::compute_blake3_hash(&doc_chunk.text_content);
                        doc_chunk.vector = embedder
                            .embed_text(&doc_chunk.text_content)
                            .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                    }
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
                        moved_from_path,
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
