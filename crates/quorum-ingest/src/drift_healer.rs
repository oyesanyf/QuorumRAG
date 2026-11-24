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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

use crate::audio_indexer::AudioIndexer;
use crate::chunker::TextChunker;
use crate::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use crate::config::{ChunkerConfig, DriftFixOptions, DriftType, IngestConfig};
use crate::crawler::FilesystemCrawler;
use crate::dedup::{FileCatalogEntry, Level1DedupCatalog, TwoLevelDedupEngine};
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
    config: Arc<tokio::sync::RwLock<IngestConfig>>,
    storage: Arc<StorageEngine>,
    classifier: Arc<FileTypeClassifier>,
    embedder: Arc<dyn EmbeddingGenerator>,
    dedup: Arc<TwoLevelDedupEngine>,
    dlp_gate: Arc<tokio::sync::RwLock<Option<Arc<dyn quorum_types::DlpContentGate>>>>,
    purge_epoch: Arc<AtomicU64>,
    blocked_prefixes: Arc<std::sync::RwLock<Vec<String>>>,
    commit_gate: Arc<tokio::sync::RwLock<()>>,
    cancel_tx: Arc<tokio::sync::watch::Sender<u64>>,
    in_flight_heals: Arc<AtomicUsize>,
    heal_done_notify: Arc<tokio::sync::Notify>,
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
            config: Arc::new(tokio::sync::RwLock::new(config)),
            storage,
            classifier,
            embedder,
            dedup,
            dlp_gate: Arc::new(tokio::sync::RwLock::new(None)),
            purge_epoch: Arc::new(AtomicU64::new(0)),
            blocked_prefixes: Arc::new(std::sync::RwLock::new(Vec::new())),
            commit_gate: Arc::new(tokio::sync::RwLock::new(())),
            cancel_tx: Arc::new(tokio::sync::watch::channel(0u64).0),
            in_flight_heals: Arc::new(AtomicUsize::new(0)),
            heal_done_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn with_dlp_gate(self, gate: Arc<dyn quorum_types::DlpContentGate>) -> Self {
        Self {
            dlp_gate: Arc::new(tokio::sync::RwLock::new(Some(gate))),
            ..self
        }
    }

    /// Shares `purge_epoch`, `blocked_prefixes`, and `commit_gate` with `worker` so
    /// prefix purges serialize across both `ReindexWorker` and `DriftHealer`.
    pub fn with_reindex_barrier(mut self, worker: &crate::reindex::ReindexWorker) -> Self {
        let (purge_epoch, blocked_prefixes, commit_gate) = worker.purge_barrier_handles();
        self.purge_epoch = purge_epoch;
        self.blocked_prefixes = blocked_prefixes;
        self.commit_gate = commit_gate;
        self
    }

    /// Attaches explicit shared purge-barrier synchronization handles.
    pub fn with_purge_barrier(
        mut self,
        purge_epoch: Arc<AtomicU64>,
        blocked_prefixes: Arc<std::sync::RwLock<Vec<String>>>,
        commit_gate: Arc<tokio::sync::RwLock<()>>,
    ) -> Self {
        self.purge_epoch = purge_epoch;
        self.blocked_prefixes = blocked_prefixes;
        self.commit_gate = commit_gate;
        self
    }

    /// Returns true when this `DriftHealer` shares the same `commit_gate` instance as `worker`.
    pub fn shares_commit_gate_with(&self, worker: &crate::reindex::ReindexWorker) -> bool {
        let (_, _, worker_gate) = worker.purge_barrier_handles();
        Arc::ptr_eq(&self.commit_gate, &worker_gate)
    }

    /// Updates the normalized list of blocked (e.g., disabled cloud-drive) path prefixes.
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
    pub fn is_path_blocked(&self, path: &Path) -> bool {
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

    /// Acquires the exclusive storage/dedup purge barrier serialized against all
    /// `DriftHealer` commits.
    pub async fn acquire_purge_barrier(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> {
        self.commit_gate.write().await
    }

    #[inline]
    fn is_cancelled(
        &self,
        task_purge_epoch: u64,
        cancel_rx: &tokio::sync::watch::Receiver<u64>,
        baseline_seq: u64,
    ) -> bool {
        *cancel_rx.borrow() != baseline_seq
            || self.purge_epoch.load(Ordering::SeqCst) != task_purge_epoch
    }

    async fn wait_cancelled(
        &self,
        task_purge_epoch: u64,
        cancel_rx: &mut tokio::sync::watch::Receiver<u64>,
        baseline_seq: u64,
    ) {
        loop {
            if *cancel_rx.borrow_and_update() != baseline_seq
                || self.purge_epoch.load(Ordering::SeqCst) != task_purge_epoch
            {
                return;
            }
            if cancel_rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Cancels any active drift-healing pass and waits up to `timeout` for all
    /// in-flight passes to exit so prefix purges cannot race with late writes.
    pub async fn cancel_and_drain(&self, timeout: std::time::Duration) -> bool {
        self.purge_epoch.fetch_add(1, Ordering::SeqCst);
        self.cancel_tx.send_modify(|seq| *seq = seq.wrapping_add(1));
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.heal_done_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.in_flight_heals.load(Ordering::SeqCst) == 0 {
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

    pub(crate) fn set_dlp_gate_try(&self, gate: Arc<dyn quorum_types::DlpContentGate>) {
        if let Ok(mut guard) = self.dlp_gate.try_write() {
            *guard = Some(gate);
        }
    }

    pub async fn set_dlp_gate(&self, gate: Option<Arc<dyn quorum_types::DlpContentGate>>) {
        *self.dlp_gate.write().await = gate;
    }

    pub async fn update_placeholder_policy(&self, policy: quorum_types::CloudPlaceholderPolicy) {
        self.config.write().await.placeholder_policy = policy;
    }

    pub async fn update_max_file_size_bytes(&self, max_file_size_bytes: u64) {
        self.config.write().await.max_file_size_bytes = max_file_size_bytes.max(1);
    }

    pub async fn update_watch_paths(&self, watch_paths: Vec<PathBuf>) {
        self.config.write().await.watch_paths = watch_paths;
    }

    pub async fn remove_watch_paths(&self, paths: &[PathBuf]) {
        let prefixes: Vec<PathBuf> = paths
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
        let mut cfg = self.config.write().await;
        cfg.watch_paths.retain(|w| {
            !prefixes
                .iter()
                .any(|r| crate::config::path_matches_prefix(w, r))
        });
    }

    pub async fn update_access_tier_rules(
        &self,
        rules: Vec<(PathBuf, u8)>,
    ) -> Result<(), IngestError> {
        let mut normalized = Vec::with_capacity(rules.len());
        for (prefix, tier) in rules {
            quorum_types::AccessTier::from_u8(tier)?;
            let norm = quorum_types::normalize_prefix_for_match(&prefix.to_string_lossy())?;
            normalized.push((PathBuf::from(norm), tier));
        }
        self.config.write().await.access_tier_rules = normalized;
        Ok(())
    }

    pub async fn config_snapshot(&self) -> IngestConfig {
        self.config.read().await.clone()
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
        struct HealDoneGuard {
            in_flight: Arc<AtomicUsize>,
            notify: Arc<tokio::sync::Notify>,
        }
        impl Drop for HealDoneGuard {
            fn drop(&mut self) {
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                self.notify.notify_waiters();
            }
        }
        self.in_flight_heals.fetch_add(1, Ordering::SeqCst);
        let _done_guard = HealDoneGuard {
            in_flight: Arc::clone(&self.in_flight_heals),
            notify: Arc::clone(&self.heal_done_notify),
        };

        let task_purge_epoch = self.purge_epoch.load(Ordering::SeqCst);
        let mut cancel_rx = self.cancel_tx.subscribe();
        let cancel_baseline_seq = *cancel_rx.borrow();
        if self.is_cancelled(task_purge_epoch, &cancel_rx, cancel_baseline_seq) {
            return Err(IngestError::Cancelled);
        }

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
            self.heal_merkle_state_drift(
                &mut report,
                options.dry_run,
                task_purge_epoch,
                &mut cancel_rx,
                cancel_baseline_seq,
            )
            .await?;
        }

        // 2. Drift Type B: Hybrid Index Desync (LanceDB <-> Tantivy)
        if target_all || targets.contains(&DriftType::HybridIndexDesync) {
            self.heal_hybrid_index_desync(
                &mut report,
                options.dry_run,
                task_purge_epoch,
                &cancel_rx,
                cancel_baseline_seq,
            )
            .await?;
        }

        // 3. Drift Type C: Vector Contract Drift
        if target_all || targets.contains(&DriftType::VectorContract) {
            self.heal_vector_contract_drift(
                &mut report,
                options.dry_run,
                task_purge_epoch,
                &cancel_rx,
                cancel_baseline_seq,
            )
            .await?;
        }

        // 4. Drift Type D: ACL Policy Drift
        if target_all || targets.contains(&DriftType::AclPolicy) {
            self.heal_acl_policy_drift(
                &options.access_tier_rules,
                &mut report,
                options.dry_run,
                task_purge_epoch,
                &cancel_rx,
                cancel_baseline_seq,
            )
            .await?;
        }

        // 5. Drift Type E: Storage Compaction & Tombstone Drift
        if target_all || targets.contains(&DriftType::StorageCompaction) {
            self.heal_storage_compaction(
                &mut report,
                options.dry_run,
                task_purge_epoch,
                &cancel_rx,
                cancel_baseline_seq,
            )
            .await?;
        }

        if self.is_cancelled(task_purge_epoch, &cancel_rx, cancel_baseline_seq) {
            return Err(IngestError::Cancelled);
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
            let _commit_guard = self.commit_gate.read().await;
            if self.is_cancelled(task_purge_epoch, &cancel_rx, cancel_baseline_seq) {
                return Err(IngestError::Cancelled);
            }
            let _ = self.storage.bump_index_epoch("drift_healer_remediated");
        }

        Ok(report)
    }

    /// Drift A: Filesystem <-> Database Merkle State Reconciliation.
    async fn heal_merkle_state_drift(
        &self,
        report: &mut DriftReport,
        dry_run: bool,
        task_purge_epoch: u64,
        cancel_rx: &mut tokio::sync::watch::Receiver<u64>,
        cancel_baseline_seq: u64,
    ) -> Result<(), IngestError> {
        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
            return Err(IngestError::Cancelled);
        }

        // Step 1: Scan all recorded file paths from catalog
        let tracked_files = self.dedup.get_all_tracked_files();

        for file_path in tracked_files {
            if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                return Err(IngestError::Cancelled);
            }
            let path = Path::new(&file_path);
            if self.is_path_blocked(path) {
                continue;
            }
            if !path.exists() {
                // File deleted while watcher was offline -> purge orphan
                if !dry_run {
                    let _commit_guard = self.commit_gate.read().await;
                    if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                        return Err(IngestError::Cancelled);
                    }
                    if self.is_path_blocked(path) {
                        continue;
                    }
                    let path_str = path.to_string_lossy().to_string();
                    let _ = self.storage.delete_by_file_path(&path_str).await;
                    self.dedup.remove_file(path);
                }
                report.orphaned_db_files_purged += 1;
            } else if path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(quorum_types::content_safety::is_visual_media_extension)
                && matches!(
                    tokio::task::spawn_blocking({
                        let p_check = path.to_path_buf();
                        move || crate::content_safety::evaluate_image_file_safety(&p_check)
                    })
                    .await
                    .unwrap_or_else(|_| crate::content_safety::ContentSafetyDecision::Blocked {
                        category: "content_safety_worker_error",
                        reason: "Content safety check worker failed (fail-closed)".to_string(),
                        confidence: 1.0,
                    }),
                    crate::content_safety::ContentSafetyDecision::Blocked { .. }
                )
            {
                // Explicit/pornographic visual media is unconditionally purged from index & dedup catalog.
                if !dry_run {
                    let _commit_guard = self.commit_gate.read().await;
                    if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                        return Err(IngestError::Cancelled);
                    }
                    let path_str = path.to_string_lossy().to_string();
                    let _ = self.storage.delete_by_file_path(&path_str).await;
                    self.dedup.remove_file(path);
                }
                report.orphaned_db_files_purged += 1;
            } else if let Ok(meta) = std::fs::metadata(path) {
                if let Some(entry) = self.dedup.get_file_entry(path) {
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);

                    if meta.len() != entry.size_bytes || mtime != entry.mtime_secs {
                        if !dry_run {
                            if self
                                .reingest_single_file_guarded(
                                    path,
                                    task_purge_epoch,
                                    cancel_rx,
                                    cancel_baseline_seq,
                                )
                                .await?
                            {
                                report.outdated_files_reindexed += 1;
                            }
                        } else {
                            report.outdated_files_reindexed += 1;
                        }
                    }
                }
            }
        }

        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
            return Err(IngestError::Cancelled);
        }

        // Step 2: Walk filesystem paths to discover untracked files
        let mut cfg_snapshot = self.config.read().await.clone();
        for bp in self.blocked_prefixes_snapshot() {
            let bp_pb = PathBuf::from(bp);
            if !cfg_snapshot.excluded_paths.iter().any(|ex| ex == &bp_pb) {
                cfg_snapshot.excluded_paths.push(bp_pb);
            }
        }

        for root in &cfg_snapshot.watch_paths {
            if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                return Err(IngestError::Cancelled);
            }
            if self.is_path_blocked(root) || !root.exists() {
                continue;
            }
            let crawler = FilesystemCrawler::new(cfg_snapshot.clone());
            let root_c = root.clone();
            let crawl_fut = tokio::task::spawn_blocking(move || crawler.crawl_path_sync(&root_c));
            let candidates = tokio::select! {
                biased;
                _ = self.wait_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) => {
                    return Err(IngestError::Cancelled);
                }
                join_res = crawl_fut => {
                    join_res.map_err(|e| IngestError::Io(std::io::Error::other(format!(
                        "DriftHealer crawl task failed: {e}"
                    ))))??
                }
            };

            for candidate in candidates {
                if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                    return Err(IngestError::Cancelled);
                }
                if self.is_path_blocked(&candidate.path) {
                    continue;
                }
                let is_tracked = self.dedup.get_file_entry(&candidate.path).is_some();
                if !is_tracked {
                    if !dry_run {
                        if self
                            .reingest_single_file_guarded(
                                &candidate.path,
                                task_purge_epoch,
                                cancel_rx,
                                cancel_baseline_seq,
                            )
                            .await?
                        {
                            report.missing_fs_files_indexed += 1;
                        }
                    } else {
                        report.missing_fs_files_indexed += 1;
                    }
                }
            }
        }

        if !dry_run
            && (report.orphaned_db_files_purged > 0
                || report.outdated_files_reindexed > 0
                || report.missing_fs_files_indexed > 0)
        {
            if let Some(ref cat_path) = cfg_snapshot.dedup_catalog_path {
                let _commit_guard = self.commit_gate.read().await;
                if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                    return Err(IngestError::Cancelled);
                }
                let _ = self.dedup.save_catalog_to_file(cat_path);
            }
        }

        Ok(())
    }

    /// Drift B: LanceDB Vector <-> Tantivy BM25 Parity Reconciliation.
    async fn heal_hybrid_index_desync(
        &self,
        report: &mut DriftReport,
        dry_run: bool,
        task_purge_epoch: u64,
        cancel_rx: &tokio::sync::watch::Receiver<u64>,
        cancel_baseline_seq: u64,
    ) -> Result<(), IngestError> {
        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
            return Err(IngestError::Cancelled);
        }

        let lance_catalog = self.storage.get_lance_chunk_catalog().await?;
        let tantivy_catalog = self.storage.get_tantivy_chunk_catalog()?;

        let lance_ids: HashSet<String> = lance_catalog.keys().cloned().collect();
        let tantivy_ids: HashSet<String> = tantivy_catalog.keys().cloned().collect();

        let lance_only: Vec<String> = lance_ids.difference(&tantivy_ids).cloned().collect();
        let tantivy_only: Vec<String> = tantivy_ids.difference(&lance_ids).cloned().collect();

        let mut lance_chunks = if !lance_only.is_empty() {
            let mut chunks = self.storage.get_chunks_by_ids(&lance_only).await?;
            chunks.retain(|c| !self.is_path_blocked(Path::new(&c.file_path)));
            chunks
        } else {
            Vec::new()
        };

        let mut tantivy_chunks = if !tantivy_only.is_empty() {
            let mut chunks = self.storage.get_chunks_from_tantivy(&tantivy_only)?;
            chunks.retain(|c| !self.is_path_blocked(Path::new(&c.file_path)));
            chunks
        } else {
            Vec::new()
        };

        report.lance_chunks_missing_in_tantivy = lance_chunks.len();
        report.tantivy_chunks_missing_in_lance = tantivy_chunks.len();

        if !dry_run {
            // Recover Lance -> Tantivy
            if !lance_chunks.is_empty() {
                let _commit_guard = self.commit_gate.read().await;
                if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                    return Err(IngestError::Cancelled);
                }
                lance_chunks.retain(|c| !self.is_path_blocked(Path::new(&c.file_path)));
                if !lance_chunks.is_empty() {
                    let _ = self.storage.insert_into_tantivy_only(&lance_chunks)?;
                }
            }

            // Recover Tantivy -> Lance
            if !tantivy_chunks.is_empty() {
                let canonical_dim = self.embedder.dimension();
                let mut healed_chunks = Vec::new();
                for chunk in &mut tantivy_chunks {
                    if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                        return Err(IngestError::Cancelled);
                    }
                    if chunk.vector.len() != canonical_dim {
                        if let Ok(vec) = self.embedder.embed_text(&chunk.text_content) {
                            chunk.vector = vec;
                        } else {
                            chunk.vector = vec![0.0; canonical_dim];
                        }
                        healed_chunks.push(chunk.clone());
                    }
                }
                let _commit_guard = self.commit_gate.read().await;
                if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                    return Err(IngestError::Cancelled);
                }
                tantivy_chunks.retain(|c| !self.is_path_blocked(Path::new(&c.file_path)));
                healed_chunks.retain(|c| !self.is_path_blocked(Path::new(&c.file_path)));
                if !tantivy_chunks.is_empty() {
                    let _ = self.storage.insert_into_lance_only(&tantivy_chunks).await?;
                }
                for healed in &healed_chunks {
                    let _ = self.storage.update_chunk_record(healed).await;
                }
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
        task_purge_epoch: u64,
        cancel_rx: &tokio::sync::watch::Receiver<u64>,
        cancel_baseline_seq: u64,
    ) -> Result<(), IngestError> {
        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
            return Err(IngestError::Cancelled);
        }

        let canonical_hash = self.embedder.contract().derive_contract_hash_hex();
        let canonical_dim = self.embedder.dimension();

        let all_chunks = self.storage.scan_all_chunks().await?;
        let mut drifted_chunks = Vec::new();

        for chunk in all_chunks {
            if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                return Err(IngestError::Cancelled);
            }
            if self.is_path_blocked(Path::new(&chunk.file_path)) {
                continue;
            }
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
                if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                    return Err(IngestError::Cancelled);
                }
                if self.is_path_blocked(Path::new(&chunk.file_path)) {
                    continue;
                }
                let new_vec = self
                    .embedder
                    .embed_text(&chunk.text_content)
                    .unwrap_or_else(|_| vec![0.0; canonical_dim]);
                chunk.vector = new_vec;

                let mut meta_val: serde_json::Value =
                    serde_json::from_str(&chunk.metadata_json).unwrap_or(serde_json::json!({}));
                meta_val["contract_hash"] = serde_json::json!(canonical_hash);
                chunk.metadata_json = meta_val.to_string();

                let _commit_guard = self.commit_gate.read().await;
                if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                    return Err(IngestError::Cancelled);
                }
                if self.is_path_blocked(Path::new(&chunk.file_path)) {
                    continue;
                }
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
        task_purge_epoch: u64,
        cancel_rx: &tokio::sync::watch::Receiver<u64>,
        cancel_baseline_seq: u64,
    ) -> Result<(), IngestError> {
        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
            return Err(IngestError::Cancelled);
        }

        let cfg_rules = self.config.read().await.access_tier_rules.clone();
        let active_rules = if !rules.is_empty() { rules } else { &cfg_rules };

        if active_rules.is_empty() {
            return Ok(());
        }

        let all_chunks = self.storage.scan_all_chunks().await?;
        let mut drifted_chunks = Vec::new();

        for chunk in all_chunks {
            if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                return Err(IngestError::Cancelled);
            }
            let chunk_path = Path::new(&chunk.file_path);
            if self.is_path_blocked(chunk_path) {
                continue;
            }
            let expected_tier = IngestConfig::resolve_tier_from_rules(active_rules, chunk_path);

            if chunk.access_tier != expected_tier {
                drifted_chunks.push((chunk.chunk_id, chunk.file_path, expected_tier));
            }
        }

        report.acl_drifted_chunks_updated = drifted_chunks.len();

        if !dry_run && !drifted_chunks.is_empty() {
            for (chunk_id, file_path, new_tier) in drifted_chunks {
                let _commit_guard = self.commit_gate.read().await;
                if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                    return Err(IngestError::Cancelled);
                }
                if self.is_path_blocked(Path::new(&file_path)) {
                    continue;
                }
                self.storage
                    .update_chunk_access_tier_for_file(&chunk_id, &file_path, new_tier)
                    .await?;
            }
        }

        Ok(())
    }

    /// Drift E: Storage Compaction & Tombstone Drift.
    async fn heal_storage_compaction(
        &self,
        report: &mut DriftReport,
        dry_run: bool,
        task_purge_epoch: u64,
        cancel_rx: &tokio::sync::watch::Receiver<u64>,
        cancel_baseline_seq: u64,
    ) -> Result<(), IngestError> {
        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
            return Err(IngestError::Cancelled);
        }
        if !dry_run {
            let stats = self.storage.compact().await?;
            if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                return Err(IngestError::Cancelled);
            }
            report.fragments_consolidated = stats.fragments_removed;
            report.old_versions_pruned = stats.old_versions_pruned;
            report.tantivy_segments_merged = stats.tantivy_segments_merged;
        }
        Ok(())
    }

    /// Helper to re-index a single file through the pipeline with cancellation,
    /// blocked-prefix filtering, and `commit_gate` barrier protection.
    async fn reingest_single_file_guarded(
        &self,
        path: &Path,
        task_purge_epoch: u64,
        cancel_rx: &tokio::sync::watch::Receiver<u64>,
        cancel_baseline_seq: u64,
    ) -> Result<bool, IngestError> {
        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
            return Err(IngestError::Cancelled);
        }
        if self.is_path_blocked(path) {
            return Ok(false);
        }

        let cfg_snapshot = self.config.read().await.clone();
        let dlp_gate = self.dlp_gate.read().await.clone();
        let router = ClassifierRouter::new(cfg_snapshot.clone());
        let decision = router.evaluate_file_with_config(path, &cfg_snapshot);

        match decision {
            FilterDecision::Accept {
                identity,
                kind,
                size_bytes,
                mtime_secs,
            } => {
                let access_tier = cfg_snapshot.resolve_access_tier(path);
                let placeholder_policy = cfg_snapshot.placeholder_policy;
                let path_str = path.to_string_lossy().to_string();

                let ext_permit = crate::thread_pool::IngestThreadPool::shared()
                    .permit_tiers()
                    .acquire_extraction()
                    .await?;

                if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                    return Err(IngestError::Cancelled);
                }
                if self.is_path_blocked(path) {
                    return Ok(false);
                }

                match kind {
                    CandidateKind::Text { .. } => {
                        let path_buf = path.to_path_buf();
                        let identity = identity.clone();
                        let embedder = Arc::clone(&self.embedder);
                        let dedup_cache = self.dedup.cache().clone();
                        let path_str_c = path_str.clone();
                        let dlp_gate_c = dlp_gate.clone();

                        let (file_b3, chunks, file_chunk_hashes, parent_doc) =
                            crate::thread_pool::IngestThreadPool::shared()
                                .spawn_blocking_pinned(ext_permit, move || -> Result<_, IngestError> {
                                    let raw_content = crate::document_extractor::DocumentExtractor::extract_text_with_policy(
                                        &path_buf,
                                        &identity,
                                        placeholder_policy,
                                    )?;
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
                                    let file_b3 = Level1DedupCatalog::hash_file_stream_with_policy(
                                        &path_buf,
                                        placeholder_policy,
                                    )
                                    .unwrap_or_else(|_| blake3::hash(content.as_bytes()).to_hex().to_string());
                                    let chunker = TextChunker::new(ChunkerConfig::default());
                                    let raw_chunks = chunker.chunk_text_structure_aware(&content);

                                    let mut file_chunk_hashes = Vec::new();
                                    let mut chunks = Vec::new();
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
                                    let parent_doc = if !content.is_empty() {
                                        let mut pdoc = crate::document_extractor::DocumentExtractor::build_ingested_parent_document_with_policy(
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
                                    let header = crate::chunker::format_contextual_header_from_meta(&resolved_meta);

                                    for raw in raw_chunks {
                                        let raw_b3 = DocumentChunk::compute_blake3_hash(raw.text_slice);
                                        let chunk_content = crate::chunker::prepend_contextual_header_with_section(
                                            &header,
                                            &raw.section_path,
                                            raw.text_slice,
                                        );
                                        let _chunk_b3 = DocumentChunk::compute_blake3_hash(&chunk_content);
                                        file_chunk_hashes.push(raw_b3.clone());

                                        let vector = if let Some(cached) = dedup_cache.get(&raw_b3) {
                                            cached
                                        } else {
                                            let v = embedder
                                                .embed_text(raw.text_slice)
                                                .unwrap_or_else(|_| vec![0.0; embedder.dimension()]);
                                            dedup_cache.insert(raw_b3.clone(), v.clone());
                                            v
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
                                        chunks.push(doc_chunk);
                                    }

                                    Ok((file_b3, chunks, file_chunk_hashes, parent_doc))
                                })
                                .await??;

                        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                            return Err(IngestError::Cancelled);
                        }
                        if self.is_path_blocked(path) {
                            return Ok(false);
                        }

                        let _commit_permit = crate::thread_pool::IngestThreadPool::shared()
                            .permit_tiers()
                            .acquire_storage_commit()
                            .await?;
                        let _commit_guard = self.commit_gate.read().await;
                        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                            return Err(IngestError::Cancelled);
                        }
                        if self.is_path_blocked(path) {
                            return Ok(false);
                        }

                        let _ = self.storage.delete_by_file_path(&path_str).await;
                        let _ = self.storage.insert_chunks(&chunks).await?;
                        if let Some(ref pdoc) = parent_doc {
                            let _ = self.storage.upsert_parent_document(pdoc, access_tier);
                        }

                        self.dedup.register_entry(FileCatalogEntry {
                            file_path: path.to_path_buf(),
                            file_blake3: file_b3,
                            mtime_secs,
                            size_bytes,
                            chunk_hashes: file_chunk_hashes,
                        });
                        Ok(true)
                    }
                    CandidateKind::Image { .. } => {
                        let path_buf = path.to_path_buf();
                        let identity = identity.clone();
                        let embedder = Arc::clone(&self.embedder);
                        let path_str_c = path_str.clone();
                        let dlp_gate_c = dlp_gate.clone();

                        let image_result = crate::thread_pool::IngestThreadPool::shared()
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
                                doc_chunk.metadata_json = crate::secret_scrubber::sanitize_and_gate_metadata_json(
                                    &path_str_c,
                                    &doc_chunk.metadata_json,
                                    access_tier,
                                    dlp_gate_c.as_deref(),
                                )
                                .map_err(|reason| IngestError::DlpBlocked {
                                    path: path_buf.clone(),
                                    reason,
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
                                let mut pdoc = crate::document_extractor::DocumentExtractor::build_ingested_parent_document_with_policy(
                                    &path_buf,
                                    &file_b3,
                                    &file_b3,
                                    &doc_chunk.text_content,
                                    mtime_secs,
                                    size_bytes,
                                    Some(quorum_types::DocumentFormat::ImageFile),
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
                                Ok((doc_chunk, file_b3, pdoc))
                            })
                            .await?;

                        let (doc_chunk, file_b3, parent_doc) = match image_result {
                            Ok(triple) => triple,
                            Err(IngestError::TypeError(
                                quorum_types::TypeError::ContentSafetyBlocked(reason),
                            )) => {
                                tracing::warn!(
                                    path = %path.display(),
                                    reason = %reason,
                                    "DriftHealer blocked and purged explicit image"
                                );
                                let _commit_guard = self.commit_gate.read().await;
                                let _ = self.storage.delete_by_file_path(&path_str).await;
                                self.dedup.remove_file(path);
                                return Ok(false);
                            }
                            Err(e) => return Err(e),
                        };

                        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                            return Err(IngestError::Cancelled);
                        }
                        if self.is_path_blocked(path) {
                            return Ok(false);
                        }

                        let _commit_permit = crate::thread_pool::IngestThreadPool::shared()
                            .permit_tiers()
                            .acquire_storage_commit()
                            .await?;
                        let _commit_guard = self.commit_gate.read().await;
                        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                            return Err(IngestError::Cancelled);
                        }
                        if self.is_path_blocked(path) {
                            return Ok(false);
                        }

                        let _ = self.storage.delete_by_file_path(&path_str).await;
                        let _ = self
                            .storage
                            .insert_chunks(std::slice::from_ref(&doc_chunk))
                            .await?;
                        let _ = self
                            .storage
                            .upsert_parent_document(&parent_doc, access_tier);

                        self.dedup.register_entry(FileCatalogEntry {
                            file_path: path.to_path_buf(),
                            file_blake3: file_b3,
                            mtime_secs,
                            size_bytes,
                            chunk_hashes: vec![doc_chunk.blake3_hash],
                        });
                        Ok(true)
                    }
                    CandidateKind::Audio { .. } => {
                        let path_buf = path.to_path_buf();
                        let identity = identity.clone();
                        let embedder = Arc::clone(&self.embedder);
                        let path_str_c = path_str.clone();
                        let dlp_gate_c = dlp_gate.clone();

                        let (doc_chunk, file_b3) = crate::thread_pool::IngestThreadPool::shared()
                            .spawn_blocking_pinned(ext_permit, move || -> Result<_, IngestError> {
                                let bytes =
                                    crate::cloud_drives::read_bytes_with_placeholder_policy(
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

                        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                            return Err(IngestError::Cancelled);
                        }
                        if self.is_path_blocked(path) {
                            return Ok(false);
                        }

                        let _commit_permit = crate::thread_pool::IngestThreadPool::shared()
                            .permit_tiers()
                            .acquire_storage_commit()
                            .await?;
                        let _commit_guard = self.commit_gate.read().await;
                        if self.is_cancelled(task_purge_epoch, cancel_rx, cancel_baseline_seq) {
                            return Err(IngestError::Cancelled);
                        }
                        if self.is_path_blocked(path) {
                            return Ok(false);
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
                            chunk_hashes: vec![doc_chunk.blake3_hash],
                        });
                        Ok(true)
                    }
                }
            }
            _ => {
                debug!(path = %path.display(), "Skipped file during re-ingestion");
                Ok(false)
            }
        }
    }
}
