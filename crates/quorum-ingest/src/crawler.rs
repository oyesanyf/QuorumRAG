//! High-Capacity Parallel Filesystem Crawler powered by `ignore::WalkParallel`.
//!
//! Traverses local filesystems with work-stealing concurrency, respecting `.gitignore`
//! and `.ignore` rules, skipping hidden directories, enforcing size caps (50MB),
//! and streaming discovered candidates with bounded backpressure.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use ignore::{WalkBuilder, WalkParallel, WalkState};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use crate::config::IngestConfig;
use crate::error::IngestError;
use quorum_classifier::FileIdentity;

/// Candidate file ready for ingestion pipeline (deduplication & chunking).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscoveredCandidate {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub mtime_secs: i64,
    pub file_identity: FileIdentity,
    pub kind: CandidateKind,
}

/// Cumulative crawler telemetry metrics.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CrawlerStats {
    pub directories_visited: usize,
    pub files_scanned: usize,
    pub files_accepted_text: usize,
    pub files_accepted_image: usize,
    pub files_accepted_audio: usize,
    pub files_skipped_size: usize,
    pub files_skipped_binary: usize,
    pub files_skipped_hidden: usize,
    pub files_skipped_io: usize,
    pub elapsed_millis: u64,
}

struct AtomicCrawlerStats {
    directories_visited: AtomicUsize,
    files_scanned: AtomicUsize,
    files_accepted_text: AtomicUsize,
    files_accepted_image: AtomicUsize,
    files_accepted_audio: AtomicUsize,
    files_skipped_size: AtomicUsize,
    files_skipped_binary: AtomicUsize,
    files_skipped_hidden: AtomicUsize,
    files_skipped_io: AtomicUsize,
}

impl AtomicCrawlerStats {
    fn new() -> Self {
        Self {
            directories_visited: AtomicUsize::new(0),
            files_scanned: AtomicUsize::new(0),
            files_accepted_text: AtomicUsize::new(0),
            files_accepted_image: AtomicUsize::new(0),
            files_accepted_audio: AtomicUsize::new(0),
            files_skipped_size: AtomicUsize::new(0),
            files_skipped_binary: AtomicUsize::new(0),
            files_skipped_hidden: AtomicUsize::new(0),
            files_skipped_io: AtomicUsize::new(0),
        }
    }

    fn snapshot(&self, elapsed_millis: u64) -> CrawlerStats {
        CrawlerStats {
            directories_visited: self.directories_visited.load(Ordering::Relaxed),
            files_scanned: self.files_scanned.load(Ordering::Relaxed),
            files_accepted_text: self.files_accepted_text.load(Ordering::Relaxed),
            files_accepted_image: self.files_accepted_image.load(Ordering::Relaxed),
            files_accepted_audio: self.files_accepted_audio.load(Ordering::Relaxed),
            files_skipped_size: self.files_skipped_size.load(Ordering::Relaxed),
            files_skipped_binary: self.files_skipped_binary.load(Ordering::Relaxed),
            files_skipped_hidden: self.files_skipped_hidden.load(Ordering::Relaxed),
            files_skipped_io: self.files_skipped_io.load(Ordering::Relaxed),
            elapsed_millis,
        }
    }
}

/// High-throughput parallel filesystem crawler.
#[derive(Debug, Clone)]
pub struct FilesystemCrawler {
    config: IngestConfig,
    router: ClassifierRouter,
    io_semaphore: Arc<tokio::sync::Semaphore>,
}

impl FilesystemCrawler {
    pub fn new(config: IngestConfig) -> Self {
        let router = ClassifierRouter::new(config.clone());
        let io_permits = if config.crawler_threads > 0 {
            (config.crawler_threads * 2).clamp(4, 64)
        } else {
            std::thread::available_parallelism()
                .map(|n| (n.get() * 2).clamp(8, 32))
                .unwrap_or(16)
        };
        let io_semaphore = Arc::new(tokio::sync::Semaphore::new(io_permits));
        Self {
            config,
            router,
            io_semaphore,
        }
    }

    /// Returns the adaptive I/O semaphore gating concurrent filesystem header reads.
    pub fn io_semaphore(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.io_semaphore
    }

    /// Blocks until an I/O permit is available, strictly bounding concurrent NVMe/SSD queue depth.
    pub fn acquire_io_permit_blocking(
        sem: &tokio::sync::Semaphore,
    ) -> Option<tokio::sync::SemaphorePermit<'_>> {
        let mut backoff = 1u64;
        loop {
            match sem.try_acquire() {
                Ok(permit) => return Some(permit),
                Err(tokio::sync::TryAcquireError::Closed) => return None,
                Err(tokio::sync::TryAcquireError::NoPermits) => {
                    if backoff < 16 {
                        std::thread::yield_now();
                        backoff += 1;
                    } else {
                        std::thread::sleep(std::time::Duration::from_micros(50));
                    }
                }
            }
        }
    }

    /// Asynchronously initiates parallel traversal over all configured watch paths.
    pub fn start_crawl(
        self: Arc<Self>,
    ) -> (
        mpsc::Receiver<DiscoveredCandidate>,
        tokio::task::JoinHandle<Result<CrawlerStats, IngestError>>,
    ) {
        let (tx, rx) = mpsc::channel(self.config.channel_buffer_size);
        let crawler = Arc::clone(&self);

        let handle = tokio::task::spawn_blocking(move || {
            crate::throttling::set_background_thread_priority();
            crawler.run_crawl_blocking(tx)
        });

        (rx, handle)
    }

    /// Crawls a specific single directory root. Useful for targeted reindexing (`reindex --path <dir>`).
    pub fn start_crawl_path(
        self: Arc<Self>,
        root: PathBuf,
    ) -> (
        mpsc::Receiver<DiscoveredCandidate>,
        tokio::task::JoinHandle<Result<CrawlerStats, IngestError>>,
    ) {
        let (tx, rx) = mpsc::channel(self.config.channel_buffer_size);
        let crawler = Arc::clone(&self);

        let handle = tokio::task::spawn_blocking(move || {
            crate::throttling::set_background_thread_priority();
            let start = Instant::now();
            let stats = Arc::new(AtomicCrawlerStats::new());
            crawler.crawl_single_root(&root, &tx, &stats)?;
            Ok(stats.snapshot(start.elapsed().as_millis() as u64))
        });

        (rx, handle)
    }

    /// Synchronously crawls a directory and collects all candidates into a Vec.
    pub fn crawl_path_sync(&self, root: &Path) -> Result<Vec<DiscoveredCandidate>, IngestError> {
        let (tx, rx) = std::sync::mpsc::channel();
        let stats = Arc::new(AtomicCrawlerStats::new());
        let walker = self.build_walker(root);
        let router = self.router.clone();

        let io_sem = Arc::clone(&self.io_semaphore);
        walker.run(move || {
            crate::throttling::set_background_thread_priority();
            let tx = tx.clone();
            let router = router.clone();
            let stats = Arc::clone(&stats);
            let io_sem = Arc::clone(&io_sem);

            Box::new(move |entry_result| {
                let _io_permit = match Self::acquire_io_permit_blocking(&io_sem) {
                    Some(p) => p,
                    None => return WalkState::Quit,
                };
                if let Some(candidate) = Self::process_walk_entry(entry_result, &router, &stats) {
                    drop(_io_permit);
                    if tx.send(candidate).is_err() {
                        return WalkState::Quit;
                    }
                }
                WalkState::Continue
            })
        });

        Ok(rx.into_iter().collect())
    }

    /// Internal synchronous multi-threaded walker execution loop.
    fn run_crawl_blocking(
        &self,
        tx: mpsc::Sender<DiscoveredCandidate>,
    ) -> Result<CrawlerStats, IngestError> {
        let start = Instant::now();
        let stats = Arc::new(AtomicCrawlerStats::new());

        for root in &self.config.watch_paths {
            if !root.exists() {
                warn!("Configured watch path does not exist: {}", root.display());
                continue;
            }
            self.crawl_single_root(root, &tx, &stats)?;
        }

        let summary = stats.snapshot(start.elapsed().as_millis() as u64);
        info!(
            scanned = summary.files_scanned,
            text_accepted = summary.files_accepted_text,
            images_accepted = summary.files_accepted_image,
            skipped_bin = summary.files_skipped_binary,
            skipped_size = summary.files_skipped_size,
            elapsed_ms = summary.elapsed_millis,
            "Filesystem parallel crawl complete"
        );
        Ok(summary)
    }

    /// Synchronously crawls multiple directory roots in a unified work-stealing parallel traversal.
    pub fn crawl_multi_root_sync(&self, roots: &[PathBuf]) -> Result<Vec<DiscoveredCandidate>, IngestError> {
        let valid_roots: Vec<&Path> = roots.iter().map(|p| p.as_path()).filter(|p| p.exists()).collect();
        if valid_roots.is_empty() {
            return Ok(Vec::new());
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let stats = Arc::new(AtomicCrawlerStats::new());
        let mut builder = WalkBuilder::new(valid_roots[0]);
        for root in &valid_roots[1..] {
            builder.add(root);
        }
        self.configure_builder(&mut builder);
        let walker = builder.build_parallel();
        let router = self.router.clone();

        let io_sem = Arc::clone(&self.io_semaphore);
        walker.run(move || {
            crate::throttling::set_background_thread_priority();
            let tx = tx.clone();
            let router = router.clone();
            let stats = Arc::clone(&stats);
            let io_sem = Arc::clone(&io_sem);

            Box::new(move |entry_result| {
                let _io_permit = match Self::acquire_io_permit_blocking(&io_sem) {
                    Some(p) => p,
                    None => return WalkState::Quit,
                };
                if let Some(candidate) = Self::process_walk_entry(entry_result, &router, &stats) {
                    drop(_io_permit);
                    if tx.send(candidate).is_err() {
                        return WalkState::Quit;
                    }
                }
                WalkState::Continue
            })
        });

        Ok(rx.into_iter().collect())
    }

    /// Streams candidate files across multiple directory roots through a bounded Tokio MPSC channel
    /// using OS low-priority background thread scheduling and work-stealing parallel traversal.
    pub fn stream_crawl_multi_root(
        self: Arc<Self>,
        roots: Vec<PathBuf>,
        tx: mpsc::Sender<DiscoveredCandidate>,
        io_semaphore: Arc<tokio::sync::Semaphore>,
    ) -> tokio::task::JoinHandle<Result<CrawlerStats, IngestError>> {
        tokio::task::spawn_blocking(move || {
            crate::throttling::set_background_thread_priority();
            let start = Instant::now();
            let stats = Arc::new(AtomicCrawlerStats::new());

            let valid_roots: Vec<PathBuf> = roots.into_iter().filter(|p| p.exists()).collect();
            if !valid_roots.is_empty() {
                let mut builder = WalkBuilder::new(&valid_roots[0]);
                for root in &valid_roots[1..] {
                    builder.add(root);
                }
                self.configure_builder(&mut builder);
                let walker = builder.build_parallel();
                let router = self.router.clone();
                let stats_clone = Arc::clone(&stats);
                let tx_clone = tx.clone();
                let io_sem = Arc::clone(&io_semaphore);

                walker.run(move || {
                    crate::throttling::set_background_thread_priority();
                    let tx = tx_clone.clone();
                    let router = router.clone();
                    let stats = Arc::clone(&stats_clone);
                    let io_sem = Arc::clone(&io_sem);

                    Box::new(move |entry_result| {
                        let _permit_guard = match Self::acquire_io_permit_blocking(&io_sem) {
                            Some(p) => p,
                            None => return WalkState::Quit,
                        };
                        if let Some(candidate) = Self::process_walk_entry(entry_result, &router, &stats) {
                            drop(_permit_guard);
                            if tx.blocking_send(candidate).is_err() {
                                return WalkState::Quit;
                            }
                        }
                        WalkState::Continue
                    })
                });
            }

            let summary = stats.snapshot(start.elapsed().as_millis() as u64);
            crate::throttling::end_background_thread_priority();
            Ok(summary)
        })
    }

    /// Configures ignore rules, source code exclusions, and binary filters on the WalkBuilder.
    pub fn configure_builder(&self, builder: &mut WalkBuilder) {
        builder
            .hidden(self.config.skip_hidden)
            .ignore(self.config.ignore_files)
            .git_ignore(self.config.git_ignore)
            .git_global(self.config.git_global)
            .git_exclude(self.config.git_ignore)
            .require_git(false)
            .add_custom_ignore_filename(".gitignore")
            .add_custom_ignore_filename(".ignore")
            .follow_links(self.config.follow_symlinks)
            .same_file_system(self.config.same_file_system)
            .max_filesize(Some(self.config.max_file_size_bytes));

        let exclude_source_code = self.config.exclude_source_code;
        let excluded_paths = self.config.excluded_paths.clone();
        builder.filter_entry(move |entry| {
            let entry_path = entry.path();
            if excluded_paths.iter().any(|ex| entry_path == ex || entry_path.starts_with(ex)) {
                return false;
            }
            if entry.depth() == 0 {
                return true;
            }
            if let Some(name) = entry.file_name().to_str() {
                let lower = name.to_ascii_lowercase();
                if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                    if matches!(
                        lower.as_str(),
                        "$recycle.bin"
                            | "system volume information"
                            | "windows"
                            | "program files"
                            | "program files (x86)"
                            | "programdata"
                            | "recovery"
                            | "perflogs"
                            | "msocache"
                            | "config.msi"
                            | "appdata"
                            | "node_modules"
                            | "target"
                            | "osoosi_target"
                            | "site-packages"
                            | "dist-packages"
                            | "docker"
                            | "chrome_temp_profile"
                            | ".git"
                            | ".cargo"
                            | ".rustup"
                            | "__pycache__"
                            | ".venv"
                            | "venv"
                            | ".pytest_cache"
                            | ".lance"
                            | "lance"
                            | ".tantivy"
                            | "tantivy"
                            | ".quorumrag-live-data"
                            | "storage"
                            | "quorumrag"
                            | ".quorumrag"
                    ) {
                        return false;
                    }
                    if exclude_source_code
                        && matches!(
                            lower.as_str(),
                            "harfile"
                                | "python311"
                                | "tools"
                                | "yara"
                                | "rules"
                                | "db"
                                | "dataset"
                                | "restored_attachments"
                        )
                    {
                        return false;
                    }
                } else if lower.starts_with('~')
                    || lower.starts_with(".~lock")
                    || lower.ends_with(".tmp")
                    || lower.ends_with(".bak")
                    || lower.ends_with(".wbk")
                    || lower == "dedup_catalog.json"
                    || lower.starts_with("dedup_catalog.")
                    || lower.starts_with(".dedup_catalog")
                    || lower.starts_with("document_catalog.")
                    || lower == "metadata.json"
                    || lower == ".metadata.json"
                    || lower == "embedding_contract.json"
                    || matches!(
                        lower.as_str(),
                        "cargo.lock"
                            | "package-lock.json"
                            | "pnpm-lock.yaml"
                            | "yarn.lock"
                            | "poetry.lock"
                            | "composer.lock"
                            | "gemfile.lock"
                    )
                {
                    return false;
                } else if exclude_source_code {
                    const EXCLUDED_SOURCE_EXTS: &[&str] = &[
                        ".rs", ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".cpp", ".h", ".hpp",
                        ".cc", ".cs", ".java", ".go", ".kt", ".rb", ".php", ".swift", ".scala",
                        ".sh", ".bash", ".ps1", ".bat", ".cmd", ".sql", ".css", ".scss", ".less",
                        ".vue", ".svelte", ".toml", ".yaml", ".yml", ".lock", ".dat", ".log",
                        ".json", ".jsonl", ".xml", ".aux", ".bbl",
                        ".blg", ".out", ".toc", ".synctex", ".crt", ".pem", ".key",
                    ];
                    if EXCLUDED_SOURCE_EXTS.iter().any(|ext| lower.ends_with(ext)) {
                        return false;
                    }
                }
            }
            true
        });

        if self.config.crawler_threads > 0 {
            builder.threads(self.config.crawler_threads);
        }
    }

    fn build_walker(&self, root: &Path) -> WalkParallel {
        let mut builder = WalkBuilder::new(root);
        self.configure_builder(&mut builder);
        builder.build_parallel()
    }

    fn crawl_single_root(
        &self,
        root: &Path,
        tx: &mpsc::Sender<DiscoveredCandidate>,
        stats: &Arc<AtomicCrawlerStats>,
    ) -> Result<(), IngestError> {
        let walker = self.build_walker(root);
        let router = self.router.clone();
        let tx_channel = tx.clone();
        let stats_ref = Arc::clone(stats);

        let io_sem = Arc::clone(&self.io_semaphore);

        walker.run(move || {
            crate::throttling::set_background_thread_priority();
            let tx = tx_channel.clone();
            let router = router.clone();
            let stats = Arc::clone(&stats_ref);
            let io_sem = Arc::clone(&io_sem);

            Box::new(move |entry_result| {
                let _permit_guard = match Self::acquire_io_permit_blocking(&io_sem) {
                    Some(p) => p,
                    None => return WalkState::Quit,
                };
                if let Some(candidate) = Self::process_walk_entry(entry_result, &router, &stats) {
                    drop(_permit_guard);
                    if tx.blocking_send(candidate).is_err() {
                        return WalkState::Quit;
                    }
                }
                WalkState::Continue
            })
        });

        Ok(())
    }

    fn process_walk_entry(
        entry_result: Result<ignore::DirEntry, ignore::Error>,
        router: &ClassifierRouter,
        stats: &AtomicCrawlerStats,
    ) -> Option<DiscoveredCandidate> {
        let entry = match entry_result {
            Ok(e) => e,
            Err(err) => {
                stats.files_skipped_io.fetch_add(1, Ordering::Relaxed);
                debug!("Crawler I/O error on entry: {}", err);
                return None;
            }
        };

        let ft = entry.file_type()?;

        if ft.is_dir() {
            stats.directories_visited.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        if !ft.is_file() {
            return None;
        }

        stats.files_scanned.fetch_add(1, Ordering::Relaxed);
        let path = entry.path().to_path_buf();

        match router.evaluate_file(&path) {
            FilterDecision::Accept {
                identity,
                kind,
                size_bytes,
                mtime_secs,
            } => {
                match &kind {
                    CandidateKind::Text { .. } => {
                        stats.files_accepted_text.fetch_add(1, Ordering::Relaxed);
                    }
                    CandidateKind::Image { .. } => {
                        stats.files_accepted_image.fetch_add(1, Ordering::Relaxed);
                    }
                    CandidateKind::Audio { .. } => {
                        stats.files_accepted_audio.fetch_add(1, Ordering::Relaxed);
                    }
                }

                Some(DiscoveredCandidate {
                    path,
                    size_bytes,
                    mtime_secs,
                    file_identity: identity,
                    kind,
                })
            }
            FilterDecision::SkipExceedsSizeCap { .. } => {
                stats.files_skipped_size.fetch_add(1, Ordering::Relaxed);
                None
            }
            FilterDecision::SkipBinary { .. } => {
                stats.files_skipped_binary.fetch_add(1, Ordering::Relaxed);
                None
            }
            FilterDecision::SkipHidden | FilterDecision::SkipSymlink => {
                stats.files_skipped_hidden.fetch_add(1, Ordering::Relaxed);
                None
            }
            FilterDecision::SkipIoError { .. } => {
                stats.files_skipped_io.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
}
