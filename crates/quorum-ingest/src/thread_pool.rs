//! Dedicated Core-Pinned Ingestion ThreadPool & Tiered Semaphore Permit Hierarchy.
//!
//! Enforces:
//! - Partitioning CPU-bound document parsing and AST chunking onto a dedicated
//!   `rayon::ThreadPool` isolated from the main Tokio async reactor.
//! - OS low-priority background scheduling on all worker threads so host responsiveness is unaffected.
//! - Tiered `Arc<tokio::sync::Semaphore>` backpressure:
//!   * High-concurrency extraction permit pool.
//!   * Memory-budgeted LanceDB / Tantivy commit semaphore (bounded to 2 concurrent writes).
//!   * Strict GPU/VRAM-aware Ollama vision captioning semaphore (bounded to 1 concurrent query).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use crate::error::IngestError;

static SHARED_INGEST_POOL: std::sync::OnceLock<IngestThreadPool> = std::sync::OnceLock::new();

/// Snapshot of peak and active permit utilization across the three ingestion semaphore tiers.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PermitTierTelemetrySnapshot {
    pub extraction_capacity: usize,
    pub storage_commit_capacity: usize,
    pub vision_capacity: usize,
    pub peak_extraction_in_use: usize,
    pub peak_storage_commit_in_use: usize,
    pub peak_vision_in_use: usize,
    pub total_extraction_acquired: usize,
    pub total_storage_commit_acquired: usize,
    pub total_vision_acquired: usize,
}

#[derive(Default)]
pub struct PermitTierTelemetry {
    pub peak_extraction_in_use: AtomicUsize,
    pub peak_storage_commit_in_use: AtomicUsize,
    pub peak_vision_in_use: AtomicUsize,
    pub total_extraction_acquired: AtomicUsize,
    pub total_storage_commit_acquired: AtomicUsize,
    pub total_vision_acquired: AtomicUsize,
}

/// Dedicated core-pinned Rayon thread pool for document parsing and chunking.
#[derive(Clone)]
pub struct IngestThreadPool {
    pool: Arc<rayon::ThreadPool>,
    thread_count: usize,
    permit_tiers: IngestPermitTiers,
}

impl IngestThreadPool {
    /// Returns a reference to the global shared core-pinned ingestion thread pool.
    pub fn shared() -> &'static IngestThreadPool {
        SHARED_INGEST_POOL.get_or_init(|| {
            Self::new().unwrap_or_else(|e| {
                panic!("Failed to initialize shared IngestThreadPool: {}", e);
            })
        })
    }

    /// Creates a dedicated thread pool with worker count derived from hardware parallelism,
    /// reserving at least 1 core for the Tokio reactor and UI threads, and pinning worker threads
    /// to background cores with OS low-priority scheduling.
    pub fn new() -> Result<Self, IngestError> {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get().saturating_sub(1).clamp(2, 16))
            .unwrap_or(4);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|idx| format!("quorum-ingest-{}", idx))
            .start_handler(|idx| {
                crate::throttling::set_background_thread_priority();
                crate::throttling::pin_worker_thread_to_background_core(idx);
            })
            .build()
            .map_err(|e| IngestError::Io(std::io::Error::other(format!("Failed to build Rayon thread pool: {}", e))))?;

        let permit_tiers = IngestPermitTiers::new(threads);

        Ok(Self {
            pool: Arc::new(pool),
            thread_count: threads,
            permit_tiers,
        })
    }

    /// Returns a reference to the permit tiers hierarchy.
    pub fn permit_tiers(&self) -> &IngestPermitTiers {
        &self.permit_tiers
    }

    /// Access the underlying `Arc<rayon::ThreadPool>`.
    pub fn pool(&self) -> &Arc<rayon::ThreadPool> {
        &self.pool
    }

    /// Returns the number of worker threads in this pool.
    pub fn thread_count(&self) -> usize {
        self.thread_count
    }

    /// Executes a CPU-bound closure on the dedicated thread pool and awaits the result asynchronously.
    pub fn spawn_task<F, R>(&self, f: F) -> impl std::future::Future<Output = Result<R, IngestError>> + Send + 'static
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let pool = Arc::clone(&self.pool);
        async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            pool.spawn(move || {
                let res = f();
                let _ = tx.send(res);
            });
            rx.await.map_err(|_| IngestError::Cancelled)
        }
    }

    /// Executes a CPU-bound closure on the dedicated thread pool while holding an explicit semaphore permit
    /// across the entire execution of the closure on the worker thread.
    pub fn spawn_blocking_pinned<F, R>(
        &self,
        permit: OwnedSemaphorePermit,
        f: F,
    ) -> impl std::future::Future<Output = Result<R, IngestError>> + Send + 'static
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let pool = Arc::clone(&self.pool);
        async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            pool.spawn(move || {
                let _permit = permit;
                let res = f();
                let _ = tx.send(res);
            });
            rx.await.map_err(|_| IngestError::Cancelled)
        }
    }
}

/// Tiered Semaphore Permit Hierarchy for strict pipeline backpressure.
#[derive(Clone)]
pub struct IngestPermitTiers {
    pub extraction: Arc<Semaphore>,
    pub storage_commit: Arc<Semaphore>,
    pub vision_captioning: Arc<Semaphore>,
    pub extraction_capacity: usize,
    pub storage_commit_capacity: usize,
    pub vision_capacity: usize,
    pub telemetry: Arc<PermitTierTelemetry>,
}

impl IngestPermitTiers {
    /// Initializes permit pools calibrated to host core count.
    pub fn new(extraction_concurrency: usize) -> Self {
        Self::new_vram_aware(extraction_concurrency, 0, 16.0)
    }

    /// Initializes permit pools calibrated to host core count and available GPU VRAM / RAM.
    pub fn new_vram_aware(extraction_concurrency: usize, free_vram_mb: u64, free_ram_gb: f64) -> Self {
        let ext_concurrency = if extraction_concurrency > 0 {
            extraction_concurrency.clamp(4, 64)
        } else {
            std::thread::available_parallelism()
                .map(|n| (n.get() * 2).clamp(8, 32))
                .unwrap_or(16)
        };
        let storage_cap = if free_ram_gb >= 24.0 { 2 } else { 2 };
        let vision_cap = if free_vram_mb >= 16_000 { 2 } else { 1 };

        Self {
            extraction: Arc::new(Semaphore::new(ext_concurrency)),
            storage_commit: Arc::new(Semaphore::new(storage_cap)),
            vision_captioning: Arc::new(Semaphore::new(vision_cap)),
            extraction_capacity: ext_concurrency,
            storage_commit_capacity: storage_cap,
            vision_capacity: vision_cap,
            telemetry: Arc::new(PermitTierTelemetry::default()),
        }
    }

    /// Acquire an extraction permit and update peak utilization telemetry.
    pub async fn acquire_extraction(&self) -> Result<OwnedSemaphorePermit, IngestError> {
        let permit = self
            .extraction
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| IngestError::Cancelled)?;
        let in_use = self
            .extraction_capacity
            .saturating_sub(self.extraction.available_permits());
        self.telemetry
            .peak_extraction_in_use
            .fetch_max(in_use, Ordering::Relaxed);
        self.telemetry
            .total_extraction_acquired
            .fetch_add(1, Ordering::Relaxed);
        Ok(permit)
    }

    /// Acquire a storage commit permit (bounds concurrent Arrow / Tantivy writes).
    pub async fn acquire_storage_commit(&self) -> Result<OwnedSemaphorePermit, IngestError> {
        let permit = self
            .storage_commit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| IngestError::Cancelled)?;
        let in_use = self
            .storage_commit_capacity
            .saturating_sub(self.storage_commit.available_permits());
        self.telemetry
            .peak_storage_commit_in_use
            .fetch_max(in_use, Ordering::Relaxed);
        self.telemetry
            .total_storage_commit_acquired
            .fetch_add(1, Ordering::Relaxed);
        Ok(permit)
    }

    /// Acquire a GPU / VRAM Ollama vision permit (serializes vision captioning).
    pub async fn acquire_vision(&self) -> Result<OwnedSemaphorePermit, IngestError> {
        let permit = self
            .vision_captioning
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| IngestError::Cancelled)?;
        let in_use = self
            .vision_capacity
            .saturating_sub(self.vision_captioning.available_permits());
        self.telemetry
            .peak_vision_in_use
            .fetch_max(in_use, Ordering::Relaxed);
        self.telemetry
            .total_vision_acquired
            .fetch_add(1, Ordering::Relaxed);
        Ok(permit)
    }

    /// Synchronously acquire a GPU / VRAM Ollama vision permit, blocking until available.
    pub fn acquire_vision_blocking(&self) -> Result<OwnedSemaphorePermit, IngestError> {
        let mut backoff = 1u64;
        loop {
            match self.vision_captioning.clone().try_acquire_owned() {
                Ok(permit) => {
                    let in_use = self
                        .vision_capacity
                        .saturating_sub(self.vision_captioning.available_permits());
                    self.telemetry
                        .peak_vision_in_use
                        .fetch_max(in_use, Ordering::Relaxed);
                    self.telemetry
                        .total_vision_acquired
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(permit);
                }
                Err(tokio::sync::TryAcquireError::Closed) => return Err(IngestError::Cancelled),
                Err(tokio::sync::TryAcquireError::NoPermits) => {
                    if backoff < 16 {
                        std::thread::yield_now();
                        backoff += 1;
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                }
            }
        }
    }

    /// Returns a snapshot of peak and total permit utilization across all three tiers.
    pub fn telemetry_snapshot(&self) -> PermitTierTelemetrySnapshot {
        PermitTierTelemetrySnapshot {
            extraction_capacity: self.extraction_capacity,
            storage_commit_capacity: self.storage_commit_capacity,
            vision_capacity: self.vision_capacity,
            peak_extraction_in_use: self.telemetry.peak_extraction_in_use.load(Ordering::Relaxed),
            peak_storage_commit_in_use: self.telemetry.peak_storage_commit_in_use.load(Ordering::Relaxed),
            peak_vision_in_use: self.telemetry.peak_vision_in_use.load(Ordering::Relaxed),
            total_extraction_acquired: self.telemetry.total_extraction_acquired.load(Ordering::Relaxed),
            total_storage_commit_acquired: self.telemetry.total_storage_commit_acquired.load(Ordering::Relaxed),
            total_vision_acquired: self.telemetry.total_vision_acquired.load(Ordering::Relaxed),
        }
    }
}
