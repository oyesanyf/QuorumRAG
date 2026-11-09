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

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use crate::error::IngestError;

static SHARED_INGEST_POOL: std::sync::OnceLock<IngestThreadPool> = std::sync::OnceLock::new();

/// Dedicated core-pinned Rayon thread pool for document parsing and chunking.
#[derive(Clone)]
pub struct IngestThreadPool {
    pool: Arc<rayon::ThreadPool>,
    thread_count: usize,
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
    /// reserving at least 1 core for the Tokio reactor and UI threads.
    pub fn new() -> Result<Self, IngestError> {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get().saturating_sub(1).clamp(2, 16))
            .unwrap_or(4);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|idx| format!("quorum-ingest-{}", idx))
            .start_handler(|_idx| {
                crate::throttling::set_background_thread_priority();
            })
            .build()
            .map_err(|e| IngestError::Io(std::io::Error::other(format!("Failed to build Rayon thread pool: {}", e))))?;

        Ok(Self {
            pool: Arc::new(pool),
            thread_count: threads,
        })
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
}

impl IngestPermitTiers {
    /// Initializes permit pools calibrated to host core count.
    pub fn new(extraction_concurrency: usize) -> Self {
        let ext_concurrency = if extraction_concurrency > 0 {
            extraction_concurrency.clamp(4, 64)
        } else {
            std::thread::available_parallelism()
                .map(|n| (n.get() * 2).clamp(8, 32))
                .unwrap_or(16)
        };

        Self {
            extraction: Arc::new(Semaphore::new(ext_concurrency)),
            storage_commit: Arc::new(Semaphore::new(2)),
            vision_captioning: Arc::new(Semaphore::new(1)),
        }
    }

    /// Acquire an extraction permit.
    pub async fn acquire_extraction(&self) -> Result<OwnedSemaphorePermit, IngestError> {
        self.extraction
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| IngestError::Cancelled)
    }

    /// Acquire a storage commit permit (bounds concurrent Arrow / Tantivy writes).
    pub async fn acquire_storage_commit(&self) -> Result<OwnedSemaphorePermit, IngestError> {
        self.storage_commit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| IngestError::Cancelled)
    }

    /// Acquire a GPU / VRAM Ollama vision permit (serializes vision captioning).
    pub async fn acquire_vision(&self) -> Result<OwnedSemaphorePermit, IngestError> {
        self.vision_captioning
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| IngestError::Cancelled)
    }
}
