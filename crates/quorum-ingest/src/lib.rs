//! `quorum-ingest`: High-capacity filesystem crawler, real-time OS watcher,
//! Google Magika content classification, two-level BLAKE3 deduplication,
//! image indexing, dedicated reindexing, and comprehensive 5-drift remediation engine.

pub mod audio_indexer;
pub mod classifier_router;
pub mod chunker;
pub mod config;
pub mod crawler;
pub mod dedup;
pub mod document_extractor;
pub mod drift_healer;
pub mod engine;
pub mod error;
pub mod exif;
pub mod image_indexer;
pub mod reindex;
pub mod reverse_geocoder;
pub mod warmer;
pub mod watcher;
pub mod throttling;

// Re-exports
pub use audio_indexer::{AudioIndexer, AudioMetadata};
pub use classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
pub use chunker::{RawTextChunk, TextChunker};
pub use config::{ChunkerConfig, DriftFixOptions, DriftType, IngestConfig, ReindexOptions};
pub use crawler::{CrawlerStats, DiscoveredCandidate, FilesystemCrawler};
pub use dedup::{
    CacheStats, DedupAction, FileCatalogEntry, Level1DedupCatalog, Level2ChunkCache,
    TwoLevelDedupEngine,
};
pub use document_extractor::DocumentExtractor;
pub use drift_healer::{DriftHealer, DriftReport};
pub use engine::IngestEngine;
pub use error::IngestError;
pub use image_indexer::{ImageIndexer, ImageMetadata};
pub use reindex::{ReindexPhase, ReindexProgress, ReindexWorker};
pub use reverse_geocoder::{resolve_location, GeoLocation};
pub use throttling::{end_background_thread_priority, set_background_thread_priority};
pub use warmer::{CacheWarmReport, CacheWarmer, WarmConfig};
pub use watcher::{FilesystemWatcher, WatcherEvent, WatcherHandle};
