//! `quorum-ingest`: High-capacity filesystem crawler, real-time OS watcher,
//! Google Magika content classification, two-level BLAKE3 deduplication,
//! image indexing, dedicated reindexing, and comprehensive 5-drift remediation engine.

pub mod artemis;
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
pub mod secret_scrubber;
pub mod warmer;
pub mod watcher;
pub mod throttling;
pub mod thread_pool;

// Re-exports
pub use artemis::{
    build_summary_text, infer_host_identifier, infer_os_platform, infer_source_path,
    infer_telemetry_type, infer_timestamp_unix_secs, parse_artemis_jsonl, parse_artemis_jsonl_str,
    scrub_json_value, ArtemisTelemetryRecord,
};
pub use audio_indexer::{AudioIndexer, AudioMetadata};
pub use classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
pub use chunker::{
    build_contextual_header, parse_section_header_line, prepend_contextual_header,
    prepend_contextual_header_with_section, resolve_document_metadata, RawTextChunk,
    ResolvedDocumentMetadata, SectionHeader, SectionHierarchyStack, StructureAwareRawChunk,
    TextChunker,
};
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
pub use image_indexer::{ImageIndexer, ImageMetadata, OcrOutcome};
pub use reindex::{ReindexPhase, ReindexProgress, ReindexWorker};
pub use reverse_geocoder::{resolve_location, GeoLocation};
pub use secret_scrubber::{
    has_mixed_classes, is_high_entropy_secret, is_uuid_or_path, scrub_high_entropy_tokens,
    scrub_regex_secrets, scrub_text, shannon_entropy_bits, SecretScrubber,
};
pub use throttling::{
    current_process_rss_bytes, end_background_thread_priority,
    pin_worker_thread_to_background_core, set_background_thread_priority,
};
pub use thread_pool::{IngestPermitTiers, IngestThreadPool, PermitTierTelemetrySnapshot};
pub use warmer::{CacheWarmReport, CacheWarmer, WarmConfig};
pub use watcher::{FilesystemWatcher, WatcherEvent, WatcherHandle};

