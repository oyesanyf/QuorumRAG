//! `quorum-ingest`: High-capacity filesystem crawler, real-time OS watcher,
//! Google Magika content classification, two-level BLAKE3 deduplication,
//! image indexing, dedicated reindexing, and comprehensive 5-drift remediation engine.

pub mod artemis;
pub mod audio_indexer;
pub mod classifier_router;
pub mod cloud_drives;
pub mod chunker;
pub mod config;
pub mod content_safety;
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
    build_summary_text, collect_forensic_directory, collect_live_os_forensics,
    infer_host_identifier, infer_os_platform, infer_source_path, infer_telemetry_type,
    infer_timestamp_unix_secs, parse_artemis_jsonl, parse_artemis_jsonl_str, scrub_json_value,
    ArtemisTelemetryRecord,
};
pub use audio_indexer::{AudioIndexer, AudioMetadata};
pub use classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
pub use cloud_drives::{
    build_default_cloud_drives_settings, discover_cloud_drives, discover_cloud_drives_with_env,
    ensure_open_allowed_for_placeholder, is_cloud_placeholder_metadata,
    is_macos_cloud_placeholder_flags, is_windows_cloud_placeholder_attrs,
    read_bytes_with_placeholder_policy, should_skip_cloud_placeholder, CloudDiscoveryEnv,
    DiscoveredCloudDrive, LiveCloudDiscoveryEnv, RegistrySyncRoot, TargetOs, WindowsDriveMount,
    FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    MACOS_SF_DATALESS, WINDOWS_CLOUD_PLACEHOLDER_MASK,
};
pub use chunker::{
    build_contextual_header, parse_section_header_line, prepend_contextual_header,
    prepend_contextual_header_with_section, resolve_document_metadata, RawTextChunk,
    ResolvedDocumentMetadata, SectionHeader, SectionHierarchyStack, StructureAwareRawChunk,
    TextChunker,
};
pub use config::{
    normalize_path_for_prefix, path_matches_prefix, ChunkerConfig, DriftFixOptions, DriftType,
    IngestConfig, ReindexOptions,
};
pub use content_safety::{
    analyze_image_pixels, check_path_explicit_content, check_text_explicit_content,
    evaluate_image_file_safety, evaluate_image_metadata_and_text, evaluate_image_safety,
    is_raster_image_extension, is_visual_media_extension, ContentSafetyDecision,
    VisualSafetyMetrics,
};
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
    has_mixed_classes, is_high_entropy_secret, is_uuid_or_path, sanitize_and_gate_metadata_json,
    sanitize_and_gate_parent_document, sanitize_and_gate_resolved_metadata, sanitize_and_gate_text,
    scrub_high_entropy_tokens, scrub_high_entropy_tokens_preserving_layout, scrub_regex_secrets,
    scrub_text, scrub_text_preserving_layout, shannon_entropy_bits, SecretScrubber,
};
pub use throttling::{
    current_process_rss_bytes, end_background_thread_priority,
    pin_worker_thread_to_background_core, set_background_thread_priority,
};
pub use thread_pool::{IngestPermitTiers, IngestThreadPool, PermitTierTelemetrySnapshot};
pub use warmer::{CacheWarmReport, CacheWarmer, WarmConfig};
pub use watcher::{FilesystemWatcher, WatcherEvent, WatcherHandle};

