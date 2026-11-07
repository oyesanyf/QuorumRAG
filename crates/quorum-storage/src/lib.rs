//! # QuorumRAG Storage Engine
//!
//! Production-grade embedded vector and full-text search engine for QuorumRAG.
//!
//! ## Architecture & Arrow Isolation
//! All `arrow-array`, `arrow-schema`, `lancedb`, and `tantivy` dependencies are
//! strictly encapsulated inside crate-internal `pub(crate)` modules.
//! ZERO Arrow or LanceDB types are exposed in the public interface.
//!
//! ## Features
//! - Embedded LanceDB vector storage with Cosine similarity and SQL pre-filtering pushdown (`only_if`).
//! - Co-located Tantivy BM25 full-text search with numeric range filtering over access tiers.
//! - Storage-level Reciprocal Rank Fusion (RRF) combining vector and lexical rankings.
//! - Automated Level-2 BLAKE3 deduplication on insertion.
//! - Parquet fragment compaction and version pruning.

pub(crate) mod arrow_interop;
pub mod config;
pub mod document_catalog;
pub mod engine;
pub mod error;
pub mod query_framing;
pub(crate) mod tantivy_fts;
pub(crate) mod vector_store;

pub use config::StorageConfig;
pub use document_catalog::{derive_work_cluster_id, DocumentCatalog, DocumentCatalogEntry};
pub use engine::{CompactionStats, SearchMode, StorageEngine, StorageSearchQuery};
pub use error::StorageError;
pub use tantivy_fts::DistinctWorkHit;

pub(crate) fn tantivy_fts_anchor_probe(anchor_text: &str) -> &str {
    let trimmed = anchor_text.trim();
    if !trimmed.starts_with("[Document:") && !trimmed.starts_with("[Image Document:") {
        let mut end = trimmed.len().min(96);
        while end > 0 && !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        return trimmed[..end].trim();
    }
    // Skip synthetic header lines to locate body text in raw parent document
    for line in trimmed.lines().skip(1) {
        let l = line.trim();
        if l.is_empty()
            || l.starts_with("Path:")
            || l.starts_with("Author:")
            || l.starts_with("Title:")
            || l.starts_with("Section:")
        {
            continue;
        }
        let mut end = l.len().min(96);
        while end > 0 && !l.is_char_boundary(end) {
            end -= 1;
        }
        return l[..end].trim();
    }
    trimmed
}
