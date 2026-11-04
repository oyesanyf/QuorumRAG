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
pub mod engine;
pub mod error;
pub mod query_framing;
pub(crate) mod tantivy_fts;
pub(crate) mod vector_store;

pub use config::StorageConfig;
pub use engine::{CompactionStats, SearchMode, StorageEngine, StorageSearchQuery};
pub use error::StorageError;
