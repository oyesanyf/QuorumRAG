//! Error types for QuorumRAG storage engine.
//!
//! # Invariant: Absolute Arrow Isolation
//! ZERO Arrow, LanceDB, or Tantivy types may be exported in public errors or APIs.

use std::path::PathBuf;
use thiserror::Error;

/// Storage errors encountered during vector storage, indexing, or retrieval operations.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Generic I/O error: {0}")]
    GenericIo(#[from] std::io::Error),

    #[error("LanceDB error: {0}")]
    Lance(String),

    #[error("Arrow conversion error: {0}")]
    Arrow(String),

    #[error("Tantivy FTS error: {0}")]
    Tantivy(String),

    #[error("Domain type error: {0}")]
    Type(#[from] quorum_types::TypeError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    #[error("Schema error: {0}")]
    Schema(String),

    #[error("Compaction error: {0}")]
    Compaction(String),

    #[error("Chunk not found: {0}")]
    NotFound(String),
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serialization(err.to_string())
    }
}
