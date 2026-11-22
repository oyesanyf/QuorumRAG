//! Error types for the `quorum-atlaskv` pure-Rust Knowledge Graph & HiKVP engine.

use std::path::PathBuf;
use thiserror::Error;

/// Unified error type returned by `quorum-atlaskv` operations.
#[derive(Debug, Error)]
pub enum AtlasKvError {
    #[error("I/O error at '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("SQLite metadata error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Vector dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },

    #[error("Input slice length mismatch: {context}")]
    LengthMismatch { context: String },

    #[error("Invalid access tier {0}: valid range is 0..=3")]
    InvalidAccessTier(u8),

    #[error("Path containment violation blocked: {0}")]
    PathTraversal(String),

    #[error("Invalid NumPy .npy format: {0}")]
    NpyFormat(String),

    #[error("Corrupted AtlasKV hierarchy file: {0}")]
    CorruptedHierarchy(String),
}
