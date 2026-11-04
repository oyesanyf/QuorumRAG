//! Error types for the ingestion subsystem.

use std::path::PathBuf;
use thiserror::Error;

/// Comprehensive error type for all ingestion operations.
#[derive(Debug, Error)]
pub enum IngestError {
    #[error("I/O error at '{path}': {source}")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("OS Watcher error: {0}")]
    WatcherError(String),

    #[error("Classification error at '{path}': {details}")]
    ClassificationError {
        path: PathBuf,
        details: String,
    },

    #[error("File '{path}' exceeds max size cap ({actual_bytes} > {max_bytes} bytes)")]
    FileSizeExceeded {
        path: PathBuf,
        actual_bytes: u64,
        max_bytes: u64,
    },

    #[error("Storage write error: {0}")]
    StorageError(#[from] quorum_storage::StorageError),

    #[error("Contract error: {0}")]
    ContractError(#[from] quorum_contract::ContractError),

    #[error("Type error: {0}")]
    TypeError(#[from] quorum_types::TypeError),

    #[error("Ingestion channel closed or consumer dropped")]
    ChannelClosed,

    #[error("Task already running: {0}")]
    TaskAlreadyRunning(String),

    #[error("Task cancelled")]
    Cancelled,
}
