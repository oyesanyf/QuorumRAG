//! Configuration options for QuorumRAG embedded storage engine.

use std::path::{Path, PathBuf};

/// Storage configuration defining filesystem layout and indexing parameters.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Root directory for all persistent storage data.
    pub storage_path: PathBuf,

    /// Name of the LanceDB vector table.
    pub table_name: String,

    /// Dimensionality of embedding vectors (e.g. 768 for Gemma).
    pub vector_dimension: usize,

    /// Minimum number of rows before creating IVF_PQ index automatically.
    pub auto_index_threshold: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_path: PathBuf::from("./data/storage"),
            table_name: "quorum_chunks".to_string(),
            vector_dimension: 768,
            auto_index_threshold: 5000,
        }
    }
}

impl StorageConfig {
    /// Create a new configuration pointing to the specified storage directory.
    pub fn new(storage_path: impl Into<PathBuf>) -> Self {
        Self {
            storage_path: storage_path.into(),
            ..Default::default()
        }
    }

    /// Set custom table name.
    pub fn with_table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = name.into();
        self
    }

    /// Set vector dimension.
    pub fn with_vector_dimension(mut self, dim: usize) -> Self {
        self.vector_dimension = dim;
        self
    }

    /// Set auto-index threshold.
    pub fn with_auto_index_threshold(mut self, threshold: usize) -> Self {
        self.auto_index_threshold = threshold;
        self
    }

    /// Path to embedded LanceDB directory.
    pub fn lance_path(&self) -> PathBuf {
        self.storage_path.join(".lance")
    }

    /// Path to co-located Tantivy FTS directory.
    pub fn tantivy_path(&self) -> PathBuf {
        self.storage_path.join(".tantivy")
    }

    /// Path to persistent metadata file storing index_epoch and synchronization state.
    pub fn metadata_path(&self) -> PathBuf {
        self.storage_path.join(".metadata.json")
    }
}

impl<P: AsRef<Path>> From<P> for StorageConfig {
    fn from(p: P) -> Self {
        Self::new(p.as_ref().to_path_buf())
    }
}
