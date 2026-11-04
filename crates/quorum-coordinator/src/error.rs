use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error("Scatter-gather query timed out after {0}ms")]
    Timeout(u64),

    #[error("Stale timestamp: server={server_time}, query={query_time}, drift={drift_secs}s exceeds limit {limit}s")]
    StaleTimestamp {
        server_time: i64,
        query_time: i64,
        drift_secs: i64,
        limit: i64,
    },

    #[error("Invalid Ed25519 cryptographic signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Storage error: {0}")]
    Storage(#[from] quorum_storage::StorageError),

    #[error("Contract error: {0}")]
    Contract(#[from] quorum_contract::ContractError),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Access denied: requested tier {requested} exceeds authorized tier {authorized}")]
    AccessDenied { requested: u8, authorized: u8 },

    #[error("Agentic state graph error: {0}")]
    GraphError(String),

    #[error("Internal coordinator error: {0}")]
    Internal(String),
}
