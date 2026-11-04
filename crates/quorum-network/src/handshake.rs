use crate::error::NetworkError;

pub const PROTOCOL_PREFIX: &str = "/quorum-rag/1.0.0/contract-";
pub const AGENT_PREFIX: &str = "quorumrag/0.1.0/";

pub fn make_protocol_version(contract_hash_hex: &str) -> String {
    format!("{}{}", PROTOCOL_PREFIX, contract_hash_hex)
}

pub fn make_agent_version(contract_hash_hex: &str) -> String {
    format!("{}{}", AGENT_PREFIX, contract_hash_hex)
}

/// Extracts a 64-character hex contract hash from protocol or agent version string.
pub fn extract_contract_hash(version_str: &str) -> Option<String> {
    if let Some(pos) = version_str.find("contract-") {
        let hash_part = &version_str[pos + "contract-".len()..];
        let hex: String = hash_part.chars().take(64).collect();
        if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hex);
        }
    }
    if let Some(pos) = version_str.rfind('/') {
        let hash_part = &version_str[pos + 1..];
        let hex: String = hash_part.chars().take(64).collect();
        if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hex);
        }
    }
    None
}

/// Constant-time verification of remote peer contract hash against local contract hash.
pub fn verify_peer_contract(
    peer_id: &str,
    local_hash_hex: &str,
    remote_hash_hex: &str,
) -> Result<(), NetworkError> {
    quorum_contract::verify_contract_handshake_hex(local_hash_hex, remote_hash_hex).map_err(|_| {
        NetworkError::ContractMismatch {
            peer_id: peer_id.to_string(),
            local_hex: local_hash_hex.to_string(),
            remote_hex: remote_hash_hex.to_string(),
        }
    })
}
