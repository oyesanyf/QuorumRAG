//! Artemis DFIR P2P Mesh Airgap & Local-Only Security Guardrails.
//!
//! Enforces:
//! 1. Artemis forensic telemetry is STRICTLY LOCAL-ONLY (never leaves host machine).
//! 2. Default configuration is disabled for both local collection and marketplace harvest.
//! 3. All inbound and outbound P2P operations reject or filter `artemis://` URIs and Tier3Restricted records.

use serde::{Deserialize, Serialize};

/// Master configuration for Artemis DFIR forensic telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtemisDfirSettings {
    /// Master opt-in toggle for Artemis DFIR subsystem (default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Enable local host forensic telemetry collection (default: false).
    #[serde(default)]
    pub local_collection_enabled: bool,

    /// Enable inclusion of forensic records in marketplace training harvests (default: false).
    #[serde(default)]
    pub marketplace_harvest_enabled: bool,

    /// Allowed artifact categories for local collection and defensive reasoning.
    #[serde(default = "default_allowed_categories")]
    pub allowed_artifact_categories: Vec<String>,

    /// Interval in minutes for automatic periodic local collection (0 = manual trigger only).
    #[serde(default)]
    pub auto_collection_interval_mins: u32,

    /// Retention period in days for local forensic indexes (default: 30 days).
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,

    /// Automatically scrub CLI secrets and high-entropy environment variables before indexing (default: true).
    #[serde(default = "default_true")]
    pub redact_secrets: bool,

    /// Require keyed BLAKE3 structural normalization before staging marketplace batches (default: true).
    #[serde(default = "default_true")]
    pub normalize_for_harvest: bool,
}

fn default_true() -> bool {
    true
}

fn default_retention_days() -> u32 {
    30
}

pub fn default_allowed_categories() -> Vec<String> {
    vec![
        "process_execution".to_string(),
        "network_connection".to_string(),
        "registry_persistence".to_string(),
        "system_event_log".to_string(),
        "prefetch_amcache_execution".to_string(),
        "service_daemon".to_string(),
    ]
}

pub fn prohibited_categories() -> &'static [&'static str] {
    &[
        "browser_cookies",
        "browser_history_oauth",
        "credential_store",
        "shell_history_raw",
    ]
}

impl Default for ArtemisDfirSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            local_collection_enabled: false,
            marketplace_harvest_enabled: false,
            allowed_artifact_categories: default_allowed_categories(),
            auto_collection_interval_mins: 0,
            retention_days: 30,
            redact_secrets: true,
            normalize_for_harvest: true,
        }
    }
}

/// Iteratively decodes percent-encoded ASCII bytes (`%XX` / `%xx`) up to 3 passes.
/// Safely decodes ASCII byte values without corrupting surrounding UTF-8 sequences.
pub fn percent_decode_ascii_lossy(input: &str) -> String {
    let mut current = input.to_string();
    for _ in 0..3 {
        if !current.contains('%') {
            break;
        }
        let bytes = current.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut changed = false;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let h1 = bytes[i + 1];
                let h2 = bytes[i + 2];
                let val1 = match h1 {
                    b'0'..=b'9' => Some(h1 - b'0'),
                    b'a'..=b'f' => Some(h1 - b'a' + 10),
                    b'A'..=b'F' => Some(h1 - b'A' + 10),
                    _ => None,
                };
                let val2 = match h2 {
                    b'0'..=b'9' => Some(h2 - b'0'),
                    b'a'..=b'f' => Some(h2 - b'a' + 10),
                    b'A'..=b'F' => Some(h2 - b'A' + 10),
                    _ => None,
                };
                if let (Some(v1), Some(v2)) = (val1, val2) {
                    let byte = (v1 << 4) | v2;
                    // Only decode printable/ASCII bytes (0x01..=0x7F) to preserve UTF-8 validity
                    if byte > 0 && byte < 128 {
                        decoded.push(byte);
                        i += 3;
                        changed = true;
                        continue;
                    }
                }
            }
            decoded.push(bytes[i]);
            i += 1;
        }
        if !changed {
            break;
        }
        if let Ok(s) = String::from_utf8(decoded) {
            current = s;
        } else {
            break;
        }
    }
    current
}

/// Returns true if `uri_or_path` references local-only airgapped Artemis telemetry.
#[inline]
pub fn is_artemis_uri(uri_or_path: &str) -> bool {
    let lower = uri_or_path.trim().to_ascii_lowercase();
    if lower.contains("artemis:") || lower.contains("artemis%3a") {
        return true;
    }
    if !lower.contains('%') {
        return false;
    }
    let decoded = percent_decode_ascii_lossy(&lower);
    decoded.contains("artemis:") || decoded.contains("artemis%3a")
}

/// Returns true if query text targets local-only airgapped Artemis data.
#[inline]
pub fn contains_artemis_query(query_text: &str) -> bool {
    let lower = query_text.to_ascii_lowercase();
    if lower.contains("artemis:") || lower.contains("artemis%3a") {
        return true;
    }
    if !lower.contains('%') {
        return false;
    }
    let decoded = percent_decode_ascii_lossy(&lower);
    decoded.contains("artemis:") || decoded.contains("artemis%3a")
}

/// Fail-closed predicate: checks if a candidate chunk DTO must be barred from the P2P mesh.
pub fn is_airgap_restricted_chunk_dto(chunk: &quorum_types::CandidateChunkDto) -> bool {
    if is_artemis_uri(&chunk.file_path) {
        return true;
    }
    if chunk.access_tier >= quorum_types::AccessTier::Tier3Restricted.as_u8() {
        return true;
    }
    false
}

/// Fail-closed predicate: checks if a DocumentChunk must be barred from the P2P mesh.
pub fn is_airgap_restricted_chunk(chunk: &quorum_types::DocumentChunk) -> bool {
    if is_artemis_uri(&chunk.file_path) {
        return true;
    }
    if chunk.access_tier >= quorum_types::AccessTier::Tier3Restricted.as_u8() {
        return true;
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&chunk.metadata_json) {
        if val.get("artemis_dfir").and_then(|v| v.as_bool()) == Some(true) {
            return true;
        }
        if val.get("mesh_sharable").and_then(|v| v.as_bool()) == Some(false) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artemis_settings_defaults() {
        let settings = ArtemisDfirSettings::default();
        assert!(!settings.enabled);
        assert!(!settings.local_collection_enabled);
        assert!(!settings.marketplace_harvest_enabled);
        assert_eq!(settings.auto_collection_interval_mins, 0);
        assert_eq!(settings.retention_days, 30);
        assert!(settings.redact_secrets);
        assert!(settings.normalize_for_harvest);
        assert_eq!(settings.allowed_artifact_categories, default_allowed_categories());
    }

    #[test]
    fn test_is_artemis_uri() {
        assert!(is_artemis_uri("artemis://windows/eventlog/security/4688"));
        assert!(is_artemis_uri("ARTEMIS://macos/unified_log"));
        assert!(is_artemis_uri("file://host/path/artemis://nested"));
        assert!(!is_artemis_uri("C:\\Users\\admin\\file.txt"));
        assert!(!is_artemis_uri("/var/log/syslog"));
        assert!(is_artemis_uri("artemis%3a//windows/eventlog"));
        assert!(is_artemis_uri("artemis%3a\\\\windows\\eventlog"));
        assert!(is_artemis_uri("artemis:\\windows\\eventlog"));
        assert!(is_artemis_uri("artemis%253a//double_encoded"));
    }

    #[test]
    fn test_contains_artemis_query() {
        assert!(contains_artemis_query("select * from artemis://logs"));
        assert!(contains_artemis_query("Show me ARTEMIS://registry/run"));
        assert!(!contains_artemis_query("Show me regular windows event logs"));
        assert!(contains_artemis_query("artemis%3a%5c%5cwindows\\eventlog"));
        assert!(contains_artemis_query("artemis:\\windows\\eventlog"));
        assert!(contains_artemis_query("artemis%3a//windows"));
    }
}
