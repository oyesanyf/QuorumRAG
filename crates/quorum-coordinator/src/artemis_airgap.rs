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

/// Returns true if a `DocumentChunk` carries explicit cloud-drive provenance in `metadata_json`.
pub fn has_cloud_drive_metadata(chunk: &quorum_types::DocumentChunk) -> bool {
    if !chunk.metadata_json.contains("cloud_drive") && !chunk.metadata_json.contains('\\') {
        return false;
    }
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&chunk.metadata_json) {
        if let Some(v) = val.get("cloud_drive") {
            return !v.is_null() && *v != serde_json::Value::Bool(false);
        }
    }
    false
}

/// Fail-closed predicate: checks if a `DocumentChunk` represents Artemis DFIR telemetry
/// via either `artemis://` URI (including percent-encoded forms) or `"artemis_dfir": true`
/// in `metadata_json` (regardless of JSON whitespace).
pub fn is_artemis_dfir_chunk(chunk: &quorum_types::DocumentChunk) -> bool {
    if is_artemis_uri(&chunk.file_path) {
        return true;
    }
    if !chunk.metadata_json.contains("artemis_dfir") && !chunk.metadata_json.contains('\\') {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(&chunk.metadata_json)
        .ok()
        .and_then(|val| val.get("artemis_dfir").and_then(|v| v.as_bool()))
        == Some(true)
}

/// Returns true if `query_text` expresses forensic / Artemis DFIR intent.
pub fn is_forensic_query_text(query_text: &str) -> bool {
    if crate::offline_engine::ForensicQueryIntent::detect(query_text).is_some()
        || contains_artemis_query(query_text)
    {
        return true;
    }
    let ql = query_text.to_ascii_lowercase();
    ql.contains("artemis")
        || ql.contains("antivirus")
        || ql.contains("defender")
        || ql.contains("codeintegrity")
        || ql.contains("eventlog")
        || ql.contains("systemeventlog")
        || ql.contains("malware")
        || ql.contains("trojan")
        || (ql.contains("process") && (ql.contains("block") || ql.contains("blocked")))
}

/// Resolved local host retrieval policy combining outbound peer tier, enabled local-only
/// Cloud Drives, disabled Cloud Drive fail-closed blocks, and Artemis DFIR local collection gating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRetrievalPolicy {
    pub peer_access_tier: u8,
    pub local_access_tier: u8,
    pub allow_artemis_local: bool,
    pub enabled_cloud_drive_prefixes: Vec<(String, u8)>,
    pub disabled_cloud_drive_prefixes: Vec<String>,
}

fn is_windows_drive_prefix_str(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

fn has_unsafe_lexical_parts(candidate: &str, allow_artemis_scheme: bool) -> bool {
    if candidate.len() > 4096 {
        return true;
    }
    let trimmed = candidate.trim();
    if trimmed.is_empty() || candidate != trimmed {
        return true;
    }
    if candidate.chars().any(|c| {
        c == '\0'
            || c.is_control()
            || matches!(
                c,
                '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
            )
    }) {
        return true;
    }

    let lower = candidate.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
        || lower.contains("%25")
        || lower.contains("%3a")
    {
        return true;
    }

    if candidate.contains("..")
        || candidate.split(['/', '\\']).any(|seg| seg == "..")
        || std::path::Path::new(candidate)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return true;
    }

    if allow_artemis_scheme && lower.starts_with("artemis://") {
        let rest = &candidate["artemis://".len()..];
        for seg in rest.split(['/', '\\']) {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg != seg.trim() || seg.ends_with('.') || seg.ends_with(' ') {
                return true;
            }
        }
        return false;
    }

    if is_artemis_uri(candidate) {
        return true;
    }

    if lower.starts_with(r"\\?\unc\") || lower.starts_with("//?/unc/") {
        return true;
    }

    let without_verbatim = if let Some(rest) = candidate.strip_prefix(r"\\?\") {
        if is_windows_drive_prefix_str(rest) {
            rest
        } else {
            return true;
        }
    } else if candidate.starts_with("//?/") {
        return true;
    } else {
        candidate
    };

    if without_verbatim.starts_with(r"\\")
        || without_verbatim.starts_with("//")
        || without_verbatim.starts_with('\\')
    {
        return true;
    }

    for seg in without_verbatim.split(['/', '\\']) {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg != seg.trim() || seg.ends_with('.') || seg.ends_with(' ') {
            return true;
        }
    }

    let has_win_drive = is_windows_drive_prefix_str(without_verbatim);
    for (idx, &b) in without_verbatim.as_bytes().iter().enumerate() {
        if b == b':' && !(idx == 1 && has_win_drive) {
            return true;
        }
    }

    false
}

fn has_unsafe_local_retrieval_path(raw: &str, allow_artemis_scheme: bool) -> bool {
    if has_unsafe_lexical_parts(raw, allow_artemis_scheme) {
        return true;
    }
    if raw.contains('%') {
        let decoded = percent_decode_ascii_lossy(raw);
        if decoded != raw && has_unsafe_lexical_parts(&decoded, allow_artemis_scheme) {
            return true;
        }
    }

    let lower = raw.to_ascii_lowercase();
    if allow_artemis_scheme && lower.starts_with("artemis://") {
        return false;
    }

    let without_verbatim = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    let is_absolute =
        is_windows_drive_prefix_str(without_verbatim) || without_verbatim.starts_with('/');
    if is_absolute && quorum_types::normalize_prefix_for_match(raw).is_err() {
        return true;
    }

    false
}

impl LocalRetrievalPolicy {
    /// Returns true if a local record at `(file_path, access_tier)` is authorized for local retrieval.
    pub fn permits_local_path_and_tier(
        &self,
        file_path: &str,
        access_tier: u8,
        is_artemis: bool,
    ) -> bool {
        if has_unsafe_local_retrieval_path(file_path, is_artemis) {
            return false;
        }

        let best_enabled = self
            .enabled_cloud_drive_prefixes
            .iter()
            .filter(|(prefix, _)| {
                quorum_types::path_matches_prefix(file_path, prefix).unwrap_or(false)
            })
            .max_by_key(|(prefix, tier)| (prefix.len(), *tier));
        let best_disabled = self
            .disabled_cloud_drive_prefixes
            .iter()
            .filter(|prefix| quorum_types::path_matches_prefix(file_path, prefix).unwrap_or(false))
            .max_by_key(|prefix| prefix.len());

        let best_enabled_len = best_enabled.map(|(p, _)| p.len()).unwrap_or(0);
        let best_disabled_len = best_disabled.map(|p| p.len()).unwrap_or(0);
        if best_disabled_len > 0 && best_disabled_len >= best_enabled_len {
            return false;
        }

        if is_artemis {
            return self.allow_artemis_local && access_tier <= self.local_access_tier;
        }

        if let Some((_, drive_tier)) = best_enabled {
            return access_tier <= *drive_tier && access_tier <= self.local_access_tier;
        }
        if access_tier <= self.peer_access_tier {
            return true;
        }
        if access_tier > self.local_access_tier {
            return false;
        }
        false
    }

    /// Returns true if a local `DocumentChunk` is permitted by this local retrieval policy.
    pub fn permits_local_chunk(&self, chunk: &quorum_types::DocumentChunk) -> bool {
        self.permits_local_path_and_tier(
            &chunk.file_path,
            chunk.access_tier,
            is_artemis_dfir_chunk(chunk),
        )
    }

    /// Returns true if a `ScoredChunk` (local or remote) is permitted by this policy.
    pub fn permits_local_scored_chunk(&self, scored: &quorum_types::ScoredChunk) -> bool {
        if scored.is_remote {
            return !is_artemis_dfir_chunk(&scored.chunk)
                && scored.chunk.access_tier <= self.peer_access_tier;
        }
        self.permits_local_chunk(&scored.chunk)
    }

    /// Returns true if a local AtlasKV `KgTripleRecord` is permitted by this policy.
    pub fn permits_local_triple(&self, triple: &quorum_atlaskv::KgTripleRecord) -> bool {
        self.permits_local_path_and_tier(
            &triple.file_path,
            triple.access_tier,
            is_artemis_uri(&triple.file_path),
        )
    }
}

/// Computes `LocalRetrievalPolicy` from persisted settings without mutating outbound `peer_access_tier`.
pub fn resolve_local_retrieval_policy(
    settings: &crate::dlp_mesh::PersistedDaemonSettings,
    peer_access_tier: u8,
    query_texts: &[&str],
) -> LocalRetrievalPolicy {
    let peer_tier = peer_access_tier.min(3);
    let is_forensic_q = query_texts.iter().any(|q| is_forensic_query_text(q));
    let allow_artemis_local =
        settings.artemis.enabled && (settings.artemis.local_collection_enabled || is_forensic_q);

    let mut max_cloud_tier: Option<u8> = None;
    let mut enabled_cloud_drive_prefixes: Vec<(String, u8)> = Vec::new();
    let mut disabled_cloud_drive_prefixes: Vec<String> = Vec::new();
    for drive in &settings.cloud_drives.drives {
        if !drive.enabled {
            for raw_path in drive.root_path.iter().chain(drive.custom_paths.iter()) {
                if let Ok(norm) = quorum_types::normalize_prefix_for_match(raw_path) {
                    disabled_cloud_drive_prefixes.push(norm);
                }
            }
            continue;
        }
        let Ok(tier) = quorum_types::AccessTier::from_u8(drive.access_tier) else {
            for raw_path in drive.root_path.iter().chain(drive.custom_paths.iter()) {
                if let Ok(norm) = quorum_types::normalize_prefix_for_match(raw_path) {
                    disabled_cloud_drive_prefixes.push(norm);
                }
            }
            continue;
        };
        let t = tier.as_u8();
        max_cloud_tier = Some(max_cloud_tier.unwrap_or(0).max(t));
        for raw_path in drive.root_path.iter().chain(drive.custom_paths.iter()) {
            if let Ok(norm) = quorum_types::normalize_prefix_for_match(raw_path) {
                enabled_cloud_drive_prefixes.push((norm, t));
            }
        }
    }

    let local_access_tier =
        peer_tier
            .max(max_cloud_tier.unwrap_or(0))
            .max(if allow_artemis_local {
                quorum_types::AccessTier::Tier3Restricted.as_u8()
            } else {
                0
            });

    LocalRetrievalPolicy {
        peer_access_tier: peer_tier,
        local_access_tier,
        allow_artemis_local,
        enabled_cloud_drive_prefixes,
        disabled_cloud_drive_prefixes,
    }
}

/// Returns true if the forensics subsystem is explicitly enabled in persistent daemon settings.
pub fn is_forensics_enabled() -> bool {
    crate::dlp_mesh::global_mesh_dlp_controller()
        .get_settings()
        .artemis
        .enabled
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
        assert_eq!(
            settings.allowed_artifact_categories,
            default_allowed_categories()
        );
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
        assert!(!contains_artemis_query(
            "Show me regular windows event logs"
        ));
        assert!(contains_artemis_query("artemis%3a%5c%5cwindows\\eventlog"));
        assert!(contains_artemis_query("artemis:\\windows\\eventlog"));
        assert!(contains_artemis_query("artemis%3a//windows"));
    }
}
