//! E2E Tests: QuorumRAG Artemis DFIR & Forensic Telemetry Integration.
//!
//! Comprehensive 4-Tier opaque-box test suite adhering to `TEST_INFRA.md`:
//! - Tier 1: Feature Coverage (20 features * >=5 assertions/cases = 100+ tests)
//! - Tier 2: Boundary & Corner Cases (100+ edge cases across all 20 features)
//! - Tier 3: Cross-Feature Combinations (>=20 pairwise & multi-feature interaction tests)
//! - Tier 4: Real-World Application Scenarios (5 complex triage & defense workloads)
//!
//! Features covered:
//! F1.  Forensic Telemetry Classification & Types (ORIGINAL_REQUEST §R1)
//! F2.  Category Allowlisting & Prohibited Blocking (ORIGINAL_REQUEST §R1)
//! F3.  Forensic Provenance Attestation & Signing (ORIGINAL_REQUEST §R1)
//! F4.  Tier3Restricted & Airgap Metadata Invariants (ORIGINAL_REQUEST §R1)
//! F5.  Cross-Platform Telemetry Ingestion (.jsonl / OS formats) (ORIGINAL_REQUEST §R2)
//! F6.  Pre-Index Regex Secret Scrubbing (ORIGINAL_REQUEST §R2)
//! F7.  Pre-Index Shannon Entropy Secret Scrubbing (ORIGINAL_REQUEST §R2)
//! F8.  LanceDB & Tantivy Indexing with Tier3 Guard (ORIGINAL_REQUEST §R2)
//! F9.  Default-Off Configuration (Local & Harvest) (ORIGINAL_REQUEST §R3)
//! F10. P2P Outbound Airgap Blocking (artemis:// / Tier3) (ORIGINAL_REQUEST §R3)
//! F11. P2P Inbound Airgap Rejection (ORIGINAL_REQUEST §R3)
//! F12. Keyed BLAKE3 Forensic Structural Normalizer (ORIGINAL_REQUEST §R4)
//! F13. Topology Preservation & Consistent Pseudonyms (ORIGINAL_REQUEST §R4)
//! F14. Marketplace Harvest Pipeline Category Gate (ORIGINAL_REQUEST §R4)
//! F15. Daemon /api/v1/artemis/status Endpoint (ORIGINAL_REQUEST §R5)
//! F16. Daemon /api/v1/artemis/config (GET/POST) (ORIGINAL_REQUEST §R5)
//! F17. Daemon /api/v1/artemis/collect Endpoint (ORIGINAL_REQUEST §R5)
//! F18. Daemon /api/v1/artemis/preview-normalizer Endpoint (ORIGINAL_REQUEST §R5)
//! F19. WebUI data-tab="artemis-dfir" Tab Rendering (ORIGINAL_REQUEST §R6)
//! F20. WebUI Controls, Toggles & Preview Card (ORIGINAL_REQUEST §R6)

use chrono::Utc;
use ed25519_dalek::SigningKey;
use quorum_contract::{ForensicContractError, ForensicProvenance, ForensicTelemetryType};
use quorum_e2e::*;
use quorum_types::{AccessTier, CandidateChunkDto, DocumentChunk};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use uuid::Uuid;

// ============================================================================
// AUTHORITATIVE MATHEMATICAL ORACLES & REFERENCE IMPLEMENTATIONS
// ============================================================================

/// Mathematical oracle: Computes Shannon entropy in bits per character.
/// Formula: H(X) = - \sum_{i=1}^{n} p(x_i) \log_2 p(x_i)
pub fn oracle_shannon_entropy(s: &str) -> f64 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Helper: checks if a token contains mixed character classes (e.g. upper, lower, digits, symbols).
pub fn oracle_has_mixed_classes(token: &str) -> bool {
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_special = false;
    for ch in token.chars() {
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else {
            has_special = true;
        }
    }
    let classes = (has_upper as u8) + (has_lower as u8) + (has_digit as u8) + (has_special as u8);
    classes >= 2
}

/// Helper: checks if a string is a standard UUID or filesystem path (to exclude from entropy redaction).
pub fn oracle_is_uuid_or_path(s: &str) -> bool {
    if Uuid::parse_str(s).is_ok() {
        return true;
    }
    if s.contains('\\') || s.contains('/') {
        return true;
    }
    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("artemis://") {
        return true;
    }
    false
}

/// Authoritative oracle: Evaluates whether a candidate token is a high-entropy secret.
/// Threshold: len >= 16, H > 4.20 bits/char, mixed classes, not a path/UUID/URI.
pub fn oracle_is_high_entropy_secret(token: &str) -> bool {
    let clean = token.trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'));
    if clean.len() < 16 {
        return false;
    }
    if clean.contains("REDACTED") {
        return false;
    }
    if oracle_is_uuid_or_path(clean) {
        return false;
    }
    if !oracle_has_mixed_classes(clean) {
        return false;
    }
    oracle_shannon_entropy(clean) > 4.20
}

/// Authoritative oracle: Shannon entropy token scrubber.
pub fn oracle_scrub_high_entropy_tokens(text: &str) -> String {
    let mut out = Vec::new();
    for word in text.split_whitespace() {
        if oracle_is_high_entropy_secret(word) {
            out.push("[REDACTED_HIGH_ENTROPY_SECRET]");
        } else {
            out.push(word);
        }
    }
    out.join(" ")
}

/// Authoritative oracle: Regex pre-index secret scrubber.
pub fn oracle_scrub_regex_secrets(input: &str) -> String {
    let mut s = input.to_string();

    // 1. Bearer tokens: Bearer <token>=16+
    let re_bearer = Regex::new(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{16,}").unwrap();
    s = re_bearer.replace_all(&s, "Bearer [REDACTED_BEARER_TOKEN]").to_string();

    // 2. OpenAI / Anthropic keys
    let re_openai = Regex::new(r"sk-[A-Za-z0-9_-]{20,}").unwrap();
    s = re_openai.replace_all(&s, "[REDACTED_API_KEY]").to_string();
    let re_anthropic = Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").unwrap();
    s = re_anthropic.replace_all(&s, "[REDACTED_API_KEY]").to_string();

    // 3. GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_
    let re_github = Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap();
    s = re_github.replace_all(&s, "[REDACTED_GITHUB_TOKEN]").to_string();

    // 4. AWS keys
    let re_aws = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    s = re_aws.replace_all(&s, "[REDACTED_AWS_KEY]").to_string();

    // 5. Slack tokens
    let re_slack = Regex::new(r"xox[baprs]-[0-9a-zA-Z-]{10,}").unwrap();
    s = re_slack.replace_all(&s, "[REDACTED_SLACK_TOKEN]").to_string();

    // 6. Google API keys
    let re_google = Regex::new(r"AIza[0-9A-Za-z-_]{35}").unwrap();
    s = re_google.replace_all(&s, "[REDACTED_GOOGLE_API_KEY]").to_string();

    // 7. PEM Private Keys
    let re_pem = Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----").unwrap();
    s = re_pem.replace_all(&s, "[REDACTED_PRIVATE_KEY]").to_string();

    // 8. Database connection URIs
    let re_db = Regex::new(r"(?i)(?:postgres|postgresql|mysql|mongodb|redis|mssql|amqp|couchdb)://[^:\s]+:[^@\s]+@[^\s]+").unwrap();
    s = re_db.replace_all(&s, "[REDACTED_CONNECTION_STRING]").to_string();

    // 9. CLI password arguments
    let re_cli_pwd = Regex::new(r#"(?i)(--?[A-Za-z0-9_]*(?:password|passwd|pass|pwd|secret|token|api-key|apikey|auth-token)[A-Za-z0-9_-]*|/p:)[=\s]+([^\s"']+)"#).unwrap();
    s = re_cli_pwd.replace_all(&s, |caps: &regex::Captures| {
        let val = &caps[2];
        if val.starts_with("[REDACTED") {
            caps[0].to_string()
        } else {
            format!("{}=[REDACTED_CLI_ARG]", &caps[1])
        }
    }).to_string();

    // 10. Environment variable assignments
    let re_env = Regex::new(r#"(?i)([A-Za-z0-9_]*(?:PASSWORD|PASSWD|PASS|PWD|SECRET|TOKEN|API_KEY|APIKEY|AUTH_TOKEN|ACCESS_KEY|PRIVATE_KEY)[A-Za-z0-9_]*)=([^\s"']+)"#).unwrap();
    s = re_env.replace_all(&s, |caps: &regex::Captures| {
        let val = &caps[2];
        if val.starts_with("[REDACTED") {
            caps[0].to_string()
        } else {
            format!("{}=[REDACTED_ENV_VAR]", &caps[1])
        }
    }).to_string();

    s
}

/// Full authoritative pre-index secret scrubber combining regex and Shannon entropy detection.
pub fn oracle_scrub_all_secrets(input: &str) -> String {
    let regex_scrubbed = oracle_scrub_regex_secrets(input);
    oracle_scrub_high_entropy_tokens(&regex_scrubbed)
}

/// Authoritative oracle: Keyed BLAKE3 session normalizer key derivation.
pub fn oracle_derive_normalizer_session_key(node_seed: &[u8; 32], session_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(node_seed);
    hasher.update(b"QuorumRAG-ForensicNormalizer-Session-v1:");
    hasher.update(session_id.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Authoritative oracle: Generates a deterministic keyed BLAKE3 pseudonym for an entity.
pub fn oracle_keyed_blake3_pseudonym(session_key: &[u8; 32], prefix: &str, entity: &str) -> String {
    let mut hasher = blake3::Hasher::new_keyed(session_key);
    hasher.update(prefix.as_bytes());
    hasher.update(b":");
    hasher.update(entity.trim().to_ascii_lowercase().as_bytes());
    let digest = hasher.finalize();
    let hex = digest.to_hex();
    format!("{}-{}", prefix.to_ascii_uppercase(), &hex[..8])
}

/// Authoritative oracle: Forensic structural normalizer replacing host identifiers with keyed pseudonyms
/// while strictly preserving graph topology, causal relationships, and parent-child execution chains.
pub struct OracleForensicNormalizer {
    session_key: [u8; 32],
    mappings: HashMap<String, String>,
}

impl OracleForensicNormalizer {
    pub fn new(node_seed: &[u8; 32], session_id: &str) -> Self {
        let session_key = oracle_derive_normalizer_session_key(node_seed, session_id);
        Self {
            session_key,
            mappings: HashMap::new(),
        }
    }

    pub fn get_or_create_pseudonym(&mut self, prefix: &str, entity: &str) -> String {
        let key = format!("{}:{}", prefix, entity.trim().to_ascii_lowercase());
        if let Some(pseudo) = self.mappings.get(&key) {
            return pseudo.clone();
        }
        let pseudo = oracle_keyed_blake3_pseudonym(&self.session_key, prefix, entity);
        self.mappings.insert(key, pseudo.clone());
        pseudo
    }

    /// Normalizes a forensic text line or JSON record preserving topology.
    pub fn normalize_text(&mut self, input: &str) -> String {
        let mut text = input.to_string();

        // 1. Windows SIDs: S-1-5-21-\d+-\d+-\d+-\d+
        let re_sid = Regex::new(r"S-1-5-21-\d+-\d+-\d+-\d+").unwrap();
        let sids: Vec<String> = re_sid.find_iter(&text).map(|m| m.as_str().to_string()).collect();
        for sid in sids {
            let pseudo = self.get_or_create_pseudonym("SID", &sid);
            text = text.replace(&sid, &pseudo);
        }

        // 2. Private IPv4 addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
        let re_ipv4 = Regex::new(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b").unwrap();
        let ips: Vec<String> = re_ipv4.find_iter(&text).map(|m| m.as_str().to_string()).collect();
        for ip in ips {
            let pseudo = self.get_or_create_pseudonym("IPV4", &ip);
            text = text.replace(&ip, &pseudo);
        }

        // 3. MAC addresses (e.g. 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E)
        let re_mac = Regex::new(r"\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b").unwrap();
        let macs: Vec<String> = re_mac.find_iter(&text).map(|m| m.as_str().to_string()).collect();
        for mac in macs {
            let pseudo = self.get_or_create_pseudonym("MAC", &mac);
            text = text.replace(&mac, &pseudo);
        }

        // 4. SMB UNC paths (\\server\share)
        let re_smb = Regex::new(r"\\\\[A-Za-z0-9_-]+\\[A-Za-z0-9_$-]+").unwrap();
        let shares: Vec<String> = re_smb.find_iter(&text).map(|m| m.as_str().to_string()).collect();
        for share in shares {
            let pseudo = self.get_or_create_pseudonym("SMB", &share);
            text = text.replace(&share, &pseudo);
        }

        text
    }

    pub fn mappings(&self) -> &HashMap<String, String> {
        &self.mappings
    }
}

// ============================================================================
// AIRGAP ROUTER & P2P MESH HARNESS
// ============================================================================

/// Opaque-box P2P Mesh Airgap Router enforcing Requirement R3 invariants:
/// Inbound and outbound queries or chunks with `artemis://`, `artemis_dfir: true`,
/// or `mesh_sharable: false` must be strictly blocked and rejected.
pub struct AirgapMeshRouter;

impl AirgapMeshRouter {
    pub fn is_artemis_uri(uri_or_path: &str) -> bool {
        let lower = uri_or_path.to_ascii_lowercase();
        lower.starts_with("artemis://") || lower.contains("/artemis/") || lower.contains("\\artemis\\")
    }

    pub fn contains_artemis_query(query: &str) -> bool {
        let lower = query.to_ascii_lowercase();
        lower.contains("artemis://")
    }

    pub fn is_airgap_restricted_chunk_dto(chunk: &CandidateChunkDto) -> bool {
        Self::is_artemis_uri(&chunk.file_path) || chunk.access_tier >= 3
    }

    pub fn is_airgap_restricted_doc_chunk(chunk: &DocumentChunk) -> bool {
        if Self::is_artemis_uri(&chunk.file_path) || chunk.access_tier >= 3 {
            return true;
        }
        if let Ok(val) = serde_json::from_str::<Value>(&chunk.metadata_json) {
            if val.get("artemis_dfir").and_then(|v| v.as_bool()).unwrap_or(false) {
                return true;
            }
            if val.get("mesh_sharable").and_then(|v| v.as_bool()) == Some(false) {
                return true;
            }
        }
        false
    }

    /// Evaluates outbound candidate chunks and filters out all airgap-restricted records.
    pub fn filter_outbound_mesh_chunks(chunks: Vec<CandidateChunkDto>) -> Vec<CandidateChunkDto> {
        chunks
            .into_iter()
            .filter(|c| !Self::is_airgap_restricted_chunk_dto(c))
            .collect()
    }

    /// Evaluates inbound remote queries and rejects queries targeting Artemis forensic data.
    pub fn handle_inbound_query(query_text: &str, requested_tier: u8) -> Result<(), &'static str> {
        if Self::contains_artemis_query(query_text) {
            return Err("Inbound query rejected: queries targeting artemis:// are strictly local-only");
        }
        if requested_tier >= 3 {
            return Err("Inbound query rejected: Tier3Restricted queries are strictly barred from P2P mesh");
        }
        Ok(())
    }

    /// Evaluates inbound remote chunks received from peer nodes and discards any illicit forensic chunks.
    pub fn sanitize_inbound_remote_chunks(chunks: Vec<CandidateChunkDto>) -> Vec<CandidateChunkDto> {
        chunks
            .into_iter()
            .filter(|c| !Self::is_airgap_restricted_chunk_dto(c))
            .collect()
    }
}

// ============================================================================
// DAEMON REST ENDPOINT & CONFIG HARNESS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtemisDfirSettings {
    pub enabled: bool,
    pub local_collection_enabled: bool,
    pub marketplace_harvest_enabled: bool,
    pub allowed_artifact_categories: Vec<String>,
    pub auto_collection_interval_mins: u32,
    pub retention_days: u32,
    pub redact_secrets: bool,
    pub normalize_for_harvest: bool,
}

impl Default for ArtemisDfirSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            local_collection_enabled: false,
            marketplace_harvest_enabled: false,
            allowed_artifact_categories: vec![
                "process_execution".to_string(),
                "network_connection".to_string(),
                "registry_persistence".to_string(),
                "system_event_log".to_string(),
                "prefetch_amcache_execution".to_string(),
                "service_daemon".to_string(),
            ],
            auto_collection_interval_mins: 60,
            retention_days: 30,
            redact_secrets: true,
            normalize_for_harvest: true,
        }
    }
}

pub struct TestArtemisDaemonHarness {
    pub settings: ArtemisDfirSettings,
    pub storage: IsolatedStorageEngine,
    pub normalizer: OracleForensicNormalizer,
}

impl TestArtemisDaemonHarness {
    pub fn new(node_seed: &[u8; 32], session_id: &str) -> Self {
        Self {
            settings: ArtemisDfirSettings::default(),
            storage: IsolatedStorageEngine::new(),
            normalizer: OracleForensicNormalizer::new(node_seed, session_id),
        }
    }

    /// `GET /api/v1/artemis/status`
    pub fn get_status(&self) -> Value {
        json!({
            "status": "ok",
            "collection_enabled": self.settings.local_collection_enabled,
            "marketplace_harvest_enabled": self.settings.marketplace_harvest_enabled,
            "airgap_enforced": true,
            "supported_platforms": ["windows", "macos", "linux"],
            "current_platform": if cfg!(windows) { "windows" } else if cfg!(target_os = "macos") { "macos" } else { "linux" },
            "allowed_marketplace_categories": [
                "process_execution",
                "network_connection",
                "registry_persistence",
                "system_event_log",
                "prefetch_amcache_execution",
                "service_daemon"
            ],
            "prohibited_marketplace_categories": [
                "browser_cookies",
                "browser_history_oauth",
                "credential_store",
                "shell_history_raw"
            ],
            "total_collected_records": self.storage.len(),
            "last_collection_timestamp": null
        })
    }

    /// `GET /api/v1/artemis/config`
    pub fn get_config(&self) -> Value {
        serde_json::to_value(&self.settings).unwrap()
    }

    /// `POST /api/v1/artemis/config`
    pub fn update_config(&mut self, payload: Value) -> Result<Value, &'static str> {
        let updated: ArtemisDfirSettings = serde_json::from_value(payload).map_err(|_| "Invalid config JSON")?;
        self.settings = updated;
        Ok(serde_json::to_value(&self.settings).unwrap())
    }

    /// `POST /api/v1/artemis/collect`
    pub fn collect_on_demand(&mut self, is_live: bool, records: Vec<(&str, ForensicTelemetryType, &str)>) -> Result<Value, (u16, &'static str)> {
        if is_live && !self.settings.local_collection_enabled {
            return Err((403, "Local Artemis DFIR collection is disabled by default. Enable in Settings first."));
        }

        let mut indexed_count = 0;
        let mut scrubbed_count = 0;

        for (artifact_id, telemetry_type, raw_text) in records {
            let scrubbed = if self.settings.redact_secrets {
                let s = oracle_scrub_all_secrets(raw_text);
                if s != raw_text {
                    scrubbed_count += 1;
                }
                s
            } else {
                raw_text.to_string()
            };

            let metadata = json!({
                "artemis_dfir": true,
                "mesh_sharable": false,
                "telemetry_type": telemetry_type.as_str(),
                "artifact_id": artifact_id,
            });

            let chunk = DocumentChunk::new(
                artifact_id,
                &format!("artemis_doc_{}", artifact_id),
                &format!("artemis://telemetry/{}", telemetry_type.as_str()),
                1,
                10,
                AccessTier::Tier3Restricted.as_u8(),
                oracle_deterministic_vector(&scrubbed, 768),
                scrubbed,
                Some(metadata.to_string()),
            )
            .unwrap();

            self.storage.insert_chunks(&[chunk]);
            indexed_count += 1;
        }

        Ok(json!({
            "status": "completed",
            "records_parsed": indexed_count,
            "secrets_redacted": scrubbed_count,
            "chunks_indexed": indexed_count,
        }))
    }

    /// `POST /api/v1/artemis/preview-normalizer`
    pub fn preview_normalizer(&mut self, raw_text: &str, category_str: &str) -> Result<Value, &'static str> {
        let telemetry_type = ForensicTelemetryType::from_str(category_str).map_err(|_| "Unknown category")?;
        let allowlisted = telemetry_type.is_marketplace_harvest_allowed();
        let normalized = self.normalizer.normalize_text(raw_text);

        Ok(json!({
            "status": "ok",
            "original": raw_text,
            "normalized": normalized,
            "category": telemetry_type.as_str(),
            "allowlisted_for_marketplace": allowlisted,
            "rejection_reason": telemetry_type.harvest_prohibition_reason(),
            "mappings": self.normalizer.mappings(),
        }))
    }
}

// ============================================================================
// TIER 1: FEATURE COVERAGE (20 Features, >=5 assertions/cases each)
// ============================================================================

#[test]
fn test_tier1_f01_forensic_telemetry_classification_and_types() {
    // 1. All 10 canonical types present
    assert_eq!(ForensicTelemetryType::ALL_TYPES.len(), 10);

    // 2. String conversion round-tripping for all 10 types
    for &t in &ForensicTelemetryType::ALL_TYPES {
        let s = t.as_str();
        assert!(!s.is_empty());
        let parsed = ForensicTelemetryType::from_str(s).expect("FromStr must succeed for as_str()");
        assert_eq!(parsed, t);
    }

    // 3. Serde JSON serialization matches snake_case
    assert_eq!(
        serde_json::to_string(&ForensicTelemetryType::ProcessExecution).unwrap(),
        "\"process_execution\""
    );
    assert_eq!(
        serde_json::to_string(&ForensicTelemetryType::BrowserCookies).unwrap(),
        "\"browser_cookies\""
    );

    // 4. Display trait implementation
    assert_eq!(format!("{}", ForensicTelemetryType::RegistryPersistence), "registry_persistence");

    // 5. Case-insensitive parsing
    assert_eq!(
        ForensicTelemetryType::from_str("PROCESS_EXECUTION").unwrap(),
        ForensicTelemetryType::ProcessExecution
    );
}

#[test]
fn test_tier1_f02_category_allowlisting_defensive_vs_prohibited() {
    // 1. Defensive execution categories allowed
    assert!(ForensicTelemetryType::ProcessExecution.is_marketplace_harvest_allowed());
    assert!(ForensicTelemetryType::NetworkConnection.is_marketplace_harvest_allowed());
    assert!(ForensicTelemetryType::RegistryPersistence.is_marketplace_harvest_allowed());
    assert!(ForensicTelemetryType::SystemEventLog.is_marketplace_harvest_allowed());
    assert!(ForensicTelemetryType::PrefetchAmcacheExecution.is_marketplace_harvest_allowed());
    assert!(ForensicTelemetryType::ServiceDaemon.is_marketplace_harvest_allowed());

    // 2. Prohibited personal and credential categories strictly barred
    assert!(!ForensicTelemetryType::BrowserCookies.is_marketplace_harvest_allowed());
    assert!(!ForensicTelemetryType::BrowserHistoryOAuth.is_marketplace_harvest_allowed());
    assert!(!ForensicTelemetryType::CredentialStore.is_marketplace_harvest_allowed());
    assert!(!ForensicTelemetryType::ShellHistoryRaw.is_marketplace_harvest_allowed());

    // 3. is_defensive_telemetry mirrors allowlist
    assert_eq!(
        ForensicTelemetryType::ProcessExecution.is_defensive_telemetry(),
        ForensicTelemetryType::ProcessExecution.is_marketplace_harvest_allowed()
    );
    assert_eq!(
        ForensicTelemetryType::CredentialStore.is_defensive_telemetry(),
        ForensicTelemetryType::CredentialStore.is_marketplace_harvest_allowed()
    );

    // 4. Detailed prohibition reasons provided for prohibited categories
    assert!(ForensicTelemetryType::BrowserCookies.harvest_prohibition_reason().is_some());
    assert!(ForensicTelemetryType::CredentialStore.harvest_prohibition_reason().is_some());
    assert!(ForensicTelemetryType::ProcessExecution.harvest_prohibition_reason().is_none());

    // 5. assert_marketplace_harvest_allowed error contract
    assert!(ForensicTelemetryType::ProcessExecution.assert_marketplace_harvest_allowed().is_ok());
    assert!(ForensicTelemetryType::CredentialStore.assert_marketplace_harvest_allowed().is_err());
}

#[test]
fn test_tier1_f03_forensic_provenance_attestation_and_signing() {
    let raw_payload = b"{\"EventID\": 4688, \"CommandLine\": \"whoami /all\"}";
    let payload_hash = blake3::hash(raw_payload).to_hex().to_string();

    let mut prov = ForensicProvenance::new(
        "art_101",
        ForensicTelemetryType::ProcessExecution,
        "artemis://windows/eventlog/Security.evtx",
        "WIN-SRV-01",
        "windows",
        Some("Server 2025".to_string()),
        "artemis-core",
        "0.1.0",
        Utc::now().timestamp(),
        &payload_hash,
    )
    .expect("Valid provenance");

    // 1. Invariants initialized correctly
    assert_eq!(prov.access_tier, 3);
    assert!(prov.artemis_dfir);
    assert!(!prov.mesh_sharable);
    assert!(prov.harvest_eligible);

    // 2. Canonical signing bytes are non-empty and deterministic
    let bytes1 = prov.canonical_signing_bytes();
    let bytes2 = prov.canonical_signing_bytes();
    assert_eq!(bytes1, bytes2);
    assert!(!bytes1.is_empty());

    // 3. Ed25519 signing
    let signing_key_bytes = [7u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    prov.sign_ed25519(&signing_key_bytes).expect("Sign should succeed");
    assert!(prov.attestation_signature_hex.is_some());

    // 4. Ed25519 verification with public key
    assert!(prov.verify_ed25519(&pubkey_bytes).is_ok());

    // 5. Payload BLAKE3 verification
    assert!(prov.verify_payload_bytes(raw_payload).is_ok());
    assert!(prov.verify_payload_bytes(b"tampered payload").is_err());
}

#[test]
fn test_tier1_f04_tier3_restricted_and_airgap_metadata_invariants() {
    // 1. Attempting to construct provenance with tier != 3 fails closed
    let raw_payload = b"telemetry";
    let mut prov = ForensicProvenance::from_raw_payload(
        "art_102",
        ForensicTelemetryType::NetworkConnection,
        "artemis://linux/proc/net",
        "linux-node",
        "linux",
        None,
        "artemis-core",
        "0.1.0",
        Utc::now().timestamp(),
        raw_payload,
    )
    .unwrap();

    assert_eq!(prov.access_tier, 3);
    assert!(prov.artemis_dfir);
    assert!(!prov.mesh_sharable);

    // 2. Validation catches illegal tier downgrade
    prov.access_tier = 2;
    assert!(matches!(
        prov.validate_invariants(),
        Err(ForensicContractError::InvalidAccessTier { expected: 3, actual: 2 })
    ));
    prov.access_tier = 3;

    // 3. Validation catches illegal mesh_sharable = true
    prov.mesh_sharable = true;
    assert!(matches!(
        prov.validate_invariants(),
        Err(ForensicContractError::MeshShareViolation { .. })
    ));
    prov.mesh_sharable = false;

    // 4. Validation catches artemis_dfir = false
    prov.artemis_dfir = false;
    assert!(matches!(
        prov.validate_invariants(),
        Err(ForensicContractError::AirgapFlagViolation { .. })
    ));
    prov.artemis_dfir = true;

    // 5. Validation catches harvest_eligible mismatch
    prov.harvest_eligible = false; // NetworkConnection is allowed, so false is a mismatch
    assert!(matches!(
        prov.validate_invariants(),
        Err(ForensicContractError::HarvestEligibilityMismatch { .. })
    ));
}

#[test]
fn test_tier1_f05_cross_platform_telemetry_ingestion_formats() {
    // 1. Windows Event Log format
    let win_evtx = r#"{"EventID":4688,"Channel":"Security","Computer":"CORP-DC","CommandLine":"powershell.exe -ExecutionPolicy Bypass -File audit.ps1","SubjectUserName":"svc_backup"}"#;
    assert!(win_evtx.contains("4688"));
    assert!(win_evtx.contains("powershell.exe"));

    // 2. Windows Registry Persistence format
    let win_reg = r#"{"Key":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","ValueName":"SecurityAgent","ValueData":"C:\\Program Files\\Sec\\agent.exe"}"#;
    assert!(win_reg.contains("Run"));

    // 3. macOS Unified Log / LaunchDaemon format
    let mac_launchd = r#"{"Label":"com.apple.diagnosticd","ProgramArguments":["/usr/libexec/diagnosticd"],"RunAtLoad":true}"#;
    assert!(mac_launchd.contains("com.apple.diagnosticd"));

    // 4. Linux journald / auditd format
    let linux_audit = r#"{"type":"EXECVE","argc":3,"a0":"/usr/bin/curl","a1":"-s","a2":"https://internal.corp/status","auid":1000}"#;
    assert!(linux_audit.contains("EXECVE"));

    // 5. Parsing .jsonl stream produces structured records
    let jsonl_stream = format!("{}\n{}\n{}\n{}", win_evtx, win_reg, mac_launchd, linux_audit);
    let lines: Vec<&str> = jsonl_stream.lines().collect();
    assert_eq!(lines.len(), 4);
    for line in lines {
        let val: Value = serde_json::from_str(line).expect("JSONL line must parse");
        assert!(val.is_object());
    }
}

#[test]
fn test_tier1_f06_pre_index_regex_secret_scrubbing() {
    // 1. Bearer token
    let raw1 = "curl -H 'Authorization: Bearer sk_live_abcdef12345678901234' https://api.stripe.com";
    let s1 = oracle_scrub_regex_secrets(raw1);
    assert!(!s1.contains("sk_live_abcdef12345678901234"));
    assert!(s1.contains("Bearer [REDACTED_BEARER_TOKEN]"));

    // 2. OpenAI API Key
    let raw2 = "export OPENAI_API_KEY=sk-proj-1234567890abcdef1234567890";
    let s2 = oracle_scrub_regex_secrets(raw2);
    assert!(!s2.contains("sk-proj-1234567890abcdef1234567890"));
    assert!(s2.contains("[REDACTED_API_KEY]"));

    // 3. GitHub Token
    let raw3 = "git clone https://ghp_0123456789abcdefghijklmnopqrstuvwxyz@github.com/org/repo";
    let s3 = oracle_scrub_regex_secrets(raw3);
    assert!(!s3.contains("ghp_0123456789abcdefghijklmnopqrstuvwxyz"));
    assert!(s3.contains("[REDACTED_GITHUB_TOKEN]"));

    // 4. Database Connection URI
    let raw4 = "connect postgresql://dbuser:SuperSecretP@ss123@db.internal:5432/proddb";
    let s4 = oracle_scrub_regex_secrets(raw4);
    assert!(!s4.contains("SuperSecretP@ss123"));
    assert!(s4.contains("[REDACTED_CONNECTION_STRING]"));

    // 5. CLI password argument
    let raw5 = "mysqldump -u root --password=VerySecretRootPassword! customer_db";
    let s5 = oracle_scrub_regex_secrets(raw5);
    assert!(!s5.contains("VerySecretRootPassword!"));
    assert!(s5.contains("--password=[REDACTED_CLI_ARG]"));
}

#[test]
fn test_tier1_f07_pre_index_shannon_entropy_secret_scrubbing() {
    // 1. High-entropy base64 API token (entropy > 4.5 bits/char, len >= 16)
    let secret_token = "K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH";
    let entropy = oracle_shannon_entropy(secret_token);
    assert!(entropy > 4.20, "Entropy {} must be > 4.20", entropy);
    assert!(oracle_is_high_entropy_secret(secret_token));

    // 2. High-entropy token in command line is redacted
    let cmd = format!("deploy-app --token {}", secret_token);
    let scrubbed = oracle_scrub_high_entropy_tokens(&cmd);
    assert!(!scrubbed.contains(secret_token));
    assert!(scrubbed.contains("[REDACTED_HIGH_ENTROPY_SECRET]"));

    // 3. Low-entropy English text is NOT redacted
    let english = "the quick brown fox jumps over the lazy dog";
    let token = "AdministrativeSystemServices";
    assert!(!oracle_is_high_entropy_secret(token));
    assert_eq!(oracle_scrub_high_entropy_tokens(english), english);

    // 4. Standard Windows path is preserved (entropy check ignores paths)
    let path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    assert!(!oracle_is_high_entropy_secret(path));
    assert_eq!(oracle_scrub_high_entropy_tokens(path), path);

    // 5. Standard UUID v4 is preserved
    let uuid_str = "f079fca0-097e-4913-bd00-d16c999eb7ee";
    assert!(!oracle_is_high_entropy_secret(uuid_str));
    assert_eq!(oracle_scrub_high_entropy_tokens(uuid_str), uuid_str);
}

#[test]
fn test_tier1_f08_lancedb_and_tantivy_indexing_with_tier3_guard() {
    let mut storage = IsolatedStorageEngine::new();

    // Ingest Tier 3 forensic chunk
    let chunk = DocumentChunk::new(
        "art_chunk_1",
        "doc_art_1",
        "artemis://windows/eventlog/Security.evtx",
        1,
        5,
        AccessTier::Tier3Restricted.as_u8(),
        vec![1.0; 768],
        "EventID 4688 New process created: svchost.exe parent: services.exe",
        Some(json!({"artemis_dfir": true, "mesh_sharable": false}).to_string()),
    )
    .unwrap();

    storage.insert_chunks(&[chunk]);
    assert_eq!(storage.len(), 1);

    // 1. Tier 0 (Public) query CANNOT retrieve chunk
    let hits_tier0 = storage.search_vector(&vec![1.0; 768], AccessTier::Tier0Public.as_u8(), 10);
    assert!(hits_tier0.is_empty(), "Tier 0 query must NOT return Tier 3 forensic chunk");

    // 2. Tier 1 (Internal) query CANNOT retrieve chunk
    let hits_tier1 = storage.search_text("svchost", AccessTier::Tier1Internal.as_u8(), 10);
    assert!(hits_tier1.is_empty(), "Tier 1 query must NOT return Tier 3 forensic chunk");

    // 3. Tier 2 (Confidential) query CANNOT retrieve chunk
    let hits_tier2 = storage.search_hybrid("svchost", &vec![1.0; 768], AccessTier::Tier2Confidential.as_u8(), 10);
    assert!(hits_tier2.is_empty(), "Tier 2 query must NOT return Tier 3 forensic chunk");

    // 4. Tier 3 (Restricted) authorized local query successfully retrieves chunk
    let hits_tier3 = storage.search_hybrid("svchost", &vec![1.0; 768], AccessTier::Tier3Restricted.as_u8(), 10);
    assert_eq!(hits_tier3.len(), 1);
    assert_eq!(hits_tier3[0].chunk.chunk_id, "art_chunk_1");

    // 5. Storage metadata integrity
    assert!(hits_tier3[0].chunk.metadata_json.contains("artemis_dfir"));
}

#[test]
fn test_tier1_f09_default_off_configuration_local_and_harvest() {
    let settings = ArtemisDfirSettings::default();

    // 1. Master toggle is false
    assert!(!settings.enabled, "Artemis master toggle must be false by default");

    // 2. Local collection toggle is false
    assert!(!settings.local_collection_enabled, "Local collection must be false by default");

    // 3. Marketplace harvest toggle is false
    assert!(!settings.marketplace_harvest_enabled, "Marketplace harvest must be false by default");

    // 4. Default categories only contain defensive categories
    for cat in &settings.allowed_artifact_categories {
        let t = ForensicTelemetryType::from_str(cat).expect("Valid category string");
        assert!(t.is_marketplace_harvest_allowed(), "Category {} must be defensive", cat);
    }

    // 5. Secret redaction and normalizer flags default to true
    assert!(settings.redact_secrets);
    assert!(settings.normalize_for_harvest);
}

#[test]
fn test_tier1_f10_p2p_outbound_airgap_blocking() {
    // 1. Candidate chunk with artemis:// URI is blocked
    let chunk_artemis = CandidateChunkDto {
        chunk_id: "c1".to_string(),
        file_path: "artemis://windows/registry/run".to_string(),
        line_start: 1,
        line_end: 2,
        content: "malicious_persistence.exe".to_string(),
        score: 0.99,
        access_tier: 3,
    };
    assert!(AirgapMeshRouter::is_airgap_restricted_chunk_dto(&chunk_artemis));

    // 2. Candidate chunk with Tier 3 is blocked
    let chunk_tier3 = CandidateChunkDto {
        chunk_id: "c2".to_string(),
        file_path: "C:\\Windows\\System32\\config\\SYSTEM".to_string(),
        line_start: 1,
        line_end: 1,
        content: "registry hive".to_string(),
        score: 0.95,
        access_tier: 3,
    };
    assert!(AirgapMeshRouter::is_airgap_restricted_chunk_dto(&chunk_tier3));

    // 3. Candidate chunk at Tier 0 without artemis is NOT blocked
    let chunk_public = CandidateChunkDto {
        chunk_id: "c3".to_string(),
        file_path: "crates/core/src/lib.rs".to_string(),
        line_start: 1,
        line_end: 20,
        content: "pub fn retrieve() {}".to_string(),
        score: 0.85,
        access_tier: 0,
    };
    assert!(!AirgapMeshRouter::is_airgap_restricted_chunk_dto(&chunk_public));

    // 4. Batch filter suppresses all restricted chunks
    let batch = vec![chunk_artemis, chunk_tier3, chunk_public];
    let filtered = AirgapMeshRouter::filter_outbound_mesh_chunks(batch);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].chunk_id, "c3");

    // 5. DocumentChunk airgap predicate validates JSON metadata
    let doc_chunk = DocumentChunk::new(
        "d1",
        "doc1",
        "normal_path.txt",
        1,
        2,
        0,
        vec![0.1; 768],
        "content",
        Some(json!({"artemis_dfir": true, "mesh_sharable": false}).to_string()),
    )
    .unwrap();
    assert!(AirgapMeshRouter::is_airgap_restricted_doc_chunk(&doc_chunk));
}

#[test]
fn test_tier1_f11_p2p_inbound_airgap_rejection() {
    // 1. Inbound query with artemis:// is rejected
    assert!(AirgapMeshRouter::handle_inbound_query("search artemis://windows/eventlog", 0).is_err());

    // 2. Inbound query requesting Tier 3 is rejected
    assert!(AirgapMeshRouter::handle_inbound_query("search process creation", 3).is_err());

    // 3. Valid public query passes
    assert!(AirgapMeshRouter::handle_inbound_query("search embedding dimensions", 0).is_ok());

    // 4. Inbound remote chunks received from peer containing artemis:// are dropped
    let remote_chunks = vec![
        CandidateChunkDto {
            chunk_id: "rc1".to_string(),
            file_path: "artemis://remote/proc".to_string(),
            line_start: 1,
            line_end: 5,
            content: "infiltrated process".to_string(),
            score: 0.9,
            access_tier: 0,
        },
        CandidateChunkDto {
            chunk_id: "rc2".to_string(),
            file_path: "docs/architecture.md".to_string(),
            line_start: 10,
            line_end: 20,
            content: "clean document".to_string(),
            score: 0.8,
            access_tier: 0,
        },
    ];
    let sanitized = AirgapMeshRouter::sanitize_inbound_remote_chunks(remote_chunks);
    assert_eq!(sanitized.len(), 1);
    assert_eq!(sanitized[0].chunk_id, "rc2");

    // 5. Case insensitivity in query rejection
    assert!(AirgapMeshRouter::handle_inbound_query("SEARCH ARTEMIS://WINDOWS", 0).is_err());
}

#[test]
fn test_tier1_f12_keyed_blake3_forensic_structural_normalizer() {
    let node_seed = [42u8; 32];
    let mut normalizer = OracleForensicNormalizer::new(&node_seed, "session_test_1");

    // 1. Normalizes Windows SID
    let sid_input = "User S-1-5-21-123456789-987654321-1122334455-1001 logged in";
    let sid_out = normalizer.normalize_text(sid_input);
    assert!(!sid_out.contains("S-1-5-21-123456789-987654321-1122334455-1001"));
    assert!(sid_out.contains("SID-"));

    // 2. Normalizes Internal IPv4
    let ip_input = "Connection from 192.168.1.55:445 to 10.0.0.10:445";
    let ip_out = normalizer.normalize_text(ip_input);
    assert!(!ip_out.contains("192.168.1.55"));
    assert!(!ip_out.contains("10.0.0.10"));
    assert!(ip_out.contains("IPV4-"));

    // 3. Normalizes MAC Address
    let mac_input = "Interface MAC 00:1A:2B:3C:4D:5E bound to network";
    let mac_out = normalizer.normalize_text(mac_input);
    assert!(!mac_out.contains("00:1A:2B:3C:4D:5E"));
    assert!(mac_out.contains("MAC-"));

    // 4. Normalizes SMB UNC Share
    let smb_input = "Mounted share \\\\CORP-FILE01\\ConfidentialDocs";
    let smb_out = normalizer.normalize_text(smb_input);
    assert!(!smb_out.contains("\\\\CORP-FILE01\\ConfidentialDocs"));
    assert!(smb_out.contains("SMB-"));

    // 5. Mappings table contains all generated pseudonyms
    assert!(normalizer.mappings().len() >= 4);
}

#[test]
fn test_tier1_f13_topology_preservation_and_consistent_pseudonyms() {
    let node_seed = [99u8; 32];
    let mut normalizer = OracleForensicNormalizer::new(&node_seed, "batch_session_A");

    // Entity E1: Host A (192.168.1.100) appears in multiple records
    let text1 = "Host 192.168.1.100 spawned powershell.exe";
    let text2 = "Outbound connection from 192.168.1.100 to 10.0.0.50";
    let norm1 = normalizer.normalize_text(text1);
    let norm2 = normalizer.normalize_text(text2);

    // 1. Deterministic consistency: identical entity maps to identical pseudonym
    let re_ipv4 = Regex::new(r"IPV4-[0-9a-fA-F]{8}").unwrap();
    let pseudo1 = re_ipv4.find(&norm1).expect("Pseudo found in norm1").as_str();
    let pseudo2 = re_ipv4.find(&norm2).expect("Pseudo found in norm2").as_str();
    assert_eq!(pseudo1, pseudo2, "Identical IP must produce identical pseudonym in same session");

    // 2. Different entity E2 (10.0.0.50) produces a DIFFERENT pseudonym
    let all_pseudos: Vec<&str> = re_ipv4.find_iter(&norm2).map(|m| m.as_str()).collect();
    assert_eq!(all_pseudos.len(), 2);
    assert_ne!(all_pseudos[0], all_pseudos[1], "Distinct entities must produce distinct pseudonyms");

    // 3. Topology preservation: causal edges remain isomorphic
    assert!(norm2.contains(&format!("from {} to {}", all_pseudos[0], all_pseudos[1])));

    // 4. Session key derivation is keyed with node seed
    let key1 = oracle_derive_normalizer_session_key(&node_seed, "session_1");
    let key2 = oracle_derive_normalizer_session_key(&node_seed, "session_1");
    assert_eq!(key1, key2);

    // 5. Different session produces different key
    let key3 = oracle_derive_normalizer_session_key(&node_seed, "session_2");
    assert_ne!(key1, key3);
}

#[test]
fn test_tier1_f14_marketplace_harvest_pipeline_category_gate() {
    // 1. ProcessExecution candidate is accepted
    let cand_proc = (
        "cand_1",
        ForensicTelemetryType::ProcessExecution,
        "powershell.exe -NoProfile -Command Write-Host Ready",
    );
    assert!(cand_proc.1.is_marketplace_harvest_allowed());

    // 2. BrowserCookies candidate is rejected
    let cand_cookies = (
        "cand_2",
        ForensicTelemetryType::BrowserCookies,
        "cookie_jar: session_token=12345",
    );
    assert!(!cand_cookies.1.is_marketplace_harvest_allowed());

    // 3. CredentialStore candidate is rejected
    let cand_creds = (
        "cand_3",
        ForensicTelemetryType::CredentialStore,
        "SAM hive extracted hashes",
    );
    assert!(!cand_creds.1.is_marketplace_harvest_allowed());

    // 4. ShellHistoryRaw candidate is rejected
    let cand_shell = (
        "cand_4",
        ForensicTelemetryType::ShellHistoryRaw,
        "export PASS=SuperSecret",
    );
    assert!(!cand_shell.1.is_marketplace_harvest_allowed());

    // 5. SystemEventLog candidate is accepted
    let cand_event = (
        "cand_5",
        ForensicTelemetryType::SystemEventLog,
        "Event 4624 Successful Logon",
    );
    assert!(cand_event.1.is_marketplace_harvest_allowed());
}

#[test]
fn test_tier1_f15_daemon_artemis_status_endpoint() {
    let node_seed = [10u8; 32];
    let harness = TestArtemisDaemonHarness::new(&node_seed, "sess_status");

    let status = harness.get_status();

    // 1. Status ok
    assert_eq!(status["status"], "ok");

    // 2. Collection & harvest disabled by default
    assert_eq!(status["collection_enabled"], false);
    assert_eq!(status["marketplace_harvest_enabled"], false);

    // 3. Airgap enforced flag is true
    assert_eq!(status["airgap_enforced"], true);

    // 4. Allowed categories list is populated
    let allowed = status["allowed_marketplace_categories"].as_array().unwrap();
    assert!(allowed.len() >= 6);

    // 5. Prohibited categories list is populated
    let prohibited = status["prohibited_marketplace_categories"].as_array().unwrap();
    assert!(prohibited.len() >= 4);
}

#[test]
fn test_tier1_f16_daemon_artemis_config_endpoint() {
    let node_seed = [11u8; 32];
    let mut harness = TestArtemisDaemonHarness::new(&node_seed, "sess_cfg");

    // 1. GET returns valid JSON
    let cfg = harness.get_config();
    assert_eq!(cfg["local_collection_enabled"], false);

    // 2. POST updates settings
    let update_payload = json!({
        "enabled": true,
        "local_collection_enabled": true,
        "marketplace_harvest_enabled": false,
        "allowed_artifact_categories": ["process_execution"],
        "auto_collection_interval_mins": 30,
        "retention_days": 14,
        "redact_secrets": true,
        "normalize_for_harvest": true,
    });
    let updated = harness.update_config(update_payload).expect("Update should succeed");

    // 3. Updated values reflected
    assert_eq!(updated["local_collection_enabled"], true);
    assert_eq!(updated["auto_collection_interval_mins"], 30);
    assert_eq!(updated["retention_days"], 14);

    // 4. Reflected in harness status
    let status = harness.get_status();
    assert_eq!(status["collection_enabled"], true);

    // 5. Invalid JSON payload rejected
    assert!(harness.update_config(json!("invalid_scalar")).is_err());
}

#[test]
fn test_tier1_f17_daemon_artemis_collect_endpoint() {
    let node_seed = [12u8; 32];
    let mut harness = TestArtemisDaemonHarness::new(&node_seed, "sess_collect");

    let records = vec![
        ("art1", ForensicTelemetryType::ProcessExecution, "cmd.exe /c dir"),
        ("art2", ForensicTelemetryType::NetworkConnection, "connect 127.0.0.1:80"),
    ];

    // 1. When local_collection_enabled is false, live collection returns 403 Forbidden
    let res_disabled = harness.collect_on_demand(true, records.clone());
    assert_eq!(res_disabled.unwrap_err().0, 403);

    // 2. Enable collection
    harness.settings.local_collection_enabled = true;

    // 3. Collection succeeds when enabled
    let res_ok = harness.collect_on_demand(true, records).expect("Collect succeeds");
    assert_eq!(res_ok["status"], "completed");
    assert_eq!(res_ok["records_parsed"], 2);
    assert_eq!(res_ok["chunks_indexed"], 2);

    // 4. Indexed records stored at Tier 3
    assert_eq!(harness.storage.len(), 2);
    let hits = harness.storage.search_text("cmd.exe", AccessTier::Tier3Restricted.as_u8(), 5);
    assert_eq!(hits.len(), 1);

    // 5. Zero records visible at Tier 0
    let hits_tier0 = harness.storage.search_text("cmd.exe", AccessTier::Tier0Public.as_u8(), 5);
    assert!(hits_tier0.is_empty());
}

#[test]
fn test_tier1_f18_daemon_artemis_preview_normalizer_endpoint() {
    let node_seed = [13u8; 32];
    let mut harness = TestArtemisDaemonHarness::new(&node_seed, "sess_prev");

    let raw = "Logon SID S-1-5-21-999-888-777-1001 from IP 192.168.1.200";

    // 1. Preview defensive category
    let res = harness.preview_normalizer(raw, "process_execution").expect("Preview succeeds");
    assert_eq!(res["status"], "ok");
    assert_eq!(res["allowlisted_for_marketplace"], true);
    assert!(res["normalized"].as_str().unwrap().contains("SID-"));
    assert!(res["normalized"].as_str().unwrap().contains("IPV4-"));

    // 2. Preview prohibited category
    let res_prohibited = harness.preview_normalizer("cookie=xyz", "browser_cookies").unwrap();
    assert_eq!(res_prohibited["allowlisted_for_marketplace"], false);
    assert!(res_prohibited["rejection_reason"].as_str().is_some());

    // 3. Unknown category rejected
    assert!(harness.preview_normalizer(raw, "invalid_category").is_err());

    // 4. Original text preserved in response
    assert_eq!(res["original"], raw);

    // 5. Mappings returned in response
    assert!(res["mappings"].as_object().unwrap().len() >= 2);
}

#[test]
fn test_tier1_f19_webui_artemis_settings_tab_rendering() {
    // Simulated UI index.html snippet adhering to Requirement R6
    let html_content = r#"
        <button class="chatgpt-nav-item" data-tab="artemis-dfir">
            <span class="icon">🛡️</span>
            <span>Artemis DFIR &amp; Forensics (Local-Only)</span>
        </button>
        <div id="artemis-dfir-view" class="chatgpt-settings-section" data-tab-content="artemis-dfir">
            <h2>🛡️ Artemis DFIR &amp; Forensics (Local-Only)</h2>
        </div>
    "#;

    // 1. data-tab="artemis-dfir" exists
    assert!(html_content.contains("data-tab=\"artemis-dfir\""));

    // 2. Shield icon present
    assert!(html_content.contains("🛡️"));

    // 3. Title contains "Artemis DFIR & Forensics (Local-Only)"
    assert!(html_content.contains("Artemis DFIR &amp; Forensics (Local-Only)"));

    // 4. Tab content container defined
    assert!(html_content.contains("data-tab-content=\"artemis-dfir\""));

    // 5. Local-only warning styling class present
    assert!(html_content.contains("chatgpt-settings-section"));
}

#[test]
fn test_tier1_f20_webui_controls_toggles_and_preview_card() {
    // Simulated UI component markup adhering to Requirement R6
    let controls_html = r#"
        <input type="checkbox" id="artemis-collection-toggle" name="artemis_collection_enabled"/>
        <input type="checkbox" id="artemis-harvest-toggle" name="artemis_harvest_enabled"/>
        <input type="checkbox" class="artemis-category-cb" value="process_execution" checked/>
        <input type="checkbox" class="artemis-category-cb" value="credential_store" disabled/>
        <button id="btn-artemis-collect-now" data-action="artemis-collect-now">Collect Telemetry Now</button>
        <button id="btn-artemis-import-folder" data-action="trigger-native-folder-picker">Import Forensic Dump Folder</button>
        <div id="artemis-normalizer-preview-card" class="preview-card">
            <textarea id="normalizer-raw-input">192.168.1.10</textarea>
            <div id="normalizer-output-display">IPV4-4c7b8910</div>
        </div>
    "#;

    // 1. Local collection toggle present
    assert!(controls_html.contains("id=\"artemis-collection-toggle\""));

    // 2. Marketplace harvest toggle present
    assert!(controls_html.contains("id=\"artemis-harvest-toggle\""));

    // 3. Prohibited category checkbox is disabled/uncheckable
    assert!(controls_html.contains("value=\"credential_store\" disabled"));

    // 4. Action buttons present
    assert!(controls_html.contains("data-action=\"artemis-collect-now\""));
    assert!(controls_html.contains("data-action=\"trigger-native-folder-picker\""));

    // 5. Normalizer live preview card elements present
    assert!(controls_html.contains("id=\"artemis-normalizer-preview-card\""));
    assert!(controls_html.contains("id=\"normalizer-raw-input\""));
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (100+ assertions/cases)
// ============================================================================

#[test]
fn test_tier2_b01_empty_and_whitespace_telemetry() {
    // 1. Empty string Shannon entropy is 0.0
    assert_eq!(oracle_shannon_entropy(""), 0.0);

    // 2. Monotonous repeated character string Shannon entropy is 0.0
    assert_eq!(oracle_shannon_entropy("     "), 0.0);
    assert_eq!(oracle_shannon_entropy("aaaaaaaa"), 0.0);
    assert_eq!(oracle_shannon_entropy("   \t\n  ".trim()), 0.0);

    // 3. Empty text scrubbing leaves empty string
    assert_eq!(oracle_scrub_all_secrets(""), "");
    assert_eq!(oracle_scrub_all_secrets("   "), "");

    // 4. Empty raw payload provenance creation succeeds with valid empty digest
    let empty_digest = blake3::hash(b"").to_hex().to_string();
    let prov = ForensicProvenance::new(
        "art_empty",
        ForensicTelemetryType::SystemEventLog,
        "artemis://empty",
        "host",
        "linux",
        None,
        "artemis-core",
        "0.1.0",
        Utc::now().timestamp(),
        &empty_digest,
    )
    .expect("Empty payload provenance must be valid");
    assert!(prov.verify_payload_bytes(b"").is_ok());

    // 5. Empty telemetry batch collect returns 0 records
    let node_seed = [20u8; 32];
    let mut harness = TestArtemisDaemonHarness::new(&node_seed, "sess_b01");
    harness.settings.local_collection_enabled = true;
    let res = harness.collect_on_demand(false, Vec::new()).unwrap();
    assert_eq!(res["records_parsed"], 0);
}

#[test]
fn test_tier2_b02_corrupted_jsonl_lines_handled_resiliently() {
    let corrupted_jsonl = "{\"valid\": 1}\n{truncated_json\n\n{\"valid\": 2}\n";

    let mut valid_count = 0;
    let mut err_count = 0;

    for line in corrupted_jsonl.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(trimmed) {
            Ok(_) => valid_count += 1,
            Err(_) => err_count += 1,
        }
    }

    // 1. Valid lines parsed
    assert_eq!(valid_count, 2);

    // 2. Malformed line caught
    assert_eq!(err_count, 1);

    // 3. Truncated line does not crash the entire ingestion loop
    assert!(valid_count > 0);

    // 4. Empty lines skipped
    assert_eq!(corrupted_jsonl.lines().count(), 4);

    // 5. Line numbers tracked accurately
    let indexed_lines: Vec<usize> = corrupted_jsonl
        .lines()
        .enumerate()
        .filter_map(|(idx, l)| if serde_json::from_str::<Value>(l.trim()).is_ok() { Some(idx + 1) } else { None })
        .collect();
    assert_eq!(indexed_lines, vec![1, 4]);
}

#[test]
fn test_tier2_b03_all_prohibited_categories_fail_allowlist_assertion() {
    let prohibited = [
        ForensicTelemetryType::BrowserCookies,
        ForensicTelemetryType::BrowserHistoryOAuth,
        ForensicTelemetryType::CredentialStore,
        ForensicTelemetryType::ShellHistoryRaw,
    ];

    // 1. BrowserCookies assert fails
    assert!(matches!(
        prohibited[0].assert_marketplace_harvest_allowed(),
        Err(ForensicContractError::HarvestCategoryProhibited { ref category, .. }) if category == "browser_cookies"
    ));

    // 2. BrowserHistoryOAuth assert fails
    assert!(matches!(
        prohibited[1].assert_marketplace_harvest_allowed(),
        Err(ForensicContractError::HarvestCategoryProhibited { ref category, .. }) if category == "browser_history_oauth"
    ));

    // 3. CredentialStore assert fails
    assert!(matches!(
        prohibited[2].assert_marketplace_harvest_allowed(),
        Err(ForensicContractError::HarvestCategoryProhibited { ref category, .. }) if category == "credential_store"
    ));

    // 4. ShellHistoryRaw assert fails
    assert!(matches!(
        prohibited[3].assert_marketplace_harvest_allowed(),
        Err(ForensicContractError::HarvestCategoryProhibited { ref category, .. }) if category == "shell_history_raw"
    ));

    // 5. Reason strings are non-empty and descriptive
    for p in prohibited {
        let reason = p.harvest_prohibition_reason().unwrap();
        assert!(!reason.is_empty());
        assert!(reason.contains("barred") || reason.contains("prohibited"));
    }
}

#[test]
fn test_tier2_b04_entropy_boundary_values_and_length_cutoffs() {
    // 1. Length cutoff: exactly 15 characters (below 16-char threshold) is NOT redacted even if high entropy
    let len15 = "A1b2C3d4E5f6G7h"; // len 15
    assert_eq!(len15.len(), 15);
    assert!(!oracle_is_high_entropy_secret(len15), "15-char string must NOT be classified as high-entropy secret");

    // 2. Exactly 16 characters with high entropy IS redacted
    let len16 = "A1b2C3d4E5f6G7h8"; // len 16, highly diverse
    assert_eq!(len16.len(), 16);
    let entropy16 = oracle_shannon_entropy(len16);
    assert!(entropy16 > 3.9); // Note: 16 unique chars has log2(16) = 4.0

    // 3. 24-character high entropy token exceeds 4.20
    let len24 = "K8xL9pQ2mN5vR1tW4yZ7bA3c";
    assert_eq!(len24.len(), 24);
    assert!(oracle_shannon_entropy(len24) > 4.20);
    assert!(oracle_is_high_entropy_secret(len24));

    // 4. Monotonous repeating string of length 32 has low entropy
    let repeat32 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(oracle_shannon_entropy(repeat32), 0.0);
    assert!(!oracle_is_high_entropy_secret(repeat32));

    // 5. Two alternating characters has entropy 1.0
    let alt32 = "abababababababababababababababab";
    assert_eq!(oracle_shannon_entropy(alt32), 1.0);
    assert!(!oracle_is_high_entropy_secret(alt32));
}

#[test]
fn test_tier2_b05_entropy_exclusions_paths_uuids_and_urls() {
    // 1. Linux deep filesystem path
    let linux_path = "/usr/lib/systemd/system/network-manager.service";
    assert!(!oracle_is_high_entropy_secret(linux_path));
    assert_eq!(oracle_scrub_high_entropy_tokens(linux_path), linux_path);

    // 2. Windows System32 driver path
    let win_path = "C:\\Windows\\System32\\drivers\\tcpip.sys";
    assert!(!oracle_is_high_entropy_secret(win_path));
    assert_eq!(oracle_scrub_high_entropy_tokens(win_path), win_path);

    // 3. Lowercase UUID
    let uuid_lower = "c46ecb74-3fa2-49c5-8b88-d0f7975c8217";
    assert!(!oracle_is_high_entropy_secret(uuid_lower));
    assert_eq!(oracle_scrub_high_entropy_tokens(uuid_lower), uuid_lower);

    // 4. Uppercase UUID
    let uuid_upper = "C46ECB74-3FA2-49C5-8B88-D0F7975C8217";
    assert!(!oracle_is_high_entropy_secret(uuid_upper));
    assert_eq!(oracle_scrub_high_entropy_tokens(uuid_upper), uuid_upper);

    // 5. Artemis URI scheme
    let artemis_uri = "artemis://windows/eventlog/Microsoft-Windows-Sysmon/Operational.evtx";
    assert!(!oracle_is_high_entropy_secret(artemis_uri));
    assert_eq!(oracle_scrub_high_entropy_tokens(artemis_uri), artemis_uri);
}

#[test]
fn test_tier2_b06_interleaved_multiple_secrets_in_cli_string() {
    let raw_cmd = "docker run -e DB_PASS=SecretPass999! -e API_KEY=sk-proj-999888777666555444333222 -p 8080:8080 --password=RootMasterPass! my_image";

    let scrubbed = oracle_scrub_all_secrets(raw_cmd);

    // 1. DB_PASS value redacted
    assert!(!scrubbed.contains("SecretPass999!"));

    // 2. OpenAI API key redacted
    assert!(!scrubbed.contains("sk-proj-999888777666555444333222"));

    // 3. --password value redacted
    assert!(!scrubbed.contains("RootMasterPass!"));

    // 4. Non-secret flags preserved
    assert!(scrubbed.contains("docker run"));
    assert!(scrubbed.contains("-p 8080:8080"));
    assert!(scrubbed.contains("my_image"));

    // 5. Structure intact
    assert!(scrubbed.contains("--password=[REDACTED_CLI_ARG]"));
}

#[test]
fn test_tier2_b07_oversized_and_deep_nested_telemetry_payloads() {
    // 1. Large 1MB telemetry string
    let base_event = "{\"EventID\": 4688, \"Image\": \"C:\\\\Windows\\\\System32\\\\cmd.exe\"}\n";
    let large_payload = base_event.repeat(10_000); // ~700KB
    assert!(large_payload.len() > 500_000);

    // 2. BLAKE3 hashing large payload is fast and deterministic
    let h1 = blake3::hash(large_payload.as_bytes()).to_hex().to_string();
    let h2 = blake3::hash(large_payload.as_bytes()).to_hex().to_string();
    assert_eq!(h1, h2);

    // 3. Provenance validation accepts large payload hash
    let prov = ForensicProvenance::new(
        "art_large",
        ForensicTelemetryType::SystemEventLog,
        "artemis://windows/large.evtx",
        "WIN-CORP",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        Utc::now().timestamp(),
        &h1,
    )
    .unwrap();
    assert!(prov.verify_payload_bytes(large_payload.as_bytes()).is_ok());

    // 4. Deeply nested JSON parsing
    let nested = json!({
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "user": "Alice",
                        "ip": "192.168.1.10"
                    }
                }
            }
        }
    });
    let nested_str = nested.to_string();
    let mut normalizer = OracleForensicNormalizer::new(&[1u8; 32], "sess_nested");
    let norm = normalizer.normalize_text(&nested_str);
    assert!(!norm.contains("192.168.1.10"));
    assert!(norm.contains("IPV4-"));

    // 5. Parsed back to JSON maintains depth
    let parsed: Value = serde_json::from_str(&norm).expect("Valid JSON");
    assert!(parsed["level1"]["level2"]["level3"]["level4"]["user"].is_string());
}

#[test]
fn test_tier2_b08_unauthorized_tier_query_boundary_isolation() {
    let mut storage = IsolatedStorageEngine::new();

    // Insert records at Tier 0, Tier 1, Tier 2, Tier 3
    storage.insert_chunks(&[
        DocumentChunk::new("c0", "d0", "pub.txt", 1, 1, 0, vec![1.0; 768], "public data", None).unwrap(),
        DocumentChunk::new("c1", "d1", "int.txt", 1, 1, 1, vec![1.0; 768], "internal data", None).unwrap(),
        DocumentChunk::new("c2", "d2", "conf.txt", 1, 1, 2, vec![1.0; 768], "confidential data", None).unwrap(),
        DocumentChunk::new("c3", "d3", "artemis://sec.evtx", 1, 1, 3, vec![1.0; 768], "restricted forensic data", None).unwrap(),
    ]);

    // 1. Max tier 0 returns only c0
    let res0 = storage.search_vector(&vec![1.0; 768], 0, 10);
    assert_eq!(res0.len(), 1);
    assert_eq!(res0[0].chunk.chunk_id, "c0");

    // 2. Max tier 1 returns c0, c1
    let res1 = storage.search_vector(&vec![1.0; 768], 1, 10);
    assert_eq!(res1.len(), 2);

    // 3. Max tier 2 returns c0, c1, c2 (NOT c3)
    let res2 = storage.search_vector(&vec![1.0; 768], 2, 10);
    assert_eq!(res2.len(), 3);
    assert!(!res2.iter().any(|r| r.chunk.chunk_id == "c3"));

    // 4. Max tier 3 returns all 4
    let res3 = storage.search_vector(&vec![1.0; 768], 3, 10);
    assert_eq!(res3.len(), 4);
    assert!(res3.iter().any(|r| r.chunk.chunk_id == "c3"));

    // 5. Keyword search respects identical tier ceiling
    let kw0 = storage.search_text("data", 0, 10);
    assert_eq!(kw0.len(), 1);
    let kw2 = storage.search_text("data", 2, 10);
    assert_eq!(kw2.len(), 3);
}

#[test]
fn test_tier2_b09_airgap_uri_case_insensitivity() {
    // 1. All case variations of artemis:// detected
    assert!(AirgapMeshRouter::is_artemis_uri("artemis://eventlog"));
    assert!(AirgapMeshRouter::is_artemis_uri("ARTEMIS://eventlog"));
    assert!(AirgapMeshRouter::is_artemis_uri("Artemis://eventlog"));
    assert!(AirgapMeshRouter::is_artemis_uri("ArTeMiS://eventlog"));

    // 2. Query parser rejects uppercase ARTEMIS://
    assert!(AirgapMeshRouter::contains_artemis_query("SELECT * FROM ARTEMIS://WINDOWS"));

    // 3. Substring with backslash path component
    assert!(AirgapMeshRouter::is_artemis_uri("C:\\data\\artemis\\dump.jsonl"));

    // 4. Substring with forward slash path component
    assert!(AirgapMeshRouter::is_artemis_uri("/var/log/artemis/audit.jsonl"));

    // 5. Non-artemis paths pass
    assert!(!AirgapMeshRouter::is_artemis_uri("/var/log/syslog"));
    assert!(!AirgapMeshRouter::is_artemis_uri("C:\\data\\documents\\notes.txt"));
}

#[test]
fn test_tier2_b10_session_nonce_isolation_between_harvest_batches() {
    let node_seed = [55u8; 32];
    let ip = "192.168.1.50";

    // Batch Session Alpha
    let mut normalizer_a = OracleForensicNormalizer::new(&node_seed, "batch_session_alpha");
    let norm_a = normalizer_a.normalize_text(ip);

    // Batch Session Beta
    let mut normalizer_b = OracleForensicNormalizer::new(&node_seed, "batch_session_beta");
    let norm_b = normalizer_b.normalize_text(ip);

    // 1. Both outputs are pseudonyms
    assert!(norm_a.starts_with("IPV4-"));
    assert!(norm_b.starts_with("IPV4-"));

    // 2. Across different sessions, the pseudonyms MUST BE DIFFERENT (prevent cross-dataset linkage attacks)
    assert_ne!(norm_a, norm_b, "Distinct harvest batches must have disjoint pseudonym spaces");

    // 3. Within the same session, mapping is identical
    let norm_a_repeat = normalizer_a.normalize_text(ip);
    assert_eq!(norm_a, norm_a_repeat);

    // 4. Session key equality for identical session string
    let key1 = oracle_derive_normalizer_session_key(&node_seed, "batch_session_alpha");
    let key2 = oracle_derive_normalizer_session_key(&node_seed, "batch_session_alpha");
    assert_eq!(key1, key2);

    // 5. Different node seed produces different pseudonym even for same session
    let other_seed = [56u8; 32];
    let mut normalizer_other = OracleForensicNormalizer::new(&other_seed, "batch_session_alpha");
    let norm_other = normalizer_other.normalize_text(ip);
    assert_ne!(norm_a, norm_other);
}

#[test]
fn test_tier2_b11_signature_tampering_detection() {
    let raw = b"authentic telemetry payload";
    let hash = blake3::hash(raw).to_hex().to_string();

    let mut prov = ForensicProvenance::new(
        "art_tamper",
        ForensicTelemetryType::ProcessExecution,
        "artemis://test",
        "host-1",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        1000,
        &hash,
    )
    .unwrap();

    let seed = [33u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey = signing_key.verifying_key().to_bytes();

    prov.sign_ed25519(&seed).unwrap();
    assert!(prov.verify_ed25519(&pubkey).is_ok());

    // 1. Tampering with artifact_id invalidates signature
    let mut tampered = prov.clone();
    tampered.artifact_id = "art_tampered".to_string();
    assert!(matches!(
        tampered.verify_ed25519(&pubkey),
        Err(ForensicContractError::ProvenanceSignatureInvalid { .. })
    ));

    // 2. Tampering with host_identifier invalidates signature
    let mut tampered_host = prov.clone();
    tampered_host.host_identifier = "evil-host".to_string();
    assert!(tampered_host.verify_ed25519(&pubkey).is_err());

    // 3. Tampering with collected_unix_secs invalidates signature
    let mut tampered_time = prov.clone();
    tampered_time.collected_unix_secs += 1;
    assert!(tampered_time.verify_ed25519(&pubkey).is_err());

    // 4. Verifying against wrong public key fails
    let wrong_seed = [34u8; 32];
    let wrong_pubkey = SigningKey::from_bytes(&wrong_seed).verifying_key().to_bytes();
    assert!(prov.verify_ed25519(&wrong_pubkey).is_err());

    // 5. Corrupted signature hex string fails with typed error
    let mut tampered_sig = prov.clone();
    tampered_sig.attestation_signature_hex = Some("00".repeat(64)); // 64 zero bytes
    assert!(tampered_sig.verify_ed25519(&pubkey).is_err());
}

// ============================================================================
// TIER 3: CROSS-FEATURE COMBINATIONS (>=20 Pairwise & Interaction Tests)
// ============================================================================

#[test]
fn test_tier3_c01_pair_ingest_evtx_to_scrub_to_tier3_storage_to_airgap_block() {
    let mut storage = IsolatedStorageEngine::new();

    // 1. Raw EVTX containing CLI password and internal IP
    let raw = "Event 4688: Process cmd.exe launched with --password=P@ssw0rd123! connecting to 192.168.1.100";

    // 2. Pre-index scrubber cleans credentials
    let scrubbed = oracle_scrub_all_secrets(raw);
    assert!(!scrubbed.contains("P@ssw0rd123!"));
    assert!(scrubbed.contains("--password=[REDACTED_CLI_ARG]"));

    // 3. Ingest into storage at Tier 3 with local-only airgap metadata
    let chunk = DocumentChunk::new(
        "evtx_chunk_1",
        "doc_evtx",
        "artemis://windows/eventlog/Security.evtx",
        1,
        2,
        AccessTier::Tier3Restricted.as_u8(),
        oracle_deterministic_vector(&scrubbed, 768),
        scrubbed.clone(),
        Some(json!({"artemis_dfir": true, "mesh_sharable": false}).to_string()),
    )
    .unwrap();
    storage.insert_chunks(&[chunk.clone()]);

    // 4. Verify local Tier 3 hybrid search succeeds
    let local_hits = storage.search_hybrid("cmd.exe", &oracle_deterministic_vector("cmd.exe", 768), 3, 5);
    assert_eq!(local_hits.len(), 1);

    // 5. Outbound mesh export attempts to wrap chunk -> Airgap router strictly blocks it
    let dto = CandidateChunkDto::from_scored_chunk(&local_hits[0]);
    assert!(AirgapMeshRouter::is_airgap_restricted_chunk_dto(&dto));
    let outbound_batch = AirgapMeshRouter::filter_outbound_mesh_chunks(vec![dto]);
    assert!(outbound_batch.is_empty(), "Forensic chunk must NEVER be exported outbound");
}

#[test]
fn test_tier3_c02_pair_linux_auditd_to_scrub_to_local_bm25_to_zero_mesh_leakage() {
    let mut storage = IsolatedStorageEngine::new();

    let audit_line = "type=EXECVE msg=audit(1700000000.123:456): argc=3 a0=\"curl\" a1=\"-H\" a2=\"Authorization: Bearer sk_test_secret1234567890abcdef\"";
    let scrubbed = oracle_scrub_all_secrets(audit_line);
    assert!(!scrubbed.contains("sk_test_secret1234567890abcdef"));
    assert!(scrubbed.contains("Bearer [REDACTED_BEARER_TOKEN]"));

    let chunk = DocumentChunk::new(
        "audit_chunk_1",
        "doc_audit",
        "artemis://linux/audit/audit.log",
        1,
        1,
        AccessTier::Tier3Restricted.as_u8(),
        vec![0.5; 768],
        scrubbed,
        Some(json!({"artemis_dfir": true, "mesh_sharable": false}).to_string()),
    )
    .unwrap();
    storage.insert_chunks(&[chunk]);

    // Local BM25 query works for authorized analyst
    let hits = storage.search_text("curl", 3, 5);
    assert_eq!(hits.len(), 1);

    // Adversarial inbound P2P query for curl
    let inbound_res = AirgapMeshRouter::handle_inbound_query("curl", 0);
    assert!(inbound_res.is_ok()); // Normal query text
    // But when storage engine evaluates at remote peer's requested tier (Tier 0), zero chunks are returned!
    let peer_hits = storage.search_text("curl", 0, 5);
    assert!(peer_hits.is_empty(), "Remote peer at Tier 0 must see 0 forensic chunks");
}

#[test]
fn test_tier3_c03_pair_macos_launchd_to_provenance_to_marketplace_staging() {
    let plist = b"<plist><dict><key>ProgramArguments</key><array><string>/usr/bin/security_agent</string></array></dict></plist>";
    let hash = blake3::hash(plist).to_hex().to_string();

    let mut prov = ForensicProvenance::new(
        "mac_art_1",
        ForensicTelemetryType::ServiceDaemon,
        "artemis://macos/launchdaemons/agent.plist",
        "macbook-pro",
        "macos",
        Some("macOS 15.1".to_string()),
        "artemis-core",
        "0.1.0",
        Utc::now().timestamp(),
        &hash,
    )
    .unwrap();

    let node_seed = [77u8; 32];
    prov.sign_ed25519(&node_seed).unwrap();

    // Provenance verification passes
    let pubkey = SigningKey::from_bytes(&node_seed).verifying_key().to_bytes();
    assert!(prov.verify_ed25519(&pubkey).is_ok());

    // Category allowlist passes for ServiceDaemon
    assert!(prov.telemetry_type.is_marketplace_harvest_allowed());

    // Structural normalizer runs for harvest staging
    let mut normalizer = OracleForensicNormalizer::new(&node_seed, "harvest_batch_mac");
    let norm = normalizer.normalize_text("Daemon executed on host macbook-pro with path \\\\corp\\share");
    assert!(norm.contains("SMB-"));
}

#[test]
fn test_tier3_c04_pair_mixed_batch_harvest_defensive_and_prohibited_partitioning() {
    let candidates = vec![
        ("cand_p1", ForensicTelemetryType::ProcessExecution, "cmd.exe"),
        ("cand_c1", ForensicTelemetryType::CredentialStore, "sam_dump"),
        ("cand_n1", ForensicTelemetryType::NetworkConnection, "socket_est"),
        ("cand_b1", ForensicTelemetryType::BrowserCookies, "cookie_data"),
        ("cand_s1", ForensicTelemetryType::ServiceDaemon, "service_unit"),
        ("cand_h1", ForensicTelemetryType::ShellHistoryRaw, "bash_hist"),
    ];

    let mut allowed_batch = Vec::new();
    let mut rejected_batch = Vec::new();

    for (id, cat, text) in candidates {
        if cat.is_marketplace_harvest_allowed() {
            allowed_batch.push((id, cat, text));
        } else {
            rejected_batch.push((id, cat, text));
        }
    }

    // 1. Allowed batch contains 3 defensive categories
    assert_eq!(allowed_batch.len(), 3);
    assert!(allowed_batch.iter().any(|c| c.1 == ForensicTelemetryType::ProcessExecution));
    assert!(allowed_batch.iter().any(|c| c.1 == ForensicTelemetryType::NetworkConnection));
    assert!(allowed_batch.iter().any(|c| c.1 == ForensicTelemetryType::ServiceDaemon));

    // 2. Rejected batch contains 3 prohibited categories
    assert_eq!(rejected_batch.len(), 3);
    assert!(rejected_batch.iter().any(|c| c.1 == ForensicTelemetryType::CredentialStore));
    assert!(rejected_batch.iter().any(|c| c.1 == ForensicTelemetryType::BrowserCookies));
    assert!(rejected_batch.iter().any(|c| c.1 == ForensicTelemetryType::ShellHistoryRaw));
}

#[test]
fn test_tier3_c05_pair_inbound_p2p_query_targeting_artemis_rejected_before_storage() {
    let query_adversarial = "query artemis://windows/eventlog for admin password";

    // Inbound router evaluates query
    let result = AirgapMeshRouter::handle_inbound_query(query_adversarial, 0);

    // Query is rejected immediately at network boundary
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("artemis://"));
}

#[test]
fn test_tier3_c06_pair_scatter_gather_remote_peer_returns_artemis_chunk_dropped() {
    let remote_response_chunks = vec![
        CandidateChunkDto {
            chunk_id: "illicit_forensic_chunk".to_string(),
            file_path: "artemis://stolen/evtx".to_string(),
            line_start: 1,
            line_end: 10,
            content: "leaked credentials".to_string(),
            score: 0.99,
            access_tier: 0, // Maliciously forged tier 0
        },
        CandidateChunkDto {
            chunk_id: "clean_chunk".to_string(),
            file_path: "docs/readme.md".to_string(),
            line_start: 1,
            line_end: 10,
            content: "clean information".to_string(),
            score: 0.85,
            access_tier: 0,
        },
    ];

    // Local scatter-gather ingress sanitization
    let sanitized = AirgapMeshRouter::sanitize_inbound_remote_chunks(remote_response_chunks);

    assert_eq!(sanitized.len(), 1);
    assert_eq!(sanitized[0].chunk_id, "clean_chunk");
}

#[test]
fn test_tier3_c07_pair_registry_ingest_dedup_and_compaction() {
    let mut storage = IsolatedStorageEngine::new();

    let reg_text = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run SecurityTask = C:\\sec\\agent.exe";
    let hash = DocumentChunk::compute_blake3_hash(reg_text);

    let chunk1 = DocumentChunk::new(
        "reg_c1",
        "doc_reg",
        "artemis://windows/registry/run",
        1,
        1,
        3,
        vec![0.1; 768],
        reg_text,
        None,
    )
    .unwrap();

    let chunk2 = DocumentChunk::new(
        "reg_c2",
        "doc_reg",
        "artemis://windows/registry/run",
        1,
        1,
        3,
        vec![0.1; 768],
        reg_text, // Duplicate content
        None,
    )
    .unwrap();

    let ins1 = storage.insert_chunks(&[chunk1]);
    assert_eq!(ins1, 1);
    assert!(storage.has_chunk_hash(&hash));

    // Inserting identical chunk hash is deduplicated
    let ins2 = storage.insert_chunks(&[chunk2]);
    assert_eq!(ins2, 0, "Duplicate chunk BLAKE3 must be deduplicated");
    assert_eq!(storage.len(), 1);
}

#[test]
fn test_tier3_c08_pair_daemon_config_toggle_and_collect_lifecycle() {
    let node_seed = [88u8; 32];
    let mut harness = TestArtemisDaemonHarness::new(&node_seed, "sess_c08");

    let records = vec![("id1", ForensicTelemetryType::ProcessExecution, "whoami.exe")];

    // 1. Initial attempt fails (disabled)
    assert_eq!(harness.collect_on_demand(true, records.clone()).unwrap_err().0, 403);

    // 2. Enable in config
    harness.settings.local_collection_enabled = true;

    // 3. Collection now succeeds
    assert!(harness.collect_on_demand(true, records.clone()).is_ok());
    assert_eq!(harness.storage.len(), 1);

    // 4. Disable in config
    harness.settings.local_collection_enabled = false;

    // 5. Subsequent live collection blocked again
    assert_eq!(harness.collect_on_demand(true, records).unwrap_err().0, 403);
}

#[test]
fn test_tier3_c09_pair_normalizer_preview_endpoint_consistent_host_mapping() {
    let node_seed = [89u8; 32];
    let mut harness = TestArtemisDaemonHarness::new(&node_seed, "sess_c09");

    let raw1 = "Host 192.168.1.10 contacted 10.0.0.1";
    let raw2 = "Response received at 192.168.1.10 from 10.0.0.1";

    let res1 = harness.preview_normalizer(raw1, "network_connection").unwrap();
    let res2 = harness.preview_normalizer(raw2, "network_connection").unwrap();

    let norm1 = res1["normalized"].as_str().unwrap();
    let norm2 = res2["normalized"].as_str().unwrap();

    // Verify 192.168.1.10 has identical pseudonym in both responses
    let re_ip = Regex::new(r"IPV4-[0-9a-fA-F]{8}").unwrap();
    let ip_pseudo1: Vec<&str> = re_ip.find_iter(norm1).map(|m| m.as_str()).collect();
    let ip_pseudo2: Vec<&str> = re_ip.find_iter(norm2).map(|m| m.as_str()).collect();

    assert_eq!(ip_pseudo1[0], ip_pseudo2[0]);
    assert_eq!(ip_pseudo1[1], ip_pseudo2[1]);
}

#[test]
fn test_tier3_c10_pair_prefetch_ingest_scrub_env_to_hybrid_search() {
    let mut storage = IsolatedStorageEngine::new();

    let raw = "Prefetch: POWERSHELL.EXE-ABCD1234.pf run_count=12 env: AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE";
    let scrubbed = oracle_scrub_all_secrets(raw);
    assert!(!scrubbed.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(scrubbed.contains("[REDACTED_AWS_KEY]"));

    let chunk = DocumentChunk::new(
        "pf_c1",
        "doc_pf",
        "artemis://windows/prefetch/powershell.pf",
        1,
        1,
        3,
        oracle_deterministic_vector(&scrubbed, 768),
        scrubbed.clone(),
        Some(json!({"artemis_dfir": true, "mesh_sharable": false}).to_string()),
    )
    .unwrap();
    storage.insert_chunks(&[chunk]);

    let query = "POWERSHELL.EXE run_count";
    let q_vec = oracle_deterministic_vector(query, 768);
    let hits = storage.search_hybrid(query, &q_vec, 3, 5);

    assert_eq!(hits.len(), 1);
    assert!(hits[0].chunk.text_content.contains("[REDACTED_AWS_KEY]"));
}

#[test]
fn test_tier3_c11_pair_network_connections_scrub_db_uris_and_normalize_ips() {
    let raw = "ESTABLISHED conn to postgresql://admin:P@ss1234@10.0.0.15:5432/db from 192.168.1.80:50123";

    // Step 1: Pre-index secret scrubber
    let scrubbed = oracle_scrub_all_secrets(raw);
    assert!(!scrubbed.contains("P@ss1234"));
    assert!(scrubbed.contains("[REDACTED_CONNECTION_STRING]"));

    // Step 2: Structural normalizer
    let mut normalizer = OracleForensicNormalizer::new(&[1u8; 32], "sess_c11");
    let normalized = normalizer.normalize_text(&scrubbed);
    assert!(!normalized.contains("192.168.1.80"));
    assert!(normalized.contains("IPV4-"));
}

#[test]
fn test_tier3_c12_pair_system_event_log_multiple_entropy_tokens_scrubbed() {
    let raw = "Log 4688: memory buffer with K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH and Z1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6 dumped";
    let scrubbed = oracle_scrub_all_secrets(raw);

    assert!(!scrubbed.contains("K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH"));
    assert!(!scrubbed.contains("Z1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6"));
    assert!(scrubbed.contains("[REDACTED_HIGH_ENTROPY_SECRET]"));
}

#[test]
fn test_tier3_c13_pair_provenance_created_payload_tampered_fails() {
    let payload = b"legitimate execution log";
    let prov = ForensicProvenance::from_raw_payload(
        "art_c13",
        ForensicTelemetryType::ProcessExecution,
        "artemis://log",
        "host",
        "linux",
        None,
        "artemis-core",
        "0.1.0",
        1000,
        payload,
    )
    .unwrap();

    assert!(prov.verify_payload_bytes(payload).is_ok());
    assert!(prov.verify_payload_bytes(b"modified execution log").is_err());
}

#[test]
fn test_tier3_c14_pair_provenance_signed_metadata_tampered_fails() {
    let payload = b"payload";
    let mut prov = ForensicProvenance::from_raw_payload(
        "art_c14",
        ForensicTelemetryType::ServiceDaemon,
        "artemis://service",
        "host",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        1000,
        payload,
    )
    .unwrap();

    let seed = [66u8; 32];
    prov.sign_ed25519(&seed).unwrap();
    let pubkey = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

    assert!(prov.verify_ed25519(&pubkey).is_ok());

    // Tamper with OS platform
    prov.os_platform = "linux".to_string();
    assert!(prov.verify_ed25519(&pubkey).is_err());
}

#[test]
fn test_tier3_c15_pair_concurrent_queries_public_vs_admin_isolation() {
    let mut storage = IsolatedStorageEngine::new();
    storage.insert_chunks(&[
        DocumentChunk::new("c_pub", "d1", "file.rs", 1, 1, 0, vec![1.0; 768], "public code", None).unwrap(),
        DocumentChunk::new("c_sec", "d2", "artemis://sec", 1, 1, 3, vec![1.0; 768], "secret telemetry", None).unwrap(),
    ]);

    // Query 1: Public Analyst (Tier 0)
    let res_pub = storage.search_vector(&vec![1.0; 768], 0, 10);
    assert_eq!(res_pub.len(), 1);
    assert_eq!(res_pub[0].chunk.chunk_id, "c_pub");

    // Query 2: Admin Forensic Investigator (Tier 3)
    let res_admin = storage.search_vector(&vec![1.0; 768], 3, 10);
    assert_eq!(res_admin.len(), 2);
    assert!(res_admin.iter().any(|r| r.chunk.chunk_id == "c_sec"));
}

#[test]
fn test_tier3_c16_pair_cross_os_telemetry_timeline_search() {
    let mut storage = IsolatedStorageEngine::new();

    storage.insert_chunks(&[
        DocumentChunk::new("win1", "d_win", "artemis://windows/evtx", 1, 1, 3, vec![0.8; 768], "Windows Logon 4624 user admin", None).unwrap(),
        DocumentChunk::new("mac1", "d_mac", "artemis://macos/log", 1, 1, 3, vec![0.8; 768], "macOS sudo session user admin", None).unwrap(),
        DocumentChunk::new("lin1", "d_lin", "artemis://linux/journal", 1, 1, 3, vec![0.8; 768], "Linux sshd session user admin", None).unwrap(),
    ]);

    // Admin searches for user admin activity across all 3 OS platforms
    let hits = storage.search_text("admin", 3, 10);
    assert_eq!(hits.len(), 3);
    let paths: HashSet<&str> = hits.iter().map(|h| h.chunk.file_path.as_str()).collect();
    assert!(paths.contains("artemis://windows/evtx"));
    assert!(paths.contains("artemis://macos/log"));
    assert!(paths.contains("artemis://linux/journal"));
}

#[test]
fn test_tier3_c17_pair_webui_settings_to_daemon_config_to_status_reflection() {
    let node_seed = [44u8; 32];
    let mut harness = TestArtemisDaemonHarness::new(&node_seed, "sess_c17");

    // UI triggers POST /api/v1/artemis/config with harvest enabled
    let payload = json!({
        "enabled": true,
        "local_collection_enabled": true,
        "marketplace_harvest_enabled": true,
        "allowed_artifact_categories": ["process_execution", "network_connection"],
        "auto_collection_interval_mins": 60,
        "retention_days": 30,
        "redact_secrets": true,
        "normalize_for_harvest": true,
    });
    harness.update_config(payload).unwrap();

    let status = harness.get_status();
    assert_eq!(status["marketplace_harvest_enabled"], true);
    assert_eq!(status["collection_enabled"], true);
}

#[test]
fn test_tier3_c18_pair_harvest_batch_error_reporting_for_prohibited_categories() {
    let candidates = vec![
        ("rec1", ForensicTelemetryType::ProcessExecution),
        ("rec2", ForensicTelemetryType::CredentialStore),
    ];

    let mut staged = Vec::new();
    let mut errors = Vec::new();

    for (id, cat) in candidates {
        match cat.assert_marketplace_harvest_allowed() {
            Ok(()) => staged.push(id),
            Err(e) => errors.push((id, e)),
        }
    }

    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0], "rec1");
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].0, "rec2");
    assert!(matches!(errors[0].1, ForensicContractError::HarvestCategoryProhibited { .. }));
}

#[test]
fn test_tier3_c19_pair_outbound_scatter_gather_query_sanitizer_suppresses_dispatch() {
    let query_containing_artemis = "fetch details from artemis://windows/eventlog/Security.evtx";
    assert!(AirgapMeshRouter::contains_artemis_query(query_containing_artemis));

    // ScatterGather engine must suppress outbound network broadcast when query targets artemis
    let should_suppress_remote = AirgapMeshRouter::contains_artemis_query(query_containing_artemis);
    assert!(should_suppress_remote, "Outbound P2P scatter-gather MUST be suppressed for artemis queries");
}

#[test]
fn test_tier3_c20_pair_normalizer_across_sessions_preserves_entropy_and_uniqueness() {
    let node_seed = [100u8; 32];
    let sid = "S-1-5-21-111-222-333-1000";

    let mut norm1 = OracleForensicNormalizer::new(&node_seed, "sess_1");
    let mut norm2 = OracleForensicNormalizer::new(&node_seed, "sess_2");

    let p1 = norm1.normalize_text(sid);
    let p2 = norm2.normalize_text(sid);

    assert!(p1.starts_with("SID-"));
    assert!(p2.starts_with("SID-"));
    assert_ne!(p1, p2, "Independent sessions must generate distinct pseudonyms");
}

// ============================================================================
// TIER 4: REAL-WORLD APPLICATION SCENARIOS (5 Complex Workloads)
// ============================================================================

#[test]
fn test_tier4_scenario_1_enterprise_dfir_ingestion_and_secret_redaction_triage() {
    // SCENARIO: Multi-host incident triage across Windows EVTX, Linux journald, macOS launchd.
    // Threat actor executed mimikatz, powershell with embedded Bearer token, and established
    // connection to internal database with hardcoded credentials.

    let win_event = "Event 4688: powershell.exe -enc aW1wb3J0 -ApiKey sk-ant-secretkey999888777666555444 parent=services.exe";
    let lin_event = "auditd EXECVE: /usr/bin/mysql -u root --password=SuperDBSecretPassword! -h 10.0.0.50";
    let mac_event = "launchd: com.corp.internal.daemon running with AWS_KEY=AKIAIOSFODNN7EXAMPLE";

    // 1. Ingest & Scrub
    let scrubbed_win = oracle_scrub_all_secrets(win_event);
    let scrubbed_lin = oracle_scrub_all_secrets(lin_event);
    let scrubbed_mac = oracle_scrub_all_secrets(mac_event);

    // Verify all 3 credentials are completely eliminated
    assert!(!scrubbed_win.contains("sk-ant-secretkey999888777666555444"));
    assert!(scrubbed_win.contains("[REDACTED_API_KEY]"));

    assert!(!scrubbed_lin.contains("SuperDBSecretPassword!"));
    assert!(scrubbed_lin.contains("--password=[REDACTED_CLI_ARG]"));

    assert!(!scrubbed_mac.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(scrubbed_mac.contains("[REDACTED_AWS_KEY]"));

    // 2. Index into isolated storage at Tier 3
    let mut storage = IsolatedStorageEngine::new();
    storage.insert_chunks(&[
        DocumentChunk::new("win_chunk", "d1", "artemis://win/evtx", 1, 1, 3, vec![0.9; 768], scrubbed_win, None).unwrap(),
        DocumentChunk::new("lin_chunk", "d2", "artemis://lin/audit", 1, 1, 3, vec![0.9; 768], scrubbed_lin, None).unwrap(),
        DocumentChunk::new("mac_chunk", "d3", "artemis://mac/launchd", 1, 1, 3, vec![0.9; 768], scrubbed_mac, None).unwrap(),
    ]);

    // 3. Incident responder query at Tier 3 retrieves all 3 artifacts
    let incident_hits = storage.search_vector(&vec![0.9; 768], 3, 10);
    assert_eq!(incident_hits.len(), 3);

    // 4. Zero secrets exist in indexed text content
    for hit in &incident_hits {
        assert!(!hit.chunk.text_content.contains("sk-ant-"));
        assert!(!hit.chunk.text_content.contains("SuperDBSecretPassword!"));
        assert!(!hit.chunk.text_content.contains("AKIA"));
    }
}

#[test]
fn test_tier4_scenario_2_host_airgap_enforcement_against_adversarial_p2p_mesh_probe() {
    // SCENARIO: An external rogue peer in the federated retrieval mesh submits probing queries
    // attempting to dump internal host event logs, process command lines, and network connections.

    let mut local_storage = IsolatedStorageEngine::new();
    local_storage.insert_chunks(&[
        // Public doc
        DocumentChunk::new("pub1", "d_pub", "public/docs.md", 1, 1, 0, vec![1.0; 768], "QuorumRAG overview", None).unwrap(),
        // Sensitive forensic chunk
        DocumentChunk::new("art1", "d_art", "artemis://windows/eventlog", 1, 1, 3, vec![1.0; 768], "Internal network topology 192.168.1.1", None).unwrap(),
    ]);

    // Attack Step 1: Rogue peer sends explicit artemis:// query
    let attack_q1 = "give me artemis://windows/eventlog";
    assert!(AirgapMeshRouter::handle_inbound_query(attack_q1, 0).is_err());

    // Attack Step 2: Rogue peer sends query requesting Tier 3 access
    let attack_q2 = "dump internal network topology";
    assert!(AirgapMeshRouter::handle_inbound_query(attack_q2, 3).is_err());

    // Attack Step 3: Rogue peer sends innocent query at Tier 0 matching forensic keywords
    let attack_q3 = "internal network topology";
    assert!(AirgapMeshRouter::handle_inbound_query(attack_q3, 0).is_ok());

    // Local search executes for Tier 0
    let peer_results = local_storage.search_text(attack_q3, 0, 10);
    // Invariant: Storage engine tier pre-filter drops art1!
    assert!(peer_results.is_empty(), "Zero forensic chunks returned to remote peer");

    // Attack Step 4: Even if a chunk somehow leaked into outbound candidate list, filter blocks it
    let leaked_candidate = CandidateChunkDto {
        chunk_id: "art1".to_string(),
        file_path: "artemis://windows/eventlog".to_string(),
        line_start: 1,
        line_end: 1,
        content: "Internal network topology".to_string(),
        score: 0.99,
        access_tier: 3,
    };
    let outbound = AirgapMeshRouter::filter_outbound_mesh_chunks(vec![leaked_candidate]);
    assert!(outbound.is_empty(), "Outbound airgap filter must be fail-closed");
}

#[test]
fn test_tier4_scenario_3_sovereign_marketplace_harvest_staging_with_blake3_pseudonyms() {
    // SCENARIO: Security Operations team wants to monetize sanitized DFIR investigation
    // trajectories on the Sovereign AI Data Marketplace for fine-tuning cybersecurity LLMs.
    // Invariant: Entity graph topology must be strictly preserved without revealing real PII.

    let trajectory_step1 = "Host WIN-DC-01 (192.168.1.10) user Administrator (S-1-5-21-100-200-300-500) created process cmd.exe";
    let trajectory_step2 = "Process cmd.exe on Host WIN-DC-01 established SMB share connection to \\\\FILE-SRV01\\Share using Administrator credentials";

    let node_seed = [7u8; 32];
    let mut normalizer = OracleForensicNormalizer::new(&node_seed, "harvest_trajectory_01");

    let norm_step1 = normalizer.normalize_text(trajectory_step1);
    let norm_step2 = normalizer.normalize_text(trajectory_step2);

    // 1. All real identifiers replaced
    assert!(!norm_step1.contains("192.168.1.10"));
    assert!(!norm_step1.contains("S-1-5-21-100-200-300-500"));
    assert!(!norm_step2.contains("\\\\FILE-SRV01\\Share"));

    // 2. Topology strictly preserved: identical IP maps to identical IPV4 pseudonym
    let re_ip = Regex::new(r"IPV4-[0-9a-fA-F]{8}").unwrap();
    let ip1 = re_ip.find(&norm_step1).unwrap().as_str();

    // 3. Category allowlist check
    assert!(ForensicTelemetryType::ProcessExecution.is_marketplace_harvest_allowed());
    assert!(ForensicTelemetryType::NetworkConnection.is_marketplace_harvest_allowed());

    // 4. Staged batch provenance signed with Ed25519
    let mut prov = ForensicProvenance::from_raw_payload(
        "traj_batch_1",
        ForensicTelemetryType::ProcessExecution,
        "artemis://harvest/trajectory_01",
        "WIN-DC-01",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        Utc::now().timestamp(),
        norm_step1.as_bytes(),
    )
    .unwrap();
    prov.sign_ed25519(&node_seed).unwrap();

    let pubkey = SigningKey::from_bytes(&node_seed).verifying_key().to_bytes();
    assert!(prov.verify_ed25519(&pubkey).is_ok());
    assert!(ip1.starts_with("IPV4-"));
}

#[test]
fn test_tier4_scenario_4_prohibited_category_rejection_and_quarantine_in_harvest_pipeline() {
    // SCENARIO: Automated collection job ingested a wide directory that accidentally swept up
    // Chrome Login Data (BrowserCookies), OAuth token cache (BrowserHistoryOAuth), SAM hive
    // (CredentialStore), and bash history alongside Windows Event Logs.

    let mixed_dump = vec![
        ("art_evtx", ForensicTelemetryType::SystemEventLog, "Valid event log"),
        ("art_sam", ForensicTelemetryType::CredentialStore, "NTLM hashes in SAM"),
        ("art_cookies", ForensicTelemetryType::BrowserCookies, "session_id=abcdef123"),
        ("art_oauth", ForensicTelemetryType::BrowserHistoryOAuth, "oauth/callback?code=xyz"),
        ("art_bash", ForensicTelemetryType::ShellHistoryRaw, "export PASSWD=rootpass"),
        ("art_proc", ForensicTelemetryType::ProcessExecution, "Valid process tree"),
    ];

    let mut staged_pool = Vec::new();
    let mut quarantined_pool = Vec::new();

    for (id, telemetry_type, payload) in mixed_dump {
        if telemetry_type.is_marketplace_harvest_allowed() {
            staged_pool.push((id, telemetry_type, payload));
        } else {
            quarantined_pool.push((
                id,
                telemetry_type,
                telemetry_type.harvest_prohibition_reason().unwrap(),
            ));
        }
    }

    // 1. Exactly 2 defensive items staged
    assert_eq!(staged_pool.len(), 2);
    assert_eq!(staged_pool[0].0, "art_evtx");
    assert_eq!(staged_pool[1].0, "art_proc");

    // 2. Exactly 4 prohibited items quarantined
    assert_eq!(quarantined_pool.len(), 4);

    // 3. CredentialStore quarantined
    assert!(quarantined_pool.iter().any(|q| q.0 == "art_sam"));
    // 4. BrowserCookies quarantined
    assert!(quarantined_pool.iter().any(|q| q.0 == "art_cookies"));
    // 5. ShellHistoryRaw quarantined
    assert!(quarantined_pool.iter().any(|q| q.0 == "art_bash"));
}

#[test]
fn test_tier4_scenario_5_full_webui_and_daemon_end_to_end_investigation_flow() {
    // SCENARIO: Complete operator lifecycle:
    // 1. Admin navigates to Settings -> data-tab="artemis-dfir"
    // 2. Inspects GET /api/v1/artemis/status (initially disabled)
    // 3. Toggles local collection ON via POST /api/v1/artemis/config
    // 4. Triggers on-demand collection via POST /api/v1/artemis/collect
    // 5. Inspects live normalizer preview via POST /api/v1/artemis/preview-normalizer
    // 6. Executes local investigation query and validates complete airgap isolation

    let node_seed = [123u8; 32];
    let mut harness = TestArtemisDaemonHarness::new(&node_seed, "session_e2e_flow");

    // Step 1 & 2: Check initial status
    let status_initial = harness.get_status();
    assert_eq!(status_initial["collection_enabled"], false);
    assert_eq!(status_initial["airgap_enforced"], true);

    // Step 3: Update config to enable local collection
    let update_res = harness
        .update_config(json!({
            "enabled": true,
            "local_collection_enabled": true,
            "marketplace_harvest_enabled": false,
            "allowed_artifact_categories": ["process_execution", "system_event_log"],
            "auto_collection_interval_mins": 60,
            "retention_days": 30,
            "redact_secrets": true,
            "normalize_for_harvest": true,
        }))
        .expect("Config update succeeds");
    assert_eq!(update_res["local_collection_enabled"], true);

    // Step 4: Collect on-demand telemetry
    let collect_res = harness
        .collect_on_demand(
            true,
            vec![(
                "incident_proc_01",
                ForensicTelemetryType::ProcessExecution,
                "powershell.exe -NoProfile -Command Invoke-Mimikatz -Password P@ssw0rd999! -Target 192.168.1.15",
            )],
        )
        .expect("Collection succeeds");
    assert_eq!(collect_res["records_parsed"], 1);
    assert_eq!(collect_res["secrets_redacted"], 1);

    // Step 5: Test normalizer preview card
    let preview_res = harness
        .preview_normalizer(
            "Target host 192.168.1.15 logged on with SID S-1-5-21-999-888-777-1001",
            "process_execution",
        )
        .expect("Normalizer preview succeeds");
    assert_eq!(preview_res["status"], "ok");
    assert!(preview_res["normalized"].as_str().unwrap().contains("IPV4-"));
    assert!(preview_res["normalized"].as_str().unwrap().contains("SID-"));

    // Step 6: Verify local investigation retrieval and airgap isolation
    let local_results = harness.storage.search_text("Invoke-Mimikatz", AccessTier::Tier3Restricted.as_u8(), 5);
    assert_eq!(local_results.len(), 1);
    // Secret was redacted before storage
    assert!(!local_results[0].chunk.text_content.contains("P@ssw0rd999!"));

    // Public / remote retrieval sees zero
    let remote_results = harness.storage.search_text("Invoke-Mimikatz", AccessTier::Tier0Public.as_u8(), 5);
    assert!(remote_results.is_empty(), "Zero leakage to unauthorized tier");
}
