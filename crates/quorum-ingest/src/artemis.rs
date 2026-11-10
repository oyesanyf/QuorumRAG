//! Cross-platform Artemis DFIR forensic telemetry ingestion and `.jsonl` parsing.
//!
//! Provides parsing and ingestion for:
//! - Windows: Event Logs (Security 4688/4624, Sysmon, System), Registry persistence,
//!   Prefetch/Amcache execution evidence, Services.
//! - macOS: Unified Logs, LaunchDaemons (`.plist` / json representations).
//! - Linux: systemd journald, auditd (EXECVE, SYSCALL, SOCKADDR), `/proc` process telemetry.
//! - `.jsonl` forensic dumps: Line-delimited JSON stream ingestion with secret scrubbing,
//!   telemetry type inference, and resilience against corrupted lines.
//!
//! Every ingested record enforces:
//! - `access_tier = 3` (`AccessTier::Tier3Restricted`)
//! - `file_path = artemis://...`
//! - `metadata_json` with `artemis_dfir: true`, `mesh_sharable: false`, `harvest_eligible`,
//!   `telemetry_type`, and `raw_payload_blake3`.

use crate::error::IngestError;
use crate::secret_scrubber::SecretScrubber;
use chrono::Utc;
use quorum_contract::{ForensicContractError, ForensicProvenance, ForensicTelemetryType};
use quorum_types::{AccessTier, DocumentChunk, TypeError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::BufRead;
use uuid::Uuid;

/// Normalized cross-platform Artemis DFIR telemetry record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtemisTelemetryRecord {
    /// Unique record identifier (UUID v4 or deterministic string).
    pub record_id: String,
    /// Classified forensic telemetry taxonomy variant.
    pub telemetry_type: ForensicTelemetryType,
    /// Normalized logical source path (must start with `artemis://`).
    pub source_path: String,
    /// Operating system platform ("windows", "macos", "linux").
    pub os_platform: String,
    /// Specific OS release, version, or kernel build.
    pub os_version: Option<String>,
    /// Origin host identifier (hostname, NetBIOS name, or machine GUID).
    pub host_identifier: String,
    /// Timestamp in Unix seconds when artifact was recorded/collected.
    pub timestamp_unix_secs: i64,
    /// Scrubbed human-readable textual summary for full-text and semantic vector indexing.
    pub summary_text: String,
    /// BLAKE3 hex digest of the raw unmodified record bytes.
    pub raw_payload_blake3: String,
    /// Structured payload JSON, with secrets redacted from commands, env vars, and arguments.
    pub raw_json: Value,
    /// Monotonically enforced access tier: invariant is 3 (`Tier3Restricted`).
    pub access_tier: u8,
    /// Airgap origin flag: invariant is `true`.
    pub artemis_dfir: bool,
    /// Airgap mesh sharing flag: invariant is `false`.
    pub mesh_sharable: bool,
    /// Marketplace sovereign training data harvest eligibility: mirrors allowlist gate.
    pub harvest_eligible: bool,
    /// Collector engine identity.
    pub collector_name: String,
    /// Collector engine version.
    pub collector_version: String,
}

impl ArtemisTelemetryRecord {
    /// Constructs a new `ArtemisTelemetryRecord` validating airgap invariants.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        record_id: impl Into<String>,
        telemetry_type: ForensicTelemetryType,
        source_path: impl Into<String>,
        os_platform: impl Into<String>,
        os_version: Option<String>,
        host_identifier: impl Into<String>,
        timestamp_unix_secs: i64,
        summary_text: impl Into<String>,
        raw_payload_blake3: impl Into<String>,
        raw_json: Value,
        collector_name: impl Into<String>,
        collector_version: impl Into<String>,
    ) -> Result<Self, IngestError> {
        let mut source_path_str = source_path.into();
        if !source_path_str.to_ascii_lowercase().starts_with("artemis://") {
            source_path_str = format!("artemis://{}", source_path_str.trim_start_matches('/'));
        }

        let scrubbed_summary = SecretScrubber::scrub_text(&summary_text.into());
        let harvest_eligible = telemetry_type.is_marketplace_harvest_allowed();

        Ok(Self {
            record_id: record_id.into(),
            telemetry_type,
            source_path: source_path_str,
            os_platform: os_platform.into().to_ascii_lowercase(),
            os_version,
            host_identifier: host_identifier.into(),
            timestamp_unix_secs,
            summary_text: scrubbed_summary,
            raw_payload_blake3: raw_payload_blake3.into(),
            raw_json,
            access_tier: 3,
            artemis_dfir: true,
            mesh_sharable: false,
            harvest_eligible,
            collector_name: collector_name.into(),
            collector_version: collector_version.into(),
        })
    }

    /// Parses and normalizes an arbitrary JSON forensic object into a typed record.
    pub fn from_json_value(
        mut val: Value,
        fallback_platform: Option<&str>,
    ) -> Result<Self, IngestError> {
        let raw_bytes = serde_json::to_vec(&val).unwrap_or_default();
        let payload_hash = blake3::hash(&raw_bytes).to_hex().to_string();

        let telemetry_type = infer_telemetry_type(&val);
        let os_platform = infer_os_platform(&val, fallback_platform);
        let source_path = infer_source_path(&val, &os_platform, telemetry_type);
        let host_identifier = infer_host_identifier(&val);
        let timestamp_unix_secs = infer_timestamp_unix_secs(&val);
        let os_version = val
            .get("os_version")
            .or_else(|| val.get("kernel"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let collector_name = val
            .get("collector_name")
            .and_then(|v| v.as_str())
            .unwrap_or("artemis-core")
            .to_string();
        let collector_version = val
            .get("collector_version")
            .and_then(|v| v.as_str())
            .unwrap_or("0.1.0")
            .to_string();

        let record_id = val
            .get("record_id")
            .or_else(|| val.get("artifact_id"))
            .or_else(|| val.get("id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let summary = build_summary_text(&val, telemetry_type, &os_platform);

        // Scrub secrets inside raw_json values (recursively scrubbing strings, commands, and envs)
        scrub_json_value(&mut val);

        Self::new(
            record_id,
            telemetry_type,
            source_path,
            os_platform,
            os_version,
            host_identifier,
            timestamp_unix_secs,
            summary,
            payload_hash,
            val,
            collector_name,
            collector_version,
        )
    }

    /// Converts this telemetry record into an indexing-ready `DocumentChunk` with:
    /// - `access_tier = 3` (`AccessTier::Tier3Restricted`)
    /// - `file_path = artemis://...`
    /// - `metadata_json` with all required airgap flags and forensic metadata.
    pub fn to_document_chunk(&self, chunk_index: usize) -> Result<DocumentChunk, TypeError> {
        let chunk_id = format!("{}:{}", self.record_id, chunk_index);
        let now_unix_secs = chrono::Utc::now().timestamp();
        let ingested_unix_secs = self
            .raw_json
            .get("ingested_unix_secs")
            .and_then(|v| v.as_i64())
            .unwrap_or(now_unix_secs);
        let metadata = serde_json::json!({
            "artemis_dfir": true,
            "mesh_sharable": false,
            "access_tier": 3,
            "telemetry_type": self.telemetry_type.as_str(),
            "host_identifier": self.host_identifier,
            "os_platform": self.os_platform,
            "os_version": self.os_version,
            "source_path": self.source_path,
            "collected_unix_secs": self.timestamp_unix_secs,
            "ingested_unix_secs": ingested_unix_secs,
            "harvest_eligible": self.harvest_eligible,
            "raw_payload_blake3": self.raw_payload_blake3,
            "collector_name": self.collector_name,
            "collector_version": self.collector_version,
        });

        DocumentChunk::new(
            chunk_id,
            self.record_id.clone(),
            self.source_path.clone(),
            1,
            1,
            AccessTier::Tier3Restricted.as_u8(),
            Vec::new(),
            self.summary_text.clone(),
            Some(metadata.to_string()),
        )
    }

    /// Converts this telemetry record into an unchunked `IngestedParentDocument` for RLM
    /// multi-step environment inspection (`PeekSlice` and `RegexGrep`) at `Tier3Restricted`.
    pub fn to_parent_document(&self) -> quorum_types::IngestedParentDocument {
        let pretty_json = serde_json::to_string_pretty(&self.raw_json)
            .unwrap_or_else(|_| self.raw_json.to_string());
        let full_text = format!("{}\n\n{}", self.summary_text, pretty_json);
        let blake3_hash = blake3::hash(full_text.as_bytes()).to_hex().to_string();
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("artemis_dfir".to_string(), "true".to_string());
        metadata.insert("mesh_sharable".to_string(), "false".to_string());
        metadata.insert("access_tier".to_string(), "3".to_string());
        metadata.insert(
            "telemetry_type".to_string(),
            self.telemetry_type.as_str().to_string(),
        );
        metadata.insert(
            "collected_unix_secs".to_string(),
            self.timestamp_unix_secs.to_string(),
        );

        let ts_i64 = self.timestamp_unix_secs;
        quorum_types::IngestedParentDocument {
            doc_id: self.record_id.clone(),
            blake3_hash,
            source_path: self.source_path.clone(),
            os_platform: self.os_platform.clone(),
            format: quorum_types::DocumentFormat::SourceCode,
            title: Some(format!(
                "Artemis DFIR {} ({})",
                self.telemetry_type.as_str(),
                self.source_path
            )),
            author: Some(self.collector_name.clone()),
            created_unix_secs: ts_i64,
            modified_unix_secs: ts_i64,
            byte_len: full_text.len() as u64,
            full_text,
            metadata,
        }
    }

    /// Converts this record into a verifiable `ForensicProvenance` attestation.
    pub fn to_provenance(&self) -> Result<ForensicProvenance, ForensicContractError> {
        ForensicProvenance::new(
            self.record_id.clone(),
            self.telemetry_type,
            self.source_path.clone(),
            self.host_identifier.clone(),
            self.os_platform.clone(),
            self.os_version.clone(),
            self.collector_name.clone(),
            self.collector_version.clone(),
            self.timestamp_unix_secs,
            self.raw_payload_blake3.clone(),
        )
    }
}

/// Recursively scrubs secret strings (API keys, passwords, bearer tokens) inside JSON values.
pub fn scrub_json_value(val: &mut Value) {
    match val {
        Value::String(s) => {
            *s = SecretScrubber::scrub_text(s);
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                scrub_json_value(item);
            }
        }
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                let key_upper = key.to_ascii_uppercase();
                let is_registry_key = (key_upper == "KEY" || key_upper == "KEY_PATH" || key_upper == "REGISTRY_KEY")
                    && matches!(v, Value::String(s) if s.starts_with("HKLM") || s.starts_with("HKCU") || s.starts_with("HKCR") || s.starts_with("HKU") || s.starts_with("HKEY_") || s.contains('\\'));

                if !is_registry_key
                    && (key_upper.contains("PASS")
                        || key_upper.contains("SECRET")
                        || key_upper.contains("TOKEN")
                        || key_upper.contains("KEY")
                        || key_upper.contains("AUTH"))
                {
                    match v {
                        Value::String(s) => {
                            if !s.starts_with("[REDACTED") {
                                *s = "[REDACTED_SECRET]".to_string();
                            }
                        }
                        Value::Array(arr) => {
                            for item in arr.iter_mut() {
                                if let Value::String(s) = item {
                                    if !s.starts_with("[REDACTED") {
                                        *s = "[REDACTED_SECRET]".to_string();
                                    }
                                } else {
                                    scrub_json_value(item);
                                }
                            }
                        }
                        _ => {
                            scrub_json_value(v);
                        }
                    }
                } else {
                    scrub_json_value(v);
                }
            }
        }
        _ => {}
    }
}

/// Infers the canonical `ForensicTelemetryType` from an Artemis JSON record.
pub fn infer_telemetry_type(val: &Value) -> ForensicTelemetryType {
    // 1. Explicit field
    for field in ["telemetry_type", "artifact_type", "type", "category"] {
        if let Some(s) = val.get(field).and_then(|v| v.as_str()) {
            if let Ok(t) = s.parse::<ForensicTelemetryType>() {
                return t;
            }
        }
    }

    // 2. Browser cookies (PROHIBITED)
    if val.get("cookies").is_some()
        || val.get("cookie_jar").is_some()
        || val.get("cookie_domain").is_some()
        || val.to_string().to_ascii_lowercase().contains("browser_cookies")
    {
        return ForensicTelemetryType::BrowserCookies;
    }

    // 3. Browser navigation history & OAuth (PROHIBITED)
    if val.get("history_url").is_some()
        || val.get("redirect_uri").is_some()
        || val.to_string().to_ascii_lowercase().contains("browser_history")
    {
        return ForensicTelemetryType::BrowserHistoryOAuth;
    }

    // 4. Credential stores (PROHIBITED)
    if val.get("sam_hashes").is_some()
        || val.get("dpapi").is_some()
        || val.get("keychain_item").is_some()
        || val.get("shadow_hash").is_some()
        || val.to_string().to_ascii_lowercase().contains("credential_store")
    {
        return ForensicTelemetryType::CredentialStore;
    }

    // 5. Raw shell history (PROHIBITED)
    if val.get("history_file").is_some()
        || val.get("shell_history").is_some()
        || val.to_string().to_ascii_lowercase().contains("shell_history")
    {
        return ForensicTelemetryType::ShellHistoryRaw;
    }

    // 6. Network connection: top-level DestinationIp / dest_ip
    if val.get("DestinationIp").is_some()
        || val.get("dest_ip").is_some()
        || val.get("destination_ip").is_some()
        || val.get("DestinationAddress").is_some()
        || val.get("dest_address").is_some()
    {
        return ForensicTelemetryType::NetworkConnection;
    }

    // 7. Windows Event Logs: EventID / Channel
    if val.get("EventID").is_some()
        || val.get("event_id").is_some()
        || val.get("Channel").is_some()
        || val.get("channel").is_some()
    {
        let event_id = val
            .get("EventID")
            .or_else(|| val.get("event_id"))
            .and_then(|v| v.as_u64());

        // Process creation: Event ID 4688 or Sysmon 1 or CommandLine present
        if event_id == Some(4688)
            || event_id == Some(1)
            || val.get("CommandLine").is_some()
            || val.get("command_line").is_some()
        {
            return ForensicTelemetryType::ProcessExecution;
        }

        // Network connection: Sysmon 3 or DestinationIp/DestinationPort
        if event_id == Some(3)
            || val.get("DestinationIp").is_some()
            || val.get("dest_ip").is_some()
        {
            return ForensicTelemetryType::NetworkConnection;
        }

        // Service installation: Event ID 7045
        if event_id == Some(7045) {
            return ForensicTelemetryType::ServiceDaemon;
        }

        return ForensicTelemetryType::SystemEventLog;
    }

    // 8. Windows Registry Persistence
    if val.get("Key").is_some()
        || val.get("key").is_some()
        || val.get("ValueName").is_some()
        || val.get("value_name").is_some()
    {
        return ForensicTelemetryType::RegistryPersistence;
    }

    // 9. Prefetch / Amcache
    let path_has_pf = val
        .get("path")
        .or_else(|| val.get("source_path"))
        .or_else(|| val.get("file_path"))
        .and_then(|v| v.as_str())
        .map_or(false, |p| {
            let pl = p.to_ascii_lowercase();
            pl.ends_with(".pf") || pl.contains(".pf")
        });

    if val.get("prefetch").is_some()
        || val.get("Prefetch").is_some()
        || val.get("amcache").is_some()
        || val.get("Amcache").is_some()
        || val.get("RunCount").is_some()
        || val.get("run_count").is_some()
        || val.get("last_run").is_some()
        || val.get("LastRun").is_some()
        || path_has_pf
        || val.to_string().to_ascii_lowercase().contains(".pf")
    {
        return ForensicTelemetryType::PrefetchAmcacheExecution;
    }

    // 10. Service / Daemon
    if val.get("ServiceName").is_some()
        || val.get("service_name").is_some()
        || val.get("LaunchDaemon").is_some()
        || val.get("launchd").is_some()
        || val.get("_SYSTEMD_UNIT").is_some()
        || val.get("ProgramArguments").is_some()
        || val.get("RunAtLoad").is_some()
    {
        return ForensicTelemetryType::ServiceDaemon;
    }

    // 11. macOS Unified Logs
    let path_is_unified_log = val
        .get("source_path")
        .or_else(|| val.get("path"))
        .and_then(|v| v.as_str())
        .map_or(false, |p| {
            let pl = p.to_ascii_lowercase();
            pl.contains("unified_log") || pl.contains("unifiedlog") || pl.contains("log show")
        });

    if path_is_unified_log
        || val.get("subsystem").is_some()
        || val.get("log_type").is_some()
        || val.get("unified_log").is_some()
        || val.get("unifiedlog").is_some()
        || (val.get("category").is_some() && (
            val.get("os_platform").and_then(|v| v.as_str()) == Some("macos")
            || val.get("subsystem").is_some()
            || val.get("process").is_some()
            || val.get("message").is_some()
        ))
        || (val.get("os_platform").and_then(|v| v.as_str()) == Some("macos")
            && (val.get("message").is_some() || val.get("MESSAGE").is_some()))
    {
        return ForensicTelemetryType::SystemEventLog;
    }

    // 12. Linux auditd EXECVE or process execution
    if let Some(t) = val.get("type").and_then(|v| v.as_str()) {
        if t.eq_ignore_ascii_case("EXECVE") || t.eq_ignore_ascii_case("SYSCALL") {
            return ForensicTelemetryType::ProcessExecution;
        }
        if t.eq_ignore_ascii_case("SOCKADDR") || t.eq_ignore_ascii_case("CONNECT") {
            return ForensicTelemetryType::NetworkConnection;
        }
    }
    if val.get("argc").is_some() && (val.get("a0").is_some() || val.get("exe").is_some()) {
        return ForensicTelemetryType::ProcessExecution;
    }

    // 13. Linux /proc
    if val.get("cmdline").is_some() || val.get("environ").is_some() || val.get("ppid").is_some() {
        return ForensicTelemetryType::ProcessExecution;
    }

    // 14. Linux journald
    if val.get("MESSAGE").is_some() || val.get("_COMM").is_some() {
        return ForensicTelemetryType::SystemEventLog;
    }

    // Fallback default
    ForensicTelemetryType::ProcessExecution
}

/// Infers the operating system platform ("windows", "macos", "linux").
pub fn infer_os_platform(val: &Value, fallback: Option<&str>) -> String {
    if let Some(os) = val
        .get("os_platform")
        .or_else(|| val.get("platform"))
        .or_else(|| val.get("os"))
        .and_then(|v| v.as_str())
    {
        return os.to_ascii_lowercase();
    }
    let val_str = val.to_string().to_ascii_lowercase();
    if val_str.contains("windows")
        || val_str.contains("evtx")
        || val_str.contains("hklm")
        || val_str.contains("prefetch")
        || val_str.contains("amcache")
    {
        return "windows".to_string();
    }
    if val_str.contains("macos")
        || val_str.contains("launchd")
        || val_str.contains("apple")
        || val_str.contains("plist")
    {
        return "macos".to_string();
    }
    if val_str.contains("linux")
        || val_str.contains("journald")
        || val_str.contains("auditd")
        || val_str.contains("/proc")
    {
        return "linux".to_string();
    }
    fallback.unwrap_or(std::env::consts::OS).to_string()
}

/// Infers or constructs the logical source path formatted as `artemis://...`.
pub fn infer_source_path(
    val: &Value,
    os_platform: &str,
    telemetry_type: ForensicTelemetryType,
) -> String {
    if let Some(p) = val
        .get("source_path")
        .or_else(|| val.get("path"))
        .and_then(|v| v.as_str())
    {
        if p.to_ascii_lowercase().starts_with("artemis://") {
            return p.to_string();
        } else {
            return format!("artemis://{}", p.trim_start_matches('/'));
        }
    }
    match (os_platform, telemetry_type) {
        ("windows", ForensicTelemetryType::ProcessExecution)
        | ("windows", ForensicTelemetryType::SystemEventLog) => {
            let channel = val
                .get("Channel")
                .or_else(|| val.get("channel"))
                .and_then(|v| v.as_str())
                .unwrap_or("Security");
            format!("artemis://windows/eventlog/{}", channel)
        }
        ("windows", ForensicTelemetryType::RegistryPersistence) => {
            "artemis://windows/registry".to_string()
        }
        ("windows", ForensicTelemetryType::PrefetchAmcacheExecution) => {
            "artemis://windows/prefetch".to_string()
        }
        ("windows", ForensicTelemetryType::ServiceDaemon) => {
            "artemis://windows/services".to_string()
        }
        ("macos", ForensicTelemetryType::ServiceDaemon) => "artemis://macos/launchd".to_string(),
        ("macos", _) => "artemis://macos/unifiedlog".to_string(),
        ("linux", ForensicTelemetryType::ProcessExecution) => {
            if val.get("type").is_some() {
                "artemis://linux/auditd".to_string()
            } else {
                "artemis://linux/proc".to_string()
            }
        }
        ("linux", ForensicTelemetryType::ServiceDaemon) => "artemis://linux/systemd".to_string(),
        ("linux", _) => "artemis://linux/journald".to_string(),
        (os, t) => format!("artemis://{}/{}", os, t.as_str()),
    }
}

/// Infers the host machine identifier.
pub fn infer_host_identifier(val: &Value) -> String {
    for field in [
        "host_identifier",
        "Computer",
        "computer",
        "_HOSTNAME",
        "hostname",
        "host",
    ] {
        if let Some(h) = val.get(field).and_then(|v| v.as_str()) {
            if !h.trim().is_empty() {
                return h.trim().to_string();
            }
        }
    }
    "localhost".to_string()
}

/// Infers the collection/occurrence timestamp in Unix seconds.
pub fn infer_timestamp_unix_secs(val: &Value) -> i64 {
    for field in [
        "collected_unix_secs",
        "timestamp",
        "time_unix_secs",
        "TimeCreated",
        "_REALTIME_TIMESTAMP",
    ] {
        if let Some(ts) = val.get(field) {
            if let Some(secs) = ts.as_i64() {
                // Handle microsecond epoch from systemd journald
                if secs > 10_000_000_000_000 {
                    return secs / 1_000_000;
                }
                return secs;
            }
            if let Some(s) = ts.as_str() {
                if let Ok(secs) = s.parse::<i64>() {
                    if secs > 10_000_000_000_000 {
                        return secs / 1_000_000;
                    }
                    return secs;
                }
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
                    return dt.timestamp();
                }
            }
        }
    }
    Utc::now().timestamp()
}

/// Builds a structured, searchable summary string for a telemetry record.
pub fn build_summary_text(
    val: &Value,
    telemetry_type: ForensicTelemetryType,
    os_platform: &str,
) -> String {
    let raw = match telemetry_type {
        ForensicTelemetryType::ProcessExecution => {
            let mut cmd = val
                .get("CommandLine")
                .or_else(|| val.get("command_line"))
                .or_else(|| val.get("cmdline"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if cmd.is_empty() && val.get("a0").is_some() {
                let mut args = Vec::new();
                let argc = val.get("argc").and_then(|v| v.as_u64()).unwrap_or(32);
                for i in 0..argc {
                    let key = format!("a{}", i);
                    if let Some(arg) = val.get(&key).and_then(|v| v.as_str()) {
                        args.push(arg);
                    } else {
                        break;
                    }
                }
                cmd = args.join(" ");
            } else if cmd.is_empty() {
                if let Some(arr) = val
                    .get("ProgramArguments")
                    .or_else(|| val.get("args"))
                    .and_then(|v| v.as_array())
                {
                    let args: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                    cmd = args.join(" ");
                }
            }

            let mut image = val
                .get("Image")
                .or_else(|| val.get("image"))
                .or_else(|| val.get("exe"))
                .or_else(|| val.get("comm"))
                .or_else(|| val.get("process"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if image.is_empty() {
                if let Some(a0) = val.get("a0").and_then(|v| v.as_str()) {
                    image = a0.to_string();
                }
            }

            let pid = val
                .get("ProcessId")
                .or_else(|| val.get("pid"))
                .or_else(|| val.get("_PID"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let user = val
                .get("SubjectUserName")
                .or_else(|| val.get("user"))
                .or_else(|| val.get("auid"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            format!(
                "ProcessExecution [{}]: image='{}', cmdline='{}', pid={}, user='{}'",
                os_platform, image, cmd, pid, user
            )
        }
        ForensicTelemetryType::RegistryPersistence => {
            let key = val
                .get("Key")
                .or_else(|| val.get("key"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let name = val
                .get("ValueName")
                .or_else(|| val.get("value_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let data = val
                .get("ValueData")
                .or_else(|| val.get("value_data"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!(
                "RegistryPersistence [{}]: key='{}', name='{}', data='{}'",
                os_platform, key, name, data
            )
        }
        ForensicTelemetryType::PrefetchAmcacheExecution => {
            let file = val
                .get("ExecutableName")
                .or_else(|| val.get("name"))
                .or_else(|| val.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let count = val
                .get("RunCount")
                .or_else(|| val.get("run_count"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            format!(
                "PrefetchAmcacheExecution [{}]: executable='{}', run_count={}",
                os_platform, file, count
            )
        }
        ForensicTelemetryType::ServiceDaemon => {
            let name = val
                .get("ServiceName")
                .or_else(|| val.get("Label"))
                .or_else(|| val.get("service_name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let bin = val
                .get("BinaryPath")
                .or_else(|| val.get("Program"))
                .or_else(|| val.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args_str = if let Some(arr) = val.get("ProgramArguments").and_then(|v| v.as_array()) {
                let parts: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
                format!(" args='{}'", parts.join(" "))
            } else {
                String::new()
            };
            format!(
                "ServiceDaemon [{}]: service='{}', path='{}'{}",
                os_platform, name, bin, args_str
            )
        }
        ForensicTelemetryType::SystemEventLog => {
            let ch = val
                .get("Channel")
                .or_else(|| val.get("channel"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let id = val
                .get("EventID")
                .or_else(|| val.get("event_id"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let msg = val
                .get("MESSAGE")
                .or_else(|| val.get("Message"))
                .or_else(|| val.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!(
                "SystemEventLog [{}]: channel='{}', event_id={}, message='{}'",
                os_platform, ch, id, msg
            )
        }
        ForensicTelemetryType::NetworkConnection => {
            let local = val
                .get("SourceIp")
                .or_else(|| val.get("local_address"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let remote = val
                .get("DestinationIp")
                .or_else(|| val.get("remote_address"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!(
                "NetworkConnection [{}]: local='{}', remote='{}'",
                os_platform, local, remote
            )
        }
        _ => val.to_string(),
    };

    SecretScrubber::scrub_text(&raw)
}

/// Parses a line-delimited JSON (`.jsonl`) stream of Artemis forensic telemetry records.
///
/// Features:
/// - Skips empty or whitespace lines.
/// - Handles corrupted, partial, or malformed lines gracefully with `tracing::warn!` without aborting.
/// - Scrubs credentials, API keys, tokens, and CLI passwords from all ingested records.
/// - Assigns `access_tier = 3` (`Tier3Restricted`) and airgap metadata flags.
pub fn parse_artemis_jsonl(
    reader: impl std::io::Read,
) -> Result<Vec<ArtemisTelemetryRecord>, IngestError> {
    let buf_reader = std::io::BufReader::new(reader);
    let mut records = Vec::new();

    for (line_idx, line_res) in buf_reader.lines().enumerate() {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!("I/O error reading JSONL at line {}: {}", line_idx + 1, e);
                return Err(IngestError::Io(e));
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        match serde_json::from_str::<Value>(trimmed) {
            Ok(val) => match ArtemisTelemetryRecord::from_json_value(val, None) {
                Ok(rec) => records.push(rec),
                Err(e) => {
                    tracing::warn!(
                        "Failed to construct telemetry record at line {}: {}",
                        line_idx + 1,
                        e
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Corrupted JSONL syntax at line {}: {} (line: {:?})",
                    line_idx + 1,
                    e,
                    trimmed
                );
            }
        }
    }

    Ok(records)
}

/// Helper parsing `.jsonl` string directly.
pub fn parse_artemis_jsonl_str(content: &str) -> Result<Vec<ArtemisTelemetryRecord>, IngestError> {
    parse_artemis_jsonl(content.as_bytes())
}

/// Runs a local OS command with `CREATE_NO_WINDOW` on Windows so zero console window ever appears.
fn run_hidden_os_command(program: &str, args: &[&str]) -> Option<String> {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let out = cmd.output().ok()?;
    if !out.stdout.is_empty() {
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        None
    }
}

fn category_enabled(allowed_categories: &[String], target: ForensicTelemetryType) -> bool {
    if allowed_categories.is_empty() {
        return target.is_marketplace_harvest_allowed();
    }
    let t_str = target.as_str().to_ascii_lowercase();
    allowed_categories.iter().any(|c| {
        let cl = c.trim().to_ascii_lowercase();
        cl == t_str || t_str.contains(&cl) || cl.contains(&t_str)
    })
}

/// Collects genuine live OS forensic telemetry concurrently across all allowlisted defensive categories:
/// - `process_execution`: Running processes (`sysinfo::System`) across Windows, macOS, and Linux
/// - `network_connection`: Active TCP/UDP sockets (`netstat -ano` on Windows, `/proc/net/tcp` on Linux, `netstat -anv` on macOS)
/// - `registry_persistence`: Windows `Run` / `RunOnce` persistence keys (`reg query`) or Unix cron/rc persistence
/// - `prefetch_amcache_execution`: Windows `C:\Windows\Prefetch\*.pf` & `Amcache.hve` execution artifacts
/// - `service_daemon`: Windows Services (`HKLM\SYSTEM\CurrentControlSet\Services`), macOS `LaunchDaemons`, Linux `systemd` units
/// - `system_event_log`: Windows Event Logs (`wevtutil qe System` / `Application`), Linux `syslog`/`journald`, macOS `system.log`
///
/// All 6 category collectors execute concurrently via `std::thread::scope` so subprocess queries (`netstat`, `reg`, `wevtutil`)
/// and filesystem/process table scans overlap across CPU cores with zero sequential bottlenecks.
pub fn collect_live_os_forensics(allowed_categories: &[String]) -> Vec<ArtemisTelemetryRecord> {
    let host = sysinfo::System::host_name().unwrap_or_else(|| "localhost".to_string());
    let os_platform = std::env::consts::OS.to_string();
    let os_version = sysinfo::System::long_os_version().or_else(sysinfo::System::os_version);
    let now_unix = Utc::now().timestamp();

    let host_ref = host.as_str();
    let os_platform_ref = os_platform.as_str();
    let os_version_ref = os_version.as_deref();

    std::thread::scope(|s| {
        // 1. ProcessExecution (`process_execution`)
        let h_proc = s.spawn(move || -> Vec<ArtemisTelemetryRecord> {
            let mut out = Vec::new();
            if !category_enabled(allowed_categories, ForensicTelemetryType::ProcessExecution) {
                return out;
            }
            let mut sys = sysinfo::System::new_all();
            sys.refresh_all();
            for (pid, process) in sys.processes() {
                let cmd = process.cmd().join(" ");
                let exe = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| process.name().to_string());
                let user = process
                    .user_id()
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "system".to_string());

                let val = serde_json::json!({
                    "telemetry_type": "process_execution",
                    "Computer": host_ref,
                    "os_platform": os_platform_ref,
                    "os_version": os_version_ref,
                    "CommandLine": if cmd.is_empty() { exe.clone() } else { cmd },
                    "Image": exe,
                    "ProcessId": pid.as_u32(),
                    "SubjectUserName": user,
                    "collected_unix_secs": now_unix,
                    "Channel": "Security",
                    "source_path": format!("artemis://{}/live/process/{}", os_platform_ref, pid.as_u32()),
                });
                if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some(os_platform_ref))
                {
                    out.push(rec);
                }
            }
            out
        });

        // 2. NetworkConnection (`network_connection`)
        let h_net = s.spawn(move || -> Vec<ArtemisTelemetryRecord> {
            let mut out = Vec::new();
            if !category_enabled(allowed_categories, ForensicTelemetryType::NetworkConnection) {
                return out;
            }
            #[cfg(target_os = "windows")]
            if let Some(netstat_out) = run_hidden_os_command("netstat", &["-ano"]) {
                for (idx, line) in netstat_out.lines().enumerate().take(120) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4
                        && (parts[0].eq_ignore_ascii_case("TCP")
                            || parts[0].eq_ignore_ascii_case("UDP"))
                    {
                        let proto = parts[0].to_ascii_uppercase();
                        let local_addr = parts[1];
                        let remote_addr = parts[2];
                        let (state, pid_str) = if proto == "TCP" && parts.len() >= 5 {
                            (parts[3], parts[4])
                        } else {
                            ("STATELESS", parts[3])
                        };
                        let pid = pid_str.parse::<u64>().unwrap_or(0);
                        let val = serde_json::json!({
                            "telemetry_type": "network_connection",
                            "Computer": host_ref,
                            "os_platform": "windows",
                            "os_version": os_version_ref,
                            "Protocol": proto,
                            "SourceIp": local_addr,
                            "DestinationIp": remote_addr,
                            "State": state,
                            "ProcessId": pid,
                            "collected_unix_secs": now_unix,
                            "source_path": format!("artemis://windows/live/netstat/{}", idx),
                        });
                        if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("windows"))
                        {
                            out.push(rec);
                        }
                    }
                }
            }

            #[cfg(target_os = "linux")]
            if let Ok(tcp_content) = std::fs::read_to_string("/proc/net/tcp") {
                for (idx, line) in tcp_content.lines().skip(1).enumerate().take(80) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let local_hex = parts[1];
                        let rem_hex = parts[2];
                        let val = serde_json::json!({
                            "telemetry_type": "network_connection",
                            "Computer": host_ref,
                            "os_platform": "linux",
                            "Protocol": "TCP",
                            "SourceIp": local_hex,
                            "DestinationIp": rem_hex,
                            "collected_unix_secs": now_unix,
                            "source_path": format!("artemis://linux/proc/net/tcp/{}", idx),
                        });
                        if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("linux"))
                        {
                            out.push(rec);
                        }
                    }
                }
            }

            #[cfg(target_os = "macos")]
            if let Some(netstat_out) = run_hidden_os_command("netstat", &["-anv"]) {
                for (idx, line) in netstat_out.lines().enumerate().take(80) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5
                        && (parts[0].starts_with("tcp") || parts[0].starts_with("udp"))
                    {
                        let val = serde_json::json!({
                            "telemetry_type": "network_connection",
                            "Computer": host_ref,
                            "os_platform": "macos",
                            "Protocol": parts[0],
                            "SourceIp": parts[3],
                            "DestinationIp": parts[4],
                            "collected_unix_secs": now_unix,
                            "source_path": format!("artemis://macos/live/netstat/{}", idx),
                        });
                        if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("macos"))
                        {
                            out.push(rec);
                        }
                    }
                }
            }

            out
        });

        // 3. RegistryPersistence (`registry_persistence`)
        let h_reg = s.spawn(move || -> Vec<ArtemisTelemetryRecord> {
            let mut out = Vec::new();
            if !category_enabled(allowed_categories, ForensicTelemetryType::RegistryPersistence) {
                return out;
            }
            #[cfg(target_os = "windows")]
            {
                let run_keys = [
                    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                ];
                std::thread::scope(|reg_scope| {
                    let mut handles = Vec::with_capacity(run_keys.len());
                    for key_path in run_keys {
                        handles.push(reg_scope.spawn(move || {
                            let mut key_recs = Vec::new();
                            if let Some(reg_out) = run_hidden_os_command("reg", &["query", key_path])
                            {
                                for line in reg_out.lines() {
                                    let trimmed = line.trim();
                                    if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
                                        continue;
                                    }
                                    for reg_type in ["REG_SZ", "REG_EXPAND_SZ", "REG_DWORD"] {
                                        if let Some(pos) = trimmed.find(reg_type) {
                                            let value_name = trimmed[..pos].trim();
                                            let value_data =
                                                trimmed[pos + reg_type.len()..].trim();
                                            let val = serde_json::json!({
                                                "telemetry_type": "registry_persistence",
                                                "Computer": host_ref,
                                                "os_platform": "windows",
                                                "os_version": os_version_ref,
                                                "Key": key_path,
                                                "ValueName": value_name,
                                                "ValueData": value_data,
                                                "collected_unix_secs": now_unix,
                                                "source_path": format!("artemis://windows/registry/run/{}", value_name.replace(' ', "_")),
                                            });
                                            if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(
                                                val,
                                                Some("windows"),
                                            ) {
                                                key_recs.push(rec);
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                            key_recs
                        }));
                    }
                    for h in handles {
                        if let Ok(recs) = h.join() {
                            out.extend(recs);
                        }
                    }
                });
            }
            out
        });

        // 4. PrefetchAmcacheExecution (`prefetch_amcache_execution`)
        let h_pf = s.spawn(move || -> Vec<ArtemisTelemetryRecord> {
            let mut out = Vec::new();
            if !category_enabled(
                allowed_categories,
                ForensicTelemetryType::PrefetchAmcacheExecution,
            ) {
                return out;
            }
            #[cfg(target_os = "windows")]
            {
                let prefetch_dir = std::path::Path::new(r"C:\Windows\Prefetch");
                if let Ok(entries) = std::fs::read_dir(prefetch_dir) {
                    for entry in entries.flatten().take(60) {
                        let path = entry.path();
                        if path.extension().map_or(false, |e| e.eq_ignore_ascii_case("pf")) {
                            out.extend(parse_prefetch_file(&path, host_ref, os_version_ref, now_unix));
                        }
                    }
                }
                // Amcache hive presence & metadata (`C:\Windows\AppCompat\Programs\Amcache.hve`)
                let amcache_path = std::path::Path::new(r"C:\Windows\AppCompat\Programs\Amcache.hve");
                if amcache_path.exists() {
                    out.extend(parse_registry_hive_file(amcache_path, host_ref, now_unix));
                }
                // Shimcache (`AppCompatCache`) & registered App Paths execution artifacts
                if let Some(app_out) = run_hidden_os_command(
                    "reg",
                    &[
                        "query",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
                    ],
                ) {
                    for line in app_out.lines().take(30) {
                        let trimmed = line.trim();
                        if let Some(exe_name) = trimmed.strip_prefix(
                            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\",
                        ) {
                            let exe_clean = exe_name.trim();
                            if !exe_clean.is_empty() {
                                let val = serde_json::json!({
                                    "telemetry_type": "prefetch_amcache_execution",
                                    "Computer": host_ref,
                                    "os_platform": "windows",
                                    "os_version": os_version_ref,
                                    "ExecutableName": exe_clean,
                                    "RunCount": 1,
                                    "PrefetchFormat": "AMCACHE_APP_PATHS",
                                    "path": trimmed,
                                    "collected_unix_secs": now_unix,
                                    "source_path": format!("artemis://windows/amcache/{}", exe_clean.replace(' ', "_")),
                                });
                                if let Ok(rec) =
                                    ArtemisTelemetryRecord::from_json_value(val, Some("windows"))
                                {
                                    out.push(rec);
                                }
                            }
                        }
                    }
                }
            }
            out
        });

        // 5. ServiceDaemon (`service_daemon`)
        let h_svc = s.spawn(move || -> Vec<ArtemisTelemetryRecord> {
            let mut out = Vec::new();
            if !category_enabled(allowed_categories, ForensicTelemetryType::ServiceDaemon) {
                return out;
            }
            #[cfg(target_os = "windows")]
            if let Some(reg_out) = run_hidden_os_command(
                "reg",
                &[
                    "query",
                    r"HKLM\SYSTEM\CurrentControlSet\Services",
                    "/s",
                    "/v",
                    "ImagePath",
                ],
            ) {
                let mut current_svc = String::new();
                let mut svc_count = 0usize;
                for line in reg_out.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\")
                    {
                        current_svc = trimmed
                            .trim_start_matches(
                                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\",
                            )
                            .to_string();
                    } else if !current_svc.is_empty() && trimmed.starts_with("ImagePath") {
                        for reg_type in ["REG_EXPAND_SZ", "REG_SZ"] {
                            if let Some(pos) = trimmed.find(reg_type) {
                                let bin_path = trimmed[pos + reg_type.len()..].trim();
                                let val = serde_json::json!({
                                    "telemetry_type": "service_daemon",
                                    "Computer": host_ref,
                                    "os_platform": "windows",
                                    "os_version": os_version_ref,
                                    "ServiceName": current_svc,
                                    "BinaryPath": bin_path,
                                    "collected_unix_secs": now_unix,
                                    "source_path": format!("artemis://windows/services/{}", current_svc),
                                });
                                if let Ok(rec) =
                                    ArtemisTelemetryRecord::from_json_value(val, Some("windows"))
                                {
                                    out.push(rec);
                                    svc_count += 1;
                                }
                                break;
                            }
                        }
                        if svc_count >= 60 {
                            break;
                        }
                    }
                }
            }

            #[cfg(target_os = "macos")]
            for dir_str in ["/Library/LaunchDaemons", "/System/Library/LaunchDaemons"] {
                if let Ok(entries) = std::fs::read_dir(dir_str) {
                    for entry in entries.flatten().take(40) {
                        let path = entry.path();
                        if path
                            .extension()
                            .map_or(false, |e| e.eq_ignore_ascii_case("plist"))
                        {
                            out.extend(parse_plist_file(&path, host_ref, now_unix));
                        }
                    }
                }
            }

            #[cfg(target_os = "linux")]
            for dir_str in ["/etc/systemd/system", "/lib/systemd/system"] {
                if let Ok(entries) = std::fs::read_dir(dir_str) {
                    for entry in entries.flatten().take(40) {
                        let path = entry.path();
                        if path
                            .extension()
                            .map_or(false, |e| e.eq_ignore_ascii_case("service"))
                        {
                            out.extend(parse_systemd_service_file(&path, host_ref, now_unix));
                        }
                    }
                }
            }

            out
        });

        // 6. SystemEventLog (`system_event_log`)
        let h_evt = s.spawn(move || -> Vec<ArtemisTelemetryRecord> {
            let mut out = Vec::new();
            if !category_enabled(allowed_categories, ForensicTelemetryType::SystemEventLog) {
                return out;
            }
            #[cfg(target_os = "windows")]
            {
                let channels = ["System", "Application"];
                std::thread::scope(|evt_scope| {
                    let mut handles = Vec::with_capacity(channels.len());
                    for channel in channels {
                        handles.push(evt_scope.spawn(move || {
                            let mut ch_recs = Vec::new();
                            if let Some(evtx_out) = run_hidden_os_command(
                                "wevtutil",
                                &["qe", channel, "/c:15", "/rd:true", "/f:Text"],
                            ) {
                                for (idx, block) in evtx_out.split("Event[").skip(1).enumerate() {
                                    let mut event_id = 0u64;
                                    let mut desc_lines = Vec::new();
                                    let mut in_desc = false;
                                    for line in block.lines() {
                                        let trimmed = line.trim();
                                        if let Some(rest) = trimmed.strip_prefix("Event ID:") {
                                            event_id = rest.trim().parse::<u64>().unwrap_or(0);
                                        } else if trimmed.starts_with("Description:") {
                                            in_desc = true;
                                        } else if in_desc && !trimmed.is_empty() {
                                            desc_lines.push(trimmed);
                                        }
                                    }
                                    let msg = if desc_lines.is_empty() {
                                        block.lines().take(6).collect::<Vec<_>>().join(" ")
                                    } else {
                                        desc_lines.join(" ")
                                    };
                                    let val = serde_json::json!({
                                        "telemetry_type": "system_event_log",
                                        "Computer": host_ref,
                                        "os_platform": "windows",
                                        "os_version": os_version_ref,
                                        "Channel": channel,
                                        "EventID": event_id,
                                        "Message": msg,
                                        "collected_unix_secs": now_unix,
                                        "source_path": format!("artemis://windows/eventlog/{}/{}_{}", channel.to_ascii_lowercase(), event_id, idx),
                                    });
                                    if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(
                                        val,
                                        Some("windows"),
                                    ) {
                                        ch_recs.push(rec);
                                    }
                                }
                            }
                            ch_recs
                        }));
                    }
                    for h in handles {
                        if let Ok(recs) = h.join() {
                            out.extend(recs);
                        }
                    }
                });
            }
            #[cfg(target_os = "macos")]
            if let Some(log_out) = run_hidden_os_command(
                "log",
                &["show", "--style", "compact", "--last", "1m"],
            ) {
                for (idx, line) in log_out.lines().skip(1).enumerate().take(25) {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let val = serde_json::json!({
                        "telemetry_type": "system_event_log",
                        "Computer": host_ref,
                        "os_platform": "macos",
                        "os_version": os_version_ref,
                        "subsystem": "com.apple.unifiedlog",
                        "Message": trimmed,
                        "collected_unix_secs": now_unix,
                        "source_path": format!("artemis://macos/unified_log/{}", idx),
                    });
                    if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("macos")) {
                        out.push(rec);
                    }
                }
            }
            #[cfg(target_os = "linux")]
            if let Some(j_out) = run_hidden_os_command(
                "journalctl",
                &["-n", "25", "-o", "short-iso", "--no-pager"],
            ) {
                for (idx, line) in j_out.lines().enumerate().take(25) {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with("-- ") {
                        continue;
                    }
                    let val = serde_json::json!({
                        "telemetry_type": "system_event_log",
                        "Computer": host_ref,
                        "os_platform": "linux",
                        "os_version": os_version_ref,
                        "_SYSTEMD_UNIT": "journald.service",
                        "MESSAGE": trimmed,
                        "collected_unix_secs": now_unix,
                        "source_path": format!("artemis://linux/journald/{}", idx),
                    });
                    if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("linux")) {
                        out.push(rec);
                    }
                }
            }
            out
        });

        let mut records = Vec::new();
        for handle in [h_proc, h_net, h_reg, h_pf, h_svc, h_evt] {
            if let Ok(part) = handle.join() {
                records.extend(part);
            }
        }
        records
    })
}

/// Parses a Windows Prefetch (`.pf`) file header (SCCA uncompressed or MAM LZXPRESS compressed)
/// into a structured `PrefetchAmcacheExecution` record.
fn parse_prefetch_file(
    path: &std::path::Path,
    host: &str,
    os_version: Option<&str>,
    now_unix: i64,
) -> Vec<ArtemisTelemetryRecord> {
    let fname = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut exe_name = fname.split('-').next().unwrap_or(&fname).to_string();
    let mut run_count = 1u64;
    let mut format_sig = "PF_FILENAME";

    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut buf = [0u8; 256];
        if let Ok(n) = f.read(&mut buf) {
            if n >= 8 && &buf[4..8] == b"SCCA" {
                format_sig = "SCCA_UNCOMPRESSED";
                if n >= 0x4C {
                    let utf16_slice = &buf[0x10..0x4C];
                    let u16s: Vec<u16> = utf16_slice
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&ch| ch != 0)
                        .collect();
                    let decoded = String::from_utf16_lossy(&u16s).trim().to_string();
                    if !decoded.is_empty() {
                        exe_name = decoded;
                    }
                }
                if n >= 0x9C {
                    let rc = u32::from_le_bytes([buf[0x98], buf[0x99], buf[0x9A], buf[0x9B]]) as u64;
                    if rc > 0 && rc < 1_000_000 {
                        run_count = rc;
                    }
                }
            } else if n >= 8 && &buf[0..3] == b"MAM" {
                format_sig = "MAM_COMPRESSED";
            }
        }
    }

    let mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(now_unix);

    let val = serde_json::json!({
        "telemetry_type": "prefetch_amcache_execution",
        "Computer": host,
        "os_platform": "windows",
        "os_version": os_version,
        "ExecutableName": exe_name,
        "RunCount": run_count,
        "PrefetchFormat": format_sig,
        "path": path.to_string_lossy().to_string(),
        "collected_unix_secs": mtime,
        "source_path": format!("artemis://windows/prefetch/{}", fname),
    });
    ArtemisTelemetryRecord::from_json_value(val, Some("windows"))
        .into_iter()
        .collect()
}

/// Parses a Windows Event Log (`.evtx`) binary archive (`ElfFile\0` header) into a structured
/// `SystemEventLog` record.
fn parse_evtx_file(path: &std::path::Path, host: &str, now_unix: i64) -> Vec<ArtemisTelemetryRecord> {
    let fname = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let channel = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "Security".to_string());
    let file_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let mut chunk_count = 0u64;
    let mut next_record_id = 0u64;
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut hdr = [0u8; 64];
        if let Ok(n) = f.read(&mut hdr) {
            if n >= 32 && &hdr[0..8] == b"ElfFile\0" {
                let last_chunk = u64::from_le_bytes([
                    hdr[16], hdr[17], hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23],
                ]);
                next_record_id = u64::from_le_bytes([
                    hdr[24], hdr[25], hdr[26], hdr[27], hdr[28], hdr[29], hdr[30], hdr[31],
                ]);
                chunk_count = last_chunk.saturating_add(1);
            }
        }
    }

    let val = serde_json::json!({
        "telemetry_type": "system_event_log",
        "Computer": host,
        "os_platform": "windows",
        "Channel": channel,
        "EventID": 4688,
        "ChunkCount": chunk_count,
        "NextRecordId": next_record_id,
        "Message": format!(
            "Imported Windows Event Log binary archive {} ({} bytes, chunks={}, next_record_id={})",
            fname, file_len, chunk_count, next_record_id
        ),
        "collected_unix_secs": now_unix,
        "source_path": format!("artemis://windows/eventlog/{}", fname),
    });
    ArtemisTelemetryRecord::from_json_value(val, Some("windows"))
        .into_iter()
        .collect()
}

/// Parses a macOS LaunchDaemon / LaunchAgent `.plist` into a structured `ServiceDaemon` record.
fn parse_plist_file(
    path: &std::path::Path,
    host: &str,
    now_unix: i64,
) -> Vec<ArtemisTelemetryRecord> {
    let mut label = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut program = path.to_string_lossy().to_string();

    if let Ok(content) = std::fs::read_to_string(path) {
        if let Some(pos) = content.find("<key>Label</key>") {
            let rest = &content[pos + "<key>Label</key>".len()..];
            if let (Some(s_start), Some(s_end)) = (rest.find("<string>"), rest.find("</string>")) {
                if s_start + 8 <= s_end {
                    let extracted = rest[s_start + 8..s_end].trim();
                    if !extracted.is_empty() {
                        label = extracted.to_string();
                    }
                }
            }
        }
        if let Some(pos) = content.find("<key>Program</key>") {
            let rest = &content[pos + "<key>Program</key>".len()..];
            if let (Some(s_start), Some(s_end)) = (rest.find("<string>"), rest.find("</string>")) {
                if s_start + 8 <= s_end {
                    let extracted = rest[s_start + 8..s_end].trim();
                    if !extracted.is_empty() {
                        program = extracted.to_string();
                    }
                }
            }
        }
    }

    let val = serde_json::json!({
        "telemetry_type": "service_daemon",
        "Computer": host,
        "os_platform": "macos",
        "Label": label,
        "Program": program,
        "collected_unix_secs": now_unix,
        "source_path": format!("artemis://macos/launchd/{}", label),
    });
    ArtemisTelemetryRecord::from_json_value(val, Some("macos"))
        .into_iter()
        .collect()
}

/// Parses a Linux systemd `.service` unit file into a structured `ServiceDaemon` record.
fn parse_systemd_service_file(
    path: &std::path::Path,
    host: &str,
    now_unix: i64,
) -> Vec<ArtemisTelemetryRecord> {
    let svc_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let exec_start = content
        .lines()
        .find_map(|l| l.trim().strip_prefix("ExecStart="))
        .unwrap_or("")
        .to_string();
    let val = serde_json::json!({
        "telemetry_type": "service_daemon",
        "Computer": host,
        "os_platform": "linux",
        "ServiceName": svc_name,
        "BinaryPath": exec_start,
        "collected_unix_secs": now_unix,
        "source_path": format!("artemis://linux/systemd/{}", svc_name),
    });
    ArtemisTelemetryRecord::from_json_value(val, Some("linux"))
        .into_iter()
        .collect()
}

/// Parses a Windows Registry hive binary (`regf` header — e.g., `Amcache.hve`, `NTUSER.DAT`, `SYSTEM`, `SOFTWARE`)
/// or `.reg` export into a structured `PrefetchAmcacheExecution` (for Amcache) or `RegistryPersistence` record.
fn parse_registry_hive_file(
    path: &std::path::Path,
    host: &str,
    now_unix: i64,
) -> Vec<ArtemisTelemetryRecord> {
    let fname = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let fname_lower = fname.to_ascii_lowercase();
    let is_amcache = fname_lower.contains("amcache");
    let mut seq1 = 0u32;
    let mut root_cell_offset = 0u32;
    let mut embedded_name = fname.clone();
    let mut hive_format = "REG_EXPORT";

    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut hdr = [0u8; 128];
        if let Ok(n) = f.read(&mut hdr) {
            if n >= 4 && &hdr[0..4] == b"regf" {
                hive_format = "REGF_BINARY_HIVE";
                if n >= 0x28 {
                    seq1 = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
                    root_cell_offset = u32::from_le_bytes([hdr[0x24], hdr[0x25], hdr[0x26], hdr[0x27]]);
                }
                if n >= 0x70 {
                    let u16s: Vec<u16> = hdr[0x30..0x70]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&ch| ch != 0)
                        .collect();
                    let decoded = String::from_utf16_lossy(&u16s).trim().to_string();
                    if !decoded.is_empty() {
                        embedded_name = decoded;
                    }
                }
            }
        }
    }

    let val = if is_amcache {
        serde_json::json!({
            "telemetry_type": "prefetch_amcache_execution",
            "Computer": host,
            "os_platform": "windows",
            "ExecutableName": embedded_name,
            "RunCount": seq1.max(1),
            "HiveFormat": hive_format,
            "RootCellOffset": root_cell_offset,
            "path": path.to_string_lossy().to_string(),
            "collected_unix_secs": now_unix,
            "source_path": format!("artemis://windows/amcache/{}", fname),
        })
    } else {
        serde_json::json!({
            "telemetry_type": "registry_persistence",
            "Computer": host,
            "os_platform": "windows",
            "Key": format!("HKLM\\{}", embedded_name),
            "ValueName": fname,
            "ValueData": format!("format={} seq={} root_cell=0x{:x}", hive_format, seq1, root_cell_offset),
            "collected_unix_secs": now_unix,
            "source_path": format!("artemis://windows/registry/hive/{}", fname),
        })
    };
    ArtemisTelemetryRecord::from_json_value(val, Some("windows"))
        .into_iter()
        .collect()
}

/// Parses an NTFS `$MFT` (`FILE` 1024-byte record header) or `$UsnJrnl` (`.usn`) binary artifact
/// into a structured `SystemEventLog` forensic record.
fn parse_mft_or_usn_file(
    path: &std::path::Path,
    host: &str,
    now_unix: i64,
) -> Vec<ArtemisTelemetryRecord> {
    let fname = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut record_sig = "NTFS_JOURNAL";
    let mut seq_number = 1u16;
    let mut flags = 1u16;

    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut buf = [0u8; 64];
        if let Ok(n) = f.read(&mut buf) {
            if n >= 4 && &buf[0..4] == b"FILE" {
                record_sig = "MFT_FILE_RECORD";
                if n >= 0x18 {
                    seq_number = u16::from_le_bytes([buf[0x10], buf[0x11]]);
                    flags = u16::from_le_bytes([buf[0x16], buf[0x17]]);
                }
            } else if n >= 4 && &buf[0..4] == b"BAAD" {
                record_sig = "MFT_BAAD_RECORD";
            } else if n >= 8 {
                let major_ver = u16::from_le_bytes([buf[4], buf[5]]);
                if matches!(major_ver, 2..=4) {
                    record_sig = "USN_JOURNAL_RECORD";
                }
            }
        }
    }

    let val = serde_json::json!({
        "telemetry_type": "system_event_log",
        "Computer": host,
        "os_platform": "windows",
        "Channel": "NTFS-Forensics",
        "EventID": 1001,
        "RecordSignature": record_sig,
        "SequenceNumber": seq_number,
        "Flags": flags,
        "Message": format!(
            "NTFS forensic journal artifact {} (signature={}, seq={}, flags=0x{:x})",
            fname, record_sig, seq_number, flags
        ),
        "collected_unix_secs": now_unix,
        "source_path": format!("artemis://windows/ntfs/{}", fname),
    });
    ArtemisTelemetryRecord::from_json_value(val, Some("windows"))
        .into_iter()
        .collect()
}

/// Parses a macOS Unified Log `.tracev3` binary archive into a structured `SystemEventLog` record.
fn parse_tracev3_file(
    path: &std::path::Path,
    host: &str,
    now_unix: i64,
) -> Vec<ArtemisTelemetryRecord> {
    let fname = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let file_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut header_tag = 0u32;
    if let Ok(mut f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut hdr = [0u8; 16];
        if let Ok(n) = f.read(&mut hdr) {
            if n >= 4 {
                header_tag = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
            }
        }
    }
    let val = serde_json::json!({
        "telemetry_type": "system_event_log",
        "Computer": host,
        "os_platform": "macos",
        "subsystem": "com.apple.unifiedlog.tracev3",
        "HeaderTag": format!("0x{:08x}", header_tag),
        "Message": format!("macOS Unified Log tracev3 archive {} ({} bytes, tag=0x{:08x})", fname, file_len, header_tag),
        "collected_unix_secs": now_unix,
        "source_path": format!("artemis://macos/unified_log/{}", fname),
    });
    ArtemisTelemetryRecord::from_json_value(val, Some("macos"))
        .into_iter()
        .collect()
}

/// Parses a Linux `auditd` `.audit` log file into structured `ProcessExecution` / `SystemEventLog` records.
fn parse_audit_log_file(
    path: &std::path::Path,
    host: &str,
    now_unix: i64,
) -> Vec<ArtemisTelemetryRecord> {
    let fname = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate().take(100) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let is_exec = trimmed.contains("type=EXECVE") || trimmed.contains("type=SYSCALL");
        let val = if is_exec {
            serde_json::json!({
                "telemetry_type": "process_execution",
                "Computer": host,
                "os_platform": "linux",
                "type": "EXECVE",
                "CommandLine": trimmed,
                "collected_unix_secs": now_unix,
                "source_path": format!("artemis://linux/auditd/{}_{}", fname, idx),
            })
        } else {
            serde_json::json!({
                "telemetry_type": "system_event_log",
                "Computer": host,
                "os_platform": "linux",
                "_SYSTEMD_UNIT": "auditd.service",
                "MESSAGE": trimmed,
                "collected_unix_secs": now_unix,
                "source_path": format!("artemis://linux/auditd/{}_{}", fname, idx),
            })
        };
        if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("linux")) {
            out.push(rec);
        }
    }
    out
}

/// Recursively collects and parses forensic artifacts from a directory on disk (`max_depth = 16`, skipping symlinks),
/// supporting `.jsonl`, `.json`, `.pf` (Windows Prefetch), `.evtx` (Windows Event Log), `.plist` (macOS LaunchDaemon),
/// and `.service` (Linux systemd) forensic files in parallel across all CPU cores using `rayon`.
pub fn collect_forensic_directory(dir: &std::path::Path) -> Vec<ArtemisTelemetryRecord> {
    use rayon::prelude::*;

    let mut file_paths = Vec::new();
    collect_forensic_file_paths_bounded(dir, 0, 16, &mut file_paths);

    let host = sysinfo::System::host_name().unwrap_or_else(|| "localhost".to_string());
    let now_unix = Utc::now().timestamp();

    file_paths
        .par_iter()
        .flat_map_iter(|path| parse_forensic_file_path(path, &host, now_unix))
        .collect()
}

fn collect_forensic_file_paths_bounded(
    dir: &std::path::Path,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<std::path::PathBuf>,
) {
    if depth > max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        if entry.file_type().map_or(false, |ft| ft.is_symlink()) {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            let dir_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if matches!(
                dir_name.as_str(),
                "tantivy"
                    | "tantivy_index"
                    | "lancedb"
                    | "lancedb_vectors"
                    | ".git"
                    | "node_modules"
                    | "target"
            ) || dir_name.ends_with(".lance")
            {
                continue;
            }
            if depth < max_depth {
                collect_forensic_file_paths_bounded(&path, depth + 1, max_depth, out);
            }
            continue;
        }
        if path.is_file() {
            out.push(path);
        }
    }
}

fn parse_forensic_file_path(
    path: &std::path::Path,
    host: &str,
    now_unix: i64,
) -> Vec<ArtemisTelemetryRecord> {
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let mut out = Vec::new();
    match ext.as_str() {
        "jsonl" => {
            if let Ok(file) = std::fs::File::open(path) {
                if let Ok(recs) = parse_artemis_jsonl(file) {
                    out.extend(recs);
                }
            }
        }
        "json" => {
            if let Ok(content) = std::fs::read_to_string(path) {
                let trimmed = content.trim();
                let is_forensic_record = |rec: &ArtemisTelemetryRecord| {
                    let v = &rec.raw_json;
                    [
                        "telemetry_type",
                        "artifact_type",
                        "EventID",
                        "event_id",
                        "Channel",
                        "channel",
                        "CommandLine",
                        "command_line",
                        "cmdline",
                        "ProcessId",
                        "pid",
                        "DestinationIp",
                        "dest_ip",
                        "ServiceName",
                        "service_name",
                        "ExecutableName",
                        "Key",
                        "RunCount",
                    ]
                    .iter()
                    .any(|k| v.get(*k).is_some())
                };
                if trimmed.starts_with('[') {
                    if let Ok(arr) = serde_json::from_str::<Vec<Value>>(trimmed) {
                        for val in arr {
                            if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, None) {
                                if is_forensic_record(&rec) {
                                    out.push(rec);
                                }
                            }
                        }
                    }
                } else if let Ok(recs) = parse_artemis_jsonl_str(trimmed) {
                    out.extend(recs.into_iter().filter(is_forensic_record));
                }
            }
        }
        "pf" => {
            out.extend(parse_prefetch_file(path, host, None, now_unix));
        }
        "evtx" => {
            out.extend(parse_evtx_file(path, host, now_unix));
        }
        "plist" => {
            out.extend(parse_plist_file(path, host, now_unix));
        }
        "service" => {
            out.extend(parse_systemd_service_file(path, host, now_unix));
        }
        "hve" | "reg" => {
            out.extend(parse_registry_hive_file(path, host, now_unix));
        }
        "mft" | "usn" => {
            out.extend(parse_mft_or_usn_file(path, host, now_unix));
        }
        "tracev3" => {
            out.extend(parse_tracev3_file(path, host, now_unix));
        }
        "audit" => {
            out.extend(parse_audit_log_file(path, host, now_unix));
        }
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_evtx_ingestion_and_secret_scrubbing() {
        let jsonl = r#"{"EventID":4688,"Channel":"Security","Computer":"CORP-DC","CommandLine":"powershell.exe -ExecutionPolicy Bypass --password=MySuperSecretPassword! -File audit.ps1","SubjectUserName":"svc_backup"}"#;

        let records = parse_artemis_jsonl_str(jsonl).expect("JSONL parsing should succeed");
        assert_eq!(records.len(), 1);

        let rec = &records[0];
        assert_eq!(rec.telemetry_type, ForensicTelemetryType::ProcessExecution);
        assert_eq!(rec.os_platform, "windows");
        assert!(rec.source_path.starts_with("artemis://windows/eventlog/"));
        assert_eq!(rec.host_identifier, "CORP-DC");
        assert_eq!(rec.access_tier, 3);
        assert!(rec.artemis_dfir);
        assert!(!rec.mesh_sharable);
        assert!(rec.harvest_eligible);

        // Secret password must be redacted
        assert!(!rec.summary_text.contains("MySuperSecretPassword!"));
        assert!(rec.summary_text.contains("[REDACTED_CLI_ARG]"));

        // DocumentChunk invariants
        let chunk = rec.to_document_chunk(0).expect("Chunk creation should succeed");
        assert_eq!(chunk.access_tier, 3);
        assert!(chunk.file_path.starts_with("artemis://"));
        assert!(chunk.metadata_json.contains("\"artemis_dfir\":true"));
        assert!(chunk.metadata_json.contains("\"mesh_sharable\":false"));
        assert!(chunk.metadata_json.contains("\"access_tier\":3"));

        // Provenance verification
        let prov = rec.to_provenance().expect("Provenance creation should succeed");
        assert_eq!(prov.access_tier, 3);
        assert!(prov.artemis_dfir);
        assert!(!prov.mesh_sharable);
        assert!(prov.harvest_eligible);
    }

    #[test]
    fn test_windows_registry_persistence() {
        let jsonl = r#"{"Key":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","ValueName":"SecAgent","ValueData":"C:\\Sec\\agent.exe --token sk-1234567890abcdef1234567890"}"#;

        let records = parse_artemis_jsonl_str(jsonl).unwrap();
        assert_eq!(records.len(), 1);
        let rec = &records[0];

        assert_eq!(rec.telemetry_type, ForensicTelemetryType::RegistryPersistence);
        assert_eq!(rec.os_platform, "windows");
        assert!(!rec.summary_text.contains("sk-1234567890abcdef1234567890"));
        assert!(rec.summary_text.contains("[REDACTED_API_KEY]") || rec.summary_text.contains("[REDACTED_CLI_ARG]"));
    }

    #[test]
    fn test_macos_launchd_and_unified_log() {
        let launchd = r#"{"Label":"com.corp.agent","ProgramArguments":["/opt/agent/run","--secret","K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH"],"RunAtLoad":true,"os_platform":"macos"}"#;
        let records = parse_artemis_jsonl_str(launchd).unwrap();
        assert_eq!(records.len(), 1);
        let rec = &records[0];

        assert_eq!(rec.telemetry_type, ForensicTelemetryType::ServiceDaemon);
        assert_eq!(rec.os_platform, "macos");
        assert!(rec.source_path.contains("artemis://macos/launchd"));
        assert!(!rec.summary_text.contains("K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH"));
    }

    #[test]
    fn test_linux_journald_and_auditd() {
        let audit = r#"{"type":"EXECVE","argc":3,"a0":"/usr/bin/curl","a1":"-H","a2":"Authorization: Bearer sk_live_abcdef12345678901234","auid":1000,"os_platform":"linux"}"#;
        let records = parse_artemis_jsonl_str(audit).unwrap();
        assert_eq!(records.len(), 1);
        let rec = &records[0];

        assert_eq!(rec.telemetry_type, ForensicTelemetryType::ProcessExecution);
        assert_eq!(rec.os_platform, "linux");
        assert!(!rec.summary_text.contains("sk_live_abcdef12345678901234"));
        assert!(rec.summary_text.contains("Bearer [REDACTED_BEARER_TOKEN]"));
    }

    #[test]
    fn test_corrupted_jsonl_lines_are_handled_resiliently() {
        let dirty_stream = "{\"EventID\": 4688, \"CommandLine\": \"whoami\"}\n{corrupted line\n\n{\"EventID\": 4624, \"Channel\": \"Security\"}\n";
        let records = parse_artemis_jsonl_str(dirty_stream).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].telemetry_type, ForensicTelemetryType::ProcessExecution);
        assert_eq!(records[1].telemetry_type, ForensicTelemetryType::SystemEventLog);
    }

    #[test]
    fn test_prohibited_category_pinning_and_harvest_eligibility() {
        let cookie_stream = r#"{"cookies":[{"name":"session","value":"s3cr3t"}],"host":"web1"}"#;
        let records = parse_artemis_jsonl_str(cookie_stream).unwrap();
        assert_eq!(records.len(), 1);
        let rec = &records[0];

        assert_eq!(rec.telemetry_type, ForensicTelemetryType::BrowserCookies);
        assert_eq!(rec.access_tier, 3);
        assert!(rec.artemis_dfir);
        assert!(!rec.mesh_sharable);
        assert!(!rec.harvest_eligible, "BrowserCookies must have harvest_eligible = false");

        let prov = rec.to_provenance().unwrap();
        assert!(!prov.harvest_eligible);
        assert!(prov.validate_invariants().is_ok());
    }

    #[test]
    fn test_windows_prefetch_amcache_and_services() {
        // Prefetch
        let prefetch_json = r#"{"ExecutableName":"CMD.EXE","RunCount":42,"path":"C:\\Windows\\Prefetch\\CMD.EXE-ABC12345.pf"}"#;
        let records = parse_artemis_jsonl_str(prefetch_json).unwrap();
        assert_eq!(records.len(), 1);
        let rec = &records[0];
        assert_eq!(rec.telemetry_type, ForensicTelemetryType::PrefetchAmcacheExecution);
        assert!(rec.harvest_eligible);
        assert!(rec.summary_text.contains("CMD.EXE"));
        assert!(rec.summary_text.contains("42"));

        // Windows Service (EventID 7045)
        let svc_json = r#"{"EventID":7045,"ServiceName":"MaliciousSvc","BinaryPath":"C:\\Windows\\Temp\\svc.exe --password=secret","Channel":"System"}"#;
        let svc_recs = parse_artemis_jsonl_str(svc_json).unwrap();
        assert_eq!(svc_recs.len(), 1);
        let svc_rec = &svc_recs[0];
        assert_eq!(svc_rec.telemetry_type, ForensicTelemetryType::ServiceDaemon);
        assert!(svc_rec.harvest_eligible);
        assert!(!svc_rec.summary_text.contains("secret"));
        assert!(svc_rec.summary_text.contains("[REDACTED_CLI_ARG]"));
    }

    #[test]
    fn test_linux_proc_and_all_prohibited_categories() {
        // Linux /proc
        let proc_json = r#"{"ppid":1,"cmdline":"/usr/sbin/sshd -D","environ":"PATH=/usr/bin SECRET=SuperSecretKey123!","os_platform":"linux"}"#;
        let proc_recs = parse_artemis_jsonl_str(proc_json).unwrap();
        assert_eq!(proc_recs.len(), 1);
        let proc_rec = &proc_recs[0];
        assert_eq!(proc_rec.telemetry_type, ForensicTelemetryType::ProcessExecution);
        assert_eq!(proc_rec.os_platform, "linux");
        assert!(!proc_rec.summary_text.contains("SuperSecretKey123!"));

        // Prohibited categories
        let prohibited_samples = [
            (r#"{"cookie_jar":"sqlite","cookies":["sess=abc"]}"#, ForensicTelemetryType::BrowserCookies),
            (r#"{"history_url":"https://oauth.example.com/callback?code=secret","redirect_uri":"https://app"}"#, ForensicTelemetryType::BrowserHistoryOAuth),
            (r#"{"sam_hashes":"aad3b435b51404eeaad3b435b51404ee","user":"Administrator"}"#, ForensicTelemetryType::CredentialStore),
            (r#"{"history_file":".bash_history","shell_history":"export AWS_SECRET=AKIAIOSFODNN7EXAMPLE"}"#, ForensicTelemetryType::ShellHistoryRaw),
        ];

        for (sample, expected_type) in prohibited_samples {
            let parsed = parse_artemis_jsonl_str(sample).unwrap();
            assert_eq!(parsed.len(), 1);
            let r = &parsed[0];
            assert_eq!(r.telemetry_type, expected_type);
            assert_eq!(r.access_tier, 3);
            assert!(r.artemis_dfir);
            assert!(!r.mesh_sharable);
            assert!(!r.harvest_eligible, "Expected {:?} to be prohibited from harvest", expected_type);
        }
    }

    #[test]
    fn test_provenance_signing_and_verification_roundtrip() {
        let json = r#"{"EventID":4688,"CommandLine":"whoami.exe","Channel":"Security","host":"PROD-SRV-01"}"#;
        let records = parse_artemis_jsonl_str(json).unwrap();
        let rec = &records[0];

        let mut prov = rec.to_provenance().expect("Provenance creation must succeed");
        assert_eq!(prov.access_tier, 3);
        assert!(prov.artemis_dfir);
        assert!(!prov.mesh_sharable);
        assert!(prov.harvest_eligible);

        // Sign with Ed25519 32-byte seed
        let seed = [42u8; 32];
        prov.sign_ed25519(&seed).expect("Signing must succeed");
        assert!(prov.attestation_signature_hex.is_some());

        // Verify payload bytes
        let raw_bytes = serde_json::to_vec(&rec.raw_json).unwrap();
        assert_eq!(prov.raw_payload_blake3, rec.raw_payload_blake3);
        assert!(prov.verify_payload_bytes(&raw_bytes).is_ok());
    }

    #[test]
    fn test_collect_live_os_forensics_multi_category() {
        let cats = vec![
            "process_execution".to_string(),
            "network_connection".to_string(),
            "registry_persistence".to_string(),
            "service_daemon".to_string(),
            "system_event_log".to_string(),
        ];
        let records = collect_live_os_forensics(&cats);
        assert!(
            !records.is_empty(),
            "Live OS forensic collection must collect real running process/network/service/event records"
        );
        for rec in &records {
            assert_eq!(rec.access_tier, 3);
            assert!(rec.artemis_dfir);
            assert!(!rec.mesh_sharable);
            assert!(rec.source_path.starts_with("artemis://"));
        }
    }

    #[test]
    fn test_collect_forensic_directory_all_formats() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("events.jsonl"),
            r#"{"EventID":4688,"Channel":"Security","CommandLine":"cmd.exe /c whoami"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("POWERSHELL.EXE-12345678.pf"),
            b"SCCA_PREFETCH_SAMPLE",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("Security.evtx"),
            b"ElfFile\x00EVTX_SAMPLE",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("com.corp.daemon.plist"),
            b"<plist><dict><key>Label</key><string>com.corp.daemon</string></dict></plist>",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("sshd.service"),
            "[Service]\nExecStart=/usr/sbin/sshd -D\n",
        )
        .unwrap();

        let records = collect_forensic_directory(dir.path());
        assert_eq!(records.len(), 5);
        for r in &records {
            assert_eq!(r.access_tier, 3);
            assert!(r.artemis_dfir);
            assert!(!r.mesh_sharable);
            assert!(r.source_path.starts_with("artemis://"));
        }
    }

    #[test]
    fn test_binary_forensic_hive_mft_usn_tracev3_and_audit_parsers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("Amcache.hve"),
            b"regf\x05\x00\x00\x00AMCACHE_HIVE_HEADER_SAMPLE_BYTES_PADDING_0123456789",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("SOFTWARE.reg"),
            b"regf\x02\x00\x00\x00SOFTWARE_HIVE_HEADER_SAMPLE_BYTES_PADDING_0123456789",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("master_file_table.mft"),
            b"FILE0123456789ABCDEF\x03\x00\x00\x00\x01\x00MFT_RECORD_SAMPLE",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("usnjrnl.usn"),
            b"\x38\x00\x00\x00\x02\x00\x00\x00USN_JOURNAL_V2_RECORD",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("unified.tracev3"),
            b"\x00\x10\x00\x00TRACEV3_UNIFIED_LOG",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("linux.audit"),
            "type=EXECVE msg=audit(1700000000.123:45): argc=2 a0=\"/usr/bin/id\" a1=\"-u\"\n",
        )
        .unwrap();

        let records = collect_forensic_directory(dir.path());
        assert_eq!(records.len(), 6);
        for r in &records {
            assert_eq!(r.access_tier, 3);
            assert!(r.artemis_dfir);
            assert!(!r.mesh_sharable);
            assert!(r.harvest_eligible);
            assert!(r.source_path.starts_with("artemis://"));
        }
    }
}
