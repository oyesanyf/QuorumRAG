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
        let mut metadata = serde_json::json!({
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

        if let Some(obj) = metadata.as_object_mut() {
            let meta_keys = [
                "port",
                "Port",
                "protocol",
                "Protocol",
                "event_id",
                "EventID",
                "channel",
                "Channel",
                "process_name",
                "ProcessName",
                "pid",
                "ProcessId",
                "query_name",
                "QueryName",
                "query_results",
                "QueryResults",
                "query_status",
                "QueryStatus",
                "dns_service",
                "dns_query",
            ];
            for key in meta_keys {
                if let Some(val) = self.raw_json.get(key) {
                    obj.insert(key.to_ascii_lowercase(), val.clone());
                }
            }
        }

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
            let proc_name = val
                .get("ProcessName")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let event_date = val
                .get("EventDate")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let host = val
                .get("Computer")
                .or_else(|| val.get("host_identifier"))
                .and_then(|v| v.as_str())
                .unwrap_or("localhost");

            if !proc_name.is_empty() && !event_date.is_empty() {
                format!(
                    "Artemis DFIR Process Execution [{}] on host '{}' (started/observed {}): Process '{}' (PID {}, user '{}') executed binary '{}' with command line '{}'.\nProcessExecution [{}]: image='{}', cmdline='{}', pid={}, user='{}'",
                    os_platform, host, event_date, proc_name, pid, user, image, cmd, os_platform, image, cmd, pid, user
                )
            } else {
                format!(
                    "ProcessExecution [{}]: image='{}', cmdline='{}', pid={}, user='{}'",
                    os_platform, image, cmd, pid, user
                )
            }
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
            let event_date = val
                .get("EventDate")
                .or_else(|| val.get("TimeCreated"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let is_dns = id == 22
                || id == 3006
                || id == 3008
                || id == 3020
                || val.get("QueryName").is_some()
                || val.get("query_name").is_some()
                || val.get("dns_query").and_then(|v| v.as_bool()).unwrap_or(false)
                || (ch.contains("Sysmon") && id == 22)
                || ch.contains("DNS-Client");

            if is_dns {
                let query_name = val
                    .get("QueryName")
                    .or_else(|| val.get("query_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let query_results = val
                    .get("QueryResults")
                    .or_else(|| val.get("query_results"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let query_status = val
                    .get("QueryStatus")
                    .or_else(|| val.get("query_status"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0");
                let proc_name = val
                    .get("ProcessName")
                    .or_else(|| val.get("process_name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let image = val
                    .get("Image")
                    .or_else(|| val.get("image"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(proc_name);
                let pid = val
                    .get("ProcessId")
                    .or_else(|| val.get("pid"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let proto = val
                    .get("Protocol")
                    .or_else(|| val.get("protocol"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("UDP");
                let port = val
                    .get("Port")
                    .or_else(|| val.get("port"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(53);
                let effective_proc = if !image.is_empty() {
                    image
                } else if !proc_name.is_empty() {
                    proc_name
                } else {
                    "unknown process"
                };
                let date_str = if event_date.is_empty() {
                    "recent timestamp"
                } else {
                    event_date
                };
                format!(
                    "DnsQuery [{}]: process='{}', pid={}, image='{}', protocol='{}', port={}, channel='{}', event_id={}, query_name='{}', query_results='{}', query_status='{}', date='{}'. {}",
                    os_platform, effective_proc, pid, image, proto, port, ch, id, query_name, query_results, query_status, date_str, msg
                )
            } else if !event_date.is_empty() {
                format!(
                    "SystemEventLog [{}]: date='{}', channel='{}', event_id={}, message='{}'.",
                    os_platform, event_date, ch, id, msg
                )
            } else {
                format!(
                    "SystemEventLog [{}]: channel='{}', event_id={}, message='{}'.",
                    os_platform, ch, id, msg
                )
            }
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
            let proc_name = val
                .get("ProcessName")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let image = val
                .get("Image")
                .and_then(|v| v.as_str())
                .unwrap_or(proc_name);
            let pid = val
                .get("ProcessId")
                .or_else(|| val.get("pid"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let proto = val
                .get("Protocol")
                .and_then(|v| v.as_str())
                .unwrap_or("TCP");
            let state = val
                .get("State")
                .and_then(|v| v.as_str())
                .unwrap_or("ACTIVE");
            let scope = val
                .get("ConnectionScope")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let internet_access = val
                .get("InternetAccess")
                .and_then(|v| v.as_bool())
                .unwrap_or(scope == "external_internet");
            let host = val
                .get("Computer")
                .or_else(|| val.get("host_identifier"))
                .and_then(|v| v.as_str())
                .unwrap_or("localhost");
            let event_date = val
                .get("EventDate")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let is_dns_socket = val.get("dns_service").is_some()
                || val.get("dns_query").and_then(|v| v.as_bool()).unwrap_or(false)
                || local.ends_with(":53")
                || local.ends_with(":853")
                || local.ends_with(":5353")
                || local.ends_with(":5355")
                || remote.ends_with(":53")
                || remote.ends_with(":853")
                || remote.ends_with(":5353")
                || remote.ends_with(":5355");

            if is_dns_socket {
                let dns_service = val.get("dns_service").and_then(|v| v.as_str()).unwrap_or("DNS");
                let dns_port = val.get("Port").or_else(|| val.get("RemotePort")).and_then(|v| v.as_u64()).unwrap_or(53);
                let label_proc = if proc_name.is_empty() {
                    if pid > 0 {
                        format!("PID {}", pid)
                    } else {
                        "active process".to_string()
                    }
                } else {
                    proc_name.to_string()
                };
                format!(
                    "DnsQuery [{}] Live Socket on host '{}' — Process '{}' (PID {}, executable '{}') holds {} socket on port {} ({}, service='{}', local='{}', remote='{}').\nNetworkConnection [{}]: process='{}', pid={}, image='{}', protocol='{}', port={}, dns_service='{}', state='{}', local='{}', remote='{}'",
                    os_platform, host, label_proc, pid, image, proto, dns_port, state, dns_service, local, remote,
                    os_platform, label_proc, pid, image, proto, dns_port, dns_service, state, local, remote
                )
            } else if internet_access && (!proc_name.is_empty() || pid > 0) {
                let label_proc = if proc_name.is_empty() {
                    format!("PID {}", pid)
                } else {
                    proc_name.to_string()
                };
                let date_clause = if event_date.is_empty() {
                    String::new()
                } else {
                    format!(" (observed {})", event_date)
                };
                format!(
                    "Artemis DFIR Live Internet Connection [{}] on host '{}'{} — Process '{}' (PID {}, executable '{}') accessed the external internet over {} ({}) from local socket {} to remote public internet endpoint {}.\nNetworkConnection [{}]: process='{}', pid={}, image='{}', protocol='{}', state='{}', scope='external_internet', local='{}', remote='{}'",
                    os_platform, host, date_clause, label_proc, pid, image, proto, state, local, remote,
                    os_platform, label_proc, pid, image, proto, state, local, remote
                )
            } else if !proc_name.is_empty() || pid > 0 {
                let label_proc = if proc_name.is_empty() {
                    format!("PID {}", pid)
                } else {
                    proc_name.to_string()
                };
                let eff_scope = if scope.is_empty() { "local_socket" } else { scope };
                format!(
                    "Artemis DFIR Network Socket [{}] on host '{}' — Process '{}' (PID {}, executable '{}') holds {} socket ({}, scope={}) local {} -> remote {}.\nNetworkConnection [{}]: process='{}', pid={}, protocol='{}', state='{}', scope='{}', local='{}', remote='{}'",
                    os_platform, host, label_proc, pid, image, proto, state, eff_scope, local, remote,
                    os_platform, label_proc, pid, proto, state, eff_scope, local, remote
                )
            } else {
                format!(
                    "NetworkConnection [{}]: local='{}', remote='{}'",
                    os_platform, local, remote
                )
            }
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

/// Runs a local OS command with `CREATE_NO_WINDOW` on Windows and a strict 3-second wall-clock
/// deadline so hung OS utilities (`netstat`, `wevtutil`, `reg`, `lsof`) are deterministically reaped
/// and never stall async workers or console-less services.
fn run_hidden_os_command(program: &str, args: &[&str]) -> Option<String> {
    use std::io::Read;
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
    let mut child = cmd.spawn().ok()?;
    let mut stdout_pipe = child.stdout.take()?;
    let reader_handle = std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(16 * 1024);
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(3000);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }

    let bytes = reader_handle.join().ok()?;
    if !bytes.is_empty() {
        Some(String::from_utf8_lossy(&bytes).to_string())
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

/// Parses a socket endpoint string (`142.250.190.46:443`, `[2607:f8b0:4009::200e]:443`, `*:*`, or macOS `142.250.190.46.443`)
/// into `(Option<IpAddr>, Option<u16>)`.
fn parse_socket_endpoint_ip(endpoint: &str) -> (Option<std::net::IpAddr>, Option<u16>) {
    let s = endpoint.trim();
    if s.is_empty() || s.starts_with('*') {
        return (None, None);
    }
    if let Ok(sock) = s.parse::<std::net::SocketAddr>() {
        return (Some(sock.ip()), Some(sock.port()));
    }
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((ip_part, port_part)) = rest.split_once(']') {
            let clean_ip = ip_part.split('%').next().unwrap_or(ip_part);
            let ip = clean_ip.parse::<std::net::IpAddr>().ok();
            let port = port_part.trim_start_matches(':').parse::<u16>().ok();
            return (ip, port);
        }
    }
    if let Some((ip_part, port_part)) = s.rsplit_once(':') {
        let clean_ip = ip_part.split('%').next().unwrap_or(ip_part);
        if let Ok(ip) = clean_ip.parse::<std::net::IpAddr>() {
            let port = port_part.parse::<u16>().ok();
            return (Some(ip), port);
        }
    }
    // macOS `netstat -anv` uses `a.b.c.d.port`
    if let Some((ip_part, port_part)) = s.rsplit_once('.') {
        if let Ok(ip) = ip_part.parse::<std::net::IpAddr>() {
            let port = port_part.parse::<u16>().ok();
            return (Some(ip), port);
        }
    }
    (s.parse::<std::net::IpAddr>().ok(), None)
}

/// Classifies an IP address mathematically into `("external_internet", true)` for globally routable
/// public Internet endpoints vs `("loopback" | "local_network" | "unspecified", false)` for RFC1918,
/// loopback, link-local, CGNAT, multicast, ULA, or unspecified addresses.
fn classify_ip_connection_scope(ip: std::net::IpAddr) -> (&'static str, bool) {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let oct = v4.octets();
            if v4.is_unspecified() {
                ("unspecified", false)
            } else if v4.is_loopback() {
                ("loopback", false)
            } else if v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || (oct[0] == 100 && (64..=127).contains(&oct[1]))
                || oct[0] == 0
                || (oct[0] == 192 && oct[1] == 0 && oct[2] == 2)
                || (oct[0] == 198 && (oct[1] == 18 || oct[1] == 19))
                || (oct[0] == 198 && oct[1] == 51 && oct[2] == 100)
                || (oct[0] == 203 && oct[1] == 0 && oct[2] == 113)
                || oct[0] >= 240
            {
                ("local_network", false)
            } else {
                ("external_internet", true)
            }
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return classify_ip_connection_scope(std::net::IpAddr::V4(mapped_v4));
            }
            let seg = v6.segments();
            if v6.is_unspecified() {
                ("unspecified", false)
            } else if v6.is_loopback() {
                ("loopback", false)
            } else if v6.is_multicast()
                || (seg[0] & 0xfe00) == 0xfc00 // fc00::/7 Unique Local
                || (seg[0] & 0xffc0) == 0xfe80 // fe80::/10 Link-Local
                || (seg[0] == 0x2001 && seg[1] == 0x0db8) // 2001:db8::/32 Documentation
            {
                ("local_network", false)
            } else {
                ("external_internet", true)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn decode_proc_net_v4_endpoint(hex_addr_port: &str) -> Option<String> {
    let (addr_hex, port_hex) = hex_addr_port.trim().split_once(':')?;
    if addr_hex.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(addr_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let bytes = raw.to_ne_bytes();
    let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    Some(format!("{}:{}", ip, port))
}

#[cfg(target_os = "linux")]
fn decode_proc_net_tcp_state(state_hex: &str) -> &'static str {
    match state_hex.trim().to_ascii_uppercase().as_str() {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTENING",
        "0B" => "CLOSING",
        _ => "ACTIVE",
    }
}

#[cfg(target_os = "linux")]
fn build_linux_socket_inode_to_pid_map() -> std::collections::HashMap<u64, u32> {
    let mut inode_map = std::collections::HashMap::new();
    let Ok(proc_entries) = std::fs::read_dir("/proc") else {
        return inode_map;
    };
    for entry in proc_entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let fd_dir = entry.path().join("fd");
        let Ok(fds) = std::fs::read_dir(fd_dir) else {
            continue;
        };
        for fd in fds.flatten().take(256) {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                let target = link.to_string_lossy();
                if let Some(inner) = target
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                {
                    if let Ok(inode) = inner.parse::<u64>() {
                        inode_map.insert(inode, pid);
                    }
                }
            }
        }
    }
    inode_map
}

#[derive(Clone)]
struct LiveProcMeta {
    pid: u32,
    name: String,
    exe: String,
    cmd: String,
    user: String,
    start_time_unix: i64,
}

/// Collects genuine live OS forensic telemetry concurrently across all allowlisted defensive categories:
/// - `process_execution`: Running processes (`sysinfo::System`) across Windows, macOS, and Linux
/// - `network_connection`: Active TCP/UDP sockets (`netstat -ano` on Windows, `/proc/net/tcp` on Linux, `lsof`/`netstat` on macOS) joined with live process names & public Internet classification
/// - `registry_persistence`: Windows `Run` / `RunOnce` persistence keys (`reg query`) or Unix cron/rc persistence
/// - `prefetch_amcache_execution`: Windows `C:\Windows\Prefetch\*.pf` & `Amcache.hve` execution artifacts
/// - `service_daemon`: Windows Services (`HKLM\SYSTEM\CurrentControlSet\Services`), macOS `LaunchDaemons`, Linux `systemd` units
/// - `system_event_log`: Windows Event Logs (`wevtutil qe System` / `Application` / `Windows Defender` / `CodeIntegrity`), Linux `syslog`/`journald`, macOS `system.log`
///
/// All 6 category collectors execute concurrently via `std::thread::scope` so subprocess queries (`netstat`, `reg`, `wevtutil`)
/// and filesystem/process table scans overlap across CPU cores with zero sequential bottlenecks.
pub fn collect_live_os_forensics(allowed_categories: &[String]) -> Vec<ArtemisTelemetryRecord> {
    let host = sysinfo::System::host_name().unwrap_or_else(|| "localhost".to_string());
    let os_platform = std::env::consts::OS.to_string();
    let os_version = sysinfo::System::long_os_version().or_else(sysinfo::System::os_version);
    let now_dt = Utc::now();
    let now_unix = now_dt.timestamp();
    let now_rfc3339 = now_dt.to_rfc3339();

    let need_proc_table = category_enabled(allowed_categories, ForensicTelemetryType::ProcessExecution)
        || category_enabled(allowed_categories, ForensicTelemetryType::NetworkConnection);

    let mut proc_map: std::collections::HashMap<u32, LiveProcMeta> = std::collections::HashMap::new();
    if need_proc_table {
        let mut sys = sysinfo::System::new_all();
        sys.refresh_all();
        for (pid_val, process) in sys.processes() {
            let pid_u32 = pid_val.as_u32();
            let name = process.name().to_string();
            let exe = process
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| name.clone());
            let cmd_joined = process.cmd().join(" ");
            let cmd = if cmd_joined.trim().is_empty() {
                exe.clone()
            } else {
                cmd_joined
            };
            let user = process
                .user_id()
                .map(|u| u.to_string())
                .unwrap_or_else(|| "system".to_string());
            let start_raw = process.start_time() as i64;
            let start_time_unix = if start_raw > 946_684_800 {
                start_raw
            } else {
                now_unix
            };
            proc_map.insert(
                pid_u32,
                LiveProcMeta {
                    pid: pid_u32,
                    name,
                    exe,
                    cmd,
                    user,
                    start_time_unix,
                },
            );
        }
    }

    let host_ref = host.as_str();
    let os_platform_ref = os_platform.as_str();
    let os_version_ref = os_version.as_deref();
    let now_rfc3339_ref = now_rfc3339.as_str();
    let proc_map_ref = &proc_map;

    std::thread::scope(|s| {
        // 1. ProcessExecution (`process_execution`) — sorted most-recently-started first
        let h_proc = s.spawn(move || -> Vec<ArtemisTelemetryRecord> {
            let mut out = Vec::new();
            if !category_enabled(allowed_categories, ForensicTelemetryType::ProcessExecution) {
                return out;
            }
            let mut procs: Vec<&LiveProcMeta> = proc_map_ref
                .values()
                .filter(|p| {
                    let cmd_low = p.cmd.to_ascii_lowercase();
                    !cmd_low.contains("127.0.0.1:303")
                        && !cmd_low.contains("/api/query")
                        && !cmd_low.contains("/api/chat")
                })
                .collect();
            procs.sort_by(|a, b| {
                b.start_time_unix
                    .cmp(&a.start_time_unix)
                    .then_with(|| b.pid.cmp(&a.pid))
            });

            for (rank, p) in procs.into_iter().take(160).enumerate() {
                let start_iso = chrono::DateTime::from_timestamp(p.start_time_unix, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_else(|| now_rfc3339_ref.to_string());
                let val = serde_json::json!({
                    "record_id": format!("artemis:live:{}:process:{}", os_platform_ref, rank),
                    "telemetry_type": "process_execution",
                    "Computer": host_ref,
                    "os_platform": os_platform_ref,
                    "os_version": os_version_ref,
                    "ProcessName": p.name,
                    "CommandLine": p.cmd,
                    "Image": p.exe,
                    "ProcessId": p.pid,
                    "SubjectUserName": p.user,
                    "ProcessStartTimeUnix": p.start_time_unix,
                    "EventDate": start_iso,
                    "collected_unix_secs": p.start_time_unix.max(now_unix - 5),
                    "Channel": "Security",
                    "source_path": format!("artemis://{}/live/process/latest_{}", os_platform_ref, rank),
                });
                if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some(os_platform_ref))
                {
                    out.push(rec);
                }
            }
            out
        });

        // 2. NetworkConnection (`network_connection`) — joined with PID -> ProcessName/Image & external Internet scope
        let h_net = s.spawn(move || -> Vec<ArtemisTelemetryRecord> {
            let mut out = Vec::new();
            if !category_enabled(allowed_categories, ForensicTelemetryType::NetworkConnection) {
                return out;
            }

            #[derive(Clone)]
            struct RawSocketCandidate {
                proto: String,
                local_addr: String,
                remote_addr: String,
                state: String,
                pid: u32,
                proc_name: String,
                exe_path: String,
                cmd_line: String,
                proc_start_unix: i64,
                scope: &'static str,
                internet_access: bool,
                remote_port: u16,
                is_dns: bool,
                dns_port: u16,
                dns_service: &'static str,
            }

            #[cfg(target_os = "windows")]
            let (dnscache_pid, shared_access_pid) = {
                let d_pid = run_hidden_os_command("sc.exe", &["queryex", "Dnscache"]).and_then(|out| {
                    for line in out.lines() {
                        let trimmed = line.trim();
                        if let Some(rest) = trimmed.strip_prefix("PID") {
                            if let Some((_, pstr)) = rest.split_once(':') {
                                if let Ok(p) = pstr.trim().parse::<u32>() {
                                    if p > 0 {
                                        return Some(p);
                                    }
                                }
                            }
                        }
                    }
                    None
                });
                let s_pid = run_hidden_os_command("sc.exe", &["queryex", "SharedAccess"]).and_then(|out| {
                    for line in out.lines() {
                        let trimmed = line.trim();
                        if let Some(rest) = trimmed.strip_prefix("PID") {
                            if let Some((_, pstr)) = rest.split_once(':') {
                                if let Ok(p) = pstr.trim().parse::<u32>() {
                                    if p > 0 {
                                        return Some(p);
                                    }
                                }
                            }
                        }
                    }
                    None
                });
                (d_pid, s_pid)
            };
            #[cfg(not(target_os = "windows"))]
            let (dnscache_pid, shared_access_pid): (Option<u32>, Option<u32>) = (None, None);

            let mut candidates: Vec<RawSocketCandidate> = Vec::new();
            let mut push_socket = |proto: String,
                                   local_addr: String,
                                   remote_addr: String,
                                   state: String,
                                   pid: u32,
                                   fallback_name: Option<String>| {
                // Exclude QuorumRAG's own local UI HTTP loopback socket on :3031
                if (local_addr.ends_with(":3031") || remote_addr.ends_with(":3031"))
                    && (local_addr.starts_with("127.0.0.1:")
                        || remote_addr.starts_with("127.0.0.1:")
                        || local_addr.starts_with("[::1]:")
                        || remote_addr.starts_with("[::1]:"))
                {
                    return;
                }
                let (_loc_ip_opt, loc_port_opt) = parse_socket_endpoint_ip(&local_addr);
                let (rem_ip_opt, rem_port_opt) = parse_socket_endpoint_ip(&remote_addr);
                let loc_port = loc_port_opt.unwrap_or(0);
                let remote_port = rem_port_opt.unwrap_or(0);
                let is_dns = loc_port == 53
                    || loc_port == 853
                    || loc_port == 5353
                    || loc_port == 5355
                    || remote_port == 53
                    || remote_port == 853
                    || remote_port == 5353
                    || remote_port == 5355;
                let (dns_port, dns_service) = if loc_port == 53 || remote_port == 53 {
                    (53u16, "DNS")
                } else if loc_port == 853 || remote_port == 853 {
                    (853u16, "DoT")
                } else if loc_port == 5353 || remote_port == 5353 {
                    (5353u16, "mDNS")
                } else if loc_port == 5355 || remote_port == 5355 {
                    (5355u16, "LLMNR")
                } else {
                    (0u16, "")
                };

                let (scope, mut internet_access) = match rem_ip_opt {
                    Some(ip) => classify_ip_connection_scope(ip),
                    None => ("unspecified", false),
                };
                if remote_port == 0 || state.eq_ignore_ascii_case("LISTENING") || state.eq_ignore_ascii_case("LISTEN") {
                    internet_access = false;
                }
                let (mut eff_pid, mut proc_name, mut exe_path, mut cmd_line, proc_start_unix) =
                    if let Some(pm) = proc_map_ref.get(&pid) {
                        (
                            pid,
                            pm.name.clone(),
                            pm.exe.clone(),
                            pm.cmd.clone(),
                            pm.start_time_unix,
                        )
                    } else if pid == 0 && is_dns && os_platform_ref == "linux" {
                        let prefer_resolved = local_addr.starts_with("127.0.0.53:")
                            || local_addr.starts_with("127.0.0.54:");
                        let matched_resolver = proc_map_ref.values().find(|pm| {
                            let nl = pm.name.to_ascii_lowercase();
                            if prefer_resolved {
                                nl == "systemd-resolved"
                            } else {
                                matches!(
                                    nl.as_str(),
                                    "systemd-resolved"
                                        | "dnsmasq"
                                        | "unbound"
                                        | "named"
                                        | "coredns"
                                        | "avahi-daemon"
                                )
                            }
                        });
                        if let Some(pm) = matched_resolver {
                            (
                                pm.pid,
                                pm.name.clone(),
                                pm.exe.clone(),
                                pm.cmd.clone(),
                                pm.start_time_unix,
                            )
                        } else {
                            (0, String::new(), String::new(), String::new(), 0)
                        }
                    } else if let Some(fb) = fallback_name.filter(|s| !s.is_empty()) {
                        (pid, fb.clone(), fb.clone(), fb, 0)
                    } else if pid == 4 && os_platform_ref == "windows" {
                        (
                            pid,
                            "System".to_string(),
                            "System".to_string(),
                            "NT Kernel & System".to_string(),
                            0,
                        )
                    } else {
                        (pid, String::new(), String::new(), String::new(), 0)
                    };

                if Some(eff_pid) == dnscache_pid {
                    proc_name = "svchost.exe (Dnscache)".to_string();
                    if exe_path.is_empty() || exe_path == "svchost.exe" {
                        exe_path = "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s Dnscache".to_string();
                    }
                    if cmd_line.is_empty() {
                        cmd_line = "svchost.exe -k NetworkService -p -s Dnscache".to_string();
                    }
                } else if Some(eff_pid) == shared_access_pid {
                    proc_name = "svchost.exe (SharedAccess)".to_string();
                    if exe_path.is_empty() || exe_path == "svchost.exe" {
                        exe_path = "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s SharedAccess".to_string();
                    }
                    if cmd_line.is_empty() {
                        cmd_line = "svchost.exe -k netsvcs -p -s SharedAccess".to_string();
                    }
                }

                candidates.push(RawSocketCandidate {
                    proto,
                    local_addr,
                    remote_addr,
                    state,
                    pid: eff_pid,
                    proc_name,
                    exe_path,
                    cmd_line,
                    proc_start_unix,
                    scope: if internet_access {
                        "external_internet"
                    } else {
                        scope
                    },
                    internet_access,
                    remote_port,
                    is_dns,
                    dns_port,
                    dns_service,
                });
            };

            #[cfg(target_os = "windows")]
            if let Some(netstat_out) = run_hidden_os_command("netstat", &["-ano"]) {
                for line in netstat_out.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4
                        && (parts[0].eq_ignore_ascii_case("TCP")
                            || parts[0].eq_ignore_ascii_case("UDP"))
                    {
                        let proto = parts[0].to_ascii_uppercase();
                        let local_addr = parts[1].to_string();
                        let remote_addr = parts[2].to_string();
                        let (state, pid_str) = if proto == "TCP" && parts.len() >= 5 {
                            (parts[3].to_string(), parts[4])
                        } else {
                            ("STATELESS".to_string(), parts[3])
                        };
                        let pid = pid_str.parse::<u32>().unwrap_or(0);
                        push_socket(proto, local_addr, remote_addr, state, pid, None);
                    }
                }
            }

            #[cfg(target_os = "linux")]
            {
                let inode_to_pid = build_linux_socket_inode_to_pid_map();
                let proc_files: &[(&str, &str)] = &[
                    ("TCP", "/proc/net/tcp"),
                    ("UDP", "/proc/net/udp"),
                    ("TCP", "/proc/net/tcp6"),
                    ("UDP", "/proc/net/udp6"),
                ];
                for &(proto, path) in proc_files {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        for line in content.lines().skip(1) {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 10 {
                                let local_dec = decode_proc_net_v4_endpoint(parts[1])
                                    .unwrap_or_else(|| parts[1].to_string());
                                let rem_dec = decode_proc_net_v4_endpoint(parts[2])
                                    .unwrap_or_else(|| parts[2].to_string());
                                let state = if proto == "UDP" {
                                    "STATELESS".to_string()
                                } else {
                                    decode_proc_net_tcp_state(parts[3]).to_string()
                                };
                                let inode = parts[9].parse::<u64>().unwrap_or(0);
                                let pid = inode_to_pid.get(&inode).copied().unwrap_or(0);
                                push_socket(proto.to_string(), local_dec, rem_dec, state, pid, None);
                            }
                        }
                    }
                }
            }

            #[cfg(target_os = "macos")]
            {
                if let Some(lsof_out) = run_hidden_os_command("lsof", &["-nP", "-iTCP", "-iUDP"]) {
                    for line in lsof_out.lines().skip(1) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 9 {
                            let cmd_name = parts[0].to_string();
                            let pid = parts[1].parse::<u32>().unwrap_or(0);
                            let proto = if parts[7].eq_ignore_ascii_case("UDP") {
                                "UDP".to_string()
                            } else {
                                "TCP".to_string()
                            };
                            let name_col = parts[8];
                            let state = parts
                                .get(9)
                                .map(|s| s.trim_matches(&['(', ')'][..]).to_string())
                                .unwrap_or_else(|| "ACTIVE".to_string());
                            if let Some((loc, rem)) = name_col.split_once("->") {
                                push_socket(
                                    proto,
                                    loc.to_string(),
                                    rem.to_string(),
                                    state,
                                    pid,
                                    Some(cmd_name),
                                );
                            } else {
                                push_socket(
                                    proto,
                                    name_col.to_string(),
                                    "*:*".to_string(),
                                    state,
                                    pid,
                                    Some(cmd_name),
                                );
                            }
                        }
                    }
                } else if let Some(netstat_out) = run_hidden_os_command("netstat", &["-anv"]) {
                    for line in netstat_out.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 9
                            && (parts[0].starts_with("tcp") || parts[0].starts_with("udp"))
                        {
                            let proto = parts[0].to_ascii_uppercase();
                            let local_addr = parts[3].to_string();
                            let remote_addr = parts[4].to_string();
                            let state = parts[5].to_string();
                            let pid = parts.get(8).and_then(|p| p.parse::<u32>().ok()).unwrap_or(0);
                            push_socket(proto, local_addr, remote_addr, state, pid, None);
                        }
                    }
                }
            }

            // Sort deterministically:
            // 1. External public Internet connections FIRST (`internet_access == true`)
            // 2. Active `ESTABLISHED` / `SYN_SENT` connections ahead of `TIME_WAIT` / `LISTENING`
            // 3. Connections with a resolved live user/system process (`!proc_name.is_empty()`) first
            // 4. Most recently started process (`proc_start_unix` descending) first!
            let state_rank = |st: &str| -> u8 {
                if st.eq_ignore_ascii_case("ESTABLISHED") {
                    4
                } else if st.eq_ignore_ascii_case("SYN_SENT") || st.eq_ignore_ascii_case("SYN_RECV") {
                    3
                } else if st.eq_ignore_ascii_case("CLOSE_WAIT") || st.eq_ignore_ascii_case("FIN_WAIT1") || st.eq_ignore_ascii_case("FIN_WAIT2") {
                    2
                } else if st.eq_ignore_ascii_case("TIME_WAIT") || st.eq_ignore_ascii_case("STATELESS") {
                    1
                } else {
                    0
                }
            };

            candidates.sort_by(|a, b| {
                let a_std_dns = a.dns_port == 53 || a.dns_port == 853;
                let b_std_dns = b.dns_port == 53 || b.dns_port == 853;
                b.is_dns
                    .cmp(&a.is_dns)
                    .then_with(|| b_std_dns.cmp(&a_std_dns))
                    .then_with(|| b.internet_access.cmp(&a.internet_access))
                    .then_with(|| state_rank(&b.state).cmp(&state_rank(&a.state)))
                    .then_with(|| (!b.proc_name.is_empty()).cmp(&(!a.proc_name.is_empty())))
                    .then_with(|| b.proc_start_unix.cmp(&a.proc_start_unix))
                    .then_with(|| b.pid.cmp(&a.pid))
            });

            // Deduplicate identical (pid, remote_addr, state) tuples while keeping bounded rich coverage
            let mut seen_tuples = std::collections::HashSet::new();
            let mut dns_rank = 0usize;
            let mut ext_rank = 0usize;
            let mut local_rank = 0usize;

            for cand in candidates {
                let dedup_key = format!("{}:{}:{}", cand.pid, cand.remote_addr, cand.state);
                if !seen_tuples.insert(dedup_key) {
                    continue;
                }
                if cand.is_dns {
                    if dns_rank < 32 {
                        let rank = dns_rank;
                        dns_rank += 1;
                        let val = serde_json::json!({
                            "record_id": format!("artemis:live:{}:dns:socket:{}", os_platform_ref, rank),
                            "telemetry_type": "network_connection",
                            "Computer": host_ref,
                            "os_platform": os_platform_ref,
                            "os_version": os_version_ref,
                            "Protocol": cand.proto,
                            "SourceIp": cand.local_addr,
                            "DestinationIp": cand.remote_addr,
                            "RemotePort": cand.remote_port,
                            "Port": cand.dns_port,
                            "State": cand.state,
                            "ProcessId": cand.pid,
                            "ProcessName": cand.proc_name,
                            "Image": cand.exe_path,
                            "CommandLine": cand.cmd_line,
                            "ProcessStartTimeUnix": cand.proc_start_unix,
                            "InternetAccess": cand.internet_access,
                            "ConnectionScope": if cand.internet_access { "external_internet" } else { cand.scope },
                            "dns_service": cand.dns_service,
                            "dns_query": true,
                            "EventDate": now_rfc3339_ref,
                            "collected_unix_secs": now_unix.saturating_sub(rank as i64),
                            "source_path": format!("artemis://{}/live/dns/socket_{}", os_platform_ref, rank),
                        });
                        if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some(os_platform_ref)) {
                            out.push(rec);
                        }
                    }
                } else if cand.internet_access {
                    if ext_rank >= 48 {
                        continue;
                    }
                    let rank = ext_rank;
                    ext_rank += 1;
                    let val = serde_json::json!({
                        "record_id": format!("artemis:live:{}:net:internet:{}", os_platform_ref, rank),
                        "telemetry_type": "network_connection",
                        "Computer": host_ref,
                        "os_platform": os_platform_ref,
                        "os_version": os_version_ref,
                        "Protocol": cand.proto,
                        "SourceIp": cand.local_addr,
                        "DestinationIp": cand.remote_addr,
                        "RemotePort": cand.remote_port,
                        "State": cand.state,
                        "ProcessId": cand.pid,
                        "ProcessName": cand.proc_name,
                        "Image": cand.exe_path,
                        "CommandLine": cand.cmd_line,
                        "ProcessStartTimeUnix": cand.proc_start_unix,
                        "InternetAccess": true,
                        "ConnectionScope": "external_internet",
                        "EventDate": now_rfc3339_ref,
                        "collected_unix_secs": now_unix.saturating_sub(rank as i64),
                        "source_path": format!("artemis://{}/live/network/internet_{}", os_platform_ref, rank),
                    });
                    if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some(os_platform_ref)) {
                        out.push(rec);
                    }
                } else {
                    if local_rank >= 24 {
                        continue;
                    }
                    let rank = local_rank;
                    local_rank += 1;
                    let val = serde_json::json!({
                        "record_id": format!("artemis:live:{}:net:socket:{}", os_platform_ref, rank),
                        "telemetry_type": "network_connection",
                        "Computer": host_ref,
                        "os_platform": os_platform_ref,
                        "os_version": os_version_ref,
                        "Protocol": cand.proto,
                        "SourceIp": cand.local_addr,
                        "DestinationIp": cand.remote_addr,
                        "RemotePort": cand.remote_port,
                        "State": cand.state,
                        "ProcessId": cand.pid,
                        "ProcessName": cand.proc_name,
                        "Image": cand.exe_path,
                        "CommandLine": cand.cmd_line,
                        "ProcessStartTimeUnix": cand.proc_start_unix,
                        "InternetAccess": false,
                        "ConnectionScope": cand.scope,
                        "EventDate": now_rfc3339_ref,
                        "collected_unix_secs": now_unix.saturating_sub(100 + rank as i64),
                        "source_path": format!("artemis://{}/live/network/socket_{}", os_platform_ref, rank),
                    });
                    if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some(os_platform_ref)) {
                        out.push(rec);
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
                let channels: &[(&str, Option<&str>)] = &[
                    (
                        "Microsoft-Windows-Windows Defender/Operational",
                        Some("*[System[(EventID=1116 or EventID=1117 or EventID=1121 or EventID=1122)]]"),
                    ),
                    (
                        "Microsoft-Windows-CodeIntegrity/Operational",
                        Some("*[System[(EventID=3077 or EventID=3076 or EventID=3033 or EventID=3089)]]"),
                    ),
                    (
                        "Microsoft-Windows-Sysmon/Operational",
                        Some("*[System[(EventID=22)]]"),
                    ),
                    (
                        "Microsoft-Windows-DNS-Client/Operational",
                        Some("*[System[(EventID=3006 or EventID=3008 or EventID=3020)]]"),
                    ),
                    ("System", None),
                    ("Application", None),
                ];
                std::thread::scope(|evt_scope| {
                    let mut handles = Vec::with_capacity(channels.len());
                    for &(channel, query_filter) in channels {
                        handles.push(evt_scope.spawn(move || {
                            let mut ch_recs = Vec::new();
                            let evtx_out_opt = if let Some(q) = query_filter {
                                let q_arg = format!("/q:{}", q);
                                run_hidden_os_command(
                                    "wevtutil",
                                    &["qe", channel, q_arg.as_str(), "/c:15", "/rd:true", "/f:Text"],
                                )
                            } else {
                                run_hidden_os_command(
                                    "wevtutil",
                                    &["qe", channel, "/c:15", "/rd:true", "/f:Text"],
                                )
                            };
                            if let Some(evtx_out) = evtx_out_opt {
                                for (idx, block) in evtx_out.split("Event[").skip(1).enumerate() {
                                    let mut event_id = 0u64;
                                    let mut event_date = String::new();
                                    let mut user_name = String::new();
                                    let mut threat_name = String::new();
                                    let mut blocked_path = String::new();
                                    let mut process_name = String::new();
                                    let mut image_path = String::new();
                                    let mut query_name = String::new();
                                    let mut query_status = String::new();
                                    let mut query_results = String::new();
                                    let mut query_type = String::new();
                                    let mut parsed_pid = 0u64;
                                    let mut action_name = String::new();
                                    let mut desc_lines = Vec::new();
                                    let mut in_desc = false;
                                    for line in block.lines() {
                                        let trimmed = line.trim();
                                        if let Some(rest) = trimmed.strip_prefix("Event ID:") {
                                            event_id = rest.trim().parse::<u64>().unwrap_or(0);
                                        } else if let Some(rest) = trimmed.strip_prefix("Date:") {
                                            event_date = rest.trim().to_string();
                                        } else if let Some(rest) = trimmed.strip_prefix("User Name:") {
                                            user_name = rest.trim().to_string();
                                        } else if let Some(rest) = trimmed.strip_prefix("Image:") {
                                            image_path = rest.trim().to_string();
                                        } else if let Some(rest) = trimmed
                                            .strip_prefix("ProcessId:")
                                            .or_else(|| trimmed.strip_prefix("Process ID:"))
                                        {
                                            parsed_pid = rest.trim().parse::<u64>().unwrap_or(0);
                                        } else if let Some(rest) = trimmed
                                            .strip_prefix("QueryName:")
                                            .or_else(|| trimmed.strip_prefix("Query Name:"))
                                        {
                                            query_name = rest.trim().to_string();
                                        } else if let Some(rest) = trimmed
                                            .strip_prefix("QueryStatus:")
                                            .or_else(|| trimmed.strip_prefix("Query Status:"))
                                        {
                                            query_status = rest.trim().to_string();
                                        } else if let Some(rest) = trimmed
                                            .strip_prefix("QueryResults:")
                                            .or_else(|| trimmed.strip_prefix("Query Results:"))
                                        {
                                            query_results = rest.trim().to_string();
                                        } else if let Some(rest) = trimmed
                                            .strip_prefix("QueryType:")
                                            .or_else(|| trimmed.strip_prefix("Query Type:"))
                                        {
                                            query_type = rest.trim().to_string();
                                        } else if trimmed.starts_with("Description:") {
                                            in_desc = true;
                                        } else if in_desc && !trimmed.is_empty() {
                                            if let Some(r) = trimmed.strip_prefix("Name:") {
                                                if threat_name.is_empty() {
                                                    threat_name = r.trim().to_string();
                                                }
                                            } else if let Some(r) = trimmed.strip_prefix("Path:") {
                                                blocked_path = r.trim().to_string();
                                            } else if let Some(r) = trimmed.strip_prefix("Process Name:") {
                                                process_name = r.trim().to_string();
                                            } else if let Some(r) = trimmed.strip_prefix("Action:") {
                                                action_name = r.trim().to_string();
                                            }
                                            desc_lines.push(trimmed);
                                        }
                                    }
                                    let raw_desc = if desc_lines.is_empty() {
                                        block.lines().take(6).collect::<Vec<_>>().join(" ")
                                    } else {
                                        desc_lines.join(" ")
                                    };
                                    let is_defender = channel.contains("Windows Defender");
                                    let is_code_integrity = channel.contains("CodeIntegrity");
                                    let is_sysmon_dns = (channel.contains("Sysmon") && event_id == 22) || event_id == 22;
                                    let is_dns_client = channel.contains("DNS-Client") || event_id == 3006 || event_id == 3008 || event_id == 3020;
                                    let is_dns_event = is_sysmon_dns || is_dns_client;

                                    if process_name.is_empty() && !image_path.is_empty() {
                                        process_name = image_path
                                            .split(['\\', '/'])
                                            .last()
                                            .unwrap_or(&image_path)
                                            .to_string();
                                    }
                                    if image_path.is_empty() && !process_name.is_empty() {
                                        image_path = process_name.clone();
                                    }

                                    let msg = if is_dns_event {
                                        let eff_proc = if !image_path.is_empty() {
                                            image_path.as_str()
                                        } else if !process_name.is_empty() {
                                            process_name.as_str()
                                        } else {
                                            "active process"
                                        };
                                        format!(
                                            "[Forensic Host DNS Query Event] On {} (Event ID {}, Channel: {}), process '{}' (PID {}) issued DNS query for domain '{}' (Status: {}, Results: '{}'). Details: {}",
                                            if event_date.is_empty() { "recent timestamp" } else { event_date.as_str() },
                                            event_id,
                                            channel,
                                            eff_proc,
                                            parsed_pid,
                                            if query_name.is_empty() { "unknown domain" } else { query_name.as_str() },
                                            if query_status.is_empty() { "0 (SUCCESS)" } else { query_status.as_str() },
                                            if query_results.is_empty() { "resolved" } else { query_results.as_str() },
                                            raw_desc
                                        )
                                    } else if is_defender {
                                        let rank_label = if idx == 0 {
                                            "Latest Process Blocked by Antivirus (Windows Defender)"
                                        } else {
                                            "Process Blocked by Antivirus (Windows Defender)"
                                        };
                                        let target_proc = if !blocked_path.is_empty() {
                                            blocked_path.as_str()
                                        } else if !process_name.is_empty() {
                                            process_name.as_str()
                                        } else {
                                            "unknown process"
                                        };
                                        format!(
                                            "[{}] On {} (Event ID {}), Microsoft Defender Antivirus blocked and removed process or command '{}' detected as threat '{}' (Action: {}, User: {}). Details: {}",
                                            rank_label,
                                            if event_date.is_empty() { "recent timestamp" } else { event_date.as_str() },
                                            event_id,
                                            target_proc,
                                            if threat_name.is_empty() { "Malware/Trojan" } else { threat_name.as_str() },
                                            if action_name.is_empty() { "Block/Remove" } else { action_name.as_str() },
                                            if user_name.is_empty() { "SYSTEM" } else { user_name.as_str() },
                                            raw_desc
                                        )
                                    } else if is_code_integrity {
                                        let rank_label = if idx == 0 {
                                            "Latest Process Blocked by Windows CodeIntegrity (Application Control)"
                                        } else {
                                            "Process Blocked by Windows CodeIntegrity (Application Control)"
                                        };
                                        format!(
                                            "[{}] On {} (Event ID {}, User: {}), Windows CodeIntegrity blocked an unsigned or policy-violating process or executable: {}",
                                            rank_label,
                                            if event_date.is_empty() { "recent timestamp" } else { event_date.as_str() },
                                            event_id,
                                            if user_name.is_empty() { "SYSTEM" } else { user_name.as_str() },
                                            raw_desc
                                        )
                                    } else {
                                        raw_desc
                                    };
                                    let slug = if is_sysmon_dns {
                                        format!("windows_sysmon_dns_query_event_{}_{}", event_id, idx)
                                    } else if is_dns_client {
                                        format!("windows_dns_client_operational_event_{}_{}", event_id, idx)
                                    } else if is_defender {
                                        format!("windows_defender_antivirus_event_{}_{}", event_id, idx)
                                    } else if is_code_integrity {
                                        format!("windows_codeintegrity_blocked_process_event_{}_{}", event_id, idx)
                                    } else {
                                        format!(
                                            "{}_event_{}_{}",
                                            channel.to_ascii_lowercase().replace(['/', ' '], "_"),
                                            event_id,
                                            idx
                                        )
                                    };
                                    let event_unix = chrono::DateTime::parse_from_rfc3339(&event_date)
                                        .map(|dt| dt.timestamp())
                                        .unwrap_or(now_unix);
                                    let mut val = serde_json::json!({
                                        "telemetry_type": "system_event_log",
                                        "Computer": host_ref,
                                        "os_platform": "windows",
                                        "os_version": os_version_ref,
                                        "Channel": channel,
                                        "EventID": event_id,
                                        "EventDate": event_date,
                                        "UserName": user_name,
                                        "ThreatName": threat_name,
                                        "BlockedProcessPath": blocked_path,
                                        "ProcessName": process_name,
                                        "Image": image_path,
                                        "ProcessId": parsed_pid,
                                        "dns_query": is_dns_event,
                                        "Message": msg,
                                        "collected_unix_secs": event_unix,
                                        "source_path": format!("artemis://windows/eventlog/{}", slug),
                                    });
                                    if is_dns_event {
                                        if let Some(obj) = val.as_object_mut() {
                                            obj.insert("QueryName".to_string(), serde_json::json!(query_name));
                                            obj.insert("QueryStatus".to_string(), serde_json::json!(query_status));
                                            obj.insert("QueryResults".to_string(), serde_json::json!(query_results));
                                            obj.insert("QueryType".to_string(), serde_json::json!(query_type));
                                            obj.insert("Port".to_string(), serde_json::json!(53));
                                            obj.insert("Protocol".to_string(), serde_json::json!("UDP"));
                                        }
                                    }
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

        #[cfg(target_os = "windows")]
        if category_enabled(allowed_categories, ForensicTelemetryType::NetworkConnection)
            || category_enabled(allowed_categories, ForensicTelemetryType::SystemEventLog)
        {
            let has_eventlog_or_port53_dns = records.iter().any(|r| {
                r.source_path.contains("sysmon_dns")
                    || r.source_path.contains("dns_client")
                    || r.raw_json.get("Port").and_then(|v| v.as_u64()) == Some(53)
            });

            if !has_eventlog_or_port53_dns {
                let mut dnscache_live_pid = 0u32;
                // 1. Inspect Dnscache service state & PID via sc.exe queryex
                if let Some(sc_out) = run_hidden_os_command("sc.exe", &["queryex", "Dnscache"]) {
                    let mut d_pid = 0u32;
                    let mut is_running = false;
                    for line in sc_out.lines() {
                        let trimmed = line.trim();
                        if trimmed.contains("STATE") && trimmed.contains("RUNNING") {
                            is_running = true;
                        } else if let Some(rest) = trimmed.strip_prefix("PID") {
                            if let Some((_, pstr)) = rest.split_once(':') {
                                d_pid = pstr.trim().parse::<u32>().unwrap_or(0);
                            }
                        }
                    }
                    if is_running {
                        dnscache_live_pid = d_pid;
                        let val = serde_json::json!({
                            "record_id": "artemis:live:windows:dns:dnscache_service",
                            "telemetry_type": "service_daemon",
                            "Computer": host_ref,
                            "os_platform": "windows",
                            "os_version": os_version_ref,
                            "ServiceName": "Dnscache",
                            "DisplayName": "DNS Client",
                            "ProcessId": d_pid,
                            "ProcessName": "svchost.exe (Dnscache)",
                            "Image": "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s Dnscache",
                            "State": "RUNNING",
                            "Port": 53,
                            "Protocol": "UDP",
                            "dns_service": "DNS",
                            "dns_query": true,
                            "Message": format!("Windows DNS Client Service (Dnscache) is active (STATE: 4 RUNNING, PID: {}, Executable: svchost.exe) handling local asset DNS query resolution and caching.", d_pid),
                            "collected_unix_secs": now_unix.saturating_add(2),
                            "source_path": "artemis://windows/live/dns/dnscache_service",
                        });
                        if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("windows")) {
                            records.push(rec);
                        }
                    }
                }

                // 2. Query PowerShell Get-DnsClientCache or ipconfig /displaydns fallback
                if let Some(cache_out) = run_hidden_os_command(
                    "powershell",
                    &[
                        "-NoProfile",
                        "-Command",
                        "Get-DnsClientCache | Select-Object -Property Entry, Type, Status, Section, Data | ConvertTo-Json -Compress",
                    ],
                ) {
                    if let Ok(parsed_json) =
                        serde_json::from_str::<serde_json::Value>(cache_out.trim())
                    {
                        let items = if let Some(arr) = parsed_json.as_array() {
                            arr.clone()
                        } else if parsed_json.is_object() {
                            vec![parsed_json]
                        } else {
                            Vec::new()
                        };
                        for (c_idx, item) in items.into_iter().take(32).enumerate() {
                            let entry_name = item
                                .get("Entry")
                                .or_else(|| item.get("Name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if entry_name.is_empty() {
                                continue;
                            }
                            let q_type = item.get("Type").and_then(|v| v.as_u64()).unwrap_or(1);
                            let q_data = item
                                .get("Data")
                                .or_else(|| item.get("IPAddress"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let q_status = item.get("Status").and_then(|v| v.as_u64()).unwrap_or(0);
                            let q_section = item.get("Section").and_then(|v| v.as_u64()).unwrap_or(1);
                            let val = serde_json::json!({
                                "record_id": format!("artemis:live:windows:dns:cache:{}", c_idx),
                                "telemetry_type": "network_connection",
                                "Computer": host_ref,
                                "os_platform": "windows",
                                "os_version": os_version_ref,
                                "ProcessId": dnscache_live_pid,
                                "ProcessName": "svchost.exe (Dnscache)",
                                "Image": "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s Dnscache",
                                "Port": 53,
                                "Protocol": "UDP",
                                "dns_service": "DNS",
                                "dns_query": true,
                                "QueryName": entry_name,
                                "QueryResults": q_data,
                                "QueryStatus": q_status.to_string(),
                                "QueryType": q_type.to_string(),
                                "CacheSection": q_section,
                                "Message": format!("Windows DNS Client Resolver Cache Entry for '{}' (Type: {}, Section: {}, Status: {}, Data: '{}')", entry_name, q_type, q_section, q_status, q_data),
                                "collected_unix_secs": now_unix.saturating_add(1).saturating_sub(c_idx as i64),
                                "source_path": format!("artemis://windows/live/dns/cache_{}", c_idx),
                            });
                            if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("windows")) {
                                records.push(rec);
                            }
                        }
                    }
                } else if let Some(ipconfig_out) = run_hidden_os_command("ipconfig", &["/displaydns"]) {
                    let mut current_name = String::new();
                    let mut current_type = String::new();
                    let mut current_data = String::new();
                    let mut c_idx = 0usize;
                    for line in ipconfig_out.lines() {
                        let trimmed = line.trim();
                        if let Some(rest) = trimmed.strip_prefix("Record Name . . . . . :") {
                            if !current_name.is_empty() && c_idx < 32 {
                                let val = serde_json::json!({
                                    "record_id": format!("artemis:live:windows:dns:cache:{}", c_idx),
                                    "telemetry_type": "network_connection",
                                    "Computer": host_ref,
                                    "os_platform": "windows",
                                    "os_version": os_version_ref,
                                    "ProcessId": dnscache_live_pid,
                                    "ProcessName": "svchost.exe (Dnscache)",
                                    "Image": "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s Dnscache",
                                    "Port": 53,
                                    "Protocol": "UDP",
                                    "dns_service": "DNS",
                                    "dns_query": true,
                                    "QueryName": current_name,
                                    "QueryResults": current_data,
                                    "QueryType": current_type,
                                    "Message": format!("Windows DNS Client Resolver Cache Entry for '{}' (Type: {}, Data: '{}')", current_name, current_type, current_data),
                                    "collected_unix_secs": now_unix.saturating_add(1).saturating_sub(c_idx as i64),
                                    "source_path": format!("artemis://windows/live/dns/cache_{}", c_idx),
                                });
                                if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("windows")) {
                                    records.push(rec);
                                }
                                c_idx += 1;
                                current_data.clear();
                                current_type.clear();
                            }
                            current_name = rest.trim().to_string();
                        } else if let Some(rest) = trimmed.strip_prefix("Record Type . . . . . :") {
                            current_type = rest.trim().to_string();
                        } else if let Some(rest) = trimmed.strip_prefix("A (Host) Record  . . . :")
                            .or_else(|| trimmed.strip_prefix("AAAA Record . . . . . :"))
                            .or_else(|| trimmed.strip_prefix("PTR Record  . . . . . :"))
                            .or_else(|| trimmed.strip_prefix("CNAME Record  . . . . :"))
                        {
                            current_data = rest.trim().to_string();
                        }
                    }
                    if !current_name.is_empty() && c_idx < 32 {
                        let val = serde_json::json!({
                            "record_id": format!("artemis:live:windows:dns:cache:{}", c_idx),
                            "telemetry_type": "network_connection",
                            "Computer": host_ref,
                            "os_platform": "windows",
                            "os_version": os_version_ref,
                            "ProcessId": dnscache_live_pid,
                            "ProcessName": "svchost.exe (Dnscache)",
                            "Image": "C:\\Windows\\System32\\svchost.exe -k NetworkService -p -s Dnscache",
                            "Port": 53,
                            "Protocol": "UDP",
                            "dns_service": "DNS",
                            "dns_query": true,
                            "QueryName": current_name,
                            "QueryResults": current_data,
                            "QueryType": current_type,
                            "Message": format!("Windows DNS Client Resolver Cache Entry for '{}' (Type: {}, Data: '{}')", current_name, current_type, current_data),
                            "collected_unix_secs": now_unix.saturating_add(1).saturating_sub(c_idx as i64),
                            "source_path": format!("artemis://windows/live/dns/cache_{}", c_idx),
                        });
                        if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("windows")) {
                            records.push(rec);
                        }
                    }
                }
            }
        }

        #[cfg(target_os = "linux")]
        if category_enabled(allowed_categories, ForensicTelemetryType::NetworkConnection)
            || category_enabled(allowed_categories, ForensicTelemetryType::SystemEventLog)
        {
            let has_linux_dns = records.iter().any(|r| {
                r.source_path.contains("/live/dns/")
                    || r.raw_json.get("Port").and_then(|v| v.as_u64()) == Some(53)
            });
            if !has_linux_dns {
                let matched_resolver = proc_map_ref.values().find(|pm| {
                    let nl = pm.name.to_ascii_lowercase();
                    matches!(
                        nl.as_str(),
                        "systemd-resolved"
                            | "dnsmasq"
                            | "unbound"
                            | "named"
                            | "coredns"
                            | "avahi-daemon"
                            | "networkmanager"
                    )
                });
                let mut nameservers: Vec<String> = Vec::new();
                if let Ok(resolv_txt) = std::fs::read_to_string("/etc/resolv.conf") {
                    for line in resolv_txt.lines() {
                        let trimmed = line.trim();
                        if let Some(rest) = trimmed.strip_prefix("nameserver") {
                            let ns = rest.split_whitespace().next().unwrap_or("").trim();
                            if !ns.is_empty() && !nameservers.iter().any(|x| x == ns) {
                                nameservers.push(ns.to_string());
                            }
                        }
                    }
                }
                let ns_target = nameservers
                    .first()
                    .map(|ns| format!("{}:53", ns))
                    .unwrap_or_else(|| "127.0.0.53:53".to_string());
                let (r_pid, r_name, r_exe) = if let Some(pm) = matched_resolver {
                    (pm.pid, pm.name.clone(), pm.exe.clone())
                } else {
                    (
                        std::process::id(),
                        "systemd-resolved / libc-resolv".to_string(),
                        "/etc/resolv.conf".to_string(),
                    )
                };
                let val = serde_json::json!({
                    "record_id": "artemis:live:linux:dns:resolver_service",
                    "telemetry_type": "network_connection",
                    "Computer": host_ref,
                    "os_platform": "linux",
                    "os_version": os_version_ref,
                    "ProcessId": r_pid,
                    "ProcessName": r_name,
                    "Image": r_exe,
                    "Protocol": "UDP",
                    "SourceIp": "127.0.0.1:0",
                    "DestinationIp": ns_target,
                    "RemotePort": 53,
                    "Port": 53,
                    "State": "ACTIVE",
                    "dns_service": "DNS",
                    "dns_query": true,
                    "Message": format!("Linux DNS Resolver '{}' (PID {}) configured with upstream DNS nameserver '{}'.", r_name, r_pid, ns_target),
                    "collected_unix_secs": now_unix.saturating_add(2),
                    "source_path": "artemis://linux/live/dns/resolver_service",
                });
                if let Ok(rec) = ArtemisTelemetryRecord::from_json_value(val, Some("linux")) {
                    records.push(rec);
                }
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

    #[test]
    fn test_classify_ip_connection_scope_public_vs_private() {
        let public_endpoints = [
            "142.250.190.78:443",
            "1.1.1.1:53",
            "8.8.8.8.443",
            "[2607:f8b0:4005:805::200e]:443",
            "[::ffff:142.250.190.78]:443",
        ];
        for ep in public_endpoints {
            let (ip, port) = parse_socket_endpoint_ip(ep);
            let ip = ip.unwrap_or_else(|| panic!("expected IP for {ep}"));
            assert!(port.is_some(), "expected port for {ep}");
            let (scope, is_internet) = classify_ip_connection_scope(ip);
            assert_eq!(scope, "external_internet", "expected external_internet for {ep}");
            assert!(is_internet, "expected public internet=true for {ep}");
        }

        let non_internet_endpoints = [
            "127.0.0.1:3031",
            "[::1]:3031",
            "10.0.0.5:443",
            "172.16.4.2:8080",
            "192.168.1.42:54321",
            "100.64.0.1:443",
            "169.254.169.254:80",
            "[fe80::1%eth0]:443",
            "[fd00::1]:443",
            "[::ffff:192.168.1.5]:443",
            "0.0.0.0:0",
            "[::]:0",
        ];
        for ep in non_internet_endpoints {
            let (ip, _port) = parse_socket_endpoint_ip(ep);
            let ip = ip.unwrap_or_else(|| panic!("expected IP for {ep}"));
            let (_scope, is_internet) = classify_ip_connection_scope(ip);
            assert!(!is_internet, "expected public internet=false for {ep}");
        }
    }

    #[test]
    fn test_live_network_and_process_collection_populates_tier3_artemis_records() {
        let categories = vec![
            "network_connection".to_string(),
            "process_execution".to_string(),
        ];
        let records = collect_live_os_forensics(&categories);
        assert!(
            !records.is_empty(),
            "Live OS process/network collection must yield real host telemetry records"
        );
        assert!(
            records
                .iter()
                .any(|r| r.telemetry_type == ForensicTelemetryType::ProcessExecution),
            "Live OS collection must include ProcessExecution records"
        );
        for rec in &records {
            assert_eq!(rec.access_tier, 3);
            assert!(rec.artemis_dfir);
            assert!(!rec.mesh_sharable);
            assert!(rec.source_path.starts_with("artemis://"));
        }
    }
}
