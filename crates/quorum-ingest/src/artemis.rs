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
}
