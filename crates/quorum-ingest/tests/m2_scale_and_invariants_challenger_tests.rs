//! Empirical Challenger Scale & Invariants Stress Test Suite for Milestone 2:
//! Artemis DFIR Ingestion & Secret Redactor.
//!
//! EMPIRICAL VERIFICATION TARGETS:
//! 1. Cross-platform telemetry records across Windows, macOS, and Linux.
//! 2. Strict DocumentChunk invariant enforcement:
//!    - access_tier == 3
//!    - file_path starting with artemis://
//!    - metadata_json with artemis_dfir: true and mesh_sharable: false
//! 3. ForensicProvenance validation:
//!    - validate_invariants() succeeds cleanly for all generated records.
//! 4. Huge input stress testing:
//!    - 10,000 JSONL records ingestion under tight time and memory bounds.
//!    - 10 MB payload forensic dump ingestion.
//!    - Interleaved corrupted lines in high-volume streams.

use quorum_contract::ForensicTelemetryType;
use quorum_ingest::artemis::{infer_telemetry_type, parse_artemis_jsonl, parse_artemis_jsonl_str};
use serde_json::{json, Value};
use std::io::Cursor;
use std::time::Instant;

#[test]
fn test_cross_platform_telemetry_matrix_and_chunk_invariants() {
    // Comprehensive matrix of Windows, macOS, and Linux telemetry payloads
    let platform_samples = [
        // Windows Event Logs - Process Execution (4688)
        (
            "windows",
            r#"{"EventID":4688,"Channel":"Security","Computer":"WIN-DC01","CommandLine":"C:\\Windows\\System32\\cmd.exe /c echo secret","SubjectUserName":"admin","TimeCreated":"2026-11-10T01:00:00Z"}"#,
            ForensicTelemetryType::ProcessExecution,
            "artemis://windows/eventlog/Security",
        ),
        // Windows Event Logs - System (7045 Service Install)
        (
            "windows",
            r#"{"EventID":7045,"Channel":"System","Computer":"WIN-DC01","ServiceName":"MaliciousAgent","BinaryPath":"C:\\Windows\\Temp\\svc.exe"}"#,
            ForensicTelemetryType::ServiceDaemon,
            "artemis://windows/services",
        ),
        // Windows Registry Persistence
        (
            "windows",
            r#"{"Key":"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","ValueName":"Backdoor","ValueData":"powershell.exe -w hidden"}"#,
            ForensicTelemetryType::RegistryPersistence,
            "artemis://windows/registry",
        ),
        // Windows Prefetch (with explicit source path)
        (
            "windows",
            r#"{"ExecutableName":"MIMIKATZ.EXE","run_count":1,"source_path":"artemis://windows/prefetch/MIMIKATZ.EXE"}"#,
            ForensicTelemetryType::PrefetchAmcacheExecution,
            "artemis://windows/prefetch/MIMIKATZ.EXE",
        ),
        // Windows Prefetch (inferred from prefetch execution fields)
        (
            "windows",
            r#"{"ExecutableName":"CMD.EXE","run_count":42,"prefetch":true}"#,
            ForensicTelemetryType::PrefetchAmcacheExecution,
            "artemis://windows/prefetch",
        ),
        // macOS LaunchDaemon Plist
        (
            "macos",
            r#"{"Label":"com.apple.badpersistence","ProgramArguments":["/usr/local/bin/backdoor","--listen","4444"],"RunAtLoad":true,"os_platform":"macos"}"#,
            ForensicTelemetryType::ServiceDaemon,
            "artemis://macos/launchd",
        ),
        // macOS Unified Logs (with explicit category)
        (
            "macos",
            r#"{"telemetry_type":"system_event_log","process":"tccd","message":"Prompting user for access to calendar","subsystem":"com.apple.tcc","os_platform":"macos"}"#,
            ForensicTelemetryType::SystemEventLog,
            "artemis://macos/unifiedlog",
        ),
        // Linux auditd EXECVE
        (
            "linux",
            r#"{"type":"EXECVE","argc":2,"a0":"/bin/sh","a1":"-c","exe":"/bin/sh","auid":1000,"os_platform":"linux"}"#,
            ForensicTelemetryType::ProcessExecution,
            "artemis://linux/auditd",
        ),
        // Linux systemd journald
        (
            "linux",
            r#"{"MESSAGE":"sshd: Failed password for root from 192.168.1.55 port 22 ssh2","_COMM":"sshd","_PID":1234,"os_platform":"linux"}"#,
            ForensicTelemetryType::SystemEventLog,
            "artemis://linux/journald",
        ),
        // Linux /proc telemetry
        (
            "linux",
            r#"{"cmdline":"/usr/sbin/nginx -g daemon off;","ppid":1,"os_platform":"linux"}"#,
            ForensicTelemetryType::ProcessExecution,
            "artemis://linux/proc",
        ),
    ];

    for (expected_os, raw_json, expected_type, expected_path_prefix) in platform_samples {
        let records = parse_artemis_jsonl_str(raw_json)
            .unwrap_or_else(|e| panic!("Failed to parse JSON for {}: {}", expected_os, e));
        assert_eq!(records.len(), 1, "Must produce exactly 1 record");
        let rec = &records[0];

        // 1. Platform & Type Checks
        assert_eq!(
            rec.os_platform, expected_os,
            "OS platform mismatch for sample"
        );
        assert_eq!(
            rec.telemetry_type, expected_type,
            "Telemetry type mismatch for sample"
        );
        assert!(
            rec.source_path.starts_with(expected_path_prefix),
            "Source path '{}' does not start with expected prefix '{}'",
            rec.source_path,
            expected_path_prefix
        );

        // 2. Base Record Invariants
        assert_eq!(rec.access_tier, 3, "Record access_tier must strictly be 3");
        assert!(rec.artemis_dfir, "Record artemis_dfir must strictly be true");
        assert!(!rec.mesh_sharable, "Record mesh_sharable must strictly be false");
        assert!(
            rec.source_path.starts_with("artemis://"),
            "Record source_path must start with artemis://"
        );

        // 3. DocumentChunk Invariants
        let chunk = rec
            .to_document_chunk(0)
            .expect("DocumentChunk generation must succeed");
        assert_eq!(
            chunk.access_tier, 3,
            "DocumentChunk access_tier must strictly be 3"
        );
        assert!(
            chunk.file_path.starts_with("artemis://"),
            "DocumentChunk file_path must start with artemis://"
        );

        // Parse metadata_json to strictly verify attributes
        let metadata: Value = serde_json::from_str(&chunk.metadata_json)
            .expect("Chunk metadata_json must be valid JSON");
        assert_eq!(
            metadata.get("artemis_dfir").and_then(|v| v.as_bool()),
            Some(true),
            "Metadata must have artemis_dfir: true"
        );
        assert_eq!(
            metadata.get("mesh_sharable").and_then(|v| v.as_bool()),
            Some(false),
            "Metadata must have mesh_sharable: false"
        );
        assert_eq!(
            metadata.get("access_tier").and_then(|v| v.as_u64()),
            Some(3),
            "Metadata must have access_tier: 3"
        );

        // 4. ForensicProvenance Invariants & Validation
        let prov = rec
            .to_provenance()
            .expect("ForensicProvenance generation must succeed");
        assert_eq!(prov.access_tier, 3);
        assert!(prov.artemis_dfir);
        assert!(!prov.mesh_sharable);
        assert!(
            prov.validate_invariants().is_ok(),
            "ForensicProvenance invariants validation failed: {:?}",
            prov.validate_invariants().err()
        );
    }
}

#[test]
fn test_adversarial_macos_unified_log_type_inference_gap() {
    // Attack scenario: Artemis macOS unified log dump without explicit "telemetry_type"
    let unified_log = json!({
        "process": "tccd",
        "subsystem": "com.apple.tcc",
        "category": "access",
        "message": "Prompting user for access to microphone",
        "os_platform": "macos"
    });

    let inferred = infer_telemetry_type(&unified_log);
    println!("[ADVERSARIAL PROBE] Inferred type for raw macOS unified log: {:?}", inferred);

    // Verification: raw macOS Unified Log without explicit telemetry_type
    // is correctly classified as SystemEventLog
    assert_eq!(
        inferred,
        ForensicTelemetryType::SystemEventLog,
        "raw macOS Unified Log with subsystem/category must infer SystemEventLog"
    );
}

#[test]
fn test_stress_10000_jsonl_records_throughput_and_invariants() {
    // Generate 10,000 JSONL records alternating across Windows, macOS, and Linux
    println!("[STRESS] Generating 10,000 synthetic forensic telemetry records...");
    let mut buffer = Vec::with_capacity(5 * 1024 * 1024); // ~5 MB estimated
    let count = 10_000;

    for i in 0..count {
        let line = match i % 3 {
            0 => format!(
                r#"{{"record_id":"win-rec-{}","EventID":4688,"CommandLine":"C:\\Windows\\System32\\svchost.exe -k netsvcs --token sk-ant-secret1234567890abcdef1234567890","Computer":"CORP-WS-{}","SubjectUserName":"SYSTEM"}}"#,
                i, i % 50
            ),
            1 => format!(
                r#"{{"record_id":"mac-rec-{}","Label":"com.corp.agent.{}","ProgramArguments":["/opt/agent/bin","--token","ghp_1234567890abcdefghijklmnopqrstuvwxyz12"],"RunAtLoad":true,"os_platform":"macos"}}"#,
                i, i % 25
            ),
            _ => format!(
                r#"{{"record_id":"lin-rec-{}","type":"EXECVE","argc":3,"a0":"/usr/bin/curl","a1":"-H","a2":"Authorization: Bearer secret-auth-token-12345678901234","auid":{},"os_platform":"linux"}}"#,
                i, 1000 + (i % 10)
            ),
        };
        buffer.extend_from_slice(line.as_bytes());
        buffer.push(b'\n');
    }

    let payload_bytes = buffer.len();
    println!(
        "[STRESS] Generated 10,000 records ({:.2} MB). Beginning ingestion...",
        payload_bytes as f64 / (1024.0 * 1024.0)
    );

    let start = Instant::now();
    let records = parse_artemis_jsonl(Cursor::new(buffer)).expect("Batch parsing should succeed");
    let elapsed = start.elapsed();

    assert_eq!(
        records.len(),
        count,
        "All 10,000 records must be successfully parsed"
    );

    let secs = elapsed.as_secs_f64();
    let recs_per_sec = count as f64 / secs;
    let mb_per_sec = (payload_bytes as f64 / (1024.0 * 1024.0)) / secs;

    println!(
        "[STRESS PERF] Ingested 10,000 records in {:.3}s ({:.1} recs/sec, {:.2} MB/s)",
        secs, recs_per_sec, mb_per_sec
    );

    // Performance assertion: 10,000 records should process under 10 seconds in debug mode
    assert!(
        secs < 10.0,
        "Ingestion of 10,000 records took too long: {:.2}s",
        secs
    );

    // Invariant spot-check across all parsed records
    for (idx, rec) in records.iter().enumerate() {
        assert_eq!(rec.access_tier, 3);
        assert!(rec.artemis_dfir);
        assert!(!rec.mesh_sharable);
        assert!(rec.source_path.starts_with("artemis://"));

        // Spot-check every 500th chunk and provenance object
        if idx % 500 == 0 {
            let chunk = rec.to_document_chunk(0).expect("Chunk must succeed");
            assert_eq!(chunk.access_tier, 3);
            assert!(chunk.file_path.starts_with("artemis://"));
            assert!(chunk.metadata_json.contains("\"artemis_dfir\":true"));
            assert!(chunk.metadata_json.contains("\"mesh_sharable\":false"));

            let prov = rec.to_provenance().expect("Provenance must succeed");
            assert_eq!(prov.access_tier, 3);
            assert!(prov.artemis_dfir);
            assert!(!prov.mesh_sharable);
            assert!(prov.validate_invariants().is_ok());

            // Ensure secrets were scrubbed from summary
            assert!(!rec.summary_text.contains("sk-ant-secret1234567890abcdef1234567890"));
            assert!(!rec.summary_text.contains("ghp_1234567890abcdefghijklmnopqrstuvwxyz12"));
            assert!(!rec.summary_text.contains("secret-auth-token-12345678901234"));
        }
    }
}

#[test]
fn test_stress_10mb_payload_forensic_dump() {
    println!("[STRESS] Constructing 10 MB forensic dump payload...");
    let target_bytes = 10 * 1024 * 1024; // 10 MB
    let mut payload = Vec::with_capacity(target_bytes + 4096);

    let mut record_idx = 0;
    while payload.len() < target_bytes {
        record_idx += 1;
        // Construct a realistic verbose EVTX / auditd record with environment variables and long command lines
        let entry = format!(
            r#"{{"record_id":"dump-entry-{}","EventID":4688,"Channel":"Security","Computer":"ENTERPRISE-SQL-01","CommandLine":"sqlservr.exe -c -sMSSQLSERVER -dC:\\Data\\master.mdf -lC:\\Logs\\mastlog.ldf --password=SuperSecretDbPassword123! --db-uri=postgres://app_user:DbPassword2026!@10.0.1.15:5432/finance_db","Environment":"PATH=C:\\Windows;C:\\SQL API_KEY=AIzaSyA1234567890abcdef1234567890abcdef1","SubjectUserName":"sql_service"}}{}"#,
            record_idx, "\n"
        );
        payload.extend_from_slice(entry.as_bytes());
    }

    let actual_size_mb = payload.len() as f64 / (1024.0 * 1024.0);
    println!(
        "[STRESS] Built 10 MB payload ({:.2} MB, {} records). Ingesting...",
        actual_size_mb, record_idx
    );

    let start = Instant::now();
    let records = parse_artemis_jsonl(Cursor::new(payload)).expect("10 MB dump should parse cleanly");
    let duration = start.elapsed();

    assert_eq!(records.len(), record_idx, "Must parse all records in the 10 MB payload");
    println!(
        "[STRESS PERF] Ingested 10 MB payload ({:.2} MB, {} records) in {:.2}s ({:.2} MB/s)",
        actual_size_mb,
        record_idx,
        duration.as_secs_f64(),
        actual_size_mb / duration.as_secs_f64()
    );

    // Verify invariants on a sample across the large payload
    for rec in records.iter().step_by(100) {
        assert_eq!(rec.access_tier, 3);
        assert!(rec.artemis_dfir);
        assert!(!rec.mesh_sharable);
        assert!(rec.source_path.starts_with("artemis://"));
        assert!(!rec.summary_text.contains("SuperSecretDbPassword123!"));
        assert!(!rec.summary_text.contains("DbPassword2026!"));
        assert!(!rec.summary_text.contains("AIzaSyA1234567890abcdef1234567890abcdef1"));

        let prov = rec.to_provenance().expect("Provenance must succeed");
        assert!(prov.validate_invariants().is_ok());
    }
}

#[test]
fn test_stress_interleaved_malformed_and_truncated_records() {
    // 1,000 records stream with 10% corrupted lines (truncated JSON, invalid syntax, binary gibberish, empty lines)
    let mut stream = Vec::new();
    let mut valid_count = 0;

    for i in 0..1000 {
        match i % 10 {
            0 => stream.extend_from_slice(b"\n\n"), // empty lines
            1 => stream.extend_from_slice(b"{\"incomplete\":\"json\"\n"), // missing closing brace
            2 => stream.extend_from_slice(b"NOT_EVEN_JSON_GIBBERISH_DATA_HERE\n"),
            3 => stream.extend_from_slice(b"{\"EventID\": 4688, \"CommandLine\": \x00\x01\x02}\n"), // binary control chars in json
            _ => {
                valid_count += 1;
                let valid = format!(
                    r#"{{"record_id":"clean-{}","EventID":4688,"CommandLine":"whoami /user","Computer":"PC-{}"}}{}"#,
                    i, i % 10, "\n"
                );
                stream.extend_from_slice(valid.as_bytes());
            }
        }
    }

    let records = parse_artemis_jsonl(Cursor::new(stream)).expect("Must not abort on dirty stream");
    assert_eq!(
        records.len(),
        valid_count,
        "Must cleanly parse all {} valid records while ignoring all malformed/empty lines",
        valid_count
    );

    for rec in &records {
        assert_eq!(rec.access_tier, 3);
        assert!(rec.artemis_dfir);
        assert!(!rec.mesh_sharable);
        let prov = rec.to_provenance().expect("Provenance must succeed");
        assert!(prov.validate_invariants().is_ok());
    }
}
