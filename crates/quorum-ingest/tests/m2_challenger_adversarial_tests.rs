//! Empirical Adversarial Challenger Verification Suite for Milestone 2:
//! Artemis DFIR Ingestion & Secret Redactor.
//!
//! EMPIRICAL ADVERSARIAL CHALLENGE DOMAINS:
//! 1. Shannon Entropy & High-Entropy Token Fuzzing (Base64, Hex, Random symbols, boundary thresholds).
//! 2. Path & UUID False-Positive Immunity (Windows drive letters, UNC, POSIX, Artemis URIs, UUIDs).
//! 3. Docker / Network CLI Flags vs Password Flags (-p 8080:8080 vs -p SecretPass123!).
//! 4. Corrupted, Truncated, and Adversarial JSONL Streams (robustness, no-panic, stream continuation).
//! 5. Hard Airgap & Provenance Invariants (Tier 3 Restricted, local-only flags, Ed25519 verification).

use quorum_contract::ForensicTelemetryType;
use quorum_ingest::artemis::{infer_telemetry_type, parse_artemis_jsonl_str, scrub_json_value};
use quorum_ingest::secret_scrubber::{
    has_mixed_classes, is_high_entropy_secret, is_uuid_or_path, scrub_text, shannon_entropy_bits,
};
use serde_json::json;

// =========================================================================
// 1. Shannon Entropy & High-Entropy Token Fuzzing
// =========================================================================

#[test]
fn test_adversarial_shannon_entropy_mathematical_bounds() {
    // Zero length
    assert_eq!(shannon_entropy_bits(""), 0.0);

    // Uniform 1-symbol string has exactly 0 bits of entropy
    assert_eq!(shannon_entropy_bits("AAAAAAAAAAAAAAAA"), 0.0);
    assert_eq!(shannon_entropy_bits("1111111111111111"), 0.0);

    // Uniform 2-symbol alternating string has exactly log2(2) = 1.0 bit
    let alt2 = "0101010101010101";
    assert!((shannon_entropy_bits(alt2) - 1.0).abs() < 1e-6);

    // Uniform 4-symbol string has exactly log2(4) = 2.0 bits
    let alt4 = "ABCDABCDABCDABCD";
    assert!((shannon_entropy_bits(alt4) - 2.0).abs() < 1e-6);

    // Uniform 16-symbol string has exactly log2(16) = 4.0 bits
    // This mathematically proves that single-case 16-character hex strings CANNOT exceed 4.0 bits!
    let hex16 = "0123456789abcdef";
    assert!((shannon_entropy_bits(hex16) - 4.0).abs() < 1e-6);

    // Uniform 32-symbol string has exactly log2(32) = 5.0 bits
    let sym32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
    assert!((shannon_entropy_bits(sym32) - 5.0).abs() < 1e-6);
}

#[test]
fn test_adversarial_high_entropy_token_fuzzing() {
    // Deterministic pseudo-random high-entropy tokens (all verified H > 4.20)
    let high_entropy_tokens = [
        "K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH",
        "dGhpcy1pcy1hLXZlcnktc2VjcmV0LXRva2VuMSE=",
        "vN8#kP2$mQ9*wR1!tX7@bY3&cZ5^dF0~",
        "Wk78JmQ92Lp0ZvR14xT6yA3bC5dE8fG9",
        "9b8c7d6e5f4a3b2c1d0eXyZ!#W$Q@P&K",
    ];

    for &tok in &high_entropy_tokens {
        let h = shannon_entropy_bits(tok);
        assert!(
            h > 4.20,
            "Expected token '{}' to have entropy > 4.20, got {:.3}",
            tok,
            h
        );
        assert!(
            tok.len() >= 16,
            "Token '{}' must be at least 16 chars long",
            tok
        );
        assert!(
            has_mixed_classes(tok),
            "Token '{}' must have mixed classes",
            tok
        );

        // When embedded in arbitrary CLI commands or prose, must be scrubbed
        let input = format!("powershell.exe -CustomAuth {} --silent", tok);
        let scrubbed = scrub_text(&input);
        assert!(
            !scrubbed.contains(tok),
            "High-entropy token '{}' was NOT scrubbed from input '{}'. Result: '{}'",
            tok,
            input,
            scrubbed
        );
        assert!(
            scrubbed.contains("[REDACTED_HIGH_ENTROPY_SECRET]")
                || scrubbed.contains("[REDACTED_CLI_ARG]")
                || scrubbed.contains("[REDACTED_API_KEY]"),
            "Expected a redaction tag in: '{}'",
            scrubbed
        );
    }
}

#[test]
fn test_adversarial_entropy_threshold_and_length_boundaries() {
    // 1. Length exactly 15 with high entropy (should NOT be scrubbed by Shannon rule)
    // 15 distinct characters -> entropy = log2(15) = 3.907 (and len < 16)
    let len15 = "AbCdEfGhIjKlMn1";
    assert_eq!(len15.len(), 15);
    assert!(!is_high_entropy_secret(len15));

    // 2. Length 16 with low entropy (repeated pairs -> entropy ~ 2.0 bits)
    let low_entropy_16 = "a1b2a1b2a1b2a1b2";
    assert_eq!(low_entropy_16.len(), 16);
    assert!(has_mixed_classes(low_entropy_16));
    assert!(shannon_entropy_bits(low_entropy_16) < 4.20);
    assert!(!is_high_entropy_secret(low_entropy_16));

    // 3. Length 16 with high entropy (> 4.20) and mixed classes
    // 16 distinct chars with mixed classes
    let high_entropy_16 = "aB3$kL9#mN2!vR5&";
    assert_eq!(high_entropy_16.len(), 16);
    assert!(has_mixed_classes(high_entropy_16));
    let h16 = shannon_entropy_bits(high_entropy_16);
    assert!(h16 > 3.9); // 16 distinct symbols = 4.0 bits
    // For 18 distinct chars:
    let high_entropy_18 = "aB3$kL9#mN2!vR5&tW";
    let h18 = shannon_entropy_bits(high_entropy_18);
    assert!(h18 > 4.10);

    // 20 distinct chars:
    let high_entropy_20 = "aB3$kL9#mN2!vR5&tW8*";
    let h20 = shannon_entropy_bits(high_entropy_20);
    assert!(h20 > 4.20);
    assert!(is_high_entropy_secret(high_entropy_20));

    // 4. Single character class (no mixed classes) even with length 30 must NOT be scrubbed by Shannon rule
    let all_lower = "abcdefghijklmnopqrstuvwxyzabcd";
    assert!(shannon_entropy_bits(all_lower) > 4.20);
    assert!(!has_mixed_classes(all_lower));
    assert!(!is_high_entropy_secret(all_lower));

    let all_digits = "012345678901234567890123456789";
    assert!(!has_mixed_classes(all_digits));
    assert!(!is_high_entropy_secret(all_digits));
}

// =========================================================================
// 2. Path & UUID False-Positive Immunity
// =========================================================================

#[test]
fn test_adversarial_system_paths_never_redacted() {
    let system_paths = [
        // Windows system paths
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\SysWOW64\kernel32.dll",
        r"C:\Program Files\Common Files\System\msadc\msadcs.dll",
        r"D:\harfile\QuorumRAG\target\debug\quorum_ingest.exe",
        r"\\SERVER01\SharedForensics\dump_20261110.raw",
        r"C:\Users\Administrator\AppData\Local\Temp\agent.log",
        // Linux system paths
        "/usr/bin/python3",
        "/etc/security/limits.conf",
        "/var/log/audit/audit.log",
        "/proc/sys/net/ipv4/ip_forward",
        "/dev/shm/.stealth_payload",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/etc/pam.d/common-auth",
        // macOS system paths
        "/System/Library/LaunchDaemons/com.apple.syslogd.plist",
        "/Library/Application Support/CrashReporter/DiagnosticReports",
        "/usr/local/bin/brew",
        // Artemis logical URIs
        "artemis://windows/eventlog/Security",
        "artemis://linux/auditd",
        "artemis://macos/launchd",
        "artemis://windows/prefetch",
        // Standard Web URLs
        "https://api.github.com/repos/puffycid/artemis",
        "http://localhost:8080/health",
        "https://raw.githubusercontent.com/rust-lang/rust/master/README.md",
    ];

    for &path in &system_paths {
        assert!(
            is_uuid_or_path(path),
            "Path '{}' must be recognized by is_uuid_or_path",
            path
        );
        let scrubbed = scrub_text(path);
        assert_eq!(
            scrubbed, path,
            "Path '{}' was falsely modified or redacted to '{}'",
            path, scrubbed
        );

        // Even inside a command line, the path must remain unredacted
        let cmd = format!("exec_tool --config {} --verbose", path);
        let cmd_scrubbed = scrub_text(&cmd);
        assert!(
            cmd_scrubbed.contains(path),
            "Path '{}' was falsely scrubbed inside command '{}'. Got: '{}'",
            path,
            cmd,
            cmd_scrubbed
        );
    }
}

#[test]
fn test_adversarial_uuids_never_redacted() {
    let test_uuids = [
        "f079fca0-097e-4913-bd00-d16c999eb7ee",
        "F079FCA0-097E-4913-BD00-D16C999EB7EE",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    ];

    for &u in &test_uuids {
        assert!(
            is_uuid_or_path(u),
            "UUID '{}' must be recognized by is_uuid_or_path",
            u
        );
        let scrubbed = scrub_text(u);
        assert_eq!(
            scrubbed, u,
            "UUID '{}' was falsely redacted to '{}'",
            u, scrubbed
        );

        // Command line context with UUID
        let cmd = format!("taskkill /PID {} /F", u);
        let cmd_scrubbed = scrub_text(&cmd);
        assert!(
            cmd_scrubbed.contains(u),
            "UUID '{}' was falsely scrubbed in command '{}'",
            u,
            cmd
        );
    }
}

// =========================================================================
// 3. Docker & Networking CLI Flags vs Password Flags
// =========================================================================

#[test]
fn test_adversarial_docker_port_flags_preserved() {
    let port_commands = [
        // Standard Docker port mapping
        ("docker run -d -p 8080:8080 nginx", "-p 8080:8080"),
        ("docker run -d -p 443:443 my_service", "-p 443:443"),
        ("docker run -d -p 80:80 httpd", "-p 80:80"),
        ("docker run -d -p 22:22 sshd", "-p 22:22"),
        ("docker run -d -p 9092:9092 kafka", "-p 9092:9092"),
        // Single port
        ("nc -l -p 4444", "-p 4444"),
        ("ssh -p 2222 user@remote", "-p 2222"),
        ("curl -p 8080 http://example.com", "-p 8080"),
        // Uppercase -P flag (Docker expose all ports)
        ("docker run -d -P 80 nginx", "-P 80"),
        // Multiple port mappings
        (
            "docker run -p 80:80 -p 443:443 -p 8080:8080 webapp",
            "-p 80:80",
        ),
    ];

    for (cmd, expected_fragment) in &port_commands {
        let scrubbed = scrub_text(cmd);
        assert!(
            scrubbed.contains(expected_fragment),
            "Port flag '{}' was falsely redacted in '{}'. Scrubbed output: '{}'",
            expected_fragment,
            cmd,
            scrubbed
        );
    }
}

#[test]
fn test_adversarial_password_cli_flags_reliably_redacted() {
    let secret_commands = [
        // Short -p with secret value
        (
            "mysql -u root -p SecretPass123! -h 127.0.0.1",
            "SecretPass123!",
        ),
        ("redis-cli -p SuperSecretAuthPwd!", "SuperSecretAuthPwd!"),
        (
            "pg_dump -U postgres -p ComplexPasswd99#",
            "ComplexPasswd99#",
        ),
        // Adjacent -p
        ("mysql -u root -pMasterSecret99!", "MasterSecret99!"),
        // Long --password=
        (
            "backup.sh --password=DatabaseMasterKey2026! --target=s3",
            "DatabaseMasterKey2026!",
        ),
        // Long --password with space
        (
            "backup.sh --password DatabaseMasterKey2026! --target=s3",
            "DatabaseMasterKey2026!",
        ),
        // Variants: --token, --api-key, --secret
        (
            "deploy.sh --token=VerySecretDeployToken12345 --env=prod",
            "VerySecretDeployToken12345",
        ),
        (
            "sync.exe --api-key=MySecretApiKey1234567890",
            "MySecretApiKey1234567890",
        ),
        (
            "run.exe --auth-token=TopSecretToken987654321",
            "TopSecretToken987654321",
        ),
        // Environment variables
        (
            "ENV_PASS=SecretPassphrase999! ./daemon",
            "SecretPassphrase999!",
        ),
        (
            "export API_KEY=sk-proj-12345678901234567890",
            "sk-proj-12345678901234567890",
        ),
    ];

    for (cmd, secret_val) in &secret_commands {
        let scrubbed = scrub_text(cmd);
        assert!(
            !scrubbed.contains(secret_val),
            "Secret '{}' was NOT scrubbed from command '{}'. Scrubbed output: '{}'",
            secret_val,
            cmd,
            scrubbed
        );
        assert!(
            scrubbed.contains("[REDACTED_CLI_ARG]")
                || scrubbed.contains("[REDACTED_ENV_VAR]")
                || scrubbed.contains("[REDACTED_API_KEY]")
                || scrubbed.contains("[REDACTED_HIGH_ENTROPY_SECRET]"),
            "Expected redaction tag in output '{}' for command '{}'",
            scrubbed,
            cmd
        );
    }
}

// =========================================================================
// 4. Corrupted, Partial, and Adversarial JSONL Streams
// =========================================================================

#[test]
fn test_adversarial_empty_and_whitespace_jsonl() {
    // Empty string
    let res = parse_artemis_jsonl_str("").expect("Empty input should succeed with empty records");
    assert_eq!(res.len(), 0);

    // Only whitespace and various newlines
    let ws = "   \n\n\t  \r\n   \n\r\n";
    let res_ws = parse_artemis_jsonl_str(ws).expect("Whitespace input should succeed with empty records");
    assert_eq!(res_ws.len(), 0);
}

#[test]
fn test_adversarial_corrupted_and_partial_jsonl_lines() {
    // Construct a dirty stream with various corruption modes interleaved with valid records
    let dirty_stream = "\
{\"EventID\":4688,\"Channel\":\"Security\",\"CommandLine\":\"whoami.exe\",\"Computer\":\"HOST-1\"}\n\
{truncated json line with missing closing brace\n\
\n\
<<<this is completely malformed binary garbage \x01\x02\x03>>>\n\
{\"type\":\"EXECVE\",\"argc\":2,\"a0\":\"/bin/ls\",\"a1\":\"-la\",\"os_platform\":\"linux\",\"hostname\":\"srv-lin\"}\n\
{\"EventID\":\n\
{\"key_without_value\": \n\
{\"Label\":\"com.apple.reportcrash\",\"ProgramArguments\":[\"/usr/libexec/ReportCrash\"],\"os_platform\":\"macos\"}\n\
";

    let records = parse_artemis_jsonl_str(dirty_stream)
        .expect("Parser must be resilient and not abort on corrupted lines");

    // Must successfully extract the 3 valid records: Windows, Linux, macOS
    assert_eq!(
        records.len(),
        3,
        "Expected exactly 3 valid records recovered from dirty stream, got {}",
        records.len()
    );

    // Record 0: Windows EventID 4688
    assert_eq!(records[0].telemetry_type, ForensicTelemetryType::ProcessExecution);
    assert_eq!(records[0].os_platform, "windows");
    assert_eq!(records[0].host_identifier, "HOST-1");

    // Record 1: Linux EXECVE
    assert_eq!(records[1].telemetry_type, ForensicTelemetryType::ProcessExecution);
    assert_eq!(records[1].os_platform, "linux");
    assert_eq!(records[1].host_identifier, "srv-lin");

    // Record 2: macOS LaunchDaemon
    assert_eq!(records[2].telemetry_type, ForensicTelemetryType::ServiceDaemon);
    assert_eq!(records[2].os_platform, "macos");
}

#[test]
fn test_adversarial_deeply_nested_json_secret_scrubbing() {
    let mut nested = json!({
        "event": {
            "metadata": {
                "auth": {
                    "API_KEY": "sk-1234567890abcdef1234567890",
                    "HIGH_ENTROPY_SECRET": "K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH",
                    "TOKEN": "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
                },
                "normal": "safe_information"
            },
            "array_data": [
                "normal item",
                "Bearer sk_live_abcdef12345678901234",
                {"SUB_SECRET": "AKIAIOSFODNN7EXAMPLE"}
            ]
        }
    });

    scrub_json_value(&mut nested);

    let serialized = nested.to_string();
    assert!(!serialized.contains("sk-1234567890abcdef1234567890"));
    assert!(!serialized.contains("K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH"));
    assert!(!serialized.contains("ghp_0123456789abcdefghijklmnopqrstuvwxyz"));
    assert!(!serialized.contains("sk_live_abcdef12345678901234"));
    assert!(!serialized.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(serialized.contains("safe_information"));
}

#[test]
fn test_adversarial_quoted_password_cli_flags_investigation() {
    // Attack scenario: CLI arguments or ENV vars containing quoted passwords
    let quoted_double = "app.exe --password=\"SecretPassword123!\" --user=admin";
    let scrubbed_double = scrub_text(quoted_double);
    println!("[ADVERSARIAL] Double-quoted password result: '{}'", scrubbed_double);

    let quoted_single = "app.exe --password='SecretPassword123!' --user=admin";
    let scrubbed_single = scrub_text(quoted_single);
    println!("[ADVERSARIAL] Single-quoted password result: '{}'", scrubbed_single);

    let env_quoted = "export DB_PASSWORD=\"SecretPassword123!\"";
    let scrubbed_env = scrub_text(env_quoted);
    println!("[ADVERSARIAL] Quoted ENV var result: '{}'", scrubbed_env);

    // Verify whether quotes bypass regex redaction
    let double_bypassed = scrubbed_double.contains("SecretPassword123!");
    let single_bypassed = scrubbed_single.contains("SecretPassword123!");
    let env_bypassed = scrubbed_env.contains("SecretPassword123!");

    println!(
        "[ADVERSARIAL PROBE] Quoted password bypasses -> double: {}, single: {}, env: {}",
        double_bypassed, single_bypassed, env_bypassed
    );

    assert!(!double_bypassed, "Double-quoted password must be redacted");
    assert!(!single_bypassed, "Single-quoted password must be redacted");
    assert!(!env_bypassed, "Quoted ENV var password must be redacted");
    assert!(scrubbed_double.contains("--password=[REDACTED_CLI_ARG]"));
    assert!(scrubbed_single.contains("--password=[REDACTED_CLI_ARG]"));
    assert!(scrubbed_env.contains("DB_PASSWORD=[REDACTED_ENV_VAR]"));
}

#[test]
fn test_adversarial_base64_with_slash_investigation() {
    // Attack scenario: High-entropy base64 tokens containing standard base64 character '/'
    let b64_with_slash = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXovMTI=";
    let h = shannon_entropy_bits(b64_with_slash);
    assert!(h > 4.20);
    assert!(has_mixed_classes(b64_with_slash));

    let treated_as_path = is_uuid_or_path(b64_with_slash);
    let detected_as_secret = is_high_entropy_secret(b64_with_slash);
    println!(
        "[ADVERSARIAL PROBE] Base64 token with '/' -> treated_as_path: {}, detected_as_secret: {}",
        treated_as_path, detected_as_secret
    );

    let scrubbed = scrub_text(b64_with_slash);
    println!("[ADVERSARIAL] Scrubbed output for b64 with slash: '{}'", scrubbed);
}

#[test]
fn test_adversarial_docker_ip_and_protocol_port_investigation() {
    // Attack scenario: Docker port mappings with IP bindings or /tcp protocol
    let ip_port = "docker run -d -p 127.0.0.1:8080:8080 nginx";
    let scrubbed_ip = scrub_text(ip_port);
    println!("[ADVERSARIAL] Docker IP port result: '{}'", scrubbed_ip);

    let proto_port = "docker run -d -p 8080:8080/tcp nginx";
    let scrubbed_proto = scrub_text(proto_port);
    println!("[ADVERSARIAL] Docker proto port result: '{}'", scrubbed_proto);

    let ip_false_redacted = scrubbed_ip.contains("[REDACTED_CLI_ARG]");
    let proto_false_redacted = scrubbed_proto.contains("[REDACTED_CLI_ARG]");
    println!(
        "[ADVERSARIAL PROBE] Docker port false redaction -> ip_binding: {}, proto_suffix: {}",
        ip_false_redacted, proto_false_redacted
    );

    assert!(!ip_false_redacted, "Docker IP port binding must not be falsely redacted");
    assert!(!proto_false_redacted, "Docker protocol port suffix must not be falsely redacted");
    assert!(scrubbed_ip.contains("-p 127.0.0.1:8080:8080"));
    assert!(scrubbed_proto.contains("-p 8080:8080/tcp"));
}

#[test]
fn test_adversarial_json_field_raw_password_investigation() {
    // Attack scenario: JSON object with sensitive field names ("password", "secret")
    // but moderate entropy (< 4.20 bits) raw passwords
    let mut obj = json!({
        "password": "SecretPassword123!",
        "secret": "DatabaseAdmin2026!"
    });
    scrub_json_value(&mut obj);
    let res = obj.to_string();
    println!("[ADVERSARIAL] JSON object with raw password fields after scrub_json_value: '{}'", res);
    let leaked = res.contains("SecretPassword123!");
    println!("[ADVERSARIAL PROBE] Raw password in JSON field leaked unredacted: {}", leaked);

    assert!(!leaked, "Raw password in JSON field must not leak");
    assert!(!res.contains("DatabaseAdmin2026!"), "Raw secret in JSON field must not leak");
    assert_eq!(obj["password"], "[REDACTED_SECRET]");
    assert_eq!(obj["secret"], "[REDACTED_SECRET]");
}

#[test]
fn test_adversarial_standalone_network_json_type_inference_investigation() {
    // Attack scenario: Standalone network telemetry without Windows EventID/Channel
    let net_val = json!({
        "DestinationIp": "192.168.1.100",
        "DestinationPort": 443,
        "SourceIp": "10.0.0.5"
    });
    let inferred = infer_telemetry_type(&net_val);
    println!("[ADVERSARIAL PROBE] Inferred type for standalone network JSON: {:?}", inferred);

    assert_eq!(
        inferred,
        ForensicTelemetryType::NetworkConnection,
        "Standalone network JSON with DestinationIp must infer NetworkConnection"
    );
}

// =========================================================================
// 5. Hard Airgap & Provenance Invariants
// =========================================================================

#[test]
fn test_adversarial_hard_airgap_invariants_across_all_categories() {
    // Generate records for every forensic telemetry category
    let category_samples = [
        (r#"{"EventID":4688,"CommandLine":"whoami.exe"}"#, ForensicTelemetryType::ProcessExecution, true),
        (r#"{"EventID":3,"DestinationIp":"192.168.1.50","DestinationPort":443}"#, ForensicTelemetryType::NetworkConnection, true),
        (r#"{"Key":"HKLM\\Software\\Run","ValueName":"Agent"}"#, ForensicTelemetryType::RegistryPersistence, true),
        (r#"{"EventID":1102,"Channel":"Security"}"#, ForensicTelemetryType::SystemEventLog, true),
        (r#"{"ExecutableName":"APP.EXE","run_count":5,"path":"C:\\Windows\\Prefetch\\APP.EXE-ABCD.pf"}"#, ForensicTelemetryType::PrefetchAmcacheExecution, true),
        (r#"{"ServiceName":"AuditSvc","BinaryPath":"audit.exe"}"#, ForensicTelemetryType::ServiceDaemon, true),
        // Prohibited categories
        (r#"{"cookies":[{"name":"auth","value":"xyz"}]}"#, ForensicTelemetryType::BrowserCookies, false),
        (r#"{"history_url":"https://oauth.example.com/token"}"#, ForensicTelemetryType::BrowserHistoryOAuth, false),
        (r#"{"sam_hashes":"aad3b435b51404eeaad3b435b51404ee"}"#, ForensicTelemetryType::CredentialStore, false),
        (r#"{"shell_history":"curl -u admin:pass https://internal"}"#, ForensicTelemetryType::ShellHistoryRaw, false),
    ];

    for (sample, expected_type, expected_harvest) in category_samples {
        let records = parse_artemis_jsonl_str(sample)
            .unwrap_or_else(|e| panic!("Failed to parse sample '{}': {}", sample, e));
        assert_eq!(records.len(), 1);
        let rec = &records[0];

        // Type match
        assert_eq!(rec.telemetry_type, expected_type);

        // Tier 3 invariant
        assert_eq!(rec.access_tier, 3, "access_tier must strictly be 3");

        // Airgap flags
        assert!(rec.artemis_dfir, "artemis_dfir must strictly be true");
        assert!(!rec.mesh_sharable, "mesh_sharable must strictly be false");

        // Harvest eligibility must strictly match the category gate
        assert_eq!(
            rec.harvest_eligible, expected_harvest,
            "harvest_eligible mismatch for {:?}",
            expected_type
        );

        // Logical URI scheme
        assert!(
            rec.source_path.starts_with("artemis://"),
            "source_path must start with artemis://, got '{}'",
            rec.source_path
        );

        // DocumentChunk invariants
        let chunk = rec.to_document_chunk(0).expect("to_document_chunk must succeed");
        assert_eq!(chunk.access_tier, 3);
        assert!(chunk.file_path.starts_with("artemis://"));
        assert!(chunk.metadata_json.contains("\"artemis_dfir\":true"));
        assert!(chunk.metadata_json.contains("\"mesh_sharable\":false"));
        assert!(chunk.metadata_json.contains("\"access_tier\":3"));

        // Provenance invariants
        let prov = rec.to_provenance().expect("to_provenance must succeed");
        assert_eq!(prov.access_tier, 3);
        assert!(prov.artemis_dfir);
        assert!(!prov.mesh_sharable);
        assert_eq!(prov.harvest_eligible, expected_harvest);
        assert!(
            prov.validate_invariants().is_ok(),
            "Provenance invariants must hold"
        );
    }
}
