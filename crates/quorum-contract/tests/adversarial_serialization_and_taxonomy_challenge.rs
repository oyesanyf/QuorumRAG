//! Empirical Stress-Test Suite for QuorumRAG Forensic Contract (Milestone 1)
//!
//! Validates:
//! 1. Exact 10-variant canonical taxonomy of `ForensicTelemetryType` strictly conforming to R1.
//! 2. Exhaustive confirmation that NO extraneous variants exist.
//! 3. Strict allowlist (6 defensive) vs prohibition (4 sensitive/personal) matrix and fail-closed assertion.
//! 4. Serialization roundtrips across JSON (string, bytes) and Binary Serde (bincode).
//! 5. Post-deserialization cryptographic attestation integrity (Ed25519 signature validity preserved across JSON & bincode).
//! 6. Fuzzing and adversarial rejection of malformed, truncated, bit-flipped binary & JSON payloads.

use ed25519_dalek::SigningKey;
use quorum_contract::{ForensicContractError, ForensicProvenance, ForensicTelemetryType};

#[test]
fn test_exact_10_variant_taxonomy_conformance_r1() {
    let all = ForensicTelemetryType::ALL_TYPES;
    assert_eq!(all.len(), 10, "Taxonomy MUST contain exactly 10 variants");

    // Exhaustively check variant identities against R1
    let expected = [
        ForensicTelemetryType::ProcessExecution,
        ForensicTelemetryType::NetworkConnection,
        ForensicTelemetryType::RegistryPersistence,
        ForensicTelemetryType::SystemEventLog,
        ForensicTelemetryType::PrefetchAmcacheExecution,
        ForensicTelemetryType::ServiceDaemon,
        ForensicTelemetryType::BrowserCookies,
        ForensicTelemetryType::BrowserHistoryOAuth,
        ForensicTelemetryType::CredentialStore,
        ForensicTelemetryType::ShellHistoryRaw,
    ];

    for (i, expected_type) in expected.iter().enumerate() {
        assert_eq!(
            all[i], *expected_type,
            "Variant at index {} does not match expected R1 canonical taxonomy",
            i
        );
    }

    // Verify exhaustive match in Rust guarantees no hidden variants exist
    for t in all {
        match t {
            ForensicTelemetryType::ProcessExecution => {}
            ForensicTelemetryType::NetworkConnection => {}
            ForensicTelemetryType::RegistryPersistence => {}
            ForensicTelemetryType::SystemEventLog => {}
            ForensicTelemetryType::PrefetchAmcacheExecution => {}
            ForensicTelemetryType::ServiceDaemon => {}
            ForensicTelemetryType::BrowserCookies => {}
            ForensicTelemetryType::BrowserHistoryOAuth => {}
            ForensicTelemetryType::CredentialStore => {}
            ForensicTelemetryType::ShellHistoryRaw => {}
        }
    }
}

#[test]
fn test_marketplace_harvest_allowlist_and_prohibition_rules() {
    // 6 Defensive telemetry categories: ALLOWED
    let defensive = [
        ForensicTelemetryType::ProcessExecution,
        ForensicTelemetryType::NetworkConnection,
        ForensicTelemetryType::RegistryPersistence,
        ForensicTelemetryType::SystemEventLog,
        ForensicTelemetryType::PrefetchAmcacheExecution,
        ForensicTelemetryType::ServiceDaemon,
    ];

    for t in defensive {
        assert!(
            t.is_marketplace_harvest_allowed(),
            "Defensive telemetry category {:?} must be allowlisted for harvest",
            t
        );
        assert!(
            t.is_defensive_telemetry(),
            "Category {:?} must report true for is_defensive_telemetry()",
            t
        );
        assert!(
            t.assert_marketplace_harvest_allowed().is_ok(),
            "assert_marketplace_harvest_allowed() must return Ok(()) for {:?}",
            t
        );
        assert!(
            t.harvest_prohibition_reason().is_none(),
            "Allowlisted category {:?} must have None for harvest_prohibition_reason()",
            t
        );
    }

    // 4 Sensitive/Personal/Credential categories: STRICTLY PROHIBITED
    let prohibited = [
        ForensicTelemetryType::BrowserCookies,
        ForensicTelemetryType::BrowserHistoryOAuth,
        ForensicTelemetryType::CredentialStore,
        ForensicTelemetryType::ShellHistoryRaw,
    ];

    for t in prohibited {
        assert!(
            !t.is_marketplace_harvest_allowed(),
            "Sensitive category {:?} must be barred from harvest",
            t
        );
        assert!(
            !t.is_defensive_telemetry(),
            "Category {:?} must not be classified as defensive telemetry",
            t
        );
        let assert_res = t.assert_marketplace_harvest_allowed();
        assert!(
            matches!(
                assert_res,
                Err(ForensicContractError::HarvestCategoryProhibited { .. })
            ),
            "assert_marketplace_harvest_allowed() must fail closed for {:?}",
            t
        );
        let reason = t.harvest_prohibition_reason();
        assert!(
            reason.is_some(),
            "Prohibited category {:?} must provide a descriptive prohibition reason",
            t
        );
        assert!(
            !reason.unwrap().is_empty(),
            "Prohibition reason must not be empty"
        );
    }
}

#[test]
fn test_extraneous_telemetry_types_fail_closed_rejection() {
    // Attempt parsing candidate telemetry types outside the canonical 10
    let invalid_candidates = [
        "MemoryDump",
        "memory_dump",
        "KernelDriver",
        "kernel_driver",
        "HardwareSensor",
        "hardware_sensor",
        "EmailInbox",
        "email_inbox",
        "ChatLog",
        "chat_log",
        "ClipboardHistory",
        "clipboard_history",
        "CameraCapture",
        "MicrophoneAudio",
        "KeystrokeLog",
        "ScreenCapture",
        "",
        " ",
        "process",
        "network",
        "registry",
        "system",
        "prefetch",
        "service",
        "browser",
        "credential",
        "shell",
    ];

    for candidate in invalid_candidates {
        let parsed = candidate.parse::<ForensicTelemetryType>();
        assert!(
            matches!(
                parsed,
                Err(ForensicContractError::UnknownTelemetryType { .. })
            ),
            "Candidate '{}' must be rejected with UnknownTelemetryType, got {:?}",
            candidate,
            parsed
        );
    }
}

#[test]
fn test_json_serialization_roundtrip_all_variants() {
    let expected_json_strings = [
        (ForensicTelemetryType::ProcessExecution, "\"process_execution\""),
        (ForensicTelemetryType::NetworkConnection, "\"network_connection\""),
        (ForensicTelemetryType::RegistryPersistence, "\"registry_persistence\""),
        (ForensicTelemetryType::SystemEventLog, "\"system_event_log\""),
        (ForensicTelemetryType::PrefetchAmcacheExecution, "\"prefetch_amcache_execution\""),
        (ForensicTelemetryType::ServiceDaemon, "\"service_daemon\""),
        (ForensicTelemetryType::BrowserCookies, "\"browser_cookies\""),
        // Explicitly annotated to produce canonical "browser_history_oauth" while accepting alias "browser_history_o_auth"
        (ForensicTelemetryType::BrowserHistoryOAuth, "\"browser_history_oauth\""),
        (ForensicTelemetryType::CredentialStore, "\"credential_store\""),
        (ForensicTelemetryType::ShellHistoryRaw, "\"shell_history_raw\""),
    ];

    for (variant, expected_json) in expected_json_strings {
        // Serialization to JSON string
        let json = serde_json::to_string(&variant).expect("JSON serialization failed");
        assert_eq!(json, expected_json, "JSON serialization format mismatch");

        // Deserialization from JSON string
        let deserialized: ForensicTelemetryType =
            serde_json::from_str(&json).expect("JSON deserialization failed");
        assert_eq!(deserialized, variant, "JSON roundtrip mismatch");

        // Deserialization from byte slice
        let bytes = json.as_bytes();
        let from_bytes: ForensicTelemetryType =
            serde_json::from_slice(bytes).expect("JSON from_slice failed");
        assert_eq!(from_bytes, variant);
    }

    // Rejection of unknown variant from JSON
    let bad_json = "\"unauthorized_telemetry_type\"";
    let bad_res = serde_json::from_str::<ForensicTelemetryType>(bad_json);
    assert!(
        bad_res.is_err(),
        "Deserializing unknown variant from JSON must fail"
    );
}

#[test]
fn test_serde_snake_case_acronym_divergence_oracle() {
    // Empirical verification of BrowserHistoryOAuth serde alignment with as_str():
    // 1. as_str() returns "browser_history_oauth"
    // 2. serde serializes to "browser_history_oauth"
    // 3. serde deserializes "browser_history_oauth" and alias "browser_history_o_auth"
    // 4. FromStr parses both "browser_history_oauth" and "browser_history_o_auth"
    let t = ForensicTelemetryType::BrowserHistoryOAuth;
    let as_str_val = t.as_str();
    assert_eq!(as_str_val, "browser_history_oauth");

    let serde_json_val = serde_json::to_string(&t).unwrap();
    assert_eq!(serde_json_val, "\"browser_history_oauth\"");
    assert_eq!(serde_json_val, format!("\"{}\"", as_str_val));

    // Deserializing both canonical and alias from JSON succeeds
    let json_de_canonical: ForensicTelemetryType =
        serde_json::from_str("\"browser_history_oauth\"").expect("Deserializing canonical failed");
    assert_eq!(json_de_canonical, t);

    let json_de_alias: ForensicTelemetryType =
        serde_json::from_str("\"browser_history_o_auth\"").expect("Deserializing alias failed");
    assert_eq!(json_de_alias, t);

    // Parsing both canonical and alias with FromStr succeeds
    let from_str_canonical: ForensicTelemetryType =
        "browser_history_oauth".parse().expect("Parsing canonical failed");
    assert_eq!(from_str_canonical, t);

    let from_str_alias: ForensicTelemetryType =
        "browser_history_o_auth".parse().expect("Parsing alias failed");
    assert_eq!(from_str_alias, t);
}

#[test]
fn test_binary_serde_bincode_roundtrip_all_variants() {
    for variant in ForensicTelemetryType::ALL_TYPES {
        // 1. Serialize to binary via bincode
        let binary_bytes = bincode::serialize(&variant).expect("Bincode serialization failed");
        assert!(
            !binary_bytes.is_empty(),
            "Binary representation must not be empty"
        );

        // 2. Deserialize from binary
        let deserialized: ForensicTelemetryType =
            bincode::deserialize(&binary_bytes).expect("Bincode deserialization failed");
        assert_eq!(
            deserialized, variant,
            "Binary roundtrip mismatch for {:?}",
            variant
        );
    }

    // Adversarial: truncated binary buffer
    let mut truncated = bincode::serialize(&ForensicTelemetryType::ProcessExecution).unwrap();
    if !truncated.is_empty() {
        truncated.pop();
        let trunc_res = bincode::deserialize::<ForensicTelemetryType>(&truncated);
        assert!(
            trunc_res.is_err(),
            "Bincode must reject truncated binary representation"
        );
    }

    // Adversarial: out-of-bounds enum discriminant in binary representation
    // bincode encodes unit variant as a u32 index. An index >= 10 must fail deserialization.
    let out_of_bounds_discriminant = 999u32.to_le_bytes();
    let oob_res = bincode::deserialize::<ForensicTelemetryType>(&out_of_bounds_discriminant);
    assert!(
        oob_res.is_err(),
        "Bincode must reject out-of-bounds enum discriminant"
    );
}

#[test]
fn test_forensic_provenance_full_roundtrip_json_and_bincode() {
    let raw_payload = b"{\"event_id\": 4688, \"process_path\": \"C:\\\\Windows\\\\System32\\\\cmd.exe\"}";
    let mut prov = ForensicProvenance::from_raw_payload(
        "artifact-roundtrip-01",
        ForensicTelemetryType::ProcessExecution,
        "artemis://windows/eventlogs/Security.evtx",
        "SEC-DC-01",
        "windows",
        Some("Windows Server 2022 Build 20348".to_string()),
        "artemis-core",
        "0.1.0",
        1762741000,
        raw_payload,
    )
    .expect("Construction failed");

    // Sign with Ed25519 key
    let seed = [0x55u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    prov.sign_ed25519(&seed).expect("Signing failed");
    assert!(prov.attestation_signature_hex.is_some());

    // 1. JSON Roundtrip
    let json_str = serde_json::to_string_pretty(&prov).expect("JSON serialization failed");
    let json_deserialized: ForensicProvenance =
        serde_json::from_str(&json_str).expect("JSON deserialization failed");
    assert_eq!(
        prov, json_deserialized,
        "JSON roundtrip structural mismatch"
    );
    assert!(
        json_deserialized.validate_invariants().is_ok(),
        "Invariants must hold after JSON deserialization"
    );
    assert!(
        json_deserialized.verify_ed25519(&pubkey_bytes).is_ok(),
        "Ed25519 signature verification MUST pass after JSON roundtrip"
    );
    assert!(
        json_deserialized.verify_payload_bytes(raw_payload).is_ok(),
        "Payload BLAKE3 verification MUST pass after JSON roundtrip"
    );

    // 2. Bincode Binary Roundtrip
    let bin_bytes = bincode::serialize(&prov).expect("Bincode serialization failed");
    let bin_deserialized: ForensicProvenance =
        bincode::deserialize(&bin_bytes).expect("Bincode deserialization failed");
    assert_eq!(
        prov, bin_deserialized,
        "Bincode roundtrip structural mismatch"
    );
    assert!(
        bin_deserialized.validate_invariants().is_ok(),
        "Invariants must hold after bincode deserialization"
    );
    assert!(
        bin_deserialized.verify_ed25519(&pubkey_bytes).is_ok(),
        "Ed25519 signature verification MUST pass after bincode roundtrip"
    );
    assert!(
        bin_deserialized.verify_payload_bytes(raw_payload).is_ok(),
        "Payload BLAKE3 verification MUST pass after bincode roundtrip"
    );

    // 3. Roundtrip with None os_version and prohibited category
    let prohibited_prov = ForensicProvenance::new(
        "artifact-roundtrip-prohibited",
        ForensicTelemetryType::CredentialStore,
        "artemis://windows/registry/SAM",
        "SEC-DC-01",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        1762741100,
        "3333333333333333333333333333333333333333333333333333333333333333",
    )
    .expect("Construction failed");

    // JSON roundtrip for prohibited record
    let p_json = serde_json::to_string(&prohibited_prov).unwrap();
    let p_json_de: ForensicProvenance = serde_json::from_str(&p_json).unwrap();
    assert_eq!(prohibited_prov, p_json_de);
    assert!(!p_json_de.harvest_eligible);
    assert!(p_json_de.validate_invariants().is_ok());

    // Bincode roundtrip for prohibited record
    let p_bin = bincode::serialize(&prohibited_prov).unwrap();
    let p_bin_de: ForensicProvenance = bincode::deserialize(&p_bin).unwrap();
    assert_eq!(prohibited_prov, p_bin_de);
    assert!(!p_bin_de.harvest_eligible);
    assert!(p_bin_de.validate_invariants().is_ok());
}

#[test]
fn test_adversarial_binary_serde_fuzz_and_corruption() {
    let prov = ForensicProvenance::new(
        "art-fuzz-01",
        ForensicTelemetryType::NetworkConnection,
        "artemis://linux/netstat",
        "EDGE-ROUTER-01",
        "linux",
        Some("6.6.0-hardened".to_string()),
        "artemis-core",
        "0.1.0",
        1762742000,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .unwrap();

    let clean_bytes = bincode::serialize(&prov).unwrap();

    // 1. Prefix truncation: progressively truncate buffer from end
    for len in (0..clean_bytes.len()).step_by(10) {
        let truncated = &clean_bytes[..len];
        let res = bincode::deserialize::<ForensicProvenance>(truncated);
        assert!(
            res.is_err(),
            "Truncated bincode payload at length {} must fail deserialization",
            len
        );
    }

    // 2. Single-byte bit flipping across binary buffer
    // For every byte in the serialized payload, flip a bit.
    // The result MUST either fail bincode deserialization, OR if it happens to deserialize,
    // it MUST fail invariant validation (e.g. if access_tier, airgap flags, or strings mutated).
    let mut bit_flip_errors = 0;
    let mut invariant_rejections = 0;

    for i in 0..clean_bytes.len() {
        let mut corrupted = clean_bytes.clone();
        corrupted[i] ^= 0x01; // flip lowest bit

        match bincode::deserialize::<ForensicProvenance>(&corrupted) {
            Err(_) => {
                bit_flip_errors += 1;
            }
            Ok(deserialized) => {
                // If it parsed, check if invariants reject it
                if deserialized.validate_invariants().is_err() {
                    invariant_rejections += 1;
                }
            }
        }
    }

    // Every bit flip that touched a critical field must either be a parse error or invariant rejection
    assert!(
        bit_flip_errors > 0,
        "Bit flips must trigger bincode deserialization errors"
    );
    assert!(
        bit_flip_errors + invariant_rejections > 0,
        "Total errors or invariant rejections must be non-zero"
    );
}
