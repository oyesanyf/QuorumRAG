//! Adversarial Stress-Test Oracle Suite for QuorumRAG Forensic Contracts
//!
//! Validates:
//! 1. Telemetry category boundary fuzzing (fail-closed allowlisting).
//! 2. Bit-flip tampering across Ed25519 signatures, public keys, canonical fields, and BLAKE3 digests.
//! 3. Access tier downgrade attacks across all 256 `u8` values (only tier 3 permitted).
//! 4. Mesh airgap violation attacks (`mesh_sharable = true`, `artemis_dfir = false`).
//! 5. Harvest eligibility tampering.
//! 6. Delimiter collision stress test in canonical_signing_bytes.

use ed25519_dalek::SigningKey;
use quorum_contract::{ForensicContractError, ForensicProvenance, ForensicTelemetryType};

#[test]
fn test_category_boundary_allowlist_and_prohibition_matrix() {
    let all_types = ForensicTelemetryType::ALL_TYPES;
    assert_eq!(all_types.len(), 10, "Taxonomy must define exactly 10 canonical types");

    let expected_allowed = [
        ForensicTelemetryType::ProcessExecution,
        ForensicTelemetryType::NetworkConnection,
        ForensicTelemetryType::RegistryPersistence,
        ForensicTelemetryType::SystemEventLog,
        ForensicTelemetryType::PrefetchAmcacheExecution,
        ForensicTelemetryType::ServiceDaemon,
    ];

    let expected_prohibited = [
        ForensicTelemetryType::BrowserCookies,
        ForensicTelemetryType::BrowserHistoryOAuth,
        ForensicTelemetryType::CredentialStore,
        ForensicTelemetryType::ShellHistoryRaw,
    ];

    assert_eq!(expected_allowed.len() + expected_prohibited.len(), 10);

    for t in &expected_allowed {
        assert!(
            t.is_marketplace_harvest_allowed(),
            "Category {:?} MUST be allowlisted for sovereign harvest",
            t
        );
        assert!(
            t.is_defensive_telemetry(),
            "Category {:?} MUST qualify as defensive telemetry",
            t
        );
        assert!(
            t.assert_marketplace_harvest_allowed().is_ok(),
            "assert_marketplace_harvest_allowed() MUST succeed for {:?}",
            t
        );
        assert!(
            t.harvest_prohibition_reason().is_none(),
            "Allowed category {:?} must have no prohibition reason",
            t
        );
    }

    for t in &expected_prohibited {
        assert!(
            !t.is_marketplace_harvest_allowed(),
            "Category {:?} MUST be barred from marketplace harvest",
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
            "assert_marketplace_harvest_allowed() MUST fail with HarvestCategoryProhibited for {:?}",
            t
        );
        assert!(
            t.harvest_prohibition_reason().is_some(),
            "Prohibited category {:?} MUST provide a descriptive prohibition reason",
            t
        );
    }
}

#[test]
fn test_serde_acronym_divergence_and_canonical_misalignment() {
    // With remediation, all 10 variants have serde JSON matching as_str() exactly.
    // BrowserHistoryOAuth also accepts the alias "browser_history_o_auth".
    for t in &ForensicTelemetryType::ALL_TYPES {
        let as_str = t.as_str();
        let serialized_json = serde_json::to_string(t).unwrap();
        assert_eq!(
            serialized_json,
            format!("\"{}\"", as_str),
            "serde_json serialization MUST match canonical as_str() for {:?}",
            t
        );
        let parsed: ForensicTelemetryType = serde_json::from_str(&serialized_json).unwrap();
        assert_eq!(*t, parsed);
    }

    // Verify BrowserHistoryOAuth specifically supports both canonical and alias
    let oauth = ForensicTelemetryType::BrowserHistoryOAuth;
    assert_eq!(serde_json::to_string(&oauth).unwrap(), "\"browser_history_oauth\"");
    let parsed_canonical: ForensicTelemetryType =
        serde_json::from_str("\"browser_history_oauth\"").unwrap();
    assert_eq!(parsed_canonical, oauth);
    let parsed_alias: ForensicTelemetryType =
        serde_json::from_str("\"browser_history_o_auth\"").unwrap();
    assert_eq!(parsed_alias, oauth);
}

#[test]
fn test_category_boundary_fuzzing_and_fail_closed_parsing() {
    // 1. Valid variations that must parse correctly
    let valid_cases = [
        ("process_execution", ForensicTelemetryType::ProcessExecution),
        ("ProcessExecution", ForensicTelemetryType::ProcessExecution),
        ("process-execution", ForensicTelemetryType::ProcessExecution),
        ("network_connection", ForensicTelemetryType::NetworkConnection),
        ("NetworkConnection", ForensicTelemetryType::NetworkConnection),
        ("network-connection", ForensicTelemetryType::NetworkConnection),
        ("registry_persistence", ForensicTelemetryType::RegistryPersistence),
        ("RegistryPersistence", ForensicTelemetryType::RegistryPersistence),
        ("registry-persistence", ForensicTelemetryType::RegistryPersistence),
        ("system_event_log", ForensicTelemetryType::SystemEventLog),
        ("SystemEventLog", ForensicTelemetryType::SystemEventLog),
        ("system-event-log", ForensicTelemetryType::SystemEventLog),
        ("prefetch_amcache_execution", ForensicTelemetryType::PrefetchAmcacheExecution),
        ("PrefetchAmcacheExecution", ForensicTelemetryType::PrefetchAmcacheExecution),
        ("prefetch_amcache", ForensicTelemetryType::PrefetchAmcacheExecution),
        ("service_daemon", ForensicTelemetryType::ServiceDaemon),
        ("ServiceDaemon", ForensicTelemetryType::ServiceDaemon),
        ("service-daemon", ForensicTelemetryType::ServiceDaemon),
        ("browser_cookies", ForensicTelemetryType::BrowserCookies),
        ("BrowserCookies", ForensicTelemetryType::BrowserCookies),
        ("browser-cookies", ForensicTelemetryType::BrowserCookies),
        ("browser_history_oauth", ForensicTelemetryType::BrowserHistoryOAuth),
        ("browser_history_o_auth", ForensicTelemetryType::BrowserHistoryOAuth),
        ("BrowserHistoryOAuth", ForensicTelemetryType::BrowserHistoryOAuth),
        ("browser_history", ForensicTelemetryType::BrowserHistoryOAuth),
        ("credential_store", ForensicTelemetryType::CredentialStore),
        ("CredentialStore", ForensicTelemetryType::CredentialStore),
        ("credential-store", ForensicTelemetryType::CredentialStore),
        ("shell_history_raw", ForensicTelemetryType::ShellHistoryRaw),
        ("ShellHistoryRaw", ForensicTelemetryType::ShellHistoryRaw),
        ("shell_history", ForensicTelemetryType::ShellHistoryRaw),
    ];

    for (raw_str, expected) in valid_cases {
        let parsed: ForensicTelemetryType = raw_str.parse().unwrap_or_else(|_| {
            panic!("Expected valid string '{}' to parse into {:?}", raw_str, expected);
        });
        assert_eq!(parsed, expected);
    }

    // 2. Adversarial fuzzing strings that MUST fail closed with UnknownTelemetryType
    let adversarial_strings = [
        "",
        " ",
        "   \t\n   ",
        "\0",
        "process_execution\0",
        "process_execution_bypass",
        "process",
        "execution",
        "credential",
        "credentials",
        "cookies",
        "history",
        "sam",
        "dpapi",
        "keychain",
        "shadow",
        "powershell",
        "cmd.exe",
        "artemis",
        "artemis://windows/eventlog",
        "../process_execution",
        "process_execution/..",
        "true",
        "false",
        "null",
        "{}",
        "[]",
        "12345",
        "\"process_execution\"",
        "PROCESS_EXECUTION_UNKNOWN",
        "process_execution; DROP TABLE telemetry;",
        "browser_cookies_allowlist_bypass",
        "credential_store_override=1",
        "SystemEventLog\u{200B}", // Zero-width space
        "SystemEventLog\u{FEFF}", // Byte order mark
        "РrocessExecution",       // Cyrillic 'Р' lookalike homoglyph
    ];

    for adv in adversarial_strings {
        let res = adv.parse::<ForensicTelemetryType>();
        assert!(
            matches!(res, Err(ForensicContractError::UnknownTelemetryType { .. })),
            "Adversarial input {:?} MUST fail closed with UnknownTelemetryType, got {:?}",
            adv,
            res
        );
    }
}

#[test]
fn test_ed25519_512_bit_flip_tampering_exhaustion() {
    let seed = [0x5au8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    let mut prov = ForensicProvenance::new(
        "art-oracle-001",
        ForensicTelemetryType::ProcessExecution,
        "artemis://windows/eventlog/Security.evtx",
        "VICTIM-HOST-01",
        "windows",
        Some("10.0.22631".to_string()),
        "artemis-core",
        "0.1.0",
        1762737000,
        "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
    )
    .expect("Construction failed");

    prov.sign_ed25519(&seed).expect("Signing failed");
    assert!(prov.verify_ed25519(&pubkey_bytes).is_ok());

    let original_sig_hex = prov.attestation_signature_hex.clone().unwrap();
    let original_sig_bytes = hex_decode_64(&original_sig_hex);

    // Adversarial Oracle: Flip EVERY SINGLE BIT across all 64 bytes of the signature (512 trials)
    for byte_idx in 0..64 {
        for bit_idx in 0..8 {
            let mut tampered_bytes = original_sig_bytes;
            tampered_bytes[byte_idx] ^= 1 << bit_idx;

            let mut tampered_prov = prov.clone();
            tampered_prov.attestation_signature_hex = Some(hex_encode(&tampered_bytes));

            let verify_res = tampered_prov.verify_ed25519(&pubkey_bytes);
            assert!(
                verify_res.is_err(),
                "Bit flip at byte {} bit {} MUST invalidate signature verification",
                byte_idx,
                bit_idx
            );
        }
    }
}

#[test]
fn test_pubkey_256_bit_flip_tampering_exhaustion() {
    let seed = [0x7bu8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    let mut prov = ForensicProvenance::new(
        "art-oracle-002",
        ForensicTelemetryType::NetworkConnection,
        "artemis://linux/proc/net/tcp",
        "NODE-EDGE-02",
        "linux",
        Some("6.8.0".to_string()),
        "artemis-core",
        "0.1.0",
        1762737100,
        "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
    )
    .expect("Construction failed");

    prov.sign_ed25519(&seed).expect("Signing failed");
    assert!(prov.verify_ed25519(&pubkey_bytes).is_ok());

    // Adversarial Oracle: Flip EVERY SINGLE BIT across all 32 bytes of the public key (256 trials)
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut tampered_pubkey = pubkey_bytes;
            tampered_pubkey[byte_idx] ^= 1 << bit_idx;

            let verify_res = prov.verify_ed25519(&tampered_pubkey);
            assert!(
                verify_res.is_err(),
                "Bit flip at pubkey byte {} bit {} MUST fail verification",
                byte_idx,
                bit_idx
            );
        }
    }
}

#[test]
fn test_canonical_signing_bytes_metadata_tampering_attacks() {
    let seed = [0x33u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    let mut baseline = ForensicProvenance::new(
        "artifact-attack-001",
        ForensicTelemetryType::SystemEventLog,
        "artemis://windows/eventlog/System.evtx",
        "SRV-CONTROLLER",
        "windows",
        Some("Server 2022".to_string()),
        "artemis-core",
        "0.1.0",
        1762738000,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    .expect("Construction failed");

    baseline.sign_ed25519(&seed).expect("Signing failed");
    assert!(baseline.verify_ed25519(&pubkey_bytes).is_ok());

    // 1. Mutate artifact_id
    let mut tampered = baseline.clone();
    tampered.artifact_id = "artifact-attack-002".to_string();
    assert!(tampered.verify_ed25519(&pubkey_bytes).is_err());

    // 2. Mutate telemetry_type
    let mut tampered = baseline.clone();
    tampered.telemetry_type = ForensicTelemetryType::RegistryPersistence;
    assert!(tampered.verify_ed25519(&pubkey_bytes).is_err());

    // 3. Mutate source_path
    let mut tampered = baseline.clone();
    tampered.source_path = "artemis://windows/eventlog/Application.evtx".to_string();
    assert!(tampered.verify_ed25519(&pubkey_bytes).is_err());

    // 4. Mutate host_identifier (even single char difference)
    let mut tampered = baseline.clone();
    tampered.host_identifier = "SRV-CONTROLLER-X".to_string();
    assert!(tampered.verify_ed25519(&pubkey_bytes).is_err());

    // 5. Mutate os_platform
    let mut tampered = baseline.clone();
    tampered.os_platform = "linux".to_string();
    assert!(tampered.verify_ed25519(&pubkey_bytes).is_err());

    // 6. Mutate collected_unix_secs (flip each of the 64 bits)
    for bit in 0..64 {
        let mut tampered = baseline.clone();
        tampered.collected_unix_secs ^= 1i64 << bit;
        assert!(
            tampered.verify_ed25519(&pubkey_bytes).is_err(),
            "Mutating collected_unix_secs at bit {} must break signature",
            bit
        );
    }

    // 7. Mutate ingested_unix_secs (flip each of the 64 bits)
    for bit in 0..64 {
        let mut tampered = baseline.clone();
        tampered.ingested_unix_secs ^= 1i64 << bit;
        assert!(
            tampered.verify_ed25519(&pubkey_bytes).is_err(),
            "Mutating ingested_unix_secs at bit {} must break signature",
            bit
        );
    }

    // 8. Mutate raw_payload_blake3 (substitute each hex character)
    for idx in 0..64 {
        let mut tampered = baseline.clone();
        let mut chars: Vec<char> = tampered.raw_payload_blake3.chars().collect();
        chars[idx] = if chars[idx] == '0' { '1' } else { '0' };
        tampered.raw_payload_blake3 = chars.into_iter().collect();
        assert!(
            tampered.verify_ed25519(&pubkey_bytes).is_err(),
            "Mutating payload BLAKE3 hex at char {} must break signature",
            idx
        );
    }

    // 9. Mutate os_version (substitute Some and None)
    let mut tampered = baseline.clone();
    tampered.os_version = Some("Server 2025".to_string());
    assert!(
        tampered.verify_ed25519(&pubkey_bytes).is_err(),
        "Mutating os_version must break signature"
    );
    let mut tampered = baseline.clone();
    tampered.os_version = None;
    assert!(
        tampered.verify_ed25519(&pubkey_bytes).is_err(),
        "Clearing os_version to None must break signature"
    );

    // 10. Mutate collector_name
    let mut tampered = baseline.clone();
    tampered.collector_name = "artemis-custom".to_string();
    assert!(
        tampered.verify_ed25519(&pubkey_bytes).is_err(),
        "Mutating collector_name must break signature"
    );

    // 11. Mutate collector_version
    let mut tampered = baseline.clone();
    tampered.collector_version = "0.2.0".to_string();
    assert!(
        tampered.verify_ed25519(&pubkey_bytes).is_err(),
        "Mutating collector_version must break signature"
    );
}

#[test]
fn test_raw_payload_bit_flip_tampering_exhaustion() {
    let payload = b"GET /v1/telemetry HTTP/1.1\r\nHost: 10.0.0.1\r\nUser-Agent: Artemis-Dfir/0.1\r\n\r\n{\"evidence\": 9999}";
    let payload_len = payload.len();

    let prov = ForensicProvenance::from_raw_payload(
        "art-payload-oracle",
        ForensicTelemetryType::ProcessExecution,
        "artemis://windows/prefetch/test.pf",
        "TEST-HOST",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        1762738200,
        payload,
    )
    .expect("Construction failed");

    // Baseline payload must verify
    assert!(prov.verify_payload_bytes(payload).is_ok());

    // Adversarial Oracle: Flip EVERY SINGLE BIT in payload (len * 8 trials)
    for byte_idx in 0..payload_len {
        for bit_idx in 0..8 {
            let mut tampered = payload.to_vec();
            tampered[byte_idx] ^= 1 << bit_idx;

            let verify_res = prov.verify_payload_bytes(&tampered);
            assert!(
                matches!(
                    verify_res,
                    Err(ForensicContractError::PayloadDigestMismatch { .. })
                ),
                "Payload bit flip at byte {} bit {} must fail with PayloadDigestMismatch",
                byte_idx,
                bit_idx
            );
        }
    }
}

#[test]
fn test_tier_downgrade_attacks_all_256_u8_values() {
    let prov = ForensicProvenance::new(
        "art-tier-downgrade",
        ForensicTelemetryType::PrefetchAmcacheExecution,
        "artemis://windows/amcache/Amcache.hve",
        "WORKSTATION-01",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        1762738500,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("Construction failed");

    // Test all 256 possible u8 values for access_tier
    for tier in 0..=255u8 {
        let mut candidate = prov.clone();
        candidate.access_tier = tier;

        if tier == 3 {
            assert!(
                candidate.validate_invariants().is_ok(),
                "Tier 3 (Tier3Restricted) must be valid"
            );
        } else {
            let res = candidate.validate_invariants();
            assert_eq!(
                res,
                Err(ForensicContractError::InvalidAccessTier {
                    expected: 3,
                    actual: tier,
                }),
                "Tier {} MUST be rejected with InvalidAccessTier",
                tier
            );

            // Also test that sign_ed25519 and verify_ed25519 fail closed on downgraded tier
            let seed = [0x11u8; 32];
            assert_eq!(
                candidate.sign_ed25519(&seed),
                Err(ForensicContractError::InvalidAccessTier {
                    expected: 3,
                    actual: tier,
                }),
                "sign_ed25519 must fail closed on invalid tier {}",
                tier
            );

            let pubkey = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            assert_eq!(
                candidate.verify_ed25519(&pubkey),
                Err(ForensicContractError::InvalidAccessTier {
                    expected: 3,
                    actual: tier,
                }),
                "verify_ed25519 must fail closed on invalid tier {}",
                tier
            );
        }
    }
}

#[test]
fn test_mesh_sharable_airgap_violation_attacks() {
    let prov = ForensicProvenance::new(
        "art-airgap-attack",
        ForensicTelemetryType::ServiceDaemon,
        "artemis://windows/services/evil.sys",
        "WORKSTATION-02",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        1762738600,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )
    .expect("Construction failed");

    // Attack 1: mesh_sharable = true (P2P mesh exfiltration attempt)
    let mut leak_attempt = prov.clone();
    leak_attempt.mesh_sharable = true;
    assert_eq!(
        leak_attempt.validate_invariants(),
        Err(ForensicContractError::MeshShareViolation {
            artifact_id: "art-airgap-attack".to_string()
        }),
        "mesh_sharable = true MUST be blocked as MeshShareViolation"
    );

    // Attack 2: artemis_dfir = false (bypassing airgap filter flag)
    let mut flag_bypass = prov.clone();
    flag_bypass.artemis_dfir = false;
    assert_eq!(
        flag_bypass.validate_invariants(),
        Err(ForensicContractError::AirgapFlagViolation {
            artifact_id: "art-airgap-attack".to_string(),
            field: "artemis_dfir".to_string(),
            expected: true,
            actual: false,
        }),
        "artemis_dfir = false MUST be blocked as AirgapFlagViolation"
    );

    // Attack 3: Combined airgap breaches
    let mut combined = prov.clone();
    combined.mesh_sharable = true;
    combined.artemis_dfir = false;
    assert!(combined.validate_invariants().is_err());
}

#[test]
fn test_harvest_eligibility_deserialization_tampering() {
    // Attack scenario: Attacker craft JSON representing CredentialStore but sets "harvest_eligible": true
    let hostile_json = r#"{
        "artifact_id": "malicious-sam-dump",
        "telemetry_type": "credential_store",
        "source_path": "artemis://windows/registry/SAM",
        "host_identifier": "ATTACKER-BOX",
        "os_platform": "windows",
        "os_version": null,
        "collector_name": "artemis-core",
        "collector_version": "0.1.0",
        "collected_unix_secs": 1762739000,
        "ingested_unix_secs": 1762739010,
        "raw_payload_blake3": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "access_tier": 3,
        "artemis_dfir": true,
        "mesh_sharable": false,
        "harvest_eligible": true,
        "attestation_signature_hex": null
    }"#;

    let prov: ForensicProvenance =
        serde_json::from_str(hostile_json).expect("Deserialization itself should succeed");

    // Invariant check MUST fail closed
    let validation = prov.validate_invariants();
    assert_eq!(
        validation,
        Err(ForensicContractError::HarvestEligibilityMismatch {
            artifact_id: "malicious-sam-dump".to_string(),
            expected: false,
            actual: true,
        }),
        "Hostile harvest_eligible elevation MUST be detected and rejected"
    );

    // Conversely: Attacker tries to suppress defensive telemetry
    let hostile_suppression_json = r#"{
        "artifact_id": "suppressed-process",
        "telemetry_type": "process_execution",
        "source_path": "artemis://windows/eventlog/Security.evtx",
        "host_identifier": "DEFENDER-BOX",
        "os_platform": "windows",
        "os_version": null,
        "collector_name": "artemis-core",
        "collector_version": "0.1.0",
        "collected_unix_secs": 1762739000,
        "ingested_unix_secs": 1762739010,
        "raw_payload_blake3": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "access_tier": 3,
        "artemis_dfir": true,
        "mesh_sharable": false,
        "harvest_eligible": false,
        "attestation_signature_hex": null
    }"#;

    let prov2: ForensicProvenance =
        serde_json::from_str(hostile_suppression_json).expect("Deserialization should succeed");

    assert_eq!(
        prov2.validate_invariants(),
        Err(ForensicContractError::HarvestEligibilityMismatch {
            artifact_id: "suppressed-process".to_string(),
            expected: true,
            actual: false,
        }),
        "Defensive telemetry harvest suppression MUST be detected and rejected"
    );
}

#[test]
fn test_signature_hex_length_and_character_adversarial_oracle() {
    let seed = [0x44u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    let mut prov = ForensicProvenance::new(
        "art-sig-hex-oracle",
        ForensicTelemetryType::SystemEventLog,
        "artemis://linux/journald",
        "HOST-HEX-01",
        "linux",
        None,
        "artemis-core",
        "0.1.0",
        1762739500,
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    )
    .expect("Construction failed");

    prov.sign_ed25519(&seed).expect("Signing failed");

    // 1. Missing signature
    let mut missing = prov.clone();
    missing.attestation_signature_hex = None;
    assert!(matches!(
        missing.verify_ed25519(&pubkey_bytes),
        Err(ForensicContractError::MissingProvenanceSignature { .. })
    ));

    // 2. Odd length (127 hex characters)
    let mut odd = prov.clone();
    odd.attestation_signature_hex = Some("a".repeat(127));
    assert!(matches!(
        odd.verify_ed25519(&pubkey_bytes),
        Err(ForensicContractError::InvalidSignatureHex { .. })
    ));

    // 3. Overflow length (129 hex characters)
    let mut overflow = prov.clone();
    overflow.attestation_signature_hex = Some("a".repeat(129));
    assert!(matches!(
        overflow.verify_ed25519(&pubkey_bytes),
        Err(ForensicContractError::InvalidSignatureHex { .. })
    ));

    // 4. Non-hex characters in 128-char string
    let mut invalid_chars = prov.clone();
    let mut bad_str = "a".repeat(126);
    bad_str.push_str("zz");
    invalid_chars.attestation_signature_hex = Some(bad_str);
    assert!(matches!(
        invalid_chars.verify_ed25519(&pubkey_bytes),
        Err(ForensicContractError::InvalidSignatureHex { .. })
    ));
}

#[test]
fn test_delimiter_collision_boundary_analysis() {
    // Delimiter collision analysis:
    // canonical_signing_bytes separates fields with "|":
    // source_path | host_identifier | os_platform
    // If source_path contains "|" and host_identifier is crafted,
    // we observe whether a collision in the byte stream can occur.
    let mut rec_a = ForensicProvenance::new(
        "art-delim-01",
        ForensicTelemetryType::ProcessExecution,
        "artemis://win/a|b",
        "node1",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        1762740000,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    .unwrap();
    rec_a.ingested_unix_secs = 1762740005;

    let mut rec_b = ForensicProvenance::new(
        "art-delim-01",
        ForensicTelemetryType::ProcessExecution,
        "artemis://win/a",
        "b|node1",
        "windows",
        None,
        "artemis-core",
        "0.1.0",
        1762740000,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    .unwrap();
    rec_b.ingested_unix_secs = 1762740005;

    let bytes_a = rec_a.canonical_signing_bytes();
    let bytes_b = rec_b.canonical_signing_bytes();

    // Empirically document that when fields contain raw '|', unescaped delimiter concatenation
    // yields byte equivalence:
    assert_eq!(bytes_a, bytes_b, "Empirical confirmation: unescaped pipe delimiter produces collision across source_path and host_identifier");
}

#[test]
fn test_multibyte_utf8_128_byte_signature_hex_oracle() {
    let seed = [0x55u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    let mut prov = ForensicProvenance::new(
        "art-utf8-oracle",
        ForensicTelemetryType::ProcessExecution,
        "artemis://windows/eventlog/Security.evtx",
        "SEC-BOX-99",
        "windows",
        Some("10.0.22631".to_string()),
        "artemis-core",
        "0.1.0",
        1762741000,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("Construction failed");

    prov.sign_ed25519(&seed).expect("Signing failed");
    assert!(prov.verify_ed25519(&pubkey_bytes).is_ok());

    // Adversarial Oracle 1: Exact 128-byte non-ASCII UTF-8 strings
    // Case 1A: 64 two-byte Cyrillic characters 'ж' (2 bytes * 64 = 128 bytes)
    let cyrillic_128: String = "ж".repeat(64);
    assert_eq!(cyrillic_128.len(), 128);
    let mut prov_test = prov.clone();
    prov_test.attestation_signature_hex = Some(cyrillic_128);
    assert!(matches!(
        prov_test.verify_ed25519(&pubkey_bytes),
        Err(ForensicContractError::InvalidSignatureHex { .. })
    ));

    // Case 1B: 32 four-byte emoji characters '🦀' (4 bytes * 32 = 128 bytes)
    let emoji_128: String = "🦀".repeat(32);
    assert_eq!(emoji_128.len(), 128);
    let mut prov_test = prov.clone();
    prov_test.attestation_signature_hex = Some(emoji_128);
    assert!(matches!(
        prov_test.verify_ed25519(&pubkey_bytes),
        Err(ForensicContractError::InvalidSignatureHex { .. })
    ));

    // Case 1C: 42 three-byte CJK characters '漢' + 2 ASCII bytes (3 * 42 + 2 = 128 bytes)
    let mut cjk_128 = "漢".repeat(42);
    cjk_128.push_str("00");
    assert_eq!(cjk_128.len(), 128);
    let mut prov_test = prov.clone();
    prov_test.attestation_signature_hex = Some(cjk_128);
    assert!(matches!(
        prov_test.verify_ed25519(&pubkey_bytes),
        Err(ForensicContractError::InvalidSignatureHex { .. })
    ));

    // Case 1D: Sliding 2-byte UTF-8 char across every single position in 126-char hex string (127 trials)
    for pos in 0..=126 {
        let mut s = String::with_capacity(128);
        for i in 0..pos {
            s.push(if i % 2 == 0 { 'a' } else { 'f' });
        }
        s.push('ж'); // 2 bytes
        for i in (pos + 1)..127 {
            s.push(if i % 2 == 0 { 'b' } else { 'e' });
        }
        assert_eq!(s.len(), 128);
        let mut prov_test = prov.clone();
        prov_test.attestation_signature_hex = Some(s);
        let res = prov_test.verify_ed25519(&pubkey_bytes);
        assert!(
            matches!(res, Err(ForensicContractError::InvalidSignatureHex { .. })),
            "2-byte char at pos {} must fail with InvalidSignatureHex without panic",
            pos
        );
    }

    // Case 1E: Sliding 4-byte emoji across every single position in 124-char hex string (125 trials)
    for pos in 0..=124 {
        let mut s = String::with_capacity(128);
        for i in 0..pos {
            s.push(if i % 2 == 0 { '0' } else { '9' });
        }
        s.push('🔥'); // 4 bytes
        for i in (pos + 1)..125 {
            s.push(if i % 2 == 0 { 'c' } else { 'd' });
        }
        assert_eq!(s.len(), 128);
        let mut prov_test = prov.clone();
        prov_test.attestation_signature_hex = Some(s);
        let res = prov_test.verify_ed25519(&pubkey_bytes);
        assert!(
            matches!(res, Err(ForensicContractError::InvalidSignatureHex { .. })),
            "4-byte emoji at pos {} must fail with InvalidSignatureHex without panic",
            pos
        );
    }

    // Case 1F: Non-ASCII high-byte boundary stress (null bytes, control chars, boundary bytes)
    for byte_val in [0x00u8, 0x01, 0x1F, 0x7F, 0x80, 0xFE, 0xFF] {
        let mut raw_bytes = vec![b'a'; 128];
        raw_bytes[63] = byte_val;
        if let Ok(valid_utf8_str) = std::str::from_utf8(&raw_bytes) {
            let mut prov_test = prov.clone();
            prov_test.attestation_signature_hex = Some(valid_utf8_str.to_string());
            let res = prov_test.verify_ed25519(&pubkey_bytes);
            assert!(
                matches!(res, Err(ForensicContractError::InvalidSignatureHex { .. })),
                "Byte 0x{:02x} at position 63 must fail without panic",
                byte_val
            );
        }
    }
}

#[test]
fn test_collector_and_os_metadata_mutation_invalidates_signature_oracle() {
    let seed = [0x66u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    let mut baseline = ForensicProvenance::new(
        "art-meta-oracle-01",
        ForensicTelemetryType::RegistryPersistence,
        "artemis://windows/registry/Run",
        "FORENSIC-WORKSTATION",
        "windows",
        Some("10.0.22631.3000".to_string()),
        "artemis-core",
        "0.1.0",
        1762742000,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    )
    .expect("Construction failed");

    baseline.sign_ed25519(&seed).expect("Signing failed");
    assert!(baseline.verify_ed25519(&pubkey_bytes).is_ok());

    // 1. Mutate collector_name - MUST fail verify_ed25519
    let bad_collector_names = [
        "artemis",
        "artemis-core-evil",
        "artemis_core",
        "ARTEMIS-CORE",
        "artemis-core\0",
        "puffycid/artemis",
        "artemis-core-v2",
        "artemis-core-x",
        "custom-collector",
        "",
    ];
    for bad_name in bad_collector_names {
        let mut tampered = baseline.clone();
        tampered.collector_name = bad_name.to_string();
        let res = tampered.verify_ed25519(&pubkey_bytes);
        assert_eq!(
            res,
            Err(ForensicContractError::ProvenanceSignatureInvalid {
                artifact_id: baseline.artifact_id.clone()
            }),
            "Mutating collector_name to {:?} MUST invalidate signature",
            bad_name
        );
    }

    // 2. Mutate collector_version - MUST fail verify_ed25519
    let bad_collector_versions = [
        "0.1.1",
        "0.2.0",
        "1.0.0",
        "0.1.0-beta",
        "0.1.0.1",
        "v0.1.0",
        "0.1.0\0",
        "0.0.9",
        "",
    ];
    for bad_version in bad_collector_versions {
        let mut tampered = baseline.clone();
        tampered.collector_version = bad_version.to_string();
        let res = tampered.verify_ed25519(&pubkey_bytes);
        assert_eq!(
            res,
            Err(ForensicContractError::ProvenanceSignatureInvalid {
                artifact_id: baseline.artifact_id.clone()
            }),
            "Mutating collector_version to {:?} MUST invalidate signature",
            bad_version
        );
    }

    // 3. Mutate os_version from Some to different Some or None - MUST fail verify_ed25519
    let bad_os_versions = [
        Some("10.0.22631.3001".to_string()),
        Some("10.0.22632".to_string()),
        Some("11.0.22000".to_string()),
        Some("Windows 11".to_string()),
        Some("10.0".to_string()),
        Some("".to_string()),
        None,
    ];
    for bad_os in bad_os_versions {
        let mut tampered = baseline.clone();
        tampered.os_version = bad_os.clone();
        let res = tampered.verify_ed25519(&pubkey_bytes);
        assert_eq!(
            res,
            Err(ForensicContractError::ProvenanceSignatureInvalid {
                artifact_id: baseline.artifact_id.clone()
            }),
            "Mutating os_version to {:?} MUST invalidate signature",
            bad_os
        );
    }

    // 4. Baseline signed with os_version: None
    let mut baseline_none_os = ForensicProvenance::new(
        "art-meta-oracle-02",
        ForensicTelemetryType::ServiceDaemon,
        "artemis://linux/systemd/units",
        "LINUX-SERVER-01",
        "linux",
        None,
        "artemis-core",
        "0.1.0",
        1762742100,
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    )
    .expect("Construction failed");

    baseline_none_os.sign_ed25519(&seed).expect("Signing failed");
    assert!(baseline_none_os.verify_ed25519(&pubkey_bytes).is_ok());

    // Mutating os_version from None to Some must fail verification
    for mutated_os in ["6.8.0-generic", "Ubuntu 24.04", "1.0", "linux"] {
        let mut tampered = baseline_none_os.clone();
        tampered.os_version = Some(mutated_os.to_string());
        let res = tampered.verify_ed25519(&pubkey_bytes);
        assert_eq!(
            res,
            Err(ForensicContractError::ProvenanceSignatureInvalid {
                artifact_id: baseline_none_os.artifact_id.clone()
            }),
            "Mutating os_version from None to Some({:?}) MUST invalidate signature",
            mutated_os
        );
    }
}

// Helpers
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn hex_decode_64(hex_str: &str) -> [u8; 64] {
    let clean = hex_str.trim();
    assert_eq!(clean.len(), 128);
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
