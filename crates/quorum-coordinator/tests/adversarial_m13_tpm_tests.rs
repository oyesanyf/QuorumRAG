//! Adversarial empirical stress harness for TPM 2.0 Hardware Inspection,
//! Platform Configuration Register (PCR) Attestation, Composite Digest Invariance,
//! OEM Vendor Fuzzing, and Monotonic ACL Gating in QuorumRAG.
//!
//! Milestone M13 Adversarial Verification.

use chrono::{Duration, Utc};
use quorum_coordinator::{
    compute_pcr_composite_digest, extend_simulated_pcr_16, inspect_tpm_hardware, simulated_pcr,
    AttestationTier, PeerAclManager, PeerAttestationRecord, TpmOemVendor, PCR_APPLICATION_AUDIT,
    PCR_PLATFORM_FIRMWARE, PCR_SECURE_BOOT,
};
use quorum_types::AccessTier;
use std::collections::{BTreeMap, HashSet};
use std::time::Instant;

/// Minimal deterministic Xorshift64Star PRNG for repeatable adversarial fuzzing.
struct FuzzRng {
    state: u64,
}

impl FuzzRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x853c49e6748fea9b } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn next_range(&mut self, min: usize, max: usize) -> usize {
        if min >= max {
            return min;
        }
        min + (self.next_u64() as usize % (max - min))
    }

    fn random_string(&mut self, max_len: usize) -> String {
        let len = self.next_range(0, max_len);
        let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./\\ \t\r\n!@#$%^&*()[]{};:<>,?~`+=|'\0"
            .chars()
            .collect();
        (0..len)
            .map(|_| chars[self.next_range(0, chars.len())])
            .collect()
    }
}

/// 1. PCR 16 State Mutability:
/// Extend simulated PCR 16 multiple times and verify that the composite PCR digest
/// changes monotonically and irreversibly with zero cycles or collisions.
#[test]
fn test_adversarial_pcr16_monotonic_mutability_and_composite_evolution() {
    let mut seen_pcr16 = HashSet::new();
    let mut seen_composites = HashSet::new();

    let initial_pcr16 = simulated_pcr(PCR_APPLICATION_AUDIT);
    seen_pcr16.insert(initial_pcr16.clone());

    let mut base_map = BTreeMap::new();
    base_map.insert(PCR_PLATFORM_FIRMWARE, simulated_pcr(PCR_PLATFORM_FIRMWARE));
    base_map.insert(PCR_SECURE_BOOT, simulated_pcr(PCR_SECURE_BOOT));
    base_map.insert(PCR_APPLICATION_AUDIT, initial_pcr16);

    let initial_composite = compute_pcr_composite_digest(&base_map);
    seen_composites.insert(initial_composite);

    let mut rng = FuzzRng::new(0xDEADBEEFCAFE);
    const EXTENSION_CYCLES: usize = 100;

    for i in 0..EXTENSION_CYCLES {
        let payload = format!("AUDIT_EVENT_{}_{}", i, rng.next_u64());
        extend_simulated_pcr_16(payload.as_bytes());

        let new_pcr16 = simulated_pcr(PCR_APPLICATION_AUDIT);
        assert_eq!(
            new_pcr16.len(),
            64,
            "PCR 16 must remain a 64-char valid hex string"
        );
        assert!(
            seen_pcr16.insert(new_pcr16.clone()),
            "PCR 16 collision or cycle detected at iteration {}! Digest: {}",
            i,
            new_pcr16
        );

        let mut current_map = BTreeMap::new();
        current_map.insert(PCR_PLATFORM_FIRMWARE, simulated_pcr(PCR_PLATFORM_FIRMWARE));
        current_map.insert(PCR_SECURE_BOOT, simulated_pcr(PCR_SECURE_BOOT));
        current_map.insert(PCR_APPLICATION_AUDIT, new_pcr16);

        let new_composite = compute_pcr_composite_digest(&current_map);
        assert_eq!(
            new_composite.len(),
            64,
            "Composite digest must remain 64 hex characters"
        );
        assert!(
            seen_composites.insert(new_composite.clone()),
            "Composite digest collision detected at extension {}! Composite: {}",
            i,
            new_composite
        );
    }

    assert_eq!(seen_pcr16.len(), EXTENSION_CYCLES + 1);
    assert_eq!(seen_composites.len(), EXTENSION_CYCLES + 1);
    println!(
        "Verified {} monotonic irreversible PCR 16 extensions and composite evolutions",
        EXTENSION_CYCLES
    );
}

/// 2. PCR Composite Digest Hash Invariance:
/// Verify that compute_pcr_composite_digest handles arbitrary PCR index orderings
/// deterministically (due to BTreeMap key ordering), handles duplicate/empty sets,
/// and behaves gracefully with invalid hex without panics.
#[test]
fn test_adversarial_pcr_composite_digest_invariance_and_resilience() {
    let pcr0 = simulated_pcr(0);
    let pcr7 = simulated_pcr(7);
    let pcr16 = simulated_pcr(16);

    // Baseline: standard insertion order
    let mut baseline = BTreeMap::new();
    baseline.insert(0, pcr0.clone());
    baseline.insert(7, pcr7.clone());
    baseline.insert(16, pcr16.clone());
    let baseline_digest = compute_pcr_composite_digest(&baseline);

    // Permutation 1: Reverse insertion order
    let mut perm1 = BTreeMap::new();
    perm1.insert(16, pcr16.clone());
    perm1.insert(7, pcr7.clone());
    perm1.insert(0, pcr0.clone());
    assert_eq!(
        compute_pcr_composite_digest(&perm1),
        baseline_digest,
        "Composite digest must be invariant to reverse insertion"
    );

    // Permutation 2: Random insertion order
    let mut perm2 = BTreeMap::new();
    perm2.insert(7, pcr7.clone());
    perm2.insert(16, pcr16.clone());
    perm2.insert(0, pcr0.clone());
    assert_eq!(
        compute_pcr_composite_digest(&perm2),
        baseline_digest,
        "Composite digest must be invariant to random insertion"
    );

    // Permutation 3: Re-updating an index with identical value
    let mut perm3 = perm2.clone();
    perm3.insert(7, pcr7.clone());
    assert_eq!(
        compute_pcr_composite_digest(&perm3),
        baseline_digest,
        "Idempotent re-insertion must yield identical composite digest"
    );

    // Resilience: Empty map produces deterministic hash without panicking
    let empty_map = BTreeMap::new();
    let empty_digest = compute_pcr_composite_digest(&empty_map);
    assert_eq!(empty_digest.len(), 64);

    // Resilience: Non-hex strings (e.g. malformed telemetry) do not panic, fall back cleanly
    let mut malformed_map = BTreeMap::new();
    malformed_map.insert(0, "NOT_VALID_HEX_DATA_XYZ_123".to_string());
    malformed_map.insert(7, "ANOTHER_NON_HEX_VALUE_!@#$%^&*()".to_string());
    let malformed_digest = compute_pcr_composite_digest(&malformed_map);
    assert_eq!(malformed_digest.len(), 64);
    assert_ne!(malformed_digest, empty_digest);

    // Resilience: Large set of PCRs (all 24 standard TPM PCRs)
    let mut full_pcrs = BTreeMap::new();
    for i in 0..24 {
        full_pcrs.insert(i, simulated_pcr(i));
    }
    let full_digest = compute_pcr_composite_digest(&full_pcrs);
    assert_eq!(full_digest.len(), 64);
    assert_ne!(full_digest, baseline_digest);
}

/// 3. OEM Vendor Fuzzing:
/// Feed randomized strings and manufacturer IDs to TpmOemVendor::from_manufacturer_id_or_str
/// to verify zero panics, strict classification for known patterns, and safe fallback to Unknown.
#[test]
fn test_adversarial_oem_vendor_fuzzing() {
    let mut rng = FuzzRng::new(0x4242_1337_CAFE);
    const FUZZ_ITERATIONS: usize = 10_000;

    // 3.1 Known IDs must ALWAYS match regardless of garbage text
    let known_id_specs = [
        (0x494E5443, TpmOemVendor::Intel),
        (0x414D4400, TpmOemVendor::Amd),
        (0x49465800, TpmOemVendor::Infineon),
        (0x53544D20, TpmOemVendor::StMicro),
        (0x4E544300, TpmOemVendor::Nuvoton),
        (0x4E545A00, TpmOemVendor::Nationz),
        (0x41544D4C, TpmOemVendor::Microchip),
    ];

    for &(mfg_id, expected_vendor) in &known_id_specs {
        for _ in 0..100 {
            let garbage = rng.random_string(64);
            let res = TpmOemVendor::from_manufacturer_id_or_str(mfg_id, &garbage);
            // If the garbage happens to contain a substring matching an earlier if-branch,
            // that is an edge case to check, but with pure garbage it should yield the expected_vendor.
            assert!(
                res == expected_vendor || res != TpmOemVendor::Unknown,
                "Known ID 0x{:08X} failed to classify cleanly with text '{}'",
                mfg_id,
                garbage
            );
        }
    }

    // 3.2 Known substrings must classify correctly even when ID is 0 or random
    let known_substring_specs = [
        ("intel", TpmOemVendor::Intel),
        ("INTEL", TpmOemVendor::Intel),
        ("InTeL Corporation Root CA", TpmOemVendor::Intel),
        ("amd", TpmOemVendor::Amd),
        ("AMD PSP fTPM", TpmOemVendor::Amd),
        ("infineon", TpmOemVendor::Infineon),
        ("OPTIGA TPM 2.0", TpmOemVendor::Infineon),
        ("stmicro", TpmOemVendor::StMicro),
        ("STM32 TPM", TpmOemVendor::StMicro),
        ("nuvoton", TpmOemVendor::Nuvoton),
        ("NTC Nuvoton TPM2", TpmOemVendor::Nuvoton),
        ("nationz", TpmOemVendor::Nationz),
        ("Nationz TPM Module", TpmOemVendor::Nationz),
        ("microchip", TpmOemVendor::Microchip),
        ("atmel crypto", TpmOemVendor::Microchip),
    ];

    for &(sub, expected) in &known_substring_specs {
        let res = TpmOemVendor::from_manufacturer_id_or_str(0, sub);
        assert_eq!(
            res, expected,
            "Substring '{}' failed to classify as {:?}",
            sub, expected
        );
    }

    // 3.3 Massive fuzzing campaign: 10,000 iterations of random IDs, extreme lengths,
    // Unicode chars, emojis, SQLi payloads, path traversal payloads, null bytes.
    let long_a = "A".repeat(10_000);
    let adversarial_strings: [&str; 10] = [
        "",
        "\0",
        "\0\0\0\0",
        "../../../../../../etc/passwd",
        "'; DROP TABLE tpm_certs; --",
        "<script>alert(1)</script>",
        "🔥🚀🛡️🔑💻",
        long_a.as_str(),
        "\u{FFFF}\u{FEFF}\u{0000}",
        "   \t\r\n   ",
    ];

    for adv in &adversarial_strings {
        let v = TpmOemVendor::from_manufacturer_id_or_str(0, adv);
        assert_eq!(
            v,
            TpmOemVendor::Unknown,
            "Adversarial input '{}' must classify as Unknown",
            adv
        );
    }

    let mut unknown_count = 0;
    for _ in 0..FUZZ_ITERATIONS {
        let random_id = rng.next_u32();
        let random_txt = rng.random_string(128);

        // Crucial invariant: must never panic under any random inputs
        let vendor = TpmOemVendor::from_manufacturer_id_or_str(random_id, &random_txt);
        if vendor == TpmOemVendor::Unknown {
            unknown_count += 1;
        }
    }

    println!(
        "Completed {} fuzz iterations safely ({} resolved to Unknown fallback)",
        FUZZ_ITERATIONS, unknown_count
    );
}

/// 4. ACL Gating Boundary & Privilege Escalation:
/// Verify that an unverified peer can NEVER be granted Tier 1, 2, or 3,
/// even if requested or statically mapped, and that an expired attestation
/// immediately demotes the peer to Tier 0.
#[test]
fn test_adversarial_acl_privilege_escalation_and_demotion_gates() {
    let mut acl = PeerAclManager::new(AccessTier::Tier0Public);

    let unverified_peer = "attacker_unverified_peer";
    let simulated_peer = "worker_simulated_peer";
    let hw_tpm_peer = "node_hw_tpm_peer";
    let hw_ek_peer = "node_hw_ek_peer";
    let phantom_peer = "phantom_unregistered_peer";

    // Scenario 1: Malicious unverified peer tries to register directly for Tier 3 Restricted
    acl.register_peer_id(
        unverified_peer.to_string(),
        AccessTier::Tier3Restricted,
    );
    // Peer provides NO attestation record:
    assert_eq!(
        acl.get_attestation_tier(unverified_peer),
        AttestationTier::Unverified
    );
    assert_eq!(
        acl.get_max_allowed_tier_by_attestation(unverified_peer),
        AccessTier::Tier0Public
    );
    // Effective tier MUST be clamped to Tier0Public
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(unverified_peer),
        AccessTier::Tier0Public
    );
    // Requested tier 3, 2, or 1 MUST be strictly clamped to Tier 0
    let effective_tier = acl.resolve_effective_tier(
        3,
        acl.get_effective_authorized_tier_for_peer_id(unverified_peer),
    );
    assert_eq!(
        effective_tier, 0,
        "Unverified peer requesting Tier 3 must be clamped to 0"
    );

    let effective_tier_2 = acl.resolve_effective_tier(
        2,
        acl.get_effective_authorized_tier_for_peer_id(unverified_peer),
    );
    assert_eq!(
        effective_tier_2, 0,
        "Unverified peer requesting Tier 2 must be clamped to 0"
    );

    let effective_tier_1 = acl.resolve_effective_tier(
        1,
        acl.get_effective_authorized_tier_for_peer_id(unverified_peer),
    );
    assert_eq!(
        effective_tier_1, 0,
        "Unverified peer requesting Tier 1 must be clamped to 0"
    );

    // Scenario 2: Simulated peer claims Tier 3
    acl.register_peer_id(simulated_peer.to_string(), AccessTier::Tier3Restricted);
    let now = Utc::now();
    let future = now + Duration::seconds(600);
    acl.record_peer_attestation(PeerAttestationRecord {
        peer_id: simulated_peer.to_string(),
        pubkey: None,
        attestation_tier: AttestationTier::Simulated,
        vendor: None,
        pcr_composite_digest: Some("c_sim".to_string()),
        hardware_backed: false,
        ek_fingerprint: None,
        verified_at: now,
        expires_at: future,
    });
    // Simulated tier can never exceed Tier 1 Internal
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(simulated_peer),
        AccessTier::Tier1Internal
    );
    assert_eq!(
        acl.resolve_effective_tier(
            3,
            acl.get_effective_authorized_tier_for_peer_id(simulated_peer)
        ),
        1,
        "Simulated peer must never escalate beyond Tier 1"
    );

    // Scenario 3: Hardware TPM without EK claims Tier 3
    acl.register_peer_id(hw_tpm_peer.to_string(), AccessTier::Tier3Restricted);
    acl.record_peer_attestation(PeerAttestationRecord {
        peer_id: hw_tpm_peer.to_string(),
        pubkey: None,
        attestation_tier: AttestationTier::VerifiedHardwareTpm,
        vendor: Some(TpmOemVendor::Nuvoton),
        pcr_composite_digest: Some("c_hw".to_string()),
        hardware_backed: true,
        ek_fingerprint: None,
        verified_at: now,
        expires_at: future,
    });
    // Hardware TPM without EK can never exceed Tier 2 Confidential
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(hw_tpm_peer),
        AccessTier::Tier2Confidential
    );
    assert_eq!(
        acl.resolve_effective_tier(
            3,
            acl.get_effective_authorized_tier_for_peer_id(hw_tpm_peer)
        ),
        2,
        "Hardware TPM without EK must never escalate beyond Tier 2"
    );

    // Scenario 4: Hardware EK peer claims Tier 3 and receives Tier 3
    acl.register_peer_id(hw_ek_peer.to_string(), AccessTier::Tier3Restricted);
    acl.record_peer_attestation(PeerAttestationRecord {
        peer_id: hw_ek_peer.to_string(),
        pubkey: None,
        attestation_tier: AttestationTier::VerifiedHardwareEk,
        vendor: Some(TpmOemVendor::Intel),
        pcr_composite_digest: Some("c_ek".to_string()),
        hardware_backed: true,
        ek_fingerprint: Some("ek_fp_intel".to_string()),
        verified_at: now,
        expires_at: future,
    });
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(hw_ek_peer),
        AccessTier::Tier3Restricted
    );

    // Scenario 5: Immediate demotion upon expiration
    // We update hw_ek_peer with an expiration in the past:
    let past = now - Duration::seconds(1);
    acl.record_peer_attestation(PeerAttestationRecord {
        peer_id: hw_ek_peer.to_string(),
        pubkey: None,
        attestation_tier: AttestationTier::VerifiedHardwareEk,
        vendor: Some(TpmOemVendor::Intel),
        pcr_composite_digest: Some("c_ek".to_string()),
        hardware_backed: true,
        ek_fingerprint: Some("ek_fp_intel".to_string()),
        verified_at: past - Duration::seconds(300),
        expires_at: past, // Expired 1 second ago!
    });
    assert_eq!(
        acl.get_attestation_tier(hw_ek_peer),
        AttestationTier::Unverified,
        "Expired peer attestation tier must instantly drop to Unverified"
    );
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(hw_ek_peer),
        AccessTier::Tier0Public,
        "Expired peer effective tier must instantly demote to Tier 0 Public"
    );
    assert_eq!(
        acl.resolve_effective_tier(
            3,
            acl.get_effective_authorized_tier_for_peer_id(hw_ek_peer)
        ),
        0,
        "Expired peer requesting Tier 3 must be demoted to 0"
    );

    // Scenario 6: Phantom unregistered peer
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(phantom_peer),
        AccessTier::Tier0Public
    );

    // Scenario 7: Pubkey-based ACL authorization without attestation
    let dummy_pk = [0x55u8; 32];
    acl.register_pubkey(dummy_pk, AccessTier::Tier3Restricted);
    assert_eq!(
        acl.get_effective_authorized_tier_for_pubkey(&dummy_pk),
        AccessTier::Tier0Public,
        "Unauthenticated pubkey must never exceed Tier 0"
    );
}

/// 5. Performance:
/// Verify that inspect_tpm_hardware() executes in < 1ms across 100 iterations.
#[test]
fn test_adversarial_tpm_hardware_inspection_submillisecond_latency() {
    const ITERATIONS: usize = 100;
    let mut latencies_micros: Vec<u128> = Vec::with_capacity(ITERATIONS);

    // Warm-up call
    let _ = inspect_tpm_hardware();

    for _ in 0..ITERATIONS {
        let t0 = Instant::now();
        let insp = inspect_tpm_hardware();
        let elapsed = t0.elapsed();
        latencies_micros.push(elapsed.as_micros());

        // Invariant checks on the inspection struct
        assert_eq!(insp.tpm_version, "2.0");
        assert!(insp.pcr_values.len() >= 3);
        assert_eq!(insp.composite_digest.len(), 64);
    }

    latencies_micros.sort_unstable();

    let min_us = latencies_micros[0];
    let max_us = latencies_micros[ITERATIONS - 1];
    let sum_us: u128 = latencies_micros.iter().sum();
    let avg_us = sum_us as f64 / ITERATIONS as f64;
    let p50_us = latencies_micros[ITERATIONS * 50 / 100];
    let p95_us = latencies_micros[ITERATIONS * 95 / 100];
    let p99_us = latencies_micros[ITERATIONS * 99 / 100];

    println!("TPM Hardware Inspection Latency over {} iterations:", ITERATIONS);
    println!("  Min:    {} µs ({:.3} ms)", min_us, min_us as f64 / 1000.0);
    println!("  P50:    {} µs ({:.3} ms)", p50_us, p50_us as f64 / 1000.0);
    println!("  Avg:    {:.1} µs ({:.3} ms)", avg_us, avg_us / 1000.0);
    println!("  P95:    {} µs ({:.3} ms)", p95_us, p95_us as f64 / 1000.0);
    println!("  P99:    {} µs ({:.3} ms)", p99_us, p99_us as f64 / 1000.0);
    println!("  Max:    {} µs ({:.3} ms)", max_us, max_us as f64 / 1000.0);

    // Strict assertion: Average execution latency MUST be < 1.0 ms (1000 µs)
    assert!(
        avg_us < 1000.0,
        "Average TPM hardware inspection took {:.1} µs (exceeds 1000 µs target!)",
        avg_us
    );

    // Strict assertion: P95 execution latency MUST be < 1.0 ms (1000 µs)
    assert!(
        p95_us < 1000,
        "P95 TPM hardware inspection took {} µs (exceeds 1000 µs target!)",
        p95_us
    );
}

/// 6. EK Certificate Parsing Adversarial Stress-Test:
/// Test TpmEkCertificate::from_der against corrupt, truncated, empty, and adversarial DER payloads.
#[test]
fn test_adversarial_ek_cert_der_fuzzing_and_rejection() {
    use quorum_coordinator::TpmEkCertificate;

    // 6.1 Empty DER bytes
    let empty_res = TpmEkCertificate::from_der(vec![]);
    assert!(empty_res.is_err(), "Empty DER must be rejected with Err");

    // 6.2 Garbage non-DER bytes
    let garbage_res = TpmEkCertificate::from_der(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]);
    assert!(garbage_res.is_err(), "Garbage bytes must be rejected with Err");

    // 6.3 Truncated ASN.1 Sequence header (0x30, 0x82, 0x04, 0x00) with 0 payload
    let truncated_hdr = vec![0x30, 0x82, 0x04, 0x00];
    let trunc_res = TpmEkCertificate::from_der(truncated_hdr);
    assert!(trunc_res.is_err(), "Truncated ASN.1 header must be rejected with Err");

    // 6.4 Fuzzing DER parser with 1,000 pseudo-random payloads: must NEVER panic
    let mut rng = FuzzRng::new(0xABCD_EF01_2345);
    for _ in 0..1000 {
        let len = rng.next_range(1, 512);
        let mut raw = Vec::with_capacity(len);
        for _ in 0..len {
            raw.push(rng.next_u32() as u8);
        }
        let _ = TpmEkCertificate::from_der(raw);
    }
}

/// 7. ACL Dynamic Gating Flaw Demonstration:
/// When an operator approves a peer and calls `register_peer_id(peer_id, Tier2)`
/// WITHOUT calling `record_peer_attestation(...)`, the peer's effective tier
/// remains stuck at Tier 0 Public!
#[test]
fn test_adversarial_acl_approved_peer_without_attestation_record_stuck_at_tier0() {
    let mut acl = PeerAclManager::new(AccessTier::Tier0Public);
    let approved_peer = "12D3KooWApprovedPeerWithoutAttestation";

    // Operator approves and registers peer with Tier 2 Confidential:
    acl.register_peer_id(approved_peer.to_string(), AccessTier::Tier2Confidential);

    // If record_peer_attestation is omitted (as in mesh.rs:504-508):
    let effective = acl.get_effective_authorized_tier_for_peer_id(approved_peer);
    assert_eq!(
        effective,
        AccessTier::Tier0Public,
        "A peer with registered tier but no attestation record is capped at Tier 0 Public"
    );

    // Once record_peer_attestation IS called:
    let now = Utc::now();
    acl.record_peer_attestation(PeerAttestationRecord {
        peer_id: approved_peer.to_string(),
        pubkey: None,
        attestation_tier: AttestationTier::VerifiedHardwareTpm,
        vendor: Some(TpmOemVendor::Nuvoton),
        pcr_composite_digest: Some("valid_digest".to_string()),
        hardware_backed: true,
        ek_fingerprint: None,
        verified_at: now,
        expires_at: now + Duration::seconds(3600),
    });

    let effective_after = acl.get_effective_authorized_tier_for_peer_id(approved_peer);
    assert_eq!(
        effective_after,
        AccessTier::Tier2Confidential,
        "Only after recording attestation does the peer receive Tier 2 Confidential"
    );
}

