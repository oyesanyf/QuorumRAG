use chrono::{Duration, Utc};
use quorum_coordinator::{
    compute_pcr_composite_digest, extend_simulated_pcr_16, inspect_tpm_hardware,
    reset_simulated_pcr_16, simulated_pcr, AttestationTier, PeerAclManager, PeerAttestationRecord,
    TpmEkCertificate, TpmHardwareInspection, TpmOemVendor, PCR_APPLICATION_AUDIT,
    PCR_PLATFORM_FIRMWARE, PCR_SECURE_BOOT,
};
use quorum_types::AccessTier;
use std::collections::BTreeMap;
use std::time::Instant;

static TPM_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_simulated_pcr_deterministic_and_unique() {
    let _lock = TPM_TEST_MUTEX.lock().unwrap();
    reset_simulated_pcr_16();
    let pcr0 = simulated_pcr(PCR_PLATFORM_FIRMWARE);
    let pcr7 = simulated_pcr(PCR_SECURE_BOOT);
    let pcr16 = simulated_pcr(PCR_APPLICATION_AUDIT);

    assert_eq!(pcr0.len(), 64, "PCR 0 digest must be 64 hex characters (32 bytes)");
    assert_eq!(pcr7.len(), 64, "PCR 7 digest must be 64 hex characters (32 bytes)");
    assert_eq!(pcr16.len(), 64, "PCR 16 digest must be 64 hex characters (32 bytes)");

    assert_ne!(pcr0, pcr7, "PCR 0 and PCR 7 digests must not collide");
    assert_ne!(pcr7, pcr16, "PCR 7 and PCR 16 digests must not collide");
    assert_ne!(pcr0, pcr16, "PCR 0 and PCR 16 digests must not collide");

    // Repeated calls must be deterministic
    assert_eq!(pcr0, simulated_pcr(PCR_PLATFORM_FIRMWARE));
    assert_eq!(pcr7, simulated_pcr(PCR_SECURE_BOOT));
}

#[test]
fn test_extend_simulated_pcr_16() {
    let _lock = TPM_TEST_MUTEX.lock().unwrap();
    reset_simulated_pcr_16();
    let before = simulated_pcr(PCR_APPLICATION_AUDIT);
    extend_simulated_pcr_16(b"TEST_APPLICATION_EVENT_LOG_ENTRY");
    let after = simulated_pcr(PCR_APPLICATION_AUDIT);

    assert_eq!(after.len(), 64);
    assert_ne!(before, after, "Extending PCR 16 must irreversibly change its hash value");
    reset_simulated_pcr_16();
}

#[test]
fn test_composite_digest_computation() {
    let _lock = TPM_TEST_MUTEX.lock().unwrap();
    // Snapshot local values to eliminate data race with concurrent test_extend_simulated_pcr_16
    let p0 = simulated_pcr(0);
    let p7 = simulated_pcr(7);
    let p16 = simulated_pcr(16);

    let mut map = BTreeMap::new();
    map.insert(0, p0.clone());
    map.insert(7, p7.clone());
    map.insert(16, p16.clone());

    let composite = compute_pcr_composite_digest(&map);
    assert_eq!(composite.len(), 64, "Composite digest must be 64 hex characters");

    // Reordering map insertions shouldn't change BTreeMap sorted order
    let mut map2 = BTreeMap::new();
    map2.insert(16, p16);
    map2.insert(0, p0);
    map2.insert(7, p7);
    assert_eq!(compute_pcr_composite_digest(&map2), composite);
}

#[test]
fn test_ek_cert_parsing() {
    // 1. Rejection of invalid DER bytes (empty, truncated, and corrupt)
    assert!(TpmEkCertificate::from_der(vec![]).is_err(), "Empty DER must fail");
    assert!(
        TpmEkCertificate::from_der(vec![0xDE, 0xAD, 0xBE, 0xEF]).is_err(),
        "Corrupt bytes must fail"
    );
    assert!(
        TpmEkCertificate::from_der(vec![0x30, 0x82, 0x04, 0x00]).is_err(),
        "Truncated ASN.1 header must fail"
    );

    // 2. Genuine DER certificate parsing (Intel OEM Root CA)
    let cert_hex = concat!(
        "3082034a30820232a00302010202104afbe27fcbd5f2b1445d2a1594e5edc2300d06092a864886f70d01010b0500",
        "3038311a3018060355040a0c11496e74656c20436f72706f726174696f6e311a301806035504030c11496e74656c20",
        "54504d20454b20526f6f74301e170d3236313130323138303833335a170d3237313130323138323833335a3038311a",
        "3018060355040a0c11496e74656c20436f72706f726174696f6e311a301806035504030c11496e74656c2054504d20",
        "454b20526f6f7430820122300d06092a864886f70d01010105000382010f003082010a02820101009e30723d83fa5e",
        "2a99a10fe0a0e66ad84e9a73047c29bac86a1f50cfe9624ba1c52ec35dbc1752bf5c47936ac8618c4cad67a9b7ca",
        "11eb63435950bbbbfcf567d444619837e54ad3624fb48517b6cf8364bf44952e2f66e1af447628e0c92112b71454",
        "9ff3747515677c66534d59ea649cd1399db71afe8c105f9e5ab2fc8c47e84acece246beff11957b9b083892be25d",
        "28d5bb0475377566a79186fc8828ccb44e0cdb91523f9f5fcb129ba243ba18a7e48789a1ae181d619d48d7dd3e8e",
        "24f1adc644813669c2f7dbbeacf2b75e2e9171307944940126be258a985d85720559af1ab0128cac0365734f953a",
        "da547bb764c15f24a618c32d25485259f858a90203010001a350304e300e0603551d0f0101ff0404030205a0301d",
        "0603551d250416301406082b0601050507030206082b06010505070301301d0603551d0e0416041444211a92e6cd",
        "70218a48e9664a265821036c8169300d06092a864886f70d01010b05000382010100067182853bb1820a0ba7fde3",
        "c6916a7da185a634d774c22930de5b2225c75330bb24b298227a95a181012473f5308d761fa9f03294c56e9813c6",
        "1768ad931b5f3bb22969688ce84729727fe06dbccb4ae484044798399b553bc839eb562f4acd2fa4b8ce222f8045",
        "11bad287311a3ccadd72c99b701979f469005cd0103fe6b8106b4c65f09b34b33ec690d9809afe3ad72c8cebdeaa",
        "62240b85d4edd55ceff32a40c52176ddf22c3dbdb5feb3bc0fa2eb51408997788c1cb701dce897c4434e7ebfb9e6",
        "9f538904c9d1e19b82a28824bb8343bd1ed08e48ff54b4440ab85e7c347d8ebc263ccce55c1c17f839b313a3b0b5",
        "d5cc3baf6be2f4dd69c9ea7ab5d4"
    );

    let der_bytes = hex::decode(cert_hex).expect("valid hex DER");
    let ek = TpmEkCertificate::from_der(der_bytes).expect("parse valid DER EK cert");

    assert_eq!(ek.vendor, TpmOemVendor::Intel);
    assert!(ek.subject.as_ref().unwrap().contains("Intel Corporation"));
    assert!(ek.issuer.as_ref().unwrap().contains("Intel Corporation"));
    assert!(ek.cert_fingerprint.is_some());
    assert_eq!(ek.cert_fingerprint.as_ref().unwrap().len(), 64);
    assert!(ek.public_key_hex.is_some());
}

#[test]
fn test_inspect_tpm_hardware_returns_valid_struct_and_speed() {
    let _lock = TPM_TEST_MUTEX.lock().unwrap();
    let start = Instant::now();
    let inspection: TpmHardwareInspection = inspect_tpm_hardware();
    let elapsed = start.elapsed();

    // Must be fast (< 50ms even on cold run, sub-millisecond on warm run)
    assert!(
        elapsed.as_millis() < 50,
        "TPM hardware inspection took too long: {:?}",
        elapsed
    );

    assert_eq!(inspection.tpm_version, "2.0");
    assert_eq!(inspection.pcr_values.len(), 3);
    assert!(inspection.pcr_values.contains_key(&0));
    assert!(inspection.pcr_values.contains_key(&7));
    assert!(inspection.pcr_values.contains_key(&16));
    assert_eq!(inspection.composite_digest.len(), 64);
}

#[test]
fn test_tpm_oem_vendor_mapping() {
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0x494E5443, ""),
        TpmOemVendor::Intel
    );
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0x414D4400, ""),
        TpmOemVendor::Amd
    );
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0x49465800, ""),
        TpmOemVendor::Infineon
    );
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0x53544D20, ""),
        TpmOemVendor::StMicro
    );
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0x4E544300, ""),
        TpmOemVendor::Nuvoton
    );
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0x4E545A00, ""),
        TpmOemVendor::Nationz
    );
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0x41544D4C, ""),
        TpmOemVendor::Microchip
    );
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0, "Intel Corporation"),
        TpmOemVendor::Intel
    );
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0, "Nuvoton Technology"),
        TpmOemVendor::Nuvoton
    );
    assert_eq!(
        TpmOemVendor::from_manufacturer_id_or_str(0, "Random Unregistered Silicon"),
        TpmOemVendor::Unknown
    );
}

#[test]
fn test_peer_acl_dynamic_attestation_gating() {
    let mut acl = PeerAclManager::new(AccessTier::Tier0Public);

    let peer_hw_ek = "peer_hw_ek";
    let peer_hw_tpm = "peer_hw_tpm";
    let peer_sim = "peer_sim";
    let peer_unver = "peer_unver";

    // All peers statically whitelisted for Tier 3 Restricted
    acl.register_peer_id(peer_hw_ek.to_string(), AccessTier::Tier3Restricted);
    acl.register_peer_id(peer_hw_tpm.to_string(), AccessTier::Tier3Restricted);
    acl.register_peer_id(peer_sim.to_string(), AccessTier::Tier3Restricted);
    acl.register_peer_id(peer_unver.to_string(), AccessTier::Tier3Restricted);

    let now = Utc::now();
    let expires = now + Duration::seconds(300);

    // Record attestation records
    acl.record_peer_attestation(PeerAttestationRecord {
        peer_id: peer_hw_ek.to_string(),
        pubkey: None,
        attestation_tier: AttestationTier::VerifiedHardwareEk,
        vendor: Some(TpmOemVendor::Amd),
        pcr_composite_digest: Some("c0".to_string()),
        hardware_backed: true,
        ek_fingerprint: Some("ek_fp".to_string()),
        verified_at: now,
        expires_at: expires,
    });

    acl.record_peer_attestation(PeerAttestationRecord {
        peer_id: peer_hw_tpm.to_string(),
        pubkey: None,
        attestation_tier: AttestationTier::VerifiedHardwareTpm,
        vendor: Some(TpmOemVendor::Intel),
        pcr_composite_digest: Some("c1".to_string()),
        hardware_backed: true,
        ek_fingerprint: None,
        verified_at: now,
        expires_at: expires,
    });

    acl.record_peer_attestation(PeerAttestationRecord {
        peer_id: peer_sim.to_string(),
        pubkey: None,
        attestation_tier: AttestationTier::Simulated,
        vendor: None,
        pcr_composite_digest: Some("c2".to_string()),
        hardware_backed: false,
        ek_fingerprint: None,
        verified_at: now,
        expires_at: expires,
    });

    // Check effective tiers bounded monotonically by attestation:
    // 1. Hardware EK -> Tier 3
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(peer_hw_ek),
        AccessTier::Tier3Restricted
    );

    // 2. Hardware TPM -> Tier 2
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(peer_hw_tpm),
        AccessTier::Tier2Confidential
    );

    // 3. Simulated -> Tier 1
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(peer_sim),
        AccessTier::Tier1Internal
    );

    // 4. Unverified -> Tier 0
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(peer_unver),
        AccessTier::Tier0Public
    );
}

#[test]
fn test_peer_acl_attestation_expiration_downgrade() {
    let mut acl = PeerAclManager::new(AccessTier::Tier0Public);
    let peer_id = "peer_expiring";

    acl.register_peer_id(peer_id.to_string(), AccessTier::Tier3Restricted);

    // Record attestation already expired in the past
    let now = Utc::now();
    let past = now - Duration::seconds(10);

    acl.record_peer_attestation(PeerAttestationRecord {
        peer_id: peer_id.to_string(),
        pubkey: None,
        attestation_tier: AttestationTier::VerifiedHardwareEk,
        vendor: Some(TpmOemVendor::Nuvoton),
        pcr_composite_digest: Some("c0".to_string()),
        hardware_backed: true,
        ek_fingerprint: Some("ek0".to_string()),
        verified_at: past - Duration::seconds(300),
        expires_at: past,
    });

    // Since attestation is expired, tier MUST downgrade to Tier 0 Public
    assert_eq!(acl.get_attestation_tier(peer_id), AttestationTier::Unverified);
    assert_eq!(
        acl.get_effective_authorized_tier_for_peer_id(peer_id),
        AccessTier::Tier0Public
    );
}
