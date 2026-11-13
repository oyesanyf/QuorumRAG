//! Comprehensive Integration Tests for Artemis DFIR P2P Mesh Airgap & Forensic Structural Normalizer.
//!
//! Validates Requirements R3 & R4:
//! 1. Default-off settings and airgap predicates.
//! 2. Unconditional suppression and filtering of artemis:// URIs and Tier3Restricted chunks in P2P mesh.
//! 3. Keyed BLAKE3 forensic structural normalization preserving investigation topology and system entities.
//! 4. Mathematical RFC1918/Loopback/Link-Local/CGNAT IP detection.
//! 5. Artifact category gate strictly rejecting prohibited forensic categories.

use quorum_contract::TrainingRecordFormat;
use quorum_coordinator::artemis_airgap::*;
use quorum_coordinator::dlp_mesh::{
    global_mesh_dlp_controller, OsoosiMeshDlpController, PersistedDaemonSettings,
};
use quorum_coordinator::forensic_normalizer::*;
use quorum_coordinator::marketplace_engine::RawTrajectoryCandidate;
use quorum_types::{AccessTier, CandidateChunkDto, DocumentChunk, VolatileRemoteChunk};
use std::sync::RwLock;

#[test]
fn test_artemis_settings_default_values_and_serde() {
    let settings = ArtemisDfirSettings::default();
    assert!(!settings.enabled, "Master toggle must be disabled by default");
    assert!(!settings.local_collection_enabled, "Local collection must be disabled by default");
    assert!(!settings.marketplace_harvest_enabled, "Marketplace harvest must be disabled by default");
    assert_eq!(settings.auto_collection_interval_mins, 0);
    assert_eq!(settings.retention_days, 30);
    assert!(settings.redact_secrets);
    assert!(settings.normalize_for_harvest);

    let allowed = default_allowed_categories();
    assert_eq!(allowed.len(), 6);
    assert!(allowed.contains(&"process_execution".to_string()));
    assert!(allowed.contains(&"network_connection".to_string()));
    assert!(allowed.contains(&"registry_persistence".to_string()));
    assert!(allowed.contains(&"system_event_log".to_string()));
    assert!(allowed.contains(&"prefetch_amcache_execution".to_string()));
    assert!(allowed.contains(&"service_daemon".to_string()));

    let prohibited = prohibited_categories();
    assert_eq!(prohibited.len(), 4);
    assert!(prohibited.contains(&"browser_cookies"));
    assert!(prohibited.contains(&"browser_history_oauth"));
    assert!(prohibited.contains(&"credential_store"));
    assert!(prohibited.contains(&"shell_history_raw"));

    // Verify serde integration with PersistedDaemonSettings
    let json = serde_json::to_string(&settings).expect("serialize settings");
    let deser: ArtemisDfirSettings = serde_json::from_str(&json).expect("deserialize settings");
    assert_eq!(settings, deser);

    // Verify backward compatibility when artemis field is omitted from JSON
    let default_daemon = PersistedDaemonSettings::default();
    let mut val = serde_json::to_value(&default_daemon).expect("serialize daemon settings");
    val.as_object_mut().unwrap().remove("artemis");
    let legacy_json = serde_json::to_string(&val).expect("serialize legacy json");
    let restored: PersistedDaemonSettings =
        serde_json::from_str(&legacy_json).expect("deserialize legacy json with default artemis");
    assert_eq!(restored.artemis, ArtemisDfirSettings::default());
}

#[test]
fn test_airgap_predicates_uri_and_query() {
    // URIs
    assert!(is_artemis_uri("artemis://windows/eventlog/security/4688"));
    assert!(is_artemis_uri("ARTEMIS://macos/unified_log/audit"));
    assert!(is_artemis_uri("   artemis://linux/journald   "));
    assert!(is_artemis_uri("prefix/artemis://nested"));
    assert!(!is_artemis_uri("C:\\Users\\admin\\report.txt"));
    assert!(!is_artemis_uri("/var/log/syslog"));
    assert!(!is_artemis_uri("https://example.com/artemis_docs"));

    // Queries
    assert!(contains_artemis_query("Find process from artemis://evtx/4688"));
    assert!(contains_artemis_query("ARTEMIS://connection/established"));
    assert!(!contains_artemis_query("Find all windows event log 4688"));
    assert!(!contains_artemis_query("Search for process creation logs"));
}

#[test]
fn test_is_airgap_restricted_chunk_dto() {
    let mut chunk = CandidateChunkDto {
        chunk_id: "doc-1:0".to_string(),
        file_path: "C:\\shared\\report.txt".to_string(),
        line_start: 1,
        line_end: 10,
        content: "Clean content".to_string(),
        score: 0.85,
        access_tier: AccessTier::Tier0Public.as_u8(),
        origin_peer_id: None,
    };
    assert!(!is_airgap_restricted_chunk_dto(&chunk));

    chunk.access_tier = AccessTier::Tier1Internal.as_u8();
    assert!(!is_airgap_restricted_chunk_dto(&chunk));

    chunk.access_tier = AccessTier::Tier2Confidential.as_u8();
    assert!(!is_airgap_restricted_chunk_dto(&chunk));

    // AccessTier >= 3 is restricted
    chunk.access_tier = AccessTier::Tier3Restricted.as_u8();
    assert!(is_airgap_restricted_chunk_dto(&chunk));

    // artemis:// path is restricted regardless of tier
    chunk.access_tier = AccessTier::Tier0Public.as_u8();
    chunk.file_path = "artemis://windows/registry/run".to_string();
    assert!(is_airgap_restricted_chunk_dto(&chunk));
}

#[test]
fn test_is_airgap_restricted_chunk_document_chunk() {
    let mut chunk = DocumentChunk {
        chunk_id: "chunk-1:0".to_string(),
        document_id: "doc-1".to_string(),
        file_path: "C:\\docs\\notes.md".to_string(),
        line_start: 1,
        line_end: 5,
        blake3_hash: "abcd".to_string(),
        access_tier: 0,
        vector: vec![0.0; 768],
        text_content: "Meeting notes".to_string(),
        metadata_json: "{}".to_string(),
    };
    assert!(!is_airgap_restricted_chunk(&chunk));

    // Tier 3 restricted
    chunk.access_tier = 3;
    assert!(is_airgap_restricted_chunk(&chunk));
    chunk.access_tier = 0;

    // artemis:// URI
    chunk.file_path = "artemis://linux/proc/self".to_string();
    assert!(is_airgap_restricted_chunk(&chunk));
    chunk.file_path = "C:\\docs\\notes.md".to_string();

    // Metadata flags
    chunk.metadata_json = r#"{"artemis_dfir": true}"#.to_string();
    assert!(is_airgap_restricted_chunk(&chunk));

    chunk.metadata_json = r#"{"artemis_dfir": false, "mesh_sharable": false}"#.to_string();
    assert!(is_airgap_restricted_chunk(&chunk));

    chunk.metadata_json = r#"{"artemis_dfir": false, "mesh_sharable": true}"#.to_string();
    assert!(!is_airgap_restricted_chunk(&chunk));
}

#[test]
fn test_dlp_mesh_check_file_shared_with_mesh_airgap_block() {
    let controller = OsoosiMeshDlpController {
        settings: RwLock::new(PersistedDaemonSettings {
            mesh: quorum_coordinator::OsoosiMeshSettings {
                p2p_enabled: true,
                require_explicit_folder_share: false, // In normal mode, this shares all folders ("*")
                shared_folders: Vec::new(),
                ..Default::default()
            },
            ..Default::default()
        }),
        stats: RwLock::new(Default::default()),
        settings_file_path: RwLock::new(None),
        hmac_secret: [0u8; 32],
    };

    // A normal file gets shared under fallback
    let normal = controller.check_file_shared_with_mesh("C:\\public\\file.txt");
    assert!(normal.is_some());

    // An artemis file is unconditionally blocked even with require_explicit_folder_share = false!
    let blocked = controller.check_file_shared_with_mesh("artemis://windows/eventlog");
    assert!(blocked.is_none(), "artemis:// URI must be rejected unconditionally");
}

#[test]
fn test_dlp_mesh_filter_and_enforce_outbound_mesh_chunks() {
    let controller = OsoosiMeshDlpController {
        settings: RwLock::new(PersistedDaemonSettings {
            mesh: quorum_coordinator::OsoosiMeshSettings {
                p2p_enabled: true,
                require_explicit_folder_share: false,
                shared_folders: Vec::new(),
                ..Default::default()
            },
            ..Default::default()
        }),
        stats: RwLock::new(Default::default()),
        settings_file_path: RwLock::new(None),
        hmac_secret: [0u8; 32],
    };

    let chunks = vec![
        CandidateChunkDto {
            chunk_id: "c1".to_string(),
            file_path: "C:\\shared\\report.txt".to_string(),
            line_start: 1,
            line_end: 10,
            content: "Safe public report data".to_string(),
            score: 0.9,
            access_tier: 0,
            origin_peer_id: None,
        },
        CandidateChunkDto {
            chunk_id: "c2".to_string(),
            file_path: "artemis://windows/eventlog/4688".to_string(),
            line_start: 1,
            line_end: 10,
            content: "Process cmdline execution".to_string(),
            score: 0.95,
            access_tier: 0,
            origin_peer_id: None,
        },
        CandidateChunkDto {
            chunk_id: "c3".to_string(),
            file_path: "C:\\shared\\classified.txt".to_string(),
            line_start: 1,
            line_end: 10,
            content: "Restricted tier chunk".to_string(),
            score: 0.92,
            access_tier: 3, // Tier3Restricted,
            origin_peer_id: None,
        },
    ];

    let filtered = controller.filter_and_enforce_outbound_mesh_chunks(chunks, "peer_123");
    assert_eq!(filtered.len(), 1, "Only the clean public chunk should survive");
    assert_eq!(filtered[0].chunk_id, "c1");

    let stats = controller.stats.read().unwrap();
    assert!(stats.total_blocked_chunks >= 2);
}

#[test]
fn test_dlp_mesh_sanitize_outbound_query() {
    let controller = global_mesh_dlp_controller();

    // Query targeting artemis:// must be suppressed (return None)
    let res = controller.sanitize_outbound_query("Search artemis://security/events for user");
    assert!(res.is_none(), "Outbound query with artemis:// must be suppressed");

    // Standard benign query passes
    let clean = controller.sanitize_outbound_query("Find deployment instructions for Rust microservice");
    assert!(clean.is_some());
}

#[test]
fn test_dlp_mesh_enforce_inbound_remote_chunks() {
    let controller = OsoosiMeshDlpController {
        settings: RwLock::new(PersistedDaemonSettings {
            mesh: quorum_coordinator::OsoosiMeshSettings {
                p2p_enabled: true,
                require_explicit_folder_share: false,
                shared_folders: Vec::new(),
                ..Default::default()
            },
            ..Default::default()
        }),
        stats: RwLock::new(Default::default()),
        settings_file_path: RwLock::new(None),
        hmac_secret: [0u8; 32],
    };

    let inbound = vec![
        VolatileRemoteChunk {
            chunk_id: "c_remote_1".to_string(),
            file_path: "C:\\peer\\doc.txt".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Normal peer doc".to_string(),
            score: 0.8,
            peer_id: "peer_remote".to_string(),
            access_tier: 0,
        },
        VolatileRemoteChunk {
            chunk_id: "c_remote_2".to_string(),
            file_path: "artemis://byzantine/leak".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Byzantine leaked forensic data".to_string(),
            score: 0.99,
            peer_id: "peer_byzantine".to_string(),
            access_tier: 0,
        },
    ];

    let sanitized = controller.enforce_inbound_remote_chunks(inbound);
    assert_eq!(sanitized.len(), 1);
    assert_eq!(sanitized[0].chunk_id, "c_remote_1");
}

#[test]
fn test_forensic_normalizer_system_account_preservation() {
    let mut normalizer = ForensicStructuralNormalizer::new([1u8; 32]);

    assert_eq!(normalizer.pseudonymize_username("system"), "system");
    assert_eq!(normalizer.pseudonymize_username("SYSTEM"), "SYSTEM");
    assert_eq!(normalizer.pseudonymize_username("NT AUTHORITY\\SYSTEM"), "NT AUTHORITY\\SYSTEM");
    assert_eq!(normalizer.pseudonymize_username("root"), "root");
    assert_eq!(normalizer.pseudonymize_username("nobody"), "nobody");
    assert_eq!(normalizer.pseudonymize_username("daemon"), "daemon");
    assert_eq!(normalizer.pseudonymize_username("local service"), "local service");
    assert_eq!(normalizer.pseudonymize_username("network service"), "network service");

    // Standard user is pseudonymized
    let user_p = normalizer.pseudonymize_username("jsmith");
    assert!(user_p.starts_with("USER_"));
    assert_eq!(normalizer.pseudonymize_username("jsmith"), user_p, "Same session must be consistent");

    // Hostnames
    assert_eq!(normalizer.pseudonymize_hostname("localhost"), "localhost");
    let host_p = normalizer.pseudonymize_hostname("CORP-DC01");
    assert!(host_p.starts_with("HOST_"));

    // SIDs
    assert_eq!(normalizer.pseudonymize_sid("S-1-5-18"), "S-1-5-18");
    assert_eq!(normalizer.pseudonymize_sid("S-1-5-19"), "S-1-5-19");
    assert_eq!(normalizer.pseudonymize_sid("S-1-5-20"), "S-1-5-20");
    assert_eq!(normalizer.pseudonymize_sid("S-1-5-32-544"), "S-1-5-32-544");

    let domain_sid = "S-1-5-21-3623811015-3361044348-30300820-1013";
    let sid_p = normalizer.pseudonymize_sid(domain_sid);
    assert!(sid_p.starts_with("SID_"));
    assert_ne!(sid_p, domain_sid);
}

#[test]
fn test_forensic_normalizer_ip_and_mac_and_unc_preservation() {
    let mut normalizer = ForensicStructuralNormalizer::new([5u8; 32]);

    // RFC1918 IPs
    let ip1 = normalizer.pseudonymize_ip("192.168.1.150");
    assert!(ip1.starts_with("IP_"));

    // MAC address
    let mac1 = normalizer.pseudonymize_mac("00:1A:2B:3C:4D:5E");
    assert!(mac1.starts_with("MAC_"));

    // SMB UNC path preserves path topology
    let unc = r"\\CORP-FILESERVER\DeptShare\Finance\Q3_Report.xlsx";
    let unc_p = normalizer.pseudonymize_smb_share(unc);
    assert!(unc_p.starts_with(r"\\HOST_"));
    assert!(unc_p.contains(r"\SHARE_"));
    assert!(unc_p.ends_with(r"\Finance\Q3_Report.xlsx"));
}

#[test]
fn test_forensic_normalizer_full_text_and_preview() {
    let mut normalizer = ForensicStructuralNormalizer::new([9u8; 32]);

    let raw_telemetry = r#"
LogEntry: Security Event 4624
ComputerName: CORP-DC01
SubjectUserName: NT AUTHORITY\SYSTEM
TargetUserName: jsmith
TargetDomainName: CONTOSO
Workstation: WORKSTATION-42
IpAddress: 10.0.4.15
ShareName: \\FILESERVER01\Finance\Audit.xlsx
MacAddress: 00-50-56-C0-00-08
TargetSid: S-1-5-21-12345678-87654321-11223344-500
WellKnownSid: S-1-5-18
ExternalIp: 8.8.8.8
"#;

    let preview = normalizer.preview_normalization(raw_telemetry);
    assert!(preview.total_replacements > 0);
    assert_eq!(preview.original_text, raw_telemetry);
    assert!(!preview.normalized_text.contains("CORP-DC01"));
    assert!(!preview.normalized_text.contains("10.0.4.15"));
    assert!(!preview.normalized_text.contains("00-50-56-C0-00-08"));
    assert!(!preview.normalized_text.contains("S-1-5-21-12345678-87654321-11223344-500"));

    // Preserved entities remain intact
    assert!(preview.normalized_text.contains("NT AUTHORITY\\SYSTEM"));
    assert!(preview.normalized_text.contains("S-1-5-18"));
    assert!(preview.normalized_text.contains("8.8.8.8"), "Public IP must not be altered");
}

#[test]
fn test_forensic_normalizer_candidate_normalization() {
    let mut normalizer = ForensicStructuralNormalizer::new([11u8; 32]);

    let candidate = RawTrajectoryCandidate {
        record_id: "traj-001".to_string(),
        origin_node_id: "node-alpha".to_string(),
        format: TrainingRecordFormat::DpoPreferencePair,
        domain_tags: vec!["process_execution".to_string()],
        prompt: "Analyze event TargetUserName: malicious_actor on Host: WIN-SRV01 connecting to 172.16.0.4".to_string(),
        rlm_trajectory: vec![quorum_contract::SanitizedRlmStep {
            step_index: 0,
            action_kind: "search".to_string(),
            sanitized_query_or_pattern: "Check connection from 172.16.0.4 to share \\\\SRV01\\Admin$".to_string(),
            abstracted_takeaway: "Found lateral movement from 172.16.0.4 to \\\\SRV01\\Admin$".to_string(),
        }],
        chosen_response: "Identified compromised account TargetUserName: malicious_actor on Host: WIN-SRV01".to_string(),
        rejected_response: Some("Failed to identify actor TargetUserName: malicious_actor".to_string()),
        citations: vec![(
            "Observed TargetUserName: malicious_actor on Host: WIN-SRV01".to_string(),
            "TargetUserName: malicious_actor".to_string(),
        )],
        extra_redact_terms: Vec::new(),
        created_unix_secs: 1700000000,
        source_file_path: Some("C:\\evidence\\triage.jsonl".to_string()),
        interaction_nonce_hex: None,
    };

    let normalized = normalizer.normalize_candidate(&candidate);
    assert!(!normalized.prompt.contains("172.16.0.4"));
    assert!(normalized.prompt.contains("IP_"));
    assert!(!normalized.chosen_response.contains("WIN-SRV01"));
    assert!(normalized.chosen_response.contains("HOST_"));
}

#[test]
fn test_artifact_category_gate_allowlist_and_prohibited_rejection() {
    let gate = ArtifactCategoryGate::default();

    // 1. Valid defensive categories pass
    for allowed_tag in &[
        "process_execution",
        "network_connection",
        "registry_persistence",
        "system_event_log",
        "prefetch_amcache_execution",
        "service_daemon",
    ] {
        let cand = RawTrajectoryCandidate {
            record_id: "valid".to_string(),
            origin_node_id: "n".to_string(),
            format: TrainingRecordFormat::DpoPreferencePair,
            domain_tags: vec![allowed_tag.to_string()],
            prompt: "defensive reasoning".to_string(),
            rlm_trajectory: Vec::new(),
            chosen_response: "safe".to_string(),
            rejected_response: None,
            citations: Vec::new(),
            extra_redact_terms: Vec::new(),
            created_unix_secs: 100,
            source_file_path: Some("C:\\logs\\triage.jsonl".to_string()),
            interaction_nonce_hex: None,
        };
        assert!(gate.evaluate_candidate(&cand).is_ok(), "Category '{}' must be accepted", allowed_tag);
    }

    // 2. Prohibited categories fail
    for prohibited_tag in &[
        "browser_cookies",
        "browser_history_oauth",
        "credential_store",
        "shell_history_raw",
    ] {
        let cand = RawTrajectoryCandidate {
            record_id: "prohibited".to_string(),
            origin_node_id: "n".to_string(),
            format: TrainingRecordFormat::DpoPreferencePair,
            domain_tags: vec![prohibited_tag.to_string()],
            prompt: "sensitive dump".to_string(),
            rlm_trajectory: Vec::new(),
            chosen_response: "leak".to_string(),
            rejected_response: None,
            citations: Vec::new(),
            extra_redact_terms: Vec::new(),
            created_unix_secs: 100,
            source_file_path: Some("C:\\logs\\triage.jsonl".to_string()),
            interaction_nonce_hex: None,
        };
        assert!(gate.evaluate_candidate(&cand).is_err(), "Category '{}' must be rejected", prohibited_tag);
    }

    // 3. Prohibited path patterns fail
    let sensitive_paths = [
        "C:\\Users\\Bob\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Users\\Alice\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        "/etc/shadow",
    ];
    for path in &sensitive_paths {
        let cand = RawTrajectoryCandidate {
            record_id: "bad_path".to_string(),
            origin_node_id: "n".to_string(),
            format: TrainingRecordFormat::DpoPreferencePair,
            domain_tags: vec!["process_execution".to_string()],
            prompt: "reasoning".to_string(),
            rlm_trajectory: Vec::new(),
            chosen_response: "safe".to_string(),
            rejected_response: None,
            citations: Vec::new(),
            extra_redact_terms: Vec::new(),
            created_unix_secs: 100,
            source_file_path: Some(path.to_string()),
            interaction_nonce_hex: None,
        };
        assert!(gate.evaluate_candidate(&cand).is_err(), "Path '{}' must be rejected by category gate", path);
    }
}
