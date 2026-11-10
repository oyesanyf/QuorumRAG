//! Empirical Adversarial Challenger Test Suite for Milestone 3:
//! Keyed BLAKE3 Normalizer & Artifact Category Gate in `crates/quorum-coordinator`.
//!
//! # Stress & Adversarial Dimensions:
//! 1. Deterministic pseudonym consistency across complex multi-step trajectories:
//!    $E_1 \equiv E_2 \implies P(E_1) \equiv P(E_2)$.
//! 2. Cryptographic session isolation across ephemeral seeds:
//!    $P_{sess1}(E) \neq P_{sess2}(E)$ and $P_{node1, sess}(E) \neq P_{node2, sess}(E)$.
//! 3. Cross-category collision freedom via BLAKE3 domain separation tags:
//!    Identical entity string mapped to user, host, sid, ip, share, mac yields mutually distinct digests.
//! 4. Boundary edge cases & invariant preservation:
//!    - Built-in system accounts (`SYSTEM`, `NT AUTHORITY\SYSTEM`, `root`, `nobody`, `daemon`, `local service`, `network service`).
//!    - Well-known SIDs (`S-1-5-18`, `S-1-5-19`, `S-1-5-20`, `S-1-5-32-544`) vs user SIDs.
//!    - Hostname preservation (`localhost`).
//!    - Mathematical IP classification: RFC1918, CGNAT, Loopback, Link-Local, ULA IPv6, IPv4-mapped vs Public IPs.
//!    - SMB UNC path decomposition with hierarchy preservation.
//!    - Hardware MAC addresses in colon and hyphen formats.
//! 5. ArtifactCategoryGate zero-leakage enforcement:
//!    - 100% rejection of all prohibited categories (`browser_cookies`, `browser_history_oauth`, `credential_store`, `shell_history_raw`).
//!    - 100% rejection of prohibited source file paths (SAM, SECURITY, shadow, DPAPI, keychain, shell histories).
//!    - 100% allowlisting of legitimate defensive execution telemetry.
//! 6. Live preview statistics and mapping fidelity.

use quorum_contract::{ForensicTelemetryType, SanitizedRlmStep, TrainingRecordFormat};
use quorum_coordinator::forensic_normalizer::{
    is_internal_private_ip, ArtifactCategoryGate, ForensicStructuralNormalizer,
};
use quorum_coordinator::marketplace_engine::RawTrajectoryCandidate;
use std::collections::HashSet;

/// Helper function to construct a rich, multi-step forensic trajectory candidate.
fn create_test_candidate(
    record_id: &str,
    domain_tags: Vec<String>,
    source_path: Option<String>,
    prompt: &str,
    chosen: &str,
    rejected: Option<&str>,
    trajectory_steps: Vec<(&str, &str)>,
    citations: Vec<(&str, &str)>,
) -> RawTrajectoryCandidate {
    let rlm_steps = trajectory_steps
        .into_iter()
        .enumerate()
        .map(|(i, (query, takeaway))| SanitizedRlmStep {
            step_index: i,
            action_kind: format!("tool_{}", i),
            sanitized_query_or_pattern: query.to_string(),
            abstracted_takeaway: takeaway.to_string(),
        })
        .collect();

    let cite_pairs = citations
        .into_iter()
        .map(|(s, q)| (s.to_string(), q.to_string()))
        .collect();

    RawTrajectoryCandidate {
        record_id: record_id.to_string(),
        origin_node_id: "node-challenger-01".to_string(),
        format: TrainingRecordFormat::DpoPreferencePair,
        domain_tags,
        prompt: prompt.to_string(),
        rlm_trajectory: rlm_steps,
        chosen_response: chosen.to_string(),
        rejected_response: rejected.map(|r| r.to_string()),
        citations: cite_pairs,
        extra_redact_terms: Vec::new(),
        created_unix_secs: 1731210000,
        source_file_path: source_path,
        interaction_nonce_hex: Some("0123456789abcdef0123456789abcdef".to_string()),
    }
}

// ============================================================================
// 1. DETERMINISTIC PSEUDONYM CONSISTENCY ACROSS MULTI-STEP TRAJECTORIES
// ============================================================================

#[test]
fn test_adversarial_deterministic_pseudonym_consistency_across_complex_trajectories() {
    let node_seed = [0x5au8; 32];
    let session_id = "session-audit-2026-q1";
    let mut normalizer = ForensicStructuralNormalizer::from_node_seed(&node_seed, session_id);

    // Entity strings that repeat across prompt, chosen response, rejected response,
    // multiple trajectory steps, and citations.
    let user_entity = "johndoe_corp";
    let host_entity = "corp-workstation-88";
    let sid_entity = "S-1-5-21-3623811015-3361044348-30300820-1013";
    let ip_entity = "192.168.1.105";
    let unc_entity = "\\\\corp-workstation-88\\ConfidentialShare\\Audits\\Financial_Audit.xlsx";
    let mac_entity = "00:1A:2B:3C:4D:5E";

    let prompt = format!(
        "Investigating security event on User: {} with ComputerName: {} at IP {} (MAC {}). Target SID was {}. Shared file: {}.",
        user_entity, host_entity, ip_entity, mac_entity, sid_entity, unc_entity
    );

    let chosen = format!(
        "The attack originated from User: {} on Host: {}. Artifact recovered from {} and IP {}. SID: {}.",
        user_entity, host_entity, unc_entity, ip_entity, sid_entity
    );

    let rejected = format!(
        "Benign activity by User: {} from Computer: {} using network interface {}.",
        user_entity, host_entity, mac_entity
    );

    let steps = vec![
        (
            format!("Query logs for User: {} on Host: {}", user_entity, host_entity),
            format!("Found persistence at {} from IP {}", unc_entity, ip_entity),
        ),
        (
            format!("Correlate MAC {} with IP {}", mac_entity, ip_entity),
            format!("Host: {} authenticated under SID: {}", host_entity, sid_entity),
        ),
        (
            format!("Inspect share {} under User: {}", unc_entity, user_entity),
            format!("Identified compromised credentials for User: {}", user_entity),
        ),
    ];

    let citations = vec![
        (
            format!("EvtLog 4688: User: {} spawned process on Host: {}", user_entity, host_entity),
            format!("Subject SID: {}, Source IP: {}", sid_entity, ip_entity),
        ),
        (
            format!("NetFlow: Connection from IP {} (MAC {})", ip_entity, mac_entity),
            format!("Destination SMB share: {}", unc_entity),
        ),
    ];

    let candidate = create_test_candidate(
        "candidate-trajectory-consistency-01",
        vec!["process_execution".to_string(), "network_connection".to_string()],
        Some("C:\\Windows\\System32\\winevt\\Logs\\System.evtx".to_string()),
        &prompt,
        &chosen,
        Some(&rejected),
        steps.iter().map(|(q, t)| (q.as_str(), t.as_str())).collect(),
        citations.iter().map(|(s, q)| (s.as_str(), q.as_str())).collect(),
    );

    // Normalize candidate
    let normalized = normalizer.normalize_candidate(&candidate);

    // Extract the pseudonym assigned to the user
    // A fresh normalizer with identical session should derive the exact same pseudonym
    let mut oracle_normalizer = ForensicStructuralNormalizer::from_node_seed(&node_seed, session_id);
    let expected_user_pseudo = oracle_normalizer.pseudonymize_username(user_entity);
    let expected_host_pseudo = oracle_normalizer.pseudonymize_hostname(host_entity);
    let expected_sid_pseudo = oracle_normalizer.pseudonymize_sid(sid_entity);
    let expected_ip_pseudo = oracle_normalizer.pseudonymize_ip(ip_entity);
    let expected_mac_pseudo = oracle_normalizer.pseudonymize_mac(mac_entity);
    let expected_unc_pseudo = oracle_normalizer.pseudonymize_smb_share(unc_entity);

    assert!(expected_user_pseudo.starts_with("USER_"));
    assert!(expected_host_pseudo.starts_with("HOST_"));
    assert!(expected_sid_pseudo.starts_with("SID_"));
    assert!(expected_ip_pseudo.starts_with("IP_"));
    assert!(expected_mac_pseudo.starts_with("MAC_"));
    assert!(expected_unc_pseudo.starts_with("\\\\"));

    // Verify Invariant: E1 == E2 => P(E1) == P(E2) across ALL candidate fields
    // 1. Prompt check
    assert!(normalized.prompt.contains(&expected_user_pseudo), "Prompt missing user pseudonym");
    assert!(normalized.prompt.contains(&expected_host_pseudo), "Prompt missing host pseudonym");
    assert!(normalized.prompt.contains(&expected_sid_pseudo), "Prompt missing sid pseudonym");
    assert!(normalized.prompt.contains(&expected_ip_pseudo), "Prompt missing ip pseudonym");
    assert!(normalized.prompt.contains(&expected_mac_pseudo), "Prompt missing mac pseudonym");
    assert!(normalized.prompt.contains(&expected_unc_pseudo), "Prompt missing unc pseudonym");
    assert!(!normalized.prompt.contains(user_entity), "Prompt leaked raw user entity!");
    assert!(!normalized.prompt.contains(host_entity), "Prompt leaked raw host entity!");
    assert!(!normalized.prompt.contains(sid_entity), "Prompt leaked raw sid entity!");
    assert!(!normalized.prompt.contains(ip_entity), "Prompt leaked raw ip entity!");
    assert!(!normalized.prompt.contains(mac_entity), "Prompt leaked raw mac entity!");

    // 2. Chosen response check
    assert!(normalized.chosen_response.contains(&expected_user_pseudo));
    assert!(normalized.chosen_response.contains(&expected_host_pseudo));
    assert!(normalized.chosen_response.contains(&expected_sid_pseudo));
    assert!(normalized.chosen_response.contains(&expected_ip_pseudo));
    assert!(normalized.chosen_response.contains(&expected_unc_pseudo));
    assert!(!normalized.chosen_response.contains(user_entity));

    // 3. Rejected response check
    let norm_rejected = normalized.rejected_response.as_ref().expect("rejected response present");
    assert!(norm_rejected.contains(&expected_user_pseudo));
    assert!(norm_rejected.contains(&expected_host_pseudo));
    assert!(norm_rejected.contains(&expected_mac_pseudo));
    assert!(!norm_rejected.contains(user_entity));

    // 4. RLM Trajectory steps check
    for (i, step) in normalized.rlm_trajectory.iter().enumerate() {
        assert!(!step.sanitized_query_or_pattern.contains(user_entity), "Step {} leaked raw user", i);
        assert!(!step.sanitized_query_or_pattern.contains(host_entity), "Step {} leaked raw host", i);
        assert!(!step.abstracted_takeaway.contains(user_entity), "Step {} takeaway leaked raw user", i);
        assert!(!step.abstracted_takeaway.contains(ip_entity), "Step {} takeaway leaked raw ip", i);
        assert!(!step.abstracted_takeaway.contains(sid_entity), "Step {} takeaway leaked raw sid", i);
    }

    // 5. Citations check
    assert_eq!(normalized.citations.len(), 2);
    // Citation 0: User & Host in slice, SID & IP in quote
    assert!(normalized.citations[0].0.contains(&expected_user_pseudo));
    assert!(normalized.citations[0].0.contains(&expected_host_pseudo));
    assert!(normalized.citations[0].1.contains(&expected_sid_pseudo));
    assert!(normalized.citations[0].1.contains(&expected_ip_pseudo));
    assert!(!normalized.citations[0].0.contains(user_entity));
    assert!(!normalized.citations[0].0.contains(host_entity));
    assert!(!normalized.citations[0].1.contains(sid_entity));
    assert!(!normalized.citations[0].1.contains(ip_entity));

    // Citation 1: IP & MAC in slice, UNC in quote
    assert!(normalized.citations[1].0.contains(&expected_ip_pseudo));
    assert!(normalized.citations[1].0.contains(&expected_mac_pseudo));
    assert!(normalized.citations[1].1.contains(&expected_unc_pseudo));
    assert!(!normalized.citations[1].0.contains(ip_entity));
    assert!(!normalized.citations[1].0.contains(mac_entity));
    assert!(!normalized.citations[1].1.contains(unc_entity));

    // 6. Byte-for-byte reproducibility across independent runs
    let mut normalizer_run2 = ForensicStructuralNormalizer::from_node_seed(&node_seed, session_id);
    let normalized_run2 = normalizer_run2.normalize_candidate(&candidate);
    assert_eq!(normalized.prompt, normalized_run2.prompt);
    assert_eq!(normalized.chosen_response, normalized_run2.chosen_response);
    assert_eq!(normalized.rejected_response, normalized_run2.rejected_response);
    assert_eq!(normalized.rlm_trajectory.len(), normalized_run2.rlm_trajectory.len());
    for i in 0..normalized.rlm_trajectory.len() {
        assert_eq!(
            normalized.rlm_trajectory[i].sanitized_query_or_pattern,
            normalized_run2.rlm_trajectory[i].sanitized_query_or_pattern
        );
        assert_eq!(
            normalized.rlm_trajectory[i].abstracted_takeaway,
            normalized_run2.rlm_trajectory[i].abstracted_takeaway
        );
    }
}

#[test]
fn test_adversarial_case_insensitivity_and_whitespace_consistency() {
    let seed = [0x77u8; 32];
    let mut normalizer = ForensicStructuralNormalizer::from_node_seed(&seed, "case-consistency");

    // Case variations of identical entities MUST produce the exact same pseudonym
    let u1 = normalizer.pseudonymize_username("AliceSmith");
    let u2 = normalizer.pseudonymize_username("alicesmith");
    let u3 = normalizer.pseudonymize_username("ALICESMITH");
    let u4 = normalizer.pseudonymize_username("   AliceSmith   ");
    assert_eq!(u1, u2);
    assert_eq!(u2, u3);
    assert_eq!(u3, u4);

    let h1 = normalizer.pseudonymize_hostname("DOMAIN-CONTROLLER-01");
    let h2 = normalizer.pseudonymize_hostname("domain-controller-01");
    let h3 = normalizer.pseudonymize_hostname("  Domain-Controller-01  ");
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);

    let sid1 = normalizer.pseudonymize_sid("S-1-5-21-12345-67890-11111-1005");
    let sid2 = normalizer.pseudonymize_sid("s-1-5-21-12345-67890-11111-1005");
    let sid3 = normalizer.pseudonymize_sid("  S-1-5-21-12345-67890-11111-1005  ");
    assert_eq!(sid1, sid2);
    assert_eq!(sid2, sid3);

    let ip1 = normalizer.pseudonymize_ip("10.0.50.25");
    let ip2 = normalizer.pseudonymize_ip("  10.0.50.25  ");
    assert_eq!(ip1, ip2);
}

// ============================================================================
// 2. CRYPTOGRAPHIC SESSION ISOLATION & CROSS-SESSION DIFFUSION
// ============================================================================

#[test]
fn test_adversarial_session_isolation_and_cross_session_diffusion() {
    let node_seed = [0x99u8; 32];

    // Two different sessions on the same node
    let mut sess_a = ForensicStructuralNormalizer::from_node_seed(&node_seed, "session-alpha");
    let mut sess_b = ForensicStructuralNormalizer::from_node_seed(&node_seed, "session-beta");

    let entities = vec![
        ("user", "ChiefSecurityOfficer"),
        ("host", "SECRET-SRV-001"),
        ("sid", "S-1-5-21-444444-555555-666666-500"),
        ("ip", "10.250.1.1"),
        ("share", "\\\\SECRET-SRV-001\\Vault"),
        ("mac", "AA:BB:CC:DD:EE:01"),
    ];

    for (cat, entity) in &entities {
        let (pseudo_a, pseudo_b) = match *cat {
            "user" => (sess_a.pseudonymize_username(entity), sess_b.pseudonymize_username(entity)),
            "host" => (sess_a.pseudonymize_hostname(entity), sess_b.pseudonymize_hostname(entity)),
            "sid" => (sess_a.pseudonymize_sid(entity), sess_b.pseudonymize_sid(entity)),
            "ip" => (sess_a.pseudonymize_ip(entity), sess_b.pseudonymize_ip(entity)),
            "share" => (sess_a.pseudonymize_smb_share(entity), sess_b.pseudonymize_smb_share(entity)),
            "mac" => (sess_a.pseudonymize_mac(entity), sess_b.pseudonymize_mac(entity)),
            _ => unreachable!(),
        };

        assert_ne!(
            pseudo_a, pseudo_b,
            "Session isolation violation: entity '{}' produced identical pseudonym across sessions",
            entity
        );
    }

    // Two different nodes with the same session id
    let node_seed_1 = [0x11u8; 32];
    let node_seed_2 = [0x22u8; 32];
    let mut node_a = ForensicStructuralNormalizer::from_node_seed(&node_seed_1, "session-fixed");
    let mut node_b = ForensicStructuralNormalizer::from_node_seed(&node_seed_2, "session-fixed");

    let p1 = node_a.pseudonymize_username("GlobalAdmin");
    let p2 = node_b.pseudonymize_username("GlobalAdmin");
    assert_ne!(p1, p2, "Node seed isolation failure: same session ID leaked across nodes");

    // Fleet session diffusion test: 10 distinct session salts must generate 10 mutually distinct pseudonyms
    let mut generated_pseudos = HashSet::new();
    for i in 0..10 {
        let mut norm = ForensicStructuralNormalizer::from_node_seed(&node_seed, &format!("batch-fleet-{}", i));
        let pseudo = norm.pseudonymize_username("FleetTargetUser");
        assert!(
            generated_pseudos.insert(pseudo.clone()),
            "Collision detected in fleet session pseudonyms: {}",
            pseudo
        );
    }
    assert_eq!(generated_pseudos.len(), 10);
}

// ============================================================================
// 3. CROSS-CATEGORY DOMAIN SEPARATION COLLISION FREEDOM
// ============================================================================

#[test]
fn test_adversarial_cross_category_domain_separation_collision_freedom() {
    let seed = [0xccu8; 32];
    let mut normalizer = ForensicStructuralNormalizer::from_node_seed(&seed, "collision-test");

    // Test with the EXACT same string "corp.local" across username, hostname, share, ip, mac, sid
    let shared_identifier = "corp.local";

    let pseudo_user = normalizer.pseudonymize_username(shared_identifier);
    let pseudo_host = normalizer.pseudonymize_hostname(shared_identifier);
    let pseudo_sid = normalizer.pseudonymize_sid(shared_identifier);
    let pseudo_ip = normalizer.pseudonymize_ip(shared_identifier);
    let pseudo_share = normalizer.pseudonymize_smb_share(shared_identifier);
    let pseudo_mac = normalizer.pseudonymize_mac(shared_identifier);

    // Verify prefixes adhere strictly to taxonomy
    assert!(pseudo_user.starts_with("USER_"), "Bad prefix: {}", pseudo_user);
    assert!(pseudo_host.starts_with("HOST_"), "Bad prefix: {}", pseudo_host);
    assert!(pseudo_sid.starts_with("SID_"), "Bad prefix: {}", pseudo_sid);
    assert!(pseudo_ip.starts_with("IP_"), "Bad prefix: {}", pseudo_ip);
    assert!(pseudo_share.starts_with("SHARE_"), "Bad prefix: {}", pseudo_share);
    assert!(pseudo_mac.starts_with("MAC_"), "Bad prefix: {}", pseudo_mac);

    // Verify that the hex payloads themselves (stripped of prefix) are mutually distinct
    // due to BLAKE3 domain separation tags ("user:", "host:", "sid:", "ip:", "share:", "mac:")
    let hex_user = pseudo_user.strip_prefix("USER_").unwrap();
    let hex_host = pseudo_host.strip_prefix("HOST_").unwrap();
    let hex_sid = pseudo_sid.strip_prefix("SID_").unwrap();
    let hex_ip = pseudo_ip.strip_prefix("IP_").unwrap();
    let hex_share = pseudo_share.strip_prefix("SHARE_").unwrap();
    let hex_mac = pseudo_mac.strip_prefix("MAC_").unwrap();

    let hex_set: HashSet<&str> = [hex_user, hex_host, hex_sid, hex_ip, hex_share, hex_mac]
        .into_iter()
        .collect();

    assert_eq!(
        hex_set.len(),
        6,
        "Domain separation failure: identical hex digest derived across distinct categories!"
    );
}

// ============================================================================
// 4. BOUNDARY EDGE CASES: SYSTEM ACCOUNTS, SIDS, HOSTNAMES, IPS, UNC, MACS
// ============================================================================

#[test]
fn test_adversarial_boundary_edge_cases_system_accounts() {
    let mut normalizer = ForensicStructuralNormalizer::new([0x33u8; 32]);

    // All standard Windows & Unix built-in system accounts must be preserved verbatim
    let system_accounts = vec![
        "SYSTEM",
        "system",
        "System",
        "NT AUTHORITY\\SYSTEM",
        "nt authority\\system",
        "NT Authority\\System",
        "local service",
        "Local Service",
        "LOCAL SERVICE",
        "network service",
        "Network Service",
        "NETWORK SERVICE",
        "root",
        "Root",
        "ROOT",
        "nobody",
        "Nobody",
        "daemon",
        "Daemon",
    ];

    for acc in system_accounts {
        let result = normalizer.pseudonymize_username(acc);
        assert_eq!(
            result, acc,
            "System account '{}' was corrupted or pseudonymized instead of preserved verbatim",
            acc
        );
    }

    // Verify that non-system accounts ARE pseudonymized
    let non_system = vec!["Administrator", "admin", "svc_backup", "guest", "jdoe"];
    for acc in non_system {
        let result = normalizer.pseudonymize_username(acc);
        assert!(
            result.starts_with("USER_"),
            "Non-system account '{}' was NOT pseudonymized: {}",
            acc,
            result
        );
    }

    // Verify text normalization pass preserving system accounts in labeled formats
    let raw_text = "Event 4624: TargetUserName: SYSTEM, SubjectUserName: NT AUTHORITY\\SYSTEM, user: root, uid: nobody";
    let normalized = normalizer.normalize_text(raw_text);
    assert!(normalized.contains("TargetUserName: SYSTEM"));
    assert!(normalized.contains("SubjectUserName: NT AUTHORITY\\SYSTEM"));
    assert!(normalized.contains("user: root"));
    assert!(normalized.contains("uid: nobody"));
}

#[test]
fn test_adversarial_boundary_edge_cases_sids() {
    let mut normalizer = ForensicStructuralNormalizer::new([0x44u8; 32]);

    // Well-known SIDs must be preserved verbatim
    let preserved_sids = vec![
        "S-1-5-18",     // Local System
        "S-1-5-19",     // Local Service
        "S-1-5-20",     // Network Service
        "S-1-5-32-544", // Built-in Administrators
    ];

    for sid in preserved_sids {
        assert_eq!(
            normalizer.pseudonymize_sid(sid),
            sid,
            "Well-known SID '{}' was corrupted",
            sid
        );
    }

    // Non-well-known domain / user SIDs must be pseudonymized
    let user_sids = vec![
        "S-1-5-21-3623811015-3361044348-30300820-1013",
        "S-1-5-21-123456789-987654321-11111111-500",
        "S-1-12-1-2",
    ];

    for sid in user_sids {
        let result = normalizer.pseudonymize_sid(sid);
        assert!(
            result.starts_with("SID_"),
            "User SID '{}' was NOT pseudonymized: {}",
            sid,
            result
        );
        assert_ne!(result, sid);
    }

    // Test text normalization SID replacement
    let raw = "User S-1-5-21-3623811015-3361044348-30300820-1013 elevated under S-1-5-18 and S-1-5-32-544";
    let norm = normalizer.normalize_text(raw);
    assert!(!norm.contains("S-1-5-21-3623811015-3361044348-30300820-1013"));
    assert!(norm.contains("S-1-5-18"));
    assert!(norm.contains("S-1-5-32-544"));
}

#[test]
fn test_adversarial_boundary_edge_cases_hostnames() {
    let mut normalizer = ForensicStructuralNormalizer::new([0x55u8; 32]);

    // Localhost in any casing must be preserved verbatim
    assert_eq!(normalizer.pseudonymize_hostname("localhost"), "localhost");
    assert_eq!(normalizer.pseudonymize_hostname("LocalHost"), "localhost");
    assert_eq!(normalizer.pseudonymize_hostname("LOCALHOST"), "localhost");
    assert_eq!(normalizer.pseudonymize_hostname("  localhost  "), "localhost");

    // Other hostnames must be pseudonymized
    let hostnames = vec!["DESKTOP-ABC1234", "DC01.corp.internal", "linux-prod-node"];
    for h in hostnames {
        let result = normalizer.pseudonymize_hostname(h);
        assert!(result.starts_with("HOST_"), "Host '{}' was not pseudonymized: {}", h, result);
    }
}

#[test]
fn test_adversarial_boundary_edge_cases_ip_classification() {
    // RFC1918 Private ranges
    assert!(is_internal_private_ip("10.0.0.0".parse().unwrap()));
    assert!(is_internal_private_ip("10.0.0.1".parse().unwrap()));
    assert!(is_internal_private_ip("10.255.255.255".parse().unwrap()));
    assert!(is_internal_private_ip("172.16.0.0".parse().unwrap()));
    assert!(is_internal_private_ip("172.16.0.1".parse().unwrap()));
    assert!(is_internal_private_ip("172.31.255.255".parse().unwrap()));
    assert!(is_internal_private_ip("192.168.0.0".parse().unwrap()));
    assert!(is_internal_private_ip("192.168.1.1".parse().unwrap()));
    assert!(is_internal_private_ip("192.168.255.255".parse().unwrap()));

    // RFC1918 Boundaries (must be public)
    assert!(!is_internal_private_ip("172.15.255.255".parse().unwrap()));
    assert!(!is_internal_private_ip("172.32.0.0".parse().unwrap()));
    assert!(!is_internal_private_ip("192.167.255.255".parse().unwrap()));
    assert!(!is_internal_private_ip("192.169.0.0".parse().unwrap()));

    // CGNAT RFC6598 (100.64.0.0/10)
    assert!(is_internal_private_ip("100.64.0.0".parse().unwrap()));
    assert!(is_internal_private_ip("100.64.0.1".parse().unwrap()));
    assert!(is_internal_private_ip("100.127.255.255".parse().unwrap()));
    assert!(!is_internal_private_ip("100.63.255.255".parse().unwrap()));
    assert!(!is_internal_private_ip("100.128.0.0".parse().unwrap()));

    // Loopback & Unspecified
    assert!(is_internal_private_ip("127.0.0.1".parse().unwrap()));
    assert!(is_internal_private_ip("127.255.255.255".parse().unwrap()));
    assert!(is_internal_private_ip("0.0.0.0".parse().unwrap()));
    assert!(is_internal_private_ip("0.1.2.3".parse().unwrap()));

    // Link-Local / Metadata (169.254.0.0/16)
    assert!(is_internal_private_ip("169.254.0.1".parse().unwrap()));
    assert!(is_internal_private_ip("169.254.169.254".parse().unwrap()));
    assert!(!is_internal_private_ip("169.253.255.255".parse().unwrap()));
    assert!(!is_internal_private_ip("169.255.0.0".parse().unwrap()));

    // IPv6
    assert!(is_internal_private_ip("::".parse().unwrap())); // Unspecified
    assert!(is_internal_private_ip("::1".parse().unwrap())); // Loopback
    assert!(is_internal_private_ip("fc00::1".parse().unwrap())); // ULA fc00::/7
    assert!(is_internal_private_ip("fd00::1".parse().unwrap())); // ULA fd00::/7
    assert!(is_internal_private_ip("fd12:3456:789a::1".parse().unwrap())); // ULA
    assert!(is_internal_private_ip("fe80::1".parse().unwrap())); // Link-local fe80::/10
    assert!(is_internal_private_ip("febf::1".parse().unwrap())); // Link-local upper bound
    assert!(!is_internal_private_ip("2001:db8::1".parse().unwrap())); // Documentation / Public
    assert!(!is_internal_private_ip("2607:f8b0:4005:805::200e".parse().unwrap())); // Google IPv6

    // IPv4-mapped IPv6 (::ffff:0:0/96)
    assert!(is_internal_private_ip("::ffff:192.168.1.1".parse().unwrap()));
    assert!(is_internal_private_ip("::ffff:10.0.0.1".parse().unwrap()));
    assert!(!is_internal_private_ip("::ffff:8.8.8.8".parse().unwrap())); // Mapped public is public!
    assert!(!is_internal_private_ip("::ffff:1.1.1.1".parse().unwrap()));

    // Public IPv4 must NOT be classified as internal
    assert!(!is_internal_private_ip("8.8.8.8".parse().unwrap()));
    assert!(!is_internal_private_ip("1.1.1.1".parse().unwrap()));
    assert!(!is_internal_private_ip("142.250.190.46".parse().unwrap()));
    assert!(!is_internal_private_ip("204.79.197.200".parse().unwrap()));

    // Text normalization: Public IPs must remain untouched, private IPs must be pseudonymized
    let mut normalizer = ForensicStructuralNormalizer::new([0x66u8; 32]);
    let raw = "Attacker from public IP 8.8.8.8 connected to private IP 192.168.1.100 and metadata IP 169.254.169.254. External DNS: 1.1.1.1";
    let normalized = normalizer.normalize_text(raw);

    assert!(normalized.contains("8.8.8.8"), "Public IP 8.8.8.8 was corrupted");
    assert!(normalized.contains("1.1.1.1"), "Public IP 1.1.1.1 was corrupted");
    assert!(!normalized.contains("192.168.1.100"), "Private IP was not pseudonymized");
    assert!(!normalized.contains("169.254.169.254"), "Metadata IP was not pseudonymized");
    assert!(normalized.contains("IP_"), "Missing IP pseudonym in output");
}

#[test]
fn test_adversarial_boundary_edge_cases_unc_and_macs() {
    let mut normalizer = ForensicStructuralNormalizer::new([0x77u8; 32]);

    // UNC share path decomposition: host and share pseudonymized, remaining path preserved
    let unc1 = "\\\\CORP-FS01\\ConfidentialDocs\\Audits\\2026\\Q1_Financials.xlsx";
    let pseudo_unc1 = normalizer.pseudonymize_smb_share(unc1);

    assert!(pseudo_unc1.starts_with("\\\\HOST_"));
    assert!(pseudo_unc1.contains("\\SHARE_"));
    assert!(pseudo_unc1.ends_with("\\Audits\\2026\\Q1_Financials.xlsx"));
    assert!(!pseudo_unc1.contains("CORP-FS01"));
    assert!(!pseudo_unc1.contains("ConfidentialDocs"));

    // UNC share with localhost
    let unc_local = "\\\\localhost\\SharedFolder\\data.bin";
    let pseudo_local = normalizer.pseudonymize_smb_share(unc_local);
    assert!(pseudo_local.starts_with("\\\\localhost\\SHARE_"));
    assert!(pseudo_local.ends_with("\\data.bin"));

    // MAC addresses: colon and dash formats
    let mac_colon = "00:0C:29:4F:8E:35";
    let mac_dash = "00-50-56-C0-00-08";
    let pseudo_colon = normalizer.pseudonymize_mac(mac_colon);
    let pseudo_dash = normalizer.pseudonymize_mac(mac_dash);

    assert!(pseudo_colon.starts_with("MAC_"));
    assert!(pseudo_dash.starts_with("MAC_"));
    assert_ne!(pseudo_colon, pseudo_dash);

    // Text normalization pass with UNC and MAC
    let raw = "Accessing \\\\FILESERVER01\\Finance\\Ledger.dat from adapter 00:0C:29:4F:8E:35 and secondary 00-50-56-C0-00-08";
    let normalized = normalizer.normalize_text(raw);
    assert!(!normalized.contains("FILESERVER01"));
    assert!(!normalized.contains("00:0C:29:4F:8E:35"));
    assert!(!normalized.contains("00-50-56-C0-00-08"));
    assert!(normalized.contains("\\Ledger.dat"));
    assert!(normalized.contains("MAC_"));
}

// ============================================================================
// 5. ARTIFACT CATEGORY GATE ZERO-LEAKAGE ENFORCEMENT
// ============================================================================

#[test]
fn test_adversarial_artifact_category_gate_rejection_matrix() {
    let gate = ArtifactCategoryGate::default();

    // 1. All prohibited category tags must be rejected 100%
    let prohibited_tags = vec![
        "browser_cookies",
        "browser_history_oauth",
        "credential_store",
        "shell_history_raw",
        "BROWSER_COOKIES",
        "Browser_Cookies",
        "Credential_Store",
        "win_credential_store_dump",
        "harvest_browser_history_oauth",
        "shell_history_raw_bash",
    ];

    for tag in prohibited_tags {
        let candidate = create_test_candidate(
            "cand-prohibited-tag",
            vec![tag.to_string()],
            Some("C:\\Windows\\System32\\cmd.exe".to_string()),
            "Prompt test",
            "Chosen test",
            None,
            vec![],
            vec![],
        );
        let eval = gate.evaluate_candidate(&candidate);
        assert!(
            eval.is_err(),
            "Category Gate FAILED to reject prohibited tag '{}'!",
            tag
        );
    }

    // 2. Prohibited ForensicTelemetryType variants must be rejected 100%
    let prohibited_enums = vec![
        ForensicTelemetryType::BrowserCookies,
        ForensicTelemetryType::BrowserHistoryOAuth,
        ForensicTelemetryType::CredentialStore,
        ForensicTelemetryType::ShellHistoryRaw,
    ];

    for enum_type in prohibited_enums {
        assert!(
            !enum_type.is_marketplace_harvest_allowed(),
            "Enum {:?} must not be harvest allowed",
            enum_type
        );
        let candidate = create_test_candidate(
            "cand-prohibited-enum",
            vec![enum_type.as_str().to_string()],
            None,
            "Prompt test",
            "Chosen test",
            None,
            vec![],
            vec![],
        );
        let eval = gate.evaluate_candidate(&candidate);
        assert!(
            eval.is_err(),
            "Category Gate FAILED to reject prohibited enum type '{:?}'!",
            enum_type
        );
    }

    // 3. Sensitive / prohibited OS credential file paths must be rejected 100%
    let prohibited_paths = vec![
        // Windows SAM & SECURITY
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\WINDOWS\\system32\\config\\sam",
        "\\\\?\\C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SECURITY",
        "C:\\WINDOWS\\system32\\config\\security",
        // Linux shadow
        "/etc/shadow",
        "/etc/shadow-",
        "/var/backup/shadow",
        "shadow",
        // DPAPI & Keychain
        "C:\\Users\\admin\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-12345\\dpapi",
        "/Users/alice/Library/Keychains/login.keychain-db",
        // Shell history
        "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        "/home/alice/.bash_history",
        "/root/.bash_history",
        // Cookies & OAuth tokens
        "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
        "/home/alice/.config/slack/oauth_tokens.json",
        // Credential stores
        "C:\\vault\\credentials.kdbx",
        "/opt/secret/credential_store.sqlite",
    ];

    for path in prohibited_paths {
        let candidate = create_test_candidate(
            "cand-prohibited-path",
            vec!["process_execution".to_string()], // Allowed tag, but sensitive path!
            Some(path.to_string()),
            "Prompt test",
            "Chosen test",
            None,
            vec![],
            vec![],
        );
        let eval = gate.evaluate_candidate(&candidate);
        assert!(
            eval.is_err(),
            "Category Gate FAILED to reject sensitive path '{}'!",
            path
        );
    }

    // 4. Allowed defensive execution categories with clean paths must evaluate to Ok(())
    let allowed_enums = vec![
        ForensicTelemetryType::ProcessExecution,
        ForensicTelemetryType::NetworkConnection,
        ForensicTelemetryType::RegistryPersistence,
        ForensicTelemetryType::SystemEventLog,
        ForensicTelemetryType::PrefetchAmcacheExecution,
        ForensicTelemetryType::ServiceDaemon,
    ];

    let clean_paths = vec![
        "C:\\Windows\\System32\\svchost.exe",
        "/proc/net/tcp",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
        "C:\\Windows\\Prefetch\\CMD.EXE-1234ABCD.pf",
        "/etc/systemd/system/dockerd.service",
    ];

    for (enum_type, path) in allowed_enums.into_iter().zip(clean_paths.into_iter()) {
        assert!(
            enum_type.is_marketplace_harvest_allowed(),
            "Allowed type {:?} failed eligibility",
            enum_type
        );
        let candidate = create_test_candidate(
            "cand-allowed",
            vec![enum_type.as_str().to_string()],
            Some(path.to_string()),
            "Defensive investigation prompt",
            "Defensive investigation chosen response",
            None,
            vec![],
            vec![],
        );
        let eval = gate.evaluate_candidate(&candidate);
        assert!(
            eval.is_ok(),
            "Category Gate wrongly rejected legitimate defensive artifact ({:?}, '{}'): {:?}",
            enum_type,
            path,
            eval.err()
        );
    }
}

// ============================================================================
// 6. LIVE PREVIEW STATISTICS AND MAPPING FIDELITY
// ============================================================================

#[test]
fn test_adversarial_preview_normalization_statistics_and_mappings() {
    let mut normalizer = ForensicStructuralNormalizer::new([0x88u8; 32]);

    let sample_text = "\
Event 4688: Process creation detected.
User: MaliciousActor was active on ComputerName: WORKSTATION-99
User: SecondOperator logged in to Computer: SERVER-DB-01
Security SID S-1-5-21-123456789-987654321-11111111-500 established connection to 10.10.10.50 and 192.168.1.200
SMB access on \\\\FILESRV01\\Accounting$\\Q4.xlsx from MAC 00:0C:29:11:22:33 and adapter 00-50-56-AA-BB-CC
Public external proxy was 8.8.8.8";

    let preview = normalizer.preview_normalization(sample_text);

    // Verify statistics
    assert_eq!(preview.usernames_replaced, 2, "Expected 2 users replaced");
    assert_eq!(preview.hostnames_replaced, 3, "Expected 3 hostnames replaced (99, DB-01, FILESRV01)");
    assert_eq!(preview.sids_replaced, 1, "Expected 1 SID replaced");
    assert_eq!(preview.ips_replaced, 2, "Expected 2 private IPs replaced (10.10.10.50, 192.168.1.200)");
    assert_eq!(preview.smb_shares_replaced, 1, "Expected 1 SMB share replaced");
    assert_eq!(preview.macs_replaced, 2, "Expected 2 MAC addresses replaced");
    assert_eq!(preview.total_replacements, 11);

    // Verify mappings contains properly prefixed categories
    assert!(preview.pseudonym_mappings.contains_key("user:maliciousactor"));
    assert!(preview.pseudonym_mappings.contains_key("user:secondoperator"));
    assert!(preview.pseudonym_mappings.contains_key("host:workstation-99"));
    assert!(preview.pseudonym_mappings.contains_key("host:server-db-01"));
    assert!(preview.pseudonym_mappings.contains_key("host:filesrv01"));
    assert!(preview.pseudonym_mappings.contains_key("sid:s-1-5-21-123456789-987654321-11111111-500"));
    assert!(preview.pseudonym_mappings.contains_key("ip:10.10.10.50"));
    assert!(preview.pseudonym_mappings.contains_key("ip:192.168.1.200"));
    assert!(preview.pseudonym_mappings.contains_key("share:\\\\filesrv01\\accounting$\\q4.xlsx"));
    assert!(preview.pseudonym_mappings.contains_key("mac:00:0c:29:11:22:33"));
    assert!(preview.pseudonym_mappings.contains_key("mac:00-50-56-aa-bb-cc"));

    // Verify that public IP was NOT mapped and NOT replaced
    assert!(preview.normalized_text.contains("8.8.8.8"));
    assert!(!preview.pseudonym_mappings.contains_key("ip:8.8.8.8"));

    // Verify no raw sensitive identifiers in normalized text
    assert!(!preview.normalized_text.contains("MaliciousActor"));
    assert!(!preview.normalized_text.contains("WORKSTATION-99"));
    assert!(!preview.normalized_text.contains("10.10.10.50"));
    assert!(!preview.normalized_text.contains("192.168.1.200"));
    assert!(!preview.normalized_text.contains("00:0C:29:11:22:33"));
    assert!(!preview.normalized_text.contains("00-50-56-AA-BB-CC"));
}

// ============================================================================
// 7. EMPIRICAL BUG REPRODUCTION: DISCOVERED VULNERABILITIES & REGRESSIONS
// ============================================================================

/// BUG REPORT 1:
/// `ArtifactCategoryGate` checks `p_lower.contains("security")` which false-positively
/// rejects legitimate Windows Security Event Logs (`C:\Windows\System32\winevt\Logs\Security.evtx`).
/// The check intended to bar the Windows `SECURITY` registry hive file (`config\SECURITY`),
/// but naively matches the string `"security"`, blocking all Windows Security Event Logs.
#[test]
fn test_challenge_bug_security_evtx_path_false_positive_rejection() {
    let gate = ArtifactCategoryGate::default();
    let candidate = create_test_candidate(
        "cand-sec-evtx",
        vec!["system_event_log".to_string()],
        Some("C:\\Windows\\System32\\winevt\\Logs\\Security.evtx".to_string()),
        "Security Event 4688 execution audit",
        "Process created by SYSTEM",
        None,
        vec![],
        vec![],
    );
    let eval = gate.evaluate_candidate(&candidate);
    assert!(
        eval.is_ok(),
        "CRITICAL BUG CONFIRMED: ArtifactCategoryGate rejected legitimate Windows Security event log! Error: {:?}",
        eval.err()
    );
}

/// BUG REPORT 2:
/// `LABELED_HOST_RE` uses `[A-Za-z0-9_.-]+` which greedily swallows sentence-ending punctuation (`.`).
/// This stores `"workstation-99."` in the hostname map and causes the token replacement
/// regex `\bWORKSTATION-99\.\b` to fail to match due to word-boundary rules, leaking raw hostnames.
#[test]
fn test_challenge_bug_hostname_trailing_punctuation_leak() {
    let mut normalizer = ForensicStructuralNormalizer::new([0x88u8; 32]);
    let raw = "Activity was detected on ComputerName: WORKSTATION-99.";
    let normalized = normalizer.normalize_text(raw);
    assert!(
        !normalized.contains("WORKSTATION-99"),
        "HIGH BUG CONFIRMED: Hostname followed by sentence-ending punctuation was not redacted! Output: '{}'",
        normalized
    );
}

/// BUG REPORT 3:
/// `normalize_text` only replaces hostnames and usernames that have explicit prefix tags
/// (e.g. `ComputerName: ...` or `User: ...`) inside the *current* string slice.
/// It never replays previously discovered mappings in `self.hostname_map` or `self.username_map`.
/// Consequently, when an entity discovered in the prompt appears in subsequent reasoning steps,
/// responses, or citations WITHOUT a prefix tag (e.g. "spawned process on WORKSTATION-88"),
/// it completely leaks in plain text!
#[test]
fn test_challenge_bug_unlabeled_entity_cross_trajectory_leak() {
    let mut normalizer = ForensicStructuralNormalizer::new([0x88u8; 32]);
    let candidate = create_test_candidate(
        "cand-cross-leak",
        vec!["process_execution".to_string()],
        Some("C:\\Windows\\System32\\winevt\\Logs\\System.evtx".to_string()),
        "Alert: ComputerName: CORP-FIN-01 was accessed by User: AliceCorporate",
        "The attack on CORP-FIN-01 was executed by AliceCorporate using PowerShell.",
        None,
        vec![
            (
                "Query persistence on CORP-FIN-01",
                "AliceCorporate established a scheduled task on CORP-FIN-01",
            ),
        ],
        vec![
            (
                "EvtLog 4688: Process creation on CORP-FIN-01",
                "AliceCorporate executed mimikatz",
            ),
        ],
    );

    let normalized = normalizer.normalize_candidate(&candidate);

    // In chosen response, reasoning steps, and citations, CORP-FIN-01 and AliceCorporate
    // do not have "ComputerName:" or "User:" prefixes. They MUST be pseudonymized
    // because they were already identified and mapped in the prompt!
    assert!(
        !normalized.chosen_response.contains("CORP-FIN-01"),
        "CRITICAL PRIVACY LEAK: Unlabeled hostname leaked in chosen_response! Got: '{}'",
        normalized.chosen_response
    );
    assert!(
        !normalized.chosen_response.contains("AliceCorporate"),
        "CRITICAL PRIVACY LEAK: Unlabeled username leaked in chosen_response! Got: '{}'",
        normalized.chosen_response
    );
    assert!(
        !normalized.rlm_trajectory[0].sanitized_query_or_pattern.contains("CORP-FIN-01"),
        "CRITICAL PRIVACY LEAK: Unlabeled hostname leaked in rlm_trajectory! Got: '{}'",
        normalized.rlm_trajectory[0].sanitized_query_or_pattern
    );
    assert!(
        !normalized.citations[0].0.contains("CORP-FIN-01"),
        "CRITICAL PRIVACY LEAK: Unlabeled hostname leaked in citations! Got: '{}'",
        normalized.citations[0].0
    );
}
