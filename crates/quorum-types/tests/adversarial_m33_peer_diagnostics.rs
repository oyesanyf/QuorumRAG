//! Adversarial and Fuzzing Tests for Milestone M33: Structured Peer Diagnostics Model.
//!
//! Validates serde roundtrip fidelity, extreme scaling (10,000+ peers),
//! unicode/control-character resiliency, and summary reason priority oracles.

use quorum_types::{
    FederatedPeerDiagnostics, PeerQueryOutcome, PeerQueryStatus, QueryResult,
};

#[test]
fn test_peer_query_status_label_and_serde_fidelity() {
    let statuses = [
        (PeerQueryStatus::Connected, "connected"),
        (PeerQueryStatus::ZeroMatchingChunks, "zero_matching_chunks"),
        (PeerQueryStatus::TimedOut, "timed_out"),
        (PeerQueryStatus::BlockedByPolicy, "blocked_by_policy"),
        (PeerQueryStatus::NetworkError, "network_error"),
    ];

    for (status, expected_label) in statuses {
        assert_eq!(status.label(), expected_label);

        // JSON serialization roundtrip
        let serialized = serde_json::to_string(&status).expect("must serialize");
        let deserialized: PeerQueryStatus =
            serde_json::from_str(&serialized).expect("must deserialize");
        assert_eq!(status, deserialized);
    }
}

#[test]
fn test_peer_query_status_invalid_deserialization_fails_safely() {
    let invalid_json = "\"non_existent_status\"";
    let res: Result<PeerQueryStatus, _> = serde_json::from_str(invalid_json);
    assert!(res.is_err(), "Invalid status enum variant must fail closed");

    let number_json = "999";
    let res2: Result<PeerQueryStatus, _> = serde_json::from_str(number_json);
    assert!(res2.is_err(), "Numeric status must fail closed");
}

#[test]
fn test_peer_query_outcome_unicode_and_adversarial_error_messages() {
    let adversarial_strings = [
        "", // empty
        "\0\0\0", // null bytes
        "CRLF\r\ninjection\r\nline: 42",
        "<script>alert('xss')</script>",
        "'; DROP TABLE peers; --",
        "🦀🔥💻🎯🚀", // 4-byte UTF-8 emojis
        "اللغة العربية", // RTL Arabic
        "日本語の文字化けテスト", // CJK
        "\u{202E}dlrow olleh", // Bidi override
        "\x1b[31;1mANSI escape code\x1b[0m", // terminal escapes
        "\"quotes\" and \\backslashes\\ and `backticks`",
    ];

    for s in adversarial_strings {
        let outcome = PeerQueryOutcome {
            peer_id: format!("peer_{}", s),
            status: PeerQueryStatus::NetworkError,
            matching_chunk_count: 0,
            cited_chunk_count: 0,
            latency_ms: 1234,
            error_message: Some(s.to_string()),
        };

        let serialized = serde_json::to_string(&outcome).expect("Serialization must succeed");
        let deserialized: PeerQueryOutcome =
            serde_json::from_str(&serialized).expect("Deserialization must succeed");

        assert_eq!(outcome, deserialized);
    }
}

#[test]
fn test_peer_diagnostics_extreme_scaling_10k_peers() {
    let num_peers = 10_000;
    let mut peer_ids = Vec::with_capacity(num_peers);
    let mut outcomes = Vec::with_capacity(num_peers);

    for i in 0..num_peers {
        let pid = format!("12D3KooW_{:08x}", i);
        peer_ids.push(pid.clone());
        outcomes.push(PeerQueryOutcome {
            peer_id: pid,
            status: if i % 100 == 0 {
                PeerQueryStatus::TimedOut
            } else if i % 50 == 0 {
                PeerQueryStatus::ZeroMatchingChunks
            } else {
                PeerQueryStatus::Connected
            },
            matching_chunk_count: if i % 50 == 0 { 0 } else { 3 },
            cited_chunk_count: 0,
            latency_ms: (i as u64) % 500,
            error_message: None,
        });
    }

    let mut diag = FederatedPeerDiagnostics {
        connected_peers_count: num_peers,
        connected_peer_ids: peer_ids,
        queried_peers_count: num_peers,
        peer_outcomes: outcomes,
        summary_reason: None,
    };

    // Stress test compute_summary_reason with 10k items
    let start = std::time::Instant::now();
    diag.compute_summary_reason(3032, 3500);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 50,
        "compute_summary_reason on 10,000 peers must execute in < 50ms, took {:?}",
        elapsed
    );
    assert!(
        diag.summary_reason.is_some(),
        "Must compute summary reason for 10k peers"
    );

    // Verify serde roundtrip of 10,000 peer outcomes
    let serialized = serde_json::to_string(&diag).expect("Must serialize 10k peers");
    assert!(serialized.len() > 100_000, "Payload must be realistic");

    let deserialized: FederatedPeerDiagnostics =
        serde_json::from_str(&serialized).expect("Must deserialize 10k peers");
    assert_eq!(deserialized.peer_outcomes.len(), num_peers);
    assert_eq!(deserialized.connected_peers_count, num_peers);
}

#[test]
fn test_peer_diagnostics_summary_reason_priority_hierarchy_oracle() {
    // Priority order invariant:
    // 1. BlockedByPolicy
    // 2. TimedOut
    // 3. ZeroMatchingChunks
    // 4. NetworkError
    // 5. Fallback

    // Case A: Blocked + TimedOut + ZeroMatching + NetworkError -> Blocked wins
    let mut diag = FederatedPeerDiagnostics {
        connected_peers_count: 4,
        connected_peer_ids: vec![
            "peer_zero".into(),
            "peer_timeout".into(),
            "peer_blocked".into(),
            "peer_neterr".into(),
        ],
        queried_peers_count: 4,
        peer_outcomes: vec![
            PeerQueryOutcome {
                peer_id: "peer_zero".into(),
                status: PeerQueryStatus::ZeroMatchingChunks,
                matching_chunk_count: 0,
                cited_chunk_count: 0,
                latency_ms: 10,
                error_message: None,
            },
            PeerQueryOutcome {
                peer_id: "peer_timeout".into(),
                status: PeerQueryStatus::TimedOut,
                matching_chunk_count: 0,
                cited_chunk_count: 0,
                latency_ms: 3500,
                error_message: None,
            },
            PeerQueryOutcome {
                peer_id: "peer_blocked".into(),
                status: PeerQueryStatus::BlockedByPolicy,
                matching_chunk_count: 0,
                cited_chunk_count: 0,
                latency_ms: 5,
                error_message: Some("Policy denied".into()),
            },
            PeerQueryOutcome {
                peer_id: "peer_neterr".into(),
                status: PeerQueryStatus::NetworkError,
                matching_chunk_count: 0,
                cited_chunk_count: 0,
                latency_ms: 100,
                error_message: Some("Connection reset".into()),
            },
        ],
        summary_reason: None,
    };
    diag.compute_summary_reason(3032, 3500);
    assert_eq!(
        diag.summary_reason,
        Some("Peer peer_blocked blocked by shared-folder / DLP policy".into())
    );

    // Case B: Remove Blocked -> TimedOut wins
    diag.peer_outcomes.retain(|o| o.status != PeerQueryStatus::BlockedByPolicy);
    diag.compute_summary_reason(3032, 3500);
    assert_eq!(
        diag.summary_reason,
        Some("Peer peer_timeout timed out after 3500ms".into())
    );

    // Case C: Remove TimedOut -> ZeroMatchingChunks wins
    diag.peer_outcomes.retain(|o| o.status != PeerQueryStatus::TimedOut);
    diag.compute_summary_reason(3032, 3500);
    assert_eq!(
        diag.summary_reason,
        Some("Peer peer_zero returned 0 matching chunks for this query".into())
    );

    // Case D: Remove ZeroMatching -> NetworkError wins
    diag.peer_outcomes.retain(|o| o.status != PeerQueryStatus::ZeroMatchingChunks);
    diag.compute_summary_reason(3032, 3500);
    assert_eq!(
        diag.summary_reason,
        Some("Peer peer_neterr network error: Connection reset".into())
    );

    // Case E: Remove NetworkError, only Connected remains (with chunks returned, but 0 cited)
    diag.peer_outcomes = vec![PeerQueryOutcome {
        peer_id: "peer_connected".into(),
        status: PeerQueryStatus::Connected,
        matching_chunk_count: 5,
        cited_chunk_count: 0,
        latency_ms: 20,
        error_message: None,
    }];
    diag.compute_summary_reason(3032, 3500);
    assert_eq!(
        diag.summary_reason,
        Some("Peer peer_connected returned 5 chunks (0 cited)".into())
    );

    // Case F: Connected peer with 0 matching chunks reaches fallback
    diag.peer_outcomes = vec![PeerQueryOutcome {
        peer_id: "peer_connected".into(),
        status: PeerQueryStatus::Connected,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 20,
        error_message: None,
    }];
    diag.compute_summary_reason(3032, 3500);
    assert_eq!(
        diag.summary_reason,
        Some("No data returned from remote peers".into())
    );
}

#[test]
fn test_query_result_backward_compatibility_when_peer_diagnostics_omitted() {
    // Simulates an older payload without peer_diagnostics field
    let legacy_json = r#"{
        "chunks": [],
        "synthesis_prompt": "Synthesize this answer",
        "execution_time_ms": 42,
        "sources_cited": [],
        "cache_hit": false,
        "cache_epoch": 1
    }"#;

    let res: QueryResult = serde_json::from_str(legacy_json)
        .expect("Must deserialize legacy QueryResult without peer_diagnostics");
    assert!(
        res.peer_diagnostics.is_none(),
        "Omitted peer_diagnostics must default to None"
    );
}

#[test]
fn test_logical_anomaly_connected_peers_with_zero_queried() {
    // When connected_peers_count = 5, but queried_peers_count = 0 (e.g. query sanitization aborted scatter-gather),
    // compute_summary_reason disambiguates and reports "P2P mesh query skipped (0 remote peers queried)".
    let mut diag = FederatedPeerDiagnostics {
        connected_peers_count: 5,
        connected_peer_ids: vec!["peer_1".into(), "peer_2".into()],
        queried_peers_count: 0,
        peer_outcomes: Vec::new(),
        summary_reason: None,
    };
    diag.compute_summary_reason(3032, 3500);

    assert_eq!(
        diag.summary_reason,
        Some("P2P mesh query skipped (0 remote peers queried)".into()),
        "Disambiguated: 0 queried reports query skipped rather than 0 peers connected"
    );
}
