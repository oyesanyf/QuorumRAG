//! Adversarial Challenge Test Suite for Milestone 37 Requirement R1 (P2P Mesh Diagnostics and Telemetry)
//!
//! Validates:
//! 1. `FederatedPeerDiagnostics::compute_summary_reason` across boundary conditions:
//!    - 0 peers connected
//!    - 1 peer with chunks (cited vs un-cited)
//!    - 1 peer with 0 chunks
//!    - 5 peers with mixed outcomes (Blocked, TimedOut, ZeroChunks, NetworkError, Connected)
//!    - Timeout conditions and latency reporting
//! 2. `contributing_peer_ids` serialization, deserialization, and deduplication invariants.

use quorum_types::{FederatedPeerDiagnostics, PeerQueryOutcome, PeerQueryStatus};

#[test]
fn test_adversarial_zero_peers_connected() {
    let mut diag = FederatedPeerDiagnostics {
        connected_peers_count: 0,
        connected_peer_ids: Vec::new(),
        queried_peers_count: 0,
        peer_outcomes: Vec::new(),
        summary_reason: None,
        contributing_peer_ids: Vec::new(),
    };
    diag.compute_summary_reason(3032, 5000);

    assert_eq!(
        diag.summary_reason.as_deref(),
        Some("0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)"),
        "Zero connected peers must report 0 peers connected on P2P port 3032"
    );
}

#[test]
fn test_adversarial_one_peer_with_chunks() {
    // Case 1: 1 peer connected, returned 5 chunks, but 0 cited
    let mut diag_uncited = FederatedPeerDiagnostics {
        connected_peers_count: 1,
        connected_peer_ids: vec!["peer_1".into()],
        queried_peers_count: 1,
        peer_outcomes: vec![PeerQueryOutcome {
            peer_id: "peer_1".into(),
            status: PeerQueryStatus::Connected,
            matching_chunk_count: 5,
            cited_chunk_count: 0,
            latency_ms: 45,
            error_message: None,
        }],
        summary_reason: None,
        contributing_peer_ids: Vec::new(),
    };
    diag_uncited.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag_uncited.summary_reason.as_deref(),
        Some("Peer peer_1 returned 5 chunks (0 cited)"),
        "Uncited chunks must report returned chunk count with 0 cited"
    );

    // Case 2: 1 peer connected, returned 5 chunks, 2 cited
    let mut diag_cited = FederatedPeerDiagnostics {
        connected_peers_count: 1,
        connected_peer_ids: vec!["peer_1".into()],
        queried_peers_count: 1,
        peer_outcomes: vec![PeerQueryOutcome {
            peer_id: "peer_1".into(),
            status: PeerQueryStatus::Connected,
            matching_chunk_count: 5,
            cited_chunk_count: 2,
            latency_ms: 45,
            error_message: None,
        }],
        summary_reason: None,
        contributing_peer_ids: vec!["peer_1".into()],
    };
    diag_cited.compute_summary_reason(3032, 5000);
    // When chunks are cited and none are uncited or erroring, summary_reason falls through to default
    assert_eq!(
        diag_cited.summary_reason.as_deref(),
        Some("No data returned from remote peers")
    );
    assert_eq!(diag_cited.contributing_peer_ids, vec!["peer_1"]);
}

#[test]
fn test_adversarial_one_peer_with_zero_chunks() {
    let mut diag = FederatedPeerDiagnostics {
        connected_peers_count: 1,
        connected_peer_ids: vec!["peer_empty".into()],
        queried_peers_count: 1,
        peer_outcomes: vec![PeerQueryOutcome {
            peer_id: "peer_empty".into(),
            status: PeerQueryStatus::ZeroMatchingChunks,
            matching_chunk_count: 0,
            cited_chunk_count: 0,
            latency_ms: 30,
            error_message: None,
        }],
        summary_reason: None,
        contributing_peer_ids: Vec::new(),
    };
    diag.compute_summary_reason(3032, 5000);

    assert_eq!(
        diag.summary_reason.as_deref(),
        Some("Peer peer_empty returned 0 matching chunks for this query"),
        "Single peer with 0 chunks must report 0 matching chunks for this query"
    );
    assert!(diag.contributing_peer_ids.is_empty());
}

#[test]
fn test_adversarial_five_peers_mixed_outcomes_priority_order() {
    // 5 peers:
    // P1: Connected with 3 matching, 0 cited
    // P2: TimedOut (latency 5000ms)
    // P3: BlockedByPolicy
    // P4: NetworkError
    // P5: ZeroMatchingChunks
    let mut diag = FederatedPeerDiagnostics {
        connected_peers_count: 5,
        connected_peer_ids: vec![
            "peer_1".into(),
            "peer_2".into(),
            "peer_3".into(),
            "peer_4".into(),
            "peer_5".into(),
        ],
        queried_peers_count: 5,
        peer_outcomes: vec![
            PeerQueryOutcome {
                peer_id: "peer_1".into(),
                status: PeerQueryStatus::Connected,
                matching_chunk_count: 3,
                cited_chunk_count: 0,
                latency_ms: 120,
                error_message: None,
            },
            PeerQueryOutcome {
                peer_id: "peer_2".into(),
                status: PeerQueryStatus::TimedOut,
                matching_chunk_count: 0,
                cited_chunk_count: 0,
                latency_ms: 5000,
                error_message: Some("Deadline exceeded".into()),
            },
            PeerQueryOutcome {
                peer_id: "peer_3".into(),
                status: PeerQueryStatus::BlockedByPolicy,
                matching_chunk_count: 0,
                cited_chunk_count: 0,
                latency_ms: 10,
                error_message: Some("DLP block".into()),
            },
            PeerQueryOutcome {
                peer_id: "peer_4".into(),
                status: PeerQueryStatus::NetworkError,
                matching_chunk_count: 0,
                cited_chunk_count: 0,
                latency_ms: 250,
                error_message: Some("Connection reset by peer".into()),
            },
            PeerQueryOutcome {
                peer_id: "peer_5".into(),
                status: PeerQueryStatus::ZeroMatchingChunks,
                matching_chunk_count: 0,
                cited_chunk_count: 0,
                latency_ms: 45,
                error_message: None,
            },
        ],
        summary_reason: None,
        contributing_peer_ids: Vec::new(),
    };

    diag.compute_summary_reason(3032, 5000);

    // Priority 1 is BlockedByPolicy (peer_3)
    assert_eq!(
        diag.summary_reason.as_deref(),
        Some("Peer peer_3 blocked by shared-folder / DLP policy"),
        "BlockedByPolicy must take precedence over TimedOut, ZeroMatchingChunks, NetworkError, and Uncited"
    );

    // Now remove BlockedByPolicy -> TimedOut (peer_2) must take precedence
    diag.peer_outcomes.retain(|o| o.status != PeerQueryStatus::BlockedByPolicy);
    diag.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag.summary_reason.as_deref(),
        Some("Peer peer_2 timed out after 5000ms"),
        "TimedOut must take precedence after BlockedByPolicy is resolved"
    );

    // Now remove TimedOut -> ZeroMatchingChunks (peer_5) must take precedence
    diag.peer_outcomes.retain(|o| o.status != PeerQueryStatus::TimedOut);
    diag.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag.summary_reason.as_deref(),
        Some("Peer peer_5 returned 0 matching chunks for this query"),
        "ZeroMatchingChunks must take precedence after TimedOut is resolved"
    );

    // Now remove ZeroMatchingChunks -> NetworkError (peer_4) must take precedence
    diag.peer_outcomes.retain(|o| o.status != PeerQueryStatus::ZeroMatchingChunks);
    diag.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag.summary_reason.as_deref(),
        Some("Peer peer_4 network error: Connection reset by peer"),
        "NetworkError must take precedence after ZeroMatchingChunks is resolved"
    );

    // Now remove NetworkError -> Connected with uncited chunks (peer_1)
    diag.peer_outcomes.retain(|o| o.status != PeerQueryStatus::NetworkError);
    diag.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag.summary_reason.as_deref(),
        Some("Peer peer_1 returned 3 chunks (0 cited)"),
        "Connected with uncited chunks must be reported when all errors are resolved"
    );
}

#[test]
fn test_adversarial_timeout_conditions_latency_fallback() {
    // Case 1: latency_ms is 0, should fall back to default_timeout_ms (5000)
    let mut diag_zero_latency = FederatedPeerDiagnostics {
        connected_peers_count: 1,
        connected_peer_ids: vec!["peer_t0".into()],
        queried_peers_count: 1,
        peer_outcomes: vec![PeerQueryOutcome {
            peer_id: "peer_t0".into(),
            status: PeerQueryStatus::TimedOut,
            matching_chunk_count: 0,
            cited_chunk_count: 0,
            latency_ms: 0,
            error_message: None,
        }],
        summary_reason: None,
        contributing_peer_ids: Vec::new(),
    };
    diag_zero_latency.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag_zero_latency.summary_reason.as_deref(),
        Some("Peer peer_t0 timed out after 5000ms")
    );

    // Case 2: latency_ms is non-zero (e.g. 4200ms)
    let mut diag_explicit_latency = FederatedPeerDiagnostics {
        connected_peers_count: 1,
        connected_peer_ids: vec!["peer_t1".into()],
        queried_peers_count: 1,
        peer_outcomes: vec![PeerQueryOutcome {
            peer_id: "peer_t1".into(),
            status: PeerQueryStatus::TimedOut,
            matching_chunk_count: 0,
            cited_chunk_count: 0,
            latency_ms: 4200,
            error_message: None,
        }],
        summary_reason: None,
        contributing_peer_ids: Vec::new(),
    };
    diag_explicit_latency.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag_explicit_latency.summary_reason.as_deref(),
        Some("Peer peer_t1 timed out after 4200ms")
    );
}

#[test]
fn test_adversarial_contributing_peer_ids_serde_backward_compat() {
    // When contributing_peer_ids is empty, it should be omitted during serialization
    let diag_empty = FederatedPeerDiagnostics {
        connected_peers_count: 1,
        connected_peer_ids: vec!["peer_1".into()],
        queried_peers_count: 1,
        peer_outcomes: Vec::new(),
        summary_reason: None,
        contributing_peer_ids: Vec::new(),
    };
    let json_empty = serde_json::to_string(&diag_empty).expect("Serialization failed");
    assert!(!json_empty.contains("contributing_peer_ids"), "Empty contributing_peer_ids should be omitted via skip_serializing_if");

    // Deserializing JSON without contributing_peer_ids field must default to empty Vec
    let deserialized: FederatedPeerDiagnostics =
        serde_json::from_str(&json_empty).expect("Deserialization failed");
    assert!(deserialized.contributing_peer_ids.is_empty());

    // When populated, should serialize and deserialize accurately
    let diag_populated = FederatedPeerDiagnostics {
        connected_peers_count: 2,
        connected_peer_ids: vec!["peer_1".into(), "peer_2".into()],
        queried_peers_count: 2,
        peer_outcomes: Vec::new(),
        summary_reason: None,
        contributing_peer_ids: vec!["12D3KooWPeer1".into(), "12D3KooWPeer2".into()],
    };
    let json_populated = serde_json::to_string(&diag_populated).expect("Serialization failed");
    assert!(json_populated.contains("\"contributing_peer_ids\":[\"12D3KooWPeer1\",\"12D3KooWPeer2\"]"));

    let deserialized_populated: FederatedPeerDiagnostics =
        serde_json::from_str(&json_populated).expect("Deserialization failed");
    assert_eq!(
        deserialized_populated.contributing_peer_ids,
        vec!["12D3KooWPeer1", "12D3KooWPeer2"]
    );
}
