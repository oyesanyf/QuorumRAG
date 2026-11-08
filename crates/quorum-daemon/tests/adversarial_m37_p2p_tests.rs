//! Adversarial Challenger Test Harness for Milestone 37:
//! P2P Multiaddr Port 4001 Filtering, Known Peers Deserialization, and Telemetry Guard Invariants.

use quorum_daemon::p2p_watcher::{
    is_dialable_lan_or_wan_multiaddr, load_known_peers_from_dir, strip_p2p_suffix,
};
use quorum_types::{FederatedPeerDiagnostics, PeerQueryOutcome, PeerQueryStatus};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_adversarial_multiaddr_port_4001_matrix() {
    // 1. IPFS default swarm port 4001 formats (MUST BE REJECTED)
    let rejected_4001_cases = vec![
        "/ip4/192.168.1.10/tcp/4001",
        "/ip4/10.0.0.5/tcp/4001",
        "/ip4/172.16.0.2/tcp/4001",
        "/ip4/192.168.1.10/udp/4001",
        "/ip4/10.0.0.5/udp/4001/quic-v1",
        "/ip4/192.168.1.10/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        "/ip4/10.0.0.5/udp/4001/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        "/dns4/bootstrap.libp2p.io/tcp/4001",
        "/dns4/ipfs.tech/tcp/4001/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
        "/dns/node.ipfs.io/udp/4001/quic-v1",
        "/dns/node.ipfs.io/tcp/4001",
        "192.168.1.10:4001",
        "10.0.0.5:4001",
    ];

    for addr in &rejected_4001_cases {
        assert!(
            !is_dialable_lan_or_wan_multiaddr(addr),
            "Adversarial failure: address '{}' containing port 4001 was falsely accepted!",
            addr
        );
    }

    // 2. Valid QuorumRAG mesh ports 3032 and 3033 formats (MUST BE ACCEPTED)
    let accepted_mesh_cases = vec![
        "/ip4/192.168.1.10/tcp/3032",
        "/ip4/10.0.0.5/tcp/3032",
        "/ip4/172.16.0.2/tcp/3032",
        "/ip4/192.168.1.10/tcp/3033",
        "/ip4/10.0.0.5/tcp/3033",
        "/ip4/192.168.1.10/udp/3032",
        "/ip4/10.0.0.5/udp/3032/quic-v1",
        "/ip4/192.168.1.10/udp/3033/quic-v1",
        "/ip4/192.168.1.10/tcp/3032/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        "/ip4/10.0.0.5/udp/3032/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
        "/dns4/peer-node.mesh.internal/tcp/3032",
        "/dns4/peer-node.mesh.internal/tcp/3033",
        "/dns/mesh.local/udp/3032/quic-v1",
    ];

    for addr in &accepted_mesh_cases {
        assert!(
            is_dialable_lan_or_wan_multiaddr(addr),
            "Adversarial failure: valid mesh address '{}' was falsely rejected!",
            addr
        );
    }

    // 3. Loopback, broadcast, and invalid IP addresses (MUST BE REJECTED regardless of port)
    let invalid_ip_cases = vec![
        "/ip4/127.0.0.1/tcp/3032",
        "/ip4/127.0.0.1/tcp/3033",
        "/ip4/0.0.0.0/tcp/3032",
        "/ip4/10.0.0.255/tcp/3032",
        "/ip4/192.168.1.255/tcp/3032",
        "/ip4/10.0.0.0/tcp/3032",
        "/ip4/224.0.0.1/tcp/3032", // multicast
    ];

    for addr in &invalid_ip_cases {
        assert!(
            !is_dialable_lan_or_wan_multiaddr(addr),
            "Adversarial failure: non-routable address '{}' was falsely accepted!",
            addr
        );
    }
}

#[test]
fn test_strip_p2p_suffix_preserves_valid_multiaddr_bases() {
    let test_cases = vec![
        (
            "/ip4/192.168.1.15/tcp/3032/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
            "/ip4/192.168.1.15/tcp/3032",
        ),
        (
            "/ip4/10.0.0.20/udp/3032/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN",
            "/ip4/10.0.0.20/udp/3032/quic-v1",
        ),
        (
            "/dns4/node.example.org/tcp/3032",
            "/dns4/node.example.org/tcp/3032",
        ),
    ];

    for (input, expected) in test_cases {
        assert_eq!(strip_p2p_suffix(input), expected);
    }
}

#[test]
fn test_adversarial_known_peers_json_scrubbing_and_filtering() {
    let temp_dir = tempdir().expect("tempdir");
    let file_path = temp_dir.path().join("p2p_known_peers.json");

    let raw_json = serde_json::json!({
        "updated_at": "2026-11-08T12:00:00Z",
        "multiaddrs": [
            "/ip4/192.168.1.50/tcp/4001",
            "/ip4/10.0.0.100/tcp/4001/p2p/12D3KooWNonQuorumPeer",
            "/ip4/192.168.1.50/tcp/3032/p2p/12D3KooWValidPeer1",
            "/ip4/127.0.0.1/tcp/3032",
            "/dns4/ipfs.io/tcp/4001",
            "/dns4/node.mesh.local/tcp/3032",
            "/ip4/10.0.0.200/udp/3033/quic-v1"
        ],
        "peer_map": {
            "12D3KooWNonQuorumPeer": "/ip4/10.0.0.100/tcp/4001",
            "12D3KooWValidPeer1": "/ip4/192.168.1.50/tcp/3032",
            "12D3KooWLoopbackPeer": "/ip4/127.0.0.1/tcp/3032",
            "12D3KooWValidPeer2": "/dns4/node.mesh.local/tcp/3032"
        }
    });

    fs::write(&file_path, serde_json::to_string_pretty(&raw_json).unwrap()).expect("write json");

    let loaded = load_known_peers_from_dir(temp_dir.path());

    // Verify multiaddrs list
    for ma in &loaded.multiaddrs {
        assert!(
            !ma.contains("4001"),
            "Scrubbing violation: port 4001 multiaddr leaked into loaded known peers: {}",
            ma
        );
        assert!(
            !ma.contains("127.0.0.1"),
            "Scrubbing violation: loopback multiaddr leaked into loaded known peers: {}",
            ma
        );
    }

    assert!(
        loaded.multiaddrs.contains(&"/ip4/192.168.1.50/tcp/3032/p2p/12D3KooWValidPeer1".to_string()),
        "Valid 3032 multiaddr was lost"
    );
    assert!(
        loaded.multiaddrs.contains(&"/dns4/node.mesh.local/tcp/3032".to_string()),
        "Valid DNS 3032 multiaddr was lost"
    );
    assert!(
        loaded.multiaddrs.contains(&"/ip4/10.0.0.200/udp/3033/quic-v1".to_string()),
        "Valid UDP 3033 multiaddr was lost"
    );

    // Verify peer_map
    assert!(!loaded.peer_map.contains_key("12D3KooWNonQuorumPeer"));
    assert!(!loaded.peer_map.contains_key("12D3KooWLoopbackPeer"));
    assert!(loaded.peer_map.contains_key("12D3KooWValidPeer1"));
    assert!(loaded.peer_map.contains_key("12D3KooWValidPeer2"));
}

#[test]
fn test_adversarial_diagnostics_summary_reason_connected_peers_hierarchy() {
    // Case A: 0 peers connected, 0 outcomes -> spurious "0 peers connected" expected
    let mut diag_zero = FederatedPeerDiagnostics::new(0, vec![]);
    diag_zero.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag_zero.summary_reason.as_deref(),
        Some("0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)")
    );

    // Case B: 1 peer connected, but 0 responses returned (empty peer_outcomes)
    // Invariant: MUST NOT say "0 peers connected"!!
    let mut diag_one_connected = FederatedPeerDiagnostics {
        connected_peers_count: 1,
        connected_peer_ids: vec!["12D3KooWPeer1".to_string()],
        queried_peers_count: 1,
        peer_outcomes: vec![],
        summary_reason: None,
        contributing_peer_ids: vec![],
    };
    diag_one_connected.compute_summary_reason(3032, 5000);
    let reason = diag_one_connected.summary_reason.unwrap();
    assert!(
        !reason.starts_with("0 peers connected"),
        "Telemetry bug: Reported '0 peers connected' when connected_peers_count == 1!"
    );
    assert_eq!(
        reason,
        "1 peer connected on P2P port 3032, but 0 responses received"
    );

    // Case C: 3 peers connected, empty outcomes
    let mut diag_three = FederatedPeerDiagnostics {
        connected_peers_count: 3,
        connected_peer_ids: vec![
            "12D3KooWPeer1".to_string(),
            "12D3KooWPeer2".to_string(),
            "12D3KooWPeer3".to_string(),
        ],
        queried_peers_count: 3,
        peer_outcomes: vec![],
        summary_reason: None,
        contributing_peer_ids: vec![],
    };
    diag_three.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag_three.summary_reason.as_deref(),
        Some("3 peers connected on P2P port 3032, but 0 responses received")
    );

    // Case D: Responding peer returned 0 matching chunks
    let mut diag_zero_matching = FederatedPeerDiagnostics {
        connected_peers_count: 1,
        connected_peer_ids: vec!["12D3KooWPeer1".to_string()],
        queried_peers_count: 1,
        peer_outcomes: vec![PeerQueryOutcome {
            peer_id: "12D3KooWPeer1".to_string(),
            status: PeerQueryStatus::ZeroMatchingChunks,
            matching_chunk_count: 0,
            cited_chunk_count: 0,
            latency_ms: 120,
            error_message: None,
        }],
        summary_reason: None,
        contributing_peer_ids: vec![],
    };
    diag_zero_matching.compute_summary_reason(3032, 5000);
    assert_eq!(
        diag_zero_matching.summary_reason.as_deref(),
        Some("Peer 12D3KooWPeer1 returned 0 matching chunks for this query")
    );
}
