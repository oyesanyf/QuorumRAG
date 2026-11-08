//! Adversarial Challenger M33 Stress Tests:
//! Rigorous empirical verification of peer query diagnostics, status outcome variations,
//! summary reason priority hierarchies, citation diagnostic omission invariants,
//! empty-state handling, and concurrency stress harnesses.

use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_types::{
    DocumentChunk, FederatedPeerDiagnostics, PeerQueryOutcome, PeerQueryStatus, ScoredChunk,
};
use std::sync::Arc;

fn make_test_chunk(id: &str, file: &str, content: &str, source: &str, is_remote: bool) -> ScoredChunk {
    let doc = DocumentChunk::new(
        id,
        "test_doc",
        file,
        1,
        10,
        0,
        vec![0.1f32; 768],
        content,
        None,
    )
    .expect("Valid chunk");
    ScoredChunk::new(doc, 0.95, source, is_remote)
}

/// 1. Verifies that all 5 PeerQueryStatus variants have distinct labels and serialize/deserialize cleanly.
#[test]
fn test_peer_query_status_all_variants_label_and_serde() {
    let variants = [
        (PeerQueryStatus::Connected, "connected", "\"Connected\""),
        (PeerQueryStatus::ZeroMatchingChunks, "zero_matching_chunks", "\"ZeroMatchingChunks\""),
        (PeerQueryStatus::TimedOut, "timed_out", "\"TimedOut\""),
        (PeerQueryStatus::BlockedByPolicy, "blocked_by_policy", "\"BlockedByPolicy\""),
        (PeerQueryStatus::NetworkError, "network_error", "\"NetworkError\""),
    ];

    let mut seen_labels = std::collections::HashSet::new();
    for (status, expected_label, expected_json) in &variants {
        assert_eq!(status.label(), *expected_label);
        assert!(
            seen_labels.insert(status.label()),
            "Duplicate status label detected: {}",
            status.label()
        );

        let json = serde_json::to_string(status).expect("Serialization failed");
        assert_eq!(&json, expected_json);

        let parsed: PeerQueryStatus = serde_json::from_str(&json).expect("Deserialization failed");
        assert_eq!(&parsed, status);
    }
}

/// 2. Verifies the strict priority hierarchy in `compute_summary_reason`:
/// Priority 1: BlockedByPolicy
/// Priority 2: TimedOut
/// Priority 3: ZeroMatchingChunks
/// Priority 4: NetworkError
/// Fallback: "No data returned from remote peers"
#[test]
fn test_summary_reason_priority_hierarchy_under_multi_peer_permutations() {
    let p_policy = PeerQueryOutcome {
        peer_id: "peer_dlp".to_string(),
        status: PeerQueryStatus::BlockedByPolicy,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 12,
        error_message: Some("Explicit folder share rejected".to_string()),
    };

    let p_timeout = PeerQueryOutcome {
        peer_id: "peer_slow".to_string(),
        status: PeerQueryStatus::TimedOut,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 450,
        error_message: Some("Timed out after 450ms".to_string()),
    };

    let p_zero = PeerQueryOutcome {
        peer_id: "peer_empty".to_string(),
        status: PeerQueryStatus::ZeroMatchingChunks,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 25,
        error_message: None,
    };

    let p_net = PeerQueryOutcome {
        peer_id: "peer_broken".to_string(),
        status: PeerQueryStatus::NetworkError,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 5,
        error_message: Some("Connection reset by peer".to_string()),
    };

    // Case A: BlockedByPolicy + TimedOut + ZeroMatchingChunks + NetworkError
    // BlockedByPolicy MUST win regardless of insertion order
    let mut diag_a = FederatedPeerDiagnostics::new(4, vec!["peer_dlp".into(), "peer_slow".into(), "peer_empty".into(), "peer_broken".into()]);
    diag_a.queried_peers_count = 4;
    diag_a.peer_outcomes = vec![p_net.clone(), p_zero.clone(), p_timeout.clone(), p_policy.clone()];
    diag_a.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag_a.summary_reason,
        Some("Peer peer_dlp blocked by shared-folder / DLP policy".to_string())
    );

    // Case B: TimedOut + ZeroMatchingChunks + NetworkError (No policy block)
    // TimedOut MUST win
    let mut diag_b = FederatedPeerDiagnostics::new(3, vec!["peer_slow".into(), "peer_empty".into(), "peer_broken".into()]);
    diag_b.queried_peers_count = 3;
    diag_b.peer_outcomes = vec![p_zero.clone(), p_net.clone(), p_timeout.clone()];
    diag_b.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag_b.summary_reason,
        Some("Peer peer_slow timed out after 450ms".to_string())
    );

    // Case C: ZeroMatchingChunks + NetworkError (No timeout, no policy block)
    // ZeroMatchingChunks MUST win
    let mut diag_c = FederatedPeerDiagnostics::new(2, vec!["peer_empty".into(), "peer_broken".into()]);
    diag_c.queried_peers_count = 2;
    diag_c.peer_outcomes = vec![p_net.clone(), p_zero.clone()];
    diag_c.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag_c.summary_reason,
        Some("Peer peer_empty returned 0 matching chunks for this query".to_string())
    );

    // Case D: NetworkError only
    let mut diag_d = FederatedPeerDiagnostics::new(1, vec!["peer_broken".into()]);
    diag_d.queried_peers_count = 1;
    diag_d.peer_outcomes = vec![p_net.clone()];
    diag_d.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag_d.summary_reason,
        Some("Peer peer_broken network error: Connection reset by peer".to_string())
    );

    // Case E: Multiple peers sharing the SAME highest-priority status:
    // First peer in outcome list MUST be selected deterministically
    let p_policy_2 = PeerQueryOutcome {
        peer_id: "peer_dlp_secondary".to_string(),
        status: PeerQueryStatus::BlockedByPolicy,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 8,
        error_message: Some("Denied by policy rule".to_string()),
    };
    let mut diag_e = FederatedPeerDiagnostics::new(2, vec!["peer_dlp_first".into(), "peer_dlp_secondary".into()]);
    diag_e.queried_peers_count = 2;
    diag_e.peer_outcomes = vec![p_policy.clone(), p_policy_2];
    diag_e.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag_e.summary_reason,
        Some("Peer peer_dlp blocked by shared-folder / DLP policy".to_string())
    );
}

/// 3. Verifies NetworkError string construction with custom error message vs fallback default.
#[test]
fn test_summary_reason_network_error_variations() {
    // With explicit error message
    let mut diag1 = FederatedPeerDiagnostics::new(1, vec!["peer_err_1".into()]);
    diag1.queried_peers_count = 1;
    diag1.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_err_1".to_string(),
        status: PeerQueryStatus::NetworkError,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 10,
        error_message: Some("tls handshake failure: bad certificate".to_string()),
    });
    diag1.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag1.summary_reason,
        Some("Peer peer_err_1 network error: tls handshake failure: bad certificate".to_string())
    );

    // With None error message (fallback)
    let mut diag2 = FederatedPeerDiagnostics::new(1, vec!["peer_err_2".into()]);
    diag2.queried_peers_count = 1;
    diag2.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_err_2".to_string(),
        status: PeerQueryStatus::NetworkError,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 10,
        error_message: None,
    });
    diag2.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag2.summary_reason,
        Some("Peer peer_err_2 network error: network error communicating with peer".to_string())
    );
}

/// 4. Verifies TimedOut latency rendering: latency_ms > 0 uses latency_ms, latency_ms == 0 uses default_timeout_ms.
#[test]
fn test_summary_reason_timed_out_latency_behavior() {
    // latency_ms > 0
    let mut diag1 = FederatedPeerDiagnostics::new(1, vec!["peer_slow_1".into()]);
    diag1.queried_peers_count = 1;
    diag1.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_slow_1".to_string(),
        status: PeerQueryStatus::TimedOut,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 385,
        error_message: None,
    });
    diag1.compute_summary_reason(3032, 500);
    assert_eq!(
        diag1.summary_reason,
        Some("Peer peer_slow_1 timed out after 385ms".to_string())
    );

    // latency_ms == 0 falls back to default_timeout_ms
    let mut diag2 = FederatedPeerDiagnostics::new(1, vec!["peer_slow_2".into()]);
    diag2.queried_peers_count = 1;
    diag2.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_slow_2".to_string(),
        status: PeerQueryStatus::TimedOut,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 0,
        error_message: None,
    });
    diag2.compute_summary_reason(3032, 750);
    assert_eq!(
        diag2.summary_reason,
        Some("Peer peer_slow_2 timed out after 750ms".to_string())
    );
}

/// 5. Verifies behavior when a peer has status Connected (e.g. matching_chunk_count > 0)
/// but 0 chunks were cited (e.g. local chunks outranked them).
#[test]
fn test_connected_peer_with_un_cited_chunks_fallback() {
    let mut diag = FederatedPeerDiagnostics::new(1, vec!["peer_connected".into()]);
    diag.queried_peers_count = 1;
    diag.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_connected".to_string(),
        status: PeerQueryStatus::Connected,
        matching_chunk_count: 3,
        cited_chunk_count: 0, // Outranked during fusion
        latency_ms: 50,
        error_message: None,
    });
    diag.compute_summary_reason(3032, 1000);

    // With Connected status and 0 cited chunks, compute_summary_reason reports returned chunks (0 cited)
    assert_eq!(
        diag.summary_reason,
        Some("Peer peer_connected returned 3 chunks (0 cited)".to_string())
    );
}

/// 6. Verifies edge cases for 0 connected peers, 0 queried peers, and empty peer outcomes.
#[test]
fn test_summary_reason_boundary_conditions() {
    // 0 connected peers
    let mut diag0 = FederatedPeerDiagnostics::new(0, vec![]);
    diag0.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag0.summary_reason,
        Some("0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)".to_string())
    );

    // Non-standard port (e.g., 4055)
    let mut diag_custom_port = FederatedPeerDiagnostics::new(0, vec![]);
    diag_custom_port.compute_summary_reason(4055, 1000);
    assert_eq!(
        diag_custom_port.summary_reason,
        Some("0 peers connected on P2P port 4055 (no mDNS or bootstrap peers online)".to_string())
    );

    // Connected peers > 0 but queried peers == 0
    let mut diag_not_queried = FederatedPeerDiagnostics::new(2, vec!["p1".into(), "p2".into()]);
    diag_not_queried.queried_peers_count = 0;
    diag_not_queried.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag_not_queried.summary_reason,
        Some("P2P mesh query skipped (0 remote peers queried)".to_string())
    );

    // Connected peers > 0, queried peers > 0, but peer_outcomes is empty
    let mut diag_empty_outcomes = FederatedPeerDiagnostics::new(2, vec!["p1".into(), "p2".into()]);
    diag_empty_outcomes.queried_peers_count = 2;
    diag_empty_outcomes.peer_outcomes.clear();
    diag_empty_outcomes.compute_summary_reason(3032, 1000);
    assert_eq!(
        diag_empty_outcomes.summary_reason,
        Some("0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)".to_string())
    );
}

/// 7. Invariant: When remote chunks ARE cited in the answer, the diagnostic failure line
/// MUST strictly NOT be rendered in format_sources_block.
#[test]
fn test_sources_block_citation_omission_invariant_strict() {
    let local_chunk = make_test_chunk("c_loc", "C:/docs/loc.md", "Local text", "local", false);
    let remote_chunk = make_test_chunk("c_rem", "C:/docs/rem.md", "Remote text", "12D3KooWAlpha", true);

    let mut diag = FederatedPeerDiagnostics::new(1, vec!["12D3KooWAlpha".into()]);
    diag.queried_peers_count = 1;
    diag.summary_reason = Some("Peer 12D3KooWAlpha returned 0 matching chunks for this query".to_string());

    // Case A: Only local chunk -> Diagnostic line MUST be rendered
    let sources_local_only = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(
        &[&local_chunk],
        Some(&diag),
    );
    assert!(
        sources_local_only.contains("- *📡 Remote Peers:* No data from remote peers — Reason:"),
        "Diagnostic row must be present when 0 remote chunks are cited"
    );

    // Case B: Both local AND remote chunks cited -> Diagnostic line MUST NOT be rendered
    let sources_mixed = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(
        &[&local_chunk, &remote_chunk],
        Some(&diag),
    );
    assert!(
        !sources_mixed.contains("📡 Remote Peers"),
        "Diagnostic row must be omitted when remote chunks are cited: {}",
        sources_mixed
    );
    assert!(
        !sources_mixed.contains("No data from remote peers"),
        "Diagnostic reason must be omitted when remote chunks are cited: {}",
        sources_mixed
    );
    assert!(
        sources_mixed.contains("(Peer: 12D3KooW)"),
        "Remote peer identifier badge must be rendered in citation: {}",
        sources_mixed
    );

    // Case C: Only remote chunk cited -> Diagnostic line MUST NOT be rendered
    let sources_remote_only = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(
        &[&remote_chunk],
        Some(&diag),
    );
    assert!(
        !sources_remote_only.contains("📡 Remote Peers"),
        "Diagnostic row must be omitted when remote chunks are cited: {}",
        sources_remote_only
    );
}

/// 8. Verifies format_sources_block with empty chunks list:
/// With diagnostics: outputs diagnostic row in a sources section.
/// Without diagnostics: outputs empty string.
#[test]
fn test_sources_block_empty_chunks_with_and_without_diagnostics() {
    let mut diag = FederatedPeerDiagnostics::new(0, vec![]);
    diag.compute_summary_reason(3032, 1000);

    // Empty chunks + with diagnostics
    let formatted_with_diag = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(
        &[],
        Some(&diag),
    );
    assert!(
        formatted_with_diag.contains("### 📚 Sources & Document Links"),
        "Header must be present when diagnostics provide a summary reason"
    );
    assert!(
        formatted_with_diag.contains("- *📡 Remote Peers:* No data from remote peers — Reason: 0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)"),
        "Diagnostic reason must be present in empty results"
    );

    // Empty chunks + None diagnostics
    let formatted_none = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(&[], None);
    assert_eq!(
        formatted_none, "",
        "Must return empty string when matched chunks is empty and no diagnostics exist"
    );

    // Empty chunks + diagnostics with summary_reason == None
    let diag_empty_reason = FederatedPeerDiagnostics::default();
    let formatted_empty_reason = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(
        &[],
        Some(&diag_empty_reason),
    );
    assert_eq!(
        formatted_empty_reason, "",
        "Must return empty string when matched chunks is empty and summary_reason is None"
    );
}

/// 9. Stress-tests ACTIVE_PEER_DIAGNOSTICS under high concurrency:
/// 30 tokio tasks concurrently setting, reading, clearing, and formatting sources.
/// Asserts that no panics, poison errors, or thread crashes occur.
#[tokio::test]
async fn test_active_peer_diagnostics_rwlock_concurrency_stress() {
    let local_chunk = Arc::new(make_test_chunk("c_c1", "C:/docs/conc.md", "Concurrent data", "local", false));

    let mut handles = Vec::new();
    for i in 0..30 {
        let chunk = Arc::clone(&local_chunk);
        handles.push(tokio::spawn(async move {
            for j in 0..20 {
                let mut diag = FederatedPeerDiagnostics::new(1, vec![format!("peer_{}_{}", i, j)]);
                diag.queried_peers_count = 1;
                diag.peer_outcomes.push(PeerQueryOutcome {
                    peer_id: format!("peer_{}_{}", i, j),
                    status: PeerQueryStatus::TimedOut,
                    matching_chunk_count: 0,
                    cited_chunk_count: 0,
                    latency_ms: (i * 10 + j) as u64,
                    error_message: None,
                });
                diag.compute_summary_reason(3032, 500);

                DeterministicOfflineSynthesisEngine::set_active_peer_diagnostics(diag);

                let active = DeterministicOfflineSynthesisEngine::active_peer_diagnostics();
                assert!(active.is_some(), "Active diagnostics should be readable");

                let formatted = DeterministicOfflineSynthesisEngine::format_sources_block(&[&chunk]);
                assert!(
                    formatted.contains("### 📚 Sources & Document Links"),
                    "Formatted block must contain sources header"
                );

                if j % 5 == 0 {
                    DeterministicOfflineSynthesisEngine::clear_active_peer_diagnostics();
                }
            }
        }));
    }

    for h in handles {
        h.await.expect("Task should join cleanly without panic");
    }

    DeterministicOfflineSynthesisEngine::clear_active_peer_diagnostics();
}

/// 10. Differential oracle: demonstrates that `format_sources_block_with_diagnostics`
/// is strictly isolated from global state, whereas `format_sources_block` reads global state.
#[test]
fn test_differential_oracle_format_sources_block_isolation() {
    let local_chunk = make_test_chunk("c_diff", "C:/docs/diff.md", "Differential text", "local", false);

    let mut diag_isolated = FederatedPeerDiagnostics::new(1, vec!["peer_isolated".into()]);
    diag_isolated.queried_peers_count = 1;
    diag_isolated.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_isolated".into(),
        status: PeerQueryStatus::BlockedByPolicy,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 10,
        error_message: None,
    });
    diag_isolated.compute_summary_reason(3032, 1000);

    // Global state is set to a DIFFERENT reason
    let mut diag_global = FederatedPeerDiagnostics::new(1, vec!["peer_global".into()]);
    diag_global.queried_peers_count = 1;
    diag_global.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_global".into(),
        status: PeerQueryStatus::ZeroMatchingChunks,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 10,
        error_message: None,
    });
    diag_global.compute_summary_reason(3032, 1000);
    DeterministicOfflineSynthesisEngine::set_active_peer_diagnostics(diag_global);

    // Isolated call MUST reflect isolated diagnostics regardless of global state
    let isolated_block = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(
        &[&local_chunk],
        Some(&diag_isolated),
    );
    assert!(
        isolated_block.contains("Peer peer_isolated blocked by shared-folder / DLP policy"),
        "Isolated call must use provided diagnostics: {}",
        isolated_block
    );
    assert!(
        !isolated_block.contains("peer_global"),
        "Isolated call must NOT be contaminated by global state: {}",
        isolated_block
    );

    // Global call uses global state
    let global_block = DeterministicOfflineSynthesisEngine::format_sources_block(&[&local_chunk]);
    assert!(
        global_block.contains("Peer peer_global returned 0 matching chunks for this query"),
        "Global call should use global state: {}",
        global_block
    );

    DeterministicOfflineSynthesisEngine::clear_active_peer_diagnostics();
}
