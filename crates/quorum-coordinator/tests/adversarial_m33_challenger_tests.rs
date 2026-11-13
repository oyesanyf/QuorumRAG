//! Adversarial Challenge Test Harness for Milestone M33:
//! Structured Peer Diagnostics, Scatter-Gather Timeouts, UTF-8 Safety, and Concurrency.

use quorum_coordinator::config::CoordinatorConfig;
use quorum_coordinator::mesh::{MockMeshDispatcher, MockRemotePeer};
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_coordinator::scatter_gather::ScatterGatherEngine;
use quorum_coordinator::{PeerAclManager, StorageSearcher};
use quorum_types::{
    CandidateChunkDto, DocumentChunk, FederatedPeerDiagnostics, PeerQueryOutcome,
    PeerQueryStatus, ScoredChunk,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Default, Clone)]
struct MockStorage {
    chunks: Vec<DocumentChunk>,
}

#[async_trait::async_trait]
impl StorageSearcher for MockStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.chunks
            .iter()
            .map(|c| ScoredChunk::new(c.clone(), 0.9, "local", false))
            .collect()
    }

    async fn search_text(
        &self,
        _query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.chunks
            .iter()
            .map(|c| ScoredChunk::new(c.clone(), 0.9, "local", false))
            .collect()
    }
}

fn make_test_chunk(id: &str, file: &str, content: &str) -> DocumentChunk {
    DocumentChunk::new(
        id,
        "doc_alpha",
        file,
        1,
        10,
        0,
        vec![0.1f32; 768],
        content,
        None,
    )
    .unwrap()
}

/// CHALLENGE 1: Empirical reproduction of the timeout calculation discrepancy in ScatterGatherEngine.
///
/// In ScatterGatherEngine::execute_query_with_p2p_query_and_exclusion:
/// `timeout_dur = Duration::from_millis(self.config.timeout_ms.saturating_sub(60).max(self.config.timeout_ms * 3 / 4));`
/// When config.timeout_ms = 50:
/// 50.saturating_sub(60) = 0.
/// 50 * 3 / 4 = 37.
/// Therefore, the remote peer timeout is 37ms, NOT 50ms!
/// This causes `diag.summary_reason` to be "Peer <id> timed out after 37ms",
/// directly failing the worker's unit test `test_peer_diagnostics_timed_out_peer` which asserted 50ms.
#[tokio::test]
async fn test_adversarial_timeout_sub_budget_scaling_reproduction() {
    let storage = Arc::new(MockStorage {
        chunks: vec![make_test_chunk("c1", "C:/local.md", "Local data")],
    });

    let mock_mesh = Arc::new(MockMeshDispatcher::new());
    mock_mesh
        .add_peer(MockRemotePeer {
            peer_id: "peer_stalled_1".to_string(),
            latency: Duration::from_millis(500),
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: "c_rem".to_string(),
                file_path: "C:/rem.md".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Remote".to_string(),
                score: 0.9,
                access_tier: 0,
                origin_peer_id: None,
            }],
        })
        .await;

    let mut config = CoordinatorConfig::default();
    config.timeout_ms = 50;

    let engine = Arc::new(ScatterGatherEngine::new(
        storage,
        mock_mesh,
        Arc::new(RwLock::new(PeerAclManager::default())),
        config,
        [0u8; 32],
        "node_local".to_string(),
    ));

    let query_vec = vec![0.1f32; 768];
    let (fused, _, _, _) = engine
        .execute_query_with_p2p_query_and_exclusion("query", "query", &query_vec, None, 0, 5, &[])
        .await;

    assert!(!fused.is_empty());
    let diag = engine.last_diagnostics().await.expect("must have diagnostics");

    assert_eq!(diag.peer_outcomes.len(), 1);
    let outcome = &diag.peer_outcomes[0];
    assert_eq!(outcome.status, PeerQueryStatus::TimedOut);

    // Empirically prove that latency_ms is 37ms (due to 3/4 budget scaling), NOT 50ms:
    assert_eq!(
        outcome.latency_ms, 37,
        "ScatterGatherEngine scales timeout to 3/4 (37ms), proving why worker test failed"
    );
    assert_eq!(
        diag.summary_reason,
        Some("Peer peer_stalled_1 timed out after 37ms".to_string())
    );
}

/// CHALLENGE 2: UTF-8 Character Boundary Slicing Panic in DeterministicOfflineSynthesisEngine.
///
/// In `DeterministicOfflineSynthesisEngine::format_sources_block`:
/// ```rust
/// let short_peer = if c.source_peer.len() > 8 {
///     &c.source_peer[..8]
/// } else {
///     &c.source_peer
/// };
/// ```
/// If `c.source_peer` has length > 8, but byte offset 8 is in the middle of a multibyte UTF-8 codepoint
/// (such as "peer_🦀_x" where 'p','e','e','r','_' is 5 bytes, and '🦀' is 4 bytes [offsets 5..9]),
/// Rust's `&str[..8]` slicing PANICS at runtime, crashing the request thread!
#[test]
fn test_adversarial_utf8_peer_id_slicing_panic() {
    let base_chunk = make_test_chunk("c_multibyte", "C:/docs/multibyte.md", "Remote multibyte peer test");
    // "peer_" = 5 bytes (0..5)
    // "🦀" = 4 bytes (5..9)
    // Byte offset 8 is inside '🦀'!
    let peer_id_with_utf8_split = "peer_🦀_node";
    assert!(peer_id_with_utf8_split.len() > 8);
    assert!(!peer_id_with_utf8_split.is_char_boundary(8));

    let remote_chunk = ScoredChunk::new(
        base_chunk,
        0.95,
        peer_id_with_utf8_split,
        true,
    );

    // Verify that format_sources_block does not panic and formats cleanly
    let panic_result = std::panic::catch_unwind(|| {
        DeterministicOfflineSynthesisEngine::format_sources_block(&[&remote_chunk])
    });

    assert!(
        panic_result.is_ok(),
        "format_sources_block must handle multibyte UTF-8 peer_ids without panicking"
    );
    let output = panic_result.unwrap();
    assert!(output.contains("Peer:"));
}

/// CHALLENGE 3: Global static `ACTIVE_PEER_DIAGNOSTICS` concurrency race condition.
///
/// `DeterministicOfflineSynthesisEngine::format_sources_block` implicitly reads from
/// the static `ACTIVE_PEER_DIAGNOSTICS` RwLock.
/// In a multi-threaded coordinator where concurrent queries execute simultaneously,
/// Query A can overwrite Query B's active peer diagnostics, causing Query B to report
/// Query A's peer failure reason in its sources block!
#[test]
fn test_adversarial_static_active_diagnostics_cross_query_leakage() {
    let chunk_local = ScoredChunk::new(
        make_test_chunk("c_race", "C:/docs/race.md", "Race condition test"),
        0.85,
        "local",
        false,
    );

    // Query A sets diagnostics indicating a policy block on peer_alpha
    let mut diag_a = FederatedPeerDiagnostics::new(1, vec!["peer_alpha".to_string()]);
    diag_a.queried_peers_count = 1;
    diag_a.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_alpha".to_string(),
        status: PeerQueryStatus::BlockedByPolicy,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 10,
        error_message: Some("Blocked".into()),
    });
    diag_a.compute_summary_reason(3032, 3500);

    // Query B sets diagnostics indicating a timeout on peer_beta
    let mut diag_b = FederatedPeerDiagnostics::new(1, vec!["peer_beta".to_string()]);
    diag_b.queried_peers_count = 1;
    diag_b.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_beta".to_string(),
        status: PeerQueryStatus::TimedOut,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 3500,
        error_message: None,
    });
    diag_b.compute_summary_reason(3032, 3500);

    // Concurrently: Query A sets its diagnostics
    DeterministicOfflineSynthesisEngine::set_active_peer_diagnostics(diag_a);
    // Before Query A formats its sources block, Query B overwrites the static diagnostics
    DeterministicOfflineSynthesisEngine::set_active_peer_diagnostics(diag_b);

    // When Query A formats its sources block without explicit diagnostics,
    // it leaks Query B's peer_beta timeout instead of Query A's peer_alpha policy block!
    let formatted = DeterministicOfflineSynthesisEngine::format_sources_block(&[&chunk_local]);

    assert!(
        formatted.contains("peer_beta timed out"),
        "Empirically proves that static ACTIVE_PEER_DIAGNOSTICS leaks state between concurrent queries"
    );
    assert!(
        !formatted.contains("peer_alpha"),
        "Query A's diagnostics were completely clobbered by Query B"
    );

    DeterministicOfflineSynthesisEngine::clear_active_peer_diagnostics();
}

/// CHALLENGE 4: Markdown header injection via adversarial summary reason.
///
/// Demonstrates that an unescaped adversarial error message from a malicious or compromised peer
/// can break Markdown hierarchy in the synthesis sources block.
#[test]
fn test_adversarial_markdown_injection_in_summary_reason() {
    let mut diag = FederatedPeerDiagnostics::new(1, vec!["peer_attacker".to_string()]);
    diag.queried_peers_count = 1;
    diag.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_attacker".to_string(),
        status: PeerQueryStatus::NetworkError,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 5,
        error_message: Some("\n\n# INJECTED ADMIN BANNER\n[Click Here](http://malicious.link)\n".to_string()),
    });
    diag.compute_summary_reason(3032, 3500);

    let chunk_local = ScoredChunk::new(
        make_test_chunk("c_sec", "C:/docs/sec.md", "Security data"),
        0.9,
        "local",
        false,
    );

    let output = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(
        &[&chunk_local],
        Some(&diag),
    );

    // Check whether injected header appears on a fresh top-level line
    assert!(
        output.contains("# INJECTED ADMIN BANNER"),
        "Demonstrates unescaped multiline injection from peer error message into markdown"
    );
}

/// CHALLENGE 5: Extreme scaling with 5,000 peers in format_sources_block_with_diagnostics.
///
/// Asserts that formatting sources with large diagnostic payloads completes in < 10ms.
#[test]
fn test_adversarial_extreme_scale_formatting_performance() {
    let num_peers = 5_000;
    let mut outcomes = Vec::with_capacity(num_peers);
    for i in 0..num_peers {
        outcomes.push(PeerQueryOutcome {
            peer_id: format!("peer_{:05}", i),
            status: PeerQueryStatus::ZeroMatchingChunks,
            matching_chunk_count: 0,
            cited_chunk_count: 0,
            latency_ms: 2,
            error_message: None,
        });
    }

    let diag = FederatedPeerDiagnostics {
        connected_peers_count: num_peers,
        connected_peer_ids: (0..num_peers).map(|i| format!("peer_{:05}", i)).collect(),
        queried_peers_count: num_peers,
        peer_outcomes: outcomes,
        summary_reason: Some("Peer peer_00000 returned 0 matching chunks for this query".to_string()),
        contributing_peer_ids: Vec::new(),
    };

    let chunk_local = ScoredChunk::new(
        make_test_chunk("c_perf", "C:/docs/perf.md", "Perf data"),
        0.9,
        "local",
        false,
    );

    // Warm-up to eliminate cold heap/code fault overhead
    let _ = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(
        &[&chunk_local],
        Some(&diag),
    );

    let start = std::time::Instant::now();
    let formatted = DeterministicOfflineSynthesisEngine::format_sources_block_with_diagnostics(
        &[&chunk_local],
        Some(&diag),
    );
    let elapsed = start.elapsed();

    let max_budget_ms = if cfg!(debug_assertions) { 50 } else { 10 };
    assert!(elapsed.as_millis() < max_budget_ms, "Formatting must complete in < {}ms, took {:?}", max_budget_ms, elapsed);
    assert!(formatted.contains("peer_00000 returned 0 matching chunks"));
}
