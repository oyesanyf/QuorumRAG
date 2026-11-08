//! Milestone M33 Tests: Structured Peer Diagnostics Model,
//! Web UI & Sources Block Peer Diagnostic Reporting, and Folder Share Gating Bug Fix.

use quorum_coordinator::config::CoordinatorConfig;
use quorum_coordinator::mesh::{MockMeshDispatcher, MockRemotePeer};
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_coordinator::scatter_gather::ScatterGatherEngine;
use quorum_coordinator::{PeerAclManager, QueryCoordinator, StorageSearcher};
use quorum_types::{
    CandidateChunkDto, DocumentChunk, FederatedPeerDiagnostics, PeerQueryOutcome,
    PeerQueryStatus, ScoredChunk,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Default, Clone)]
struct TestLocalStorage {
    chunks: Vec<DocumentChunk>,
}

#[async_trait::async_trait]
impl StorageSearcher for TestLocalStorage {
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

fn sample_chunk(id: &str, path: &str, text: &str) -> DocumentChunk {
    DocumentChunk::new(
        id,
        "doc_1",
        path,
        1,
        10,
        0,
        vec![0.1f32; 768],
        text,
        None,
    )
    .unwrap()
}

/// 1. Verifies that when 0 remote peers are connected on the P2P port,
/// `peer_diagnostics.summary_reason` is populated with:
/// "0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)",
/// and the offline sources block renders the exact diagnostic message.
#[tokio::test]
async fn test_peer_diagnostics_zero_connected_peers() {
    let local_chunk = sample_chunk("c_local_1", "C:/docs/alpha.md", "Local Alpha documentation");
    let storage = Arc::new(TestLocalStorage {
        chunks: vec![local_chunk],
    });

    let mock_mesh = Arc::new(MockMeshDispatcher::new());
    let mut config = CoordinatorConfig::default();
    config.timeout_ms = 500;

    let engine = Arc::new(ScatterGatherEngine::new(
        storage,
        mock_mesh,
        Arc::new(RwLock::new(PeerAclManager::default())),
        config,
        [0u8; 32],
        "local_node".to_string(),
    ));

    let query_vec = vec![0.1f32; 768];
    let (fused, _, _, _) = engine
        .execute_query_with_p2p_query_and_exclusion("Alpha query", "Alpha query", &query_vec, None, 0, 5, &[])
        .await;

    assert!(!fused.is_empty(), "Local chunk should be returned");
    let diag = engine.last_diagnostics().await.expect("diagnostics should be recorded");

    assert_eq!(diag.connected_peers_count, 0);
    assert_eq!(diag.queried_peers_count, 0);
    assert!(diag.peer_outcomes.is_empty());
    assert_eq!(
        diag.summary_reason,
        Some("0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)".to_string())
    );

    let fused_refs: Vec<&ScoredChunk> = fused.iter().collect();
    let sources_block = DeterministicOfflineSynthesisEngine::format_sources_block(&fused_refs);
    assert!(
        sources_block.contains("- *📡 Remote Peers:* No data from remote peers — Reason: 0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)"),
        "Sources block must render the exact 0-peer diagnostic row: {}",
        sources_block
    );
}

/// 2. Verifies that when a connected peer returns 0 matching chunks,
/// `peer_diagnostics.summary_reason` contains "Peer <id> returned 0 matching chunks for this query",
/// and the offline sources block renders this exact reason.
#[tokio::test]
async fn test_peer_diagnostics_zero_matching_chunks() {
    let local_chunk = sample_chunk("c_local_2", "C:/docs/beta.md", "Local Beta documentation");
    let storage = Arc::new(TestLocalStorage {
        chunks: vec![local_chunk],
    });

    let mock_mesh = Arc::new(MockMeshDispatcher::new());
    mock_mesh
        .add_peer(MockRemotePeer {
            peer_id: "peer_bravo_001".to_string(),
            latency: Duration::from_millis(10),
            max_access_tier: 0,
            candidate_chunks: Vec::new(), // 0 matching chunks
        })
        .await;

    let mut config = CoordinatorConfig::default();
    config.timeout_ms = 500;

    let engine = Arc::new(ScatterGatherEngine::new(
        storage,
        mock_mesh,
        Arc::new(RwLock::new(PeerAclManager::default())),
        config,
        [0u8; 32],
        "local_node".to_string(),
    ));

    let query_vec = vec![0.1f32; 768];
    let (fused, _, _, _) = engine
        .execute_query_with_p2p_query_and_exclusion("Beta query", "Beta query", &query_vec, None, 0, 5, &[])
        .await;

    let diag = engine.last_diagnostics().await.expect("diagnostics should be recorded");
    assert_eq!(diag.connected_peers_count, 1);
    assert_eq!(diag.queried_peers_count, 1);
    assert_eq!(diag.peer_outcomes.len(), 1);
    assert_eq!(diag.peer_outcomes[0].status, PeerQueryStatus::ZeroMatchingChunks);
    assert_eq!(
        diag.summary_reason,
        Some("Peer peer_bravo_001 returned 0 matching chunks for this query".to_string())
    );

    let fused_refs: Vec<&ScoredChunk> = fused.iter().collect();
    let sources_block = DeterministicOfflineSynthesisEngine::format_sources_block(&fused_refs);
    assert!(
        sources_block.contains("- *📡 Remote Peers:* No data from remote peers — Reason: Peer peer_bravo_001 returned 0 matching chunks for this query"),
        "Sources block must render the exact zero-matching chunks diagnostic: {}",
        sources_block
    );
}

/// 3. Verifies that when a connected peer times out,
/// `peer_diagnostics.summary_reason` contains "Peer <id> timed out after <N>ms",
/// and the offline sources block renders this exact reason.
#[tokio::test]
async fn test_peer_diagnostics_timed_out_peer() {
    let local_chunk = sample_chunk("c_local_3", "C:/docs/gamma.md", "Local Gamma documentation");
    let storage = Arc::new(TestLocalStorage {
        chunks: vec![local_chunk],
    });

    let mock_mesh = Arc::new(MockMeshDispatcher::new());
    mock_mesh
        .add_peer(MockRemotePeer {
            peer_id: "peer_charlie_002".to_string(),
            latency: Duration::from_millis(500), // Latency exceeds 50ms timeout
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: "c_remote_slow".to_string(),
                file_path: "C:/remote/slow.md".to_string(),
                line_start: 1,
                line_end: 10,
                content: "Slow remote chunk".to_string(),
                score: 0.95,
                access_tier: 0,
            }],
        })
        .await;

    let mut config = CoordinatorConfig::default();
    config.timeout_ms = 50; // Fast timeout to trigger TimedOut

    let engine = Arc::new(ScatterGatherEngine::new(
        storage,
        mock_mesh,
        Arc::new(RwLock::new(PeerAclManager::default())),
        config,
        [0u8; 32],
        "local_node".to_string(),
    ));

    let query_vec = vec![0.1f32; 768];
    let (fused, _, _, _) = engine
        .execute_query_with_p2p_query_and_exclusion("Gamma query", "Gamma query", &query_vec, None, 0, 5, &[])
        .await;

    let diag = engine.last_diagnostics().await.expect("diagnostics should be recorded");
    assert_eq!(diag.connected_peers_count, 1);
    assert_eq!(diag.peer_outcomes.len(), 1);
    assert_eq!(diag.peer_outcomes[0].status, PeerQueryStatus::TimedOut);
    let reason = diag.summary_reason.as_ref().expect("summary_reason must be present");
    assert!(
        reason.starts_with("Peer peer_charlie_002 timed out after ") && reason.ends_with("ms"),
        "Unexpected timeout summary reason: {}",
        reason
    );

    let fused_refs: Vec<&ScoredChunk> = fused.iter().collect();
    let sources_block = DeterministicOfflineSynthesisEngine::format_sources_block(&fused_refs);
    assert!(
        sources_block.contains(&format!("- *📡 Remote Peers:* No data from remote peers — Reason: {}", reason)),
        "Sources block must render the exact timed-out peer diagnostic: {}",
        sources_block
    );
}

/// 4. Verifies that when a peer is blocked by shared-folder / DLP policy,
/// `peer_diagnostics.summary_reason` is "Peer <id> blocked by shared-folder / DLP policy",
/// and the offline sources block renders this exact reason.
#[tokio::test]
async fn test_peer_diagnostics_blocked_by_policy() {
    let mut diag = FederatedPeerDiagnostics::new(1, vec!["peer_delta_003".to_string()]);
    diag.queried_peers_count = 1;
    diag.peer_outcomes.push(PeerQueryOutcome {
        peer_id: "peer_delta_003".to_string(),
        status: PeerQueryStatus::BlockedByPolicy,
        matching_chunk_count: 0,
        cited_chunk_count: 0,
        latency_ms: 5,
        error_message: Some("Explicit folder share rejected".to_string()),
    });
    diag.compute_summary_reason(3032, 3500);

    assert_eq!(
        diag.summary_reason,
        Some("Peer peer_delta_003 blocked by shared-folder / DLP policy".to_string())
    );

    DeterministicOfflineSynthesisEngine::set_active_peer_diagnostics(diag);

    let local_chunk = sample_chunk("c_local_4", "C:/docs/delta.md", "Local Delta documentation");
    let scored_chunk = ScoredChunk::new(local_chunk, 0.9, "local", false);
    let sources_block = DeterministicOfflineSynthesisEngine::format_sources_block(&[&scored_chunk]);

    assert!(
        sources_block.contains("- *📡 Remote Peers:* No data from remote peers — Reason: Peer peer_delta_003 blocked by shared-folder / DLP policy"),
        "Sources block must render policy blocked diagnostic: {}",
        sources_block
    );

    DeterministicOfflineSynthesisEngine::clear_active_peer_diagnostics();
}

/// 5. Verifies that when remote peer chunks ARE cited in the final answer,
/// the remote failure diagnostic row is omitted entirely from the sources block.
#[tokio::test]
async fn test_peer_diagnostics_omitted_when_remote_chunks_cited() {
    let local_chunk = sample_chunk("c_local_5", "C:/docs/epsilon.md", "Local Epsilon text");
    let storage = Arc::new(TestLocalStorage {
        chunks: vec![local_chunk],
    });

    let mock_mesh = Arc::new(MockMeshDispatcher::new());
    mock_mesh
        .add_peer(MockRemotePeer {
            peer_id: "peer_echo_004".to_string(),
            latency: Duration::from_millis(10),
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: "c_remote_echo".to_string(),
                file_path: "C:/remote/echo.md".to_string(),
                line_start: 1,
                line_end: 50,
                content: "Epsilon remote text from peer echo".to_string(),
                score: 0.99,
                access_tier: 0,
            }],
        })
        .await;

    let mut config = CoordinatorConfig::default();
    config.timeout_ms = 500;

    let engine = Arc::new(ScatterGatherEngine::new(
        storage,
        mock_mesh,
        Arc::new(RwLock::new(PeerAclManager::default())),
        config,
        [0u8; 32],
        "local_node".to_string(),
    ));

    let query_vec = vec![0.1f32; 768];
    let (fused, _, _, _) = engine
        .execute_query_with_p2p_query_and_exclusion("Epsilon query", "Epsilon query", &query_vec, None, 0, 5, &[])
        .await;

    assert!(
        fused.iter().any(|c| c.is_remote),
        "Fused results must include the remote chunk"
    );

    let fused_refs: Vec<&ScoredChunk> = fused.iter().collect();
    let sources_block = DeterministicOfflineSynthesisEngine::format_sources_block(&fused_refs);
    assert!(
        !sources_block.contains("📡 Remote Peers"),
        "Sources block must NOT render the remote failure diagnostic row when remote chunks are cited: {}",
        sources_block
    );
}

/// 6. Verifies end-to-end QueryCoordinator populates `peer_diagnostics` in `QueryResult`.
#[tokio::test]
async fn test_coordinator_query_result_contains_diagnostics() {
    let local_chunk = sample_chunk("c_local_6", "C:/docs/zeta.md", "Local Zeta text");
    let storage = Arc::new(TestLocalStorage {
        chunks: vec![local_chunk],
    });

    let mock_mesh = Arc::new(MockMeshDispatcher::new());
    let mut config = CoordinatorConfig::default();
    config.timeout_ms = 500;

    let engine = Arc::new(ScatterGatherEngine::new(
        storage,
        mock_mesh,
        Arc::new(RwLock::new(PeerAclManager::default())),
        config.clone(),
        [0u8; 32],
        "local_node".to_string(),
    ));

    let coordinator = QueryCoordinator::new(engine, config);
    let result = coordinator.query("Zeta prompt", 5).await.expect("query should succeed");

    let diag = result.peer_diagnostics.expect("QueryResult must contain peer_diagnostics");
    assert_eq!(diag.connected_peers_count, 0);
    assert_eq!(
        diag.summary_reason,
        Some("0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)".to_string())
    );
}
