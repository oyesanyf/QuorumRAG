use quorum_coordinator::agentic::RetrieveMeshNode;
use quorum_coordinator::dlp_mesh::global_mesh_dlp_controller;
use quorum_coordinator::fusion::RrfCombiner;
use quorum_coordinator::langextract::Extraction;
use quorum_coordinator::mesh::{MockMeshDispatcher, MockRemotePeer};
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_coordinator::types::{AgenticGraphState, SynthesisModelFamily};
use quorum_coordinator::{CoordinatorConfig, PeerAclManager, ScatterGatherEngine, StorageSearcher};
use quorum_types::{CandidateChunkDto, DocumentChunk, ScoredChunk};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Storage that returns nothing by default, or returns local document if requested.
struct EmptyOrCustomStorage {
    local_chunks: Vec<ScoredChunk>,
}

#[async_trait::async_trait]
impl StorageSearcher for EmptyOrCustomStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.local_chunks.clone()
    }

    async fn search_vector(
        &self,
        _vector: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.local_chunks.clone()
    }

    async fn search_text(
        &self,
        query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.local_chunks
            .iter()
            .filter(|c| {
                let text_l = c.chunk.text_content.to_ascii_lowercase();
                let q_l = query.to_ascii_lowercase();
                q_l.split_whitespace().any(|term| text_l.contains(term))
            })
            .cloned()
            .collect()
    }

    fn index_epoch(&self) -> u64 {
        1
    }
}

/// Reset global mesh DLP controller settings cleanly for test isolation.
fn reset_mesh_controller(max_peer_responses: usize, p2p_enabled: bool) {
    let ctrl = global_mesh_dlp_controller();
    let mut s = ctrl.settings.write().unwrap();
    s.mesh.p2p_enabled = p2p_enabled;
    s.mesh.max_peer_responses = max_peer_responses;
}

#[tokio::test]
async fn test_adversarial_max_peer_responses_capping_k_less_than_n() {
    let mock_disp = Arc::new(MockMeshDispatcher::default());

    // Setup N = 6 mock peers, each with 2 distinct chunks
    const TOTAL_PEERS: usize = 6;
    for i in 1..=TOTAL_PEERS {
        let peer_id = format!("12D3KooWPeerNode{:04}", i);
        let chunk1 = CandidateChunkDto {
            chunk_id: format!("chunk_peer_{}_a", i),
            file_path: format!("shared/doc_peer_{}_a.txt", i),
            line_start: 1,
            line_end: 10,
            score: 0.90,
            access_tier: 0,
            content: format!("Distinct unique payload A from peer node number {}", i),
        };
        let chunk2 = CandidateChunkDto {
            chunk_id: format!("chunk_peer_{}_b", i),
            file_path: format!("shared/doc_peer_{}_b.txt", i),
            line_start: 11,
            line_end: 20,
            score: 0.85,
            access_tier: 0,
            content: format!("Distinct unique payload B from peer node number {}", i),
        };

        mock_disp
            .add_peer(MockRemotePeer {
                peer_id,
                latency: std::time::Duration::from_millis(1),
                max_access_tier: 0,
                candidate_chunks: vec![chunk1, chunk2],
            })
            .await;
    }

    let storage = Arc::new(EmptyOrCustomStorage {
        local_chunks: Vec::new(),
    });

    // 1. Stress test K = 3 where K < N (3 < 6)
    {
        reset_mesh_controller(3, true);
        let mut config = CoordinatorConfig::default();
        config.max_peer_responses = 3;

        let engine = ScatterGatherEngine::new(
            storage.clone(),
            mock_disp.clone(),
            Arc::new(RwLock::new(PeerAclManager::default())),
            config,
            [0xAA; 32],
            "12D3KooWLocalCoordinatorTest".to_string(),
        );

        let (fused, _volatile, _) = engine
            .execute_query("general query payload", &[0.1; 768], 0, 20)
            .await;

        let distinct_peers: HashSet<String> =
            fused.iter().map(|c| c.source_peer.clone()).collect();

        assert_eq!(
            distinct_peers.len(),
            3,
            "Expected exactly 3 unique peer responses to be accepted when K=3 < N=6, found: {:?}",
            distinct_peers
        );

        // Since each accepted peer contributed 2 distinct chunks, fused list must contain exactly 6 chunks
        assert_eq!(
            fused.len(),
            6,
            "Expected all 6 chunks from the 3 accepted peers to be present in fused list"
        );
    }

    // 2. Stress test K = 1 (strict single peer cap)
    {
        reset_mesh_controller(1, true);
        let mut config = CoordinatorConfig::default();
        config.max_peer_responses = 1;

        let engine = ScatterGatherEngine::new(
            storage.clone(),
            mock_disp.clone(),
            Arc::new(RwLock::new(PeerAclManager::default())),
            config,
            [0xAA; 32],
            "12D3KooWLocalCoordinatorTest".to_string(),
        );

        let (fused_1, _volatile_1, _) = engine
            .execute_query("general query payload", &[0.1; 768], 0, 20)
            .await;

        let distinct_peers_1: HashSet<String> =
            fused_1.iter().map(|c| c.source_peer.clone()).collect();

        assert_eq!(
            distinct_peers_1.len(),
            1,
            "Expected strictly 1 unique peer response when max_peer_responses = 1, found: {:?}",
            distinct_peers_1
        );

        // The single peer has 2 chunks
        assert_eq!(fused_1.len(), 2);
    }

    // 3. Stress test search_federated_text with K = 2
    {
        reset_mesh_controller(2, true);
        let mut config = CoordinatorConfig::default();
        config.max_peer_responses = 2;

        let engine = ScatterGatherEngine::new(
            storage.clone(),
            mock_disp.clone(),
            Arc::new(RwLock::new(PeerAclManager::default())),
            config,
            [0xAA; 32],
            "12D3KooWLocalCoordinatorTest".to_string(),
        );

        let fed_results = engine.search_federated_text("payload", 0, 20).await;
        let fed_peers: HashSet<String> =
            fed_results.iter().map(|c| c.source_peer.clone()).collect();

        assert_eq!(
            fed_peers.len(),
            2,
            "search_federated_text must cap remote peer responses to exactly max_peer_responses = 2"
        );
    }
}

#[test]
fn test_adversarial_filename_and_peer_disambiguation_three_peers() {
    let peer_alice = "12D3KooWPeerAliceXXXXXXXX".to_string();
    let peer_bob = "12D3KooWPeerBobYYYYYYYY".to_string();
    let peer_charlie = "12D3KooWPeerCharlieZZZZZZ".to_string();

    // 1. Local chunk with identical file name "document.pdf"
    let local_doc = DocumentChunk::new(
        "local_c1",
        "doc_loc",
        "C:/Corporate/document.pdf",
        1,
        20,
        0,
        vec![0.1; 768],
        "Local node corporate governance charter and bylaws.",
        None,
    )
    .unwrap();
    let local = vec![ScoredChunk::new(local_doc, 0.95, "local", false)];

    // 2. Peer Alice chunk with identical file name "document.pdf"
    let chunk_alice = CandidateChunkDto {
        chunk_id: "alice_c1".to_string(),
        file_path: "D:/DataStore/document.pdf".to_string(),
        line_start: 1,
        line_end: 25,
        score: 0.91,
        access_tier: 0,
        content: "Peer Alice independent operational security risk assessments.".to_string(),
    };

    // 3. Peer Bob chunk with identical file name "document.pdf"
    let chunk_bob = CandidateChunkDto {
        chunk_id: "bob_c1".to_string(),
        file_path: "/var/storage/document.pdf".to_string(),
        line_start: 1,
        line_end: 30,
        score: 0.89,
        access_tier: 0,
        content: "Peer Bob cryptographic key management guidelines and protocols.".to_string(),
    };

    // 4. Peer Charlie chunk with identical file name "document.pdf"
    let chunk_charlie = CandidateChunkDto {
        chunk_id: "charlie_c1".to_string(),
        file_path: "https://mesh.charlie.net/document.pdf".to_string(),
        line_start: 1,
        line_end: 35,
        score: 0.87,
        access_tier: 0,
        content: "Peer Charlie financial audit reconciliation and treasury disclosures.".to_string(),
    };

    let remote_lists = vec![
        (peer_alice.clone(), vec![chunk_alice]),
        (peer_bob.clone(), vec![chunk_bob]),
        (peer_charlie.clone(), vec![chunk_charlie]),
    ];

    // Reciprocal Rank Fusion preserving responder peer identities
    let fused = RrfCombiner::fuse_rankings_with_peers(local, remote_lists, 60.0, 10);
    assert_eq!(
        fused.len(),
        4,
        "All 4 chunks sharing document.pdf filename must be retained across peers in fusion"
    );

    // Verify all chunks retain their respective responder peer IDs in ScoredChunk.source_peer
    let mut observed_peers = HashSet::new();
    for c in &fused {
        observed_peers.insert(c.source_peer.clone());
    }
    assert!(observed_peers.contains("local"), "Local source_peer must be 'local'");
    assert!(observed_peers.contains(&peer_alice), "Alice source_peer must be preserved");
    assert!(observed_peers.contains(&peer_bob), "Bob source_peer must be preserved");
    assert!(observed_peers.contains(&peer_charlie), "Charlie source_peer must be preserved");

    // Verify deduplication in offline_engine.rs does not drop distinct peer copies of the same filename
    let refs: Vec<&ScoredChunk> = fused.iter().collect();
    let citations = DeterministicOfflineSynthesisEngine::build_deduplicated_citations(&refs);
    assert_eq!(
        citations.len(),
        4,
        "Citations list must retain all 4 distinct peer copies of document.pdf"
    );

    // Verify citations format includes (Peer: <short_peer>)
    let sources_block = DeterministicOfflineSynthesisEngine::format_sources_block(&refs);
    assert!(
        sources_block.contains("document.pdf (Peer: 12D3KooW)"),
        "Sources block must format peer attribution with short peer ID for remote files"
    );

    // Verify local document does not have a peer suffix
    assert!(
        sources_block.contains("- [📄 document.pdf]("),
        "Local document must be formatted as '- [📄 document.pdf](' without peer suffix, got:\n{}",
        sources_block
    );
    assert!(
        !sources_block.contains("(Peer: local)"),
        "Local document must not have (Peer: local)"
    );

    // Adversarial sub-test: Intra-peer deduplication must still work for multiple chunks from the same peer and same file
    let chunk_alice_2 = CandidateChunkDto {
        chunk_id: "alice_c2".to_string(),
        file_path: "D:/DataStore/document.pdf".to_string(),
        line_start: 50,
        line_end: 75,
        score: 0.80,
        access_tier: 0,
        content: "Peer Alice additional section 2 from document.pdf.".to_string(),
    };

    let remote_lists_with_dup = vec![
        (peer_alice.clone(), vec![
            CandidateChunkDto {
                chunk_id: "alice_c1".to_string(),
                file_path: "D:/DataStore/document.pdf".to_string(),
                line_start: 1,
                line_end: 25,
                score: 0.91,
                access_tier: 0,
                content: "Peer Alice independent operational security risk assessments.".to_string(),
            },
            chunk_alice_2,
        ]),
        (peer_bob.clone(), vec![
            CandidateChunkDto {
                chunk_id: "bob_c1".to_string(),
                file_path: "/var/storage/document.pdf".to_string(),
                line_start: 1,
                line_end: 30,
                score: 0.89,
                access_tier: 0,
                content: "Peer Bob cryptographic key management guidelines and protocols.".to_string(),
            },
        ]),
    ];

    let fused_with_dup = RrfCombiner::fuse_rankings_with_peers(Vec::new(), remote_lists_with_dup, 60.0, 10);
    assert_eq!(fused_with_dup.len(), 3, "Fusion contains 2 chunks from Alice and 1 from Bob");

    let refs_with_dup: Vec<&ScoredChunk> = fused_with_dup.iter().collect();
    let citations_with_dup = DeterministicOfflineSynthesisEngine::build_deduplicated_citations(&refs_with_dup);
    assert_eq!(
        citations_with_dup.len(),
        2,
        "Intra-peer duplicate file must be collapsed to 1 citation per peer, giving exactly 2 citations (Alice and Bob)"
    );
}

#[tokio::test]
async fn test_adversarial_retrieve_mesh_node_federated_entity_search() {
    let mock_disp = Arc::new(MockMeshDispatcher::default());
    let peer_id = "12D3KooWPeerOmega99999".to_string();

    // Remote peer holds confidential ProjectTitanium specification document
    let remote_chunk = CandidateChunkDto {
        chunk_id: "chunk_titanium_spec_01".to_string(),
        file_path: "remote_shares/ProjectTitanium_Specifications.pdf".to_string(),
        line_start: 1,
        line_end: 15,
        score: 0.94,
        access_tier: 0,
        content: "ProjectTitanium specifications require 99.999% SLA availability and mutual indemnification terms.".to_string(),
    };

    mock_disp
        .add_peer(MockRemotePeer {
            peer_id: peer_id.clone(),
            latency: std::time::Duration::from_millis(1),
            max_access_tier: 0,
            candidate_chunks: vec![remote_chunk],
        })
        .await;

    // Local storage has ZERO documents matching ProjectTitanium
    let storage = Arc::new(EmptyOrCustomStorage {
        local_chunks: Vec::new(),
    });

    reset_mesh_controller(4, true);

    let mut config = CoordinatorConfig::default();
    config.max_peer_responses = 4;

    let engine = ScatterGatherEngine::new(
        storage,
        mock_disp.clone(),
        Arc::new(RwLock::new(PeerAclManager::default())),
        config,
        [0x77; 32],
        "12D3KooWLocalCoordinatorNode".to_string(),
    );

    // Construct AgenticGraphState with extracted entity "ProjectTitanium"
    let mut state = AgenticGraphState::new(
        "What are the terms and specifications of ProjectTitanium?",
        SynthesisModelFamily::Glm4Agentic,
        3,
    );
    state.extracted_entities.push(Extraction::new(
        "named_entity",
        "ProjectTitanium",
    ));

    let dummy_vector = vec![0.0; 768];

    // Execute RetrieveMeshNode
    RetrieveMeshNode::execute(&mut state, &engine, &dummy_vector, 0, 10).await;

    // Verify that entity search dispatched federated query across mesh peers via search_federated_text
    assert!(
        !state.retrieved_chunks.is_empty(),
        "RetrieveMeshNode must retrieve remote peer chunks for extracted entity 'ProjectTitanium'"
    );

    let found_chunk = state
        .retrieved_chunks
        .iter()
        .find(|c| c.chunk.text_content.contains("ProjectTitanium"));

    assert!(
        found_chunk.is_some(),
        "Expected retrieved chunks to contain ProjectTitanium content from remote peer"
    );

    let chunk = found_chunk.unwrap();
    assert_eq!(
        chunk.source_peer, peer_id,
        "Retrieved entity chunk must retain responder peer ID '12D3KooWPeerOmega99999'"
    );
    assert!(
        chunk.is_remote,
        "Retrieved entity chunk must have is_remote == true"
    );
}

#[test]
fn test_adversarial_engine_mode_contract_hash_differentiation() {
    let contract_offline = quorum_contract::EmbeddingContract::canonical_deterministic_offline();
    assert_eq!(contract_offline.engine_mode, "DeterministicOffline");

    let contract_candle = quorum_contract::EmbeddingContract::canonical_gemma_300m();
    assert_eq!(contract_candle.engine_mode, "GemmaCandle");

    let hash_offline = contract_offline.derive_contract_hash();
    let hash_candle = contract_candle.derive_contract_hash();

    assert_ne!(
        hash_offline, hash_candle,
        "BLAKE3 contract hash must strictly differ between DeterministicOffline and GemmaCandle engine modes"
    );

    // Mutated engine mode must also diverge
    let mut contract_mutated = contract_offline.clone();
    contract_mutated.engine_mode = "IncompatibleAdversarialEngine".to_string();
    let hash_mutated = contract_mutated.derive_contract_hash();

    assert_ne!(
        hash_offline, hash_mutated,
        "Mutating engine_mode must produce different contract hash preventing invalid peer handshakes"
    );
}

#[tokio::test]
async fn test_adversarial_max_peer_responses_zero_fallback() {
    let mock_disp = Arc::new(MockMeshDispatcher::default());

    for i in 1..=3 {
        let peer_id = format!("12D3KooWPeerZeroTest{:02}", i);
        let chunk = CandidateChunkDto {
            chunk_id: format!("chunk_z_{}", i),
            file_path: format!("shared/file_z_{}.txt", i),
            line_start: 1,
            line_end: 5,
            score: 0.85,
            access_tier: 0,
            content: format!("Zero fallback content {}", i),
        };
        mock_disp
            .add_peer(MockRemotePeer {
                peer_id,
                latency: std::time::Duration::from_millis(1),
                max_access_tier: 0,
                candidate_chunks: vec![chunk],
            })
            .await;
    }

    // Set max_peer_responses = 0 in both config and settings
    reset_mesh_controller(0, true);
    let mut config = CoordinatorConfig::default();
    config.max_peer_responses = 0;

    let storage = Arc::new(EmptyOrCustomStorage {
        local_chunks: Vec::new(),
    });

    let engine = ScatterGatherEngine::new(
        storage,
        mock_disp.clone(),
        Arc::new(RwLock::new(PeerAclManager::default())),
        config,
        [0x88; 32],
        "12D3KooWZeroCoordinatorNode".to_string(),
    );

    // execute_query should not hang or panic when max_peer_responses == 0
    let (fused, _, _) = engine
        .execute_query("test fallback", &[0.1; 768], 0, 10)
        .await;

    // When max_peer_responses == 0, system falls back to default (e.g. config.max_peer_responses.max(1) or 8)
    assert!(
        !fused.is_empty(),
        "Query with max_peer_responses = 0 should safely fall back to >= 1 peer response without panicking"
    );
}
