use chrono::Utc;
use quorum_coordinator::crypto::sign_request;
use quorum_coordinator::dlp_mesh::global_mesh_dlp_controller;
use quorum_coordinator::fusion::RrfCombiner;
use quorum_coordinator::mesh::{MockMeshDispatcher, MockRemotePeer, OsoosiMeshInboundHandler};
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_coordinator::{CoordinatorConfig, PeerAclManager, ScatterGatherEngine, StorageSearcher};
use quorum_network::InboundQueryHandler;
use quorum_types::{AccessTier, CandidateChunkDto, DocumentChunk, FederatedQueryRequest, ScoredChunk};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

struct DummyStorage;

#[async_trait::async_trait]
impl StorageSearcher for DummyStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        Vec::new()
    }

    async fn search_text(
        &self,
        query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        if query.contains("LocalOnly") {
            let doc = DocumentChunk::new(
                "local_c1",
                "local_doc",
                "C:/workspace/local_contract.pdf",
                1,
                10,
                0,
                vec![0.1; 768],
                "Local contract excerpt for evaluation.",
                None,
            ).unwrap();
            vec![ScoredChunk::new(doc, 0.92, "local", false)]
        } else {
            Vec::new()
        }
    }
}

#[test]
fn test_peer_and_filename_disambiguation() {
    let peer_a = "12D3KooWPeerAAAAAAA11111".to_string();
    let peer_b = "12D3KooWPeerBBBBBBB22222".to_string();

    let local_chunk = DocumentChunk::new(
        "loc_01",
        "doc_loc",
        "C:/Shared/contract.pdf",
        1,
        20,
        0,
        vec![0.1; 768],
        "Local terms and conditions agreement.",
        None,
    ).unwrap();
    let local = vec![ScoredChunk::new(local_chunk, 0.95, "local", false)];

    let chunk_a = CandidateChunkDto {
        chunk_id: "peer_a_01".to_string(),
        file_path: "D:/Data/contract.pdf".to_string(),
        line_start: 1,
        line_end: 25,
        score: 0.90,
        access_tier: 0,
        content: "Peer A exclusive addendum to agreement.".to_string(),
    };

    let chunk_b = CandidateChunkDto {
        chunk_id: "peer_b_01".to_string(),
        file_path: "/var/reports/contract.pdf".to_string(),
        line_start: 1,
        line_end: 30,
        score: 0.88,
        access_tier: 0,
        content: "Peer B specialized commercial riders.".to_string(),
    };

    let remote_lists = vec![
        (peer_a.clone(), vec![chunk_a]),
        (peer_b.clone(), vec![chunk_b]),
    ];

    let fused = RrfCombiner::fuse_rankings_with_peers(local, remote_lists, 60.0, 10);
    assert_eq!(fused.len(), 3);

    // Verify source_peer is preserved
    let peers: Vec<String> = fused.iter().map(|c| c.source_peer.clone()).collect();
    assert!(peers.contains(&"local".to_string()));
    assert!(peers.contains(&peer_a));
    assert!(peers.contains(&peer_b));

    // Verify citation deduplication retains both peer files and local file
    let refs: Vec<&ScoredChunk> = fused.iter().collect();
    let citations = DeterministicOfflineSynthesisEngine::build_deduplicated_citations(&refs);
    assert_eq!(citations.len(), 3, "Same-named files from different peers must not be deduplicated away");

    // Verify sources block shows peer attribution for remote peers
    let sources_block = DeterministicOfflineSynthesisEngine::format_sources_block(&refs);
    assert!(sources_block.contains("(Peer: 12D3KooW)"));
}

#[tokio::test]
async fn test_max_peer_responses_capping() {
    let mock_disp = Arc::new(MockMeshDispatcher::default());

    for i in 1..=4 {
        let peer_id = format!("12D3KooWPeer{:04}", i);
        let chunk = CandidateChunkDto {
            chunk_id: format!("chunk_p{}", i),
            file_path: format!("file_p{}.txt", i),
            line_start: 1,
            line_end: 5,
            score: 0.85,
            access_tier: 0,
            content: format!("Content from peer {}", i),
        };
        mock_disp.add_peer(MockRemotePeer {
            peer_id,
            latency: std::time::Duration::from_millis(1),
            max_access_tier: 0,
            candidate_chunks: vec![chunk],
        }).await;
    }

    // Configure max_peer_responses = 2
    let mut config = CoordinatorConfig::default();
    config.max_peer_responses = 2;

    {
        let ctrl = global_mesh_dlp_controller();
        let mut s = ctrl.settings.write().unwrap();
        s.mesh.p2p_enabled = true;
        s.mesh.max_peer_responses = 2;
    }

    let storage = Arc::new(DummyStorage);
    let engine = ScatterGatherEngine::new(
        storage,
        mock_disp.clone(),
        Arc::new(RwLock::new(PeerAclManager::default())),
        config,
        [0x42; 32],
        "12D3KooWLocalTestNode".to_string(),
    );

    let (fused, _volatile, _) = engine
        .execute_query("test query", &[0.1; 768], 0, 10)
        .await;

    // With 4 peers responding and max_peer_responses = 2, exactly 2 remote chunks must be fused
    assert_eq!(fused.len(), 2, "Expected exactly 2 peer responses to be fused when max_peer_responses = 2");

    // Reconfigure to 1
    {
        let ctrl = global_mesh_dlp_controller();
        let mut s = ctrl.settings.write().unwrap();
        s.mesh.max_peer_responses = 1;
    }

    let (fused_1, _, _) = engine
        .execute_query("test query", &[0.1; 768], 0, 10)
        .await;
    assert_eq!(fused_1.len(), 1, "Expected exactly 1 peer response to be fused when max_peer_responses = 1");
}

#[tokio::test]
async fn test_persistent_peer_id_spoofing_gate() {
    let temp = tempfile::tempdir().unwrap();
    let seed = quorum_network::load_or_generate_node_seed(temp.path()).unwrap();

    let secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
    let ed_kp = quorum_network::libp2p::identity::ed25519::Keypair::from(secret);
    let valid_peer_id = quorum_network::libp2p::identity::Keypair::from(ed_kp).public().to_peer_id().to_string();

    let storage = Arc::new(DummyStorage);
    let inbound = OsoosiMeshInboundHandler::new(storage, "12D3KooWReceiverNode".to_string());

    // 1. Legitimate query with matching sender_peer_id
    let mut req_valid = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: valid_peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "test".to_string(),
        embedding: vec![0.0; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut req_valid, AccessTier::Tier0Public);

    let resp_valid = inbound.handle_query(req_valid).await;
    assert_eq!(resp_valid.responder_peer_id, "12D3KooWReceiverNode");

    // 2. Spoofed query with mismatched sender_peer_id (e.g. old "local_daemon" hardcode)
    let mut req_spoofed = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: "local_daemon".to_string(),
        sender_pubkey: [0u8; 32],
        query_text: "test".to_string(),
        embedding: vec![0.0; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut req_spoofed, AccessTier::Tier0Public);

    let resp_spoofed = inbound.handle_query(req_spoofed).await;
    // Inbound handler rejects spoofed query and returns empty chunks with blank responder_peer_id
    assert!(resp_spoofed.chunks.is_empty());
}
