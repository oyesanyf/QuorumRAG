//! Milestone M32 Tests: Cross-Engine Embedding Contract Compatibility,
//! Network Timeout & Scatter-Gather Defaults, Guaranteed Federated Peer Diversity Slots,
//! and Multimodal Mesh Parity & Media Preservation.

use chrono::Utc;
use quorum_contract::{
    is_canonical_quorum_contract_hash, is_canonical_quorum_contract_hex,
    verify_federated_contract_handshake_hex, EmbeddingContract,
};
use quorum_coordinator::config::CoordinatorConfig;
use quorum_coordinator::crypto::sign_request;
use quorum_coordinator::dlp_mesh::global_mesh_dlp_controller;
use quorum_coordinator::fusion::RrfCombiner;
use quorum_coordinator::mesh::OsoosiMeshInboundHandler;
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_coordinator::StorageSearcher;
use quorum_network::InboundQueryHandler;
use quorum_types::{AccessTier, CandidateChunkDto, DocumentChunk, FederatedQueryRequest, ScoredChunk};
use std::sync::Arc;
use uuid::Uuid;

struct TestMockStorage {
    image_chunk_id: String,
}

#[async_trait::async_trait]
impl StorageSearcher for TestMockStorage {
    async fn search_hybrid(
        &self,
        query_text: &str,
        query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        assert_eq!(query_vec.len(), 768, "Hybrid search must receive 768-dim query vector");
        let chunk = DocumentChunk::new(
            "doc_hybrid_1",
            "doc_1",
            "C:/Docs/femi_profile.pdf",
            1,
            20,
            0,
            vec![0.1; 768],
            &format!("Professional engineering background for query: {}", query_text),
            None,
        )
        .unwrap();
        vec![ScoredChunk::new(chunk, 0.95, "local", false)]
    }

    async fn search_text(
        &self,
        query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        let q_lower = query.to_ascii_lowercase();
        if q_lower.contains("femi") || q_lower.contains("checkmarx") || q_lower.contains("assets") {
            let img_chunk = DocumentChunk::new(
                &self.image_chunk_id,
                "img_doc_1",
                "C:/Pictures/Checkmarx Social Media Assets - Femi Oyesanya.png",
                1,
                1,
                0,
                vec![0.1; 768],
                "[Image Document: Checkmarx Social Media Assets - Femi Oyesanya.png]\n[OCR Text]: Checkmarx security engineer Femi Oyesanya verified.",
                None,
            )
            .unwrap();
            vec![ScoredChunk::new(img_chunk, 0.90, "local", false)]
        } else {
            Vec::new()
        }
    }
}

/// 1. Verifies that all 3 canonical 768d embedding contracts (DeterministicOffline, GemmaCandle, OllamaEmbedding)
/// interoperate seamlessly during federated handshakes, while foreign arbitrary hashes fail closed.
#[test]
fn test_cross_engine_canonical_contract_handshake() {
    let offline = EmbeddingContract::canonical_deterministic_offline();
    let gemma = EmbeddingContract::canonical_gemma_300m();
    let ollama = EmbeddingContract::canonical_ollama_embeddinggemma();

    let offline_hex = offline.derive_contract_hash_hex();
    let gemma_hex = gemma.derive_contract_hash_hex();
    let ollama_hex = ollama.derive_contract_hash_hex();

    // Verify recognition
    assert!(is_canonical_quorum_contract_hash(&offline.derive_contract_hash()));
    assert!(is_canonical_quorum_contract_hash(&gemma.derive_contract_hash()));
    assert!(is_canonical_quorum_contract_hash(&ollama.derive_contract_hash()));

    assert!(is_canonical_quorum_contract_hex(&offline_hex));
    assert!(is_canonical_quorum_contract_hex(&gemma_hex));
    assert!(is_canonical_quorum_contract_hex(&ollama_hex));

    // Cross-engine pairwise combinations
    assert!(verify_federated_contract_handshake_hex(&offline_hex, &gemma_hex).is_ok());
    assert!(verify_federated_contract_handshake_hex(&gemma_hex, &offline_hex).is_ok());
    assert!(verify_federated_contract_handshake_hex(&offline_hex, &ollama_hex).is_ok());
    assert!(verify_federated_contract_handshake_hex(&ollama_hex, &gemma_hex).is_ok());

    // Foreign hashes fail closed
    let rogue_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    assert!(!is_canonical_quorum_contract_hex(rogue_hex));
    assert!(verify_federated_contract_handshake_hex(&offline_hex, rogue_hex).is_err());
    assert!(verify_federated_contract_handshake_hex(rogue_hex, &gemma_hex).is_err());
}

/// 2. Verifies that default timeout_ms in CoordinatorConfig is 5000ms.
#[test]
fn test_coordinator_config_default_timeout() {
    let config = CoordinatorConfig::default();
    assert_eq!(config.timeout_ms, 5000, "Default timeout_ms must be 5000ms for LAN/WAN reliability");
}

/// 3. Verifies that RrfCombiner guarantees at least min(remote.len(), max(2, top_k / 3)) diversity slots
/// for remote peer chunks when local storage returns many candidate hits, and interleaves them.
#[test]
fn test_rrf_combiner_guaranteed_federated_diversity_slots() {
    // Local storage returns 10 high-scoring chunks
    let mut local_results = Vec::new();
    for i in 1..=10 {
        let chunk = DocumentChunk::new(
            &format!("local_chunk_{}", i),
            &format!("local_doc_{}", i),
            &format!("C:/local/doc_{}.txt", i),
            1,
            10,
            0,
            vec![0.1; 768],
            &format!("Local document content line {}", i),
            None,
        )
        .unwrap();
        // Give high RRF-like scores so without diversity slots, they would occupy all top_k=10 slots
        local_results.push(ScoredChunk::new(chunk, 0.99 - (i as f32 * 0.01), "local", false));
    }

    // Remote peer returns 3 chunks with lower individual scores
    let remote_peer_id = "12D3KooWRemoteHostOmega777".to_string();
    let mut remote_candidates = Vec::new();
    for j in 1..=3 {
        remote_candidates.push(CandidateChunkDto {
            chunk_id: format!("remote_chunk_{}", j),
            file_path: format!("D:/remote/evidence_{}.pdf", j),
            line_start: 1,
            line_end: 15,
            score: 0.50 - (j as f32 * 0.02),
            access_tier: 0,
            content: format!("Vital remote peer intelligence segment {}", j),
            origin_peer_id: None,
        });
    }

    let remote_lists = vec![(remote_peer_id.clone(), remote_candidates)];

    let top_k = 10;
    // Expected diversity slots: min(3, max(2, 10 / 3)) = min(3, 3) = 3
    let fused = RrfCombiner::fuse_rankings_with_peers(local_results, remote_lists, 60.0, top_k);

    assert_eq!(fused.len(), 10, "Fused length must equal top_k");

    let remote_fused: Vec<&ScoredChunk> = fused
        .iter()
        .filter(|c| c.source_peer == remote_peer_id)
        .collect();

    assert_eq!(
        remote_fused.len(),
        3,
        "RrfCombiner must guarantee 3 diversity slots for remote peer chunks instead of local starvation"
    );

    // Verify interleaving: remote chunks must not all be crowded at indices 8 and 9
    let remote_indices: Vec<usize> = fused
        .iter()
        .enumerate()
        .filter(|(_, c)| c.source_peer == remote_peer_id)
        .map(|(i, _)| i)
        .collect();

    assert!(
        remote_indices[0] <= 3,
        "First remote chunk must appear at or before index 3 due to interleaving: got {:?}",
        remote_indices
    );
    assert!(
        remote_indices[1] <= 6,
        "Second remote chunk must appear at or before index 6: got {:?}",
        remote_indices
    );
}

/// 4. Verifies OsoosiMeshInboundHandler re-embeds query locally with local embedder,
/// executes concurrent hybrid and BM25 search, and preserves multimodal chunks.
#[tokio::test]
async fn test_inbound_mesh_handler_reembedding_and_multimodal_parity() {
    let temp = tempfile::tempdir().unwrap();
    let seed = quorum_network::load_or_generate_node_seed(temp.path()).unwrap();
    let secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
    let ed_kp = quorum_network::libp2p::identity::ed25519::Keypair::from(secret);
    let sender_id = quorum_network::libp2p::identity::Keypair::from(ed_kp).public().to_peer_id().to_string();

    let storage = Arc::new(TestMockStorage {
        image_chunk_id: "chunk_img_checkmarx_1".to_string(),
    });

    let offline_embedder = Arc::new(quorum_contract::DeterministicOfflineEngine::new());
    let inbound = OsoosiMeshInboundHandler::new(storage, "12D3KooWReceiverTestNode".to_string())
        .with_embedder(offline_embedder);

    {
        let ctrl = global_mesh_dlp_controller();
        let mut s = ctrl.settings.write().unwrap();
        s.mesh.p2p_enabled = true;
        s.mesh.require_explicit_folder_share = false;
        s.ui.default_peer_access_tier = 0;
    }

    // Sender sends query with all-zero vector (cross-engine / offline mode)
    let mut req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: sender_id,
        sender_pubkey: [0u8; 32],
        query_text: "whi is Femi Oyesanya Checkmarx".to_string(),
        embedding: vec![0.0; 768],
        top_k: 8,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
        origin_peer_id: None,
        relay_hops: 0,
        visited_peers: Vec::new(),
    };
    sign_request(&seed, &mut req, AccessTier::Tier0Public);

    let resp = inbound.handle_query(req).await;
    assert_eq!(resp.responder_peer_id, "12D3KooWReceiverTestNode");
    assert!(!resp.chunks.is_empty(), "Inbound handler must return matching chunks");

    // Must preserve the multimodal image chunk
    let has_image = resp
        .chunks
        .iter()
        .any(|c| c.file_path.contains("Checkmarx Social Media Assets - Femi Oyesanya.png"));
    assert!(has_image, "Inbound mesh handler must preserve matching multimodal image chunks");
}

/// 5. Verifies that offline synthesis engine never prunes multimodal image chunks during weak excerpt pruning.
#[test]
fn test_multimodal_image_chunks_never_pruned() {
    let img_chunk = DocumentChunk::new(
        "img_1",
        "img_doc",
        "D:/Pictures/Checkmarx Social Media Assets - Femi Oyesanya.png",
        1,
        1,
        0,
        vec![0.1; 768],
        "[Image Document: Checkmarx Social Media Assets - Femi Oyesanya.png]\n[OCR Text]: Checkmarx Social Media Assets",
        None,
    )
    .unwrap();

    let text_chunk = DocumentChunk::new(
        "text_1",
        "text_doc",
        "D:/Docs/resume.pdf",
        1,
        50,
        0,
        vec![0.1; 768],
        "Femi Oyesanya is a Lead Application Security Engineer with extensive AppSec experience.",
        None,
    )
    .unwrap();

    let scored_img = ScoredChunk::new(img_chunk, 0.70, "12D3KooWRemoteHost", true);
    let scored_text = ScoredChunk::new(text_chunk, 0.99, "local", false);

    let list = vec![&scored_text, &scored_img];
    let kept = DeterministicOfflineSynthesisEngine::prune_weak_excerpts("who is Femi Oyesanya", &list);

    let has_img = kept.iter().any(|c| c.chunk.file_path.contains(".png"));
    assert!(has_img, "Weak excerpt pruning must never drop multimodal image chunks matching the query");
}
