use chrono::Utc;
use quorum_coordinator::crypto::sign_request;
use quorum_coordinator::fusion::RrfCombiner;
use quorum_coordinator::mesh::OsoosiMeshInboundHandler;
use quorum_coordinator::scatter_gather::{ScatterGatherEngine, StorageSearcher};
use quorum_coordinator::types::{AgenticGraphState, SynthesisModelFamily};
use quorum_network::{derive_peer_id_from_pubkey, is_allowed_dial_address, Multiaddr};
use quorum_types::{AccessTier, CandidateChunkDto, DocumentChunk, FederatedQueryRequest, ScoredChunk};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Mock storage searcher tracking calls to search_vector and search_text
struct MockTrackingStorage {
    vector_search_count: AtomicUsize,
    text_search_count: AtomicUsize,
    sample_chunk: ScoredChunk,
}

impl MockTrackingStorage {
    fn new(sample_chunk: ScoredChunk) -> Self {
        Self {
            vector_search_count: AtomicUsize::new(0),
            text_search_count: AtomicUsize::new(0),
            sample_chunk,
        }
    }
}

#[async_trait::async_trait]
impl StorageSearcher for MockTrackingStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.vector_search_count.fetch_add(1, Ordering::SeqCst);
        self.text_search_count.fetch_add(1, Ordering::SeqCst);
        vec![self.sample_chunk.clone()]
    }

    async fn search_vector(
        &self,
        _vector: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.vector_search_count.fetch_add(1, Ordering::SeqCst);
        vec![self.sample_chunk.clone()]
    }

    async fn search_text(
        &self,
        _query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.text_search_count.fetch_add(1, Ordering::SeqCst);
        vec![self.sample_chunk.clone()]
    }
}

fn sample_chunk(id: &str, text: &str) -> ScoredChunk {
    let doc = DocumentChunk {
        chunk_id: id.to_string(),
        document_id: "doc1".to_string(),
        file_path: r"D:\harfile\QuorumRAG\docs\test.txt".to_string(),
        line_start: 1,
        line_end: 10,
        blake3_hash: DocumentChunk::compute_blake3_hash(text),
        access_tier: 0,
        vector: vec![0.1; 768],
        text_content: text.to_string(),
        metadata_json: "{}".to_string(),
    };
    ScoredChunk::new(doc, 0.95, "local", false)
}

#[test]
fn test_byzantine_consensus_anti_stuffing() {
    // Feature 50: A single remote peer cannot inflate scores by returning duplicate chunks
    let local = vec![sample_chunk("local_1", "unique local text")];

    let stuffed_candidate = CandidateChunkDto {
        chunk_id: "chunk_A".to_string(),
        file_path: "remote/file.txt".to_string(),
        line_start: 1,
        line_end: 5,
        access_tier: 0,
        score: 0.9,
        content: "malicious duplicated payload".to_string(),
    };

    // Peer 1 sends identical content 5 times under different or identical chunk IDs
    let remote_peer_stuffed = vec![
        stuffed_candidate.clone(),
        CandidateChunkDto {
            chunk_id: "chunk_B".to_string(),
            ..stuffed_candidate.clone()
        },
        CandidateChunkDto {
            chunk_id: "chunk_C".to_string(),
            ..stuffed_candidate.clone()
        },
    ];

    let fused = RrfCombiner::fuse_rankings(local, vec![remote_peer_stuffed], 60.0, 10);

    // The remote chunk must appear at most once in fused rankings
    let duplicate_count = fused
        .iter()
        .filter(|c| c.chunk.text_content == "malicious duplicated payload")
        .count();
    assert_eq!(
        duplicate_count, 1,
        "Peer duplicate chunk stuffing must be deduplicated to exactly 1"
    );

    // Score must be base score 1 / (60 + 1) without multi-peer boost
    let stuffed_result = fused
        .iter()
        .find(|c| c.chunk.text_content == "malicious duplicated payload")
        .unwrap();
    let expected_single_score = 1.0 / 61.0;
    assert!(
        (stuffed_result.score - expected_single_score).abs() < 1e-5,
        "Single peer with duplicate chunks must only receive single rank score: got {}, expected {}",
        stuffed_result.score,
        expected_single_score
    );
}

#[test]
fn test_multi_peer_consensus_boost() {
    // Feature 50: Two distinct peers returning matching content receive 1.25x consensus multiplier
    let content = "consensual agreement text across nodes";
    let chunk_hash = DocumentChunk::compute_blake3_hash(content);

    let local = vec![];
    let peer1 = vec![CandidateChunkDto {
        chunk_id: "peer1_chunk".to_string(),
        file_path: "node1/a.txt".to_string(),
        line_start: 1,
        line_end: 10,
        access_tier: 0,
        score: 0.9,
        content: content.to_string(),
    }];

    let peer2 = vec![CandidateChunkDto {
        chunk_id: "peer2_chunk".to_string(),
        file_path: "node2/b.txt".to_string(),
        line_start: 10,
        line_end: 20,
        access_tier: 0,
        score: 0.88,
        content: content.to_string(),
    }];

    let fused = RrfCombiner::fuse_rankings(local, vec![peer1, peer2], 60.0, 10);
    assert_eq!(fused.len(), 1);

    let base_combined_score = (1.0 / 61.0) + (1.0 / 61.0);
    let expected_boosted = base_combined_score * 1.25;
    assert_eq!(fused[0].chunk.blake3_hash, chunk_hash);
    assert!(
        (fused[0].score - expected_boosted).abs() < 1e-5,
        "Multi-peer consensus boost must be 1.25x: got {}, expected {}",
        fused[0].score,
        expected_boosted
    );
}

#[test]
fn test_air_gapped_dial_address_restrictions() {
    // Feature 51: Air-gapped network dialect validation
    let loopback_v4 = Multiaddr::from_str("/ip4/127.0.0.1/tcp/9000").unwrap();
    let rfc1918_10 = Multiaddr::from_str("/ip4/10.1.2.3/tcp/9000").unwrap();
    let rfc1918_172 = Multiaddr::from_str("/ip4/172.16.5.4/tcp/9000").unwrap();
    let rfc1918_192 = Multiaddr::from_str("/ip4/192.168.1.100/tcp/9000").unwrap();
    let loopback_v6 = Multiaddr::from_str("/ip6/::1/tcp/9000").unwrap();
    let ula_v6 = Multiaddr::from_str("/ip6/fd00::1/tcp/9000").unwrap();
    let localhost_dns = Multiaddr::from_str("/dns4/localhost/tcp/9000").unwrap();

    assert!(is_allowed_dial_address(&loopback_v4));
    assert!(is_allowed_dial_address(&rfc1918_10));
    assert!(is_allowed_dial_address(&rfc1918_172));
    assert!(is_allowed_dial_address(&rfc1918_192));
    assert!(is_allowed_dial_address(&loopback_v6));
    assert!(is_allowed_dial_address(&ula_v6));
    assert!(is_allowed_dial_address(&localhost_dns));

    // Public WAN addresses must be blocked
    let public_v4 = Multiaddr::from_str("/ip4/8.8.8.8/tcp/9000").unwrap();
    let cloudflare_v4 = Multiaddr::from_str("/ip4/1.1.1.1/tcp/9000").unwrap();
    let public_dns = Multiaddr::from_str("/dns4/google.com/tcp/9000").unwrap();

    assert!(!is_allowed_dial_address(&public_v4));
    assert!(!is_allowed_dial_address(&cloudflare_v4));
    assert!(!is_allowed_dial_address(&public_dns));
}

#[tokio::test]
async fn test_p2p_cryptographic_handshake_and_replay_rejection() {
    use quorum_network::InboundQueryHandler;

    let chunk = sample_chunk("c1", "secret local data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));
    let seed = [7u8; 32];

    let secret_key = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
    let keypair = quorum_network::libp2p::identity::ed25519::Keypair::from(secret_key);
    let public_key = quorum_network::libp2p::identity::PublicKey::from(keypair.public());
    let peer_id = quorum_network::libp2p::PeerId::from_public_key(&public_key).to_string();

    let handler = OsoosiMeshInboundHandler::new(storage, &peer_id);

    // 1. Valid authentic request
    let mut valid_req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "valid query".to_string(),
        embedding: vec![0.05; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut valid_req, AccessTier::Tier0Public);

    let resp = handler.handle_query(valid_req).await;
    assert!(
        !resp.chunks.is_empty(),
        "Valid signed query should return chunks"
    );

    // 2. Stale timestamp (>60 seconds) must be rejected
    let mut stale_req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "stale replay query".to_string(),
        embedding: vec![0.05; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp() - 120, // 2 minutes ago
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut stale_req, AccessTier::Tier0Public);

    let resp_stale = handler.handle_query(stale_req).await;
    assert!(
        resp_stale.chunks.is_empty(),
        "Stale query (>60s drift) must be rejected"
    );

    // 3. Spoofed peer ID (sender_pubkey derives to peer A, but sender_peer_id claims peer B)
    let mut spoofed_req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: "12D3KooWSpoofedPeerIdNotMatchingKey".to_string(),
        sender_pubkey: [0u8; 32],
        query_text: "spoof query".to_string(),
        embedding: vec![0.05; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut spoofed_req, AccessTier::Tier0Public);

    let resp_spoofed = handler.handle_query(spoofed_req).await;
    assert!(
        resp_spoofed.chunks.is_empty(),
        "Spoofed sender_peer_id mismatching pubkey derivation must be rejected"
    );

    // 4. Malformed payload: invalid embedding length != 768
    let mut malformed_emb_req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "malformed embedding query".to_string(),
        embedding: vec![0.05; 128], // Invalid: must be 768
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut malformed_emb_req, AccessTier::Tier0Public);

    let resp_emb = handler.handle_query(malformed_emb_req).await;
    assert!(
        resp_emb.chunks.is_empty(),
        "Malformed embedding dimension must be rejected"
    );

    // 5. Malformed payload: NaN float in embedding
    let mut nan_emb = vec![0.05; 768];
    nan_emb[10] = f32::NAN;
    let mut nan_req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "nan embedding query".to_string(),
        embedding: nan_emb,
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut nan_req, AccessTier::Tier0Public);

    let resp_nan = handler.handle_query(nan_req).await;
    assert!(
        resp_nan.chunks.is_empty(),
        "Non-finite floats in embedding must be rejected"
    );
}

#[tokio::test]
async fn test_rewrite_hop_vector_cache_bypass() {
    // Feature 48: When rewrite hops occur with the same query vector, avoid redundant LanceDB searches
    let chunk = sample_chunk("c1", "some content");
    let tracking_storage = Arc::new(MockTrackingStorage::new(chunk));

    let engine = ScatterGatherEngine::new(
        tracking_storage.clone(),
        Arc::new(quorum_coordinator::mesh::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(
            quorum_coordinator::acl::PeerAclManager::new(AccessTier::Tier0Public),
        )),
        quorum_coordinator::config::CoordinatorConfig::default(),
        [1u8; 32],
        "local_node".to_string(),
    );

    let mut state = AgenticGraphState::new(
        "query with coreference",
        SynthesisModelFamily::Glm4Agentic,
        3,
    );

    let query_vector = vec![0.02f32; 768];

    // Hop 0: initial retrieval (populates cached_vector_hits)
    state.hop_count = 0;
    quorum_coordinator::agentic::RetrieveMeshNode::execute(
        &mut state,
        &engine,
        &query_vector,
        0,
        10,
    )
    .await;

    assert_eq!(tracking_storage.vector_search_count.load(Ordering::SeqCst), 1);
    assert!(!state.cached_vector_hits.is_empty());

    // Hop 1: rewrite hop with same query vector
    state.hop_count = 1;
    state.current_query = "rewritten disambiguated query".to_string();

    quorum_coordinator::agentic::RetrieveMeshNode::execute(
        &mut state,
        &engine,
        &query_vector,
        0,
        10,
    )
    .await;

    // Vector search count must STILL be 1 because cached vector hits were reused!
    assert_eq!(
        tracking_storage.vector_search_count.load(Ordering::SeqCst),
        1,
        "Rewrite hop must bypass redundant vector search and reuse cached vector hits"
    );
    // But text search was executed for the new rewritten query!
    assert_eq!(tracking_storage.text_search_count.load(Ordering::SeqCst), 2);
}

#[test]
fn test_pubkey_to_peer_id_derivation() {
    // Feature 49: Deriving libp2p PeerId from 32-byte Ed25519 public key
    let seed = [42u8; 32];
    let secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
    let ed_kp = quorum_network::libp2p::identity::ed25519::Keypair::from(secret);
    let expected_peer_id = quorum_network::libp2p::identity::PublicKey::from(ed_kp.public()).to_peer_id();

    let derived = derive_peer_id_from_pubkey(&ed_kp.public().to_bytes()).unwrap();
    assert_eq!(derived, expected_peer_id);
}
