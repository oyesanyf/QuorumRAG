use quorum_coordinator::fusion::RrfCombiner;
use quorum_coordinator::mesh::{MeshQueryDispatcher, MockRemotePeer};
use quorum_coordinator::scatter_gather::{FederatedQueryCoordinator, ScatterGatherEngine, StorageSearcher};
use quorum_coordinator::agentic::retrieve::RetrieveMeshNode;
use quorum_coordinator::types::{AgenticGraphState, SynthesisModelFamily};
use quorum_coordinator::acl::PeerAclManager;
use quorum_coordinator::config::CoordinatorConfig;
use quorum_types::{
    AccessTier, CandidateChunkDto, DocumentChunk, FederatedQueryRequest, FederatedQueryResponse,
    ScoredChunk,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

// =========================================================================
// Mocks for Empirical Testing
// =========================================================================

#[derive(Default, Clone)]
struct MockStorage {
    chunks: Vec<DocumentChunk>,
    search_hybrid_count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl StorageSearcher for MockStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.search_hybrid_count.fetch_add(1, Ordering::SeqCst);
        let mut results: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier)
            .map(|c| ScoredChunk::new(c.clone(), 0.95, "local", false))
            .collect();
        results.truncate(top_k);
        results
    }

    async fn search_vector(
        &self,
        _vector: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let mut results: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier)
            .map(|c| ScoredChunk::new(c.clone(), 0.95, "local", false))
            .collect();
        results.truncate(top_k);
        results
    }

    async fn search_text(
        &self,
        query: &str,
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let q_lower = query.to_ascii_lowercase();
        let mut results: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier && c.text_content.to_ascii_lowercase().contains(&q_lower))
            .map(|c| ScoredChunk::new(c.clone(), 0.90, "local", false))
            .collect();
        results.truncate(top_k);
        results
    }
}

fn create_sample_chunk(id: &str, file: &str, text: &str, tier: u8, line_start: u32, line_end: u32) -> DocumentChunk {
    DocumentChunk {
        chunk_id: id.to_string(),
        document_id: "doc_test".to_string(),
        file_path: file.to_string(),
        line_start,
        line_end,
        blake3_hash: DocumentChunk::compute_blake3_hash(text),
        access_tier: tier,
        vector: vec![0.05; 768],
        text_content: text.to_string(),
        metadata_json: "{}".to_string(),
    }
}

// Custom dispatcher for injecting exact remote peer responses into ScatterGatherEngine
struct DirectResponseDispatcher {
    responses: Vec<FederatedQueryResponse>,
}

#[async_trait::async_trait]
impl MeshQueryDispatcher for DirectResponseDispatcher {
    async fn query_peers(
        &self,
        _request: &FederatedQueryRequest,
        _timeout: Duration,
    ) -> Result<Vec<FederatedQueryResponse>, quorum_coordinator::error::CoordinatorError> {
        Ok(self.responses.clone())
    }

    fn peer_count(&self) -> usize {
        self.responses.len()
    }
}

// =========================================================================
// 1. Byzantine Quorum Consensus Hardening (fusion.rs)
// =========================================================================

#[test]
fn test_adv_byzantine_sybil_score_stuffing_and_honest_peer_superiority() {
    // Mission 1.1: Simulate a rogue peer submitting the same chunk 100 times at ranks 0..99.
    // Verify that intra-peer deduplication ensures it receives at most a single rank contribution
    // (1 / (60 + 1)) and cannot inflate its score above honest peers.

    let honest_chunk_1 = ScoredChunk::new(
        create_sample_chunk("honest_local_1", "docs/honest.txt", "Consensus verified data across honest nodes", 0, 1, 10),
        0.95,
        "local",
        false,
    );
    let local_results = vec![honest_chunk_1];

    // Rogue peer submits 100 duplicates of the same content at ranks 0..99 under different chunk_ids
    let rogue_text = "Malicious unverified claim injected by rogue peer";
    let mut rogue_candidates = Vec::new();
    for rank in 0..100 {
        rogue_candidates.push(CandidateChunkDto {
            chunk_id: format!("rogue_chunk_{}", rank),
            file_path: format!("rogue/path_{}.txt", rank),
            line_start: rank + 1,
            line_end: rank + 10,
            access_tier: 0,
            score: 0.99 - (rank as f32 * 0.001),
            content: rogue_text.to_string(),
        });
    }

    // Honest peer 2 also corroborates the honest chunk content
    let honest_peer_candidates = vec![CandidateChunkDto {
        chunk_id: "honest_remote_chunk_1".to_string(),
        file_path: "docs/honest_remote.txt".to_string(),
        line_start: 1,
        line_end: 10,
        access_tier: 0,
        score: 0.95,
        content: "Consensus verified data across honest nodes".to_string(),
    }];

    // Fuse rankings: Local + Rogue Peer (peer 1) + Honest Remote Peer (peer 2)
    let fused = RrfCombiner::fuse_rankings(
        local_results,
        vec![rogue_candidates, honest_peer_candidates],
        60.0,
        10,
    );

    // 1. Rogue chunk must appear at most once in fused rankings
    let rogue_matches: Vec<&ScoredChunk> = fused
        .iter()
        .filter(|c| c.chunk.text_content == rogue_text)
        .collect();
    assert_eq!(
        rogue_matches.len(),
        1,
        "Rogue peer 100-duplicate stuffing attack MUST be deduplicated to exactly 1 entry"
    );

    // 2. Score of rogue chunk must be strictly equal to single rank contribution 1 / (60 + 1)
    let expected_single_score = 1.0 / (60.0 + 1.0);
    assert!(
        (rogue_matches[0].score - expected_single_score).abs() < 1e-6,
        "Rogue chunk score must be exactly single rank score 1/(60+1)={}: got {}",
        expected_single_score,
        rogue_matches[0].score
    );

    // 3. Honest chunk (seen by Local and Peer 2) receives multi-peer consensus boost: (1/61 + 1/61) * 1.25 = 2.5 / 61
    let honest_match = fused
        .iter()
        .find(|c| c.chunk.text_content == "Consensus verified data across honest nodes")
        .expect("Honest chunk must be present in fused rankings");

    let expected_honest_score = ((1.0 / 61.0) + (1.0 / 61.0)) * 1.25;
    assert!(
        (honest_match.score - expected_honest_score).abs() < 1e-6,
        "Honest chunk must receive 1.25x multi-peer consensus boost: got {}, expected {}",
        honest_match.score,
        expected_honest_score
    );

    // 4. Honest chunk must outrank rogue chunk and sit at rank #0 despite 100 rogue submissions
    assert_eq!(
        fused[0].chunk.text_content, "Consensus verified data across honest nodes",
        "Honest consensus chunk must be rank #0, defeating rogue 100x inflation attempt"
    );
    assert!(
        fused[0].score > fused[1].score,
        "Honest score ({}) must be strictly higher than rogue score ({})",
        fused[0].score,
        fused[1].score
    );
}

#[test]
fn test_adv_aggregation_key_blake3_hash_anti_malleability() {
    // Mission 1.2: Verify that aggregation key is the cryptographic blake3_hash rather than malleable chunk_id.

    // Scenario A: Collision attack / Chunk ID spoofing
    // Rogue peer uses the EXACT same chunk_id ("chunk_shared_001") as an honest chunk,
    // but provides altered/adversarial content.
    let honest_content = "Critical security patch instructions for node";
    let rogue_content = "Malicious trojan payload masquerading under legitimate ID";

    let local_results = vec![ScoredChunk::new(
        create_sample_chunk("chunk_shared_001", "sec/patch.rs", honest_content, 0, 1, 20),
        0.95,
        "local",
        false,
    )];

    let rogue_peer_list = vec![CandidateChunkDto {
        chunk_id: "chunk_shared_001".to_string(), // Spoofing legitimate chunk_id!
        file_path: "rogue/fake.rs".to_string(),
        line_start: 1,
        line_end: 20,
        access_tier: 0,
        score: 0.95,
        content: rogue_content.to_string(),
    }];

    let fused = RrfCombiner::fuse_rankings(local_results, vec![rogue_peer_list], 60.0, 10);

    // Because aggregation is keyed by blake3_hash, they MUST NOT be merged together into one chunk!
    assert_eq!(
        fused.len(),
        2,
        "Chunks with identical chunk_id but distinct content hashes MUST remain separate"
    );

    let honest_scored = fused.iter().find(|c| c.chunk.text_content == honest_content).unwrap();
    let rogue_scored = fused.iter().find(|c| c.chunk.text_content == rogue_content).unwrap();

    // Neither should receive multi-peer boost
    assert!(
        (honest_scored.score - (1.0 / 61.0)).abs() < 1e-6,
        "Honest chunk should not be boosted by spoofed ID"
    );
    assert!(
        (rogue_scored.score - (1.0 / 61.0)).abs() < 1e-6,
        "Rogue chunk should not be boosted by spoofed ID"
    );
    assert_ne!(honest_scored.chunk.blake3_hash, rogue_scored.chunk.blake3_hash);

    // Scenario B: Legitimate multi-peer consensus across DIFFERENT chunk_ids
    // Peer 1 and Peer 2 have identical content, but completely different ephemeral chunk_ids.
    let consensus_text = "Universal consensus text across all distributed nodes";
    let peer1_list = vec![CandidateChunkDto {
        chunk_id: "peer1_uuid_1111".to_string(),
        file_path: "node1/file.txt".to_string(),
        line_start: 1,
        line_end: 5,
        access_tier: 0,
        score: 0.90,
        content: consensus_text.to_string(),
    }];
    let peer2_list = vec![CandidateChunkDto {
        chunk_id: "peer2_uuid_2222".to_string(), // Different chunk_id!
        file_path: "node2/file.txt".to_string(),
        line_start: 1,
        line_end: 5,
        access_tier: 0,
        score: 0.88,
        content: consensus_text.to_string(),
    }];

    let fused_consensus = RrfCombiner::fuse_rankings(vec![], vec![peer1_list, peer2_list], 60.0, 10);
    assert_eq!(
        fused_consensus.len(),
        1,
        "Identical content across different chunk_ids MUST be merged via blake3_hash"
    );
    let expected_boost = ((1.0 / 61.0) + (1.0 / 61.0)) * 1.25;
    assert!(
        (fused_consensus[0].score - expected_boost).abs() < 1e-6,
        "Merged chunk must receive 1.25x consensus multiplier"
    );
}

#[test]
fn test_adv_independent_honest_peers_accumulate_consensus_boost() {
    // Mission 1.3: Verify that independent honest peers correctly accumulate consensus score boosts.
    let shared_content = "Cryptographic ledger confirmation state";

    let peer1 = vec![CandidateChunkDto {
        chunk_id: "c1".to_string(),
        file_path: "node1/ledger.rs".to_string(),
        line_start: 10,
        line_end: 20,
        access_tier: 0,
        score: 0.9,
        content: shared_content.to_string(),
    }];

    let peer2 = vec![CandidateChunkDto {
        chunk_id: "c2".to_string(),
        file_path: "node2/ledger.rs".to_string(),
        line_start: 10,
        line_end: 20,
        access_tier: 0,
        score: 0.9,
        content: shared_content.to_string(),
    }];

    let peer3 = vec![CandidateChunkDto {
        chunk_id: "c3".to_string(),
        file_path: "node3/ledger.rs".to_string(),
        line_start: 10,
        line_end: 20,
        access_tier: 0,
        score: 0.9,
        content: shared_content.to_string(),
    }];

    let fused = RrfCombiner::fuse_rankings(vec![], vec![peer1, peer2, peer3], 60.0, 10);
    assert_eq!(fused.len(), 1);

    // 3 peers contributing at rank 0: (1/61 + 1/61 + 1/61) * 1.25
    let expected = (3.0 / 61.0) * 1.25;
    assert!(
        (fused[0].score - expected).abs() < 1e-6,
        "3 independent peers must accumulate score: expected {}, got {}",
        expected,
        fused[0].score
    );
}

// =========================================================================
// 2. Remote Chunk Isolation & Access Tier Clamping (scatter_gather.rs)
// =========================================================================

#[tokio::test]
async fn test_adv_remote_chunk_access_tier_clamping_to_requested() {
    // Mission 2.1: Submit remote chunks with access_tier = 5 when requested_tier = 1.
    // Verify that tier is clamped to 1.

    let storage = Arc::new(MockStorage::default());
    let (seed, _pubkey, peer_id) = (
        [9u8; 32],
        [0u8; 32],
        "local_coordinator_peer".to_string(),
    );

    // Configure a dispatcher returning remote chunks with excessive access_tier = 5 and public 0
    let remote_response = FederatedQueryResponse {
        query_id: uuid::Uuid::new_v4(),
        responder_peer_id: "remote_node_1".to_string(),
        chunks: vec![
            CandidateChunkDto {
                chunk_id: "chunk_priv_5".to_string(),
                file_path: "confidential/internal.txt".to_string(),
                line_start: 1,
                line_end: 10,
                access_tier: 5, // Excessive tier!
                score: 0.99,
                content: "Confidential document text requiring tier 5".to_string(),
            },
            CandidateChunkDto {
                chunk_id: "chunk_pub_0".to_string(),
                file_path: "public/readme.txt".to_string(),
                line_start: 1,
                line_end: 10,
                access_tier: 0, // Lower tier
                score: 0.85,
                content: "Public document text accessible to all".to_string(),
            },
        ],
    };

    let dispatcher = Arc::new(DirectResponseDispatcher {
        responses: vec![remote_response],
    });

    let config = CoordinatorConfig::default();
    let acl_mgr = Arc::new(RwLock::new(PeerAclManager::new(AccessTier::Tier1Internal)));

    let engine = ScatterGatherEngine::new(
        storage.clone(),
        dispatcher,
        acl_mgr,
        config,
        seed,
        peer_id,
    );

    // Request query with access_tier = 1
    let requested_tier = 1u8;
    let (fused, volatile, _duration) = engine
        .execute_query("test query", &[0.05; 768], requested_tier, 10)
        .await;

    // Verify in volatile chunks
    assert_eq!(volatile.len(), 2, "Both chunks should be ingested into volatile memory");
    let priv_chunk = volatile.iter().find(|c| c.chunk_id == "chunk_priv_5").unwrap();
    assert_eq!(
        priv_chunk.access_tier, 1,
        "Remote chunk with access_tier 5 MUST be clamped to requested_tier 1 in VolatileRemoteChunk"
    );

    let pub_chunk = volatile.iter().find(|c| c.chunk_id == "chunk_pub_0").unwrap();
    assert_eq!(
        pub_chunk.access_tier, 0,
        "Remote chunk with lower access_tier 0 must retain its lower tier 0"
    );

    // Verify in fused ScoredChunks
    let fused_priv = fused.iter().find(|c| c.chunk.chunk_id == "chunk_priv_5").unwrap();
    assert_eq!(
        fused_priv.chunk.access_tier, 1,
        "Remote chunk in fused ScoredChunk MUST be clamped to requested_tier 1"
    );
}

#[tokio::test]
async fn test_adv_remote_chunk_inverted_lines_rejected() {
    // Mission 2.2: Submit inverted lines (line_start = 50, line_end = 10).
    // Verify that chunk is rejected.

    let storage = Arc::new(MockStorage::default());
    let (seed, _pubkey, peer_id) = (
        [9u8; 32],
        [0u8; 32],
        "local_coordinator_peer".to_string(),
    );

    let remote_response = FederatedQueryResponse {
        query_id: uuid::Uuid::new_v4(),
        responder_peer_id: "remote_malicious_peer".to_string(),
        chunks: vec![
            CandidateChunkDto {
                chunk_id: "malformed_inverted_50_10".to_string(),
                file_path: "bad/inverted.txt".to_string(),
                line_start: 50, // Inverted! 50 > 10
                line_end: 10,
                access_tier: 0,
                score: 0.99,
                content: "Malformed chunk with inverted line range".to_string(),
            },
            CandidateChunkDto {
                chunk_id: "malformed_inverted_100_1".to_string(),
                file_path: "bad/inverted2.txt".to_string(),
                line_start: 100, // Inverted! 100 > 1
                line_end: 1,
                access_tier: 0,
                score: 0.98,
                content: "Malformed chunk 2 with inverted line range".to_string(),
            },
            CandidateChunkDto {
                chunk_id: "valid_chunk_10_50".to_string(),
                file_path: "good/valid.txt".to_string(),
                line_start: 10, // Valid! 10 <= 50
                line_end: 50,
                access_tier: 0,
                score: 0.85,
                content: "Valid chunk with proper line ranges".to_string(),
            },
        ],
    };

    let dispatcher = Arc::new(DirectResponseDispatcher {
        responses: vec![remote_response],
    });

    let config = CoordinatorConfig::default();
    let acl_mgr = Arc::new(RwLock::new(PeerAclManager::new(AccessTier::Tier0Public)));

    let engine = ScatterGatherEngine::new(
        storage.clone(),
        dispatcher,
        acl_mgr,
        config,
        seed,
        peer_id,
    );

    let (fused, volatile, _duration) = engine
        .execute_query("test", &[0.05; 768], 0, 10)
        .await;

    // Both inverted chunks must be rejected, only valid chunk survives
    assert_eq!(
        volatile.len(),
        1,
        "Only valid chunk must be retained in volatile memory; inverted chunks MUST be dropped"
    );
    assert_eq!(volatile[0].chunk_id, "valid_chunk_10_50");

    assert_eq!(
        fused.len(),
        1,
        "Only valid chunk must be retained in fused rankings; inverted chunks MUST be dropped"
    );
    assert_eq!(fused[0].chunk.chunk_id, "valid_chunk_10_50");

    // Also verify in FederatedQueryCoordinator
    let mut fed_coord = FederatedQueryCoordinator::new(storage);
    fed_coord.add_peer(MockRemotePeer {
        peer_id: "fed_peer".to_string(),
        latency: Duration::from_millis(5),
        max_access_tier: 10,
        candidate_chunks: vec![
            CandidateChunkDto {
                chunk_id: "bad_chunk".to_string(),
                file_path: "bad.txt".to_string(),
                line_start: 50,
                line_end: 10,
                access_tier: 0,
                score: 0.99,
                content: "Bad chunk".to_string(),
            },
            CandidateChunkDto {
                chunk_id: "good_chunk".to_string(),
                file_path: "good.txt".to_string(),
                line_start: 1,
                line_end: 1,
                access_tier: 0,
                score: 0.80,
                content: "Good chunk".to_string(),
            },
        ],
    });

    let (fed_fused, fed_vol, _) = fed_coord.execute_query("query", &[0.05; 768], 0, 10).await;
    assert_eq!(fed_vol.len(), 1);
    assert_eq!(fed_vol[0].chunk_id, "good_chunk");
    assert_eq!(fed_fused.len(), 1);
    assert_eq!(fed_fused[0].chunk.chunk_id, "good_chunk");
}

// =========================================================================
// 3. Multi-Term Entity Matching Precision (retrieve.rs)
// =========================================================================

#[tokio::test]
async fn test_adv_multi_term_entity_matching_precision() {
    // Mission 3: Test multi-word queries like "what is universal mineral income"
    // against documents containing only "income" or "mineral" in isolation.
    // Verify that chunks matching fewer than (len + 1) / 2 distinct terms are marked is_relevant = false.

    let chunk_income_only = create_sample_chunk(
        "doc_income_only",
        "taxes/Statement_2023.pdf",
        "Annual statement of gross income and tax deductions for the fiscal year.",
        0,
        1,
        10,
    );

    let chunk_mineral_only = create_sample_chunk(
        "doc_mineral_only",
        "geology/Survey_Nevada.pdf",
        "Geological survey mapping mineral deposits, copper ores, and quartz veins.",
        0,
        1,
        10,
    );

    let chunk_universal_only = create_sample_chunk(
        "doc_universal_only",
        "philosophy/Human_Rights.pdf",
        "The doctrine of universal human dignity is foundational to modern law.",
        0,
        1,
        10,
    );

    let chunk_mineral_income_two_terms = create_sample_chunk(
        "doc_two_terms",
        "economics/Alaska_Fund.pdf",
        "The state dividend provides mineral income disbursements from oil extraction royalties.",
        0,
        1,
        10,
    );

    let chunk_all_three_terms = create_sample_chunk(
        "doc_all_three",
        "policy/Universal_Mineral_Policy.pdf",
        "Establishing a universal mineral income dividend policy for regional natural resources.",
        0,
        1,
        10,
    );

    let storage = Arc::new(MockStorage {
        chunks: vec![
            chunk_income_only,
            chunk_mineral_only,
            chunk_universal_only,
            chunk_mineral_income_two_terms,
            chunk_all_three_terms,
        ],
        search_hybrid_count: Arc::new(AtomicUsize::new(0)),
    });

    let config = CoordinatorConfig::default();
    let acl_mgr = Arc::new(RwLock::new(PeerAclManager::new(AccessTier::Tier0Public)));
    let engine = ScatterGatherEngine::new(
        storage.clone(),
        Arc::new(quorum_coordinator::mesh::LocalOnlyDispatcher),
        acl_mgr,
        config,
        [0u8; 32],
        "local_node".to_string(),
    );

    // Query with 3 terms: "what is universal mineral income"
    // query_terms = ["universal", "mineral", "income"] -> len = 3
    // Threshold (len + 1) / 2 = 2 distinct terms
    let mut state = AgenticGraphState::new(
        "what is universal mineral income",
        SynthesisModelFamily::Glm4Agentic,
        3,
    );

    RetrieveMeshNode::execute(&mut state, &engine, &[0.05; 768], 0, 10).await;

    // Chunks matching fewer than (len + 1) / 2 = 2 distinct terms MUST be filtered out!
    let retrieved_ids: Vec<&str> = state
        .retrieved_chunks
        .iter()
        .map(|c| c.chunk.chunk_id.as_str())
        .collect();

    println!("Retrieved chunk IDs: {:?}", retrieved_ids);

    // 1. "income" in isolation MUST be rejected (is_relevant = false)
    assert!(
        !retrieved_ids.contains(&"doc_income_only"),
        "Document containing ONLY generic 'income' in isolation MUST be filtered out (is_relevant = false)"
    );

    // 2. "mineral" in isolation MUST be rejected (is_relevant = false)
    assert!(
        !retrieved_ids.contains(&"doc_mineral_only"),
        "Document containing ONLY 'mineral' in isolation (1 term < 2 threshold) MUST be filtered out (is_relevant = false)"
    );

    // 3. "universal" in isolation MUST be rejected (is_relevant = false)
    assert!(
        !retrieved_ids.contains(&"doc_universal_only"),
        "Document containing ONLY 'universal' in isolation MUST be filtered out (is_relevant = false)"
    );

    // 4. Two-term match ("mineral income") matches 2 terms >= 2 -> MUST be retained
    assert!(
        retrieved_ids.contains(&"doc_two_terms"),
        "Document matching 2 distinct terms ('mineral' and 'income') MUST be retained"
    );

    // 5. Three-term match ("universal mineral income") matches 3 terms >= 2 -> MUST be retained
    assert!(
        retrieved_ids.contains(&"doc_all_three"),
        "Document matching all 3 terms MUST be retained"
    );
}
