use chrono::Utc;
use quorum_coordinator::{
    extract_query_metadata_filters, filter_grounded, ground_extraction, oracle_sign_query,
    oracle_verify_query, ExampleData, Extraction, FederatedQueryCoordinator, LlmFusionConsensus,
    MockRemotePeer, PeerAclManager, RrfCombiner, StorageSearcher,
};
use quorum_types::{AccessTier, CandidateChunkDto, DocumentChunk, ScoredChunk};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Default, Clone)]
struct MockLocalStorage {
    chunks: Vec<DocumentChunk>,
}

#[async_trait::async_trait]
impl StorageSearcher for MockLocalStorage {
    async fn search_hybrid(
        &self,
        query_text: &str,
        _query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let mut matches: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier && c.text_content.contains(query_text))
            .map(|c| ScoredChunk::new(c.clone(), 0.9, "local", false))
            .collect();
        matches.truncate(top_k);
        matches
    }
}

#[test]
fn test_crypto_signing_and_verification() {
    let seed = [0x42u8; 32];
    let query_id = Uuid::new_v4();
    let sender_id = "peer_alice_123";
    let timestamp = Utc::now().timestamp();
    let access_tier = AccessTier::Tier0Public;
    let top_k = 10;
    let embedding = vec![0.5f32; 768];
    let query_text = "What is the consensus contract for Gemma embeddings?";

    let (pubkey, sig_bytes) = oracle_sign_query(
        &seed,
        query_id,
        sender_id,
        timestamp,
        access_tier,
        top_k,
        &embedding,
        query_text,
    );
    let verify_result = oracle_verify_query(
        &pubkey,
        &sig_bytes,
        query_id,
        sender_id,
        timestamp,
        access_tier,
        top_k,
        &embedding,
        query_text,
        60,
    );
    assert!(verify_result.is_ok(), "Authentic signature must verify");

    // Tampered access_tier must fail
    let tampered_tier = oracle_verify_query(
        &pubkey,
        &sig_bytes,
        query_id,
        sender_id,
        timestamp,
        AccessTier::Tier2Confidential,
        top_k,
        &embedding,
        query_text,
        60,
    );
    assert!(tampered_tier.is_err(), "Tampered access tier must fail verification");

    // Tampered embedding must fail
    let mut tampered_emb = embedding.clone();
    tampered_emb[0] += 0.1;
    let tampered_emb_res = oracle_verify_query(
        &pubkey,
        &sig_bytes,
        query_id,
        sender_id,
        timestamp,
        access_tier,
        top_k,
        &tampered_emb,
        query_text,
        60,
    );
    assert!(tampered_emb_res.is_err(), "Tampered embedding must fail verification");
}

#[test]
fn test_crypto_stale_timestamp_rejection() {
    let seed = [0x99u8; 32];
    let query_id = Uuid::new_v4();
    let sender_id = "peer_adversary";
    let stale_timestamp = Utc::now().timestamp() - 600; // 10 minutes ago
    let access_tier = AccessTier::Tier0Public;
    let top_k = 5;
    let embedding = vec![0.1f32; 768];
    let query_text = "Replayed query";

    let (pubkey, sig_bytes) = oracle_sign_query(
        &seed,
        query_id,
        sender_id,
        stale_timestamp,
        access_tier,
        top_k,
        &embedding,
        query_text,
    );
    let result = oracle_verify_query(
        &pubkey,
        &sig_bytes,
        query_id,
        sender_id,
        stale_timestamp,
        access_tier,
        top_k,
        &embedding,
        query_text,
        60,
    );
    assert!(result.is_err(), "Timestamp drift > 60s must fail");
}

#[test]
fn test_crypto_forged_signature_rejection() {
    let seed = [0x55u8; 32];
    let query_id = Uuid::new_v4();
    let sender_id = "peer_attacker";
    let timestamp = Utc::now().timestamp();
    let access_tier = AccessTier::Tier0Public;
    let top_k = 5;
    let embedding = vec![0.2f32; 768];
    let query_text = "Query with forged signature";

    let (pubkey, mut sig_bytes) = oracle_sign_query(
        &seed,
        query_id,
        sender_id,
        timestamp,
        access_tier,
        top_k,
        &embedding,
        query_text,
    );
    sig_bytes[0] ^= 0xaa; // Corrupt signature byte

    let result = oracle_verify_query(
        &pubkey,
        &sig_bytes,
        query_id,
        sender_id,
        timestamp,
        access_tier,
        top_k,
        &embedding,
        query_text,
        60,
    );
    assert!(result.is_err(), "Corrupted signature must fail verification");
}

#[test]
fn test_acl_effective_tier_resolution() {
    let mut acl = PeerAclManager::default();
    let pubkey = [0x11u8; 32];
    acl.register_pubkey(pubkey, AccessTier::Tier1Internal);

    let auth = acl.get_authorized_tier_for_pubkey(&pubkey);
    assert_eq!(auth, AccessTier::Tier1Internal);

    // Requester asks for Tier 2 Confidential, but only authorized for Tier 1 Internal
    let effective = acl.resolve_effective_tier(2, auth);
    assert_eq!(effective, 1, "Must cap at authorized upper bound");

    // Requester asks for Tier 0 Public, authorized for Tier 1 -> effective is 0
    let effective_pub = acl.resolve_effective_tier(0, auth);
    assert_eq!(effective_pub, 0);
}

#[test]
fn test_rrf_combiner_consensus_boost() {
    let local = vec![
        ScoredChunk::new(
            DocumentChunk::new(
                "c_shared",
                "doc1",
                "f.rs",
                1,
                2,
                0,
                vec![1.0; 768],
                "Shared context",
                None,
            )
            .unwrap(),
            0.9,
            "local",
            false,
        ),
        ScoredChunk::new(
            DocumentChunk::new(
                "c_single",
                "doc2",
                "single.rs",
                1,
                2,
                0,
                vec![1.0; 768],
                "Single peer context",
                None,
            )
            .unwrap(),
            0.8,
            "local",
            false,
        ),
    ];

    let remote_peers = vec![
        vec![CandidateChunkDto {
            chunk_id: "c_shared".to_string(),
            file_path: "f.rs".to_string(),
            line_start: 1,
            line_end: 2,
            content: "Shared context".to_string(),
            score: 0.9,
            access_tier: 0,
        }],
        vec![CandidateChunkDto {
            chunk_id: "c_shared".to_string(),
            file_path: "f.rs".to_string(),
            line_start: 1,
            line_end: 2,
            content: "Shared context".to_string(),
            score: 0.9,
            access_tier: 0,
        }],
    ];

    let fused = RrfCombiner::fuse_rankings(local, remote_peers, 60.0, 5);
    assert_eq!(fused.len(), 2);

    // 1 local (rank 1) + 2 remote (rank 1) = (3 / 61) * 1.25 ~ 0.06148
    let expected_boosted = (3.0 / 61.0) * 1.25;
    assert!(
        (fused[0].score - expected_boosted).abs() < 1e-4,
        "Expected score ~ {:.5}, got {:.5}",
        expected_boosted,
        fused[0].score
    );
    assert_eq!(fused[0].chunk.chunk_id, "c_shared");

    // Single peer (local rank 2) = 1 / (60 + 2) = 1 / 62 without consensus boost
    let expected_single = 1.0 / 62.0;
    assert!(
        (fused[1].score - expected_single).abs() < 1e-4,
        "Expected score ~ {:.5}, got {:.5}",
        expected_single,
        fused[1].score
    );
    assert_eq!(fused[1].chunk.chunk_id, "c_single");
}

#[test]
fn test_volatile_memory_scrubbing() {
    let dto = CandidateChunkDto {
        chunk_id: "c_vol".to_string(),
        file_path: "memo.txt".to_string(),
        line_start: 1,
        line_end: 5,
        content: "TOP_SECRET_EPHEMERAL_TEXT".to_string(),
        score: 0.9,
        access_tier: 2,
    };

    let mut volatile = dto.into_volatile_remote_chunk("peer_1");
    assert_eq!(volatile.content(), "TOP_SECRET_EPHEMERAL_TEXT");

    volatile.content.zeroize();
    assert!(
        volatile.content().is_empty() || volatile.content().chars().all(|c| c == '\0'),
        "Buffer must be zeroized"
    );
}

#[tokio::test]
async fn test_scatter_gather_400ms_timeout_aborts_slow_peer() {
    let mut storage = MockLocalStorage::default();
    storage.chunks.push(
        DocumentChunk::new(
            "c_local",
            "doc1",
            "loc.rs",
            1,
            5,
            0,
            vec![1.0; 768],
            "Fast query text",
            None,
        )
        .unwrap(),
    );

    let mut coord = FederatedQueryCoordinator::new(storage);

    // Fast peer (30ms)
    coord.add_peer(MockRemotePeer {
        peer_id: "peer_fast".to_string(),
        latency: Duration::from_millis(30),
        max_access_tier: 0,
        candidate_chunks: vec![CandidateChunkDto {
            chunk_id: "c_fast".to_string(),
            file_path: "fast.rs".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Fast query text remote".to_string(),
            score: 0.88,
            access_tier: 0,
        }],
    });

    // Slow peer (800ms)
    coord.add_peer(MockRemotePeer {
        peer_id: "peer_slow".to_string(),
        latency: Duration::from_millis(800),
        max_access_tier: 0,
        candidate_chunks: vec![CandidateChunkDto {
            chunk_id: "c_slow".to_string(),
            file_path: "slow.rs".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Slow hanging chunk".to_string(),
            score: 0.99,
            access_tier: 0,
        }],
    });

    let (results, _volatile, duration_ms) =
        coord.execute_query("Fast query text", &vec![1.0; 768], 0, 10).await;

    assert!(
        duration_ms <= 480,
        "Duration {}ms violated 400ms hard deadline",
        duration_ms
    );
    assert!(!results.iter().any(|r| r.chunk.chunk_id == "c_slow"));
    assert!(results.iter().any(|r| r.chunk.chunk_id == "c_fast"));
    assert!(results.iter().any(|r| r.chunk.chunk_id == "c_local"));
}

#[tokio::test]
async fn test_zero_peer_graceful_local_fallback() {
    let mut storage = MockLocalStorage::default();
    storage.chunks.push(
        DocumentChunk::new(
            "c_solitary",
            "doc",
            "s.rs",
            1,
            2,
            0,
            vec![1.0; 768],
            "Solitary text",
            None,
        )
        .unwrap(),
    );

    let coord = FederatedQueryCoordinator::new(storage);

    let (results, volatile, duration_ms) =
        coord.execute_query("Solitary text", &vec![1.0; 768], 0, 5).await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].chunk.chunk_id, "c_solitary");
    assert!(volatile.is_empty());
    assert!(duration_ms < 50, "Zero-peer query must resolve immediately");
}

#[test]
fn test_langextract_verbatim_grounding_and_hallucination_filtering() {
    let source_text =
        "The QuorumRAG protocol uses Gemma 768-dim embeddings with BLAKE3 contract hash verification.";

    let mut grounded_ext = Extraction::new("EmbeddingSpec", "Gemma 768-dim embeddings");
    let mut hallucinated_ext = Extraction::new("EmbeddingSpec", "OpenAI text-embedding-ada-002");

    assert!(ground_extraction(&mut grounded_ext, source_text));
    assert!(grounded_ext.char_interval.is_some());
    let (s, e) = grounded_ext.char_interval.unwrap();
    assert_eq!(&source_text[s..e], "Gemma 768-dim embeddings");

    assert!(!ground_extraction(&mut hallucinated_ext, source_text));
    assert!(hallucinated_ext.char_interval.is_none());

    let all = vec![grounded_ext.clone(), hallucinated_ext];
    let filtered = filter_grounded(all);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].extraction_text, "Gemma 768-dim embeddings");
}

#[test]
fn test_langextract_fewshot_example_schema_validation() {
    let text = "Function authenticate_peer verifies Ed25519 signatures with BLAKE3 digest.";
    let valid_extraction =
        Extraction::new("SecurityFunction", "authenticate_peer").with_interval(9, 26);
    let example = ExampleData::new(text, vec![valid_extraction]);
    assert!(example.validate_schema().is_ok());

    let invalid_extraction =
        Extraction::new("SecurityFunction", "authenticate_peer").with_interval(0, 10);
    let invalid_example = ExampleData::new(text, vec![invalid_extraction]);
    assert!(invalid_example.validate_schema().is_err());
}

#[test]
fn test_langextract_4arm_consensus_and_adversarial_rejection() {
    let source_text =
        "Peer authentication enforces Ed25519 signatures and 400ms scatter-gather timeouts.";
    let ext1 = Extraction::new("CryptoAlgorithm", "Ed25519").with_attribute("tier", "0");
    let ext2 = Extraction::new("NetworkTimeout", "400ms").with_attribute("category", "timeout");

    // All genuine extractions
    let res = LlmFusionConsensus::evaluate_extractions(
        source_text,
        vec![ext1.clone(), ext2.clone()],
        None,
    );
    assert!(res.consensus_passed);
    assert_eq!(res.arm_reports.len(), 4);
    for arm in &res.arm_reports {
        assert!(arm.passed, "Arm '{}' failed", arm.arm_name);
    }
    assert_eq!(res.verified_extractions.len(), 2);
    assert_eq!(res.metadata_filters.get("tier").map(String::as_str), Some("0"));
    assert_eq!(
        res.metadata_filters.get("category").map(String::as_str),
        Some("timeout")
    );

    // Inject hallucination
    let fake_ext = Extraction::new("FakeFeature", "QuantumEncryption128");
    let res_hallucinated =
        LlmFusionConsensus::evaluate_extractions(source_text, vec![ext1, fake_ext], None);
    assert!(
        !res_hallucinated.consensus_passed,
        "Hallucinated extraction must fail consensus"
    );
    assert_eq!(
        res_hallucinated.verified_extractions.len(),
        1,
        "Only genuine extraction must survive"
    );
}

#[test]
fn test_langextract_query_metadata_filters() {
    let query = "find architecture diagrams filetype:pdf author:alice year:2026 tier:internal";
    let filters = extract_query_metadata_filters(query).expect("Filters must be parsed");
    assert_eq!(filters.get("filetype").map(String::as_str), Some("pdf"));
    assert_eq!(filters.get("author").map(String::as_str), Some("alice"));
    assert_eq!(filters.get("date").map(String::as_str), Some("2026"));
    assert_eq!(filters.get("tier").map(String::as_str), Some("internal"));

    let plain_query = "simple query without filters";
    assert!(extract_query_metadata_filters(plain_query).is_none());
}

