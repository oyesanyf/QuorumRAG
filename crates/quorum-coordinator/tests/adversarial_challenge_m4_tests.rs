use quorum_coordinator::{
    AgenticStateGraphRunner, AgenticTelemetryEvent, CoordinatorConfig, FederatedQueryCoordinator,
    MockMeshDispatcher, MockRemotePeer, PeerAclManager, RrfCombiner, ScatterGatherEngine,
    StorageSearcher, SynthesisModelFamily,
    langextract::{ground_extraction, Extraction, LlmFusionConsensus},
};
use quorum_types::{CandidateChunkDto, DocumentChunk, ScoredChunk, VolatileRemoteChunk};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use zeroize::Zeroize;

#[derive(Default, Clone)]
struct MockStorage {
    chunks: Vec<DocumentChunk>,
}

#[async_trait::async_trait]
impl StorageSearcher for MockStorage {
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

/// Adversarial Challenge 1: Slow/hanging peer added FIRST must NOT block fast peers added SECOND.
///
/// In a concurrent scatter-gather architecture, if peer 0 is hanging/delayed (>400ms)
/// and peer 1 finishes in 30ms, the coordinator MUST gather peer 1's chunks before the 400ms deadline.
#[tokio::test]
async fn challenge_slow_peer_first_must_not_drop_fast_peer() {
    let mut storage = MockStorage::default();
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

    // Slow peer (800ms) added FIRST
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

    // Fast peer (30ms) added SECOND
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

    let (results, _volatile, duration_ms) =
        coord.execute_query("Fast query text", &vec![1.0; 768], 0, 10).await;

    assert!(
        duration_ms <= 480,
        "Duration {}ms violated 400ms hard deadline",
        duration_ms
    );
    assert!(!results.iter().any(|r| r.chunk.chunk_id == "c_slow"), "Slow chunk should not be returned");
    assert!(
        results.iter().any(|r| r.chunk.chunk_id == "c_fast"),
        "CRITICAL BUG: Fast peer response was dropped because slow peer was earlier in the tasks list!"
    );
    assert!(results.iter().any(|r| r.chunk.chunk_id == "c_local"));
}

/// Adversarial Challenge 2: ScatterGatherEngine with MockMeshDispatcher where slow peer is first.
#[tokio::test]
async fn challenge_scatter_gather_engine_slow_peer_first() {
    let mut storage = MockStorage::default();
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

    let dispatcher = MockMeshDispatcher::new();
    // Add slow peer first
    dispatcher
        .add_peer(MockRemotePeer {
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
        })
        .await;

    // Add fast peer second
    dispatcher
        .add_peer(MockRemotePeer {
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
        })
        .await;

    let engine = ScatterGatherEngine::new(
        Arc::new(storage),
        Arc::new(dispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig {
            timeout_ms: 400,
            ..Default::default()
        },
        [0x11u8; 32],
        "test_sender".to_string(),
    );

    let (results, _volatile, duration_ms) =
        engine.execute_query("Fast query text", &vec![1.0; 768], 0, 10).await;

    assert!(duration_ms <= 480, "Duration {}ms violated 400ms deadline", duration_ms);
    assert!(!results.iter().any(|r| r.chunk.chunk_id == "c_slow"));
    assert!(
        results.iter().any(|r| r.chunk.chunk_id == "c_fast"),
        "CRITICAL BUG: Fast peer response was dropped because slow peer was earlier in the tasks list!"
    );
}

/// Adversarial Challenge 3: Agentic state graph loop bounds when candidate score is 0.0
#[tokio::test]
async fn challenge_agentic_loop_terminates_strictly_at_max_hops() {
    #[derive(Default)]
    struct ZeroScoreStorage;

    #[async_trait::async_trait]
    impl StorageSearcher for ZeroScoreStorage {
        async fn search_hybrid(
            &self,
            _query_text: &str,
            _query_vec: &[f32],
            _max_tier: u8,
            _top_k: usize,
        ) -> Vec<ScoredChunk> {
            // Return candidate with score 0.0, far below threshold 0.60
            vec![ScoredChunk::new(
                DocumentChunk::new(
                    "zero_chunk",
                    "doc_zero",
                    "irrelevant.txt",
                    1,
                    1,
                    0,
                    vec![0.0; 768],
                    "Completely irrelevant text",
                    None,
                )
                .unwrap(),
                0.0,
                "local",
                false,
            )]
        }
    }

    let runner = AgenticStateGraphRunner::new(3, 0.60);
    let engine = ScatterGatherEngine::new(
        Arc::new(ZeroScoreStorage),
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0u8; 32],
        "node_zero".to_string(),
    );

    let (tx, mut rx) = mpsc::channel(64);
    let monitor = tokio::spawn(async move {
        let mut hops = Vec::new();
        while let Some(ev) = rx.recv().await {
            if let AgenticTelemetryEvent::StateTransition { to_state, hop, .. } = ev {
                hops.push((to_state, hop));
            }
        }
        hops
    });

    let state = runner
        .run(
            "Query that will never meet threshold",
            SynthesisModelFamily::AutoFusion,
            &engine,
            &vec![0.0; 768],
            0,
            5,
            Some(tx),
        )
        .await
        .expect("Must terminate cleanly without infinite loop");

    assert_eq!(state.hop_count, 3, "State graph must terminate at exactly max_hops (3)");
    assert!(state.synthesized_response.is_some());

    let transitions = monitor.await.unwrap();
    for (_st, hop) in &transitions {
        assert!(*hop <= 3, "Hop {} exceeded max_hops 3", hop);
    }
}

/// Adversarial Challenge 4: VolatileRemoteChunk zeroizes memory on drop.
#[test]
fn challenge_volatile_remote_chunk_zeroizes_buffer() {
    let secret = "VERY_CONFIDENTIAL_REMOTE_CONTENT_CANARY_123456789".to_string();
    let ptr = secret.as_ptr();
    let len = secret.len();

    let mut chunk = VolatileRemoteChunk {
        chunk_id: "c_canary".to_string(),
        peer_id: "peer_canary".to_string(),
        file_path: "classified.txt".to_string(),
        line_start: 1,
        line_end: 10,
        score: 0.95,
        access_tier: 3,
        content: secret,
    };

    assert_eq!(chunk.content(), "VERY_CONFIDENTIAL_REMOTE_CONTENT_CANARY_123456789");

    chunk.zeroize();
    assert!(chunk.content.is_empty());

    let slice_after = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(
        slice_after.iter().all(|&b| b == 0),
        "Memory at pointer was not zeroed!"
    );
}


/// Adversarial Challenge 5: VolatileRemoteChunk implicit drop zeroizes memory buffer.
#[test]
fn challenge_volatile_remote_chunk_implicit_drop_zeroizes() {
    let secret = "VERY_CONFIDENTIAL_IMPLICIT_DROP_CANARY_987654321".to_string();
    let ptr = secret.as_ptr();
    let len = secret.len();

    {
        let chunk = VolatileRemoteChunk {
            chunk_id: "c_drop".to_string(),
            peer_id: "peer_drop".to_string(),
            file_path: "classified.txt".to_string(),
            line_start: 1,
            line_end: 10,
            score: 0.95,
            access_tier: 3,
            content: secret,
        };
        assert_eq!(chunk.content(), "VERY_CONFIDENTIAL_IMPLICIT_DROP_CANARY_987654321");
    } // chunk dropped here; ZeroizeOnDrop must overwrite memory at ptr with zeroes

    let slice_after = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert!(
        slice_after.iter().all(|&b| b == 0),
        "Memory at pointer was not zeroed upon implicit drop!"
    );
}

/// Adversarial Challenge 6: Agentic state graph with empty retrieval terminates immediately.
#[tokio::test]
async fn challenge_agentic_loop_empty_retrieval_terminates() {
    #[derive(Default)]
    struct EmptyStorage;

    #[async_trait::async_trait]
    impl StorageSearcher for EmptyStorage {
        async fn search_hybrid(
            &self,
            _query_text: &str,
            _query_vec: &[f32],
            _max_tier: u8,
            _top_k: usize,
        ) -> Vec<ScoredChunk> {
            Vec::new()
        }
    }

    let runner = AgenticStateGraphRunner::new(3, 0.60);
    let engine = ScatterGatherEngine::new(
        Arc::new(EmptyStorage),
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0u8; 32],
        "node_empty".to_string(),
    );

    let state = runner
        .run(
            "Empty query",
            SynthesisModelFamily::AutoFusion,
            &engine,
            &vec![0.0; 768],
            0,
            5,
            None,
        )
        .await
        .expect("Must terminate cleanly on empty retrieval");

    // When retrieval is empty, GradeRelevance marks unsatisfactory, triggering rewrite hops
    // bounded strictly at max_hops (3), then synthesizes cleanly.
    assert_eq!(
        state.hop_count, 3,
        "Empty retrieval must trigger query rewrite hops up to max_hops (3)"
    );
    assert!(state.synthesized_response.is_some());
}

/// Adversarial Challenge 7: 1.25x Consensus Boost Math, Provenance Deduplication, & Tie-Breaking.
#[test]
fn challenge_rrf_combiner_consensus_boost_adversarial_math() {
    let chunk_local = ScoredChunk::new(
        DocumentChunk::new(
            "chunk_multi",
            "doc1",
            "multi.rs",
            1,
            5,
            0,
            vec![1.0; 768],
            "Multi peer chunk content",
            None,
        )
        .unwrap(),
        0.9,
        "local",
        false,
    );

    let chunk_single = ScoredChunk::new(
        DocumentChunk::new(
            "chunk_single",
            "doc2",
            "single.rs",
            1,
            5,
            0,
            vec![1.0; 768],
            "Single peer chunk content",
            None,
        )
        .unwrap(),
        0.8,
        "local",
        false,
    );

    // chunk_multi present in local (rank 1), remote 1 (rank 1), and remote 2 (rank 1)
    // chunk_single present in local only (rank 2)
    // chunk_same_peer_dup present twice in remote 1 (rank 2 and rank 3) -> MUST NOT get 1.25x boost!
    let local = vec![chunk_local, chunk_single];
    let remote_peers = vec![
        vec![
            CandidateChunkDto {
                chunk_id: "chunk_multi".to_string(),
                file_path: "multi.rs".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Multi peer chunk content".to_string(),
                score: 0.9,
                access_tier: 0,
            },
            CandidateChunkDto {
                chunk_id: "chunk_same_peer_dup".to_string(),
                file_path: "dup.rs".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Duplicate in same peer".to_string(),
                score: 0.7,
                access_tier: 0,
            },
            CandidateChunkDto {
                chunk_id: "chunk_same_peer_dup".to_string(),
                file_path: "dup.rs".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Duplicate in same peer".to_string(),
                score: 0.6,
                access_tier: 0,
            },
        ],
        vec![CandidateChunkDto {
            chunk_id: "chunk_multi".to_string(),
            file_path: "multi.rs".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Multi peer chunk content".to_string(),
            score: 0.9,
            access_tier: 0,
        }],
    ];

    let fused = RrfCombiner::fuse_rankings(local, remote_peers, 60.0, 10);
    assert_eq!(fused.len(), 3);

    // 1. chunk_multi: 3 distinct peers (local=0, remote1=1, remote2=2)
    // base_score = 1/(60+1) + 1/(60+1) + 1/(60+1) = 3 / 61
    // 3 peers >= 2 -> boosted: (3.0 / 61.0) * 1.25
    let expected_multi = (3.0 / 61.0) * 1.25;
    assert_eq!(fused[0].chunk.chunk_id, "chunk_multi");
    assert!(
        (fused[0].score - expected_multi).abs() < 1e-5,
        "Expected boosted score {:.6}, got {:.6}",
        expected_multi,
        fused[0].score
    );

    // 2. chunk_same_peer_dup: present at rank 2 and 3 of remote 1 ONLY (distinct peers = {1}, len = 1)
    // Under M8 Feature 50 Byzantine hardening, intra-peer score stuffing is eliminated:
    // a peer contributes at most once per unique chunk at its highest/first rank (rank 2 -> 1/62).
    let expected_dup = 1.0 / 62.0;
    let dup_chunk = fused
        .iter()
        .find(|c| c.chunk.chunk_id == "chunk_same_peer_dup")
        .expect("chunk_same_peer_dup must be present");
    assert!(
        (dup_chunk.score - expected_dup).abs() < 1e-5,
        "Same-peer duplicate was incorrectly boosted! Expected {:.6}, got {:.6}",
        expected_dup,
        dup_chunk.score
    );

    // 3. chunk_single: local rank 2 -> base_score = 1/62, unboosted
    let single_chunk = fused
        .iter()
        .find(|c| c.chunk.chunk_id == "chunk_single")
        .expect("chunk_single must be present");
    let expected_single = 1.0 / 62.0;
    assert!(
        (single_chunk.score - expected_single).abs() < 1e-5,
        "Expected unboosted score {:.6}, got {:.6}",
        expected_single,
        single_chunk.score
    );

    // 4. Deterministic tie-breaking test:
    let tie1 = ScoredChunk::new(
        DocumentChunk::new(
            "chunk_bravo",
            "doc_b",
            "b.rs",
            1,
            2,
            0,
            vec![1.0; 768],
            "Tie content bravo",
            None,
        )
        .unwrap(),
        0.5,
        "local",
        false,
    );
    // Both at rank 1 in their own isolated peer lists: tie1 in local, chunk_alpha in remote
    let tie_fused = RrfCombiner::fuse_rankings(
        vec![tie1],
        vec![vec![CandidateChunkDto {
            chunk_id: "chunk_alpha".to_string(),
            file_path: "a.rs".to_string(),
            line_start: 1,
            line_end: 2,
            content: "Tie content alpha".to_string(),
            score: 0.5,
            access_tier: 0,
        }]],
        60.0,
        2,
    );
    // Both have exact same score 1/61. Sort must place "chunk_alpha" before "chunk_bravo" alphabetically.
    assert_eq!(tie_fused[0].chunk.chunk_id, "chunk_alpha");
    assert_eq!(tie_fused[1].chunk.chunk_id, "chunk_bravo");
}

/// Adversarial Challenge 8: LangExtract Ungrounded Strings Cannot Fabricate Char Intervals.
#[test]
fn challenge_langextract_adversarial_grounding_and_hallucination_proofing() {
    let source_text = "The QuorumRAG protocol verifies Ed25519 signatures with BLAKE3 hashes. \
                       Привет мир! Multibyte UTF-8 span verification.";

    // Attack 1: Candidate with pre-fabricated char_interval targeting ungrounded hallucination
    let mut fabricated = Extraction::new("MaliciousConcept", "Fabricated hallucinated entity")
        .with_interval(0, 30);
    assert!(!ground_extraction(&mut fabricated, source_text));
    assert!(
        fabricated.char_interval.is_none(),
        "ground_extraction must wipe fabricated char_interval to None!"
    );

    // Attack 2: Empty extraction text
    let mut empty_ext = Extraction::new("EmptyConcept", "");
    assert!(!ground_extraction(&mut empty_ext, source_text));
    assert!(empty_ext.char_interval.is_none());

    // Attack 3: Partial substring mismatch
    let mut partial_ext = Extraction::new("PartialConcept", "Ed25519 signatures forged");
    assert!(!ground_extraction(&mut partial_ext, source_text));
    assert!(partial_ext.char_interval.is_none());

    // Genuine Multibyte UTF-8 extraction: "Привет мир!" (starts at byte 71, length 20 bytes)
    let mut utf8_ext = Extraction::new("Greeting", "Привет мир!");
    assert!(ground_extraction(&mut utf8_ext, source_text));
    assert!(utf8_ext.char_interval.is_some());
    let (start, end) = utf8_ext.char_interval.unwrap();
    assert!(source_text.is_char_boundary(start));
    assert!(source_text.is_char_boundary(end));
    assert_eq!(&source_text[start..end], "Привет мир!");

    // Attack 4: 4-Arm Consensus must reject candidate list containing ungrounded or syntactically invalid items
    let genuine_ext = Extraction::new("Crypto", "Ed25519");
    let fake_ext = Extraction::new("Fake", "Completely absent hallucination");
    let unbalanced_ext = Extraction::new("SyntaxError", "unbalanced (syntax [bracket");

    let res = LlmFusionConsensus::evaluate_extractions(
        source_text,
        vec![genuine_ext.clone(), fake_ext, unbalanced_ext],
        None,
    );
    assert!(
        !res.consensus_passed,
        "Consensus must fail when ungrounded or unbalanced candidates are injected"
    );
    assert_eq!(
        res.verified_extractions.len(),
        1,
        "Only the 1 genuine extraction must pass counterfactual judge"
    );
    assert_eq!(res.verified_extractions[0].extraction_text, "Ed25519");
}

/// Adversarial Challenge 9: Batch VolatileRemoteChunk Drop Zeroizes All Buffers.
#[test]
fn challenge_volatile_remote_chunk_stress_zeroize_vectors() {
    let mut raw_ptrs = Vec::new();

    {
        let mut chunks = Vec::new();
        for i in 0..10 {
            let secret = format!("VERY_SECRET_CANARY_PAYLOAD_CHUNK_INDEX_{:04}_DATA", i);
            let ptr = secret.as_ptr();
            let len = secret.len();
            raw_ptrs.push((ptr, len));

            chunks.push(VolatileRemoteChunk {
                chunk_id: format!("c_{}", i),
                peer_id: format!("peer_{}", i),
                file_path: format!("file_{}.txt", i),
                line_start: 1,
                line_end: 10,
                score: 0.9,
                access_tier: 1,
                content: secret,
            });
        }

        // Verify chunks contain expected secrets before drop
        for (i, c) in chunks.iter().enumerate() {
            assert!(c.content().contains(&format!("INDEX_{:04}", i)));
        }
    } // chunks vector dropped here; all 10 chunks must have their memory zeroed

    for (i, &(ptr, len)) in raw_ptrs.iter().enumerate() {
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(
            slice.iter().all(|&b| b == 0),
            "Memory buffer for chunk {} at pointer {:?} was not zeroed on drop!",
            i,
            ptr
        );
    }
}

/// Adversarial Challenge 10: Interleaved Fast and Slow Peers With Strict 400ms Deadline.
#[tokio::test]
async fn challenge_scatter_gather_interleaved_fast_and_slow_peers() {
    let mut storage = MockStorage::default();
    storage.chunks.push(
        DocumentChunk::new(
            "c_local",
            "doc1",
            "loc.rs",
            1,
            5,
            0,
            vec![1.0; 768],
            "Interleaved test query",
            None,
        )
        .unwrap(),
    );

    let dispatcher = MockMeshDispatcher::new();

    // 6 peers interleaved: slow, fast, slow, fast, slow, fast
    let peers = vec![
        ("peer_slow_0", Duration::from_millis(700), "c_slow_0"),
        ("peer_fast_1", Duration::from_millis(20), "c_fast_1"),
        ("peer_slow_2", Duration::from_millis(800), "c_slow_2"),
        ("peer_fast_3", Duration::from_millis(40), "c_fast_3"),
        ("peer_slow_4", Duration::from_millis(900), "c_slow_4"),
        ("peer_fast_5", Duration::from_millis(60), "c_fast_5"),
    ];

    for (pid, latency, cid) in peers {
        dispatcher
            .add_peer(MockRemotePeer {
                peer_id: pid.to_string(),
                latency,
                max_access_tier: 0,
                candidate_chunks: vec![CandidateChunkDto {
                    chunk_id: cid.to_string(),
                    file_path: format!("{}.rs", cid),
                    line_start: 1,
                    line_end: 5,
                    content: format!("Interleaved test query remote for {}", cid),
                    score: 0.85,
                    access_tier: 0,
                }],
            })
            .await;
    }

    let engine = ScatterGatherEngine::new(
        Arc::new(storage),
        Arc::new(dispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig {
            timeout_ms: 400,
            ..Default::default()
        },
        [0x22u8; 32],
        "interleaved_sender".to_string(),
    );

    let (results, _volatile, duration_ms) =
        engine.execute_query("Interleaved test query", &vec![1.0; 768], 0, 10).await;

    assert!(
        duration_ms <= 550,
        "Duration {}ms violated 400ms hard deadline",
        duration_ms
    );

    // All 3 fast peers must be present
    assert!(
        results.iter().any(|r| r.chunk.chunk_id == "c_fast_1"),
        "Missing fast peer 1"
    );
    assert!(
        results.iter().any(|r| r.chunk.chunk_id == "c_fast_3"),
        "Missing fast peer 3"
    );
    assert!(
        results.iter().any(|r| r.chunk.chunk_id == "c_fast_5"),
        "Missing fast peer 5"
    );

    // None of the 3 slow peers must be present
    assert!(!results.iter().any(|r| r.chunk.chunk_id == "c_slow_0"));
    assert!(!results.iter().any(|r| r.chunk.chunk_id == "c_slow_2"));
    assert!(!results.iter().any(|r| r.chunk.chunk_id == "c_slow_4"));
}

