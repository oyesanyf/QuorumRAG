//! Empirical Adversarial Challenger Test Suite for Milestone 38:
//! Query Execution Performance, Agentic Latency, Citation Filtering & Semaphore-Bounded Retrieval (Requirement R2 + Multithreading).
//!
//! Verifies:
//! 1. Mesh query latency: single peer query must resolve immediately upon response arrival (<200ms) without waiting for 5,000ms deadline or long grace periods.
//! 2. Dead/unhealthy peer resilience: queries with mixed responsive (fast) and dead/straggler peers must resolve rapidly without timing out.
//! 3. Single-doc author query hop 0 completion: author questions over single-document states pass grading on hop 0 with zero rewrite loops.
//! 4. G-28 citation filtering: identity queries with both resume chunks and USCIS Form G-28 / DHS boilerplate chunks never include the G-28 boilerplate in the citations or sources block.
//! 5. Concurrency & Semaphore-Bounded DLP inspection: semaphore-bounded DLP inspection in `scatter_gather.rs` handles concurrent chunk streams without deadlock or memory bloat.

use chrono::Utc;
use quorum_coordinator::{
    agentic::grade::GradeRelevanceNode,
    crypto::sign_request,
    dlp_mesh::{global_mesh_dlp_controller, DlpEnforcementMode},
    global_peer_health_registry,
    offline_engine::DeterministicOfflineSynthesisEngine,
    AgenticGraphState, AgenticStateGraphRunner, CoordinatorConfig,
    MeshQueryDispatcher, MockMeshDispatcher, MockRemotePeer, PeerAclManager,
    ScatterGatherEngine, StorageSearcher, SynthesisModelFamily,
};
use quorum_types::{
    AccessTier, CandidateChunkDto, DocumentChunk, FederatedQueryRequest, PeerQueryStatus,
    ScoredChunk,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Realistic mock storage implementation for scatter-gather and agentic runner integration.
#[derive(Default, Clone)]
struct EmpiricalMockStorage {
    chunks: Vec<DocumentChunk>,
}

impl EmpiricalMockStorage {
    fn new(chunks: Vec<DocumentChunk>) -> Self {
        Self { chunks }
    }
}

#[async_trait::async_trait]
impl StorageSearcher for EmpiricalMockStorage {
    async fn search_hybrid(
        &self,
        query_text: &str,
        _query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let q_low = query_text.to_ascii_lowercase();
        let query_terms: Vec<&str> = q_low.split_whitespace().collect();
        let mut matches: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier)
            .map(|c| {
                let content_low = c.text_content.to_ascii_lowercase();
                let matches_count = query_terms
                    .iter()
                    .filter(|term| content_low.contains(*term))
                    .count();
                let score = if !query_terms.is_empty() {
                    (matches_count as f32 / query_terms.len() as f32) * 0.95
                } else {
                    0.5
                };
                ScoredChunk::new(c.clone(), score.max(0.1), "local", false)
            })
            .collect();
        matches.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        matches.truncate(top_k);
        matches
    }
}

fn make_doc_chunk(
    chunk_id: &str,
    file_path: &str,
    text: &str,
    access_tier: u8,
) -> DocumentChunk {
    DocumentChunk::new(
        chunk_id,
        "doc_test",
        file_path,
        1,
        10,
        access_tier,
        vec![0.1f32; 768],
        text,
        None,
    )
    .expect("DocumentChunk construction must succeed")
}

fn make_scored_chunk(
    chunk_id: &str,
    file_path: &str,
    text: &str,
    score: f32,
) -> ScoredChunk {
    let doc = make_doc_chunk(chunk_id, file_path, text, 0);
    ScoredChunk::new(doc, score, "local", false)
}

fn create_signed_test_request(query: &str) -> FederatedQueryRequest {
    let mut req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: "test_challenger_node".to_string(),
        sender_pubkey: [0u8; 32],
        query_text: query.to_string(),
        embedding: vec![0.1f32; 768],
        top_k: 10,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&[0x42u8; 32], &mut req, AccessTier::Tier0Public);
    req,
    origin_peer_id: None,
    relay_hops: 0,
    visited_peers: Vec::new(),
}

// ============================================================================
// REQUIREMENT 1: MESH QUERY LATENCY (<200ms IMMEDIATE RESOLUTION)
// ============================================================================

#[tokio::test]
async fn test_empirical_mesh_latency_single_peer_resolves_immediately_under_200ms() {
    let dispatcher = MockMeshDispatcher::new();
    dispatcher
        .add_peer(MockRemotePeer {
            peer_id: "fast_peer_alpha".to_string(),
            latency: Duration::from_millis(25),
            max_access_tier: 0,
            candidate_chunks: vec![
                CandidateChunkDto {
                    chunk_id: "chunk_remote_1".to_string(),
                    file_path: "remote/architecture.md".to_string(),
                    line_start: 1,
                    line_end: 10,
                    content: "QuorumRAG deterministic scatter-gather architecture".to_string(),
                    score: 0.92,
                    access_tier: 0,
                    origin_peer_id: None,
                },
                CandidateChunkDto {
                    chunk_id: "chunk_remote_2".to_string(),
                    file_path: "remote/consensus.md".to_string(),
                    line_start: 1,
                    line_end: 8,
                    content: "Byzantine fault tolerance and RRF rank fusion".to_string(),
                    score: 0.88,
                    access_tier: 0,
                    origin_peer_id: None,
                },
            ],
        })
        .await;

    let req = create_signed_test_request("scatter-gather architecture");
    let requested_timeout = Duration::from_millis(5000);

    let start = Instant::now();
    let (responses, diagnostics) = dispatcher
        .query_peers_with_diagnostics(&req, requested_timeout)
        .await
        .expect("Query peers must succeed");
    let elapsed = start.elapsed();

    // Invariant: single peer query MUST resolve immediately upon response arrival (<200ms),
    // and MUST NEVER wait out the 5,000ms deadline.
    assert!(
        elapsed < Duration::from_millis(200),
        "Elapsed duration {:?} exceeded 200ms threshold for single peer query (waited on deadline!)",
        elapsed
    );
    assert_eq!(responses.len(), 1, "Expected exactly 1 peer response");
    assert_eq!(responses[0].chunks.len(), 2, "Expected 2 candidate chunks from peer");
    assert_eq!(diagnostics.queried_peers_count, 1);
    assert_eq!(diagnostics.peer_outcomes.len(), 1);
    assert_eq!(
        diagnostics.peer_outcomes[0].status,
        PeerQueryStatus::Connected,
        "Peer status must be Connected"
    );
    assert_eq!(diagnostics.peer_outcomes[0].matching_chunk_count, 2);
}

#[tokio::test]
async fn test_empirical_scatter_gather_single_peer_immediate_resolution() {
    let storage = EmpiricalMockStorage::new(vec![make_doc_chunk(
        "chunk_local_1",
        "local/doc.txt",
        "Local enterprise security guidelines",
        0,
    )]);

    let dispatcher = MockMeshDispatcher::new();
    dispatcher
        .add_peer(MockRemotePeer {
            peer_id: "peer_bravo".to_string(),
            latency: Duration::from_millis(30),
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: "chunk_remote_bravo".to_string(),
                file_path: "remote/zero_trust.md".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Remote zero-trust cryptographic enclaves".to_string(),
                score: 0.90,
                access_tier: 0,
                origin_peer_id: None,
            }],
        })
        .await;

    let engine = ScatterGatherEngine::new(
        Arc::new(storage),
        Arc::new(dispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig {
            timeout_ms: 5000, // Explicitly large 5-second timeout configured
            ..Default::default()
        },
        [0x99u8; 32],
        "challenger_coordinator".to_string(),
    );

    let start = Instant::now();
    let (results, volatile, duration_ms) = engine
        .execute_query("zero-trust cryptographic enclaves", &vec![0.1f32; 768], 0, 10)
        .await;
    let actual_elapsed = start.elapsed();

    assert!(
        duration_ms < 250,
        "Engine reported duration {}ms exceeded 250ms limit",
        duration_ms
    );
    assert!(
        actual_elapsed < Duration::from_millis(300),
        "Actual wall-clock time {:?} exceeded 300ms limit",
        actual_elapsed
    );
    assert!(!results.is_empty(), "Must return search results");
    assert_eq!(volatile.len(), 1, "Must capture 1 volatile remote chunk");
    assert_eq!(volatile[0].peer_id, "peer_bravo");
}

// ============================================================================
// REQUIREMENT 2: DEAD / UNHEALTHY PEER RESILIENCE & STRAGGLER GRACE CLAMPING
// ============================================================================

#[tokio::test]
async fn test_empirical_dead_peer_straggler_early_resolution_with_fast_responder() {
    let dispatcher = MockMeshDispatcher::new();

    // 1. Fast peer responds in 20ms with 2 matching chunks
    dispatcher
        .add_peer(MockRemotePeer {
            peer_id: "fast_peer_1".to_string(),
            latency: Duration::from_millis(20),
            max_access_tier: 0,
            candidate_chunks: vec![
                CandidateChunkDto {
                    chunk_id: "c_fast_1".to_string(),
                    file_path: "doc1.txt".to_string(),
                    line_start: 1,
                    line_end: 5,
                    content: "Fast peer high-priority candidate chunk".to_string(),
                    score: 0.95,
                    access_tier: 0,
                    origin_peer_id: None,
                },
                CandidateChunkDto {
                    chunk_id: "c_fast_2".to_string(),
                    file_path: "doc2.txt".to_string(),
                    line_start: 1,
                    line_end: 5,
                    content: "Fast peer second candidate chunk".to_string(),
                    score: 0.89,
                    access_tier: 0,
                    origin_peer_id: None,
                },
            ],
        })
        .await;

    // 2. Slow straggler peer takes 4,500ms (near the 5,000ms deadline)
    dispatcher
        .add_peer(MockRemotePeer {
            peer_id: "straggler_peer_2".to_string(),
            latency: Duration::from_millis(4500),
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: "c_slow_1".to_string(),
                file_path: "slow.txt".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Straggler delayed content".to_string(),
                score: 0.50,
                access_tier: 0,
                origin_peer_id: None,
            }],
        })
        .await;

    // 3. Hanging dead peer takes 6,000ms (exceeds deadline)
    dispatcher
        .add_peer(MockRemotePeer {
            peer_id: "dead_peer_3".to_string(),
            latency: Duration::from_millis(6000),
            max_access_tier: 0,
            candidate_chunks: Vec::new(),
        })
        .await;

    let req = create_signed_test_request("high-priority candidate chunk");
    let requested_timeout = Duration::from_millis(5000);

    let start = Instant::now();
    let (responses, diagnostics) = dispatcher
        .query_peers_with_diagnostics(&req, requested_timeout)
        .await
        .expect("Query peers must succeed");
    let elapsed = start.elapsed();

    // Invariant: Once fast_peer_1 returned non-empty chunks, straggler grace was clamped
    // to 120ms max. Total time should be ~20ms + 120ms = ~140ms, strictly < 300ms.
    assert!(
        elapsed < Duration::from_millis(300),
        "Elapsed duration {:?} exceeded 300ms (failed to clamp straggler grace deadline!)",
        elapsed
    );

    // Fast peer responses were gathered
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].responder_peer_id, "fast_peer_1");
    assert_eq!(responses[0].chunks.len(), 2);

    // Stragglers were safely marked as TimedOut without blocking the user
    let fast_outcome = diagnostics
        .peer_outcomes
        .iter()
        .find(|o| o.peer_id == "fast_peer_1")
        .expect("fast_peer_1 outcome must exist");
    assert_eq!(fast_outcome.status, PeerQueryStatus::Connected);

    let straggler_outcome = diagnostics
        .peer_outcomes
        .iter()
        .find(|o| o.peer_id == "straggler_peer_2")
        .expect("straggler_peer_2 outcome must exist");
    assert_eq!(straggler_outcome.status, PeerQueryStatus::TimedOut);

    let dead_outcome = diagnostics
        .peer_outcomes
        .iter()
        .find(|o| o.peer_id == "dead_peer_3")
        .expect("dead_peer_3 outcome must exist");
    assert_eq!(dead_outcome.status, PeerQueryStatus::TimedOut);
}

#[tokio::test]
async fn test_empirical_dead_peer_straggler_with_zero_chunks_fast_peer() {
    let dispatcher = MockMeshDispatcher::new();

    // Fast peer returns 0 chunks in 20ms
    dispatcher
        .add_peer(MockRemotePeer {
            peer_id: "empty_fast_peer".to_string(),
            latency: Duration::from_millis(20),
            max_access_tier: 0,
            candidate_chunks: Vec::new(),
        })
        .await;

    // Straggler peer hangs for 4,000ms
    dispatcher
        .add_peer(MockRemotePeer {
            peer_id: "slow_peer_hang".to_string(),
            latency: Duration::from_millis(4000),
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: "c_slow".to_string(),
                file_path: "slow.txt".to_string(),
                line_start: 1,
                line_end: 2,
                content: "Too slow".to_string(),
                score: 0.1,
                access_tier: 0,
                origin_peer_id: None,
            }],
        })
        .await;

    let req = create_signed_test_request("empty search test");
    let start = Instant::now();
    let (responses, diagnostics) = dispatcher
        .query_peers_with_diagnostics(&req, Duration::from_millis(5000))
        .await
        .expect("Query peers must succeed");
    let elapsed = start.elapsed();

    // When 0 chunks have arrived from the first peer, straggler grace is clamped to 200ms max.
    // Total elapsed: ~20ms + 200ms = ~220ms, strictly < 350ms.
    assert!(
        elapsed < Duration::from_millis(350),
        "Elapsed duration {:?} exceeded 350ms when fast peer had 0 chunks",
        elapsed
    );

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].chunks.len(), 0);

    let empty_outcome = diagnostics
        .peer_outcomes
        .iter()
        .find(|o| o.peer_id == "empty_fast_peer")
        .unwrap();
    assert_eq!(empty_outcome.status, PeerQueryStatus::ZeroMatchingChunks);

    let slow_outcome = diagnostics
        .peer_outcomes
        .iter()
        .find(|o| o.peer_id == "slow_peer_hang")
        .unwrap();
    assert_eq!(slow_outcome.status, PeerQueryStatus::TimedOut);
}

#[test]
fn test_empirical_peer_health_registry_tracks_failures_and_evicts_dead_peers() {
    let registry = global_peer_health_registry();
    let zombie_peer = "peer_zombie_empirical_test";
    let healthy_peer = "peer_healthy_empirical_test";

    // Clear any previous state
    registry.clear_peer_failures(zombie_peer);
    registry.clear_peer_failures(healthy_peer);

    // Record 3 consecutive failures on zombie peer
    registry.record_failure(zombie_peer, "Connection refused");
    registry.record_failure(zombie_peer, "Connection reset by peer");
    registry.record_failure(zombie_peer, "Socket timeout after 5000ms");

    let zombie_stats = registry.get(zombie_peer).expect("Zombie stats must exist");
    assert_eq!(
        zombie_stats.consecutive_failures, 3,
        "Zombie peer must have exactly 3 consecutive failures"
    );

    // Record success on healthy peer
    registry.record_success(healthy_peer, 25.0, 5);
    let healthy_stats = registry.get(healthy_peer).expect("Healthy stats must exist");
    assert_eq!(healthy_stats.consecutive_failures, 0);
    assert_eq!(healthy_stats.success_count, 1);

    // Verify unhealthy peers detection
    let unhealthy = registry.unhealthy_peers(3);
    assert!(
        unhealthy.contains(&zombie_peer.to_string()),
        "Registry unhealthy_peers must identify zombie peer"
    );
    assert!(
        !unhealthy.contains(&healthy_peer.to_string()),
        "Registry unhealthy_peers must NOT flag healthy peer"
    );

    // Verify dead peer eviction logic used in SwarmMeshDispatcher:
    let mut candidate_peers = vec![zombie_peer.to_string(), healthy_peer.to_string()];
    let has_healthy = candidate_peers.iter().any(|p| {
        registry.get(p).map_or(true, |s| s.consecutive_failures < 3)
    });
    assert!(has_healthy, "Must detect presence of healthy peer");

    candidate_peers.retain(|p| {
        registry.get(p).map_or(true, |s| s.consecutive_failures < 3)
    });

    assert_eq!(
        candidate_peers,
        vec![healthy_peer.to_string()],
        "Zombie peer must be evicted from dispatch when healthy peer exists"
    );
}

// ============================================================================
// REQUIREMENT 3: SINGLE-DOC AUTHOR QUERY HOP 0 COMPLETION
// ============================================================================

#[test]
fn test_empirical_single_doc_author_query_completes_on_hop_0_without_rewrites() {
    let grader = GradeRelevanceNode::default();

    // Test multiple natural phrasing variations of author/creator queries
    let test_queries = [
        "What research papers were written by Femi Oyesanya?",
        "Who is the author of African Churches and Gang Violence?",
        "Articles authored by Femi Oyesanya",
        "Has Femi Oyesanya written any publications?",
    ];

    for query in test_queries {
        assert!(
            DeterministicOfflineSynthesisEngine::is_authorship_query(&query.to_ascii_lowercase()),
            "Query must be recognized as authorship query: '{}'",
            query
        );

        let mut state = AgenticGraphState::new(
            query,
            SynthesisModelFamily::AutoFusion,
            3, // max_hops
        );
        state.hop_count = 0; // Initial hop 0

        // Single-document state with matching author content and high cosine score
        state.retrieved_chunks = vec![make_scored_chunk(
            "chunk_african_church_1",
            "African_Churches_and_Gang_Violence.docx",
            "African Churches and Gang Violence: Community Youth Intervention Programs by Femi Oyesanya (2023).",
            0.85,
        )];

        let (grade, will_rewrite) = grader.execute(&mut state);

        assert!(
            grade.satisfactory,
            "Query '{}' over single authoritative author doc must be satisfactory on hop 0",
            query
        );
        assert!(
            grade.is_relevant,
            "Relevance must be true for query '{}'",
            query
        );
        assert!(
            !will_rewrite,
            "Hop 0 author query must NEVER trigger query rewrite loops for query '{}'",
            query
        );
        assert_eq!(state.hop_count, 0, "Hop count must remain at 0");
    }
}

#[test]
fn test_empirical_single_doc_author_query_rrf_regime_passes_hop_0() {
    let grader = GradeRelevanceNode::default();
    let query = "What books or articles did Femi Oyesanya write?";

    let mut state = AgenticGraphState::new(
        query,
        SynthesisModelFamily::AutoFusion,
        3,
    );
    state.hop_count = 0;

    // In the RRF regime (max_score <= 0.1), content match verifies the single document
    state.retrieved_chunks = vec![make_scored_chunk(
        "chunk_rrf_author",
        "Femi_Oyesanya_Monograph.pdf",
        "A comprehensive treatise written by Femi Oyesanya examining juvenile diversion programs.",
        0.01639, // 1.0 / (60 + 1)
    )];

    let (grade, will_rewrite) = grader.execute(&mut state);

    assert!(
        grade.satisfactory,
        "Single-doc author query in RRF regime with verified content match must pass"
    );
    assert!(!will_rewrite, "Must not trigger rewrite in RRF regime when content matches");
}

#[test]
fn test_empirical_author_query_fails_closed_on_unrelated_single_doc() {
    let grader = GradeRelevanceNode::default();
    let query = "What publications were authored by Femi Oyesanya?";

    let mut state = AgenticGraphState::new(
        query,
        SynthesisModelFamily::AutoFusion,
        3,
    );
    state.hop_count = 0;

    // Single document, but content is completely unrelated and low score
    state.retrieved_chunks = vec![make_scored_chunk(
        "chunk_unrelated",
        "printer_manual.txt",
        "Instructions for replacing toner cartridge and clearing paper jams in HP LaserJet.",
        0.01639,
    )];

    let (grade, will_rewrite) = grader.execute(&mut state);

    // Fail-Closed Invariant: Unrelated content must NOT get a free pass!
    assert!(
        !grade.satisfactory,
        "Unrelated single document must FAIL grading"
    );
    assert!(
        will_rewrite,
        "Unrelated single document must trigger query rewrite"
    );
}

#[tokio::test]
async fn test_empirical_agentic_state_graph_runner_author_query_hop_0_convergence() {
    let runner = AgenticStateGraphRunner::new(3, 0.60);

    // Storage contains only 1 document matching the author query
    let storage = EmpiricalMockStorage::new(vec![make_doc_chunk(
        "chunk_author_sole",
        "African_Churches_and_Gang_Violence.docx",
        "African Churches and Gang Violence: Delinquency and Church Intervention by Femi Oyesanya (2023).",
        0,
    )]);

    let engine = ScatterGatherEngine::new(
        Arc::new(storage),
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0u8; 32],
        "test_agentic_author".to_string(),
    );

    let query = "What papers were written by Femi Oyesanya?";
    let vector = vec![0.1f32; 768];

    let result = runner
        .run(
            query,
            SynthesisModelFamily::AutoFusion,
            &engine,
            &vector,
            0,
            5,
            None,
        )
        .await
        .expect("Agentic runner must complete");

    // Invariant: author query must finish on hop 0 without executing 3 futile rewrite loops!
    assert_eq!(
        result.hop_count, 0,
        "Hop count was {} but author query over single doc must complete on hop 0",
        result.hop_count
    );
    assert!(result.synthesized_response.is_some());
    let response = result.synthesized_response.unwrap();
    assert!(
        response.contains("African Churches") || response.contains("Femi Oyesanya"),
        "Synthesized response must contain authored work details"
    );
}

// ============================================================================
// REQUIREMENT 4: USCIS FORM G-28 CITATION & SOURCE FILTERING
// ============================================================================

#[test]
fn test_empirical_identity_query_filters_form_g28_and_dhs_boilerplate_from_citations_and_sources() {
    let resume_chunk_1 = make_scored_chunk(
        "chunk_resume_exec",
        "C:/Users/oyesanyf/Documents/Femi_Oyesanya_Resume_2026.docx",
        "FEMI OYESANYA, CISSP | Principal Security Architect | CyberDefense Solutions LLC.\nOver 15 years engineering enterprise zero-trust architectures and sovereign cryptographic enclaves.",
        0.98,
    );

    let resume_chunk_2 = make_scored_chunk(
        "chunk_resume_edu",
        "C:/Users/oyesanyf/Documents/Femi_Oyesanya_CV.pdf",
        "Master of Science in Information Security Architecture, WGU. Certified Information Systems Security Professional (CISSP).",
        0.94,
    );

    let g28_chunk_1 = make_scored_chunk(
        "chunk_g28_main",
        "C:/Users/oyesanyf/Downloads/Form_G-28_USCIS.pdf",
        "USCIS Form G-28 Notice of Entry of Appearance as Attorney or Accredited Representative. Department of Homeland Security. OMB No. 1615-0105. Part 1. Information About Attorney. 111 Massachusetts Avenue, NW, Washington, DC 20529. In re: Femi Oyesanya.",
        0.85,
    );

    let g28_chunk_2 = make_scored_chunk(
        "chunk_g28_instructions",
        "C:/Users/oyesanyf/Downloads/g-28_instructions.pdf",
        "Department of Homeland Security. Instructions for Notice of Entry of Appearance as Attorney or Accredited Representative. Form G-28. Eligibility Information.",
        0.80,
    );

    let dhs_notice_chunk = make_scored_chunk(
        "chunk_dhs_action",
        "C:/Users/oyesanyf/Downloads/USCIS_DHS_Notice_I797.pdf",
        "United States Citizenship and Immigration Services Form I-130 Notice of Action. Beneficiary: Femi Oyesanya. Department of Homeland Security.",
        0.75,
    );

    let candidate_chunks = vec![
        resume_chunk_1,
        resume_chunk_2,
        g28_chunk_1,
        g28_chunk_2,
        dhs_notice_chunk,
    ];

    let query = "Who is Femi Oyesanya and what are his roles and certifications?";
    let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
        query,
        &candidate_chunks,
        "offline",
    );

    // 1. Resume documents MUST be cited
    assert!(
        citations.iter().any(|c| c.file_path.contains("Resume")),
        "Resume document must be cited in citations list"
    );
    assert!(
        citations.iter().any(|c| c.file_path.contains("CV")),
        "CV document must be cited in citations list"
    );

    // 2. Form G-28 and DHS boilerplate documents MUST NEVER appear in citations
    for cit in &citations {
        let path_l = cit.file_path.to_ascii_lowercase();
        assert!(
            !path_l.contains("g-28") && !path_l.contains("g28"),
            "Citation file_path '{}' must NOT contain Form G-28",
            cit.file_path
        );
        assert!(
            !path_l.contains("uscis") && !path_l.contains("dhs"),
            "Citation file_path '{}' must NOT contain USCIS/DHS administrative notices",
            cit.file_path
        );
    }

    // 3. Body text must contain genuine biographical and professional content
    assert!(
        body.contains("Security Architect") || body.contains("CISSP"),
        "Synthesized body must describe professional roles"
    );

    // 4. Sources block in synthesized body must omit all Form G-28 references
    assert!(
        !body.contains("Form_G-28"),
        "Synthesized sources block must NOT contain Form_G-28"
    );
    assert!(
        !body.contains("Notice of Entry of Appearance"),
        "Synthesized sources block must NOT contain Notice of Entry of Appearance"
    );
    assert!(
        !body.contains("111 Massachusetts Avenue"),
        "Synthesized text must NOT contain USCIS administrative office address"
    );
}

#[test]
fn test_empirical_is_g28_or_administrative_boilerplate_positive_and_negative_matrix() {
    // Positive cases: MUST return true
    let positive_samples = [
        ("C:/docs/Form_G-28.pdf", "Notice of Entry of Appearance as Attorney"),
        ("D:/downloads/USCIS_Filing.pdf", "OMB No. 1615-0105 in re petitioner"),
        ("C:/cases/I-130_receipt.pdf", "Department of Homeland Security USCIS"),
        ("C:/docs/g28_attorney.pdf", "Part 1. Information About Attorney"),
        ("C:/docs/instructions.pdf", "Instructions for Notice of Entry of Appearance"),
        ("C:/records/agency.txt", "111 Massachusetts Avenue NW Washington DC"),
        ("C:/records/uscis_doc.pdf", "United States Citizenship and Immigration Services"),
    ];

    for (path, text) in positive_samples {
        assert!(
            DeterministicOfflineSynthesisEngine::is_g28_or_administrative_boilerplate(path, text),
            "Expected true for G-28 boilerplate: path='{}', text='{}'",
            path,
            text
        );
    }

    // Negative cases: MUST return false (prevent false positive suppression of real resumes/papers)
    let negative_samples = [
        (
            "C:/Users/oyesanyf/Documents/Resume_2026.docx",
            "Principal Security Architect with expertise adhering to federal and Homeland Security guidance.",
        ),
        (
            "C:/Users/oyesanyf/Documents/CV.pdf",
            "University of Massachusetts graduate in Computer Engineering.",
        ),
        (
            "C:/Users/oyesanyf/Research/Whitepaper.docx",
            "A decentralized protocol for verifiable sovereign quorum consensus.",
        ),
        (
            "C:/Users/oyesanyf/Documents/Employment_Contract.pdf",
            "Standard employee non-disclosure and intellectual property agreement.",
        ),
    ];

    for (path, text) in negative_samples {
        assert!(
            !DeterministicOfflineSynthesisEngine::is_g28_or_administrative_boilerplate(path, text),
            "Expected false for legitimate document: path='{}', text='{}'",
            path,
            text
        );
    }
}

// ============================================================================
// REQUIREMENT 5: SEMAPHORE-BOUNDED CONCURRENCY & DLP INSPECTION STRESS
// ============================================================================

#[tokio::test]
async fn test_empirical_semaphore_bounded_dlp_concurrent_chunk_streams_stress() {
    let controller = global_mesh_dlp_controller();
    // Ensure DLP is in Redact mode for test
    {
        let mut s = controller.settings.write().unwrap_or_else(|e| e.into_inner());
        s.mesh.p2p_enabled = true;
        s.dlp.enabled = true;
        s.dlp.mode = DlpEnforcementMode::Redact;
        s.dlp.protect_ssn = true;
        s.dlp.protect_medical_records = true;
    }

    let dispatcher = MockMeshDispatcher::new();

    // Create 4 concurrent mock peers, each streaming 8 candidate chunks (total 32 chunks per query)
    for p_idx in 0..4 {
        let peer_id = format!("peer_mesh_stress_{}", p_idx);
        let mut chunks = Vec::with_capacity(8);
        for c_idx in 0..8 {
            let content = match c_idx % 4 {
                0 => format!(
                    "Patient intake note {}-{}: John Doe with SSN: 123-45-6789 and clinical history.",
                    p_idx, c_idx
                ),
                1 => format!(
                    "Medical record entry {}-{}: MRN: MRN-987654 diagnosis ICD-10 J45.909 acute asthma.",
                    p_idx, c_idx
                ),
                2 => format!(
                    "Byzantine malformed chunk {}-{}: line_start > line_end must be dropped.",
                    p_idx, c_idx
                ),
                _ => format!(
                    "Clean technical chunk {}-{}: Distributed consensus and reciprocal rank fusion.",
                    p_idx, c_idx
                ),
            };

            // c_idx == 2 generates byzantine invalid line numbers
            let (line_start, line_end) = if c_idx % 4 == 2 {
                (20, 10) // Invalid: start > end
            } else {
                (1, 10)
            };

            chunks.push(CandidateChunkDto {
                chunk_id: format!("chunk_stress_{}_{}", p_idx, c_idx),
                file_path: format!("remote/peer_{}/file_{}.txt", p_idx, c_idx),
                line_start,
                line_end,
                content,
                score: 0.90,
                access_tier: 0,
                origin_peer_id: None,
            });
        }

        dispatcher
            .add_peer(MockRemotePeer {
                peer_id,
                latency: Duration::from_millis(15),
                max_access_tier: 0,
                candidate_chunks: chunks,
            })
            .await;
    }

    let storage = EmpiricalMockStorage::new(vec![make_doc_chunk(
        "local_storage_anchor",
        "local/doc.txt",
        "Local anchor data for concurrent scatter gather",
        0,
    )]);

    let engine = Arc::new(ScatterGatherEngine::new(
        Arc::new(storage),
        Arc::new(dispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig {
            timeout_ms: 1000,
            ..Default::default()
        },
        [0x77u8; 32],
        "stress_initiator_node".to_string(),
    ));

    // Fire 4 concurrent queries simultaneously across the engine
    let query_vector = vec![0.1f32; 768];
    let mut handles = Vec::new();

    for q_idx in 0..4 {
        let eng = Arc::clone(&engine);
        let q_vec = query_vector.clone();
        handles.push(tokio::spawn(async move {
            let start = Instant::now();
            let query_text = format!("concurrent scatter-gather test query {}", q_idx);
            let (results, volatile, dur_ms) = eng.execute_query(&query_text, &q_vec, 0, 20).await;
            (q_idx, results, volatile, dur_ms, start.elapsed())
        }));
    }

    let mut query_results = Vec::new();
    for h in handles {
        let res = h.await.expect("Concurrent query task must not panic or abort");
        query_results.push(res);
    }

    assert_eq!(query_results.len(), 4, "All 4 concurrent queries must complete");

    for (q_idx, results, volatile, dur_ms, elapsed) in query_results {
        assert!(
            elapsed < Duration::from_millis(3000),
            "Query {} took {:?}, exceeding 3000ms limit under load (deadlock/stall)",
            q_idx,
            elapsed
        );
        assert!(
            dur_ms < 3000,
            "Query {} reported dur_ms {} exceeded 3000ms",
            q_idx,
            dur_ms
        );
        assert!(!results.is_empty(), "Results must not be empty");
        assert!(!volatile.is_empty(), "Volatile chunks must not be empty");

        // Verify DLP and Byzantine filtering across all volatile chunks
        for v in &volatile {
            // 1. Raw SSN must NEVER leak in volatile memory
            assert!(
                !v.content.contains("123-45-6789"),
                "Unscrubbed SSN leaked in volatile chunk: {}",
                v.content
            );

            // 2. Raw MRN must NEVER leak in volatile memory
            assert!(
                !v.content.contains("MRN-987654"),
                "Unscrubbed MRN leaked in volatile chunk: {}",
                v.content
            );

            // 3. Byzantine malformed chunks (line_start > line_end) must have been rejected
            assert!(
                !v.content.contains("Byzantine malformed chunk"),
                "Malformed Byzantine chunk line_start > line_end was NOT rejected: {}",
                v.content
            );
        }
    }
}
