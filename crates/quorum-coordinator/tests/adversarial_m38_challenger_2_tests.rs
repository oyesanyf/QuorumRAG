//! Adversarial Edge-Case Stress Test Suite for Milestone 38 (Challenger 2).
//!
//! Evaluates Requirement R2 and High-Performance Multithreading invariants:
//! 1. Adversarial mesh queries:
//!    - 0 responsive peers, 10 dead peers -> cleanly returns 0 responses without hanging for 5,000ms.
//!    - 1 responsive peer + 5 dead peers -> immediately returns the 1 peer's response.
//!    - Saturated response threshold -> breaks immediately once `max_peer_responses` is met.
//! 2. Adversarial author grading queries:
//!    - Author name mentioned but document score < 0.1 and no content match -> rewrites/rejects, not falsely pass.
//!    - Author name match with 1 doc and score >= 0.70 -> passes on hop 0 without futile rewrite loops.
//! 3. Adversarial citation synthesis:
//!    - "G-28", "G28_Appearance", "USCIS_Notice" with boilerplate -> completely omitted when resume present.
//!    - Multiple documents with legitimate career data -> all retained with correct line numbers and citations.
//! 4. Vision model edge cases:
//!    - Fast-fail when Ollama is offline or endpoint returns error / unloaded model.

use chrono::Utc;
use quorum_coordinator::{
    agentic::grade::GradeRelevanceNode,
    mesh::{MeshQueryDispatcher, MockMeshDispatcher, MockRemotePeer},
    offline_engine::DeterministicOfflineSynthesisEngine,
    scatter_gather::{FederatedQueryCoordinator, StorageSearcher},
    types::{AgenticGraphState, SynthesisModelFamily},
    vision::describe_image_file,
};
use quorum_types::{CandidateChunkDto, DocumentChunk, FederatedQueryRequest, ScoredChunk};
use std::net::{SocketAddr, TcpListener};
use std::time::{Duration, Instant};
use uuid::Uuid;

struct MockStorage {
    chunks: Vec<ScoredChunk>,
}

#[async_trait::async_trait]
impl StorageSearcher for MockStorage {
    async fn search_hybrid(&self, _: &str, _: &[f32], _: u8, _: usize) -> Vec<ScoredChunk> {
        self.chunks.clone()
    }
}

fn make_test_request() -> FederatedQueryRequest {
    FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: "challenger_tester".to_string(),
        sender_pubkey: [0u8; 32],
        query_text: "adversarial benchmark query".to_string(),
        embedding: vec![0.1; 768],
        top_k: 10,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    }
}

fn make_chunk(id: &str, file_path: &str, text: &str, start: u32, end: u32, score: f32) -> ScoredChunk {
    let doc = DocumentChunk::new(
        id,
        "doc_id",
        file_path,
        start,
        end,
        0,
        vec![0.1; 768],
        text,
        None,
    )
    .expect("DocumentChunk construction must succeed");
    ScoredChunk::new(doc, score, "local", false)
}

// =========================================================================
// Category 1: Adversarial Mesh Query Tests
// =========================================================================

/// 1a. 0 responsive peers, 10 dead peers in MockMeshDispatcher -> cleanly returns 0 responses without hanging for 5,000ms.
#[tokio::test]
async fn test_adversarial_mesh_zero_responsive_ten_dead_peers_mock_dispatcher() {
    let dispatcher = MockMeshDispatcher::new();
    for i in 1..=10 {
        dispatcher
            .add_peer(MockRemotePeer {
                peer_id: format!("dead_peer_{}", i),
                latency: Duration::from_millis(2),
                max_access_tier: 0,
                candidate_chunks: vec![],
            })
            .await;
    }

    let req = make_test_request();
    let start = Instant::now();
    let (responses, diag) = dispatcher
        .query_peers_with_diagnostics(&req, Duration::from_millis(5000))
        .await
        .expect("Query must succeed");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(300),
        "0 responsive peers must resolve in < 300ms without waiting for 5,000ms deadline; took: {:?}",
        elapsed
    );
    assert_eq!(
        responses.iter().map(|r| r.chunks.len()).sum::<usize>(),
        0,
        "0 chunks must be returned from 10 dead peers"
    );
    assert_eq!(
        diag.queried_peers_count, 10,
        "All 10 dead peers must be tracked in diagnostics"
    );
}

/// 1b. 0 responsive peers, 10 hanging/partitioned peers in ScatterGatherEngine -> cleanly completes in <= 450ms (governed by 400ms deadline), never 5,000ms.
#[tokio::test]
async fn test_adversarial_mesh_zero_responsive_ten_hanging_peers_scatter_gather() {
    let mut coordinator = FederatedQueryCoordinator::new(MockStorage { chunks: vec![] });
    for i in 1..=10 {
        coordinator.add_peer(MockRemotePeer {
            peer_id: format!("hanging_peer_{}", i),
            latency: Duration::from_millis(6000 + i as u64 * 500),
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: format!("stale_{}", i),
                file_path: format!("dead/doc_{}.txt", i),
                line_start: 1,
                line_end: 10,
                access_tier: 0,
                score: 0.99,
                content: "Stale data that should never be returned".to_string(),
            }],
        });
    }

    let start = Instant::now();
    let (results, volatile, duration_ms) = coordinator
        .execute_query("test query", &vec![0.1; 768], 0, 10)
        .await;
    let elapsed = start.elapsed();

    assert!(
        duration_ms <= 450,
        "ScatterGatherEngine must complete within 450ms, took {}ms",
        duration_ms
    );
    assert!(
        elapsed < Duration::from_millis(600),
        "Query with 10 dead/hanging peers must cleanly cancel at 400ms deadline, never hang for 5,000ms; took: {:?}",
        elapsed
    );
    assert!(
        results.is_empty(),
        "Results must be completely empty when local storage and remote peers are dead"
    );
    assert!(
        volatile.is_empty(),
        "Volatile container must be empty from 10 hanging peers"
    );
}

/// 1c. 1 responsive peer + 5 dead peers -> immediately returns the 1 peer's response without waiting out 5,000ms.
#[tokio::test]
async fn test_adversarial_mesh_one_responsive_five_dead_peers_immediate_return() {
    let dispatcher = MockMeshDispatcher::new();
    dispatcher
        .add_peer(MockRemotePeer {
            peer_id: "peer_honest_fast".to_string(),
            latency: Duration::from_millis(20),
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: "honest_chunk_1".to_string(),
                file_path: "authoritative/valid.pdf".to_string(),
                line_start: 1,
                line_end: 10,
                content: "Authoritative candidate content from honest peer".to_string(),
                score: 0.92,
                access_tier: 0,
            }],
        })
        .await;

    // 5 Dead peers (10,000ms latency - silent drop / hung socket)
    for i in 1..=5 {
        dispatcher
            .add_peer(MockRemotePeer {
                peer_id: format!("peer_hung_{}", i),
                latency: Duration::from_millis(10_000),
                max_access_tier: 0,
                candidate_chunks: vec![],
            })
            .await;
    }

    let req = make_test_request();
    let start = Instant::now();
    let (responses, diag) = dispatcher
        .query_peers_with_diagnostics(&req, Duration::from_millis(5000))
        .await
        .expect("Query must succeed");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(300),
        "Query with 1 fast peer and 5 dead peers must resolve within straggler grace (<300ms), took: {:?}",
        elapsed
    );
    assert_eq!(
        responses.len(), 1,
        "Must return exactly the 1 responsive peer's response"
    );
    assert_eq!(
        responses[0].responder_peer_id, "peer_honest_fast",
        "Response must originate from the responsive peer"
    );
    assert_eq!(
        responses[0].chunks.len(), 1,
        "Must preserve the candidate chunk from the honest peer"
    );

    let timed_out_count = diag
        .peer_outcomes
        .iter()
        .filter(|o| matches!(o.status, quorum_types::PeerQueryStatus::TimedOut))
        .count();
    assert_eq!(
        timed_out_count, 5,
        "All 5 dead peers must be recorded as TimedOut in diagnostics"
    );
}

/// 1d. Saturated response threshold -> must break immediately once `max_peer_responses` is met.
#[tokio::test]
async fn test_adversarial_mesh_saturated_response_threshold_immediate_break() {
    let dispatcher = MockMeshDispatcher::new();
    // Register 14 peers, each responding quickly (10ms)
    for i in 1..=14 {
        dispatcher
            .add_peer(MockRemotePeer {
                peer_id: format!("peer_batch_{}", i),
                latency: Duration::from_millis(10),
                max_access_tier: 0,
                candidate_chunks: vec![CandidateChunkDto {
                    chunk_id: format!("batch_chunk_{}", i),
                    file_path: format!("batch/doc_{}.txt", i),
                    line_start: 1,
                    line_end: 5,
                    content: format!("Batch document {} content", i),
                    score: 0.85,
                    access_tier: 0,
                }],
            })
            .await;
    }

    let req = make_test_request();
    let start = Instant::now();
    let (responses, _) = dispatcher
        .query_peers_with_diagnostics(&req, Duration::from_millis(5000))
        .await
        .expect("Query must succeed");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(200),
        "Saturated response query must break immediately without straggler wait; took: {:?}",
        elapsed
    );
    // Default max_peer_responses is 8
    assert_eq!(
        responses.len(),
        8,
        "Must cap exactly at max_peer_responses (8) and break immediately"
    );
}

// =========================================================================
// Category 2: Adversarial Author Grading Queries
// =========================================================================

/// 2a. Edge case: author name mentioned but document score < 0.1 and no content match -> must rewrite or reject, not falsely pass.
#[test]
fn test_adversarial_author_grading_score_below_point_one_no_content_rewrites() {
    let grader = GradeRelevanceNode::default();
    let prompt = "Who is the author of this paper? Has Dr. Aris Thorne written any articles?";
    let mut state = AgenticGraphState::new(
        prompt,
        SynthesisModelFamily::AutoFusion,
        3,
    );

    // Completely unrelated chunk with low RRF score (0.04) and zero author/research terms
    let unrelated_chunk = make_chunk(
        "unrelated_tax_chunk",
        "corporate/financials_2024.pdf",
        "Quarterly fiscal accounting ledger and corporate amortized tax returns for FY2024.",
        1,
        20,
        0.04,
    );
    state.retrieved_chunks = vec![unrelated_chunk];

    let (grade, will_rewrite) = grader.execute(&mut state);

    assert!(
        !grade.satisfactory,
        "Chunk with score < 0.1 and no content match MUST NOT satisfy author query"
    );
    assert!(
        !grade.is_relevant,
        "RelevanceGrade::is_relevant must be false for unrelated content"
    );
    assert!(
        will_rewrite,
        "State machine must schedule a query rewrite on hop 0 when content is unrelated"
    );
    assert!(
        grade.reasoning.contains("failed content relevance check"),
        "Reasoning must record content relevance failure: {}",
        grade.reasoning
    );
}

/// 2b. Author name match with 1 doc and score >= 0.70 -> must pass on hop 0 without triggering futile rewrite loops.
#[test]
fn test_adversarial_author_grading_single_doc_match_score_ge_70_passes_hop_0() {
    let grader = GradeRelevanceNode::default();
    let prompt = "What publications has Dr. Aris Thorne authored?";
    let mut state = AgenticGraphState::new(
        prompt,
        SynthesisModelFamily::AutoFusion,
        3,
    );

    // Single authoritative document with cosine score 0.78 (>= 0.70)
    let author_doc_chunk = make_chunk(
        "author_paper_1",
        "research/distributed_consensus_thorne.pdf",
        "Dr. Aris Thorne is the primary author of 'Byzantine Fault Tolerance in Asymmetric Networks' and 'ZeroizeOnDrop Memory Scrubbing'.",
        1,
        15,
        0.78,
    );
    state.retrieved_chunks = vec![author_doc_chunk];

    let (grade, will_rewrite) = grader.execute(&mut state);

    assert!(
        grade.satisfactory,
        "Single authoritative document with score >= 0.70 MUST pass author query on hop 0"
    );
    assert!(
        grade.is_relevant,
        "RelevanceGrade::is_relevant must be true"
    );
    assert!(
        !will_rewrite,
        "Must NOT schedule rewrite loops when single doc satisfies author query on hop 0"
    );
    assert!(
        grade.reasoning.contains("meets threshold"),
        "Reasoning must confirm threshold was met: {}",
        grade.reasoning
    );
}

/// 2c. Author query with 1 doc in RRF score regime (< 0.1) but verified content match -> passes hop 0 via RRF content check.
#[test]
fn test_adversarial_author_grading_single_doc_content_match_rrf_passes() {
    let grader = GradeRelevanceNode::default();
    let prompt = "Has Dr. Aris Thorne written any articles on cryptography?";
    let mut state = AgenticGraphState::new(
        prompt,
        SynthesisModelFamily::AutoFusion,
        3,
    );

    // Single document with score 0.03 (RRF regime) but matching terms
    let rrf_matching_chunk = make_chunk(
        "rrf_thorne_article",
        "papers/quantum_cryptography.pdf",
        "Dr. Aris Thorne has written multiple articles on post-quantum lattice cryptography and Kyber key encapsulation.",
        5,
        25,
        0.03,
    );
    state.retrieved_chunks = vec![rrf_matching_chunk];

    let (grade, will_rewrite) = grader.execute(&mut state);

    assert!(
        grade.satisfactory,
        "Single document with matching content in RRF regime MUST pass hop 0"
    );
    assert!(
        !will_rewrite,
        "Must NOT rewrite when RRF content match is verified"
    );
}

// =========================================================================
// Category 3: Adversarial Citation Synthesis
// =========================================================================

/// 3a. Document names containing "G-28", "G28_Appearance", "USCIS_Notice" with boilerplate text
/// must be completely omitted from citations and sources when a resume document is present.
#[test]
fn test_adversarial_citation_g28_and_uscis_boilerplate_omitted_when_resume_present() {
    let resume_chunk = make_chunk(
        "resume_chunk_1",
        "C:/Users/Candidate/Documents/Jane_Doe_Resume_2026.pdf",
        "Jane Doe | Senior Distributed Systems Architect | 10+ years experience building consensus engines, Raft, and LanceDB storage. Work Experience: Principal Architect at EdgeTech.",
        1,
        45,
        0.98,
    );

    let g28_chunk = make_chunk(
        "g28_chunk_1",
        "C:/Users/Candidate/Downloads/Form_G-28_USCIS.pdf",
        "Department of Homeland Security USCIS Form G-28 Notice of Entry of Appearance as Attorney or Accredited Representative. OMB No. 1615-0105. Part 1 Information About Attorney.",
        1,
        60,
        0.88,
    );

    let g28_appearance_chunk = make_chunk(
        "g28_appearance_chunk_1",
        "C:/Users/Candidate/Downloads/G28_Appearance_Notice.pdf",
        "Notice of Entry of Appearance as Attorney or Accredited Representative. Mail to: 111 Massachusetts Avenue, NW, Washington, DC 20529.",
        1,
        35,
        0.87,
    );

    let uscis_notice_chunk = make_chunk(
        "uscis_notice_chunk_1",
        "C:/Users/Candidate/Downloads/USCIS_Notice_Receipt.pdf",
        "Department of Homeland Security United States Citizenship and Immigration Services receipt notice I-130 Petition for Alien Relative.",
        1,
        25,
        0.86,
    );

    let all_chunks = vec![
        &resume_chunk,
        &g28_chunk,
        &g28_appearance_chunk,
        &uscis_notice_chunk,
    ];

    // 1. Verify build_deduplicated_citations completely purges all G-28 and USCIS boilerplate
    let citations = DeterministicOfflineSynthesisEngine::build_deduplicated_citations(&all_chunks);
    assert_eq!(
        citations.len(),
        1,
        "Only the resume document must survive citation filtering when G-28/USCIS notices are present"
    );
    assert!(
        citations[0].file_path.contains("Jane_Doe_Resume_2026.pdf"),
        "Retained citation must be the resume document, got: {}",
        citations[0].file_path
    );
    assert_eq!(citations[0].line_start, 1);
    assert_eq!(citations[0].line_end, 45);

    // 2. Verify format_sources_block completely purges all G-28 and USCIS boilerplate
    let sources_block = DeterministicOfflineSynthesisEngine::format_sources_block(&all_chunks);
    assert!(
        sources_block.contains("Jane_Doe_Resume_2026.pdf"),
        "Sources block must reference the resume document"
    );
    assert!(
        !sources_block.contains("G-28")
            && !sources_block.contains("G28")
            && !sources_block.contains("USCIS_Notice")
            && !sources_block.contains("111 Massachusetts"),
        "Sources block must omit all G-28 and administrative notices, got:\n{}",
        sources_block
    );
}

/// 3b. Multiple documents with legitimate career data -> must all be retained with correct line numbers and citations.
#[test]
fn test_adversarial_citation_multiple_legitimate_career_documents_all_retained() {
    let doc1_resume = make_chunk(
        "c_career_1",
        "C:/Portfolio/Jane_Doe_Resume.pdf",
        "Professional Summary: Lead Infrastructure Engineer. Work Experience at CloudScale (2020-2026).",
        10,
        50,
        0.95,
    );

    let doc2_portfolio = make_chunk(
        "c_career_2",
        "C:/Portfolio/Architect_Case_Studies.docx",
        "Curriculum Vitae & Case Studies: Architectural deep-dive on LanceDB columnar indexing and Tantivy BM25.",
        25,
        80,
        0.91,
    );

    let doc3_bio = make_chunk(
        "c_career_3",
        "C:/Portfolio/Executive_Biography.pdf",
        "Career Summary and Biographical Profile: Jane Doe is a recognized contributor to rust-libp2p and consensus protocols.",
        5,
        30,
        0.89,
    );

    let doc4_g28 = make_chunk(
        "c_g28_noise",
        "C:/Downloads/Form_G-28_Immigration.pdf",
        "Department of Homeland Security Form G-28 Notice of Entry of Appearance. Instructions for Notice of Entry.",
        1,
        40,
        0.85,
    );

    let candidate_chunks = vec![&doc1_resume, &doc2_portfolio, &doc3_bio, &doc4_g28];
    let citations = DeterministicOfflineSynthesisEngine::build_deduplicated_citations(&candidate_chunks);

    // Invariant 1: Exactly 3 legitimate career documents retained, G-28 filtered
    assert_eq!(
        citations.len(),
        3,
        "All 3 legitimate career documents must be retained in citations; G-28 must be filtered"
    );

    // Invariant 2: G-28 must NOT be in citations
    assert!(
        !citations.iter().any(|c| c.file_path.contains("G-28") || c.file_path.contains("G28")),
        "G-28 document must be completely filtered"
    );

    // Invariant 3: Line numbers must be preserved exactly for all 3 retained career documents
    let cit1 = citations.iter().find(|c| c.file_path.contains("Resume")).unwrap();
    assert_eq!(cit1.line_start, 10);
    assert_eq!(cit1.line_end, 50);

    let cit2 = citations.iter().find(|c| c.file_path.contains("Case_Studies")).unwrap();
    assert_eq!(cit2.line_start, 25);
    assert_eq!(cit2.line_end, 80);

    let cit3 = citations.iter().find(|c| c.file_path.contains("Biography")).unwrap();
    assert_eq!(cit3.line_start, 5);
    assert_eq!(cit3.line_end, 30);
}

// =========================================================================
// Category 4: Vision Model Edge Cases
// =========================================================================

/// 4a. Fast-fail when Ollama is offline (closed port) -> returns false in < 200ms and describe_image_file returns None in < 900ms.
#[test]
fn test_adversarial_vision_offline_ollama_fast_fails() {
    let closed_addr: SocketAddr = "127.0.0.1:59998".parse().unwrap();
    let host_port = "127.0.0.1:59998";

    // 1. is_model_warm_in_ollama must fast-fail in < 200ms
    let start_warm = Instant::now();
    let warm = DeterministicOfflineSynthesisEngine::is_model_warm_in_ollama(&closed_addr, host_port, "llava:7b");
    let elapsed_warm = start_warm.elapsed();

    assert!(!warm, "Offline Ollama must return is_model_warm == false");
    assert!(
        elapsed_warm < Duration::from_millis(250),
        "is_model_warm_in_ollama must fast-fail in < 250ms when port closed, took: {:?}",
        elapsed_warm
    );

    // 2. describe_image_file on offline endpoint must return None in < 900ms (connect_timeout is 800ms)
    let temp_dir = tempfile::tempdir().expect("tempdir creation must succeed");
    let img_path = temp_dir.path().join("test_sample.jpg");
    std::fs::write(&img_path, vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01])
        .expect("Image write must succeed");

    let start_desc = Instant::now();
    let desc = describe_image_file(&closed_addr, host_port, "llava:7b", &img_path, "describe image");
    let elapsed_desc = start_desc.elapsed();

    assert!(desc.is_none(), "Offline Ollama must return None for image description");
    assert!(
        elapsed_desc < Duration::from_millis(900),
        "describe_image_file must fast-fail in < 900ms when offline, took: {:?}",
        elapsed_desc
    );
}

/// 4b. When Ollama /api/ps reports an unloaded model (empty list), is_model_warm_in_ollama returns false immediately.
#[test]
fn test_adversarial_vision_unloaded_model_returns_false_immediately() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral loopback");
    let local_addr = listener.local_addr().expect("Local addr must resolve");
    let host_port = local_addr.to_string();

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::{Read, Write};
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let resp = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"models\":[]}";
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let start = Instant::now();
    let is_warm = DeterministicOfflineSynthesisEngine::is_model_warm_in_ollama(&local_addr, &host_port, "llava:7b");
    let elapsed = start.elapsed();

    assert!(!is_warm, "Unloaded vision model must return is_model_warm == false");
    assert!(
        elapsed < Duration::from_millis(250),
        "Unloaded check must return in < 250ms, took: {:?}",
        elapsed
    );
}

/// 4c. When Ollama /api/generate returns HTTP 500 or 404, describe_image_file immediately returns None without blocking.
#[test]
fn test_adversarial_vision_http_500_or_404_fast_fails_to_none() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral loopback");
    let local_addr = listener.local_addr().expect("Local addr must resolve");
    let host_port = local_addr.to_string();

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::{Read, Write};
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let resp = "HTTP/1.0 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{\"error\":\"model 'llava:7b' failed to allocate VRAM\"}";
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let temp_dir = tempfile::tempdir().expect("tempdir creation must succeed");
    let img_path = temp_dir.path().join("test_error_img.jpg");
    std::fs::write(&img_path, vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01])
        .expect("Image write must succeed");

    let start = Instant::now();
    let desc = describe_image_file(&local_addr, &host_port, "llava:7b", &img_path, "describe");
    let elapsed = start.elapsed();

    assert!(desc.is_none(), "HTTP 500 error must return None for description");
    assert!(
        elapsed < Duration::from_millis(200),
        "HTTP 500 must fast-fail in < 200ms, took: {:?}",
        elapsed
    );
}

/// 4d. Non-image queries with image chunks present in candidate pool skip vision inspection without incurring vision timeouts.
#[test]
fn test_adversarial_vision_non_image_query_zero_overhead() {
    let img_chunk = make_chunk(
        "image_chunk_1",
        "C:/Users/Candidate/Pictures/diagram.png",
        "[Image Document: diagram.png] System architecture diagram showing LanceDB and Tantivy nodes.",
        1,
        1,
        0.85,
    );

    let text_chunk = make_chunk(
        "text_chunk_1",
        "C:/Users/Candidate/Documents/Jane_Doe_Resume.pdf",
        "Work Experience: Senior Architect with deep expertise in distributed storage and consensus.",
        1,
        30,
        0.95,
    );

    let start = Instant::now();
    // Query does NOT ask about images: asks_image == false
    let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "What is Jane Doe's work experience?",
        &[text_chunk, img_chunk],
        "offline",
    );
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(2000),
        "Non-image query must execute in under 2.0s without incurring 2.5s vision socket timeouts; took: {:?}",
        elapsed
    );
    assert!(!body.is_empty(), "Body must be synthesized");
    assert!(!citations.is_empty(), "Citations must be present");
}
