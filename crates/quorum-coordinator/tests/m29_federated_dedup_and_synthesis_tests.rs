//! Unit & Integration Test Suite for Milestone M29:
//! Federation-Wide Document Family Deduplication & Ollama 16K/1500 Token Synthesis Parameters.

use quorum_coordinator::agentic::retrieve::RetrieveMeshNode;
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_types::{DocumentChunk, ScoredChunk};
use regex::Regex;

fn make_scored_chunk(
    chunk_id: &str,
    file_path: &str,
    text: &str,
    source_peer: &str,
    score: f32,
) -> ScoredChunk {
    let doc_chunk = DocumentChunk::new(
        chunk_id,
        "doc_candidate",
        file_path,
        1,
        50,
        0,
        vec![0.1f32; 768],
        text,
        None,
    )
    .expect("DocumentChunk creation must succeed");

    ScoredChunk::new(doc_chunk, score, source_peer, source_peer != "local")
}

#[test]
fn test_federated_document_family_deduplication_cross_nodes() {
    // Simulate candidate chunks returned across local and 3 remote mesh peers
    let mut candidate_pool: Vec<ScoredChunk> = Vec::new();

    // 5 revisions of the "femi_oyesanya_resume" family scattered across 4 distinct nodes
    candidate_pool.push(make_scored_chunk(
        "c_local_v1",
        "C:/Users/femi/Femi_Oyesanya_Resume_v1.pdf",
        "Executive Summary: Information Security Architect with 15+ years experience in zero trust.",
        "local",
        0.98,
    ));
    candidate_pool.push(make_scored_chunk(
        "c_local_v2",
        "C:/Users/femi/Femi_Oyesanya_Resume_v2.pdf",
        "Professional Experience: Lead Architect designing cryptographic mesh protocols.",
        "local",
        0.95,
    ));
    candidate_pool.push(make_scored_chunk(
        "c_peer1_final",
        "D:/Peers/Alice/Femi_Oyesanya_Resume_Final.docx",
        "Education: Master of Science in Information Security Architecture.",
        "12D3KooWPeerAlice",
        0.94,
    ));
    candidate_pool.push(make_scored_chunk(
        "c_peer2_copy",
        "E:/Peers/Bob/Femi_Oyesanya_Resume (1).pdf",
        "Certifications: CISSP, SABSA Chartered Architect, CISM.",
        "12D3KooWPeerBob",
        0.92,
    ));
    candidate_pool.push(make_scored_chunk(
        "c_peer3_draft",
        "Z:/Peers/Charlie/Femi_Oyesanya_Resume_draft.pdf",
        "Core Competencies: Distributed Byzantine fault tolerance, Rust, Linux kernel.",
        "12D3KooWPeerCharlie",
        0.90,
    ));

    // 3 revisions of the "redactx_technical_report" family across 3 nodes
    candidate_pool.push(make_scored_chunk(
        "c_local_rx_v1",
        "C:/Users/femi/RedactX_Technical_Report_v1.pdf",
        "RedactX Architecture: Real-time clinical redaction pipeline utilizing local LLMs.",
        "local",
        0.88,
    ));
    candidate_pool.push(make_scored_chunk(
        "c_peer1_rx_v2",
        "D:/Peers/Alice/RedactX_Technical_Report_v2.pdf",
        "Empirical benchmarks: 99.4% precision on HIPAA Safe Harbor identifier redaction.",
        "12D3KooWPeerAlice",
        0.87,
    ));
    candidate_pool.push(make_scored_chunk(
        "c_peer2_rx_final",
        "E:/Peers/Bob/RedactX_Technical_Report_Final.pdf",
        "Deployment Guide: Air-gapped deployment in hospital enclave networks.",
        "12D3KooWPeerBob",
        0.85,
    ));

    // 1 chunk of an independent document family ("autonomous_consensus_spec")
    candidate_pool.push(make_scored_chunk(
        "c_peer3_auto",
        "Z:/Peers/Charlie/Autonomous_Consensus_Spec.pdf",
        "Autonomous consensus protocol specification for federated peer discovery.",
        "12D3KooWPeerCharlie",
        0.80,
    ));

    assert_eq!(candidate_pool.len(), 9, "Initial pool must contain 9 candidate chunks");

    // Cap document families federated (global cap = 2 per family stem)
    let capped = RetrieveMeshNode::cap_document_families_federated(candidate_pool, 2);

    let mut family_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for c in &capped {
        let stem = DeterministicOfflineSynthesisEngine::normalize_file_stem(&c.chunk.file_path);
        *family_counts.entry(stem).or_insert(0) += 1;
    }

    // Verify "femi_oyesanya_resume" is strictly capped at 2 across the entire federation (not 5!)
    assert_eq!(
        family_counts.get("femi_oyesanya_resume"),
        Some(&2),
        "Resume family must be capped at exactly 2 excerpts across all local and remote nodes"
    );

    // Verify "redactx_technical_report" is strictly capped at 2 across the entire federation (not 3!)
    assert_eq!(
        family_counts.get("redactx_technical_report"),
        Some(&2),
        "RedactX report family must be capped at exactly 2 excerpts across all local and remote nodes"
    );

    // Verify independent family is preserved
    assert_eq!(
        family_counts.get("autonomous_consensus_spec"),
        Some(&1),
        "Independent document family must be retained"
    );

    // Total retained chunks must be exactly 2 + 2 + 1 = 5
    assert_eq!(
        capped.len(),
        5,
        "Federation-wide deduplication must prevent revisions from crowding out search diversity: expected 5, got {}",
        capped.len()
    );
}

#[test]
fn test_dedup_near_identical_excerpts_cross_peer_120_char_collapse() {
    let opening_text = "Femi Oyesanya is an independent researcher evaluating live clinical redaction pipelines across hospital notes in secure environments.";

    let c_local = make_scored_chunk(
        "p1_local",
        "C:/Users/femi/RedactX_v1.pdf",
        opening_text,
        "local",
        0.95,
    );
    let c_peer_alice = make_scored_chunk(
        "p1_alice",
        "D:/Peers/Alice/RedactX_v2.pdf",
        opening_text,
        "12D3KooWPeerAlice",
        0.93,
    );
    let c_peer_bob = make_scored_chunk(
        "p1_bob",
        "E:/Peers/Bob/RedactX_Final.pdf",
        opening_text,
        "12D3KooWPeerBob",
        0.91,
    );
    let c_distinct = make_scored_chunk(
        "p2_local",
        "C:/Users/femi/RedactX_v1.pdf",
        "Methodology: We benchmarked throughput and latency across multiple CPU and GPU discrete configurations.",
        "local",
        0.88,
    );

    let refs = vec![&c_local, &c_peer_alice, &c_peer_bob, &c_distinct];

    let deduped = DeterministicOfflineSynthesisEngine::dedup_near_identical_excerpts(refs);

    // 3 duplicate excerpts across 3 different peers must collapse into 1, while distinct excerpt is preserved
    assert_eq!(
        deduped.len(),
        2,
        "Near-identical opening text across 3 distinct peers must collapse to 1 entry: got {}",
        deduped.len()
    );

    assert!(deduped.iter().any(|c| c.chunk.chunk_id == "p1_local"));
    assert!(deduped.iter().any(|c| c.chunk.chunk_id == "p2_local"));
}

#[test]
fn test_ollama_chat_options_num_ctx_and_num_predict() {
    // Verify that low requested context and predict tokens are automatically scaled to M29 minimums
    let options_low = DeterministicOfflineSynthesisEngine::build_ollama_chat_options(0.1, 256, 4096);
    assert_eq!(
        options_low["num_ctx"].as_u64(),
        Some(16384),
        "num_ctx must be at least 16384"
    );
    assert_eq!(
        options_low["num_predict"].as_u64(),
        Some(1500),
        "num_predict must be at least 1500"
    );

    // Verify that higher values (e.g. 32K context or 4K predict) are preserved
    let options_high = DeterministicOfflineSynthesisEngine::build_ollama_chat_options(0.1, 4096, 32768);
    assert_eq!(
        options_high["num_ctx"].as_u64(),
        Some(32768),
        "num_ctx >= 16384 must be preserved"
    );
    assert_eq!(
        options_high["num_predict"].as_u64(),
        Some(4096),
        "num_predict >= 1500 must be preserved"
    );
}

#[test]
fn test_ollama_chat_system_prompt_requirements() {
    let prompt = DeterministicOfflineSynthesisEngine::build_ollama_chat_system_prompt("");

    assert!(
        prompt.contains("multi-paragraph"),
        "System prompt must explicitly require multi-paragraph responses"
    );
    assert!(
        prompt.contains("[N]") || prompt.contains("[1]"),
        "System prompt must mandate bracketed inline citations [N]"
    );
    assert!(
        prompt.contains("grounded sources") || prompt.contains("source documents"),
        "System prompt must mandate grounding in source documents"
    );
    assert!(
        prompt.contains("QUESTION-RESTATING OPENING"),
        "System prompt must mandate question-restating opening"
    );
}

#[test]
fn test_deterministic_langextract_fallback_when_offline() {
    let chunk1 = make_scored_chunk(
        "chunk_femi_1",
        "C:/Users/femi/Femi_Oyesanya_Resume.docx",
        "FEMI OYESANYA | 122 East Ave | 708.359.1414 | oyesanyf@gmail.com\n\
         Phone: (708) 359-1414\n\
         Email: oyesanyf@gmail.com\n\
         Femi Oyesanya is a Distinguished Enterprise Security Architect with 15+ years of experience engineering zero-trust architectures and sovereign enclaves.\n\
         Recognized for authoring novel decentralized quorum consensus protocols, Byzantine-fault-tolerant telemetry networks, and post-quantum cryptographic migration frameworks.",
        "local",
        0.98,
    );

    let chunk2 = make_scored_chunk(
        "chunk_femi_2",
        "C:/Users/femi/Femi_Oyesanya_CV_2026.pdf",
        "EDUCATION & CREDENTIALS\n\
         Master of Science in Information Security Architecture from Western Governors University.\n\
         CISSP-certified cybersecurity leader specializing in enterprise defense systems and AI security architectures.",
        "local",
        0.94,
    );

    let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "who is Femi Oyesanya",
        &[chunk1, chunk2],
        "offline",
    );

    println!("=== Synthesized Fallback Body ===\n{}\n===============================", body);

    // 1. Must NOT collapse into pipe-delimited contact template
    let contact_template_regex = Regex::new(r"(?i)is a .*[|@].*").expect("valid regex");
    assert!(
        !contact_template_regex.is_match(&body),
        "CRITICAL: Fallback collapsed into contact header template: {}",
        body
    );

    // 2. Bare contact lines and headers must not be present in body prose
    assert!(
        !body.contains("122 East Ave | 708.359.1414"),
        "Bare contact bar must be filtered out of body prose"
    );

    // 3. Substantive multi-sentence body paragraphs must be synthesized
    assert!(
        body.contains("Distinguished Enterprise Security Architect"),
        "Must contain substantive role synthesis: {}",
        body
    );
    assert!(
        body.contains("Master of Science in Information Security Architecture"),
        "Must contain education credentials from second chunk: {}",
        body
    );
    assert!(
        body.contains("CISSP-certified"),
        "Must contain CISSP credential: {}",
        body
    );

    // 4. Sources block with clean citations must be attached
    assert_eq!(citations.len(), 2, "Both distinct document citations must be preserved");
    assert!(body.contains("### 📚 Sources & Document Links"));
    assert!(body.contains("[📄 Femi_Oyesanya_Resume.docx]"));
    assert!(body.contains("[📄 Femi_Oyesanya_CV_2026.pdf]"));
}
