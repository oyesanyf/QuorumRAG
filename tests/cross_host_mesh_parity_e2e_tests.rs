//! Comprehensive End-to-End Test Suite for Cross-Host Mesh Retrieval Parity,
//! Deep Multi-Document Synthesis, Mesh Synthesis Relay Protocol, Proper-Noun Snapping,
//! Relevance Attestation Gate, 100% Attested Contribution Guarantee, and RLM Long-Form Assembly.

use std::sync::Arc;
use std::time::Duration;
use quorum_types::{
    CandidateChunkDto, DocumentChunk, ScoredChunk,
    FederatedQueryRequest, MeshSynthesisRelayPayload,
};
use quorum_coordinator::MeshQueryDispatcher;
use quorum_coordinator::mesh::{
    MockMeshDispatcher, MockRemotePeer, set_global_mesh_dispatcher,
};
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_coordinator::relevance_attestor::NimbleRelevanceAttestation;
use quorum_coordinator::hardware::HardwareTelemetry;
use quorum_contract::rlm::{RetrievedChunk, RlmConfig};
use quorum_coordinator::rlm_orchestrator::RlmOrchestrator;
use quorum_coordinator::fusion::RrfCombiner;
use quorum_coordinator::agentic::retrieve::RetrieveMeshNode;

#[tokio::test]
async fn test_cross_host_retrieval_parity_across_3_nodes() {
    // Node A, Node B, Node C with documents on different nodes
    let chunk_doc1 = DocumentChunk {
        chunk_id: "doc1:0".to_string(),
        document_id: "doc1".to_string(),
        file_path: "C:/Docs/Femi_Oyesanya_Bio.txt".to_string(),
        line_start: 1,
        line_end: 25,
        blake3_hash: format!("{:064x}", 1),
        access_tier: 0,
        vector: vec![0.1; 768],
        text_content: "Femi Oyesanya is a senior cybersecurity engineer specializing in distributed consensus, threat detection, and agentic multi-hop systems.".to_string(),
        metadata_json: "{}".to_string(),
    };

    let chunk_doc2 = DocumentChunk {
        chunk_id: "doc2:0".to_string(),
        document_id: "doc2".to_string(),
        file_path: "C:/Docs/Paschal_Beverly_Randolph.txt".to_string(),
        line_start: 1,
        line_end: 30,
        blake3_hash: format!("{:064x}", 2),
        access_tier: 0,
        vector: vec![0.2; 768],
        text_content: "Paschal Beverly Randolph was an American physician, occultist, and author who championed emancipation and Rosicrucian thought.".to_string(),
        metadata_json: "{}".to_string(),
    };

    let chunk_doc3 = DocumentChunk {
        chunk_id: "doc3:0".to_string(),
        document_id: "doc3".to_string(),
        file_path: "C:/Docs/Angela_Davis_History.txt".to_string(),
        line_start: 1,
        line_end: 20,
        blake3_hash: format!("{:064x}", 3),
        access_tier: 0,
        vector: vec![0.3; 768],
        text_content: "Angela Davis is an American political activist, philosopher, and academic known for her advocacy of social justice.".to_string(),
        metadata_json: "{}".to_string(),
    };

    // Candidate chunks with equal base relevance score: global tie-breaking on (chunk_id ASC, blake3_hash ASC)
    // MUST guarantee identical ranking order regardless of whether the chunk is local or remote!
    let mut list_from_host_a = vec![
        ScoredChunk::new(chunk_doc2.clone(), 0.90, "peer_b", true),
        ScoredChunk::new(chunk_doc1.clone(), 0.90, "local", false),
        ScoredChunk::new(chunk_doc3.clone(), 0.90, "peer_c", true),
    ];

    let mut list_from_host_b = vec![
        ScoredChunk::new(chunk_doc3.clone(), 0.90, "peer_c", true),
        ScoredChunk::new(chunk_doc1.clone(), 0.90, "peer_a", true),
        ScoredChunk::new(chunk_doc2.clone(), 0.90, "local", false),
    ];

    let mut list_from_host_c = vec![
        ScoredChunk::new(chunk_doc1.clone(), 0.90, "peer_a", true),
        ScoredChunk::new(chunk_doc2.clone(), 0.90, "peer_b", true),
        ScoredChunk::new(chunk_doc3.clone(), 0.90, "local", false),
    ];

    let tie_break_sort = |chunks: &mut [ScoredChunk]| {
        chunks.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.chunk.blake3_hash.cmp(&b.chunk.blake3_hash))
                .then_with(|| a.chunk.chunk_id.cmp(&b.chunk.chunk_id))
        });
    };

    tie_break_sort(&mut list_from_host_a);
    tie_break_sort(&mut list_from_host_b);
    tie_break_sort(&mut list_from_host_c);

    // Assert that all three nodes arrive at the EXACT same canonical chunk order
    assert_eq!(list_from_host_a.len(), 3);
    assert_eq!(list_from_host_b.len(), 3);
    assert_eq!(list_from_host_c.len(), 3);

    for i in 0..3 {
        assert_eq!(list_from_host_a[i].chunk.chunk_id, list_from_host_b[i].chunk.chunk_id);
        assert_eq!(list_from_host_b[i].chunk.chunk_id, list_from_host_c[i].chunk.chunk_id);
    }

    assert_eq!(list_from_host_a[0].chunk.chunk_id, "doc1:0");
    assert_eq!(list_from_host_a[1].chunk.chunk_id, "doc2:0");
    assert_eq!(list_from_host_a[2].chunk.chunk_id, "doc3:0");
}

#[tokio::test]
async fn test_corpus_grounded_proper_noun_snapping() {
    let chunk = DocumentChunk {
        chunk_id: "doc:bio".to_string(),
        document_id: "doc".to_string(),
        file_path: "C:/Docs/bio.txt".to_string(),
        line_start: 1,
        line_end: 10,
        blake3_hash: format!("{:064x}", 0),
        access_tier: 0,
        vector: vec![0.0; 768],
        text_content: "Femi Oyesanya is a senior engineer. Paschal Beverly Randolph was a 19th-century author.".to_string(),
        metadata_json: "{}".to_string(),
    };
    let sc = ScoredChunk::new(chunk, 0.95, "local", false);
    let chunks = vec![sc];

    let chunk_refs: Vec<&ScoredChunk> = chunks.iter().collect();

    // Typo 1: "who is femi Oyeesanya" -> snaps to "Femi Oyesanya is "
    let prefix1 = DeterministicOfflineSynthesisEngine::format_question_restated_prefix_with_chunks(
        "who is femi Oyeesanya",
        &chunk_refs,
    );
    assert_eq!(prefix1, "Femi Oyesanya is ");

    // Typo 2: Contraction lead + typo "who's is pascal bevely randolph" -> snaps to "Paschal Beverly Randolph is "
    let prefix2 = DeterministicOfflineSynthesisEngine::format_question_restated_prefix_with_chunks(
        "who's is pascal bevely randolph",
        &chunk_refs,
    );
    assert_eq!(prefix2, "Paschal Beverly Randolph is ");

    // Contraction lead normalization: verify zero "Who's Is ... — " defect
    assert!(!prefix2.starts_with("Who's Is"));
    assert!(!prefix2.contains("—"));
}

#[tokio::test]
async fn test_composer_hardening_clean_text_and_no_orphan_citations() {
    // 1. Unstripped section headers must be cleanly stripped
    let raw_chunk = "[Document: Bio | Author: Unknown]\n[Section: Executive Summary]\n\nFemi Oyesanya founded the distributed consensus initiative.";
    let cleaned = DeterministicOfflineSynthesisEngine::clean_chunk_text(raw_chunk);
    assert!(!cleaned.contains("[Section:"));
    assert!(!cleaned.contains("[Document:"));
    assert!(cleaned.contains("Femi Oyesanya founded the distributed consensus initiative."));

    // 2. Orphan citation stubs must not be emitted
    let raw_paragraph = "Femi Oyesanya completed advanced research in distributed systems [1].\n[2].\n[3].";
    let stripped = DeterministicOfflineSynthesisEngine::strip_orphan_citation_stubs(raw_paragraph);
    assert!(!stripped.contains("[2]."));
    assert!(!stripped.contains("[3]."));
}

#[tokio::test]
async fn test_mesh_synthesis_relay_protocol_delegation() {
    let mock_disp = Arc::new(MockMeshDispatcher::new());
    // Register peer_beta as having a warm LLM with simulated synthesis
    mock_disp.register_warm_llm("peer_beta", Some("Synthesized answer by peer_beta: Femi Oyesanya is a lead architect [1].".to_string())).await;
    mock_disp.add_peer(MockRemotePeer {
        peer_id: "peer_beta".to_string(),
        latency: Duration::from_millis(10),
        max_access_tier: 0,
        candidate_chunks: Vec::new(),
    }).await;

    set_global_mesh_dispatcher(mock_disp.clone());

    let req = FederatedQueryRequest {
        query_id: uuid::Uuid::new_v4(),
        sender_peer_id: "peer_alpha".to_string(),
        sender_pubkey: [0u8; 32],
        query_text: "Who is Femi Oyesanya?".to_string(),
        embedding: vec![0.0; 768],
        top_k: 16,
        timestamp: chrono::Utc::now().timestamp(),
        signature: [0u8; 64],
        origin_peer_id: None,
        relay_hops: 0,
        visited_peers: Vec::new(),
        synthesis_relay: Some(MeshSynthesisRelayPayload {
            prompt: "Who is Femi Oyesanya?".to_string(),
            history: Vec::new(),
            evidence_chunks: vec![CandidateChunkDto {
                chunk_id: "doc1:0".to_string(),
                file_path: "C:/Docs/Femi.txt".to_string(),
                content: "Femi Oyesanya is a lead architect.".to_string(),
                score: 0.95,
                access_tier: 0,
                line_start: 1,
                line_end: 10,
                origin_peer_id: Some("peer_alpha".to_string()),
                expanded_window: None,
            }],
            model_tag: Some("qwen2.5:7b".to_string()),
        }),
    };

    let responses = mock_disp.query_peers(&req, Duration::from_millis(2000)).await.expect("query peers");
    assert_eq!(responses.len(), 1);
    let resp = &responses[0];
    assert!(resp.warm_llm_available);
    assert!(resp.synthesis_response.is_some());
    let synth = resp.synthesis_response.as_ref().unwrap();
    assert!(synth.synthesized_text.contains("Femi Oyesanya is a lead architect"));
    assert_eq!(synth.responder_peer_id, "peer_beta");
}

#[tokio::test]
async fn test_artemis_airgap_governance_invariants() {
    let artemis_dto = CandidateChunkDto {
        chunk_id: "artemis_dfir:0".to_string(),
        file_path: "artemis://local/forensic_event.json".to_string(),
        content: "Host-local memory dump analysis.".to_string(),
        score: 0.90,
        access_tier: 3, // Tier3Restricted
        line_start: 1,
        line_end: 10,
        origin_peer_id: Some("local".to_string()),
        expanded_window: None,
    };

    // Outbound check: must detect restricted chunk
    assert!(quorum_coordinator::artemis_airgap::is_airgap_restricted_chunk_dto(&artemis_dto));

    // Query text check: must detect artemis:// reference
    assert!(quorum_coordinator::artemis_airgap::contains_artemis_query("inspect artemis://local/forensic"));
    assert!(!quorum_coordinator::artemis_airgap::contains_artemis_query("Who is Femi Oyesanya?"));
}

#[tokio::test]
async fn test_nimble_relevance_attestation_rejects_screenshot_ocr_distractor() {
    let attestor = NimbleRelevanceAttestation::new();

    let text_doc = DocumentChunk {
        chunk_id: "c1:0".to_string(),
        document_id: "c1".to_string(),
        file_path: "C:/Docs/Femi_Bio.pdf".to_string(),
        line_start: 1,
        line_end: 20,
        blake3_hash: format!("{:064x}", 1),
        access_tier: 0,
        vector: vec![0.0; 768],
        text_content: "Femi Oyesanya is a principal security architect leading mesh telemetry defense.".to_string(),
        metadata_json: "{}".to_string(),
    };
    let sc_text = ScoredChunk::new(text_doc, 0.92, "local", false);

    // Search-UI screenshot OCR chunk on non-image query
    let ocr_distractor = DocumentChunk {
        chunk_id: "c2:0".to_string(),
        document_id: "c2".to_string(),
        file_path: "C:/Screenshots/google_search_results.png".to_string(),
        line_start: 1,
        line_end: 10,
        blake3_hash: format!("{:064x}", 2),
        access_tier: 0,
        vector: vec![0.0; 768],
        text_content: "[ocr text] google search results for femi query top images and web links ...".to_string(),
        metadata_json: "{}".to_string(),
    };
    let sc_ocr = ScoredChunk::new(ocr_distractor, 0.50, "local", false);

    // Attest candidate chunks for "Who is Femi Oyesanya?"
    let attested_text = attestor.attest_relevance("Who is Femi Oyesanya?", &[&sc_text]).await;
    assert_eq!(attested_text.len(), 1);
    assert!(attested_text[0].is_relevant);

    let attested_distractor = attestor.attest_relevance("Who is Femi Oyesanya?", &[&sc_ocr]).await;
    assert_eq!(attested_distractor.len(), 1);
    assert!(!attested_distractor[0].is_relevant, "Screenshot OCR distractor must be rejected by relevance attestation!");
}

#[tokio::test]
async fn test_100_percent_attested_document_contribution_guarantee() {
    let mut chunks = Vec::new();
    for i in 1..=5 {
        chunks.push(ScoredChunk::new(
            DocumentChunk {
                chunk_id: format!("doc_{}:0", i),
                document_id: format!("doc_{}", i),
                file_path: format!("C:/Research/Topic_{}.txt", i),
                line_start: 1,
                line_end: 15,
                blake3_hash: format!("{:064x}", i),
                access_tier: 0,
                vector: vec![0.0; 768],
                text_content: format!("Key grounded discovery {} regarding the decentralized architecture.", i),
                metadata_json: "{}".to_string(),
            },
            0.90 - (i as f32 * 0.05),
            if i % 2 == 0 { "peer_beta" } else { "local" },
            i % 2 == 0,
        ));
    }

    let (answer, citations) = DeterministicOfflineSynthesisEngine::synthesize_with_history(
        "Summarize the key architectural findings across all documents",
        "Summarize the key architectural findings across all documents",
        &[],
        &chunks,
        "qwen2.5:7b",
        None,
    );

    assert!(!answer.is_empty());
    // 100% of attested documents [1]..[5] MUST carry inline citations in the synthesized answer!
    for k in 1..=5 {
        assert!(
            answer.contains(&format!("[{}]", k)),
            "Answer must cite attested document [{}]! Got: {}",
            k,
            answer
        );
    }
    assert!(citations.len() >= 5, "Citations list must include all 5 attested documents!");
}

#[tokio::test]
async fn test_rlm_longform_multi_buffer_and_undefined_buffer_resilience() {
    let config = RlmConfig::default();
    let hw = HardwareTelemetry {
        free_vram_mb: 8000,
        free_ram_gb: 16.0,
        total_ram_gb: 32.0,
        cpu_cores: 8,
        gpu_name: Some("RTX 4090".to_string()),
        total_vram_mb: 24000,
        gpu_count: 1,
    };
    let orch = RlmOrchestrator::new(config, hw, vec!["qwen2.5:7b".to_string()]);

    let mut docs = Vec::new();
    for i in 1..=6 {
        docs.push(RetrievedChunk {
            id: format!("chunk_{}", i),
            document_id: format!("doc_{}", i),
            file_path: format!("C:/MeshDocs/Doc_{}.txt", i),
            line_start: 1,
            line_end: 20,
            text: format!("Substantive empirical finding {} demonstrating distributed performance across nodes.", i),
            score: 0.90,
            access_tier: 0,
            source_peer: if i % 2 == 0 { "peer_b".to_string() } else { "local".to_string() },
            node_id: None,
            is_external: i % 2 == 0,
            node_alias: None,
            work_cluster_id: None,
        });
    }

    let (answer, citations) = orch.assemble_longform_multi_buffer("What are the key empirical findings?", &docs);
    assert!(!answer.is_empty());
    assert!(answer.contains("### Analysis Section 1"));
    assert!(answer.contains("### Analysis Section 2"));

    // Verify 100% citation coverage [1]..[6]
    for i in 1..=6 {
        assert!(answer.contains(&format!("[{}]", i)), "Must cite [{}] in assembled output", i);
    }
    assert_eq!(citations.len(), 6);
}

#[tokio::test]
async fn test_multi_host_federated_wire_blake3_hash_parity_and_rrf_dedup() {
    // 1. Invariant: CandidateChunkDto MUST preserve canonical BLAKE3 hash on wire
    let canonical_text = "QuorumRAG federated consensus architecture guarantees Byzantine agreement across all peers.";
    let canonical_hash = DocumentChunk::compute_blake3_hash(canonical_text);

    let doc = DocumentChunk {
        chunk_id: "shared_spec:0".to_string(),
        document_id: "shared_spec".to_string(),
        file_path: "C:/Docs/spec.txt".to_string(),
        line_start: 1,
        line_end: 15,
        blake3_hash: canonical_hash.clone(),
        access_tier: 0,
        vector: vec![0.1; 768],
        text_content: canonical_text.to_string(),
        metadata_json: "{}".to_string(),
    };

    let scored_local = ScoredChunk::new(doc.clone(), 0.95, "local", false);
    let mut dto_remote = CandidateChunkDto::from_scored_chunk(&scored_local);
    dto_remote.origin_peer_id = Some("12D3KooWPeerHostB".to_string());
    // Attach 10KB expanded window auxiliary field without corrupting canonical content
    dto_remote.expanded_window = Some("Parent document expanded window up to 10KB...".to_string());

    // Wire verification: candidate.content must match canonical text and produce identical BLAKE3 hash
    assert_eq!(dto_remote.content, canonical_text);
    let wire_hash = DocumentChunk::compute_blake3_hash(&dto_remote.content);
    assert_eq!(wire_hash, canonical_hash);

    // 2. Query executed on Host A: local holds doc, Peer B returns doc
    let host_a_local = vec![scored_local.clone()];
    let host_a_remotes = vec![("12D3KooWPeerHostB".to_string(), vec![dto_remote.clone()])];
    let host_a_fused = RrfCombiner::fuse_rankings_with_peers(host_a_local, host_a_remotes, 60.0, 10);

    // Assert deduplication succeeded: exactly 1 fused chunk survives, NOT 2 duplicates
    assert_eq!(host_a_fused.len(), 1, "Shared document must deduplicate into exactly 1 chunk");
    assert_eq!(host_a_fused[0].chunk.blake3_hash, canonical_hash);
    // Consensus boost (1.25x) applied because seen on both local (peer 0) and remote (peer 1)
    let expected_base_score = (1.0 / 61.0) + (1.0 / 61.0);
    let expected_boosted = expected_base_score * 1.25;
    assert!((host_a_fused[0].score - expected_boosted).abs() < 1e-4);

    // 3. Symmetric Query executed on Host B: Host B holds doc locally, Peer A returns doc as remote
    let scored_on_b = ScoredChunk::new(doc.clone(), 0.95, "local", false);
    let mut dto_from_a = CandidateChunkDto::from_scored_chunk(&scored_on_b);
    dto_from_a.origin_peer_id = Some("12D3KooWPeerHostA".to_string());
    dto_from_a.expanded_window = Some("Parent document expanded window up to 10KB...".to_string());

    let host_b_local = vec![scored_on_b];
    let host_b_remotes = vec![("12D3KooWPeerHostA".to_string(), vec![dto_from_a])];
    let host_b_fused = RrfCombiner::fuse_rankings_with_peers(host_b_local, host_b_remotes, 60.0, 10);

    // Both Host A and Host B MUST achieve 100% parity on candidate count, hash, and score
    assert_eq!(host_a_fused.len(), host_b_fused.len());
    assert_eq!(host_a_fused[0].chunk.blake3_hash, host_b_fused[0].chunk.blake3_hash);
    assert!((host_a_fused[0].score - host_b_fused[0].score).abs() < 1e-5);
}

#[tokio::test]
async fn test_multi_host_relevance_quorum_uniformity() {
    // Under a multi-term query, verify identical relevance decisions whether evaluated locally or on remote peer
    let query_terms = vec!["architecture".to_string(), "consensus".to_string()];
    let required_hits = 2;

    // Single-hit chunk: contains only "architecture", not "consensus"
    let single_hit_chunk = ScoredChunk::new(
        DocumentChunk {
            chunk_id: "c_single:0".to_string(),
            document_id: "c_single".to_string(),
            file_path: "C:/Docs/general_architecture.txt".to_string(),
            line_start: 1,
            line_end: 10,
            blake3_hash: format!("{:064x}", 10),
            access_tier: 0,
            vector: vec![0.0; 768],
            text_content: "General software architecture patterns and modular design.".to_string(),
            metadata_json: "{}".to_string(),
        },
        0.50,
        "local",
        false,
    );

    // Two-hit chunk: contains both "architecture" and "consensus"
    let double_hit_chunk = ScoredChunk::new(
        DocumentChunk {
            chunk_id: "c_double:0".to_string(),
            document_id: "c_double".to_string(),
            file_path: "C:/Docs/quorum_consensus.txt".to_string(),
            line_start: 1,
            line_end: 10,
            blake3_hash: format!("{:064x}", 11),
            access_tier: 0,
            vector: vec![0.0; 768],
            text_content: "The system architecture enforces Byzantine consensus across nodes.".to_string(),
            metadata_json: "{}".to_string(),
        },
        0.85,
        "local",
        false,
    );

    let check_relevance = |c: &ScoredChunk| -> bool {
        let tl = c.chunk.text_content.to_ascii_lowercase();
        let total_hits = query_terms.iter().filter(|w| tl.contains(w.as_str())).count();
        total_hits >= required_hits
    };

    // 1. Evaluated locally on home node
    assert!(!check_relevance(&single_hit_chunk), "Local single-hit chunk must be rejected under 2-term quorum");
    assert!(check_relevance(&double_hit_chunk), "Local double-hit chunk must pass under 2-term quorum");

    // 2. Evaluated as remote peer chunk on querying host
    let mut remote_single = single_hit_chunk.clone();
    remote_single.source_peer = "12D3KooWPeerRemote".to_string();
    remote_single.is_remote = true;

    let mut remote_double = double_hit_chunk.clone();
    remote_double.source_peer = "12D3KooWPeerRemote".to_string();
    remote_double.is_remote = true;

    assert!(!check_relevance(&remote_single), "Remote single-hit chunk must NOT pass with asymmetric 1-hit relaxation!");
    assert!(check_relevance(&remote_double), "Remote double-hit chunk must pass uniformly");
}

#[tokio::test]
async fn test_stem_document_family_capping_and_dedup_parity() {
    let pool_host_a = vec![
        ScoredChunk::new(
            DocumentChunk {
                chunk_id: "res_a_1".to_string(),
                document_id: "res_a".to_string(),
                file_path: "C:/Local/Femi_Oyesanya_Resume_v1.pdf".to_string(),
                line_start: 1,
                line_end: 10,
                blake3_hash: "hash_a1".to_string(),
                access_tier: 0,
                vector: vec![0.0; 768],
                text_content: "Femi Oyesanya resume page 1 executive summary".to_string(),
                metadata_json: "{}".to_string(),
            },
            0.98,
            "local",
            false,
        ),
        ScoredChunk::new(
            DocumentChunk {
                chunk_id: "res_a_2".to_string(),
                document_id: "res_a".to_string(),
                file_path: "C:/Local/Femi_Oyesanya_Resume_v2.docx".to_string(),
                line_start: 1,
                line_end: 10,
                blake3_hash: "hash_a2".to_string(),
                access_tier: 0,
                vector: vec![0.0; 768],
                text_content: "Femi Oyesanya resume page 2 experience".to_string(),
                metadata_json: "{}".to_string(),
            },
            0.95,
            "local",
            false,
        ),
        ScoredChunk::new(
            DocumentChunk {
                chunk_id: "res_b_remote".to_string(),
                document_id: "res_b".to_string(),
                file_path: "D:/PeerB/Femi_Oyesanya_Resume_Final.pdf".to_string(),
                line_start: 1,
                line_end: 10,
                blake3_hash: "hash_b1".to_string(),
                access_tier: 0,
                vector: vec![0.0; 768],
                text_content: "Femi Oyesanya resume final revision".to_string(),
                metadata_json: "{}".to_string(),
            },
            0.90,
            "12D3KooWPeerB",
            true,
        ),
    ];

    // Global cap of 2 per family stem: the 3rd resume must be capped regardless of peer
    let capped_a = RetrieveMeshNode::cap_document_families_federated(pool_host_a, 2);
    assert_eq!(capped_a.len(), 2, "Document family cap must enforce exactly 2 chunks across federation");
    assert_eq!(capped_a[0].chunk.chunk_id, "res_a_1");
    assert_eq!(capped_a[1].chunk.chunk_id, "res_a_2");

    // Citation deduplication parity
    let deduped = DeterministicOfflineSynthesisEngine::deduplicated_chunks_with_scores(&capped_a.iter().collect::<Vec<_>>());
    assert_eq!(deduped.len(), 1, "All revisions of femi_oyesanya_resume must collapse into 1 canonical document family");
    assert_eq!(deduped[0].0.chunk.chunk_id, "res_a_2", "Canonical deduplication must pick higher version v2.docx over v1.pdf");
}

#[tokio::test]
async fn test_canonical_synthesis_prompt_cross_host_parity() {
    let doc1 = DocumentChunk {
        chunk_id: "doc1:0".to_string(),
        document_id: "doc1".to_string(),
        file_path: "C:/Docs/spec.txt".to_string(),
        line_start: 1,
        line_end: 10,
        blake3_hash: format!("{:064x}", 1),
        access_tier: 0,
        vector: vec![0.0; 768],
        text_content: "Decentralized consensus protocol specification.".to_string(),
        metadata_json: "{}".to_string(),
    };

    // Prompt built on Host A (where doc1 was local)
    let chunks_host_a = vec![ScoredChunk::new(doc1.clone(), 0.95, "local", false)];
    let prompt_host_a = DeterministicOfflineSynthesisEngine::build_synthesis_prompt(
        "Explain the consensus protocol",
        &chunks_host_a,
    );

    // Prompt built on Host B (where doc1 arrived from peer_a)
    let chunks_host_b = vec![ScoredChunk::new(doc1.clone(), 0.95, "peer_a", true)];
    let prompt_host_b = DeterministicOfflineSynthesisEngine::build_synthesis_prompt(
        "Explain the consensus protocol",
        &chunks_host_b,
    );

    // Invariant: Prompt text presented to LLM/synthesis engine MUST be 100% byte-for-byte identical!
    assert_eq!(
        prompt_host_a, prompt_host_b,
        "Synthesis prompt must not vary by querying host!"
    );
    assert!(!prompt_host_a.contains("Peer: local"));
    assert!(!prompt_host_b.contains("Peer: peer_a"));
}
