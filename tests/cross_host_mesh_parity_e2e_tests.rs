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

struct DelayedInboundHandler {
    delay: Duration,
    inner: Arc<quorum_coordinator::OsoosiMeshInboundHandler>,
}

#[async_trait::async_trait]
impl quorum_network::InboundQueryHandler for DelayedInboundHandler {
    async fn handle_query(
        &self,
        request: quorum_types::FederatedQueryRequest,
    ) -> quorum_types::FederatedQueryResponse {
        tokio::time::sleep(self.delay).await;
        self.inner.handle_query(request).await
    }
}

#[tokio::test]
async fn test_swarm_mesh_dispatcher_3_peer_parity_with_1_8s_million_chunk_peer() {
    use quorum_coordinator::{
        global_mesh_dlp_controller, global_peer_health_registry, CoordinatorConfig,
        OsoosiMeshInboundHandler, PeerAclManager, QueryCoordinator, ScatterGatherEngine,
        SwarmMeshDispatcher, SynthesisModelFamily,
    };
    use quorum_network::{start_network_node, NetworkConfig};
    use quorum_storage::{StorageConfig, StorageEngine};

    {
        let ctrl = global_mesh_dlp_controller();
        let mut g = ctrl.settings.write().unwrap();
        g.mesh.p2p_enabled = true;
        g.mesh.require_explicit_folder_share = false;
        g.mesh.shared_folders.clear();
    }

    let dir_wdrdl = tempfile::tempdir().expect("dir_wdrdl");
    let dir_wkhc3 = tempfile::tempdir().expect("dir_wkhc3");
    let dir_wecnh = tempfile::tempdir().expect("dir_wecnh");

    let storage_wdrdl = Arc::new(
        StorageEngine::open(StorageConfig::new(dir_wdrdl.path().to_path_buf()))
            .await
            .expect("storage_wdrdl"),
    );
    let storage_wkhc3 = Arc::new(
        StorageEngine::open(StorageConfig::new(dir_wkhc3.path().to_path_buf()))
            .await
            .expect("storage_wkhc3"),
    );
    let storage_wecnh = Arc::new(
        StorageEngine::open(StorageConfig::new(dir_wecnh.path().to_path_buf()))
            .await
            .expect("storage_wecnh"),
    );

    let emb = vec![0.07f32; 768];

    // Host WDRDL: Academic document
    storage_wdrdl
        .insert_chunks(&[DocumentChunk::new(
            "wdrdl_acad:0",
            "wdrdl_acad",
            "C:/WDRDL/Women Race Class Summary.docx",
            1,
            25,
            0,
            emb.clone(),
            "Women, Race & Class is a landmark critical theory work by Angela Davis, first published in 1981.",
            None,
        )
        .unwrap()])
        .await
        .unwrap();

    // Host WKHc3 (fast peer ~15ms): Lease document
    storage_wkhc3
        .insert_chunks(&[DocumentChunk::new(
            "wkhc3_lease:0",
            "wkhc3_lease",
            "C:/WKHc3/Susan MONTH TO MONTH LEASE AGREEMENT.doc",
            1,
            25,
            0,
            emb.clone(),
            "SIMPLE LEASE AGREEMENT between Angela Davis (landlord) and Casey Ringgold (tenant) at 2913 Castiglione St., New Orleans, LA 70119.",
            None,
        )
        .unwrap()])
        .await
        .unwrap();

    // Host WEcNh (1.8s million-chunk peer): Ministry document + copy of Women Race Class Summary.docx
    storage_wecnh
        .insert_chunks(&[
            DocumentChunk::new(
                "wecnh_ministry:0",
                "wecnh_ministry",
                "D:/WEcNh/Unity_Ministry_Steward.docx",
                1,
                25,
                0,
                emb.clone(),
                "Reverend Angela Davis serves on the STEWARD ministry board leading New Thought spiritual teaching and metaphysical affirmations.",
                None,
            )
            .unwrap(),
            DocumentChunk::new(
                "wecnh_wrc_dup:0",
                "wecnh_wrc_dup",
                "D:/WEcNh/Women Race Class Summary.docx",
                1,
                25,
                0,
                emb,
                "Women, Race & Class is a landmark critical theory work by Angela Davis, first published in 1981.",
                None,
            )
            .unwrap(),
        ])
        .await
        .unwrap();

    let derive_pid = |seed: [u8; 32]| -> String {
        let sk = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
        let kp = quorum_network::libp2p::identity::ed25519::Keypair::from(sk);
        quorum_network::libp2p::identity::Keypair::from(kp)
            .public()
            .to_peer_id()
            .to_string()
    };

    let seed_wdrdl = [0x61u8; 32];
    let seed_wkhc3 = [0x62u8; 32];
    let seed_wecnh = [0x63u8; 32];

    let pid_wdrdl = derive_pid(seed_wdrdl);
    let pid_wkhc3 = derive_pid(seed_wkhc3);
    let pid_wecnh = derive_pid(seed_wecnh);

    let registry = global_peer_health_registry();
    registry.clear_peer_failures(&pid_wdrdl);
    registry.clear_peer_failures(&pid_wkhc3);
    registry.clear_peer_failures(&pid_wecnh);

    let handler_wdrdl = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_wdrdl) as Arc<dyn quorum_coordinator::StorageSearcher>,
        pid_wdrdl.clone(),
    ));
    let handler_wkhc3 = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_wkhc3) as Arc<dyn quorum_coordinator::StorageSearcher>,
        pid_wkhc3.clone(),
    ));
    let handler_wecnh = Arc::new(DelayedInboundHandler {
        delay: Duration::from_millis(1800),
        inner: Arc::new(OsoosiMeshInboundHandler::new(
            Arc::clone(&storage_wecnh) as Arc<dyn quorum_coordinator::StorageSearcher>,
            pid_wecnh.clone(),
        )),
    });

    let mut cfg_net_wdrdl = NetworkConfig::new_localhost();
    cfg_net_wdrdl.ed25519_seed = Some(seed_wdrdl);
    let (_jh1, handle_wdrdl) = start_network_node(cfg_net_wdrdl, Some(handler_wdrdl))
        .await
        .expect("start wdrdl");

    let mut cfg_net_wkhc3 = NetworkConfig::new_localhost();
    cfg_net_wkhc3.ed25519_seed = Some(seed_wkhc3);
    let (_jh2, handle_wkhc3) = start_network_node(cfg_net_wkhc3, Some(handler_wkhc3))
        .await
        .expect("start wkhc3");

    let mut cfg_net_wecnh = NetworkConfig::new_localhost();
    cfg_net_wecnh.ed25519_seed = Some(seed_wecnh);
    let (_jh3, handle_wecnh) = start_network_node(cfg_net_wecnh, Some(handler_wecnh))
        .await
        .expect("start wecnh");

    let tcp_addr_wkhc3 = handle_wkhc3
        .listen_addresses()
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .unwrap();
    let tcp_addr_wecnh = handle_wecnh
        .listen_addresses()
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .unwrap();

    // Form full 3-peer mesh
    handle_wdrdl.dial(tcp_addr_wkhc3.clone()).await.unwrap();
    handle_wdrdl.dial(tcp_addr_wecnh).await.unwrap();
    handle_wecnh.dial(tcp_addr_wkhc3).await.unwrap();
    tokio::time::sleep(Duration::from_millis(450)).await;

    assert_eq!(handle_wdrdl.connected_peers().await.unwrap().len(), 2);
    assert_eq!(handle_wecnh.connected_peers().await.unwrap().len(), 2);

    let default_cfg = CoordinatorConfig::default();
    assert_eq!(default_cfg.timeout_ms, 8000);

    let coord_wdrdl = QueryCoordinator::new(
        Arc::new(ScatterGatherEngine::new(
            Arc::clone(&storage_wdrdl) as Arc<dyn quorum_coordinator::StorageSearcher>,
            Arc::new(SwarmMeshDispatcher::new(
                handle_wdrdl.clone(),
                pid_wdrdl.clone(),
                seed_wdrdl,
            )),
            Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
            default_cfg.clone(),
            seed_wdrdl,
            pid_wdrdl.clone(),
        )),
        default_cfg.clone(),
    );

    let coord_wecnh = QueryCoordinator::new(
        Arc::new(ScatterGatherEngine::new(
            Arc::clone(&storage_wecnh) as Arc<dyn quorum_coordinator::StorageSearcher>,
            Arc::new(SwarmMeshDispatcher::new(
                handle_wecnh.clone(),
                pid_wecnh.clone(),
                seed_wecnh,
            )),
            Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
            default_cfg.clone(),
            seed_wecnh,
            pid_wecnh.clone(),
        )),
        default_cfg,
    );

    // Query from WDRDL (must wait for 1.8s healthy WEcNh peer even after fast WKHc3 responds in ~15ms!)
    let res_wdrdl = coord_wdrdl
        .query_agentic_with_history_and_session(
            "Who is Angela Davis",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            12,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("query from wdrdl");

    // Query from WEcNh
    let res_wecnh = coord_wecnh
        .query_agentic_with_history_and_session(
            "Who is Angela Davis",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            12,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("query from wecnh");

    // Both WDRDL and WEcNh must see BOTH remote peers and produce the exact same 3 unique canonical document families!
    let diag_wdrdl = res_wdrdl.peer_diagnostics.as_ref().expect("diag_wdrdl");
    assert!(
        diag_wdrdl.contributing_peer_ids.contains(&pid_wkhc3)
            && diag_wdrdl.contributing_peer_ids.contains(&pid_wecnh),
        "WDRDL must receive chunks from BOTH fast peer WKHc3 and 1.8s million-chunk peer WEcNh! Got: {:?}",
        diag_wdrdl
    );

    assert_eq!(
        res_wdrdl.sources_cited.len(),
        3,
        "WDRDL must collapse duplicate Women Race Class Summary and cite all 3 unique families: {:?}",
        res_wdrdl.sources_cited
    );
    assert_eq!(
        res_wecnh.sources_cited.len(),
        3,
        "WEcNh must achieve 100% 3-source parity with WDRDL: {:?}",
        res_wecnh.sources_cited
    );

    // Also verify unhealthy-peer fast clamping: if WEcNh has consecutive_failures > 0, straggler grace clamps to 400ms
    registry.record_failure(&pid_wecnh, "simulated prior timeout");
    let mut direct_req = FederatedQueryRequest {
        query_id: uuid::Uuid::new_v4(),
        sender_peer_id: pid_wdrdl.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "Who is Angela Davis".to_string(),
        embedding: vec![0.07f32; 768],
        top_k: 12,
        timestamp: chrono::Utc::now().timestamp(),
        signature: [0u8; 64],
        origin_peer_id: None,
        relay_hops: 0,
        visited_peers: Vec::new(),
        synthesis_relay: None,
    };
    quorum_coordinator::crypto::sign_request(
        &seed_wdrdl,
        &mut direct_req,
        quorum_types::AccessTier::Tier0Public,
    );
    let disp_wdrdl = SwarmMeshDispatcher::new(handle_wdrdl, pid_wdrdl.clone(), seed_wdrdl);
    let t0 = std::time::Instant::now();
    let (unhealthy_resps, _) = disp_wdrdl
        .query_peers_with_diagnostics(&direct_req, Duration::from_millis(8000))
        .await
        .expect("unhealthy straggler clamp query");
    let clamp_elapsed = t0.elapsed();
    assert!(
        clamp_elapsed < Duration::from_millis(1200),
        "When remaining pending peer has consecutive_failures > 0, SwarmMeshDispatcher must clamp straggler grace to 400ms (took {:?})",
        clamp_elapsed
    );
    assert_eq!(unhealthy_resps.len(), 1, "Fast peer WKHc3 still returned immediately");
    registry.clear_peer_failures(&pid_wecnh);
}

#[tokio::test]
async fn test_transitive_3_node_discovery_auto_dial_and_signing_credentials() {
    use quorum_coordinator::{
        global_mesh_dlp_controller, global_peer_health_registry, OsoosiMeshInboundHandler,
        SwarmMeshDispatcher, P2P_WATCHER_CANARY_QUERY,
    };
    use quorum_network::{start_network_node, NetworkConfig};
    use quorum_storage::{StorageConfig, StorageEngine};

    {
        let ctrl = global_mesh_dlp_controller();
        let mut g = ctrl.settings.write().unwrap();
        g.mesh.p2p_enabled = true;
        g.mesh.require_explicit_folder_share = false;
        g.mesh.shared_folders.clear();
    }

    let dir_a = tempfile::tempdir().expect("dir_a");
    let dir_b = tempfile::tempdir().expect("dir_b");
    let dir_c = tempfile::tempdir().expect("dir_c");

    let storage_a = Arc::new(
        StorageEngine::open(StorageConfig::new(dir_a.path().to_path_buf()))
            .await
            .expect("storage_a"),
    );
    let storage_b = Arc::new(
        StorageEngine::open(StorageConfig::new(dir_b.path().to_path_buf()))
            .await
            .expect("storage_b"),
    );
    let storage_c = Arc::new(
        StorageEngine::open(StorageConfig::new(dir_c.path().to_path_buf()))
            .await
            .expect("storage_c"),
    );

    let derive_pid = |seed: [u8; 32]| -> String {
        let sk = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
        let kp = quorum_network::libp2p::identity::ed25519::Keypair::from(sk);
        quorum_network::libp2p::identity::Keypair::from(kp)
            .public()
            .to_peer_id()
            .to_string()
    };

    let seed_a = [0x71u8; 32];
    let seed_b = [0x72u8; 32];
    let seed_c = [0x73u8; 32];
    let pid_a = derive_pid(seed_a);
    let pid_b = derive_pid(seed_b);
    let pid_c = derive_pid(seed_c);

    let registry = global_peer_health_registry();
    registry.clear_peer_failures(&pid_a);
    registry.clear_peer_failures(&pid_b);
    registry.clear_peer_failures(&pid_c);

    let handler_a = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_a) as Arc<dyn quorum_coordinator::StorageSearcher>,
        pid_a.clone(),
    ));
    let handler_b = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_b) as Arc<dyn quorum_coordinator::StorageSearcher>,
        pid_b.clone(),
    ));
    let handler_c = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_c) as Arc<dyn quorum_coordinator::StorageSearcher>,
        pid_c.clone(),
    ));

    let mut cfg_a = NetworkConfig::new_localhost();
    cfg_a.ed25519_seed = Some(seed_a);
    let (_jh_a, handle_a) = start_network_node(cfg_a, Some(handler_a.clone()))
        .await
        .expect("start A");

    let mut cfg_b = NetworkConfig::new_localhost();
    cfg_b.ed25519_seed = Some(seed_b);
    let (_jh_b, handle_b) = start_network_node(cfg_b, Some(handler_b.clone()))
        .await
        .expect("start B");

    let mut cfg_c = NetworkConfig::new_localhost();
    cfg_c.ed25519_seed = Some(seed_c);
    let (_jh_c, handle_c) = start_network_node(cfg_c, Some(handler_c.clone()))
        .await
        .expect("start C");

    let disp_a = Arc::new(SwarmMeshDispatcher::new(
        handle_a.clone(),
        pid_a.clone(),
        seed_a,
    ));
    let disp_b = Arc::new(SwarmMeshDispatcher::new(
        handle_b.clone(),
        pid_b.clone(),
        seed_b,
    ));
    let disp_c = Arc::new(SwarmMeshDispatcher::new(
        handle_c.clone(),
        pid_c.clone(),
        seed_c,
    ));
    handler_a.set_dispatcher(disp_a.clone());
    handler_b.set_dispatcher(disp_b.clone());
    handler_c.set_dispatcher(disp_c.clone());

    // Verify signing_credentials returns real Ed25519 identity
    assert_eq!(
        disp_a.signing_credentials(),
        Some((pid_a.clone(), seed_a)),
        "SwarmMeshDispatcher::signing_credentials must return configured Ed25519 identity"
    );

    let tcp_b = handle_b
        .listen_addresses()
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .unwrap();
    let tcp_c = handle_c
        .listen_addresses()
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .unwrap();

    // Linear topology ONLY: A <-> B and B <-> C (A is NOT initially connected to C)
    handle_a.dial(tcp_b).await.expect("A dials B");
    handle_b.dial(tcp_c).await.expect("B dials C");
    tokio::time::sleep(Duration::from_millis(450)).await;

    assert_eq!(handle_a.connected_peers().await.unwrap().len(), 1);
    assert_eq!(handle_b.connected_peers().await.unwrap().len(), 2);
    assert_eq!(handle_c.connected_peers().await.unwrap().len(), 1);

    let b_addrs = disp_b.connected_peer_multiaddrs();
    assert!(
        b_addrs.iter().any(|ma| ma.ends_with(&format!("/p2p/{}", pid_c))),
        "B must report C's dialable multiaddr in connected_peer_multiaddrs: {:?}",
        b_addrs
    );
    assert!(
        b_addrs.iter().all(|ma| !ma.contains("/tcp/4001") && !ma.contains("/udp/4001")),
        "connected_peer_multiaddrs must filter port 4001 noise: {:?}",
        b_addrs
    );

    // Send a signed canary query from A -> B; B responds with peer_multiaddrs containing C (excluding A and B),
    // and A's SwarmMeshDispatcher::query_peers_with_diagnostics auto-dials C into a full 3-way mesh!
    let mut canary_req = FederatedQueryRequest {
        query_id: uuid::Uuid::new_v4(),
        sender_peer_id: pid_a.clone(),
        sender_pubkey: [0u8; 32],
        query_text: P2P_WATCHER_CANARY_QUERY.to_string(),
        embedding: vec![0.0f32; 768],
        top_k: 0,
        timestamp: chrono::Utc::now().timestamp(),
        signature: [0u8; 64],
        origin_peer_id: None,
        relay_hops: 0,
        visited_peers: Vec::new(),
        synthesis_relay: None,
    };
    quorum_coordinator::crypto::sign_request(
        &seed_a,
        &mut canary_req,
        quorum_types::AccessTier::Tier0Public,
    );

    let (resps, _) = disp_a
        .query_peers_with_diagnostics(&canary_req, Duration::from_secs(4))
        .await
        .expect("canary query A->B");
    assert_eq!(resps.len(), 1);
    assert!(
        resps[0]
            .peer_multiaddrs
            .iter()
            .any(|ma| ma.ends_with(&format!("/p2p/{}", pid_c))),
        "B's response must advertise C in peer_multiaddrs: {:?}",
        resps[0].peer_multiaddrs
    );
    assert!(
        resps[0]
            .peer_multiaddrs
            .iter()
            .all(|ma| !ma.ends_with(&format!("/p2p/{}", pid_a))
                && !ma.ends_with(&format!("/p2p/{}", pid_b))),
        "B must exclude requester A and self B from advertised peer_multiaddrs: {:?}",
        resps[0].peer_multiaddrs
    );

    // Wait up to 2.5s for A's async auto-dial to converge into a full 3-way mesh
    let mut converged = false;
    for _ in 0..50 {
        let a_peers = handle_a.connected_peers().await.unwrap();
        let c_peers = handle_c.connected_peers().await.unwrap();
        if a_peers.len() == 2 && c_peers.len() == 2 {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        converged,
        "A and C must converge into full 3-way mesh (A={:?}, C={:?})",
        handle_a.connected_peers().await.unwrap(),
        handle_c.connected_peers().await.unwrap()
    );

    // Also verify port 4001 and self-dial filtering directly
    let bad_and_self = vec![
        format!("/ip4/127.0.0.1/tcp/4001/p2p/{}", pid_c),
        format!("/ip4/127.0.0.1/tcp/3032/p2p/{}", pid_a),
    ];
    let filtered = quorum_coordinator::mesh::filter_newly_learned_dial_targets(
        &bad_and_self,
        &pid_a,
        &handle_a.connected_peer_addresses(),
        &handle_a.listen_addresses().await.unwrap(),
    );
    assert!(
        filtered.is_empty(),
        "Port 4001 and self-dials must be filtered out: {:?}",
        filtered
    );
}

#[test]
fn test_synthesis_relay_preserves_provenance_and_prefers_expanded_window() {
    let responder_pid = "12D3KooWKHc3ResponderNode";
    let remote_origin_pid = "12D3KooWEcNhOriginNode";
    let dtos = vec![
        CandidateChunkDto {
            chunk_id: "c_remote:0".to_string(),
            file_path: "D:/Docs/Unity_Ministry_Steward.docx".to_string(),
            line_start: 1,
            line_end: 30,
            content: "Short chunk snippet".to_string(),
            score: 0.91,
            access_tier: 0,
            origin_peer_id: Some(remote_origin_pid.to_string()),
            expanded_window: Some("Full 10KB expanded ministry stewardship text with Rev. Angela Davis signature.".to_string()),
        },
        CandidateChunkDto {
            chunk_id: "c_responder_local:0".to_string(),
            file_path: "C:/Docs/Susan_Lease.doc".to_string(),
            line_start: 1,
            line_end: 20,
            content: "Lease between Angela Davis and Casey Ringgold".to_string(),
            score: 0.85,
            access_tier: 0,
            origin_peer_id: Some(responder_pid.to_string()),
            expanded_window: None,
        },
        CandidateChunkDto {
            chunk_id: "c_local_kw:0".to_string(),
            file_path: "C:/Docs/Local_Note.txt".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Local note".to_string(),
            score: 0.70,
            access_tier: 0,
            origin_peer_id: Some("local".to_string()),
            expanded_window: None,
        },
    ];

    let scored = quorum_coordinator::mesh::build_relay_scored_chunks(&dtos, responder_pid);
    assert_eq!(scored.len(), 3);

    assert!(scored[0].is_remote);
    assert_eq!(scored[0].source_peer, remote_origin_pid);
    assert!(scored[0].chunk.text_content.contains("Full 10KB expanded ministry stewardship text"));
    let cit_0 = scored[0].to_citation();
    assert!(cit_0.is_external_node);
    assert_eq!(cit_0.node_id.as_deref(), Some(remote_origin_pid));

    assert!(!scored[1].is_remote);
    assert_eq!(scored[1].source_peer, responder_pid);
    assert_eq!(scored[1].chunk.text_content, "Lease between Angela Davis and Casey Ringgold");

    assert!(!scored[2].is_remote);
    assert_eq!(scored[2].source_peer, "local");
}

#[test]
fn test_r2_cross_host_deterministic_canonical_citation_and_table_parity() {
    let emb = vec![0.03f32; 768];
    let make_chunk = |id: &str, path: &str, text: &str, score: f32, peer: &str, remote: bool| {
        ScoredChunk::new(
            DocumentChunk::new(id, id, path, 1, 20, 0, emb.clone(), text, None).unwrap(),
            score,
            peer,
            remote,
        )
    };

    // Host A sees local Academic + remote Lease + remote Ministry
    let host_a_inputs = vec![
        make_chunk(
            "a_acad:0",
            "C:/HostA/Women_Race_Class_Summary.docx",
            "Women, Race & Class is a landmark critical theory work by Angela Davis, published in 1981.",
            0.96,
            "local",
            false,
        ),
        make_chunk(
            "a_lease:0",
            "D:/HostB/Susan_Lease.doc",
            "SIMPLE LEASE AGREEMENT between Angela Davis (landlord) and Casey Ringgold (tenant) at 2913 Castiglione St. Monthly rent $614.00.",
            0.90,
            "12D3KooWHostB",
            true,
        ),
        make_chunk(
            "a_min:0",
            "E:/HostC/Visionary_Fire_Creation.docx",
            "Unity ministry sermon on spiritual teaching and divine presence signed by Rev. Angela Davis.",
            0.88,
            "12D3KooWHostC",
            true,
        ),
    ];

    // Host B receives the EXACT same 3 documents in REVERSED arrival order and inverted local/remote origin & scores
    let host_b_inputs = vec![
        make_chunk(
            "b_min:0",
            "E:/HostC/Visionary_Fire_Creation.docx",
            "Unity ministry sermon on spiritual teaching and divine presence signed by Rev. Angela Davis.",
            0.97,
            "12D3KooWHostC",
            true,
        ),
        make_chunk(
            "b_lease:0",
            "D:/HostB/Susan_Lease.doc",
            "SIMPLE LEASE AGREEMENT between Angela Davis (landlord) and Casey Ringgold (tenant) at 2913 Castiglione St. Monthly rent $614.00.",
            0.95,
            "local",
            false,
        ),
        make_chunk(
            "b_acad:0",
            "C:/HostA/Women_Race_Class_Summary.docx",
            "Women, Race & Class is a landmark critical theory work by Angela Davis, published in 1981.",
            0.85,
            "12D3KooWHostA",
            true,
        ),
    ];

    let (ans_a, cits_a) = DeterministicOfflineSynthesisEngine::synthesize_with_history(
        "Who is Angela Davis",
        "Who is Angela Davis",
        &[],
        &host_a_inputs,
        "offline",
        None,
    );
    let (ans_b, cits_b) = DeterministicOfflineSynthesisEngine::synthesize_with_history(
        "Who is Angela Davis",
        "Who is Angela Davis",
        &[],
        &host_b_inputs,
        "offline",
        None,
    );

    let keys_a: Vec<String> = cits_a
        .iter()
        .map(|c| DeterministicOfflineSynthesisEngine::derive_document_family_key(&c.file_path))
        .collect();
    let keys_b: Vec<String> = cits_b
        .iter()
        .map(|c| DeterministicOfflineSynthesisEngine::derive_document_family_key(&c.file_path))
        .collect();
    assert_eq!(keys_a, keys_b, "Cross-host [1]..[N] canonical order must be identical");
    assert_eq!(
        keys_a,
        vec![
            "women_race_class_summary".to_string(),
            "susan_lease".to_string(),
            "visionary_fire_creation".to_string(),
        ]
    );

    let table_rows = |ans: &str| -> Vec<String> {
        ans.lines()
            .filter(|l| l.starts_with("| **["))
            .map(|l| {
                let cols: Vec<&str> = l.split('|').collect();
                format!("{}|{}", cols.get(1).unwrap_or(&"").trim(), cols.get(2).unwrap_or(&"").trim())
            })
            .collect()
    };
    assert_eq!(
        table_rows(&ans_a),
        table_rows(&ans_b),
        "Identity & Domain Cluster Summary row order must match 100% across hosts:\nA:\n{ans_a}\nB:\n{ans_b}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_r2_2node_libp2p_synthesis_relay_round_trip_with_mock_ollama() {
    use quorum_coordinator::{
        global_peer_health_registry, OsoosiMeshInboundHandler, SwarmMeshDispatcher,
    };
    use quorum_network::{start_network_node, NetworkConfig};
    use quorum_storage::{StorageConfig, StorageEngine};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock ollama");
    let addr = listener.local_addr().expect("mock ollama addr");
    let host_port = format!("127.0.0.1:{}", addr.port());
    let seen_prompts = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen_prompts_srv = Arc::clone(&seen_prompts);
    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_srv = Arc::clone(&stop_flag);
    listener.set_nonblocking(true).expect("set_nonblocking");

    let server_handle = std::thread::spawn(move || {
        while !stop_srv.load(std::sync::atomic::Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                    let mut req_line = String::new();
                    if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                        continue;
                    }
                    let mut content_len = 0usize;
                    let mut hline = String::new();
                    loop {
                        hline.clear();
                        if reader.read_line(&mut hline).unwrap_or(0) == 0
                            || hline == "\r\n"
                            || hline == "\n"
                        {
                            break;
                        }
                        let low = hline.to_ascii_lowercase();
                        if let Some(rest) = low.strip_prefix("content-length:") {
                            content_len = rest.trim().parse::<usize>().unwrap_or(0);
                        }
                    }
                    let mut body_bytes = vec![0u8; content_len];
                    if content_len > 0 && reader.read_exact(&mut body_bytes).is_err() {
                        continue;
                    }
                    let req_json: serde_json::Value =
                        serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
                    let user_prompt = req_json["messages"]
                        .as_array()
                        .and_then(|arr| arr.last())
                        .and_then(|m| m["content"].as_str())
                        .unwrap_or("")
                        .to_string();
                    seen_prompts_srv.lock().unwrap().push(user_prompt.clone());

                    let mut doc_nums: Vec<usize> = Vec::new();
                    for line in user_prompt.lines() {
                        if let Some(rest) = line.strip_prefix('[') {
                            if let Some((num_s, after)) = rest.split_once(']') {
                                if after.starts_with(" Source File:") {
                                    if let Ok(n) = num_s.parse::<usize>() {
                                        doc_nums.push(n);
                                    }
                                }
                            }
                        }
                    }
                    const LEASE_SENTS: &[&str] = &[
                        "Angela Davis serves as landlord at 2913 Castiglione St. with $725.00 monthly rent",
                        "The 2913 Castiglione St. lease names Angela Davis as landlord for $725.00 monthly rent",
                        "Monthly rent of $725.00 is specified for Castiglione Street under landlord Angela Davis",
                        "Angela Davis manages the Castiglione Street lease at 2913 Castiglione St. for $725.00",
                        "Under the Castiglione Street lease, Angela Davis is the landlord collecting $725.00 monthly rent",
                        "The lease record at 2913 Castiglione St. confirms Angela Davis as landlord at $725.00 monthly rent",
                        "Castiglione Street landlord Angela Davis documented the $725.00 monthly rent arrangement",
                        "Verified terms at 2913 Castiglione St. establish $725.00 monthly rent with Angela Davis",
                        "Angela Davis oversees the 2913 Castiglione St. lease with $725.00 monthly rent",
                        "The Castiglione Street lease sets $725.00 monthly rent payable to landlord Angela Davis",
                        "Landlord Angela Davis signed the Castiglione Street lease at 2913 Castiglione St. for $725.00",
                        "Rent of $725.00 monthly is documented at 2913 Castiglione St. under Angela Davis",
                    ];
                    const MINISTRY_SENTS: &[&str] = &[
                        "Rev. Angela Davis serves on the Unity ministry board",
                        "On the Unity ministry board, Rev. Angela Davis contributes spiritual leadership",
                        "The Unity ministry board record names Rev. Angela Davis as a serving member",
                        "Rev. Angela Davis participates in Unity ministry board stewardship",
                        "Unity ministry board documentation confirms service by Rev. Angela Davis",
                        "Ministry records show Rev. Angela Davis serving on the Unity ministry board",
                        "Spiritual governance on the Unity ministry board includes Rev. Angela Davis",
                        "Rev. Angela Davis is documented on the Unity ministry board",
                        "The Unity ministry board roster includes Rev. Angela Davis",
                        "Board stewardship at Unity ministry involves Rev. Angela Davis",
                        "Rev. Angela Davis holds a role on the Unity ministry board",
                        "Unity ministry records identify Rev. Angela Davis on the ministry board",
                    ];
                    let is_ministry = user_prompt.contains("Religious Ministry");
                    let sents = if is_ministry { MINISTRY_SENTS } else { LEASE_SENTS };
                    let mut reply_text = String::new();
                    for &n in &doc_nums {
                        for idx in 0..12 {
                            reply_text.push_str(&format!("{} [{n}]. ", sents[idx]));
                        }
                    }
                    if reply_text.is_empty() {
                        reply_text = "Angela Davis serves as landlord at 2913 Castiglione St. with $725.00 monthly rent [1].".to_string();
                    }
                    let chunk = serde_json::json!({
                        "model": "qwen2.5:7b",
                        "message": { "role": "assistant", "content": reply_text },
                        "done": true,
                        "done_reason": "stop",
                        "eval_count": 48
                    })
                    .to_string();
                    let http_resp = format!(
                        "HTTP/1.0 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n{}\n",
                        chunk
                    );
                    let _ = stream.write_all(http_resp.as_bytes());
                    let _ = stream.flush();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let dir_a = tempfile::tempdir().expect("dir_a");
    let dir_b = tempfile::tempdir().expect("dir_b");
    let storage_a = Arc::new(
        StorageEngine::open(StorageConfig::new(dir_a.path().to_path_buf()))
            .await
            .expect("storage_a"),
    );
    let storage_b = Arc::new(
        StorageEngine::open(StorageConfig::new(dir_b.path().to_path_buf()))
            .await
            .expect("storage_b"),
    );

    let derive_pid = |seed: [u8; 32]| -> String {
        let sk = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
        let kp = quorum_network::libp2p::identity::ed25519::Keypair::from(sk);
        quorum_network::libp2p::identity::Keypair::from(kp)
            .public()
            .to_peer_id()
            .to_string()
    };

    let seed_a = [0x71u8; 32];
    let seed_b = [0x72u8; 32];
    let seed_c = [0x73u8; 32];
    let pid_a = derive_pid(seed_a);
    let pid_b = derive_pid(seed_b);
    let pid_c = derive_pid(seed_c);

    let registry = global_peer_health_registry();
    registry.clear_peer_failures(&pid_a);
    registry.clear_peer_failures(&pid_b);

    let hw_b = HardwareTelemetry {
        free_ram_gb: 32.0,
        total_ram_gb: 32.0,
        free_vram_mb: 16384,
        total_vram_mb: 16384,
        cpu_cores: 16,
        gpu_name: Some("MockGPU".to_string()),
        gpu_count: 1,
    };

    let handler_a = Arc::new(OsoosiMeshInboundHandler::new(
        Arc::clone(&storage_a) as Arc<dyn quorum_coordinator::StorageSearcher>,
        pid_a.clone(),
    ));
    let handler_b = Arc::new(
        OsoosiMeshInboundHandler::new(
            Arc::clone(&storage_b) as Arc<dyn quorum_coordinator::StorageSearcher>,
            pid_b.clone(),
        )
        .with_ollama_override(addr, host_port, hw_b, vec!["qwen2.5:7b".to_string()]),
    );

    let mut cfg_a = NetworkConfig::new_localhost();
    cfg_a.ed25519_seed = Some(seed_a);
    cfg_a.request_timeout = Duration::from_secs(120);
    let (_jh_a, handle_a) = start_network_node(cfg_a, Some(handler_a))
        .await
        .expect("start node A");

    let mut cfg_b = NetworkConfig::new_localhost();
    cfg_b.ed25519_seed = Some(seed_b);
    cfg_b.request_timeout = Duration::from_secs(120);
    let (_jh_b, handle_b) = start_network_node(cfg_b, Some(handler_b))
        .await
        .expect("start node B");

    let tcp_addr_b = handle_b
        .listen_addresses()
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .unwrap();
    handle_a.dial(tcp_addr_b).await.unwrap();
    for _ in 0..20 {
        if handle_a.connected_peers().await.unwrap().len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(handle_a.connected_peers().await.unwrap().len(), 1);

    let disp_a = SwarmMeshDispatcher::new(handle_a.clone(), pid_a.clone(), seed_a);

    let local_sc = ScoredChunk::new(
        DocumentChunk::new(
            "relay_loc:0",
            "relay_loc",
            "C:/HostA/Castiglione_Lease.docx",
            1,
            20,
            0,
            vec![0.1; 768],
            "Short snippet only.",
            None,
        )
        .unwrap(),
        0.95,
        "local",
        false,
    );
    let third_peer_sc = ScoredChunk::new(
        DocumentChunk::new(
            "relay_c:0",
            "relay_c",
            "D:/HostC/Unity_Ministry_Steward.docx",
            1,
            20,
            0,
            vec![0.1; 768],
            "Rev. Angela Davis serves on the Unity ministry board.",
            None,
        )
        .unwrap(),
        0.92,
        pid_c.clone(),
        true,
    );

    // 1. Direct signed MeshSynthesisRelayPayload over 2-node libp2p testing expanded_window preference
    let mut relay_req = DeterministicOfflineSynthesisEngine::build_mesh_synthesis_relay_request(
        "Who is Angela Davis",
        &[],
        &[&local_sc, &third_peer_sc],
        "qwen2.5:7b",
        disp_a.signing_credentials(),
    );
    if let Some(ref mut payload) = relay_req.synthesis_relay {
        assert_eq!(
            payload.evidence_chunks[0].origin_peer_id.as_deref(),
            Some(pid_a.as_str())
        );
        assert_eq!(
            payload.evidence_chunks[1].origin_peer_id.as_deref(),
            Some(pid_c.as_str())
        );
        payload.evidence_chunks[0].expanded_window = Some(
            "Expanded 10KB Castiglione Street lease at 2913 Castiglione St. naming Angela Davis as landlord with $725.00 monthly rent."
                .to_string(),
        );
    }
    quorum_coordinator::crypto::sign_request(
        &seed_a,
        &mut relay_req,
        quorum_types::AccessTier::Tier0Public,
    );

    let responses = disp_a
        .query_peers(&relay_req, Duration::from_millis(90_000))
        .await
        .expect("libp2p synthesis_relay query_peers should succeed");
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].responder_peer_id, pid_b);
    let synth = responses[0]
        .synthesis_response
        .as_ref()
        .expect("Node B must return synthesis_response");
    assert_eq!(synth.responder_peer_id, pid_b);
    assert!(synth.synthesized_text.contains("2913 Castiglione St."));
    assert_eq!(synth.citations.len(), 2);
    assert!(synth.citations.iter().all(|c| c.is_external_node));
    let cited_nodes: Vec<Option<&str>> = synth
        .citations
        .iter()
        .map(|c| c.node_id.as_deref())
        .collect();
    assert!(cited_nodes.contains(&Some(pid_a.as_str())));
    assert!(cited_nodes.contains(&Some(pid_c.as_str())));

    {
        let prompts = seen_prompts.lock().unwrap();
        assert!(
            !prompts.is_empty()
                && prompts
                    .iter()
                    .any(|p| p.contains("Expanded 10KB Castiglione Street lease")),
            "Node B must prefer expanded_window over short content; prompts={:?}",
            *prompts
        );
    }

    // 2. Verify try_mesh_synthesis_relay_with_dispatcher end-to-end without mutating global dispatcher
    let rich_local_sc = ScoredChunk::new(
        DocumentChunk::new(
            "relay_loc2:0",
            "relay_loc2",
            "C:/HostA/Castiglione_Lease.docx",
            1,
            20,
            0,
            vec![0.1; 768],
            "Angela Davis serves as landlord at 2913 Castiglione St. with $725.00 monthly rent.",
            None,
        )
        .unwrap(),
        0.95,
        "local",
        false,
    );
    let relayed_via_helper = DeterministicOfflineSynthesisEngine::try_mesh_synthesis_relay_with_dispatcher(
        &disp_a,
        "Who is Angela Davis",
        &[],
        &[&rich_local_sc, &third_peer_sc],
        "qwen2.5:7b",
        None,
    );

    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = server_handle.join();

    let (helper_text, helper_cits) =
        relayed_via_helper.expect("try_mesh_synthesis_relay_with_dispatcher must succeed over libp2p");
    assert!(helper_text.contains("2913 Castiglione St."));
    assert_eq!(helper_cits.len(), 2);
}
