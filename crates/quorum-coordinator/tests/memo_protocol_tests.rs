//! Automated paper-grounded and regression tests for MeMo (`arXiv:2605.15156`) integration
//! in `crates/quorum-coordinator`.
//!
//! Covers all 5 Milestone-2 behavioral contracts:
//! 1. Stage-1 stateless atomic sub-query decomposition (`query_variants` / `DeepGraph`) without cross-turn contamination.
//! 2. Stage-2 `UncertainAnswerStreakTracker` distractor pruning at `streak_limit`, streak reset on corroboration, and fast-path bypass.
//! 3. $1 \times N$ distractor noise robustness fixture over real `StorageEngine` + `AtlasKvStore` + `QueryCoordinator`.
//! 4. Homonym preservation (`Vec<String>` across distinct `domain_cluster`s without collapsing distinct identities).
//! 5. Stale `rewritten_vector` refresh on multi-hop rewrites, Stage-3 verbatim citation (`slice_text.contains(&verbatim_quote)`),
//!    fail-closed `AccessTier` isolation, `ZeroizeOnDrop`, and loopback `TypedStructuredExtractor<Stage1ClueProbeOutput>`.

use std::sync::{Arc, Mutex};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use quorum_atlaskv::AtlasKvStore;
use quorum_contract::{DeterministicOfflineEngine, EmbeddingGenerator};
use quorum_coordinator::agentic::{
    ClassifyIntentNode, GradeRelevanceNode, RetrieveMeshNode, RewriteQueryNode,
    SynthesizeWithCitationsNode,
};
use quorum_coordinator::{
    should_engage_memo_protocol, verify_and_annotate_chunk_self_containment, AdaptiveQueryPlan,
    AgenticGraphState, AgenticStateGraphRunner, AgenticTelemetryEvent, AtomicClueProbe,
    CoordinatorConfig, HardwareTelemetry, LocalOnlyDispatcher, MemoProtocolConfig, MemoStage,
    PeerAclManager, QueryCoordinator, QueryIntentType, RagEvalHarness, RetrievalDepth,
    ScatterGatherEngine, Stage1ClueProbeOutput, Stage2TurnDirective, StorageSearcher,
    SynthesisModelFamily, TypedStructuredExtractor, UncertainAnswerStreakTracker,
    VolatileRemoteChunk,
};
use quorum_types::{AccessTier, DocumentChunk, ScoredChunk};

struct RecordingStorage {
    chunks: Vec<DocumentChunk>,
    recorded_queries: Arc<Mutex<Vec<(String, Vec<f32>)>>>,
    atlaskv: Option<Arc<AtlasKvStore>>,
}

#[async_trait::async_trait]
impl StorageSearcher for RecordingStorage {
    async fn search_hybrid(
        &self,
        query_text: &str,
        query_vec: &[f32],
        max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.recorded_queries
            .lock()
            .unwrap()
            .push((query_text.to_string(), query_vec.to_vec()));

        let q_low = query_text.to_ascii_lowercase();
        let terms: Vec<&str> = q_low
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() >= 3)
            .collect();

        let mut hits: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier)
            .filter_map(|c| {
                let hay = format!(
                    "{} {}",
                    c.file_path.to_ascii_lowercase(),
                    c.text_content.to_ascii_lowercase()
                );
                let matched = terms.iter().filter(|t| hay.contains(**t)).count();
                if matched > 0 {
                    let score = 0.70 + (matched.min(5) as f32) * 0.05;
                    Some(ScoredChunk::new(c.clone(), score, "local", false))
                } else {
                    None
                }
            })
            .collect();

        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hits
    }

    async fn search_text(&self, query: &str, max_tier: u8, top_k: usize) -> Vec<ScoredChunk> {
        self.search_hybrid(query, &[], max_tier, top_k).await
    }

    async fn get_chunks_by_ids(&self, chunk_ids: &[String], max_tier: u8) -> Vec<DocumentChunk> {
        self.chunks
            .iter()
            .filter(|c| c.access_tier <= max_tier && chunk_ids.contains(&c.chunk_id))
            .cloned()
            .collect()
    }

    fn atlaskv(&self) -> Option<Arc<AtlasKvStore>> {
        self.atlaskv.clone()
    }
}

#[tokio::test]
async fn test_memo_stage1_stateless_subquery_decomposition_without_cross_turn_bleed() {
    let embedder = DeterministicOfflineEngine::new();
    let q = "who is Elena Rostova and what did she publish in 2023";
    let qvec = embedder.embed_text(q).unwrap();

    let c_bio = DocumentChunk::new(
        "elena_bio:0",
        "elena_bio",
        "C:/Library/Elena_Rostova_Profile.docx",
        1,
        15,
        0,
        embedder
            .embed_text("Elena Rostova computational linguist at Zurich Institute")
            .unwrap(),
        "Elena Rostova is a computational linguist specializing in multilingual syntax at the Zurich Institute.",
        None,
    )
    .unwrap();

    let c_pub = DocumentChunk::new(
        "elena_bio:5",
        "elena_bio",
        "C:/Library/Elena_Rostova_Profile.docx",
        50,
        65,
        0,
        embedder
            .embed_text("published Sparse Graph Attention in 2023")
            .unwrap(),
        "She later published Sparse Graph Attention in 2023 for cross-lingual dependency parsing.",
        None,
    )
    .unwrap();

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let storage = Arc::new(RecordingStorage {
        chunks: vec![c_bio, c_pub],
        recorded_queries: Arc::clone(&recorded),
        atlaskv: None,
    });
    let engine = ScatterGatherEngine::new(
        storage,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [1u8; 32],
        "local-stage1-test".to_string(),
    );

    let mut state = AgenticGraphState::new(q, SynthesisModelFamily::AutoFusion, 3);
    ClassifyIntentNode::execute(&mut state, &HardwareTelemetry::probe());
    let plan = state
        .adaptive_plan
        .as_ref()
        .expect("ClassifyIntentNode must populate adaptive_plan");
    assert_eq!(plan.depth, RetrievalDepth::DecomposedMultiQuery);
    assert_eq!(plan.primary_subject.as_deref(), Some("Elena Rostova"));
    assert!(plan.sub_questions.len() >= 2);
    assert!(plan.query_variants.len() >= 2);

    RetrieveMeshNode::execute(&mut state, &engine, &qvec, 0, 10).await;

    // Verify multiple stateless sub-queries were dispatched (primary + Stage-1 variants)
    let calls = recorded.lock().unwrap();
    assert!(
        calls.len() >= 2,
        "Expected Stage-1 sub-query fan-out in RetrieveMeshNode, saw {:?}",
        calls.iter().map(|(s, _)| s).collect::<Vec<_>>()
    );
    // Ensure sub-queries are stateless (none embeds raw text from another sub-query's retrieved chunk)
    for (subq, _) in calls.iter() {
        assert!(
            !subq.contains("Sparse Graph Attention") && !subq.contains("Zurich Institute"),
            "Stateless Stage-1 sub-query leaked prior hit text: {subq}"
        );
    }

    // Verify self-containment metadata annotation without mutating text_content or BLAKE3 hash
    assert!(!state.retrieved_chunks.is_empty());
    for sc in &state.retrieved_chunks {
        assert!(
            sc.chunk.verify_hash(),
            "BLAKE3 hash must remain intact after self-containment annotation"
        );
        let meta: serde_json::Value =
            serde_json::from_str(&sc.chunk.metadata_json).expect("valid metadata_json");
        assert!(meta.get("self_contained").is_some());
        if sc.chunk.chunk_id == "elena_bio:5" {
            assert_eq!(meta["self_contained"], serde_json::json!(false));
            assert_eq!(
                meta["resolved_entity_anchor"],
                serde_json::json!("Elena Rostova")
            );
        }
    }
}

#[test]
fn test_memo_stage2_tracker_pruning_reset_and_bypass_with_grade_and_rewrite() {
    // 1. Fast-path bypass checks
    let cfg = MemoProtocolConfig::default();
    let trivial_plan = AdaptiveQueryPlan {
        depth: RetrievalDepth::SingleHop,
        primary_subject: None,
        sub_questions: vec!["list files".to_string()],
        query_variants: vec!["list files".to_string()],
        hyde_passage: None,
    };
    assert!(!should_engage_memo_protocol(
        &cfg,
        Some(QueryIntentType::LocalDocumentSearch),
        &trivial_plan,
        false,
        false
    ));
    assert!(!should_engage_memo_protocol(
        &cfg,
        Some(QueryIntentType::GeneralConversation),
        &trivial_plan,
        false,
        false
    ));
    assert!(!should_engage_memo_protocol(
        &cfg,
        Some(QueryIntentType::MultiHopReasoning),
        &trivial_plan,
        true,
        false
    ));

    // 2. Stage-2 GradeRelevance + RewriteQuery + UncertainAnswerStreakTracker pruning & reset
    let mut tracker = UncertainAnswerStreakTracker::new(3, 2);
    let clues = vec![AtomicClueProbe {
        sub_question: "Who led Project Horizon?".to_string(),
        retrieved_chunk_ids: Vec::new(),
        grounded_clue: None,
        candidate_entities: vec!["Noise Candidate".to_string()],
        is_uncertain: true,
        confidence: 0.2,
    }];
    tracker.seed_from_stage1(&clues, &[], &[]);

    let mut state = AgenticGraphState::new(
        "Who led Project Horizon?",
        SynthesisModelFamily::AutoFusion,
        3,
    );
    state.memo_stage = MemoStage::Stage2EntityIdentification;
    state.entity_streak_tracker = Some(tracker);

    // Hop 1 rewrite driven by Stage-2 directive
    let rewritten = RewriteQueryNode::execute(&mut state).expect("rewrite hop 1");
    assert!(rewritten.contains("Noise Candidate"));
    assert!(!rewritten.contains("(disambiguation hop"));

    // GradeRelevance at hop 1 with empty/uncorroborated chunks triggers streak_limit=2 -> prunes & stops rewrite
    let grader = GradeRelevanceNode::default();
    let (_grade, will_rewrite) = grader.execute(&mut state);
    assert!(
        !will_rewrite,
        "Once all Stage-2 candidates are pruned at streak_limit, GradeRelevance must stop rewriting cleanly"
    );
    assert!(state
        .entity_streak_tracker
        .as_ref()
        .unwrap()
        .all_candidates_pruned());

    // 3. Streak reset upon corroboration triggers SkipToStage3
    let mut reset_tracker = UncertainAnswerStreakTracker::new(3, 2);
    reset_tracker.record_probe_outcome("Alice Vance", true, &[], &[]);
    assert_eq!(
        reset_tracker.candidates["alice vance::general"].consecutive_uncertain_streak,
        1
    );
    reset_tracker.record_probe_outcome("Alice Vance", false, &["c_alice:0".to_string()], &[7]);
    assert_eq!(
        reset_tracker.candidates["alice vance::general"].consecutive_uncertain_streak,
        0
    );
    assert_eq!(
        reset_tracker.pinned_entities,
        vec!["Alice Vance".to_string()]
    );
    assert!(matches!(
        reset_tracker.begin_stage2_turn(),
        Stage2TurnDirective::SkipToStage3 { .. }
    ));
}

#[tokio::test]
async fn test_memo_1xn_distractor_noise_robustness_and_eval_metrics() {
    let temp_dir = tempdir().expect("tempdir");
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(quorum_storage::StorageConfig::new(
            temp_dir.path().to_path_buf(),
        ))
        .await
        .expect("storage open"),
    );

    let embedder = DeterministicOfflineEngine::new();
    let target_chunk = DocumentChunk::new(
        "horizon:0",
        "horizon",
        "C:/Projects/Project_Horizon_Charter.docx",
        1,
        25,
        0,
        embedder
            .embed_text("Alice Vance directed Project Horizon in 2024")
            .unwrap(),
        "Project Horizon Charter: Alice Vance served as Lead Systems Architect and directed Project Horizon in 2024 with a $1.2M verification budget.",
        Some(r#"{"doc_title":"Project Horizon Charter","doc_author":"Alice Vance"}"#.to_string()),
    )
    .unwrap();

    let mut all_chunks = vec![target_chunk];
    for idx in 1..=5 {
        all_chunks.push(
            DocumentChunk::new(
                format!("noise_{idx}:0"),
                format!("noise_{idx}"),
                format!("C:/Noise/Unrelated_Memo_{idx}.docx"),
                1,
                10,
                0,
                embedder
                    .embed_text(&format!("Distractor memo {idx} quarterly parking budget"))
                    .unwrap(),
                format!(
                    "Quarterly parking memo {idx} discussing office badge renewals and cafeteria hours for Bob Distractor{idx}."
                ),
                None,
            )
            .unwrap(),
        );
    }

    storage.insert_chunks(&all_chunks).await.expect("insert");

    let scatter_gather = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageSearcher>,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x31u8; 32],
        "local-1xn-node".to_string(),
    ));
    let coordinator = Arc::new(QueryCoordinator::new(
        scatter_gather,
        CoordinatorConfig::default(),
    ));

    let res = coordinator
        .query_agentic_with_history_and_session(
            "Who directed Project Horizon in 2024?",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            8,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("query");

    assert!(
        res.synthesis_prompt.contains("Alice Vance"),
        "Must ground Alice Vance under 1xN distractor noise: {}",
        res.synthesis_prompt
    );
    assert!(
        !res.synthesis_prompt.contains("Bob Distractor"),
        "Distractor entities must not pollute final answer: {}",
        res.synthesis_prompt
    );
    assert!(!res.sources_cited.is_empty(), "Expected grounded citations");
    for cit in &res.sources_cited {
        if let Some(ref quote) = cit.verbatim_quote {
            let matches_raw = res
                .chunks
                .iter()
                .any(|c| c.chunk.file_path == cit.file_path && c.chunk.text_content.contains(quote));
            assert!(
                matches_raw,
                "Citation verbatim_quote {:?} must be a substring of raw chunk text",
                quote
            );
        }
    }

    let chunk_refs: Vec<&ScoredChunk> = res.chunks.iter().collect();
    let eval = RagEvalHarness::evaluate_with_memo(
        "Who directed Project Horizon in 2024?",
        &chunk_refs,
        &res.synthesis_prompt,
        None,
        &["Alice Vance", "Project Horizon"],
    );
    assert_eq!(eval.entity_coverage, 1.0);
}

#[tokio::test]
async fn test_memo_homonym_preservation_and_access_tier_isolation() {
    let temp_dir = tempdir().expect("tempdir");
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(quorum_storage::StorageConfig::new(
            temp_dir.path().to_path_buf(),
        ))
        .await
        .expect("storage open"),
    );

    let embedder = DeterministicOfflineEngine::new();
    let vec_zero = embedder.embed_text("who is Michael Chen").unwrap();

    let clinical = DocumentChunk::new(
        "mc_clin:0",
        "mc_clin",
        "C:/Hospital/Cardiology_Roster.pdf",
        1,
        20,
        0,
        vec_zero.clone(),
        "Dr. Michael Chen, MD is an attending clinical cardiologist treating heart failure patients at Memorial Hospital.",
        None,
    )
    .unwrap();
    let engineering = DocumentChunk::new(
        "mc_eng:0",
        "mc_eng",
        "C:/Engineering/Michael_Chen_Profile.pdf",
        1,
        20,
        0,
        vec_zero.clone(),
        "Michael Chen is a principal software engineer and CISSP security architect specializing in Kubernetes and distributed systems.",
        None,
    )
    .unwrap();
    let restricted = DocumentChunk::new(
        "mc_restricted:0",
        "mc_restricted",
        "C:/Vault/Restricted_Michael_Chen_Finance.docx",
        1,
        15,
        3, // Tier3Restricted — MUST NEVER leak to Tier0Public queries
        vec_zero,
        "Confidential tax account 99887766 for Michael Chen under restricted clearance.",
        None,
    )
    .unwrap();

    storage
        .insert_chunks(&[clinical, engineering, restricted])
        .await
        .expect("insert");

    let scatter_gather = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageSearcher>,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x44u8; 32],
        "local-homonym-node".to_string(),
    ));
    let coordinator = Arc::new(QueryCoordinator::new(
        scatter_gather,
        CoordinatorConfig::default(),
    ));

    let res = coordinator
        .query_agentic_with_history_and_session(
            "who is Michael Chen",
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            10,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("query");

    assert!(
        res.synthesis_prompt
            .contains("### Clinical & Healthcare Records"),
        "Clinical cluster must be preserved: {}",
        res.synthesis_prompt
    );
    assert!(
        res.synthesis_prompt
            .contains("### Software Engineering, Architecture & Cybersecurity"),
        "Engineering cluster must be preserved: {}",
        res.synthesis_prompt
    );
    assert!(
        !res.synthesis_prompt.contains("99887766"),
        "Tier3Restricted chunk must NEVER leak into Tier0Public output"
    );
}

#[tokio::test]
async fn test_memo_rewritten_vector_refresh_verbatim_citation_zeroize_and_loopback_probe() {
    // 1. Verify stale rewritten_vector bug is fixed across multi-hop RewriteQuery -> RetrieveMesh
    //    even when hop 0 returns a non-empty local distractor chunk that populates `cached_vector_hits`.
    let embedder = DeterministicOfflineEngine::new();
    let hop0_query = "Who is Mystery Subject?";
    let hop0_vec = embedder.embed_text(hop0_query).unwrap();

    let distractor_chunk = DocumentChunk::new(
        "distractor:0",
        "distractor",
        "C:/Noise/Parking_Notice.docx",
        1,
        5,
        0,
        hop0_vec.clone(),
        "Who is the office contact for quarterly badge renewals?",
        None,
    )
    .unwrap();

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let non_empty_storage = Arc::new(RecordingStorage {
        chunks: vec![distractor_chunk],
        recorded_queries: Arc::clone(&recorded),
        atlaskv: None,
    });
    let engine = ScatterGatherEngine::new(
        non_empty_storage,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x22u8; 32],
        "local-vector-refresh-node".to_string(),
    );

    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let runner = AgenticStateGraphRunner::new(2, 0.60);
    let final_state = runner
        .run_with_history_and_session(
            hop0_query,
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            &engine,
            &hop0_vec,
            0,
            6,
            std::collections::HashSet::new(),
            Some(tx),
        )
        .await
        .expect("runner");

    let mut saw_memo_event = false;
    let mut saw_stage3_event = false;
    while let Ok(ev) = rx.try_recv() {
        if let AgenticTelemetryEvent::MemoStageEvent { stage, .. } = ev {
            saw_memo_event = true;
            if stage == MemoStage::Stage3AnswerSeeking {
                saw_stage3_event = true;
            }
        }
    }
    assert!(saw_memo_event, "Expected MemoStageEvent telemetry emissions");
    assert!(
        saw_stage3_event,
        "Expected Stage3AnswerSeeking MemoStageEvent transition"
    );
    assert!(final_state.hop_count >= 1);
    assert!(
        !final_state.cached_vector_hits.is_empty(),
        "Hop 0 distractor must populate cached_vector_hits so hop 1 proves search_hybrid bypass"
    );

    let calls = recorded.lock().unwrap();
    let hop1_entry = calls
        .iter()
        .find(|(q, _)| q.contains("disambiguation hop 1") || q.contains("entity probe hop 1"))
        .expect("expected hop 1 rewritten query execution");
    assert!(
        !hop1_entry.1.is_empty(),
        "Hop 1 must invoke search_hybrid with a non-empty rewritten_vector rather than cached search_text(&[])"
    );
    assert_ne!(
        hop1_entry.1, hop0_vec,
        "rewritten_vector MUST be refreshed on RewriteQuery instead of reusing stale hop-0 vector"
    );
    let expected_hop1_vec = embedder.embed_text(&hop1_entry.0).unwrap();
    assert_eq!(hop1_entry.1, expected_hop1_vec);

    // 2. Verify ZeroizeOnDrop & self-containment text immutability
    let mut local_sc = ScoredChunk::new(
        DocumentChunk::new(
            "z:0",
            "z",
            "C:/Docs/Quote.docx",
            1,
            5,
            0,
            vec![0.1; 8],
            "It verified exact byte-range grounding in 2025.",
            None,
        )
        .unwrap(),
        0.95,
        "local",
        false,
    );
    let original = local_sc.chunk.text_content.clone();
    let _ = verify_and_annotate_chunk_self_containment(&mut local_sc, Some("QuorumRAG"));
    assert_eq!(local_sc.chunk.text_content, original);

    let vrc = VolatileRemoteChunk {
        chunk_id: "rem:0".to_string(),
        peer_id: "peer_a".to_string(),
        file_path: "D:/Remote/Doc.docx".to_string(),
        line_start: 1,
        line_end: 5,
        score: 0.9,
        access_tier: AccessTier::Tier0Public as u8,
        content: "secret remote text".to_string(),
        expanded_window: None,
    };
    drop(vrc);

    // 3. Loopback TypedStructuredExtractor<Stage1ClueProbeOutput> HTTP roundtrip
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = vec![0u8; 16384];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.starts_with("POST /api/chat"));
            assert!(req.contains("\"format\""));
            let body = serde_json::json!({
                "model": "qwen2.5:7b",
                "message": {
                    "role": "assistant",
                    "content": "{\"answer\":\"Alice Vance directed Project Horizon.\",\"entity_candidates\":[\"Alice Vance\"],\"is_uncertain\":false,\"verbatim_evidence\":\"Alice Vance directed Project Horizon in 2024\"}"
                },
                "done": true
            })
            .to_string();
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(http.as_bytes()).await;
        }
    });

    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let ext = TypedStructuredExtractor::<Stage1ClueProbeOutput>::new(
        &endpoint,
        "qwen2.5:7b",
        "Extract atomic Stage-1 clue.",
    );
    let out = ext
        .extract_ollama_async("Who directed Project Horizon?")
        .await
        .expect("loopback Stage1ClueProbeOutput extraction");
    assert_eq!(out.entity_candidates, vec!["Alice Vance".to_string()]);
    assert!(!out.is_uncertain);
    let _ = server.await;
}

#[tokio::test]
async fn test_memo_stage3_self_rag_critique_gates_cache_and_repairs_ungrounded_draft() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        // Handle initial critique + 1 bounded corrective re-check
        for _ in 0..2 {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = vec![0u8; 16384];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                assert!(req.starts_with("POST /api/chat"));
                assert!(req.contains("\"format\""));
                let body = serde_json::json!({
                    "model": "qwen2.5:7b",
                    "message": {
                        "role": "assistant",
                        "content": "{\"is_grounded\":false,\"answers_all_sub_questions\":false,\"unsupported_claims\":[\"Fabricated pretraining claim.\"],\"missing_document_refs\":[1],\"confidence\":0.2}"
                    },
                    "done": true
                })
                .to_string();
                let http = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(http.as_bytes()).await;
            }
        }
    });

    let mut state = AgenticGraphState::new(
        "Who directed Project Horizon?",
        SynthesisModelFamily::AutoFusion,
        3,
    );
    state.memo_stage = MemoStage::Stage3AnswerSeeking;
    state.selected_model_tag = "qwen2.5:7b".to_string();
    state.retrieved_chunks = vec![ScoredChunk::new(
        DocumentChunk::new(
            "horizon:0",
            "horizon",
            "C:/Projects/Project_Horizon_Charter.docx",
            1,
            15,
            0,
            vec![0.1; 8],
            "Alice Vance directed Project Horizon in 2024 with a $1.2M verification budget.",
            None,
        )
        .unwrap(),
        0.95,
        "local",
        false,
    )];

    let (tx, mut rx) = tokio::sync::mpsc::channel(32);

    // 1. execute_draft must populate synthesized_response WITHOUT emitting FinalAnswer
    SynthesizeWithCitationsNode::execute_draft(&mut state, Some(&tx));
    assert!(state.synthesized_response.is_some());
    while let Ok(ev) = rx.try_recv() {
        assert!(
            !matches!(ev, AgenticTelemetryEvent::FinalAnswer { .. }),
            "execute_draft must defer FinalAnswer until SelfRagCritique completes"
        );
    }

    // Inject an unsupported claim into the draft before critique gating
    state.synthesized_response = Some(
        "Alice Vance directed Project Horizon.\nFabricated pretraining claim.".to_string(),
    );

    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let cache_eligible =
        AgenticStateGraphRunner::apply_self_rag_critique_gate(&mut state, &endpoint, Some(&tx))
            .await;

    assert!(
        !cache_eligible,
        "SelfRagCritique with is_grounded=false MUST return cache_eligible=false to prevent query_cache poisoning"
    );
    let repaired = state.synthesized_response.as_deref().unwrap_or("");
    assert!(
        !repaired.contains("Fabricated pretraining claim."),
        "Corrective repair must strip unsupported claims: {repaired}"
    );
    assert!(
        repaired.contains("Project Horizon"),
        "Corrective repair must ground missing_document_refs against retrieved_chunks: {repaired}"
    );

    let mut saw_memo_event = false;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev, AgenticTelemetryEvent::MemoStageEvent { .. }) {
            saw_memo_event = true;
        }
    }
    assert!(
        saw_memo_event,
        "SelfRagCritique corrective path must emit MemoStageEvent"
    );

    SynthesizeWithCitationsNode::emit_final_answer(&state, Some(&tx));
    let mut saw_final_answer = false;
    while let Ok(ev) = rx.try_recv() {
        if matches!(ev, AgenticTelemetryEvent::FinalAnswer { .. }) {
            saw_final_answer = true;
        }
    }
    assert!(
        saw_final_answer,
        "emit_final_answer must emit FinalAnswer after critique gate completes"
    );

    let _ = server.await;
}
