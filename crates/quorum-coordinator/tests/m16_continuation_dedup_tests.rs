//! M16: Multi-Turn Continuation Deduplication & State Graph Pipeline Verification Tests
//!
//! Validates:
//! 1. Negative chunk ID filtering in storage and scatter-gather retrieval
//! 2. Continuation facet rewriting on multi-turn follow-ups
//! 3. Maximal Marginal Relevance (MMR) retrieval diversification
//! 4. Pairwise sentence embedding deduplication (>= 0.88 cosine similarity threshold)
//! 5. Cross-citation entity consolidation and deduplication

use quorum_coordinator::{
    agentic::retrieve::apply_mmr_selection,
    agentic::rewrite::ContinuationFacetExtractor,
    agentic::{AgenticGraphState, RewriteContinuationNode},
    offline_engine::DeterministicOfflineSynthesisEngine,
    scatter_gather::ScatterGatherEngine,
    ChatTurnMessage, CoordinatorConfig, LocalOnlyDispatcher, PeerAclManager, SynthesisModelFamily,
};
use quorum_storage::{StorageEngine, StorageSearchQuery};
use quorum_types::{DocumentChunk, ScoredChunk};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Test A: Verifies that seen_chunk_ids negative filtering excludes previously seen
/// chunk IDs while permitting subsequent unseen chunks from the same document.
#[tokio::test]
async fn test_seen_chunk_ids_negative_filtering() {
    let tmp = tempfile::tempdir().unwrap();
    let storage = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk0 = DocumentChunk::new(
        "doc_lease:0",
        "doc_lease",
        "leases/apartment_2026.txt",
        1,
        10,
        0,
        vec![0.1f32; 768],
        "Residential lease terms: Monthly rent is $1200 due on the first.",
        None,
    )
    .unwrap();

    let chunk1 = DocumentChunk::new(
        "doc_lease:1",
        "doc_lease",
        "leases/apartment_2026.txt",
        11,
        20,
        0,
        vec![0.2f32; 768],
        "Eviction terms: In the event of court proceedings, the filing fee is $195.",
        None,
    )
    .unwrap();

    storage.insert_chunks(&[chunk0, chunk1]).await.unwrap();

    // 1. StorageSearchQuery negative filtering check
    let query_with_exclusion = StorageSearchQuery::hybrid("lease eviction", vec![0.15f32; 768], 0, 10)
        .with_exclusion(vec!["doc_lease:0".to_string()]);
    let hits = storage.search(&query_with_exclusion).await.unwrap();
    assert!(!hits.is_empty(), "Should retrieve eligible chunks");
    assert!(
        hits.iter().all(|c| c.chunk.chunk_id != "doc_lease:0"),
        "doc_lease:0 must be filtered out by negative exclusion"
    );
    assert!(
        hits.iter().any(|c| c.chunk.chunk_id == "doc_lease:1"),
        "doc_lease:1 must still be returned from the same document"
    );

    // 2. Direct search_hybrid_with_exclusion check
    let hybrid_hits = storage
        .search_hybrid_with_exclusion(
            "lease eviction fee",
            &[0.15f32; 768],
            0,
            10,
            &["doc_lease:0".to_string()],
        )
        .await
        .unwrap();
    assert!(
        hybrid_hits.iter().all(|c| c.chunk.chunk_id != "doc_lease:0"),
        "Direct hybrid search must filter excluded chunks"
    );
    assert!(
        hybrid_hits.iter().any(|c| c.chunk.chunk_id == "doc_lease:1"),
        "Direct hybrid search must retain non-excluded chunks"
    );

    // 3. ScatterGatherEngine exclusion check
    let storage_arc = Arc::new(storage);
    let engine = ScatterGatherEngine::new(
        storage_arc,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0u8; 32],
        "node_test".to_string(),
    );

    let (scatter_chunks, _volatile, _duration, _new_vectors) = engine
        .execute_query_with_cached_vector_and_exclusion(
            "lease eviction",
            &[0.15f32; 768],
            None,
            0,
            10,
            &["doc_lease:0".to_string()],
        )
        .await;

    assert!(
        scatter_chunks.iter().all(|c| c.chunk.chunk_id != "doc_lease:0"),
        "ScatterGatherEngine must respect exclude_chunk_ids"
    );
    assert!(
        scatter_chunks.iter().any(|c| c.chunk.chunk_id == "doc_lease:1"),
        "ScatterGatherEngine must retain doc_lease:1"
    );
}

/// Test B: Verifies continuation facet query rewriting targeting uncovered topic aspects.
#[tokio::test]
async fn test_continuation_facet_rewriting() {
    let lease_history = vec![
        ChatTurnMessage {
            role: "user".to_string(),
            content: "What are the terms of the apartment lease?".to_string(),
        },
        ChatTurnMessage {
            role: "assistant".to_string(),
            content: "The lease specifies a 12-month duration with rent of $1,500/month.".to_string(),
        },
    ];

    // Check lease facet discovery
    let covered = ContinuationFacetExtractor::extract_covered_facets("The lease specifies a 12-month duration with rent of $1,500/month.");
    assert!(!covered.is_empty(), "Should extract covered base rent terms");
    assert!(covered.contains("base_rent_terms"));

    let (rewritten_lease, rationale) = ContinuationFacetExtractor::rewrite_continuation_query("apartment lease", &covered, 2);
    assert!(
        rewritten_lease.contains("maintenance")
            || rewritten_lease.contains("utilities")
            || rewritten_lease.contains("termination")
            || rewritten_lease.contains("subletting"),
        "Lease rewrite must target uncovered operational clauses: {} ({})",
        rewritten_lease,
        rationale
    );

    // Check biographical facet discovery
    let _bio_history = vec![
        ChatTurnMessage {
            role: "user".to_string(),
            content: "Who is Angela Davis?".to_string(),
        },
        ChatTurnMessage {
            role: "assistant".to_string(),
            content: "Angela Davis is an American political activist, philosopher, and academic who studied at Brandeis and Frankfurt.".to_string(),
        },
    ];
    let covered_bio = ContinuationFacetExtractor::extract_covered_facets("Angela Davis is an American political activist, philosopher, and academic who studied at Brandeis and Frankfurt.");
    assert!(covered_bio.contains("education_and_early_philosophy"));

    let (rewritten_bio, bio_rationale) = ContinuationFacetExtractor::rewrite_continuation_query("Angela Davis", &covered_bio, 2);
    assert!(
        rewritten_bio.contains("trial")
            || rewritten_bio.contains("activism")
            || rewritten_bio.contains("prison")
            || rewritten_bio.contains("scholarship")
            || rewritten_bio.contains("professor"),
        "Biographical rewrite must target unexplored career milestones: {} ({})",
        rewritten_bio,
        bio_rationale
    );

    // Test RewriteContinuationNode in state graph
    let mut state = AgenticGraphState::new("continue", SynthesisModelFamily::AutoFusion, 3);
    state.conversation_history = lease_history;
    let res = RewriteContinuationNode::execute(&mut state);
    assert!(res.is_ok());

    assert_ne!(
        state.current_query, "continue",
        "Continuation query must be rewritten to an informative topic query"
    );
    assert!(
        state.current_query.to_ascii_lowercase().contains("lease"),
        "Rewritten query must retain topic context ('lease'): {}",
        state.current_query
    );
}

/// Test C: Verifies Maximal Marginal Relevance (MMR) retrieval diversification.
#[test]
fn test_mmr_selection_diversification() {
    // Construct 4 candidate chunks:
    // c1, c2, c3 are near-identical copies (cosine similarity ~1.0)
    // c4 is orthogonal / diverse (cosine similarity ~0.0)
    let c1 = ScoredChunk::new(
        DocumentChunk::new(
            "chunk_1",
            "doc_1",
            "terms.txt",
            1,
            5,
            0,
            vec![1.0, 0.0, 0.0],
            "Eviction filing fee is $195 in municipal court.",
            None,
        )
        .unwrap(),
        0.98,
        "local",
        false,
    );

    let c2 = ScoredChunk::new(
        DocumentChunk::new(
            "chunk_2",
            "doc_1",
            "terms.txt",
            6,
            10,
            0,
            vec![0.999, 0.001, 0.0],
            "Eviction filing fee is $195 in municipal court proceedings.",
            None,
        )
        .unwrap(),
        0.95,
        "local",
        false,
    );

    let c3 = ScoredChunk::new(
        DocumentChunk::new(
            "chunk_3",
            "doc_1",
            "terms.txt",
            11,
            15,
            0,
            vec![0.998, 0.002, 0.0],
            "Eviction filing fee is $195 in municipal court hearings.",
            None,
        )
        .unwrap(),
        0.92,
        "local",
        false,
    );

    let c4 = ScoredChunk::new(
        DocumentChunk::new(
            "chunk_4",
            "doc_2",
            "maintenance.txt",
            1,
            5,
            0,
            vec![0.0, 1.0, 0.0],
            "Landlord is responsible for structural heating, plumbing, and roof maintenance.",
            None,
        )
        .unwrap(),
        0.80,
        "local",
        false,
    );

    let candidates = vec![c1, c2, c3, c4];
    let query_vector = vec![1.0, 0.0, 0.0];

    // Select top 2 using MMR with lambda = 0.70
    let selected = apply_mmr_selection(candidates, &query_vector, 2, 0.70);
    assert_eq!(selected.len(), 2, "Must select exactly 2 candidates");

    // The first selected must be the highest-scoring candidate (chunk_1)
    assert_eq!(selected[0].chunk.chunk_id, "chunk_1");

    // The second selected must be the diverse candidate (chunk_4), NOT the near-duplicates chunk_2 or chunk_3
    assert_eq!(
        selected[1].chunk.chunk_id, "chunk_4",
        "MMR diversification must select orthogonal chunk_4 over redundant near-duplicate chunks"
    );
}

/// Test D: Verifies pairwise sentence semantic deduplication with threshold 0.88.
#[test]
fn test_pairwise_sentence_dedup_088() {
    let prior_assistant_text = "\
The lease specifies a 12-month term. In the event of an eviction proceeding, \
the court filing fee is $195 paid by the tenant.";

    // Candidate chunk contains the exact repeated $195 eviction clause plus a new notice requirement
    let chunk_text = "\
In the event of an eviction proceeding, the court filing fee is $195 paid by the tenant. \
Tenants must provide 30 days written notice prior to vacating the premises.";

    let candidate = ScoredChunk::new(
        DocumentChunk::new(
            "chunk_turn2",
            "doc_turn2",
            "lease_addendum.txt",
            1,
            10,
            0,
            vec![0.0f32; 768],
            chunk_text,
            None,
        )
        .unwrap(),
        0.85,
        "local",
        false,
    );

    let deduped = DeterministicOfflineSynthesisEngine::deduplicate_chunk_segments_against_prior(
        vec![candidate],
        prior_assistant_text,
        0.88,
    );

    assert_eq!(deduped.len(), 1, "Candidate chunk should remain with non-duplicate sentences");
    let result_text = &deduped[0].chunk.text_content;

    assert!(
        result_text.contains("30 days written notice"),
        "New, non-covered sentence must be preserved: {}",
        result_text
    );
    assert!(
        !result_text.contains("$195"),
        "Duplicate sentence matching prior assistant turn (> 0.88 similarity) must be dropped: {}",
        result_text
    );
}

/// Test E: Verifies cross-citation entity consolidation and bracket merging.
#[test]
fn test_cross_citation_entity_consolidation() {
    let raw_synthesis = "\
The court eviction filing fee is $195 [1]. The court eviction filing fee is $195 [2]. \
Tenants must maintain renter's insurance with at least $100,000 in liability coverage [3].";

    let consolidated = DeterministicOfflineSynthesisEngine::consolidate_duplicate_entity_statements(raw_synthesis);

    // Verify $195 fee is mentioned exactly once
    let fee_count = consolidated.matches("$195").count();
    assert_eq!(
        fee_count, 1,
        "Duplicate $195 eviction fee must be consolidated into a single mention: {}",
        consolidated
    );

    // Verify citation brackets were consolidated to [1], [2]
    assert!(
        consolidated.contains("[1], [2]") || consolidated.contains("**[1]**, **[2]**"),
        "Consolidated statement must merge citations into [1], [2]: {}",
        consolidated
    );

    // Verify independent clause is preserved
    assert!(
        consolidated.contains("renter's insurance") && consolidated.contains("$100,000"),
        "Distinct non-duplicate entity statements must be preserved: {}",
        consolidated
    );

    // Test cross-paragraph entity consolidation with varying phrasing
    let multi_para_synthesis = "\
Under the residential lease, late payments incur a 5% monthly penalty [1].

Late payments incur a 5% monthly penalty under the tenancy terms [2].

Trash collection is included in the monthly rent [3].";

    let para_consolidated = DeterministicOfflineSynthesisEngine::consolidate_duplicate_entity_statements(multi_para_synthesis);
    let penalty_count = para_consolidated.matches("5%").count();
    assert_eq!(
        penalty_count, 1,
        "Multi-paragraph duplicate 5% late penalty must be consolidated: {}",
        para_consolidated
    );
    assert!(
        para_consolidated.contains("[1], [2]"),
        "Merged paragraph citations must combine [1], [2]: {}",
        para_consolidated
    );
    assert!(
        para_consolidated.contains("Trash collection"),
        "Non-duplicate paragraph must remain intact"
    );

    // Test normalized $195.00 vs $195 and bank account #1569837451 vs 1569837451 consolidation
    let bank_and_fee = "\
Rent is directed to Chase Bank account #1569837451 [3]. \
Direct deposits are directed to Chase Bank account 1569837451 [5]. \
Eviction proceedings require a $195.00 court fee [2]. \
Eviction proceedings require a $195 court fee [4].";
    let norm_consolidated =
        DeterministicOfflineSynthesisEngine::consolidate_duplicate_entity_statements(bank_and_fee);
    assert_eq!(
        norm_consolidated.matches("1569837451").count(),
        1,
        "Bank account #1569837451 and 1569837451 must consolidate into one statement: {}",
        norm_consolidated
    );
    assert_eq!(
        norm_consolidated.matches("195").count(),
        1,
        "Normalized $195.00 and $195 eviction fees must consolidate: {}",
        norm_consolidated
    );
}

/// Test F: Verifies corpus-grounded domain disambiguation (New Orleans landlord Angela Davis
/// expands lease facets, never non-corpus biographical terms) and cross-turn $195.00 -> $195 suppression.
#[test]
fn test_landlord_domain_disambiguation_and_prior_fee_suppression() {
    let landlord_turn1 = "Angela Davis is a landlord who has entered into multiple lease agreements in New Orleans. \
If rent remains unpaid after the fifth day, she files eviction proceedings which include a requirement for a $195.00 fee to cover court and eviction costs [2], [3].";

    let covered = ContinuationFacetExtractor::extract_covered_facets(landlord_turn1);
    assert!(covered.contains("domain:lease"));
    assert!(!covered.contains("domain:biographical"));

    let (rewritten, _) =
        ContinuationFacetExtractor::rewrite_continuation_query("tell me about Angela Davis", &covered, 2);
    let low = rewritten.to_ascii_lowercase();
    assert!(
        low.contains("maintenance") || low.contains("utilities") || low.contains("termination"),
        "Landlord Angela Davis continuation must expand lease facets: {}",
        rewritten
    );
    assert!(
        !low.contains("marin") && !low.contains("santa cruz") && !low.contains("prison"),
        "Must never inject hardcoded out-of-corpus activist terms: {}",
        rewritten
    );

    let turn2_draft = "Tenants must undergo extermination services every three months [1]. \
For certain agreements, if rent is not paid within 10 days, eviction procedures will commence, requiring the tenant to pay an additional $195 to cover costs [1]. \
No junk cars or immovable vehicles are allowed to sit on the property [1].";
    let filtered =
        DeterministicOfflineSynthesisEngine::drop_sentences_repeating_prior(turn2_draft, landlord_turn1);
    assert!(
        !filtered.contains("$195"),
        "Repeated $195 eviction fee from Turn 1 ($195.00) must be dropped in Turn 2: {}",
        filtered
    );
    assert!(
        filtered.contains("extermination services") && filtered.contains("junk cars"),
        "Novel Turn 2 clauses must be preserved intact: {}",
        filtered
    );
}
