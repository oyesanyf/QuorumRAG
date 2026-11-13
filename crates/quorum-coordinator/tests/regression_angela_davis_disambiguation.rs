//! Regression test suite for Milestone M9:
//! Two-Layer Homonym Entity Disambiguation (Angela Davis Fix), Zero Pretraining Backfill & Distractor Isolation.
//!
//! Verifies:
//! 1. "WHO IS ANGELA DAVIS" disambiguates multiple distinct personas sharing the name.
//! 2. Layer 1: Graph-level entity domain clustering groups chunks into:
//!    - Academic & Critical Theory Works (1981 author of *Women, Race & Class*),
//!    - New Orleans Residential Property Management & Lease Agreement (lessor / landlord).
//! 3. Remote proper-noun quorum enforcement drops remote distractor documents:
//!    `Zrubrics Clarification.docx` and `Zoom Presentation Feedback.docx`.
//! 4. Layer 2: Prompt hard-grounding enforces zero pretraining backfill:
//!    `assert!(!answer.contains("Born as Angela Yvonne Davis"))`.
//! 5. Output features an upfront disambiguation disclaimer and dedicated `###` headed sections.

use std::sync::Arc;
use tempfile::tempdir;
use quorum_types::{DocumentChunk, ScoredChunk};
use quorum_coordinator::{
    answer_orchestrator::classify_entity_domain_cluster,
    offline_engine::DeterministicOfflineSynthesisEngine,
    QueryCoordinator, CoordinatorConfig, ScatterGatherEngine, PeerAclManager,
    SynthesisModelFamily,
};

#[test]
fn test_entity_domain_cluster_classification() {
    let scholar_text = "Angela Davis is the author of Women, Race & Class (1981), exploring Marxist feminism and critical theory.";
    let scholar_path = "C:/Docs/Women_Race_Class_1981.pdf";
    assert_eq!(
        classify_entity_domain_cluster(scholar_path, scholar_text),
        "Academic & Critical Theory Works (1981)"
    );

    let lease_text = "SIMPLE LEASE AGREEMENT between Angela Davis (landlord) and Casey Ringgold (tenant) for 2913 Castiglione St., New Orleans, LA.";
    let lease_path = "C:/Leases/Susan MONTH TO MONTH LEASE AGREEMENT.doc";
    assert_eq!(
        classify_entity_domain_cluster(lease_path, lease_text),
        "New Orleans Residential Property Management & Lease Agreement"
    );

    let ava_lease_text = "RESIDENTIAL LEASE AGREEMENT for dwelling unit. Rent paid to Angela Davis (landlord) after the 3rd of each month.";
    let ava_lease_path = "C:/Leases/Ava Davis LEASE AGREEMENT.doc";
    assert_eq!(
        classify_entity_domain_cluster(ava_lease_path, ava_lease_text),
        "New Orleans Residential Property Management & Lease Agreement",
        "Ava Davis LEASE AGREEMENT must stay in landlord cluster when Angela Davis appears as landlord"
    );
}

#[tokio::test]
async fn test_who_is_angela_davis_two_layer_disambiguation() {
    let temp_dir = tempdir().expect("tempdir");
    let storage_config = quorum_storage::StorageConfig::new(temp_dir.path().to_path_buf());
    let storage = Arc::new(
        quorum_storage::StorageEngine::open(storage_config)
            .await
            .expect("storage open"),
    );

    let dummy_embedding = vec![0.0f32; 768];

    // 1. Scholar chunk: 1981 author of Women, Race & Class
    let scholar_chunk = DocumentChunk::new(
        "doc_scholar_0",
        "doc_scholar",
        "C:/Library/Angela_Davis_Women_Race_Class_1981.pdf",
        1,
        25,
        0,
        dummy_embedding.clone(),
        "Angela Davis authored Women, Race & Class in 1981, providing critical theory on intersectional oppression, historical capitalism, and systemic racism.",
        Some(r#"{"doc_title":"Women, Race & Class","doc_author":"Angela Davis","year":"1981"}"#.to_string()),
    ).expect("chunk");

    // 2. Lessor chunk 1: Susan lease in New Orleans
    let lease_chunk_1 = DocumentChunk::new(
        "doc_lease_1",
        "doc_lease_susan",
        "C:/Leases/Susan MONTH TO MONTH LEASE AGREEMENT.doc",
        1,
        30,
        0,
        dummy_embedding.clone(),
        "SIMPLE LEASE AGREEMENT made between Angela Davis (landlord) and Casey Ringgold (tenant) for the dwelling unit located at 2913 Castiglione St. New Orleans, LA 70119. Rent is $614.00 per month.",
        Some(r#"{"doc_title":"Susan Month to Month Lease","role":"landlord","city":"New Orleans"}"#.to_string()),
    ).expect("chunk");

    // 3. Lessor chunk 2: Ava Davis lease in New Orleans with Firldeal Breure
    let lease_chunk_2 = DocumentChunk::new(
        "doc_lease_2",
        "doc_lease_ava",
        "C:/Leases/Ava Davis LEASE AGREEMENT.doc",
        1,
        30,
        0,
        dummy_embedding.clone(),
        "RESIDENTIAL LEASE AGREEMENT entered into between Angela Davis, also referenced as Firldeal ('Angela Davis') Breure, and Jamie Williams for 4023 D'Hemecourt St. New Orleans. Rent payment due on the first day.",
        Some(r#"{"doc_title":"Ava Davis Lease Agreement","role":"landlord","city":"New Orleans"}"#.to_string()),
    ).expect("chunk");

    // 4. Remote distractor chunks (do NOT mention both Angela and Davis, or only distractor topics)
    let distractor_chunk_1 = DocumentChunk::new(
        "doc_distractor_1",
        "doc_distractor_zrubrics",
        "C:/Projects/Zrubrics Clarification.docx",
        1,
        20,
        0,
        dummy_embedding.clone(),
        "Zrubrics Clarification document explaining student rubric scoring metrics, grading scales, and evaluative benchmarks.",
        None,
    ).expect("chunk");

    let distractor_chunk_2 = DocumentChunk::new(
        "doc_distractor_2",
        "doc_distractor_zoom",
        "C:/Projects/Zoom Presentation Feedback.docx",
        1,
        20,
        0,
        dummy_embedding.clone(),
        "Zoom Presentation Feedback notes regarding audio visual setup, participant engagement, and camera framing.",
        None,
    ).expect("chunk");

    storage.insert_chunks(&[
        scholar_chunk,
        lease_chunk_1,
        lease_chunk_2,
        distractor_chunk_1,
        distractor_chunk_2,
    ]).await.expect("insert");

    let node_seed = [0x5Cu8; 32];
    let scatter_gather = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn quorum_coordinator::StorageSearcher>,
        Arc::new(quorum_coordinator::LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        node_seed,
        "12D3KooWAngelaTestNode".to_string(),
    ));

    let coordinator = Arc::new(QueryCoordinator::new(
        scatter_gather,
        CoordinatorConfig::default(),
    ));

    let query = "WHO IS ANGELA DAVIS";
    let result = coordinator
        .query_agentic_with_history_and_session(
            query,
            Vec::new(),
            SynthesisModelFamily::AutoFusion,
            12,
            std::collections::HashSet::new(),
            None,
        )
        .await
        .expect("query");

    let answer = result.synthesis_prompt;

    // 1. Assert upfront disambiguation disclaimer
    assert!(
        answer.contains("multiple distinct individuals") || answer.contains("distinct personas") || answer.contains("distinct contexts"),
        "Answer must contain upfront disambiguation disclaimer stating multiple distinct individuals share the name: {}",
        answer
    );

    // 2. Assert separate headed sections
    assert!(
        answer.contains("### Academic & Critical Theory Works (1981)") || answer.contains("### Academic"),
        "Answer must contain separate section for Academic & Critical Theory Works: {}",
        answer
    );
    assert!(
        answer.contains("### New Orleans Residential Property Management & Lease Agreement") || answer.contains("### New Orleans"),
        "Answer must contain separate section for New Orleans Residential Property Management: {}",
        answer
    );

    // 3. Assert zero pretraining backfill (NO "Born as Angela Yvonne Davis")
    assert!(
        !answer.contains("Born as Angela Yvonne Davis"),
        "Answer must strictly respect corpus hard-grounding with ZERO pretraining backfill: {}",
        answer
    );

    // 4. Assert zero distractor leaks
    assert!(
        !answer.contains("Zrubrics"),
        "Answer must NOT leak remote distractor Zrubrics Clarification.docx: {}",
        answer
    );
    assert!(
        !answer.contains("Zoom Presentation"),
        "Answer must NOT leak remote distractor Zoom Presentation Feedback.docx: {}",
        answer
    );

    // 5. Assert factual details
    assert!(
        answer.contains("Women, Race & Class") || answer.contains("1981"),
        "Answer must mention 1981 work Women, Race & Class: {}",
        answer
    );
    assert!(
        answer.contains("New Orleans") && (answer.contains("2913 Castiglione") || answer.contains("4023 D'Hemecourt")),
        "Answer must mention New Orleans properties: {}",
        answer
    );
}
