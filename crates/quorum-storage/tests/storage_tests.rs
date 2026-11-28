//! Integration tests for QuorumRAG embedded storage engine.
//!
//! Invariants verified:
//! - Arrow type boundary isolation: ZERO Arrow types leak into public interface.
//! - LanceDB Cosine vector search with SQL pre-filtering (`access_tier <= max_tier`).
//! - Co-located Tantivy BM25 full-text search.
//! - Storage-level Reciprocal Rank Fusion (RRF) hybrid combination.
//! - Level-2 BLAKE3 deduplication on insert.
//! - Compaction and file lifecycle.

use quorum_storage::{CompactionStats, SearchMode, StorageConfig, StorageEngine, StorageSearchQuery};
use quorum_types::{AccessTier, DocumentChunk};
use tempfile::tempdir;

#[allow(clippy::too_many_arguments)]
fn sample_chunk(
    chunk_id: &str,
    doc_id: &str,
    file_path: &str,
    start: u32,
    end: u32,
    tier: u8,
    vector_val: f32,
    text: &str,
) -> DocumentChunk {
    DocumentChunk::new(
        chunk_id,
        doc_id,
        file_path,
        start,
        end,
        tier,
        vec![vector_val; 768],
        text,
        Some("{\"source\":\"unit_test\"}".to_string()),
    )
    .expect("Valid chunk")
}

#[tokio::test]
async fn test_storage_arrow_type_isolation_contract() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(config).await.expect("StorageEngine open failed");

    let chunk = sample_chunk(
        "chunk_iso_1",
        "doc_iso_1",
        "crates/core/src/lib.rs",
        1,
        20,
        0,
        0.05,
        "pub fn core_logic() -> bool { true }",
    );

    let inserted = engine.insert_chunks(std::slice::from_ref(&chunk)).await.unwrap();
    assert_eq!(inserted, 1);
    assert_eq!(engine.count().await.unwrap(), 1);

    // Verify retrieval returns pure domain types (ScoredChunk / DocumentChunk)
    let hits = engine.search_vector(&vec![0.05; 768], 0, 5).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].chunk.chunk_id, "chunk_iso_1");
    assert_eq!(hits[0].chunk.document_id, "doc_iso_1");
    assert_eq!(hits[0].chunk.file_path, "crates/core/src/lib.rs");
    assert_eq!(hits[0].chunk.access_tier, 0);
    assert!(!hits[0].is_remote);
    assert_eq!(hits[0].source_peer, "local");
}

#[tokio::test]
async fn test_storage_vector_cosine_similarity_ordering() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk_close = DocumentChunk::new(
        "c_close",
        "doc_1",
        "file1.rs",
        1,
        5,
        0,
        vec![1.0; 768], // Identical direction
        "fn alpha() {}",
        None,
    )
    .unwrap();

    let chunk_ortho = DocumentChunk::new(
        "c_ortho",
        "doc_2",
        "file2.rs",
        1,
        5,
        0,
        vec![0.0; 768], // Orthogonal / zero direction
        "fn beta() {}",
        None,
    )
    .unwrap();

    engine.insert_chunks(&[chunk_close, chunk_ortho]).await.unwrap();

    let query_vector = vec![1.0; 768];
    let hits = engine.search_vector(&query_vector, 0, 10).await.unwrap();

    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].chunk.chunk_id, "c_close");
    assert!((hits[0].score - 1.0).abs() < 1e-3, "Exact match should have cosine similarity ~1.0");
    assert!(hits[0].score > hits[1].score);
}

#[tokio::test]
async fn test_storage_keyword_search_bm25() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk1 = sample_chunk(
        "c_kv1",
        "doc_kv",
        "src/auth.rs",
        10,
        25,
        0,
        0.1,
        "Authenticate user with Ed25519 digital signature and verify public key",
    );

    let chunk2 = sample_chunk(
        "c_kv2",
        "doc_kv",
        "src/ui.rs",
        1,
        15,
        0,
        0.1,
        "Render ChatGPT HTML interface with 5-theme switcher and sidebar",
    );

    engine.insert_chunks(&[chunk1, chunk2]).await.unwrap();

    let auth_hits = engine.search_text("Ed25519 digital signature", 0, 5).await.unwrap();
    assert_eq!(auth_hits.len(), 1);
    assert_eq!(auth_hits[0].chunk.chunk_id, "c_kv1");
    assert!(auth_hits[0].chunk.text_content.contains("Ed25519"));

    let ui_hits = engine.search_text("ChatGPT sidebar", 0, 5).await.unwrap();
    assert_eq!(ui_hits.len(), 1);
    assert_eq!(ui_hits[0].chunk.chunk_id, "c_kv2");
}

#[tokio::test]
async fn test_storage_hybrid_search_rrf_combination() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Chunk that matches both vector direction and keyword query
    let chunk_dual = DocumentChunk::new(
        "c_dual",
        "doc_dual",
        "dual.rs",
        1,
        10,
        0,
        vec![1.0; 768],
        "Kademlia distributed hash table routing protocol for p2p swarm",
        None,
    )
    .unwrap();

    // Chunk that matches only keyword query (opposite vector)
    let chunk_kw_only = DocumentChunk::new(
        "c_kw",
        "doc_kw",
        "kw.rs",
        1,
        10,
        0,
        vec![-1.0; 768],
        "Kademlia distributed hash table protocol",
        None,
    )
    .unwrap();

    engine.insert_chunks(&[chunk_dual, chunk_kw_only]).await.unwrap();

    let query_text = "Kademlia protocol";
    let query_vector = vec![1.0; 768];

    let hits = engine.search_hybrid(query_text, &query_vector, 0, 5).await.unwrap();
    assert!(!hits.is_empty());
    // Dual match must be ranked #1 due to accumulated RRF scores from both vector and keyword ranks
    assert_eq!(hits[0].chunk.chunk_id, "c_dual");
}

#[tokio::test]
async fn test_storage_sql_prefilter_tier_isolation() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let c_pub = sample_chunk("c_pub", "d1", "pub.rs", 1, 5, AccessTier::Tier0Public.as_u8(), 1.0, "public doc");
    let c_int = sample_chunk("c_int", "d2", "int.rs", 1, 5, AccessTier::Tier1Internal.as_u8(), 1.0, "internal doc");
    let c_conf = sample_chunk("c_conf", "d3", "conf.rs", 1, 5, AccessTier::Tier2Confidential.as_u8(), 1.0, "confidential doc");
    let c_rest = sample_chunk("c_rest", "d4", "rest.rs", 1, 5, AccessTier::Tier3Restricted.as_u8(), 1.0, "restricted doc");

    engine.insert_chunks(&[c_pub, c_int, c_conf, c_rest]).await.unwrap();

    // Tier 0 (Public): Only Tier 0
    let hits_tier0 = engine.search_vector(&vec![1.0; 768], 0, 10).await.unwrap();
    assert_eq!(hits_tier0.len(), 1);
    assert_eq!(hits_tier0[0].chunk.chunk_id, "c_pub");

    // Tier 1 (Internal): Tier 0 + Tier 1
    let hits_tier1 = engine.search_vector(&vec![1.0; 768], 1, 10).await.unwrap();
    assert_eq!(hits_tier1.len(), 2);
    let ids1: Vec<&str> = hits_tier1.iter().map(|h| h.chunk.chunk_id.as_str()).collect();
    assert!(ids1.contains(&"c_pub"));
    assert!(ids1.contains(&"c_int"));

    // Tier 2 (Confidential): Tier 0 + 1 + 2 (No Tier 3)
    let hits_tier2 = engine.search_vector(&vec![1.0; 768], 2, 10).await.unwrap();
    assert_eq!(hits_tier2.len(), 3);
    assert!(!hits_tier2.iter().any(|h| h.chunk.chunk_id == "c_rest"));

    // Tier 3 (Restricted): All 4 documents
    let hits_tier3 = engine.search_vector(&vec![1.0; 768], 3, 10).await.unwrap();
    assert_eq!(hits_tier3.len(), 4);
}

#[tokio::test]
async fn test_storage_level2_blake3_dedup() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let text = "Unique chunk payload for BLAKE3 cataloging";
    let expected_hash = DocumentChunk::compute_blake3_hash(text);

    let chunk = sample_chunk("c_hash_test", "doc_hash", "data.txt", 1, 1, 0, 0.2, text);

    assert!(!engine.has_chunk_hash(&expected_hash).await.unwrap());
    let inserted1 = engine.insert_chunks(std::slice::from_ref(&chunk)).await.unwrap();
    assert_eq!(inserted1, 1);
    assert!(engine.has_chunk_hash(&expected_hash).await.unwrap());

    // Duplicate insertion: must be ignored on insert
    let inserted2 = engine.insert_chunks(&[chunk]).await.unwrap();
    assert_eq!(inserted2, 0);
    assert_eq!(engine.count().await.unwrap(), 1);
}

#[tokio::test]
async fn test_storage_boundary_corner_cases() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // 1. Empty insert
    let inserted_empty = engine.insert_chunks(&[]).await.unwrap();
    assert_eq!(inserted_empty, 0);
    assert!(engine.is_empty().await.unwrap());

    // 2. Zero-norm vector query
    let chunk = sample_chunk("c1", "d1", "f1.rs", 1, 2, 0, 0.5, "content payload");
    engine.insert_chunks(&[chunk]).await.unwrap();
    let zero_vec = vec![0.0; 768];
    let zero_hits = engine.search_vector(&zero_vec, 0, 5).await.unwrap();
    assert_eq!(zero_hits.len(), 1);
    assert_eq!(zero_hits[0].score, 0.0, "Zero norm vector must yield 0.0 score without NaN/panic");

    // 3. Huge top_k exceeding table size
    let huge_hits = engine.search_vector(&vec![0.5; 768], 0, 100_000).await.unwrap();
    assert_eq!(huge_hits.len(), 1, "Requesting 100,000 hits must cap safely at actual row count");

    // 4. Empty/whitespace text query
    let empty_text_hits = engine.search_text("   ", 0, 5).await.unwrap();
    assert!(empty_text_hits.is_empty());
}

#[tokio::test]
async fn test_storage_search_mode_dispatcher() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk = sample_chunk("c_mode", "d_mode", "mode.rs", 1, 10, 0, 0.8, "Rust libp2p swarm dispatcher");
    engine.insert_chunks(&[chunk]).await.unwrap();

    // Mode: Vector
    let q_vec = StorageSearchQuery::vector(vec![0.8; 768], 0, 5);
    assert_eq!(q_vec.mode, SearchMode::Vector);
    let hits_vec = engine.search(&q_vec).await.unwrap();
    assert_eq!(hits_vec.len(), 1);
    assert_eq!(hits_vec[0].chunk.chunk_id, "c_mode");

    // Mode: Keyword
    let q_kw = StorageSearchQuery::keyword("libp2p swarm", 0, 5);
    assert_eq!(q_kw.mode, SearchMode::Keyword);
    let hits_kw = engine.search(&q_kw).await.unwrap();
    assert_eq!(hits_kw.len(), 1);
    assert_eq!(hits_kw[0].chunk.chunk_id, "c_mode");

    // Mode: Hybrid
    let q_hyb = StorageSearchQuery::hybrid("libp2p swarm", vec![0.8; 768], 0, 5);
    assert_eq!(q_hyb.mode, SearchMode::Hybrid);
    let hits_hyb = engine.search(&q_hyb).await.unwrap();
    assert_eq!(hits_hyb.len(), 1);
    assert_eq!(hits_hyb[0].chunk.chunk_id, "c_mode");
}

#[tokio::test]
async fn test_storage_compaction_and_lifecycle() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let c1 = sample_chunk("c1", "d1", "file_a.rs", 1, 10, 0, 0.1, "file a content");
    let c2 = sample_chunk("c2", "d2", "file_b.rs", 1, 10, 0, 0.2, "file b content");
    engine.insert_chunks(&[c1, c2]).await.unwrap();
    assert_eq!(engine.count().await.unwrap(), 2);

    // Delete file_a
    let deleted = engine.delete_by_file_path("file_a.rs").await.unwrap();
    assert_eq!(deleted, 1);

    // Compact
    let stats: CompactionStats = engine.compact().await.unwrap();
    assert!(stats.tantivy_segments_merged);
}

#[tokio::test]
async fn test_storage_index_epoch_persistence_and_atomic_bump() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path());
    let meta_file = config.metadata_path();

    // 1. Initial open creates .metadata.json with epoch = 1
    {
        let engine = StorageEngine::open(config.clone()).await.unwrap();
        assert_eq!(engine.index_epoch(), 1);
        assert!(meta_file.exists());

        let new_epoch = engine.bump_index_epoch("test_first_bump").unwrap();
        assert_eq!(new_epoch, 2);
        assert_eq!(engine.index_epoch(), 2);

        let meta = engine.metadata();
        assert_eq!(meta.index_epoch, 2);
        assert_eq!(meta.last_bump_reason, "test_first_bump");
        assert_eq!(meta.mutation_count, 1);
    }

    // 2. Re-opening existing directory loads persisted index_epoch = 2
    {
        let engine = StorageEngine::open(config.clone()).await.unwrap();
        assert_eq!(engine.index_epoch(), 2);

        engine.set_index_epoch(10, "explicit_reset").unwrap();
        assert_eq!(engine.index_epoch(), 10);
    }

    // 3. Confirm 10 persisted
    {
        let engine = StorageEngine::open(config).await.unwrap();
        assert_eq!(engine.index_epoch(), 10);
        let meta = engine.metadata();
        assert_eq!(meta.last_bump_reason, "explicit_reset");
    }
}

#[tokio::test]
async fn test_insert_chunks_tracks_active_subject_across_document_without_mutating_text() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(config).await.unwrap();

    let text_a0 = "Angela Davis is an American political activist and scholar.";
    let text_a1 = "She later published Women, Race & Class in 1981.";
    let text_b0 = "He wrote Sample Manual in 2020.";
    let text_artemis = "She later published Airgap Event in 2025.";

    let chunk_a0 = sample_chunk(
        "doc-angela:0",
        "doc-angela",
        "D:/Docs/bio_notes.txt",
        1,
        5,
        0,
        0.5,
        text_a0,
    );
    let chunk_a1 = sample_chunk(
        "doc-angela:1",
        "doc-angela",
        "D:/Docs/bio_notes.txt",
        6,
        10,
        0,
        0.5,
        text_a1,
    );
    let chunk_b0 = sample_chunk(
        "doc-other:0",
        "doc-other",
        "D:/Docs/other_notes.txt",
        1,
        5,
        2,
        0.5,
        text_b0,
    );
    let chunk_artemis = sample_chunk(
        "artemis-doc:0",
        "artemis-doc",
        "artemis://host-01/forensics.jsonl",
        1,
        5,
        0,
        0.5,
        text_artemis,
    );

    // Intentionally insert out-of-order (`chunk_a1` before `chunk_a0`)
    let inserted = engine
        .insert_chunks(&[chunk_a1, chunk_b0, chunk_artemis, chunk_a0])
        .await
        .unwrap();
    assert_eq!(inserted, 4);

    // 1. Source `text_content` and BLAKE3 hashes must remain completely untouched
    let stored = engine.scan_all_chunks().await.unwrap();
    let stored_a1 = stored
        .iter()
        .find(|c| c.chunk_id == "doc-angela:1")
        .expect("doc-angela:1 present");
    assert_eq!(stored_a1.text_content, text_a1);
    assert!(stored_a1.verify_hash());

    // 2. AtlasKV `query_entity_surface` at Tier 0 finds the resolved triple from Chunk 1
    let surfaced_t0 = engine
        .atlaskv()
        .query_entity_surface("Angela Davis", 0, 10, None)
        .unwrap();
    assert!(
        surfaced_t0.iter().any(|h| {
            h.triple.entity == "Angela Davis"
                && h.triple.relation == "published work"
                && h.triple.value == "Women, Race & Class"
                && text_a1.contains(&h.triple.value)
        }),
        "Expected resolved triple for Angela Davis from anaphoric chunk 1, got {surfaced_t0:#?}"
    );
    assert!(
        surfaced_t0.iter().all(|h| h.triple.access_tier == 0),
        "Tier > 0 must never leak into max_tier = 0 query"
    );
    assert!(
        !surfaced_t0
            .iter()
            .any(|h| h.triple.value.contains("Sample Manual") || h.triple.value.contains("Airgap Event")),
        "Cross-doc, Tier 2, and artemis:// chunks must not leak"
    );

    // 3. Even at Tier 3, `doc-other` (no antecedent) and `artemis://` must not inherit Angela Davis
    let surfaced_t3 = engine
        .atlaskv()
        .query_entity_surface("Angela Davis", 3, 20, None)
        .unwrap();
    assert!(
        !surfaced_t3
            .iter()
            .any(|h| h.triple.document_id == "doc-other" || h.triple.file_path.starts_with("artemis://")),
        "Cross-document or air-gap chunk leaked into Angela Davis entity surface: {surfaced_t3:#?}"
    );
}

#[tokio::test]
async fn test_insert_chunks_partial_batch_resolves_subject_from_catalog() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(config).await.unwrap();

    let chunk_0 = sample_chunk(
        "doc-partial:0",
        "doc-partial",
        "D:/Docs/partial_bio.txt",
        1,
        5,
        0,
        0.5,
        "Angela Davis taught at UCLA during her academic career.",
    );
    engine.insert_chunks(&[chunk_0]).await.unwrap();

    // Second separate insert_chunks call containing only anaphoric chunk 1
    let chunk_1 = sample_chunk(
        "doc-partial:1",
        "doc-partial",
        "D:/Docs/partial_bio.txt",
        6,
        10,
        0,
        0.5,
        "She later published Women, Race & Class in 1981.",
    );
    engine.insert_chunks(&[chunk_1]).await.unwrap();

    let surfaced = engine
        .atlaskv()
        .query_entity_surface("Angela Davis", 0, 10, None)
        .unwrap();
    assert!(
        surfaced.iter().any(|h| {
            h.triple.chunk_id == "doc-partial:1"
                && h.triple.relation == "published work"
                && h.triple.value == "Women, Race & Class"
        }),
        "Partial batch should resolve antecedent from DocumentCatalog: {surfaced:#?}"
    );
}

#[tokio::test]
async fn test_insert_chunks_subject_shift_slash_parity_and_no_stem_contamination() {
    let tmp = tempdir().unwrap();
    let config = StorageConfig::new(tmp.path()).with_vector_dimension(768);
    let engine = StorageEngine::open(config).await.unwrap();

    // Challenge 4: Intra-document subject shift from Angela Davis -> [Document: "Memo" | Author: Bob Smith ...]
    let shift_0 = sample_chunk(
        "doc-shift:0",
        "doc-shift",
        "D:/Docs/notes.txt",
        1,
        3,
        0,
        0.5,
        "Angela Davis is an activist.",
    );
    let shift_1 = sample_chunk(
        "doc-shift:1",
        "doc-shift",
        "D:/Docs/notes.txt",
        4,
        7,
        0,
        0.5,
        "[Document: \"Memo\" | Author: Bob Smith | Kind: report | File: notes.txt]\nIt requires annual audits.",
    );
    engine.insert_chunks(&[shift_0, shift_1]).await.unwrap();

    let memo_hits = engine
        .atlaskv()
        .query_entity_surface("Memo", 0, 10, None)
        .unwrap();
    assert!(
        memo_hits.iter().any(|h| {
            h.triple.entity == "Memo"
                && h.triple.relation == "provision"
                && h.triple.value == "annual audits"
        }),
        "Expected Memo provision triple after subject shift, got {memo_hits:#?}"
    );
    let angela_hits = engine
        .atlaskv()
        .query_entity_surface("Angela Davis", 0, 10, None)
        .unwrap();
    assert!(
        !angela_hits
            .iter()
            .any(|h| h.triple.chunk_id == "doc-shift:1" && h.triple.value == "annual audits"),
        "Prior subject Angela Davis must not hijack Memo provision: {angela_hits:#?}"
    );

    // Challenge 4b: Mixed slash style partial-batch lookup via DocumentCatalog::get_by_file_path
    let slash_0 = sample_chunk(
        "doc-slash:0",
        "doc-slash",
        "D:/Docs/slash_bio.txt",
        1,
        3,
        0,
        0.5,
        "Angela Davis taught at UCLA during her career.",
    );
    engine.insert_chunks(&[slash_0]).await.unwrap();
    let slash_1 = sample_chunk(
        "doc-slash:1",
        "doc-slash",
        r"D:\Docs\slash_bio.txt",
        4,
        7,
        0,
        0.5,
        "She later published Women, Race & Class in 1981.",
    );
    engine.insert_chunks(&[slash_1]).await.unwrap();

    let slash_hits = engine
        .atlaskv()
        .query_entity_surface("Angela Davis", 0, 10, None)
        .unwrap();
    assert!(
        slash_hits.iter().any(|h| {
            h.triple.chunk_id == "doc-slash:1"
                && h.triple.relation == "published work"
                && h.triple.value == "Women, Race & Class"
        }),
        "Mixed-slash partial batch should resolve antecedent from catalog: {slash_hits:#?}"
    );

    // Reviewer Finding 2: filename-stem KV triple on chunk 0 must NOT seed active subject for personal pronoun
    let stem_0 = sample_chunk(
        "doc-stem:0",
        "doc-stem",
        "D:/Docs/my_private_notes.txt",
        1,
        3,
        0,
        0.5,
        "Property Address: 412 Oakwood Lane",
    );
    let stem_1 = sample_chunk(
        "doc-stem:1",
        "doc-stem",
        "D:/Docs/my_private_notes.txt",
        4,
        7,
        0,
        0.5,
        "She later published Secret Treatise in 2024.",
    );
    engine.insert_chunks(&[stem_0, stem_1]).await.unwrap();

    let stem_hits = engine
        .atlaskv()
        .query_entity_surface("my private notes", 0, 10, None)
        .unwrap();
    assert!(
        !stem_hits
            .iter()
            .any(|h| h.triple.relation == "published work" && h.triple.value == "Secret Treatise"),
        "Filename stem must not be bound to personal pronoun: {stem_hits:#?}"
    );
}
