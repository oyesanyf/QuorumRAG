//! E2E Tests: Storage Engine Isolation, LanceDB Hybrid Search, & Arrow Encapsulation.
//!
//! Tiers covered:
//! - Tier 1: Feature Coverage (Arrow type isolation, LanceDB vector search, Tantivy BM25, RRF hybrid fusion, compaction)
//! - Tier 2: Boundary & Corner Cases (empty insert, zero vector, out-of-bounds top_k, SQL pre-filter tier limits, compaction dedup)

use quorum_e2e::*;
use quorum_types::{AccessTier, DocumentChunk};

// ============================================================================
// TIER 1: FEATURE COVERAGE (>=5 test cases)
// ============================================================================

#[test]
fn test_storage_arrow_type_isolation_contract() {
    // Invariant: Storage crate and public APIs expose ZERO Arrow types.
    let chunk = DocumentChunk::new(
        "chunk_iso_1",
        "doc_iso_1",
        "crates/core/src/lib.rs",
        1,
        20,
        0,
        vec![0.05; 768],
        "pub fn core_logic() -> bool { true }",
        None,
    )
    .expect("Valid chunk");

    let mut engine = IsolatedStorageEngine::new();
    let inserted = engine.insert_chunks(&[chunk.clone()]);
    assert_eq!(inserted, 1);

    // Verify retrieval returns pure domain types (ScoredChunk / DocumentChunk)
    let hits = engine.search_vector(&vec![0.05; 768], 0, 5);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].chunk.chunk_id, "chunk_iso_1");
    assert_eq!(hits[0].chunk.document_id, "doc_iso_1");
    assert_eq!(hits[0].chunk.file_path, "crates/core/src/lib.rs");
    assert!(!hits[0].is_remote);
}

#[test]
fn test_storage_vector_cosine_similarity_ordering() {
    let mut engine = IsolatedStorageEngine::new();

    let chunk_close = DocumentChunk::new(
        "c_close",
        "doc_1",
        "file1.rs",
        1,
        5,
        0,
        vec![1.0; 768], // Identical direction to query
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
        vec![0.0; 768], // Zero / orthogonal direction
        "fn beta() {}",
        None,
    )
    .unwrap();

    engine.insert_chunks(&[chunk_close, chunk_ortho]);

    let query_vector = vec![1.0; 768];
    let hits = engine.search_vector(&query_vector, 0, 10);

    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].chunk.chunk_id, "c_close");
    assert!((hits[0].score - 1.0).abs() < 1e-4, "Exact match should have cosine similarity ~1.0");
    assert!(hits[0].score > hits[1].score);
}

#[test]
fn test_storage_keyword_search_bm25() {
    let mut engine = IsolatedStorageEngine::new();

    let chunk1 = DocumentChunk::new(
        "c_kv1",
        "doc_kv",
        "src/auth.rs",
        10,
        25,
        0,
        vec![0.1; 768],
        "Authenticate user with Ed25519 digital signature and verify public key",
        None,
    )
    .unwrap();

    let chunk2 = DocumentChunk::new(
        "c_kv2",
        "doc_kv",
        "src/ui.rs",
        1,
        15,
        0,
        vec![0.1; 768],
        "Render ChatGPT HTML interface with 5-theme switcher and sidebar",
        None,
    )
    .unwrap();

    engine.insert_chunks(&[chunk1, chunk2]);

    let auth_hits = engine.search_text("Ed25519 digital signature", 0, 5);
    assert_eq!(auth_hits.len(), 1);
    assert_eq!(auth_hits[0].chunk.chunk_id, "c_kv1");
    assert!(auth_hits[0].chunk.text_content.contains("Ed25519"));

    let ui_hits = engine.search_text("ChatGPT sidebar", 0, 5);
    assert_eq!(ui_hits.len(), 1);
    assert_eq!(ui_hits[0].chunk.chunk_id, "c_kv2");
}

#[test]
fn test_storage_hybrid_search_rrf_combination() {
    let mut engine = IsolatedStorageEngine::new();

    // Chunk that matches both vector and keyword queries
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

    // Chunk that matches only keyword query
    let chunk_kw_only = DocumentChunk::new(
        "c_kw",
        "doc_kw",
        "kw.rs",
        1,
        10,
        0,
        vec![-1.0; 768], // Opposite vector direction
        "Kademlia distributed hash table protocol",
        None,
    )
    .unwrap();

    engine.insert_chunks(&[chunk_dual, chunk_kw_only]);

    let query_text = "Kademlia protocol";
    let query_vector = vec![1.0; 768];

    let hits = engine.search_hybrid(query_text, &query_vector, 0, 5);
    assert!(!hits.is_empty());
    // Dual match must be ranked #1 due to accumulating RRF scores from both vector and keyword ranks
    assert_eq!(hits[0].chunk.chunk_id, "c_dual");
}

#[test]
fn test_storage_has_chunk_hash_deduplication() {
    let mut engine = IsolatedStorageEngine::new();
    let text = "Unique chunk payload for BLAKE3 cataloging";
    let expected_hash = DocumentChunk::compute_blake3_hash(text);

    let chunk = DocumentChunk::new(
        "c_hash_test",
        "doc_hash",
        "data.txt",
        1,
        1,
        0,
        vec![0.2; 768],
        text,
        None,
    )
    .unwrap();

    assert!(!engine.has_chunk_hash(&expected_hash));
    engine.insert_chunks(&[chunk]);
    assert!(engine.has_chunk_hash(&expected_hash));
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (>=5 test cases)
// ============================================================================

#[test]
fn test_storage_boundary_empty_chunks_insert() {
    let mut engine = IsolatedStorageEngine::new();
    let inserted = engine.insert_chunks(&[]);
    assert_eq!(inserted, 0);
    assert_eq!(engine.len(), 0);
    assert!(engine.is_empty());
}

#[test]
fn test_storage_boundary_zero_vector_query() {
    let mut engine = IsolatedStorageEngine::new();
    let chunk = DocumentChunk::new("c1", "d1", "f1.rs", 1, 2, 0, vec![0.5; 768], "content", None).unwrap();
    engine.insert_chunks(&[chunk]);

    // All zero vector has norm = 0.0
    let zero_vec = vec![0.0; 768];
    let hits = engine.search_vector(&zero_vec, 0, 5);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].score, 0.0, "Zero norm vector must yield 0.0 similarity without NaN/panic");
}

#[test]
fn test_storage_boundary_huge_top_k_exceeding_table_size() {
    let mut engine = IsolatedStorageEngine::new();
    for i in 0..5 {
        let chunk = DocumentChunk::new(
            format!("c_{}", i),
            "doc_small",
            "file.rs",
            i as u32,
            i as u32 + 1,
            0,
            vec![0.1 * (i as f32); 768],
            format!("Text content line {}", i),
            None,
        )
        .unwrap();
        engine.insert_chunks(&[chunk]);
    }

    let hits = engine.search_vector(&vec![0.2; 768], 0, 100_000);
    assert_eq!(hits.len(), 5, "Requesting 100,000 hits must safely cap at existing row count");
}

#[test]
fn test_storage_boundary_sql_prefilter_tier_isolation() {
    let mut engine = IsolatedStorageEngine::new();

    // Create chunks across all 4 tiers
    let c_public = DocumentChunk::new("c_pub", "d1", "pub.rs", 1, 5, AccessTier::Tier0Public.as_u8(), vec![1.0; 768], "public doc", None).unwrap();
    let c_internal = DocumentChunk::new("c_int", "d2", "int.rs", 1, 5, AccessTier::Tier1Internal.as_u8(), vec![1.0; 768], "internal doc", None).unwrap();
    let c_confidential = DocumentChunk::new("c_conf", "d3", "conf.rs", 1, 5, AccessTier::Tier2Confidential.as_u8(), vec![1.0; 768], "confidential doc", None).unwrap();
    let c_restricted = DocumentChunk::new("c_rest", "d4", "rest.rs", 1, 5, AccessTier::Tier3Restricted.as_u8(), vec![1.0; 768], "restricted doc", None).unwrap();

    engine.insert_chunks(&[c_public, c_internal, c_confidential, c_restricted]);

    // Query with Tier 0 (Public): Must ONLY return public doc
    let hits_tier0 = engine.search_vector(&vec![1.0; 768], 0, 10);
    assert_eq!(hits_tier0.len(), 1);
    assert_eq!(hits_tier0[0].chunk.chunk_id, "c_pub");

    // Query with Tier 1 (Internal): Returns public + internal
    let hits_tier1 = engine.search_vector(&vec![1.0; 768], 1, 10);
    assert_eq!(hits_tier1.len(), 2);
    let ids: Vec<&str> = hits_tier1.iter().map(|h| h.chunk.chunk_id.as_str()).collect();
    assert!(ids.contains(&"c_pub"));
    assert!(ids.contains(&"c_int"));

    // Query with Tier 2 (Confidential): Returns public + internal + confidential
    let hits_tier2 = engine.search_vector(&vec![1.0; 768], 2, 10);
    assert_eq!(hits_tier2.len(), 3);
    assert!(!hits_tier2.iter().any(|h| h.chunk.chunk_id == "c_rest"));

    // Query with Tier 3 (Restricted): Returns all 4 documents
    let hits_tier3 = engine.search_vector(&vec![1.0; 768], 3, 10);
    assert_eq!(hits_tier3.len(), 4);
}

#[test]
fn test_storage_boundary_compaction_deduplication() {
    let mut engine = IsolatedStorageEngine::new();

    let chunk = DocumentChunk::new("c_dup", "doc", "f.rs", 1, 2, 0, vec![0.1; 768], "same text", None).unwrap();
    engine.insert_chunks(&[chunk.clone()]);
    // Duplicate insertion with same text hash
    engine.insert_chunks(&[chunk]);

    assert_eq!(engine.len(), 1, "Duplicate BLAKE3 hash must be ignored on insert");
    assert!(engine.compact().is_ok());
    assert_eq!(engine.len(), 1);
}
