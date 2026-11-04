//! Adversarial stress test suite for QuorumRAG embedded storage engine (LanceDB + Tantivy FTS).
//!
//! # Objective
//! Stress-test edge cases, boundary conditions, and failure modes across:
//! 1. Reciprocal Rank Fusion (RRF): identical ranks, pure keyword vs pure vector, opposing cosine similarity.
//! 2. Tantivy BM25 tokenization: non-ASCII UTF-8, punctuation, regex-like tokens, empty text payloads.
//! 3. Compaction resilience: repeated empty compaction, post-deletion compaction, concurrent read/compaction stress.
//! 4. Windows filesystem resilience: complex file paths with quotes and backslashes.

use std::sync::Arc;
use std::time::Duration;

use quorum_storage::StorageEngine;
use quorum_types::DocumentChunk;
use tempfile::tempdir;
use tokio::time::sleep;

/// Helper to create a canonical sample chunk for adversarial testing.
#[allow(clippy::too_many_arguments)]
fn make_chunk(
    chunk_id: &str,
    doc_id: &str,
    file_path: &str,
    start: u32,
    end: u32,
    tier: u8,
    vector: Vec<f32>,
    text: &str,
) -> DocumentChunk {
    DocumentChunk::new(
        chunk_id,
        doc_id,
        file_path,
        start,
        end,
        tier,
        vector,
        text,
        Some("{\"adversarial\":true}".to_string()),
    )
    .expect("Valid chunk creation")
}

// ============================================================================
// Group 1: Reciprocal Rank Fusion (RRF) Adversarial Tests
// ============================================================================

#[tokio::test]
async fn test_adversarial_rrf_identical_ranks_deterministic_tiebreak() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Create 3 chunks with identical RRF rank potential:
    // Chunks have identical vectors and equal-length text containing identical query terms,
    // but distinct initial tokens ("alpha", "beta", "gamma") so Level-2 BLAKE3 deduplication
    // does not skip inserting them.
    // We verify that ties are broken deterministically by chunk_id ASC across all iterations.
    let base_vec = vec![0.5; 768];
    let chunk_a = make_chunk(
        "chunk_tie_alpha",
        "doc_tie",
        "tie_a.rs",
        1,
        10,
        0,
        base_vec.clone(),
        "alpha semantic payload tie breaker evaluation",
    );
    let chunk_b = make_chunk(
        "chunk_tie_beta",
        "doc_tie",
        "tie_b.rs",
        1,
        10,
        0,
        base_vec.clone(),
        "beta semantic payload tie breaker evaluation",
    );
    let chunk_c = make_chunk(
        "chunk_tie_gamma",
        "doc_tie",
        "tie_c.rs",
        1,
        10,
        0,
        base_vec.clone(),
        "gamma semantic payload tie breaker evaluation",
    );

    engine
        .insert_chunks(&[chunk_a, chunk_b, chunk_c])
        .await
        .unwrap();

    let query_text = "semantic payload tie breaker";
    let query_vector = base_vec;

    // Run hybrid query 20 times across multiple iterations
    let first_result = engine
        .search_hybrid(query_text, &query_vector, 0, 5)
        .await
        .unwrap();
    assert_eq!(first_result.len(), 3);

    // Verify that all co-scoring chunks receive identical RRF scores
    assert!(
        (first_result[0].score - first_result[1].score).abs() < 1e-6,
        "Co-scoring chunks must receive identical RRF score"
    );
    assert!(
        (first_result[1].score - first_result[2].score).abs() < 1e-6,
        "Co-scoring chunks must receive identical RRF score"
    );

    let first_order: Vec<String> = first_result
        .iter()
        .map(|s| s.chunk.chunk_id.clone())
        .collect();

    // Verify ordering is strictly alphabetical for identical scores:
    // chunk_tie_alpha < chunk_tie_beta < chunk_tie_gamma
    assert_eq!(first_order[0], "chunk_tie_alpha");
    assert_eq!(first_order[1], "chunk_tie_beta");
    assert_eq!(first_order[2], "chunk_tie_gamma");

    for _ in 0..20 {
        let repeat = engine
            .search_hybrid(query_text, &query_vector, 0, 5)
            .await
            .unwrap();
        let repeat_order: Vec<String> = repeat
            .iter()
            .map(|s| s.chunk.chunk_id.clone())
            .collect();
        assert_eq!(
            first_order, repeat_order,
            "RRF ranking tie-breaker must be 100% deterministic across all iterations"
        );
    }
}

#[tokio::test]
async fn test_adversarial_rrf_pure_keyword_vs_pure_vector() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Chunk 1: Pure vector hit. High cosine similarity, but text contains completely unrelated vocabulary.
    let chunk_vec = make_chunk(
        "c_pure_vec",
        "doc_vec",
        "vec.rs",
        1,
        5,
        0,
        vec![1.0; 768],
        "apples oranges bananas tropical fruits agriculture",
    );

    // Chunk 2: Pure keyword hit. Text matches exact query keywords, but vector is orthogonal (0.0).
    let chunk_kw = make_chunk(
        "c_pure_kw",
        "doc_kw",
        "kw.rs",
        1,
        5,
        0,
        vec![0.0; 768],
        "quantum entanglement and non-local hidden variable theory",
    );

    // Chunk 3: Dual match. High vector similarity AND exact keyword match.
    let chunk_dual = make_chunk(
        "c_dual",
        "doc_dual",
        "dual.rs",
        1,
        5,
        0,
        vec![1.0; 768],
        "quantum entanglement non-local hidden variable theory bell inequalities",
    );

    engine
        .insert_chunks(&[chunk_vec, chunk_kw, chunk_dual])
        .await
        .unwrap();

    let query_text = "quantum entanglement hidden variable";
    let query_vector = vec![1.0; 768];

    let hits = engine
        .search_hybrid(query_text, &query_vector, 0, 10)
        .await
        .unwrap();

    // Dual match must accumulate RRF from both vector and keyword, placing it at #1
    assert!(!hits.is_empty());
    assert_eq!(hits[0].chunk.chunk_id, "c_dual");

    // Pure vector hit and pure keyword hit must both appear without panic or NaN
    let hit_ids: Vec<&str> = hits.iter().map(|h| h.chunk.chunk_id.as_str()).collect();
    assert!(hit_ids.contains(&"c_dual"));
    assert!(hit_ids.contains(&"c_pure_kw"));
    assert!(hit_ids.contains(&"c_pure_vec"));

    for hit in &hits {
        assert!(!hit.score.is_nan(), "RRF score must never be NaN");
        assert!(!hit.score.is_infinite(), "RRF score must not be infinite");
        assert!(hit.score > 0.0, "RRF score must be strictly positive");
    }
}

#[tokio::test]
async fn test_adversarial_rrf_opposing_vector_cosine_vs_text_matching() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Chunk with negative cosine similarity (-1.0) but exact keyword match
    let chunk_opposing_vec = make_chunk(
        "c_opposing",
        "doc_opp",
        "opp.rs",
        1,
        10,
        0,
        vec![-1.0; 768], // Directly opposing direction
        "Byzantine fault tolerant Paxos consensus state machine",
    );

    // Chunk with positive vector similarity (1.0) but no keyword match
    let chunk_positive_vec = make_chunk(
        "c_positive",
        "doc_pos",
        "pos.rs",
        1,
        10,
        0,
        vec![1.0; 768],
        "unrelated recipes for sourdough bread baking",
    );

    engine
        .insert_chunks(&[chunk_opposing_vec, chunk_positive_vec])
        .await
        .unwrap();

    let query_text = "Byzantine Paxos consensus";
    let query_vector = vec![1.0; 768];

    let hits = engine
        .search_hybrid(query_text, &query_vector, 0, 5)
        .await
        .unwrap();

    // The opposing vector chunk must NOT receive vector rank (because vector score <= 0.0 is filtered),
    // but it MUST receive keyword rank from text search.
    // The positive vector chunk receives vector rank, but no keyword rank.
    let opp_hit = hits.iter().find(|h| h.chunk.chunk_id == "c_opposing");
    assert!(
        opp_hit.is_some(),
        "Opposing vector chunk with keyword match must be retained in hybrid results"
    );

    // Expected RRF for rank 1 text: 1.0 / (60.0 + 1.0) = 1.0 / 61.0 ~= 0.016393
    let expected_single_modality_rrf = 1.0 / 61.0;
    let actual_score = opp_hit.unwrap().score;
    assert!(
        (actual_score - expected_single_modality_rrf).abs() < 1e-4,
        "Opposing vector must accumulate solely keyword rank ({}), got {}",
        expected_single_modality_rrf,
        actual_score
    );
}

#[tokio::test]
async fn test_adversarial_rrf_extreme_parameters_and_zero_norms() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk = make_chunk(
        "c_param",
        "doc_p",
        "p.rs",
        1,
        5,
        0,
        vec![0.1; 768],
        "test parameter bounds",
    );
    engine.insert_chunks(&[chunk]).await.unwrap();

    // 1. top_k = 0: must return empty Vec gracefully
    let hits_zero = engine
        .search_hybrid("test", &vec![0.1; 768], 0, 0)
        .await
        .unwrap();
    assert!(hits_zero.is_empty());

    // 2. top_k = usize::MAX or very large: must cap at available rows
    let hits_large = engine
        .search_hybrid("test", &vec![0.1; 768], 0, 50_000)
        .await
        .unwrap();
    assert_eq!(hits_large.len(), 1);

    // 3. All-zero vector query: must not divide by zero or panic
    let zero_vec = vec![0.0; 768];
    let hits_zero_vec = engine.search_hybrid("test", &zero_vec, 0, 5).await.unwrap();
    assert_eq!(hits_zero_vec.len(), 1);

    // 4. Non-matching keyword + zero vector query: returns empty
    let hits_empty = engine
        .search_hybrid("xyznonexistentvocab987", &zero_vec, 0, 5)
        .await
        .unwrap();
    assert!(hits_empty.is_empty());
}

// ============================================================================
// Group 2: Tantivy BM25 Tokenization Adversarial Tests
// ============================================================================

#[tokio::test]
async fn test_adversarial_tantivy_non_ascii_multilingual() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunks = vec![
        make_chunk(
            "c_cjk",
            "doc_cjk",
            "chinese.rs",
            1,
            10,
            0,
            vec![0.2; 768],
            "零知识证明与环签名的隐私保密分布式账本技术架构",
        ),
        make_chunk(
            "c_cyrillic",
            "doc_ru",
            "russian.rs",
            1,
            10,
            0,
            vec![0.2; 768],
            "Квантово-устойчивая криптография и распределенные протоколы консенсуса",
        ),
        make_chunk(
            "c_arabic",
            "doc_ar",
            "arabic.rs",
            1,
            10,
            0,
            vec![0.2; 768],
            "تشفير ما بعد الكم وخوارزميات التوزيع اللامركزية عبر الشبكات",
        ),
        make_chunk(
            "c_latin_diacritics",
            "doc_lat",
            "french.rs",
            1,
            10,
            0,
            vec![0.2; 768],
            "Système distribué de haute disponibilité avec résilience Byzantine et Übergröße",
        ),
        make_chunk(
            "c_emoji",
            "doc_em",
            "emoji.rs",
            1,
            10,
            0,
            vec![0.2; 768],
            "🦀 Rust 🚀 Rocket 🛡️ Security ZeroizeOnDrop 🔑 Ed25519",
        ),
    ];

    engine.insert_chunks(&chunks).await.unwrap();
    assert_eq!(engine.count().await.unwrap(), 5);

    // Search Cyrillic
    let ru_hits = engine.search_text("Квантово криптография", 0, 5).await.unwrap();
    assert!(!ru_hits.is_empty());
    assert_eq!(ru_hits[0].chunk.chunk_id, "c_cyrillic");
    assert!(ru_hits[0].chunk.text_content.contains("Квантово"));

    // Search Arabic
    let ar_hits = engine.search_text("تشفير اللامركزية", 0, 5).await.unwrap();
    assert!(!ar_hits.is_empty());
    assert_eq!(ar_hits[0].chunk.chunk_id, "c_arabic");

    // Search Diacritics
    let lat_hits = engine.search_text("Byzantine Übergröße", 0, 5).await.unwrap();
    assert!(!lat_hits.is_empty());
    assert_eq!(lat_hits[0].chunk.chunk_id, "c_latin_diacritics");

    // Search Emoji & ASCII terms mixed
    let em_hits = engine.search_text("ZeroizeOnDrop Ed25519", 0, 5).await.unwrap();
    assert!(!em_hits.is_empty());
    assert_eq!(em_hits[0].chunk.chunk_id, "c_emoji");
}

#[tokio::test]
async fn test_adversarial_tantivy_punctuation_and_query_syntax() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk = make_chunk(
        "c_syntax",
        "doc_syn",
        "syntax.rs",
        1,
        20,
        0,
        vec![0.3; 768],
        "SELECT * FROM users WHERE auth_token = 'secret'; function arc_rwlock<T>() -> Option<T>",
    );
    engine.insert_chunks(&[chunk]).await.unwrap();

    // Adversarial queries containing Lucene / Tantivy syntax characters
    let hostile_queries = vec![
        "auth_token:secret AND NOT",
        "SELECT * FROM",
        "+auth_token -unwanted",
        "((((unbalanced brackets",
        "unclosed \"quote string",
        "\"\"\" triple quotes \"\"\"",
        "REGEX: [a-zA-Z0-9_]+.*?",
        "^start.*end$",
        "\\path\\to\\file.rs",
        "http://127.0.0.1:8080/api/v1?token=xyz#hash",
        "' OR '1'='1'; DROP TABLE chunks; --",
        "$(whoami) `cat /etc/passwd`",
        "!@#$%^&*()_+-=[]{}|;':,.<>?/",
    ];

    for hostile in hostile_queries {
        let result = engine.search_text(hostile, 0, 5).await;
        assert!(
            result.is_ok(),
            "Hostile query {:?} must never panic or return Err",
            hostile
        );
    }
}

#[tokio::test]
async fn test_adversarial_tantivy_empty_and_extreme_text_payloads() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // 1. Whitespace only payload
    let chunk_ws = make_chunk(
        "c_ws",
        "doc_ws",
        "ws.txt",
        1,
        1,
        0,
        vec![0.1; 768],
        "   \t\r\n   ",
    );

    // 2. Huge single token without spaces (4,000 chars)
    let long_token = "A".repeat(4000);
    let chunk_long = make_chunk(
        "c_long",
        "doc_long",
        "long.txt",
        1,
        1,
        0,
        vec![0.1; 768],
        &long_token,
    );

    // 3. Dense symbol block
    let symbols = "!@#$%^&*()_+-=[]{}|;':,.<>?/".repeat(50);
    let chunk_sym = make_chunk(
        "c_sym",
        "doc_sym",
        "sym.txt",
        1,
        1,
        0,
        vec![0.1; 768],
        &symbols,
    );

    let inserted = engine
        .insert_chunks(&[chunk_ws, chunk_long, chunk_sym])
        .await
        .unwrap();
    assert_eq!(inserted, 3);
    assert_eq!(engine.count().await.unwrap(), 3);

    // Search empty string -> returns empty without error
    let empty_search = engine.search_text("", 0, 5).await.unwrap();
    assert!(empty_search.is_empty());

    // Search whitespace -> returns empty without error
    let ws_search = engine.search_text("   \n\t  ", 0, 5).await.unwrap();
    assert!(ws_search.is_empty());
}

// ============================================================================
// Group 3: Compaction Resilience Adversarial Tests
// ============================================================================

#[tokio::test]
async fn test_adversarial_compaction_repeated_empty_table() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    assert!(engine.is_empty().await.unwrap());

    // Repeatedly compact an empty table 10 times consecutively
    for i in 1..=10 {
        let stats = engine.compact().await;
        assert!(
            stats.is_ok(),
            "Compaction cycle {} on empty storage failed: {:?}",
            i,
            stats.err()
        );
    }

    assert!(engine.is_empty().await.unwrap());

    // Verify table is fully operational after empty compactions
    let chunk = make_chunk(
        "c_after_compact",
        "doc_ac",
        "after.rs",
        1,
        5,
        0,
        vec![0.4; 768],
        "Table remains usable after repeated empty compactions",
    );
    engine.insert_chunks(&[chunk]).await.unwrap();
    assert_eq!(engine.count().await.unwrap(), 1);

    let hits = engine.search_text("reusable usable compactions", 0, 5).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].chunk.chunk_id, "c_after_compact");
}

#[tokio::test]
async fn test_adversarial_compaction_after_deletions_and_reinsertions() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Insert 30 chunks across 3 distinct file paths
    let mut chunks = Vec::with_capacity(30);
    for i in 0..10 {
        chunks.push(make_chunk(
            &format!("chunk_a_{}", i),
            "doc_a",
            "dir/file_a.rs",
            i * 5 + 1,
            i * 5 + 5,
            0,
            vec![0.1; 768],
            &format!("Content for file_a segment {}", i),
        ));
        chunks.push(make_chunk(
            &format!("chunk_b_{}", i),
            "doc_b",
            "dir/file_b.rs",
            i * 5 + 1,
            i * 5 + 5,
            0,
            vec![0.2; 768],
            &format!("Content for file_b segment {}", i),
        ));
        chunks.push(make_chunk(
            &format!("chunk_c_{}", i),
            "doc_c",
            "dir/file_c.rs",
            i * 5 + 1,
            i * 5 + 5,
            0,
            vec![0.3; 768],
            &format!("Content for file_c segment {}", i),
        ));
    }

    engine.insert_chunks(&chunks).await.unwrap();
    assert_eq!(engine.count().await.unwrap(), 30);

    // Delete file_b.rs
    let deleted_b = engine.delete_by_file_path("dir/file_b.rs").await.unwrap();
    assert_eq!(deleted_b, 10);
    assert_eq!(engine.count().await.unwrap(), 20);

    // Compact
    let stats = engine.compact().await.unwrap();
    assert!(stats.tantivy_segments_merged);

    // Ensure file_b chunks are absent from keyword search
    let b_hits = engine.search_text("file_b", 0, 10).await.unwrap();
    assert!(
        b_hits.is_empty(),
        "Deleted file_b chunks must not appear in search results"
    );
    let segment_hits = engine.search_text("file_b segment", 0, 10).await.unwrap();
    assert!(
        !segment_hits.iter().any(|h| h.chunk.file_path == "dir/file_b.rs"),
        "Deleted file_b chunks must not appear in search results"
    );

    // Ensure file_a and file_c chunks remain retrievable
    let a_hits = engine.search_text("file_a segment", 0, 10).await.unwrap();
    assert_eq!(a_hits.len(), 10);

    // Delete remaining files
    engine.delete_by_file_path("dir/file_a.rs").await.unwrap();
    engine.delete_by_file_path("dir/file_c.rs").await.unwrap();
    assert_eq!(engine.count().await.unwrap(), 0);
    assert!(engine.is_empty().await.unwrap());

    // Compact again on now-empty table
    engine.compact().await.unwrap();
    assert!(engine.is_empty().await.unwrap());

    // Re-insert new chunks
    let new_chunk = make_chunk(
        "chunk_d_0",
        "doc_d",
        "dir/file_d.rs",
        1,
        10,
        0,
        vec![0.5; 768],
        "Fresh post-compaction chunk lifecycle verify",
    );
    engine.insert_chunks(&[new_chunk]).await.unwrap();
    assert_eq!(engine.count().await.unwrap(), 1);

    let d_hits = engine.search_text("lifecycle verify", 0, 5).await.unwrap();
    assert_eq!(d_hits.len(), 1);
    assert_eq!(d_hits[0].chunk.chunk_id, "chunk_d_0");
}

#[tokio::test]
async fn test_adversarial_compaction_concurrent_reads_stress() {
    let tmp = tempdir().unwrap();
    let engine = Arc::new(StorageEngine::open(tmp.path()).await.unwrap());

    // Seed storage with 20 chunks
    let mut initial_chunks = Vec::new();
    for i in 0..20 {
        initial_chunks.push(make_chunk(
            &format!("concurrent_c_{}", i),
            "doc_concurrent",
            &format!("concurrent_file_{}.rs", i),
            1,
            10,
            (i % 4) as u8,
            vec![(i as f32) * 0.05; 768],
            &format!("Concurrent stress payload data stream {}", i),
        ));
    }
    engine.insert_chunks(&initial_chunks).await.unwrap();

    // Spawn 8 reader tasks executing concurrent searches
    let mut reader_handles = Vec::new();
    for reader_id in 0..8 {
        let eng = Arc::clone(&engine);
        let handle = tokio::spawn(async move {
            for iter in 0..30 {
                let vec_query = vec![0.1 * ((iter % 10) as f32); 768];
                let text_query = format!("stream {}", iter % 20);

                let _vec_hits = eng.search_vector(&vec_query, 3, 5).await.unwrap();
                let _text_hits = eng.search_text(&text_query, 3, 5).await.unwrap();
                let _hyb_hits = eng
                    .search_hybrid(&text_query, &vec_query, 3, 5)
                    .await
                    .unwrap();

                sleep(Duration::from_millis(5)).await;
            }
            reader_id
        });
        reader_handles.push(handle);
    }

    // Simultaneously run 4 compaction cycles on the engine
    for _ in 0..4 {
        sleep(Duration::from_millis(25)).await;
        let stats = engine.compact().await;
        assert!(
            stats.is_ok(),
            "Compaction during concurrent reads must succeed"
        );
    }

    // Await all readers
    for handle in reader_handles {
        let reader_id = handle.await.expect("Reader task panicked");
        assert!(reader_id < 8);
    }

    // Final verification that engine is healthy and consistent
    assert_eq!(engine.count().await.unwrap(), 20);
}

// ============================================================================
// Group 4: Windows Filesystem Path & Deletion Adversarial Tests
// ============================================================================

#[tokio::test]
async fn test_adversarial_windows_paths_deletion_resilience() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Windows paths with spaces, single quotes, backslashes, parentheses
    let weird_path_1 = "C:\\Users\\O'Connor\\Projects\\Quorum (v2.0)\\data's_file.rs";
    let weird_path_2 = "D:\\Nested\\Directory With Spaces\\sub'folder\\file.txt";

    let c1 = make_chunk(
        "c_path_1",
        "doc_p1",
        weird_path_1,
        1,
        10,
        0,
        vec![0.1; 768],
        "Payload in path with single quote and backslashes",
    );
    let c2 = make_chunk(
        "c_path_2",
        "doc_p2",
        weird_path_2,
        1,
        10,
        0,
        vec![0.2; 768],
        "Payload in nested directory with spaces and quotes",
    );

    engine.insert_chunks(&[c1, c2]).await.unwrap();
    assert_eq!(engine.count().await.unwrap(), 2);

    // Delete path with single quote and backslash
    let deleted1 = engine.delete_by_file_path(weird_path_1).await.unwrap();
    assert_eq!(deleted1, 1);
    assert_eq!(engine.count().await.unwrap(), 1);

    // Search should only find chunk 2
    let hits = engine.search_vector(&vec![0.2; 768], 0, 5).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].chunk.chunk_id, "c_path_2");

    // Delete path 2
    let deleted2 = engine.delete_by_file_path(weird_path_2).await.unwrap();
    assert_eq!(deleted2, 1);
    assert_eq!(engine.count().await.unwrap(), 0);
}
