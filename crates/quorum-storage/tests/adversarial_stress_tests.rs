//! Adversarial Stress & Vulnerability Test Suite for `quorum-storage`.
//!
//! Objectives:
//! 1. High-concurrency rapid insertions and queries.
//! 2. Extremely large batches and chunk payloads.
//! 3. Zero vectors, NaN vectors, and orthogonal vectors in LanceDB and Tantivy.
//! 4. Extreme out-of-bounds `top_k` and invalid `access_tier` boundaries.
//! 5. Verify that `quorum-storage` never panics, leaks Arrow memory, or corrupts data.

use std::sync::Arc;
use quorum_storage::{StorageEngine, StorageSearchQuery};
use quorum_types::DocumentChunk;
use tempfile::tempdir;

fn make_chunk(
    id: &str,
    doc: &str,
    path: &str,
    tier: u8,
    vector: Vec<f32>,
    text: &str,
) -> DocumentChunk {
    DocumentChunk::new(
        id,
        doc,
        path,
        1,
        10,
        tier,
        vector,
        text,
        Some("{\"adversarial\":true}".to_string()),
    )
    .expect("Valid chunk creation")
}

// ============================================================================
// 1. ADVERSARIAL VECTOR STRESS TESTS
// ============================================================================

#[tokio::test]
async fn test_adv_vector_zero_norm() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk = make_chunk("c_zero", "d1", "f1.rs", 0, vec![0.0; 768], "zero vector payload");
    let inserted = engine.insert_chunks(&[chunk]).await.unwrap();
    assert_eq!(inserted, 1);

    // Query with zero vector
    let zero_query = vec![0.0; 768];
    let hits = engine.search_vector(&zero_query, 0, 5).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].score, 0.0);
    assert!(!hits[0].score.is_nan());
}

#[tokio::test]
async fn test_adv_vector_nan_query() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk = make_chunk("c_norm", "d1", "f1.rs", 0, vec![0.5; 768], "normal vector payload");
    engine.insert_chunks(&[chunk]).await.unwrap();

    // Query vector containing NaNs
    let mut nan_query = vec![0.5; 768];
    nan_query[0] = f32::NAN;
    nan_query[100] = f32::NAN;

    let res = engine.search_vector(&nan_query, 0, 5).await;
    match res {
        Ok(hits) => {
            for h in hits {
                assert!(!h.score.is_nan(), "Score must never be NaN");
            }
        }
        Err(e) => {
            // Returning an error is also safe, but it must not panic
            println!("search_vector with NaN returned expected error: {}", e);
        }
    }
}

#[tokio::test]
async fn test_adv_vector_infinity_query() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk = make_chunk("c_inf", "d1", "f1.rs", 0, vec![0.5; 768], "normal payload");
    engine.insert_chunks(&[chunk]).await.unwrap();

    let mut inf_query = vec![0.5; 768];
    inf_query[0] = f32::INFINITY;
    inf_query[10] = f32::NEG_INFINITY;

    let res = engine.search_vector(&inf_query, 0, 5).await;
    match res {
        Ok(hits) => {
            for h in hits {
                assert!(!h.score.is_nan(), "Score must never be NaN");
                assert!(!h.score.is_infinite(), "Score must never be Inf");
            }
        }
        Err(e) => {
            println!("search_vector with Inf returned expected error: {}", e);
        }
    }
}

#[tokio::test]
async fn test_adv_vector_dimension_mismatch_query() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk = make_chunk("c_dim", "d1", "f1.rs", 0, vec![0.5; 768], "payload");
    engine.insert_chunks(&[chunk]).await.unwrap();

    // Query with wrong dimensions: 0, 10, 1000
    for bad_dim in [0, 10, 500, 767, 769, 1000] {
        let bad_vec = vec![0.5; bad_dim];
        let res = engine.search_vector(&bad_vec, 0, 5).await;
        // Must either return Err or handle gracefully without panicking
        assert!(res.is_err() || res.unwrap().is_empty(), "Dimension mismatch must not succeed blindly or panic: dim {}", bad_dim);
    }
}

#[tokio::test]
async fn test_adv_vector_nan_chunk_insertion() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let mut nan_vec = vec![0.1; 768];
    nan_vec[42] = f32::NAN;

    let chunk = make_chunk("c_nan_ins", "d_nan", "nan.rs", 0, nan_vec, "chunk with NaN vector");
    let res = engine.insert_chunks(&[chunk]).await;
    println!("Inserting chunk with NaN vector result: {:?}", res);
    // LanceDB might accept or reject, but must not corrupt table
    let count = engine.count().await.unwrap_or(0);
    println!("Count after NaN insert: {}", count);
}

// ============================================================================
// 2. EXTREME TOP_K & ARITHMETIC OVERFLOW STRESS TESTS
// ============================================================================

#[tokio::test]
async fn test_adv_top_k_zero() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk = make_chunk("c_k0", "d1", "f1.rs", 0, vec![0.5; 768], "content");
    engine.insert_chunks(&[chunk]).await.unwrap();

    // Vector
    let h_vec = engine.search_vector(&vec![0.5; 768], 0, 0).await.unwrap();
    assert!(h_vec.is_empty());

    // Text
    let h_text = engine.search_text("content", 0, 0).await.unwrap();
    assert!(h_text.is_empty());

    // Hybrid
    let h_hyb = engine.search_hybrid("content", &vec![0.5; 768], 0, 0).await.unwrap();
    assert!(h_hyb.is_empty());

    // Unified search
    let q = StorageSearchQuery::hybrid("content", vec![0.5; 768], 0, 0);
    let h_q = engine.search(&q).await.unwrap();
    assert!(h_q.is_empty());
}

#[tokio::test]
async fn test_adv_top_k_huge() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let chunk = make_chunk("c_huge_k", "d1", "f1.rs", 0, vec![0.5; 768], "content");
    engine.insert_chunks(&[chunk]).await.unwrap();

    let h = engine.search_vector(&vec![0.5; 768], 0, 1_000_000).await.unwrap();
    assert_eq!(h.len(), 1);
}

#[tokio::test]
async fn test_adv_top_k_overflow_in_hybrid() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();
    let chunk = make_chunk("c_ovf", "d1", "f1.rs", 0, vec![0.5; 768], "content");
    engine.insert_chunks(&[chunk]).await.unwrap();

    let text_hits = engine
        .search_text("content", 0, usize::MAX)
        .await
        .expect("search_text with top_k = usize::MAX must succeed cleanly without panicking");
    assert_eq!(text_hits.len(), 1, "Direct Tantivy search with usize::MAX must return 1 hit");

    let hits = engine
        .search_hybrid("content", &vec![0.5; 768], 0, usize::MAX)
        .await
        .expect("search_hybrid with top_k = usize::MAX must succeed cleanly without panicking");
    assert_eq!(hits.len(), 1, "Hybrid search with usize::MAX must return 1 hit");
}


// ============================================================================
// 3. ACCESS TIER BOUNDARY TESTS
// ============================================================================

#[tokio::test]
async fn test_adv_access_tier_out_of_bounds() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let c0 = make_chunk("c0", "d0", "f0.rs", 0, vec![1.0; 768], "pub text");
    let c1 = make_chunk("c1", "d1", "f1.rs", 1, vec![1.0; 768], "int text");
    let c2 = make_chunk("c2", "d2", "f2.rs", 2, vec![1.0; 768], "conf text");
    let c3 = make_chunk("c3", "d3", "f3.rs", 3, vec![1.0; 768], "rest text");

    engine.insert_chunks(&[c0, c1, c2, c3]).await.unwrap();

    // Query with max_tier = 255 (should return all 4 tiers without failing or crashing)
    let hits_255 = engine.search_vector(&vec![1.0; 768], 255, 10).await.unwrap();
    assert_eq!(hits_255.len(), 4, "max_tier = 255 should return all tiers");

    // Tantivy search with max_tier = 255
    let hits_text_255 = engine.search_text("text", 255, 10).await.unwrap();
    assert_eq!(hits_text_255.len(), 4);

    // Hybrid search with max_tier = 255
    let hits_hyb_255 = engine.search_hybrid("text", &vec![1.0; 768], 255, 10).await.unwrap();
    assert_eq!(hits_hyb_255.len(), 4);

    // Query with max_tier = 0: ONLY c0
    let hits_0 = engine.search_vector(&vec![1.0; 768], 0, 10).await.unwrap();
    assert_eq!(hits_0.len(), 1);
    assert_eq!(hits_0[0].chunk.chunk_id, "c0");
}

// ============================================================================
// 4. LARGE BATCH & MASSIVE CHUNK PAYLOAD STRESS TESTS
// ============================================================================

#[tokio::test]
async fn test_adv_massive_chunk_payload_5mb() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Create a massive 5MB text payload (5 * 1024 * 1024 characters)
    let paragraph = "QuorumRAG production grade retrieval augmented generation storage engine testing. ";
    let repeat_count = (5 * 1024 * 1024) / paragraph.len();
    let massive_text = paragraph.repeat(repeat_count);

    let chunk = make_chunk(
        "c_massive_5mb",
        "doc_massive",
        "big_file.txt",
        0,
        vec![0.1; 768],
        &massive_text,
    );

    let inserted = engine.insert_chunks(&[chunk]).await.expect("Must handle 5MB chunk without Arrow buffer overflow");
    assert_eq!(inserted, 1);
    assert_eq!(engine.count().await.unwrap(), 1);

    // Search against the massive payload
    let hits = engine.search_text("QuorumRAG", 0, 5).await.unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].chunk.chunk_id, "c_massive_5mb");
}

#[tokio::test]
async fn test_adv_large_batch_insertion_1000_chunks() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    let count = 1000;
    let mut batch = Vec::with_capacity(count);
    for i in 0..count {
        let chunk = make_chunk(
            &format!("batch_chunk_{}", i),
            "doc_batch",
            &format!("src/file_{}.rs", i % 20),
            (i % 4) as u8,
            vec![0.001 * (i as f32); 768],
            &format!("Batch document content item index {} with keyword marker alpha_{}", i, i % 10),
        );
        batch.push(chunk);
    }

    let inserted = engine.insert_chunks(&batch).await.expect("Inserting 1000 chunks in single batch must succeed");
    assert_eq!(inserted, count);
    assert_eq!(engine.count().await.unwrap(), count);

    // Verify search over 1000 chunks
    let hits = engine.search_text("alpha_5", 3, 20).await.unwrap();
    assert!(!hits.is_empty());
}

#[tokio::test]
async fn test_adv_filename_search_in_tantivy() {
    let tmp = tempdir().unwrap();
    let engine = StorageEngine::open(tmp.path()).await.unwrap();

    // Chunk where file_path has filename "special_handler.rs" but text does NOT mention the filename
    let chunk = make_chunk(
        "c_fn_test",
        "doc_fn",
        "crates/network/src/special_handler.rs",
        0,
        vec![0.1; 768],
        "This function implements cryptographic handshake and key agreement.",
    );
    engine.insert_chunks(&[chunk]).await.unwrap();

    // Search for filename keyword "special_handler"
    let hits = engine.search_text("special_handler", 0, 5).await.unwrap();
    println!("Filename keyword search 'special_handler' hits: {}", hits.len());
    assert_eq!(hits.len(), 1, "Searching by filename keyword must return 1 hit");
}

// ============================================================================
// 5. HIGH-CONCURRENCY RAPID INSERTIONS & QUERIES
// ============================================================================

#[tokio::test]
async fn test_adv_high_concurrency_rapid_insertions_and_queries() {
    let tmp = tempdir().unwrap();
    let engine = Arc::new(StorageEngine::open(tmp.path()).await.unwrap());

    let num_tasks = 8;
    let chunks_per_task = 25;
    let mut writer_handles = Vec::new();
    let mut reader_handles = Vec::new();

    // Spawn 8 concurrent writer tasks
    for task_idx in 0..num_tasks {
        let engine_clone = Arc::clone(&engine);
        let handle = tokio::spawn(async move {
            let mut my_chunks = Vec::new();
            for i in 0..chunks_per_task {
                let id = format!("task_{}_chunk_{}", task_idx, i);
                let text = format!("Concurrent insertion payload task {} item {}", task_idx, i);
                let chunk = DocumentChunk::new(
                    id,
                    format!("doc_task_{}", task_idx),
                    format!("file_task_{}.rs", task_idx),
                    1,
                    10,
                    0,
                    vec![0.1 * (task_idx as f32 + 1.0); 768],
                    text,
                    None,
                )
                .unwrap();
                my_chunks.push(chunk);
            }
            engine_clone.insert_chunks(&my_chunks).await
        });
        writer_handles.push(handle);
    }

    // Spawn 4 concurrent reader tasks querying while writes occur
    for _query_idx in 0..4 {
        let engine_clone = Arc::clone(&engine);
        let query_handle = tokio::spawn(async move {
            for _ in 0..10 {
                let _ = engine_clone.search_vector(&vec![0.1; 768], 0, 10).await;
                let _ = engine_clone.search_text("Concurrent", 0, 10).await;
                let _ = engine_clone.search_hybrid("payload", &vec![0.1; 768], 0, 5).await;
                tokio::task::yield_now().await;
            }
        });
        reader_handles.push(query_handle);
    }

    // Await all tasks
    let mut writer_success = 0;
    let mut writer_errors = 0;
    for handle in writer_handles {
        match handle.await.unwrap() {
            Ok(count) => writer_success += count,
            Err(e) => {
                println!("Writer task encountered error: {}", e);
                writer_errors += 1;
            }
        }
    }
    for handle in reader_handles {
        handle.await.unwrap();
    }
    println!("Concurrent writers: {} chunks written, {} errors", writer_success, writer_errors);


    let final_count = engine.count().await.unwrap();
    println!("Final row count after concurrency stress test: {}", final_count);
    assert_eq!(
        final_count,
        num_tasks * chunks_per_task,
        "All concurrent insertions must commit without dropped rows or write conflicts"
    );
}
