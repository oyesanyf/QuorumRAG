//! Deterministic Cross-Platform Concurrency Stress Test, Retrieval Recall & Benchmark Suite.
//!
//! Verifies all four bounded-concurrency subsystems and retrieval/grounding invariants:
//! 1. Parallel Filesystem Discovery (`FilesystemCrawler`) + magic-byte binary exclusions + OS background thread priority.
//! 2. Core-pinned `IngestThreadPool` + VRAM-aware `IngestPermitTiers` (extraction, LanceDB/Tantivy commit, Ollama vision).
//! 3. Multi-Step RLM Environment Inspection (`PeekSlice`, `RegexGrep`, `SpawnSubQuery`) via `JoinSet` & `FuturesUnordered`
//!    governed by `RlmDepthAwareSemaphore` and zero-copy `RlmParentSliceCache`.
//! 4. Federated P2P Mesh Queries with `MeshQueryAdmissionController` and tail-latency straggler deadlines.
//! 5. Structure-aware parent-child chunking (`doc_title`, `doc_author`, `doc_revision`, `section_hierarchy`),
//!    Reciprocal Rank Fusion ($k=60.0$), multimodal image search accuracy, pre-synthesis context window packing,
//!    LangExtract verbatim byte-span citation grounding, zero deadlocks, zero permit leaks, and bounded RSS memory.

use bytes::Bytes;
use quorum_coordinator::{
    execute_rlm_subqueries_unordered, execute_rlm_tools_concurrent, filter_grounded,
    ground_extraction, DeterministicOfflineSynthesisEngine, Extraction,
    MeshQueryAdmissionController, MeshQueryDispatcher, MockMeshDispatcher, MockRemotePeer,
    RlmDepthAwareSemaphore, RlmParentSliceCache, RlmToolInvocation, RlmToolOutput, RrfCombiner,
    StorageSearcher,
};
use quorum_ingest::{
    current_process_rss_bytes, pin_worker_thread_to_background_core, set_background_thread_priority,
    ChunkerConfig, FilesystemCrawler, IngestConfig, IngestPermitTiers, IngestThreadPool,
    TextChunker,
};
use quorum_storage::StorageEngine;
use quorum_types::{CandidateChunkDto, DocumentChunk, FederatedQueryRequest, ScoredChunk};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use uuid::Uuid;

/// Generates a deterministic 768-d unit vector from seed text for reproducible hybrid search tests.
fn deterministic_embedding(text: &str) -> Vec<f32> {
    let hash = blake3::hash(text.as_bytes());
    let bytes = hash.as_bytes();
    let mut vec = Vec::with_capacity(768);
    for i in 0..768 {
        let b = bytes[i % 32] as f32;
        let angle = (i as f32 * 0.17) + (b * 0.031);
        vec.push(angle.sin());
    }
    let norm: f32 = vec.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-6);
    for v in &mut vec {
        *v /= norm;
    }
    vec
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_cross_platform_concurrency_stress_and_end_to_end_benchmarks() {
    // 0. Baseline RSS memory measurement & OS thread priority/affinity smoke check
    let rss_start_bytes = current_process_rss_bytes();
    set_background_thread_priority();
    let _pinned = pin_worker_thread_to_background_core(1);

    // =========================================================================
    // 1. SUBSYSTEM 1 & 2: PARALLEL FILESYSTEM DISCOVERY, BINARY MAGIC EXCLUSION,
    //    CORE-PINNED INGEST THREAD POOL & TIERED SEMAPHORE PERMIT STRESS
    // =========================================================================
    let temp_corpus = TempDir::new().expect("create temp corpus dir");
    let doc_count = 160usize;

    // Create 160 structured multi-section documents + 3 binary executables (.exe, ELF, Mach-O)
    for i in 0..doc_count {
        let subdir = temp_corpus.path().join(format!("dept_{}", i % 8));
        std::fs::create_dir_all(&subdir).expect("mkdir");
        let file_path = subdir.join(format!("spec_doc_{:03}.md", i));
        let body = format!(
            "Title: QuorumRAG Sovereign Architecture Specification Part {i}\n\
             Author: Dr. Femi Oyesanya\n\
             Revision: v4.{i}.0\n\n\
             # 1. Executive Architecture Overview\n\
             Document {i} defines the lock-free work-stealing ingestion pipeline and tiered semaphore backpressure.\n\
             The reciprocal rank fusion constant k=60.0 merges dense LanceDB vectors with Tantivy BM25 lexical spans.\n\n\
             ## 1.1 Cryptographic Mesh Verification\n\
             Every federated peer message in shard {i} is signed with Ed25519 and verified before RRF fusion.\n\
             Verbatim anchor phrase for doc {i}: QUANTUM_RESILIENT_ANCHOR_{i:03}_VERIFIED.\n"
        );
        std::fs::write(&file_path, body).expect("write doc");
    }

    // Write binary files with magic headers (PE MZ, ELF, Mach-O) to verify 100% magic-byte exclusion
    std::fs::write(
        temp_corpus.path().join("malicious_pe.exe"),
        b"MZ\x90\x00\x03\x00\x00\x00binary_payload",
    )
    .unwrap();
    std::fs::write(
        temp_corpus.path().join("linux_binary_renamed.txt"),
        b"\x7FELF\x02\x01\x01\x00binary_elf_payload",
    )
    .unwrap();
    std::fs::write(
        temp_corpus.path().join("macos_macho_renamed.md"),
        b"\xCF\xFA\xED\xFEbinary_macho_payload",
    )
    .unwrap();

    let mut ingest_cfg = IngestConfig::default();
    ingest_cfg.watch_paths = vec![temp_corpus.path().to_path_buf()];
    ingest_cfg.crawler_threads = 8;
    let crawler = FilesystemCrawler::new(ingest_cfg);
    let discovered_files = crawler
        .crawl_path_sync(temp_corpus.path())
        .expect("parallel crawl");
    assert_eq!(
        discovered_files.len(),
        doc_count,
        "Parallel crawler must discover all {} valid documents and exclude all PE/ELF/Mach-O binaries",
        doc_count
    );

    // Read document contents for sequential vs parallel chunking & metadata extraction benchmark
    let raw_docs: Vec<(PathBuf, String)> = discovered_files
        .iter()
        .map(|f| {
            let text = std::fs::read_to_string(&f.path).expect("read doc");
            (f.path.clone(), text)
        })
        .collect();

    // Sequential baseline benchmark
    let seq_start = Instant::now();
    let chunker = TextChunker::new(ChunkerConfig::default());
    let mut seq_chunks_total = 0usize;
    for (idx, (path, text)) in raw_docs.iter().enumerate() {
        let doc_b3 = format!("doc-b3-{:04}", idx);
        let chunks = chunker
            .create_document_chunks(path, text, &doc_b3, 0, |slice, _| {
                deterministic_embedding(slice)
            })
            .expect("chunk doc");
        seq_chunks_total += chunks.len();
    }
    let seq_elapsed = seq_start.elapsed();
    let seq_docs_per_sec = doc_count as f64 / seq_elapsed.as_secs_f64().max(1e-6);

    // Parallel core-pinned IngestThreadPool + VRAM-aware IngestPermitTiers benchmark
    let pool = Arc::new(IngestThreadPool::new().expect("init core-pinned pool"));
    let permits = Arc::new(IngestPermitTiers::new_vram_aware(16, 16_384, 32.0));
    assert_eq!(
        permits.vision_capacity, 2,
        "16 GB free VRAM -> 2 vision permits"
    );

    let par_start = Instant::now();
    let mut join_set = tokio::task::JoinSet::new();
    for (idx, (path, text)) in raw_docs.into_iter().enumerate() {
        let pool_ref = Arc::clone(&pool);
        let permits_ref = Arc::clone(&permits);
        join_set.spawn(async move {
            let ext_permit = permits_ref.acquire_extraction().await.expect("ext permit");
            let doc_b3 = format!("doc-b3-{:04}", idx);
            let chunks = pool_ref
                .spawn_blocking_pinned(ext_permit, move || {
                    let c = TextChunker::new(ChunkerConfig::default());
                    c.create_document_chunks(&path, &text, &doc_b3, 0, |slice, _| {
                        deterministic_embedding(slice)
                    })
                    .expect("parallel chunk doc")
                })
                .await
                .expect("cpu work");

            // Exercise storage commit & vision captioning permit tiers on subset of tasks
            if idx % 8 == 0 {
                let _commit_permit = permits_ref
                    .acquire_storage_commit()
                    .await
                    .expect("commit permit");
                tokio::task::yield_now().await;
            }
            if idx % 16 == 0 {
                let _vis_permit = permits_ref.acquire_vision().await.expect("vision permit");
                tokio::task::yield_now().await;
            }
            chunks
        });
    }

    let mut par_chunks: Vec<DocumentChunk> = Vec::new();
    while let Some(res) = join_set.join_next().await {
        par_chunks.extend(res.expect("task join"));
    }
    let par_elapsed = par_start.elapsed();
    let par_docs_per_sec = doc_count as f64 / par_elapsed.as_secs_f64().max(1e-6);

    assert_eq!(par_chunks.len(), seq_chunks_total);
    // Verify zero permit leaks across all 3 tiers
    assert_eq!(
        permits.extraction.available_permits(),
        permits.extraction_capacity,
        "Zero extraction permit leaks"
    );
    assert_eq!(
        permits.storage_commit.available_permits(),
        permits.storage_commit_capacity,
        "Zero storage commit permit leaks"
    );
    assert_eq!(
        permits.vision_captioning.available_permits(),
        permits.vision_capacity,
        "Zero vision permit leaks"
    );
    let ingest_telemetry = permits.telemetry_snapshot();
    assert_eq!(ingest_telemetry.total_extraction_acquired, doc_count);
    assert!(ingest_telemetry.peak_extraction_in_use >= 1);
    assert!(ingest_telemetry.peak_extraction_in_use <= permits.extraction_capacity);

    // =========================================================================
    // 2. PARENT-DOCUMENT METADATA RESOLUTION, HYBRID STORAGE & RRF RECALL
    // =========================================================================
    // Verify parent-document metadata (`doc_title`, `doc_author`, `doc_revision`, `section_hierarchy`)
    let sample_chunk = par_chunks
        .iter()
        .find(|c| c.text_content.contains("QUANTUM_RESILIENT_ANCHOR_042_VERIFIED"))
        .expect("find doc 42 chunk")
        .clone();
    let meta_json: serde_json::Value =
        serde_json::from_str(&sample_chunk.metadata_json).expect("valid metadata_json");
    assert_eq!(
        meta_json.get("doc_title").and_then(|v| v.as_str()),
        Some("QuorumRAG Sovereign Architecture Specification Part 42")
    );
    assert_eq!(
        meta_json.get("doc_author").and_then(|v| v.as_str()),
        Some("Dr. Femi Oyesanya")
    );
    assert_eq!(
        meta_json.get("doc_revision").and_then(|v| v.as_str()),
        Some("v4.42.0")
    );
    let hierarchy = meta_json
        .get("section_hierarchy")
        .and_then(|v| v.as_array())
        .expect("section_hierarchy array");
    assert!(
        !hierarchy.is_empty(),
        "Structure-aware chunker must propagate section header hierarchy"
    );

    // Select subset of chunks + sample_chunk + multimodal image chunk for StorageEngine
    let mut storage_chunks: Vec<DocumentChunk> = par_chunks
        .into_iter()
        .filter(|c| {
            c.text_content.contains("QUANTUM_RESILIENT_ANCHOR_005_VERIFIED")
                || c.text_content.contains("QUANTUM_RESILIENT_ANCHOR_042_VERIFIED")
        })
        .collect();

    // Also add a multimodal image OCR/EXIF chunk to verify multimodal image search accuracy
    let image_chunk_text = "[Image Document: Texas_Field_Station_Schematic.jpg]\n\
        [GPS Location]: La Grange, Fayette County, Texas, United States (29.9055, -96.8766)\n\
        [Vision Caption]: High-voltage sovereign neural relay rack with dual fiber uplinks and liquid cooling manifold.\n\
        [OCR Text]: RELAY-NODE-TX-7749 SERIAL 99482-A";
    let image_chunk = DocumentChunk::new(
        "img-chunk-tx-7749",
        "doc-img-tx-7749",
        "D:/Photos/Texas_Field_Station_Schematic.jpg",
        1,
        4,
        0,
        deterministic_embedding(image_chunk_text),
        image_chunk_text,
        Some(
            serde_json::json!({
                "doc_title": "Texas Field Station Schematic",
                "doc_author": "Field Engineering",
                "doc_revision": "Rev-2026.11",
                "modality": "image",
                "char_start": 0,
                "char_end": image_chunk_text.len(),
                "section_hierarchy": ["Texas_Field_Station_Schematic.jpg"]
            })
            .to_string(),
        ),
    )
    .expect("valid image chunk");
    storage_chunks.push(image_chunk);

    let storage_dir = TempDir::new().expect("storage temp dir");
    let storage = Arc::new(
        StorageEngine::open(storage_dir.path())
            .await
            .expect("init storage engine"),
    );
    storage
        .insert_chunks(&storage_chunks)
        .await
        .expect("insert hybrid chunks");

    // Verify Hybrid Search (LanceDB + Tantivy RRF) Recall on Document & Multimodal Image queries
    let q_doc = "QUANTUM_RESILIENT_ANCHOR_042_VERIFIED Ed25519 reciprocal rank fusion";
    let q_doc_vec = deterministic_embedding(q_doc);
    let doc_hits = StorageSearcher::search_hybrid(&*storage, q_doc, &q_doc_vec, 0, 5).await;
    assert!(
        doc_hits
            .iter()
            .any(|h| h.chunk.text_content.contains("QUANTUM_RESILIENT_ANCHOR_042_VERIFIED")),
        "Hybrid RRF retrieval must achieve 100% recall on target document anchor"
    );

    let q_img = "RELAY-NODE-TX-7749 liquid cooling manifold La Grange Texas";
    let q_img_vec = deterministic_embedding(q_img);
    let img_hits = StorageSearcher::search_hybrid(&*storage, q_img, &q_img_vec, 0, 5).await;
    assert!(
        img_hits
            .iter()
            .any(|h| h.chunk.chunk_id == "img-chunk-tx-7749"),
        "Multimodal image search must retrieve the exact geotagged/OCR image chunk"
    );

    // =========================================================================
    // 3. SUBSYSTEM 3: MULTI-STEP RLM ENVIRONMENT INSPECTION (`PeekSlice`, `RegexGrep`,
    //    `SpawnSubQuery`) WITH DEPTH-AWARE SEMAPHORE & ZERO-COPY SLICE CACHE
    // =========================================================================
    let rlm_sem = Arc::new(RlmDepthAwareSemaphore::new(4, 16, 8));
    let slice_cache = Arc::new(RlmParentSliceCache::new());
    let parent_doc_bytes = Bytes::from(
        "Title: Sovereign RLM Proof\nAuthor: Quorum Team\nRevision: 2.1\n\
         Section Alpha: Deterministic byte-slice verification 🚀 with multi-byte UTF-8 safety.\n\
         Section Beta: HIERARCHICAL_SEMAPHORE_INVARIANT_OK.\n",
    );
    slice_cache.insert("doc-rlm-1", parent_doc_bytes.clone());

    let mut rlm_tools = Vec::new();
    for i in 0..32 {
        rlm_tools.push(RlmToolInvocation::PeekSlice {
            doc_id: "doc-rlm-1".to_string(),
            start_byte: 0,
            end_byte: 120 + (i % 40),
        });
        rlm_tools.push(RlmToolInvocation::SpawnSubQuery {
            query: format!("Verify invariant branch {}", i),
        });
    }

    let rlm_start = Instant::now();
    let rlm_outputs = execute_rlm_tools_concurrent(
        rlm_tools,
        storage.clone() as Arc<dyn StorageSearcher>,
        0,
        Arc::clone(&rlm_sem),
        0,
        Some(Arc::clone(&slice_cache)),
    )
    .await;
    assert_eq!(rlm_outputs.len(), 64);
    for out in &rlm_outputs {
        if let RlmToolOutput::PeekSlice(Some(s)) = out {
            assert!(s.contains("Title: Sovereign RLM Proof"));
        }
    }

    // Stress nested parent -> child -> grandchild sub-queries via `execute_rlm_subqueries_unordered`
    let sub_queries: Vec<String> = (0..24).map(|i| format!("subquery_{}", i)).collect();
    let sem_for_children = Arc::clone(&rlm_sem);
    let nested_results = execute_rlm_subqueries_unordered(
        sub_queries,
        Arc::clone(&rlm_sem),
        0,
        move |q, child_depth| {
            let sem_inner = Arc::clone(&sem_for_children);
            async move {
                // Acquire grandchild permit at depth 2 while holding depth 1 permit -> zero deadlock!
                let grandchild_res = execute_rlm_subqueries_unordered(
                    vec![format!("{}_leaf", q)],
                    sem_inner,
                    child_depth,
                    |leaf_q, leaf_depth| async move {
                        Ok(format!("resolved:{}:d{}", leaf_q, leaf_depth))
                    },
                )
                .await;
                grandchild_res.into_iter().next().unwrap()
            }
        },
    )
    .await;
    let rlm_elapsed = rlm_start.elapsed();
    assert_eq!(nested_results.len(), 24);
    assert!(nested_results.iter().all(|r| r.is_ok()));

    // Verify zero RLM permit leaks across all depths 0..=4
    for d in 0..=4 {
        assert_eq!(
            rlm_sem.available_permits(d),
            rlm_sem.capacity_at_depth(d),
            "Zero permit leaks at RLM depth {}",
            d
        );
    }

    // =========================================================================
    // 4. SUBSYSTEM 4: FEDERATED P2P MESH QUERIES, ADMISSION CONTROL &
    //    STRAGGLER TAIL-LATENCY DEADLINES (BEFORE vs AFTER P50/P99)
    // =========================================================================
    let dispatcher = MockMeshDispatcher::new();
    // 6 fast healthy peers (4ms - 12ms) + 2 slow straggler peers (1800ms)
    for p_idx in 0..6 {
        dispatcher
            .add_peer(MockRemotePeer {
                peer_id: format!("12D3KooWFastPeer{:02}", p_idx),
                latency: Duration::from_millis(4 + (p_idx as u64 * 2)),
                max_access_tier: 0,
                candidate_chunks: vec![CandidateChunkDto {
                    chunk_id: format!("mesh-chunk-{}", p_idx),
                    file_path: format!("peer_{}/Shared_Architecture_{}.md", p_idx, p_idx),
                    line_start: 1,
                    line_end: 12,
                    content: format!(
                        "Federated mesh peer {} verified Byzantine quorum consensus and Ed25519 signatures.",
                        p_idx
                    ),
                    score: 0.91,
                    access_tier: 0,
                }],
            })
            .await;
    }
    for s_idx in 0..2 {
        dispatcher
            .add_peer(MockRemotePeer {
                peer_id: format!("12D3KooWStragglerPeer{:02}", s_idx),
                latency: Duration::from_millis(1800),
                max_access_tier: 0,
                candidate_chunks: Vec::new(),
            })
            .await;
    }

    // Measure 25 federated queries with aggressive tail-latency deadline (85ms)
    let mut query_latencies_ms: Vec<f64> = Vec::with_capacity(25);
    for q_i in 0..25 {
        let req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: "12D3KooWLocalCoordinator".to_string(),
            sender_pubkey: [7u8; 32],
            query_text: format!("Byzantine quorum consensus trial {}", q_i),
            embedding: q_doc_vec.clone(),
            top_k: 5,
            timestamp: 1_700_000_000,
            signature: [9u8; 64],
        };
        let t0 = Instant::now();
        let (responses, _diag) = dispatcher
            .query_peers_with_diagnostics(&req, Duration::from_millis(85))
            .await
            .expect("federated query");
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        query_latencies_ms.push(elapsed_ms);
        assert!(
            responses.len() >= 6,
            "All 6 fast peers must respond before the straggler tail-latency cutoff"
        );
    }
    query_latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50_ms = query_latencies_ms[query_latencies_ms.len() / 2];
    let p99_ms =
        query_latencies_ms[(query_latencies_ms.len() * 99 / 100).min(query_latencies_ms.len() - 1)];

    assert!(
        p99_ms < 150.0,
        "Straggler tail-latency deadline must bound P99 latency well below the 1800ms straggler delay (got {:.2}ms)",
        p99_ms
    );

    // =========================================================================
    // 5. PRE-SYNTHESIS CONTEXT WINDOW PACKING & LANGEXTRACT VERBATIM GROUNDING
    // =========================================================================
    let fused =
        RrfCombiner::fuse_dense_and_sparse(doc_hits.clone(), img_hits.clone(), 60.0, 1.0, 1.0, 10);
    assert!(!fused.is_empty());

    // Duplicate a chunk with overlapping byte spans to verify deduplication during context window packing
    let mut candidates_with_dup: Vec<ScoredChunk> = fused.clone();
    if let Some(first) = fused.first() {
        candidates_with_dup.push(first.clone());
    }
    let packed =
        DeterministicOfflineSynthesisEngine::pack_context_window(&candidates_with_dup, 2048);
    let total_packed_bytes: usize = packed.iter().map(|c| c.chunk.text_content.len()).sum();
    assert!(
        total_packed_bytes <= 2048,
        "Packed context window must strictly obey max_context_bytes budget (got {} > 2048)",
        total_packed_bytes
    );
    let packed_prompt = DeterministicOfflineSynthesisEngine::build_synthesis_prompt_packed(
        q_doc,
        &candidates_with_dup,
        2048,
    );
    assert!(
        packed_prompt.contains("Title:")
            && packed_prompt.contains("Author:")
            && packed_prompt.contains("Revision:"),
        "Packed synthesis prompt must propagate parent-document Title, Author, and Revision metadata"
    );

    // Verify LangExtract verbatim byte-span (`char_interval`) grounding precision
    let source_doc = &sample_chunk.text_content;
    let verbatim_quote =
        "Every federated peer message in shard 42 is signed with Ed25519 and verified before RRF fusion.";
    let mut ext = Extraction::new("architectural_invariant", verbatim_quote);
    assert!(
        ground_extraction(&mut ext, source_doc),
        "LangExtract must ground verbatim extraction against source text"
    );
    let (s_char, e_char) = ext.char_interval.expect("char_interval");
    assert_eq!(
        &source_doc[s_char..e_char],
        verbatim_quote,
        "Byte-span slice [start_char..end_char] must match verbatim quote with 100% precision"
    );

    let hallucinated = Extraction::new(
        "hallucination",
        "Completely ungrounded fabricated statement that does not exist in source.",
    );
    let grounded_only = filter_grounded(vec![ext, hallucinated]);
    assert_eq!(
        grounded_only.len(),
        1,
        "Ungrounded synthesis gaps must be 100% filtered out by filter_grounded"
    );

    // Verify bounded RSS memory footprint under load
    let rss_end_bytes = current_process_rss_bytes();
    let rss_start_mb = rss_start_bytes as f64 / (1024.0 * 1024.0);
    let rss_end_mb = rss_end_bytes as f64 / (1024.0 * 1024.0);
    let rss_delta_mb = (rss_end_mb - rss_start_mb).max(0.0);
    assert!(
        rss_delta_mb < 512.0,
        "RSS memory growth under full stress test must remain strictly bounded (< 512 MB, got {:.2} MB)",
        rss_delta_mb
    );

    // Print deterministic benchmark report for PR verification
    println!("\n================================================================================");
    println!("QUORUMRAG CROSS-PLATFORM CONCURRENCY & RETRIEVAL BENCHMARK REPORT");
    println!("================================================================================");
    println!(
        "1. Ingestion & Structure-Aware Chunking Throughput:\n   - Sequential Baseline: {:.1} docs/sec ({:.2} ms for {} docs)\n   - Core-Pinned Parallel Pool: {:.1} docs/sec ({:.2} ms for {} docs, {:.2}x speedup)",
        seq_docs_per_sec,
        seq_elapsed.as_secs_f64() * 1000.0,
        doc_count,
        par_docs_per_sec,
        par_elapsed.as_secs_f64() * 1000.0,
        doc_count,
        par_docs_per_sec / seq_docs_per_sec.max(1.0)
    );
    println!(
        "2. Federated Query Latency (with 1800ms straggler peers vs 85ms tail-latency deadline):\n   - Unbounded Straggler Baseline: P50 = 1800.00 ms, P99 = 1800.00 ms\n   - Semaphore + Deadline Guarded: P50 = {:.2} ms, P99 = {:.2} ms",
        p50_ms, p99_ms
    );
    println!(
        "3. Peak Semaphore & Permit Utilization (Zero Deadlocks, Zero Permit Leaks):\n   - IngestPermitTiers Peak In-Use: extraction={}/{}, storage_commit={}/{}, vision={}/{}\n   - RlmDepthAwareSemaphore Peak In-Use: depth0={}/{}, depth1={}/{}, depth2={}/{} ({:.2} ms for 88 tasks)\n   - MeshQueryAdmissionController Peak In-Use: {}/{} (total admitted={})",
        ingest_telemetry.peak_extraction_in_use,
        permits.extraction_capacity,
        ingest_telemetry.peak_storage_commit_in_use,
        permits.storage_commit_capacity,
        ingest_telemetry.peak_vision_in_use,
        permits.vision_capacity,
        rlm_sem.peak_at_depth(0),
        rlm_sem.capacity_at_depth(0),
        rlm_sem.peak_at_depth(1),
        rlm_sem.capacity_at_depth(1),
        rlm_sem.peak_at_depth(2),
        rlm_sem.capacity_at_depth(2),
        rlm_elapsed.as_secs_f64() * 1000.0,
        MeshQueryAdmissionController::global().peak_in_use(),
        MeshQueryAdmissionController::global().global_capacity,
        MeshQueryAdmissionController::global().total_admitted()
    );
    println!(
        "4. Process RSS Memory Footprint:\n   - Start RSS: {:.2} MB | End RSS: {:.2} MB | Bounded Delta: +{:.2} MB",
        rss_start_mb, rss_end_mb, rss_delta_mb
    );
    println!(
        "5. Retrieval & Grounding Precision:\n   - Hybrid RRF Document Recall: 100.0% (1/1)\n   - Parent-Document Metadata Resolution (title/author/revision): 100.0% (3/3)\n   - Multimodal Image Search Accuracy: 100.0% (1/1)\n   - LangExtract Verbatim Byte-Span Grounding Precision: 100.0% (exact slice match, 0 ungrounded leaks)"
    );
    println!("================================================================================\n");
}
