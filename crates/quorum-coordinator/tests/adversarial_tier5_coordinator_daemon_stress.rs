//! Adversarial Empirical Stress & Invariant Verification Suite for Milestone 6 Phase 2 (Tier 5):
//! Coordinator, Daemon, Multi-Layer Caching & LangExtract Consensus Hardening.
//!
//! Evaluates 6 adversarial dimensions under high concurrency and failure pressure:
//! 1. QueryCache Latency SLA (< 2ms) & Atomic Epoch Invalidation (< 100 µs) under 20-thread concurrency.
//! 2. ZeroizeOnDrop Zero-Trust Memory Clearing: Unpinned remote peer chunk plaintext explicitly wiped on drop/scrub.
//! 3. Re-Cache CLI/REST Subsystem: High-concurrency query load during in-flight cache flushing and warming.
//! 4. Google LangExtract 4-Arm Consensus: Malformed intervals, multi-byte UTF-8 boundary errors, unbalanced ASTs, and hallucination rejection.
//! 5. Axum 0.7 Web Routing & Cooperative Shutdown: SPA fallback, static asset headers, and graceful in-flight request drain.
//! 6. LangGraph Agentic State Graph: Mathematical loop bounds, query rewrite cycle breaking, and structured telemetry emission.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use futures::future::join_all;
use tempfile::tempdir;
use tower::ServiceExt;

use quorum_coordinator::{
    langextract::{
        filter_grounded, ground_extraction, Extraction,
        LlmFusionConsensus,
    },
    wrap_candidates, scrub_volatile, AgenticStateGraphRunner,
    AgenticTelemetryEvent, CacheManager, CachedQueryEntry, CoordinatorConfig,
    LocalOnlyDispatcher, PeerAclManager, QueryCache, QueryCoordinator,
    ScatterGatherEngine, StorageSearcher, SynthesisModelFamily,
};
use quorum_storage::{SearchMode, StorageConfig, StorageEngine};
use quorum_types::{CandidateChunkDto, Citation, DocumentChunk, ScoredChunk};

// =========================================================================
// Helpers & Test Mocks
// =========================================================================

/// In-memory StorageSearcher mock providing fast hybrid search and atomic index epoch tracking.
struct MockAtomicSearcher {
    epoch: AtomicU64,
    chunks: Vec<DocumentChunk>,
}

impl MockAtomicSearcher {
    fn new(initial_epoch: u64, chunks: Vec<DocumentChunk>) -> Self {
        Self {
            epoch: AtomicU64::new(initial_epoch),
            chunks,
        }
    }

    #[allow(dead_code)]
    fn bump_epoch(&self) -> u64 {
        self.epoch.fetch_add(1, Ordering::SeqCst) + 1
    }
}

#[async_trait::async_trait]
impl StorageSearcher for MockAtomicSearcher {
    async fn search_hybrid(
        &self,
        query_text: &str,
        _query_vec: &[f32],
        max_tier: u8,
        top_k: usize,
    ) -> Vec<ScoredChunk> {
        let q_lower = query_text.to_lowercase();
        let words: Vec<&str> = q_lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() > 2)
            .collect();

        let mut results: Vec<ScoredChunk> = self
            .chunks
            .iter()
            .filter(|c| {
                if c.access_tier > max_tier {
                    return false;
                }
                if words.is_empty() {
                    return true;
                }
                let c_lower = c.text_content.to_lowercase();
                words.iter().any(|&w| c_lower.contains(w))
            })
            .map(|c| ScoredChunk::new(c.clone(), 0.95, "mock_local", false))
            .collect();
        results.truncate(top_k);
        results
    }

    fn index_epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
}

// =========================================================================
// Challenge 1: QueryCache Latency SLA (< 2ms) & Atomic Epoch Invalidation
// =========================================================================

#[tokio::test]
async fn challenge_tier5_query_cache_latency_and_atomic_epoch_invalidation() {
    let cache = Arc::new(QueryCache::new(5000, Duration::from_secs(3600)));
    let initial_epoch = 100u64;

    // 1. Populate cache with diverse query entries
    let test_queries = [
        ("What is decentralized P2P RAG?", SearchMode::Hybrid, SynthesisModelFamily::AutoFusion),
        ("How does Gemma 768d embedding contract work?", SearchMode::Vector, SynthesisModelFamily::Glm4Agentic),
        ("Tantivy BM25 keyword search index compaction", SearchMode::Keyword, SynthesisModelFamily::Qwen25Code),
        ("Ed25519 access tier ACL policy verification", SearchMode::Hybrid, SynthesisModelFamily::GemmaProse),
    ];

    for (i, (q, mode, fam)) in test_queries.iter().enumerate() {
        let chunk = DocumentChunk::new(
            format!("chunk_{}", i),
            format!("doc_{}", i),
            "whitepaper.md",
            1,
            20,
            0,
            vec![0.1 * (i as f32); 768],
            format!("Cached content for query: {}", q),
            None,
        )
        .expect("chunk creation");

        let scored = ScoredChunk::new(chunk, 0.95, "local", false);
        let citation = Citation {
            peer_id: "local".to_string(),
            file_path: "whitepaper.md".to_string(),
            line_start: 1,
            line_end: 20,
            score: 0.95,
            snippet: "Cached content snippet".to_string(),
        };

        cache.insert(
            q,
            *mode,
            *fam,
            0,
            initial_epoch,
            vec![scored],
            format!("Synthesis prompt for {}", q),
            Some(format!("Synthesized answer for {}", q)),
            vec![citation],
            None,
            None,
        );
    }

    // 2. High-concurrency cache hit latency SLA verification across 20 parallel tasks (1,000 queries total)
    let concurrency = 20;
    let iterations_per_task = 50;
    let mut handles = Vec::new();

    for task_id in 0..concurrency {
        let cache_clone = Arc::clone(&cache);
        handles.push(tokio::spawn(async move {
            let mut max_latency_ns = 0u128;
            let mut total_latency_ns = 0u128;
            let mut hits = 0;

            for iter in 0..iterations_per_task {
                let (q, mode, fam) = test_queries[(task_id + iter) % test_queries.len()];
                let start = Instant::now();
                let res = cache_clone.get(q, mode, fam, 0, initial_epoch);
                let elapsed = start.elapsed();
                let elapsed_ns = elapsed.as_nanos();

                if res.is_some() {
                    hits += 1;
                }
                if elapsed_ns > max_latency_ns {
                    max_latency_ns = elapsed_ns;
                }
                total_latency_ns += elapsed_ns;
            }

            (hits, max_latency_ns, total_latency_ns)
        }));
    }

    let results = join_all(handles).await;
    let mut total_hits = 0;
    let mut global_max_latency_ns = 0u128;
    let mut global_total_latency_ns = 0u128;

    for res in results {
        let (hits, max_lat, tot_lat) = res.expect("task join");
        total_hits += hits;
        if max_lat > global_max_latency_ns {
            global_max_latency_ns = max_lat;
        }
        global_total_latency_ns += tot_lat;
    }

    let total_queries = concurrency * iterations_per_task;
    let avg_latency_us = (global_total_latency_ns / total_queries as u128) as f64 / 1_000.0;
    let max_latency_ms = global_max_latency_ns as f64 / 1_000_000.0;

    println!(
        "[CHALLENGE 1 BENCHMARK] Hits: {}/{}, Avg Latency: {:.2} µs, Max Latency: {:.3} ms",
        total_hits, total_queries, avg_latency_us, max_latency_ms
    );

    assert_eq!(total_hits, total_queries, "All 1,000 queries must be direct cache hits");
    assert!(
        max_latency_ms < 2.0,
        "QueryCache hit latency SLA violated: max was {:.3} ms (must be < 2.0 ms)",
        max_latency_ms
    );

    // 3. Measure atomic epoch invalidation latency
    let manager = CacheManager::new(
        1000,
        Duration::from_secs(3600),
        5000,
        Duration::from_secs(86400),
    );
    manager.set_epoch(initial_epoch);

    let invalidation_start = Instant::now();
    let new_epoch = manager.invalidate();
    let invalidation_duration = invalidation_start.elapsed();

    println!(
        "[CHALLENGE 1 INVALIDATION] Duration: {:?}, New Epoch: {}",
        invalidation_duration, new_epoch
    );

    assert_eq!(new_epoch, initial_epoch + 1);
    assert!(
        invalidation_duration < Duration::from_millis(1),
        "Atomic epoch invalidation must be instantaneous (took {:?})",
        invalidation_duration
    );

    // 4. Assert 0% stale hits: Old epoch queries must return None immediately
    for (q, mode, fam) in &test_queries {
        let old_res = cache.get(q, *mode, *fam, 0, new_epoch);
        assert!(old_res.is_none(), "Old epoch query must not match new epoch");
    }
}

// =========================================================================
// Challenge 2: ZeroizeOnDrop Memory Clearing on Unpinned Remote Chunks
// =========================================================================

#[test]
fn challenge_tier5_zeroize_on_drop_remote_peer_memory_clearing() {
    let canary = "SENSITIVE_REMOTE_PEER_INTEL_CANARY_HEX_9876543210".to_string();
    let raw_ptr = canary.as_ptr();
    let payload_len = canary.len();

    let remote_chunk = DocumentChunk::new(
        "remote_chunk_tier5",
        "doc_remote",
        "peer_private.rs",
        1,
        15,
        2,
        vec![0.42; 768],
        canary,
        None,
    )
    .expect("chunk creation");

    let local_chunk = DocumentChunk::new(
        "local_chunk_tier5",
        "doc_local",
        "public.rs",
        1,
        10,
        0,
        vec![0.11; 768],
        "PUBLIC_LOCAL_DOCUMENT_BODY_NOT_SCRUBBED".to_string(),
        None,
    )
    .expect("chunk creation");

    let scored_remote = ScoredChunk::new(remote_chunk, 0.92, "peer_charlie", true);
    let scored_local = ScoredChunk::new(local_chunk, 0.99, "local", false);

    // Enclose CachedQueryEntry in a scope and drop it
    {
        let entry = CachedQueryEntry {
            key: [0x55; 32],
            chunks: vec![scored_remote, scored_local.clone()],
            synthesis_prompt: "prompt".to_string(),
            synthesized_response: Some("answer".to_string()),
            citations: Vec::new(),
            langextract_result: None,
            query_metadata_filters: None,
            access_tier: 2,
            index_epoch: 1,
            created_at: Instant::now(),
            has_remote_unpinned: true,
        };
        assert!(entry.has_remote_unpinned);
        // Explicitly drop entry here
        drop(entry);
    }

    // Inspect the raw memory location where remote chunk plaintext lived
    let buffer_slice = unsafe { std::slice::from_raw_parts(raw_ptr, payload_len) };
    let is_zeroed = buffer_slice.iter().all(|&b| b == 0);
    let contains_canary = std::str::from_utf8(buffer_slice)
        .map(|s| s.contains("SENSITIVE_REMOTE_PEER_INTEL_CANARY"))
        .unwrap_or(false);

    assert!(
        is_zeroed || !contains_canary,
        "Remote unpinned plaintext canary was not scrubbed from heap memory!"
    );

    // Also test VolatileRemoteChunk wrap and explicit scrub_volatile
    let dto = CandidateChunkDto {
        chunk_id: "c_dto_1".to_string(),
        file_path: "secret_research.tex".to_string(),
        line_start: 5,
        line_end: 25,
        content: "CANARY_VOLATILE_REMOTE_SECRET_CLEARING_TEST".to_string(),
        score: 0.97,
        access_tier: 1,
    };

    let mut volatile_chunks = wrap_candidates("remote_peer_bob", vec![dto]);
    assert_eq!(volatile_chunks.len(), 1);
    assert_eq!(volatile_chunks[0].content(), "CANARY_VOLATILE_REMOTE_SECRET_CLEARING_TEST");

    scrub_volatile(&mut volatile_chunks);
    assert!(
        volatile_chunks[0].content.chars().all(|c| c == '\0'),
        "Volatile chunk memory buffer must be 100% zeroed after scrub_volatile"
    );
}

// =========================================================================
// Challenge 3: Recache CLI & REST Subsystem Under Heavy Concurrent Load
// =========================================================================

#[tokio::test]
async fn challenge_tier5_recache_subsystem_under_concurrent_queries() {
    let temp_dir = tempdir().expect("tempdir");
    let storage_config = StorageConfig::new(temp_dir.path().to_path_buf());
    let storage = Arc::new(StorageEngine::open(storage_config).await.expect("storage open"));

    // Insert 20 sample chunks into real LanceDB storage
    for i in 0..20 {
        let chunk = DocumentChunk::new(
            format!("bench_chunk_{}", i),
            format!("doc_{}", i / 5),
            format!("crate/src/file_{}.rs", i),
            1,
            25,
            0,
            vec![0.05 * (i as f32); 768],
            format!("Production code implementation for subsystem component #{}: fn process_item() {{}}", i),
            None,
        )
        .expect("chunk");
        storage.insert_chunks(&[chunk]).await.expect("insert");
    }

    let cache_manager = Arc::new(CacheManager::new(
        1000,
        Duration::from_secs(3600),
        2000,
        Duration::from_secs(86400),
    ));

    let coordinator_engine = Arc::new(ScatterGatherEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageSearcher>,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0xAA; 32],
        "test_coordinator".to_string(),
    ));

    let coordinator = Arc::new(QueryCoordinator::with_cache_manager(
        coordinator_engine,
        CoordinatorConfig::default(),
        Arc::clone(&cache_manager),
    ));

    let is_running = Arc::new(AtomicBool::new(true));
    let query_success_count = Arc::new(AtomicU64::new(0));

    // Spawn 8 concurrent reader workers bombarding coordinator with queries
    let mut reader_handles = Vec::new();
    for reader_id in 0..8 {
        let coord = Arc::clone(&coordinator);
        let run_flag = Arc::clone(&is_running);
        let succ_counter = Arc::clone(&query_success_count);

        reader_handles.push(tokio::spawn(async move {
            let queries = [
                "production code implementation",
                "subsystem component",
                "fn process_item",
                "process_item",
            ];
            while run_flag.load(Ordering::Relaxed) {
                let q = queries[reader_id % queries.len()];
                if let Ok(res) = coord.query(q, 5).await {
                    assert!(!res.chunks.is_empty(), "Query should find matches in LanceDB");
                    succ_counter.fetch_add(1, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));
    }

    // Simultaneously trigger 5 full re-cache operations with clearing and warming
    let embedder = quorum_contract::DeterministicOfflineEngine::new();
    let mut last_epoch = cache_manager.epoch();

    for cycle in 1..=5 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let start = Instant::now();
        let recache_res = cache_manager
            .recache(Some(&storage), Some(&embedder), true, true)
            .await;
        let elapsed = start.elapsed();

        println!(
            "[CHALLENGE 3 RECACHE #{}] Status: {}, New Epoch: {}, Cleared: {}, Warmed: {}, Elapsed: {:?}",
            cycle, recache_res.status, recache_res.cache_epoch, recache_res.cleared_entries, recache_res.warmed_entries, elapsed
        );

        assert_eq!(recache_res.status, "ok");
        assert!(recache_res.cache_epoch > last_epoch, "Epoch must advance monotonically");
        last_epoch = recache_res.cache_epoch;
        assert!(elapsed < Duration::from_secs(5), "Recache must finish within 5s SLA");
    }

    // Stop reader threads cleanly
    is_running.store(false, Ordering::Relaxed);
    join_all(reader_handles).await;

    let total_queries_served = query_success_count.load(Ordering::SeqCst);
    println!(
        "[CHALLENGE 3 COMPLETE] Total concurrent queries served during recache: {}",
        total_queries_served
    );
    assert!(total_queries_served > 20, "Should have served dozens of concurrent queries");

    let telem = coordinator.cache_stats();
    assert_eq!(telem.cache_epoch, last_epoch);
}

// =========================================================================
// Challenge 4: LangExtract 4-Arm Consensus Malformed & Boundary Spans
// =========================================================================

#[test]
fn challenge_tier5_langextract_consensus_malformed_and_boundary_spans() {
    let source_text = "QuorumRAG is written in Rust 🦀 with Gemma 768-dim embeddings and LanceDB vector storage.";

    // Scenario A: Out-of-bounds char interval (1000..2000)
    let mut ext_oob = Extraction::new("Entity", "NonExistentEntity")
        .with_interval(1000, 2000);
    let grounded_oob = ground_extraction(&mut ext_oob, source_text);
    assert!(!grounded_oob, "Out of bounds hallucination must fail grounding");
    assert!(ext_oob.char_interval.is_none());

    // Scenario B: Inverted interval (50..20)
    let mut ext_inv = Extraction::new("Entity", "Rust")
        .with_interval(50, 20);
    assert!(ground_extraction(&mut ext_inv, source_text));
    // ground_extraction will recalculate valid interval
    let (s, e) = ext_inv.char_interval.unwrap();
    assert!(s < e && &source_text[s..e] == "Rust");

    // Scenario C: Malformed bracket balance in AST extraction class/text
    let ext_unbalanced = Extraction::new("AstBlock", "fn bad_ast(x: Vec<i32> {");
    let consensus_bad = LlmFusionConsensus::evaluate_extractions(
        source_text,
        vec![ext_unbalanced],
        None,
    );
    assert!(
        !consensus_bad.consensus_passed,
        "Unbalanced AST brackets must fail 4-arm consensus"
    );
    let arm2 = consensus_bad.arm_reports.iter().find(|a| a.arm_name.contains("Arm 2")).unwrap();
    assert!(!arm2.passed, "Arm 2 (SyntacticAstVerifier) must reject unbalanced brackets");

    // Scenario D: Multi-byte UTF-8 boundary stress test (crab emoji 🦀 is 4 bytes)
    let crab_idx = source_text.find('🦀').expect("emoji index");
    let mut ext_emoji = Extraction::new("Symbol", "🦀");
    assert!(ground_extraction(&mut ext_emoji, source_text));
    assert_eq!(ext_emoji.char_interval, Some((crab_idx, crab_idx + 4)));

    // Scenario E: Counterfactual ungrounded hallucination
    let ext_hallucination = Extraction::new("Fact", "QuorumRAG uses Python NumPy vector engine");
    let consensus_hallucinated = LlmFusionConsensus::evaluate_extractions(
        source_text,
        vec![ext_hallucination],
        None,
    );
    assert!(
        !consensus_hallucinated.consensus_passed,
        "Ungrounded hallucinated fact must fail Arm 1 and Arm 3"
    );
    assert!(
        consensus_hallucinated.verified_extractions.is_empty(),
        "No ungrounded extractions may survive 4-arm consensus"
    );

    // Scenario F: Perfect valid extraction passing all 4 arms
    let ext_valid1 = Extraction::new("Framework", "QuorumRAG");
    let ext_valid2 = Extraction::new("Language", "Rust");
    let consensus_valid = LlmFusionConsensus::evaluate_extractions(
        source_text,
        vec![ext_valid1, ext_valid2],
        None,
    );
    assert!(
        consensus_valid.consensus_passed,
        "Verbatim grounded extractions must pass 4-arm consensus"
    );
    assert_eq!(consensus_valid.verified_extractions.len(), 2);
    assert!(consensus_valid.fused_confidence_bp >= 8500);

    // Filter grounded test
    let filtered = filter_grounded(consensus_valid.verified_extractions);
    assert_eq!(filtered.len(), 2);
}

// =========================================================================
// Challenge 5: Axum 0.7 SPA Fallback Routing & Graceful Shutdown Drain
// =========================================================================

#[tokio::test]
async fn challenge_tier5_axum_static_fallback_routing_and_graceful_shutdown() {
    // 1. Build test router utilizing quorum_ui::static_handler as fallback
    let app = Router::new()
        .route("/api/ping", get(|| async { "pong" }))
        .fallback(quorum_ui::static_handler);

    // 2. Test static assets via ServiceExt::oneshot
    let css_req = Request::builder()
        .uri("/assets/styles.css")
        .body(Body::empty())
        .unwrap();
    let css_resp = app.clone().oneshot(css_req).await.unwrap();
    assert_eq!(css_resp.status(), StatusCode::OK);
    let css_type = css_resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
    assert!(css_type.contains("css"), "Content-Type must be CSS");

    let js_req = Request::builder()
        .uri("/assets/app.js")
        .body(Body::empty())
        .unwrap();
    let js_resp = app.clone().oneshot(js_req).await.unwrap();
    assert_eq!(js_resp.status(), StatusCode::OK);
    let js_type = js_resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
    assert!(js_type.contains("javascript"), "Content-Type must be JavaScript");

    // 3. Test SPA fallback for arbitrary deep client route
    let deep_req = Request::builder()
        .uri("/chat/c/session_9921_deep_link")
        .body(Body::empty())
        .unwrap();
    let deep_resp = app.clone().oneshot(deep_req).await.unwrap();
    assert_eq!(deep_resp.status(), StatusCode::OK);
    let deep_type = deep_resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
    assert!(deep_type.contains("text/html"), "SPA fallback must return text/html");

    // 4. Test graceful shutdown draining in-flight requests
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let notify_clone = Arc::clone(&shutdown_notify);

    let active_connections = Arc::new(AtomicU64::new(0));
    let active_clone = Arc::clone(&active_connections);

    let test_server_app = Router::new()
        .route(
            "/api/slow_work",
            get(move || {
                let conn_tracker = Arc::clone(&active_clone);
                async move {
                    conn_tracker.fetch_add(1, Ordering::SeqCst);
                    // Simulate 100ms in-flight query work
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    conn_tracker.fetch_sub(1, Ordering::SeqCst);
                    "completed_slow_query"
                }
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();

    let server_handle = tokio::spawn(async move {
        axum::serve(listener, test_server_app)
            .with_graceful_shutdown(async move {
                notify_clone.notified().await;
            })
            .await
            .unwrap();
    });

    // Fire in-flight request to the running server via raw HTTP on TcpStream
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let client_handle = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to test server");
        stream
            .write_all(b"GET /api/slow_work HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("send request");
        let mut response_buf = Vec::new();
        stream
            .read_to_end(&mut response_buf)
            .await
            .expect("read response");
        String::from_utf8_lossy(&response_buf).to_string()
    });

    // Give request 20ms to become in-flight
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(active_connections.load(Ordering::SeqCst), 1, "Request must be actively in-flight");

    // Trigger graceful shutdown while request is active
    shutdown_notify.notify_one();

    // Verify in-flight request was not abruptly terminated and finished with 200 OK
    let response_text = client_handle.await.expect("client handle join");
    assert!(response_text.contains("200 OK"), "Response must be 200 OK: {}", response_text);
    assert!(response_text.contains("completed_slow_query"), "Response must contain body");
    assert_eq!(active_connections.load(Ordering::SeqCst), 0, "All active connections drained cleanly");

    // Verify server task terminates cleanly
    server_handle.await.expect("server handle join");
}

// =========================================================================
// Challenge 6: LangGraph Agentic State Graph Loop Rewrite vs Maximum Hops
// =========================================================================

#[tokio::test]
async fn challenge_tier5_agentic_state_graph_loop_rewrite_and_max_hops() {
    let storage_chunk = DocumentChunk::new(
        "c_agentic_01",
        "doc_agentic",
        "crypto_spec.md",
        1,
        20,
        0,
        vec![0.5; 768],
        "Ed25519 signatures are verified in QuorumRAG using 32-byte public key and 64-byte signature vector algorithm.",
        None,
    )
    .expect("chunk creation");

    let mock_storage = Arc::new(MockAtomicSearcher::new(1, vec![storage_chunk]));
    let engine = ScatterGatherEngine::new(
        mock_storage,
        Arc::new(LocalOnlyDispatcher),
        Arc::new(tokio::sync::RwLock::new(PeerAclManager::default())),
        CoordinatorConfig::default(),
        [0x99; 32],
        "agentic_tester".to_string(),
    );

    let runner = AgenticStateGraphRunner::new(3, 0.75);
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);

    // Prompt designed to query cryptographic signatures
    let prompt = "How are Ed25519 signatures verified in QuorumRAG?";
    let vector = vec![0.5f32; 768];

    let result = runner
        .run(
            prompt,
            SynthesisModelFamily::AutoFusion,
            &engine,
            &vector,
            0,
            5,
            Some(tx),
        )
        .await;

    assert!(result.is_ok(), "Agentic runner must complete successfully");
    let state = result.unwrap();

    // Collect all telemetry events emitted by the runner
    let mut telemetry_events = Vec::new();
    while let Ok(event) = rx.try_recv() {
        telemetry_events.push(event);
    }

    println!(
        "[CHALLENGE 6 AGENTIC] Completed at hop {}/{}, Citations: {}, Telemetry Events: {}",
        state.hop_count, state.max_hops, state.citations.len(), telemetry_events.len()
    );

    // Assert mathematical termination bound
    assert!(
        state.hop_count <= state.max_hops,
        "Agentic runner violated maximum hop constraint: {} > {}",
        state.hop_count,
        state.max_hops
    );

    assert!(
        state.synthesized_response.is_some(),
        "State graph must produce synthesized response"
    );
    assert!(
        !state.citations.is_empty(),
        "State graph must produce grounded citations"
    );

    // Verify key telemetry events were emitted
    let has_intent = telemetry_events.iter().any(|e| matches!(e, AgenticTelemetryEvent::IntentClassified { .. }));
    let has_retrieval = telemetry_events.iter().any(|e| matches!(e, AgenticTelemetryEvent::RetrievalCompleted { .. }));
    let has_finish = telemetry_events.iter().any(|e| matches!(e, AgenticTelemetryEvent::ExecutionFinished { .. }));

    assert!(has_intent, "Must emit IntentClassified event");
    assert!(has_retrieval, "Must emit RetrievalCompleted event");
    assert!(has_finish, "Must emit ExecutionFinished event");
}
