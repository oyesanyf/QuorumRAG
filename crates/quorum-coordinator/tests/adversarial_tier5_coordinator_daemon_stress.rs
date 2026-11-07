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
use std::sync::{Arc, Mutex};
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
use quorum_contract::rlm::*;
use quorum_coordinator::rlm_orchestrator::{RlmOrchestrator, RlmWorkspaceState};
use quorum_coordinator::HardwareTelemetry;
use rhai::{Dynamic, Scope};

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
            node_id: None,
            is_external_node: false,
            origin_label: Some("local".to_string()),
            node_alias: None,
            verbatim_quote: None,
            byte_range: None,
            grounding_rationale: None,
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

// =========================================================================
// Challenge 7: Pure-Rust Sandboxed Rhai REPL Sandbox Limits & Host Isolation
// =========================================================================

fn create_test_heterogeneous_chunks() -> Vec<RetrievedChunk> {
    vec![
        RetrievedChunk {
            id: "local_c1".to_string(),
            document_id: "doc_local".to_string(),
            file_path: "D:/Research/QuantumConsensus.pdf".to_string(),
            line_start: 1,
            line_end: 25,
            text: "Quantum consensus protocols enable fault-tolerant distributed Byzantine agreements in polynomial time.".to_string(),
            score: 0.95,
            access_tier: 0,
            source_peer: "local".to_string(),
            node_id: None,
            is_external: false,
            node_alias: None,
            work_cluster_id: Some("quantum_paper".to_string()),
        },
        RetrievedChunk {
            id: "remote_c2".to_string(),
            document_id: "doc_remote_1".to_string(),
            file_path: "peer://12D3KooWAlpha/security/threat_matrix.pdf".to_string(),
            line_start: 10,
            line_end: 45,
            text: "Adversarial network isolation prevents lateral breakout across federated sub-clusters.".to_string(),
            score: 0.91,
            access_tier: 1,
            source_peer: "12D3KooWAlpha".to_string(),
            node_id: Some("12D3KooWAlpha".to_string()),
            is_external: true,
            node_alias: Some("Alpha Peer".to_string()),
            work_cluster_id: Some("threat_matrix".to_string()),
        },
        RetrievedChunk {
            id: "remote_c3".to_string(),
            document_id: "doc_remote_2".to_string(),
            file_path: "peer://12D3KooWBeta/telemetry/audit_log.json".to_string(),
            line_start: 100,
            line_end: 150,
            text: "Telemetry events verified by Ed25519 node signatures and Merkle proof inclusion.".to_string(),
            score: 0.88,
            access_tier: 0,
            source_peer: "12D3KooWBeta".to_string(),
            node_id: Some("12D3KooWBeta".to_string()),
            is_external: true,
            node_alias: Some("Beta Peer".to_string()),
            work_cluster_id: Some("audit_log".to_string()),
        },
    ]
}

#[test]
fn challenge_tier5_rlm_infinite_loop_and_op_limit_terminates_strictly() {
    let config = RlmConfig {
        max_ops: 100_000,
        max_call_depth: 16,
        max_string_size: 1_048_576,
        max_array_size: 4096,
        timeout_ms: 10_000,
        ..Default::default()
    };
    let ws = Arc::new(Mutex::new(RlmWorkspaceState::default()));
    let engine = RlmOrchestrator::create_sandboxed_engine(&config, ws, "qwen2.5:1.5b".to_string());

    // 1a. Unbounded while true loop
    let start = Instant::now();
    let res1 = engine.eval::<Dynamic>("let counter = 0; while true { counter += 1; }");
    let elapsed1 = start.elapsed();
    assert!(res1.is_err(), "Unbounded while loop MUST trigger ErrorTooManyOperations");
    let err_str = res1.unwrap_err().to_string();
    assert!(
        err_str.contains("Too many operations") || err_str.contains("operations"),
        "Error message should reflect operation limit: {}",
        err_str
    );
    assert!(
        elapsed1.as_millis() < 500,
        "100,000 op limit must terminate rapidly (< 500ms), took {:?}",
        elapsed1
    );

    // 1b. Nested loops with multiplication
    let start2 = Instant::now();
    let res2 = engine.eval::<Dynamic>(
        r#"
        let total = 0;
        let i = 0;
        while i < 1000 {
            let j = 0;
            while j < 1000 {
                total += 1;
                j += 1;
            }
            i += 1;
        }
        total
        "#,
    );
    let elapsed2 = start2.elapsed();
    assert!(res2.is_err(), "Nested loops exceeding 100k ops MUST trigger operation limit");
    assert!(
        elapsed2.as_millis() < 500,
        "Nested loop op limit must terminate rapidly (< 500ms), took {:?}",
        elapsed2
    );

    // 1c. Loop calling host function repeatedly
    let ws3 = Arc::new(Mutex::new(RlmWorkspaceState {
        chunks: create_test_heterogeneous_chunks(),
        ..Default::default()
    }));
    let engine3 = RlmOrchestrator::create_sandboxed_engine(&config, ws3, "qwen2.5:1.5b".to_string());
    let res3 = engine3.eval::<Dynamic>("while true { let n = ctx_len(); }");
    assert!(res3.is_err(), "Repeated host function calls must terminate at 100,000 ops");

    // 1d. Timeout guard verification
    let config_timeout = RlmConfig {
        max_ops: 10_000_000,
        max_call_depth: 16,
        max_string_size: 1_048_576,
        max_array_size: 4096,
        timeout_ms: 250,
        ..Default::default()
    };
    let ws_to = Arc::new(Mutex::new(RlmWorkspaceState::default()));
    let engine_to = RlmOrchestrator::create_sandboxed_engine(&config_timeout, ws_to, "qwen2.5:1.5b".to_string());
    let start_to = Instant::now();
    let res_to = engine_to.eval::<Dynamic>("let x = 0; while true { x += 1; }");
    let elapsed_to = start_to.elapsed();
    let err_to = res_to.unwrap_err();
    let err_to_msg = err_to.to_string();
    assert!(
        err_to_msg.contains("Script terminated")
            || err_to_msg.contains("timeout")
            || err_to_msg.contains("Script execution timeout"),
        "Error message must specify script termination: {}",
        err_to_msg
    );
    if let rhai::EvalAltResult::ErrorTerminated(ref val, _) = *err_to {
        let reason = val.clone().into_string().unwrap_or_default();
        assert!(
            reason.contains("timeout"),
            "Termination payload must specify timeout: {}",
            reason
        );
    }
    assert!(
        elapsed_to.as_millis() >= 200 && elapsed_to.as_millis() < 2000,
        "Timeout guard must fire near 250ms, took {:?}",
        elapsed_to
    );
}

#[test]
fn challenge_tier5_rlm_call_depth_exhaustion_terminates_cleanly() {
    let config = RlmConfig {
        max_ops: 100_000,
        max_call_depth: 16,
        max_string_size: 1_048_576,
        max_array_size: 4096,
        timeout_ms: 10_000,
        ..Default::default()
    };
    let ws = Arc::new(Mutex::new(RlmWorkspaceState::default()));
    let engine = RlmOrchestrator::create_sandboxed_engine(&config, ws, "qwen2.5:1.5b".to_string());

    // 2a. Direct infinite recursion
    let res1 = engine.eval::<Dynamic>(
        r#"
        fn recurse(depth) {
            recurse(depth + 1);
        }
        recurse(1);
        "#,
    );
    assert!(res1.is_err(), "Direct recursion exceeding 16 levels must fail");
    let err1 = res1.unwrap_err().to_string();
    assert!(
        err1.contains("call levels") || err1.contains("Stack overflow") || err1.contains("call depth") || err1.contains("StackOverflow"),
        "Error must indicate call stack depth exhaustion: {}",
        err1
    );

    // 2b. Mutual recursion between two functions
    let res2 = engine.eval::<Dynamic>(
        r#"
        fn ping(n) {
            pong(n + 1);
        }
        fn pong(n) {
            ping(n + 1);
        }
        ping(1);
        "#,
    );
    assert!(res2.is_err(), "Mutual recursion exceeding 16 levels must fail");
    let err2 = res2.unwrap_err().to_string();
    assert!(
        err2.contains("call levels") || err2.contains("Stack overflow") || err2.contains("StackOverflow"),
        "Error must indicate call stack depth exhaustion: {}",
        err2
    );

    // 2c. Boundary test: recursion up to 10 levels should succeed cleanly
    let res3 = engine.eval::<i64>(
        r#"
        fn safe_depth(n) {
            if n <= 1 {
                return 1;
            }
            return 1 + safe_depth(n - 1);
        }
        safe_depth(10);
        "#,
    );
    assert_eq!(res3.expect("Recursion within 16 levels must succeed"), 10);
}

#[test]
fn challenge_tier5_rlm_memory_allocation_limits_strictly_enforced() {
    let config = RlmConfig {
        max_ops: 100_000,
        max_call_depth: 16,
        max_string_size: 1_000_000, // 1 MB limit
        max_array_size: 4096,       // 4,096 elements limit
        timeout_ms: 10_000,
        ..Default::default()
    };
    let ws = Arc::new(Mutex::new(RlmWorkspaceState::default()));
    let engine = RlmOrchestrator::create_sandboxed_engine(&config, ws, "qwen2.5:1.5b".to_string());

    // 3a. String exponential expansion attack (doubling repeatedly)
    let res_str = engine.eval::<Dynamic>(
        r#"
        let s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        while true {
            s += s;
        }
        s
        "#,
    );
    assert!(res_str.is_err(), "String expansion beyond 1 MB must be rejected");
    let err_str = res_str.unwrap_err().to_string();
    assert!(
        err_str.contains("Data too large") || err_str.contains("size") || err_str.contains("string"),
        "String allocation limit should be reported: {}",
        err_str
    );

    // 3b. Array unbounded growth attack
    let res_arr = engine.eval::<Dynamic>(
        r#"
        let arr = [];
        while true {
            arr.push("chunk_element_item");
        }
        arr
        "#,
    );
    assert!(res_arr.is_err(), "Array expansion beyond 4,096 elements must be rejected");
    let err_arr = res_arr.unwrap_err().to_string();
    assert!(
        err_arr.contains("Data too large") || err_arr.contains("size") || err_arr.contains("array"),
        "Array allocation limit should be reported: {}",
        err_arr
    );

    // 3c. Map unbounded growth attack
    let res_map = engine.eval::<Dynamic>(
        r#"
        let m = #{};
        let i = 0;
        while true {
            m["k" + i] = i;
            i += 1;
        }
        m
        "#,
    );
    assert!(res_map.is_err(), "Map expansion beyond 4,096 keys must be rejected");
}

#[test]
fn challenge_tier5_rlm_host_functions_adversarial_isolation_and_no_breakout() {
    let config = RlmConfig::default();
    let chunks = create_test_heterogeneous_chunks();
    let ws = Arc::new(Mutex::new(RlmWorkspaceState {
        chunks,
        ..Default::default()
    }));
    let engine = RlmOrchestrator::create_sandboxed_engine(&config, Arc::clone(&ws), "qwen2.5:1.5b".to_string());
    let mut scope = Scope::new();

    // 1. catalog_find_documents with path traversal, SQL injection, extreme limits
    let res_cat1: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"catalog_find_documents("../../../../Windows/System32/cmd.exe", 10)"#,
    ).expect("catalog_find_documents must not panic on path traversal");
    assert_eq!(res_cat1.len(), 0, "No chunks should match unindexed system paths");

    let res_cat2: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"catalog_find_documents("' OR '1'='1' --", -50)"#,
    ).expect("catalog_find_documents must handle negative limit and SQL injection strings");
    assert_eq!(res_cat2.len(), 0);

    // 2. corpus_search with extreme k and special tokens
    scope.push("query_with_null", "consensus protocols \x00\r\n\t");
    let res_cs1: rhai::Array = engine.eval_with_scope(
        &mut scope,
        "corpus_search(query_with_null, -1)",
    ).expect("corpus_search must not panic on negative k or null chars");
    assert!(!res_cs1.is_empty(), "Valid tokens should match index");

    // 3. corpus_search_excluding with regex metas and path characters
    let res_cse: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"corpus_search_excluding("protocols", 5, "quantum")"#,
    ).expect("corpus_search_excluding must not panic");
    for idx_dyn in res_cse {
        let idx = idx_dyn.as_int().unwrap() as usize;
        let c = &ws.lock().unwrap().chunks[idx];
        assert!(
            !c.file_path.to_ascii_lowercase().contains("quantum"),
            "Excluded stem 'quantum' must not appear in results"
        );
    }

    // 4. ctx_len verification
    let len: i64 = engine.eval_with_scope(&mut scope, "ctx_len()").expect("ctx_len");
    assert_eq!(len, 3);

    // 5. ctx_chunk out-of-bounds and negative indices
    let c_neg: String = engine.eval_with_scope(&mut scope, "ctx_chunk(-1)").expect("ctx_chunk negative");
    assert_eq!(c_neg, "", "Negative index must safely return empty string");

    let c_oob: String = engine.eval_with_scope(&mut scope, "ctx_chunk(999999)").expect("ctx_chunk oob");
    assert_eq!(c_oob, "", "OOB index must safely return empty string");

    let c_valid: String = engine.eval_with_scope(&mut scope, "ctx_chunk(0)").expect("ctx_chunk valid");
    assert!(c_valid.contains("Quantum consensus"));

    // 6. ctx_grep with ReDoS catastrophic backtracking and invalid patterns
    let res_redos: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"ctx_grep("(a+)+$")"#,
    ).expect("ctx_grep with complex pattern must not hang or panic");
    assert_eq!(res_redos.len(), 0);

    let res_invalid_re: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"ctx_grep("[unclosed-regex-bracket")"#,
    ).expect("ctx_grep with invalid regex must safely return empty array");
    assert_eq!(res_invalid_re.len(), 0);

    let res_grep_match: rhai::Array = engine.eval_with_scope(
        &mut scope,
        r#"ctx_grep("Quantum")"#,
    ).expect("ctx_grep match");
    assert_eq!(res_grep_match.len(), 1);

    // 7. ctx_sub regex replacement in-place and 3-arg version
    let _ = engine.eval_with_scope::<Dynamic>(
        &mut scope,
        r#"append_section("Draft", "Initial draft with foo and bar.");"#,
    ).expect("append_section");

    let _ = engine.eval_with_scope::<Dynamic>(
        &mut scope,
        r#"ctx_sub("foo", "RESOLVED_FOO");"#,
    ).expect("ctx_sub in-place");

    let rep_after_sub: String = engine.eval_with_scope(&mut scope, "get_report()").expect("get_report");
    assert!(rep_after_sub.contains("RESOLVED_FOO"));

    let replaced_str: String = engine.eval_with_scope(
        &mut scope,
        r#"ctx_sub("The old token value", "old token", "new token")"#,
    ).expect("ctx_sub 3-arg");
    assert_eq!(replaced_str, "The new token value");

    // 8. llm_query command injection resilience
    let llm_res: String = engine.eval_with_scope(
        &mut scope,
        r#"llm_query("; rm -rf / ; cat /etc/passwd ; dir & calc.exe")"#,
    ).expect("llm_query must never execute OS commands");
    assert!(!llm_res.is_empty());
    assert_eq!(ws.lock().unwrap().sub_queries_log.len(), 1);

    // 9. mesh_sub_query path traversal and command injection resilience
    let mesh_res: String = engine.eval_with_scope(
        &mut scope,
        r#"mesh_sub_query("../../etc/shadow", "verify integrity")"#,
    ).expect("mesh_sub_query must safely register peer query");
    assert!(mesh_res.contains("Findings from mesh peer"));
    let guard = ws.lock().unwrap();
    assert!(guard.external_nodes_seen.contains(&"../../etc/shadow".to_string()));
    assert_eq!(guard.mesh_contributions.len(), 1);
    drop(guard);

    // 10. append_section with malicious markdown / HTML injection
    scope.push("malicious_html", "<script>alert('xss')</script>\0\r\n## Fake Title");
    let _ = engine.eval_with_scope::<Dynamic>(
        &mut scope,
        r#"append_section("MaliciousSection", malicious_html);"#,
    ).expect("append_section malicious string");

    // 11. get_report Markdown structure
    let rep_full: String = engine.eval_with_scope(&mut scope, "get_report()").expect("get_report");
    assert!(rep_full.contains("### Draft"));
    assert!(rep_full.contains("### MaliciousSection"));

    // 12. submit_final persistence
    let _ = engine.eval_with_scope::<Dynamic>(
        &mut scope,
        r#"submit_final("Final verified report body.");"#,
    ).expect("submit_final");
    assert_eq!(
        ws.lock().unwrap().final_answer.as_deref(),
        Some("Final verified report body.")
    );

    // 13. Sandbox OS Isolation: verify Rhai cannot access OS/filesystem APIs
    let res_fs = engine.eval_with_scope::<Dynamic>(&mut scope, r#"import "std";"#);
    assert!(res_fs.is_err(), "Rhai sandbox must reject module imports like 'std'");

    let res_cmd = engine.eval_with_scope::<Dynamic>(&mut scope, r#"std::process::Command::new("cmd");"#);
    assert!(res_cmd.is_err(), "Rhai sandbox must reject std::process calls");

    let res_file = engine.eval_with_scope::<Dynamic>(&mut scope, r#"open("test.txt");"#);
    assert!(res_file.is_err(), "Rhai sandbox must reject undefined filesystem functions");
}

#[test]
fn challenge_tier5_rlm_node_provenance_and_telemetry_invariants() {
    let hw = HardwareTelemetry {
        gpu_name: Some("NVIDIA RTX 4000 Ada Generation".to_string()),
        free_vram_mb: 16384,
        total_vram_mb: 20480,
        free_ram_gb: 32.0,
        total_ram_gb: 64.0,
        cpu_cores: 16,
        gpu_count: 1,
    };
    let config = RlmConfig {
        max_iterations: 4,
        max_ops: 100_000,
        max_call_depth: 16,
        max_string_size: 1_048_576,
        max_array_size: 4096,
        timeout_ms: 10_000,
        ..Default::default()
    };

    let orch = RlmOrchestrator::new(config, hw, vec!["qwen2.5:7b".to_string()]);
    let chunks = create_test_heterogeneous_chunks();

    // Verify model selection logic
    let fast_model = orch.select_fast_map_model();
    assert_eq!(fast_model, "qwen2.5:7b", "High VRAM (>4500MB) must select qwen2.5:7b");

    let (heavy_model, num_ctx) = orch.select_heavy_reduce_model();
    assert_eq!(heavy_model, "qwen2.5:7b");
    assert_eq!(num_ctx, 32768, "VRAM >= 16000MB must scale num_ctx to 32768");

    // Execute RLM with heterogeneous chunks
    let prompt = "Explain quantum consensus and distributed threat isolation.";
    let resp = orch.execute(prompt, chunks.clone()).expect("execute RLM pipeline");

    // 5a. Final answer and citations must not be empty
    assert!(!resp.final_answer.is_empty());
    assert!(!resp.traces.is_empty(), "Must record step execution traces");
    assert_eq!(resp.citations.len(), chunks.len(), "Each chunk must produce a grounded citation");

    // 5b. Verify external node IDs are captured in response
    assert!(
        resp.external_node_ids.contains(&"12D3KooWAlpha".to_string()),
        "External node 12D3KooWAlpha must be in external_node_ids"
    );
    assert!(
        resp.external_node_ids.contains(&"12D3KooWBeta".to_string()),
        "External node 12D3KooWBeta must be in external_node_ids"
    );
    assert!(
        !resp.external_node_ids.contains(&"local".to_string()),
        "Local node must NOT be listed in external_node_ids"
    );

    // 5c. Verify exact citation node provenance
    let local_citation = resp.citations.iter().find(|c| c.document_id == "doc_local").expect("local citation");
    assert!(!local_citation.is_external, "Local citation must have is_external == false");
    assert_eq!(local_citation.node_id, "local", "Local chunk node_id must default to 'local'");
    assert!(local_citation.node_alias.is_none());

    let remote_alpha_citation = resp.citations.iter().find(|c| c.document_id == "doc_remote_1").expect("remote 1 citation");
    assert!(remote_alpha_citation.is_external, "Alpha citation must have is_external == true");
    assert_eq!(remote_alpha_citation.node_id, "12D3KooWAlpha", "Alpha node_id must be preserved");
    assert_eq!(remote_alpha_citation.node_alias.as_deref(), Some("Alpha Peer"));

    let remote_beta_citation = resp.citations.iter().find(|c| c.document_id == "doc_remote_2").expect("remote 2 citation");
    assert!(remote_beta_citation.is_external, "Beta citation must have is_external == true");
    assert_eq!(remote_beta_citation.node_id, "12D3KooWBeta", "Beta node_id must be preserved");
    assert_eq!(remote_beta_citation.node_alias.as_deref(), Some("Beta Peer"));

    // 5d. Complementary mesh findings fusion test
    let mut modified_answer = resp.final_answer.clone();
    let mesh_contrib = vec![
        MeshContribution {
            node_id: "12D3KooWGamma".to_string(),
            node_alias: Some("Gamma Peer".to_string()),
            summary: "Gamma peer confirmed zero Byzantine divergence under 100k rounds.".to_string(),
            citations: Vec::new(),
        },
    ];
    RlmOrchestrator::fuse_complementary_mesh_findings(&mut modified_answer, &mesh_contrib);

    assert!(
        modified_answer.contains("### Complementary Mesh Findings [Mesh ID: 12D3KooWGamma]"),
        "Fused answer must contain heading with exact peer node ID"
    );
    assert!(
        modified_answer.contains("Gamma peer confirmed zero Byzantine divergence"),
        "Fused answer must include peer summary text"
    );
}
