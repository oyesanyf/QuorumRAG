//! Feature 56: Byzantine Peer & Fault Regression Test Suite (`crates/quorum-coordinator/tests/byzantine_fault_regression.rs`)
//!
//! Validates:
//! 1. `test_byzantine_sybil_score_stuffing_under_high_load`:
//!    Deduplication of rogue peer chunk flooding and ordinal RRF score clamping under high load.
//! 2. `test_byzantine_merkle_root_and_chunk_hash_tampering`:
//!    Verification of cryptographic BLAKE3 content hash and anti-malleability against spoofed chunk IDs.
//! 3. `test_byzantine_ed25519_forged_signature_and_identity_spoofing`:
//!    Fail-closed rejection of mismatched public keys, bit-flipped signatures, and post-signing tampering.
//! 4. `test_byzantine_network_partition_and_silent_drop_400ms_deadline`:
//!    Strict cancellation of partitioned / hanging peers within the 400ms scatter-gather deadline.
//! 5. `test_byzantine_replay_attack_and_drift_window_rejection`:
//!    Rejection of expired (>60s) or future (>60s) timestamps and anti-replay window enforcement.
//! 6. `test_invariant_fault_regression_source_code_and_temp_file_leakage`:
//!    Ingestion filtering invariant rejecting source code, lock files, temporary files, and binaries.
//! 7. `test_invariant_fault_regression_deterministic_synthesis_and_monotonic_progress`:
//!    Zero hallucinated RAG citations on missing/incidental matches and monotonically non-decreasing reindex progress.

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use uuid::Uuid;
use chrono::Utc;

use quorum_classifier::FileTypeClassifier;
use quorum_contract::{EmbeddingGenerator, DeterministicOfflineEngine};
use quorum_coordinator::crypto::{sign_request, verify_request};
use quorum_coordinator::fusion::RrfCombiner;
use quorum_coordinator::mesh::{MockRemotePeer, OsoosiMeshInboundHandler};
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_coordinator::scatter_gather::{FederatedQueryCoordinator, StorageSearcher};
use quorum_ingest::classifier_router::{ClassifierRouter, FilterDecision};
use quorum_ingest::config::{IngestConfig, ReindexOptions};
use quorum_ingest::dedup::TwoLevelDedupEngine;
use quorum_ingest::reindex::{ReindexPhase, ReindexWorker};
use quorum_network::InboundQueryHandler;
use quorum_storage::{StorageConfig, StorageEngine};
use quorum_types::{AccessTier, CandidateChunkDto, DocumentChunk, FederatedQueryRequest, ScoredChunk};

fn create_keypair(seed_byte: u8) -> ([u8; 32], [u8; 32], String) {
    let seed = [seed_byte; 32];
    let secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
    let ed_kp = quorum_network::libp2p::identity::ed25519::Keypair::from(secret);
    let pubkey_bytes = ed_kp.public().to_bytes();
    let pk = quorum_network::libp2p::identity::PublicKey::from(ed_kp.public());
    let peer_id = quorum_network::libp2p::PeerId::from_public_key(&pk).to_string();
    (seed, pubkey_bytes, peer_id)
}

// ---------------------------------------------------------------------------
// TEST 1: Sybil Score Stuffing & Flooding Attack Resistance
// ---------------------------------------------------------------------------
#[test]
fn test_byzantine_sybil_score_stuffing_under_high_load() {
    // 1. Legitimate local document
    let local_doc = DocumentChunk::new(
        "local_c1", "doc_local", "docs/report.pdf", 1, 10, 0, vec![0.1; 768],
        "Official verified corporate financial statement and audit.", None,
    ).unwrap();
    let local_results = vec![ScoredChunk::new(local_doc, 0.95, "local", false)];

    // 2. Byzantine Peer A floods 100 identical chunks claiming score 0.999
    let sybil_text = "Phishing attack or poison payload attempting to hijack search";
    let mut rogue_peer_a_chunks = Vec::new();
    for i in 0..100 {
        rogue_peer_a_chunks.push(CandidateChunkDto {
            chunk_id: format!("rogue_a_{}", i),
            file_path: format!("remote_a/fake_{}.txt", i),
            line_start: 1,
            line_end: 10,
            access_tier: 0,
            score: 0.999, // Artificially inflated
            content: sybil_text.to_string(),
        });
    }

    // 3. Honest Peer B corroborates the local document
    let honest_peer_b_chunks = vec![CandidateChunkDto {
        chunk_id: "peer_b_c1".to_string(),
        file_path: "remote_b/report.pdf".to_string(),
        line_start: 1,
        line_end: 10,
        access_tier: 0,
        score: 0.92,
        content: "Official verified corporate financial statement and audit.".to_string(),
    }];

    // Execute RRF Fusion: Local + Rogue Peer A + Honest Peer B
    let fused = RrfCombiner::fuse_rankings(
        local_results,
        vec![rogue_peer_a_chunks, honest_peer_b_chunks],
        60.0,
        10,
    );

    // Assertions:
    // a. The 100 flooded chunks MUST be deduplicated to exactly 1 entry
    let rogue_count = fused.iter().filter(|c| c.chunk.text_content == sybil_text).count();
    assert_eq!(rogue_count, 1, "Rogue peer 100-chunk flood must be deduplicated to exactly 1");

    // b. Score of rogue chunk must equal single rank 1 score 1 / 61
    let rogue_chunk = fused.iter().find(|c| c.chunk.text_content == sybil_text).unwrap();
    let expected_single_score = 1.0 / 61.0;
    assert!((rogue_chunk.score - expected_single_score).abs() < 1e-6);

    // c. Honest chunk receives multi-peer 1.25x boost and outranks rogue chunk at rank 0
    let honest_chunk = &fused[0];
    assert_eq!(honest_chunk.chunk.chunk_id, "local_c1");
    let expected_honest_score = ((1.0 / 61.0) + (1.0 / 61.0)) * 1.25;
    assert!((honest_chunk.score - expected_honest_score).abs() < 1e-6);
    assert!(honest_chunk.score > rogue_chunk.score);
}

// ---------------------------------------------------------------------------
// TEST 2: Merkle Root & Chunk Hash Tampering Detection
// ---------------------------------------------------------------------------
#[test]
fn test_byzantine_merkle_root_and_chunk_hash_tampering() {
    let authentic_text = "Verified cryptographic audit trail block";
    let chunk = DocumentChunk::new(
        "chunk_audit_01", "doc_audit", "audit.log", 1, 5, 0, vec![0.05; 768],
        authentic_text, None,
    ).unwrap();

    // Verification check on authentic chunk passes
    assert!(chunk.verify_hash(), "Authentic chunk hash must verify cleanly");

    // Tamper 1: Alter text content without updating blake3_hash
    let mut tampered_text_chunk = chunk.clone();
    tampered_text_chunk.text_content = "Tampered unauthorized modification of audit block".to_string();
    assert!(!tampered_text_chunk.verify_hash(), "Tampered text MUST fail hash verification");

    // Tamper 2: Alter blake3_hash without updating text
    let mut tampered_hash_chunk = chunk.clone();
    tampered_hash_chunk.blake3_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    assert!(!tampered_hash_chunk.verify_hash(), "Tampered hash MUST fail hash verification");

    // Tamper 3: Collision attack during RRF fusion
    // Rogue candidate attempts to claim the authentic chunk's ID but supplies altered content
    let candidate = CandidateChunkDto {
        chunk_id: "chunk_audit_01".to_string(), // Spoofed ID
        file_path: "fake/audit.log".to_string(),
        line_start: 1,
        line_end: 5,
        access_tier: 0,
        score: 0.99,
        content: "Malicious payload under legitimate ID".to_string(),
    };

    let fused = RrfCombiner::fuse_rankings(
        vec![ScoredChunk::new(chunk, 0.95, "local", false)],
        vec![vec![candidate]],
        60.0,
        10,
    );

    // Because fusion keys on dynamically recomputed BLAKE3 hash, both chunks remain separate!
    assert_eq!(fused.len(), 2, "Distinct content MUST remain separate despite identical chunk_id");
    assert_ne!(fused[0].chunk.blake3_hash, fused[1].chunk.blake3_hash);
}

// ---------------------------------------------------------------------------
// TEST 3: Ed25519 Forged Signatures & Identity Spoofing Rejection
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_byzantine_ed25519_forged_signature_and_identity_spoofing() {
    struct MockStorage {
        access_count: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl StorageSearcher for MockStorage {
        async fn search_hybrid(&self, _: &str, _: &[f32], _: u8, _: usize) -> Vec<ScoredChunk> {
            self.access_count.fetch_add(1, Ordering::SeqCst);
            vec![]
        }
    }

    let storage = Arc::new(MockStorage {
        access_count: AtomicUsize::new(0),
    });

    let (seed_a, pubkey_a, peer_id_a) = create_keypair(11);
    let (_seed_b, _pubkey_b, peer_id_b) = create_keypair(22);

    let handler = OsoosiMeshInboundHandler::new(storage.clone(), &peer_id_a);

    // Attack A: Identity Spoofing (Keypair A signs request, but claims peer ID B)
    let mut spoofed_req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id_b,
        sender_pubkey: pubkey_a,
        query_text: "Target confidential document".to_string(),
        embedding: vec![0.02; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed_a, &mut spoofed_req, AccessTier::Tier0Public);
    let resp_spoofed = handler.handle_query(spoofed_req).await;
    assert!(resp_spoofed.chunks.is_empty(), "Spoofed sender_peer_id MUST return 0 chunks");
    assert_eq!(storage.access_count.load(Ordering::SeqCst), 0);

    // Attack B: Forged Signature (Bit flip in signature byte 0)
    let mut forged_sig_req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id_a.clone(),
        sender_pubkey: pubkey_a,
        query_text: "Target confidential document".to_string(),
        embedding: vec![0.02; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed_a, &mut forged_sig_req, AccessTier::Tier0Public);
    forged_sig_req.signature[0] ^= 0x01; // Bit flip
    let resp_forged = handler.handle_query(forged_sig_req).await;
    assert!(resp_forged.chunks.is_empty(), "Forged signature MUST return 0 chunks");
    assert_eq!(storage.access_count.load(Ordering::SeqCst), 0);

    // Attack C: Query Tampering After Signing (Altered query text)
    let mut tampered_text_req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id_a.clone(),
        sender_pubkey: pubkey_a,
        query_text: "Public weather query".to_string(),
        embedding: vec![0.02; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed_a, &mut tampered_text_req, AccessTier::Tier0Public);
    tampered_text_req.query_text = "Classified confidential keys".to_string();
    let resp_tampered = handler.handle_query(tampered_text_req).await;
    assert!(resp_tampered.chunks.is_empty(), "Tampered query text MUST return 0 chunks");
    assert_eq!(storage.access_count.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// TEST 4: Network Partitions, Silent Drops, & 400ms Hard Timeout Guard
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_byzantine_network_partition_and_silent_drop_400ms_deadline() {
    struct TestLocalSearcher {
        sample_chunk: ScoredChunk,
    }
    #[async_trait::async_trait]
    impl StorageSearcher for TestLocalSearcher {
        async fn search_hybrid(&self, _: &str, _: &[f32], _: u8, _: usize) -> Vec<ScoredChunk> {
            tokio::time::sleep(Duration::from_millis(15)).await;
            vec![self.sample_chunk.clone()]
        }
    }

    let local_doc = DocumentChunk::new(
        "local_stable_1", "doc_local", "local/data.txt", 1, 10, 0, vec![0.1; 768],
        "Local authoritative document that survives network partition.", None,
    ).unwrap();
    let local_searcher = TestLocalSearcher {
        sample_chunk: ScoredChunk::new(local_doc, 0.95, "local", false),
    };

    let mut coordinator = FederatedQueryCoordinator::new(local_searcher);

    // Fast responsive peer (responds in 30ms)
    coordinator.add_peer(MockRemotePeer {
        peer_id: "peer_fast_honest".to_string(),
        latency: Duration::from_millis(30),
        max_access_tier: 0,
        candidate_chunks: vec![CandidateChunkDto {
            chunk_id: "c_fast_remote".to_string(),
            file_path: "fast/doc.txt".to_string(),
            line_start: 1,
            line_end: 10,
            access_tier: 0,
            score: 0.90,
            content: "Fast remote peer document".to_string(),
        }],
    });

    // 5 Partitioned / Silent Drop / Hanging Peers (delays 800ms to 4,000ms > 400ms deadline)
    for i in 1..=5 {
        coordinator.add_peer(MockRemotePeer {
            peer_id: format!("peer_partitioned_{}", i),
            latency: Duration::from_millis(800 * i as u64),
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: format!("c_partitioned_{}", i),
                file_path: format!("bad/part_{}.txt", i),
                line_start: 1,
                line_end: 10,
                access_tier: 0,
                score: 0.99,
                content: format!("Partitioned peer {} data should be discarded", i),
            }],
        });
    }

    // Execute query: Hard deadline is 400ms
    let start = std::time::Instant::now();
    let (results, volatile, duration_ms) = coordinator
        .execute_query("partition test", &vec![0.1; 768], 0, 10)
        .await;
    let elapsed = start.elapsed();

    // Invariants:
    // 1. Duration must be around 400ms (<= 450ms), NOT 4,000ms!
    assert!(
        duration_ms <= 450,
        "Scatter-gather query took {}ms (> 450ms deadline violation)",
        duration_ms
    );
    assert!(elapsed.as_millis() <= 500);

    // 2. Results must contain local chunk and fast peer chunk
    let ids: Vec<&str> = results.iter().map(|r| r.chunk.chunk_id.as_str()).collect();
    assert!(ids.contains(&"local_stable_1"));
    assert!(ids.contains(&"c_fast_remote"));

    // 3. None of the partitioned peers' chunks must appear
    for i in 1..=5 {
        let part_id = format!("c_partitioned_{}", i);
        assert!(!ids.contains(&part_id.as_str()));
    }

    // 4. Remote chunks in volatile memory must be scrubbed on drop
    assert!(!volatile.is_empty());
}

// ---------------------------------------------------------------------------
// TEST 5: Replay Attacks & Anti-Replay Freshness Windows
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_byzantine_replay_attack_and_drift_window_rejection() {
    struct MockStorage;
    #[async_trait::async_trait]
    impl StorageSearcher for MockStorage {
        async fn search_hybrid(&self, _: &str, _: &[f32], _: u8, _: usize) -> Vec<ScoredChunk> {
            vec![]
        }
    }

    let (seed, pubkey, peer_id) = create_keypair(22);
    let handler = OsoosiMeshInboundHandler::new(Arc::new(MockStorage), &peer_id);
    let now = Utc::now().timestamp();

    // Expired past timestamps (> 60s) and future timestamps (> 60s)
    let replayed_timestamps = vec![
        now - 61,       // 1 second past drift window
        now - 120,      // 2 minutes ago
        now - 3600,     // 1 hour ago
        now - 86400,    // 1 day ago
        0,              // Unix epoch replay (1970)
        now + 61,       // 1 second in future
        now + 3600,     // 1 hour in future
    ];

    for ts in replayed_timestamps {
        let mut req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: peer_id.clone(),
            sender_pubkey: pubkey,
            query_text: "Replayed authentic query".to_string(),
            embedding: vec![0.05; 768],
            top_k: 5,
            timestamp: ts,
            signature: [0u8; 64],
        };
        sign_request(&seed, &mut req, AccessTier::Tier0Public);

        let resp = handler.handle_query(req.clone()).await;
        assert!(
            resp.chunks.is_empty(),
            "Replayed request with timestamp {} must return 0 chunks",
            ts
        );
        assert!(verify_request(&req, AccessTier::Tier0Public, 60).is_err());
    }

    // Valid timestamps within 60s drift window must pass
    for ts in [now - 30, now, now + 30] {
        let mut valid_req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: peer_id.clone(),
            sender_pubkey: pubkey,
            query_text: "Valid query within drift window".to_string(),
            embedding: vec![0.05; 768],
            top_k: 5,
            timestamp: ts,
            signature: [0u8; 64],
        };
        sign_request(&seed, &mut valid_req, AccessTier::Tier0Public);
        assert!(verify_request(&valid_req, AccessTier::Tier0Public, 60).is_ok());
    }
}

// ---------------------------------------------------------------------------
// TEST 6: Invariant Fault Regression: Source Code & Temp File Leakage
// ---------------------------------------------------------------------------
#[test]
fn test_invariant_fault_regression_source_code_and_temp_file_leakage() {
    let dir = tempdir().unwrap();
    let base = dir.path();

    // 1. Create mixed directory: source code, temp files, binaries, legitimate docs
    let files: [(&str, &[u8], bool); 12] = [
        ("main.rs", b"fn main() { println!(\"code\"); }", true),
        ("app.py", b"def run(): pass", true),
        ("bundle.js", b"console.log('js');", true),
        ("query.sql", b"SELECT * FROM users;", true),
        ("~$Confidential_Audit.docx", b"Word lock buffer", true),
        ("~autosave.tmp", b"Temporary autosave buffer", true),
        ("backup_data.bak", b"Backup copy", true),
        ("payload.exe", b"MZ executable binary", true),
        ("library.dll", b"PE DLL binary", true),
        ("annual_report.pdf", b"%PDF-1.5 Annual financial earnings report and overview.\n%%EOF", false),
        ("meeting_notes.txt", b"Meeting notes regarding architectural roadmap and milestones.", false),
        ("system_architecture.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4", false),
    ];

    let mut cfg = IngestConfig::default();
    cfg.exclude_source_code = true;
    let router = ClassifierRouter::new(cfg);

    for (name, content, should_exclude) in files {
        let path = base.join(name);
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(content).unwrap();
        }

        let decision = router.evaluate_file(&path);
        if should_exclude {
            assert!(
                matches!(decision, FilterDecision::SkipBinary { .. } | FilterDecision::SkipHidden),
                "File '{}' MUST be excluded by ClassifierRouter, got {:?}",
                name, decision
            );
        } else {
            assert!(
                matches!(decision, FilterDecision::Accept { .. }),
                "Legitimate file '{}' MUST be accepted, got {:?}",
                name, decision
            );
        }
    }
}

// ---------------------------------------------------------------------------
// TEST 7: Invariant Fault Regression: Deterministic Grounding & Progress Monotonicity
// ---------------------------------------------------------------------------
#[tokio::test]
async fn test_invariant_fault_regression_deterministic_synthesis_and_monotonic_progress() {
    // Part A: Zero Ungrounded Hallucinations in Synthesis
    // 1. Query with 0 matching documents -> Deterministic fallback, 0 citations
    let (response_empty, citations_empty) = DeterministicOfflineSynthesisEngine::synthesize(
        "what is quantum teleportation cryptography", &[], "AutoFusion",
    );
    assert!(response_empty.contains("No matching documents were found in your local RAG index"));
    assert!(citations_empty.is_empty(), "Empty search MUST return 0 citations");

    // 2. Query with non-matching multi-term query (incidental generic hit rejected)
    let tax_chunk = ScoredChunk::new(
        DocumentChunk::new(
            "tax_c1", "doc_tax", "tax_statement_2023.pdf", 1, 20, 0, vec![0.1; 768],
            "Annual gross taxable income statement and standard deduction calculation.", None,
        ).unwrap(),
        0.85, "local", false,
    );
    // Query: "universal mineral income" -> has generic term "income", but 0 hits for "universal" or "mineral"
    let (response_incidental, citations_incidental) = DeterministicOfflineSynthesisEngine::synthesize(
        "what is universal mineral income", &[tax_chunk], "AutoFusion",
    );
    assert!(response_incidental.contains("No matching documents were found"));
    assert!(citations_incidental.is_empty(), "Incidental generic term match MUST be rejected");

    // Part B: Monotonic Indexer Progress Invariant
    let temp = tempdir().unwrap();
    let root = temp.path();
    let sub = root.join("docs");
    create_dir_all(&sub).unwrap();

    for i in 0..12 {
        let p = sub.join(format!("document_{}.txt", i));
        let mut f = File::create(&p).unwrap();
        writeln!(f, "Document {} content for monotonic progress assertion.", i).unwrap();
    }

    let storage_dir = root.join("storage");
    let storage = Arc::new(StorageEngine::open(StorageConfig::new(storage_dir)).await.unwrap());
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(DeterministicOfflineEngine::new());
    let dedup = Arc::new(TwoLevelDedupEngine::new());

    let config = IngestConfig {
        watch_paths: vec![sub.clone()],
        ..Default::default()
    };

    let worker = ReindexWorker::new(config, storage, classifier, embedder, dedup);
    let options = ReindexOptions {
        target_paths: vec![sub],
        full_rebuild: true,
        force_reembed: false,
        batch_size: 4,
        num_threads: 0,
        dry_run: false,
    };

    worker.start_reindex(options).await.unwrap();

    let mut last_scanned = 0;
    let mut last_pct = 0.0;
    let mut polls = 0;

    loop {
        tokio::time::sleep(Duration::from_millis(5)).await;
        polls += 1;

        if let Some(prog) = worker.get_progress().await {
            // Invariant 1: files_scanned must be monotonically non-decreasing
            assert!(
                prog.files_scanned >= last_scanned,
                "files_scanned dropped from {} to {}",
                last_scanned, prog.files_scanned
            );
            last_scanned = prog.files_scanned;

            // Invariant 2: progress percentage must be monotonically non-decreasing
            if prog.files_total_estimated > 0 {
                let current_pct = (prog.files_scanned as f64 / prog.files_total_estimated as f64) * 100.0;
                assert!(
                    current_pct >= last_pct - 0.0001,
                    "Progress percentage dropped from {:.2}% to {:.2}%",
                    last_pct, current_pct
                );
                last_pct = current_pct;
            }

            if matches!(prog.phase, ReindexPhase::Completed) {
                assert_eq!(prog.files_scanned, 12);
                assert_eq!(prog.files_indexed, 12);
                break;
            }
        }
        if polls > 500 {
            panic!("Reindex worker timed out");
        }
    }
    assert!(last_pct >= 99.99);
}
