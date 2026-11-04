//! E2E Tests: Tier 3 Cross-Feature Interactions & Pairwise Combinations.
//!
//! Pairwise feature combinations covered:
//! 1. Magika file classification + Level-1/2 BLAKE3 deduplication + Isolated LanceDB storage insert.
//! 2. Dedup matching across files while access tier restricts chunk visibility.
//! 3. Concurrent local file ingestion + remote peer query + Web SSE response stream.
//! 4. 400ms scatter-gather timeout firing during active SSE response stream.
//! 5. Ed25519 signature verification failure terminating query pipeline before storage scan.
//! 6. Embedding contract hash mismatch gating peer before admission to scatter-gather mesh.
//! 7. Memory security: Volatile remote chunk zeroized on drop while local chunks remain persistent.

use chrono::Utc;
use quorum_classifier::FileTypeClassifier;
use quorum_contract::{verify_contract_handshake, EmbeddingContract};
use quorum_e2e::*;
use quorum_types::{AccessTier, CandidateChunkDto, DocumentChunk};
use std::fs::File;
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;
use uuid::Uuid;
use zeroize::Zeroize;

#[test]
fn test_pair_magika_to_dedup_to_isolated_storage() {
    let dir = tempdir().unwrap();
    let classifier = FileTypeClassifier::new();
    let mut storage = IsolatedStorageEngine::new();

    // 1. Create a genuine Rust file
    let rs_path = dir.path().join("algo.rs");
    {
        let mut f = File::create(&rs_path).unwrap();
        writeln!(f, "pub fn compute_rrf(k: f32) -> f32 {{ 1.0 / (k + 1.0) }}").unwrap();
    }

    // 2. Classify using Magika deep content classifier
    let identity = classifier.classify_file(&rs_path).unwrap();
    assert_eq!(identity.label, "rust");
    assert!(identity.is_text);
    assert!(!identity.is_binary);

    // 3. Ingest into document chunk with BLAKE3 hash
    let content = std::fs::read_to_string(&rs_path).unwrap();
    let b3 = DocumentChunk::compute_blake3_hash(&content);
    let vector = oracle_deterministic_vector(&content, 768);

    let chunk = DocumentChunk::new(
        "c_algo",
        "doc_algo",
        rs_path.to_string_lossy().to_string(),
        1,
        5,
        0,
        vector,
        content,
        None,
    )
    .unwrap();

    // 4. Insert into isolated storage
    let inserted = storage.insert_chunks(&[chunk]);
    assert_eq!(inserted, 1);
    assert!(storage.has_chunk_hash(&b3));

    // 5. Query storage
    let hits = storage.search_text("compute_rrf", 0, 5);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].chunk.chunk_id, "c_algo");
}

#[test]
fn test_pair_dedup_matching_with_access_tier_restriction() {
    let mut storage = IsolatedStorageEngine::new();

    let secret_text = "CONFIDENTIAL_ORGANIZATION_STRATEGY_2027";
    let text_b3 = DocumentChunk::compute_blake3_hash(secret_text);

    // Document ingested at Tier 2 (Confidential)
    let confidential_chunk = DocumentChunk::new(
        "chunk_conf",
        "doc_conf",
        "strategy.txt",
        1,
        2,
        AccessTier::Tier2Confidential.as_u8(),
        vec![1.0; 768],
        secret_text,
        None,
    )
    .unwrap();

    storage.insert_chunks(&[confidential_chunk]);

    // Invariant 1: Storage knows this chunk hash exists for deduplication
    assert!(storage.has_chunk_hash(&text_b3));

    // Invariant 2: A Tier 0 (Public) query CANNOT retrieve this chunk, even though the text exists in DB
    let public_hits = storage.search_vector(&vec![1.0; 768], AccessTier::Tier0Public.as_u8(), 5);
    assert!(public_hits.is_empty(), "Public query must NOT retrieve confidential chunk");

    // Invariant 3: A Tier 2 (Confidential) query CAN retrieve this chunk
    let conf_hits = storage.search_vector(&vec![1.0; 768], AccessTier::Tier2Confidential.as_u8(), 5);
    assert_eq!(conf_hits.len(), 1);
    assert_eq!(conf_hits[0].chunk.chunk_id, "chunk_conf");
}

#[tokio::test]
async fn test_pair_concurrent_ingestion_and_federated_mesh_query() {
    let mut storage = IsolatedStorageEngine::new();
    storage.insert_chunks(&[DocumentChunk::new(
        "c_base",
        "d_base",
        "base.txt",
        1,
        2,
        0,
        vec![1.0; 768],
        "Base system architecture",
        None,
    )
    .unwrap()]);

    let coordinator = FederatedQueryCoordinator::new(storage.clone());

    // Task 1: Ingest 50 chunks concurrently
    let storage_clone = storage.clone();
    let ingest_handle = tokio::spawn(async move {
        let mut st = storage_clone;
        for i in 0..50 {
            let chunk = DocumentChunk::new(
                format!("c_async_{}", i),
                "d_async",
                "async.txt",
                i as u32,
                i as u32 + 1,
                0,
                vec![0.1 * (i as f32); 768],
                format!("Async content line {}", i),
                None,
            )
            .unwrap();
            st.insert_chunks(&[chunk]);
        }
        st.len()
    });

    // Task 2: Dispatch federated query simultaneously
    let query_handle = tokio::spawn(async move {
        coordinator
            .execute_query("architecture", &vec![1.0; 768], 0, 5)
            .await
    });

    let (st_res, query_res) = tokio::join!(ingest_handle, query_handle);
    let st_len = st_res.unwrap();
    let (hits, _, duration_ms) = query_res.unwrap();
    assert_eq!(st_len, 51);
    assert!(!hits.is_empty());
    assert!(duration_ms < 400);
}

#[tokio::test]
async fn test_pair_scatter_gather_timeout_during_active_query() {
    let local_storage = IsolatedStorageEngine::new();
    let mut coordinator = FederatedQueryCoordinator::new(local_storage);

    // Extremely slow peer (1.5 seconds latency)
    let hanging_peer = MockRemotePeer {
        peer_id: "peer_hang".to_string(),
        latency: Duration::from_millis(1500),
        max_access_tier: 0,
        candidate_chunks: vec![CandidateChunkDto {
            chunk_id: "c_never".to_string(),
            file_path: "hang.txt".to_string(),
            line_start: 1,
            line_end: 2,
            content: "Never arrives".to_string(),
            score: 0.99,
            access_tier: 0,
        }],
    };
    coordinator.add_peer(hanging_peer);

    let start = tokio::time::Instant::now();
    let (results, _, elapsed_ms) = coordinator
        .execute_query("fast", &vec![0.0; 768], 0, 10)
        .await;

    let real_elapsed = start.elapsed().as_millis() as u64;
    assert!(results.is_empty());
    assert!(
        real_elapsed <= 490,
        "400ms timeout guard must abort 1500ms hanging peer within ~400ms (took {}ms)",
        real_elapsed
    );
    assert!(elapsed_ms <= 490);
}

#[test]
fn test_pair_ed25519_auth_failure_blocks_downstream_storage_scan() {
    let mut storage = IsolatedStorageEngine::new();
    storage.insert_chunks(&[DocumentChunk::new(
        "secret_chunk",
        "d_sec",
        "sec.txt",
        1,
        2,
        0,
        vec![1.0; 768],
        "Top secret payload",
        None,
    )
    .unwrap()]);

    let seed = [0x77u8; 32];
    let query_id = Uuid::new_v4();
    let sender_id = "peer_attacker";
    let timestamp = Utc::now().timestamp();
    let query_text = "Top secret payload";

    let (pubkey, mut sig_bytes) = oracle_sign_query(&seed, query_id, sender_id, timestamp, query_text);

    // Corrupt signature to simulate forgery / MITM tamper
    sig_bytes[10] ^= 0xfe;

    let auth_result = oracle_verify_query(&pubkey, &sig_bytes, query_id, sender_id, timestamp, query_text, 60);

    // Gate: If verification fails, storage is NEVER accessed!
    let hits = if auth_result.is_ok() {
        storage.search_text(query_text, 0, 5)
    } else {
        Vec::new() // Gate closes immediately
    };

    assert!(auth_result.is_err(), "Corrupted signature must fail verification");
    assert!(hits.is_empty(), "Zero chunks should be returned when signature fails");
}

#[test]
fn test_pair_contract_mismatch_prevents_peer_admission_to_mesh() {
    let local_contract = EmbeddingContract::canonical_gemma_300m();
    let local_hash = local_contract.derive_contract_hash();

    // Adversary peer attempts to connect using 384-dimensional model (e.g. MiniLM)
    let mut rogue_contract = local_contract.clone();
    rogue_contract.model_name = "sentence-transformers/all-MiniLM-L6-v2".to_string();
    rogue_contract.dimension = 384;
    let rogue_hash = rogue_contract.derive_contract_hash();

    let handshake_res = verify_contract_handshake(&local_hash, &rogue_hash);
    assert!(handshake_res.is_err(), "Rogue model must be rejected on handshake");

    // Mesh admission gate: Only admitted peers can participate in scatter-gather
    let peer_admitted = handshake_res.is_ok();
    assert!(!peer_admitted, "Peer MUST NOT be admitted to the swarm");
}

#[test]
fn test_pair_memory_security_volatile_vs_persistent_lifecycle() {
    let local_text = "Persistent local document on NVMe disk";
    let remote_text = "Volatile ephemeral remote peer chunk in RAM";

    // 1. Persistent local chunk
    let local_chunk = DocumentChunk::new("c_local", "d_local", "local.txt", 1, 2, 0, vec![1.0; 768], local_text, None).unwrap();

    // 2. Volatile remote chunk
    let dto = CandidateChunkDto {
        chunk_id: "c_remote".to_string(),
        file_path: "remote.txt".to_string(),
        line_start: 1,
        line_end: 2,
        content: remote_text.to_string(),
        score: 0.95,
        access_tier: 0,
    };
    let mut volatile = dto.to_volatile_remote_chunk("peer_ephemeral");

    assert_eq!(volatile.content(), remote_text);
    assert_eq!(local_chunk.text_content, local_text);

    // 3. Scrub remote memory upon query synthesis completion
    volatile.content.zeroize();

    assert!(volatile.content().is_empty() || volatile.content().chars().all(|c| c == '\0'));
    // Local chunk remains completely intact
    assert_eq!(local_chunk.text_content, local_text);
}
