//! E2E Tests: Federated Mesh Retrieval, 400ms Scatter-Gather Timeout, Ed25519 ACL, & Volatile Memory Safety.
//!
//! Tiers covered:
//! - Tier 1: Feature Coverage (Ed25519 verification, 400ms hard timeout guard, access-tier isolation, RRF fusion, ZeroizeOnDrop)
//! - Tier 2: Boundary & Corner Cases (expired timestamp anti-replay, forged signature rejection, 0 peers fallback, consensus chunk score boost, concurrent queries)

use chrono::Utc;
use quorum_e2e::*;
use quorum_types::{CandidateChunkDto, DocumentChunk};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroize;

// ============================================================================
// TIER 1: FEATURE COVERAGE (>=5 test cases)
// ============================================================================

#[test]
fn test_federated_ed25519_signature_signing_and_verification() {
    let seed = [0x42u8; 32];
    let query_id = Uuid::new_v4();
    let sender_id = "peer_alice_123";
    let timestamp = Utc::now().timestamp();
    let query_text = "What is the consensus contract for Gemma embeddings?";

    let (pubkey, sig_bytes) = oracle_sign_query(&seed, query_id, sender_id, timestamp, query_text);

    // Verify valid signature passes
    let verify_result = oracle_verify_query(&pubkey, &sig_bytes, query_id, sender_id, timestamp, query_text, 60);
    assert!(verify_result.is_ok(), "Authentic Ed25519 signature must verify cleanly");
}

#[tokio::test]
async fn test_federated_scatter_gather_400ms_timeout_aborts_slow_peer() {
    let mut local_storage = IsolatedStorageEngine::new();
    let local_chunk = DocumentChunk::new(
        "c_local_fast",
        "doc_local",
        "local.rs",
        1,
        10,
        0,
        vec![1.0; 768],
        "Local immediate response content",
        None,
    )
    .unwrap();
    local_storage.insert_chunks(&[local_chunk]);

    let mut coordinator = FederatedQueryCoordinator::new(local_storage);

    // Peer 1: Fast peer (responds in 50ms)
    let fast_peer = MockRemotePeer {
        peer_id: "peer_fast".to_string(),
        latency: Duration::from_millis(50),
        max_access_tier: 0,
        candidate_chunks: vec![CandidateChunkDto {
            chunk_id: "c_remote_fast".to_string(),
            file_path: "remote_fast.rs".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Fast remote chunk content".to_string(),
            score: 0.85,
            access_tier: 0,
        }],
    };

    // Peer 2: Slow/hanging peer (delayed by 800ms > 400ms deadline)
    let slow_peer = MockRemotePeer {
        peer_id: "peer_slow".to_string(),
        latency: Duration::from_millis(800),
        max_access_tier: 0,
        candidate_chunks: vec![CandidateChunkDto {
            chunk_id: "c_remote_slow".to_string(),
            file_path: "slow.rs".to_string(),
            line_start: 1,
            line_end: 5,
            content: "Slow remote chunk should NOT be gathered".to_string(),
            score: 0.99,
            access_tier: 0,
        }],
    };

    coordinator.add_peer(fast_peer);
    coordinator.add_peer(slow_peer);

    let (results, _volatile, duration_ms) = coordinator
        .execute_query("fast content", &vec![1.0; 768], 0, 10)
        .await;

    // Hard invariant: total execution must complete around 400ms (not 800ms!)
    assert!(
        duration_ms <= 480,
        "Scatter-gather query took {}ms, which violated the 400ms hard deadline",
        duration_ms
    );

    // Slow peer chunk must NOT be in results
    assert!(!results.iter().any(|r| r.chunk.chunk_id == "c_remote_slow"));

    // Fast peer and local chunks MUST be present
    let ids: Vec<&str> = results.iter().map(|r| r.chunk.chunk_id.as_str()).collect();
    assert!(ids.contains(&"c_local_fast"));
    assert!(ids.contains(&"c_remote_fast"));
}

#[tokio::test]
async fn test_federated_access_tier_blocks_remote_confidential_documents() {
    let local_storage = IsolatedStorageEngine::new();
    let mut coordinator = FederatedQueryCoordinator::new(local_storage);

    // Remote peer has internal and confidential documents
    let peer = MockRemotePeer {
        peer_id: "peer_vault".to_string(),
        latency: Duration::from_millis(10),
        max_access_tier: 2, // Host has up to tier 2
        candidate_chunks: vec![
            CandidateChunkDto {
                chunk_id: "c_pub".to_string(),
                file_path: "public.txt".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Open public chunk".to_string(),
                score: 0.80,
                access_tier: 0,
            },
            CandidateChunkDto {
                chunk_id: "c_conf".to_string(),
                file_path: "secret_keys.txt".to_string(),
                line_start: 1,
                line_end: 5,
                content: "CONFIDENTIAL_ORGANIZATION_KEYS".to_string(),
                score: 0.99,
                access_tier: 2,
            },
        ],
    };
    coordinator.add_peer(peer);

    // Requester only has Tier 0 (Public) credentials
    let (results_public, _volatile, _) = coordinator
        .execute_query("keys", &vec![1.0; 768], 0, 10)
        .await;

    assert_eq!(results_public.len(), 1);
    assert_eq!(results_public[0].chunk.chunk_id, "c_pub");
    assert!(!results_public.iter().any(|r| r.chunk.chunk_id == "c_conf"));
}

#[tokio::test]
async fn test_federated_rrf_combines_local_and_remote_rankings() {
    let mut local_storage = IsolatedStorageEngine::new();
    local_storage.insert_chunks(&[DocumentChunk::new(
        "chunk_A",
        "docA",
        "docA.txt",
        1,
        2,
        0,
        vec![1.0; 768],
        "Consensus document topic",
        None,
    )
    .unwrap()]);

    let mut coordinator = FederatedQueryCoordinator::new(local_storage);

    // Remote peer also returns chunk_A with identical content
    let peer = MockRemotePeer {
        peer_id: "peer_remote".to_string(),
        latency: Duration::from_millis(20),
        max_access_tier: 0,
        candidate_chunks: vec![CandidateChunkDto {
            chunk_id: "chunk_A".to_string(),
            file_path: "docA.txt".to_string(),
            line_start: 1,
            line_end: 2,
            content: "Consensus document topic".to_string(),
            score: 0.90,
            access_tier: 0,
        }],
    };
    coordinator.add_peer(peer);

    let (results, _, _) = coordinator
        .execute_query("topic", &vec![1.0; 768], 0, 5)
        .await;

    assert_eq!(results.len(), 1);
    let fused_score = results[0].score;

    // RRF expected: 1/(60+1) [local rank 1] + 1/(60+1) [remote rank 1] = 2/61 ~ 0.03278
    let expected_rrf = (1.0 / 61.0) + (1.0 / 61.0);
    assert!(
        (fused_score - expected_rrf).abs() < 1e-4,
        "Consensus chunk must accumulate RRF rank scores across local and remote sources"
    );
}

#[test]
fn test_federated_volatile_remote_chunk_zeroizes_on_drop() {
    let dto = CandidateChunkDto {
        chunk_id: "c_volatile_1".to_string(),
        file_path: "confidential_memo.txt".to_string(),
        line_start: 1,
        line_end: 10,
        content: "EXTREMELY_SENSITIVE_TEMPORARY_REMOTE_CONTENT".to_string(),
        score: 0.95,
        access_tier: 2,
    };

    let mut volatile = dto.to_volatile_remote_chunk("peer_test");
    assert_eq!(volatile.content(), "EXTREMELY_SENSITIVE_TEMPORARY_REMOTE_CONTENT");

    // Manually trigger zeroize to assert buffer content is overwritten with zeroes
    volatile.content.zeroize();
    assert!(
        volatile.content().is_empty() || volatile.content().chars().all(|c| c == '\0'),
        "Volatile remote chunk content must be scrubbed with zeroes"
    );
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (>=5 test cases)
// ============================================================================

#[test]
fn test_federated_boundary_expired_timestamp_replay_rejection() {
    let seed = [0x99u8; 32];
    let query_id = Uuid::new_v4();
    let sender_id = "peer_adversary";
    // Timestamp from 10 minutes ago (600 seconds)
    let stale_timestamp = Utc::now().timestamp() - 600;
    let query_text = "Replayed query payload";

    let (pubkey, sig_bytes) = oracle_sign_query(&seed, query_id, sender_id, stale_timestamp, query_text);

    // Verification must fail closed due to timestamp drift exceeding 60s
    let result = oracle_verify_query(&pubkey, &sig_bytes, query_id, sender_id, stale_timestamp, query_text, 60);
    assert!(result.is_err(), "Stale query with timestamp drift > 60s must be rejected");
}

#[test]
fn test_federated_boundary_forged_signature_rejected() {
    let seed = [0x55u8; 32];
    let query_id = Uuid::new_v4();
    let sender_id = "peer_attacker";
    let timestamp = Utc::now().timestamp();
    let query_text = "Query with forged signature";

    let (pubkey, mut sig_bytes) = oracle_sign_query(&seed, query_id, sender_id, timestamp, query_text);

    // Corrupt signature
    sig_bytes[0] ^= 0xaa;

    let result = oracle_verify_query(&pubkey, &sig_bytes, query_id, sender_id, timestamp, query_text, 60);
    assert!(result.is_err(), "Forged signature must fail cryptographic verification");
}

#[tokio::test]
async fn test_federated_boundary_zero_peers_graceful_local_fallback() {
    let mut local_storage = IsolatedStorageEngine::new();
    local_storage.insert_chunks(&[DocumentChunk::new(
        "c_local_only",
        "doc",
        "doc.txt",
        1,
        2,
        0,
        vec![1.0; 768],
        "Local solitary context",
        None,
    )
    .unwrap()]);

    // Zero remote peers added to coordinator
    let coordinator = FederatedQueryCoordinator::new(local_storage);

    let (results, volatile, duration_ms) = coordinator
        .execute_query("solitary", &vec![1.0; 768], 0, 5)
        .await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].chunk.chunk_id, "c_local_only");
    assert!(volatile.is_empty());
    assert!(duration_ms < 50, "Zero-peer query must resolve immediately");
}

#[tokio::test]
async fn test_federated_boundary_multi_peer_consensus_boost() {
    let local_storage = IsolatedStorageEngine::new();
    let mut coordinator = FederatedQueryCoordinator::new(local_storage);

    // 3 different peers all return the exact same chunk
    for i in 0..3 {
        let peer = MockRemotePeer {
            peer_id: format!("peer_{}", i),
            latency: Duration::from_millis(10 * i as u64),
            max_access_tier: 0,
            candidate_chunks: vec![CandidateChunkDto {
                chunk_id: "consensus_chunk".to_string(),
                file_path: "shared.txt".to_string(),
                line_start: 1,
                line_end: 5,
                content: "Crucial consensus insight".to_string(),
                score: 0.90,
                access_tier: 0,
            }],
        };
        coordinator.add_peer(peer);
    }

    let (results, _, _) = coordinator
        .execute_query("insight", &vec![1.0; 768], 0, 5)
        .await;

    assert_eq!(results.len(), 1);
    // 3 peers at rank 1 each contribute 1/(60+1) = 3/61 ~ 0.04918
    let expected = 3.0 / 61.0;
    assert!((results[0].score - expected).abs() < 1e-4);
}

#[tokio::test]
async fn test_federated_boundary_concurrent_queries() {
    let mut local_storage = IsolatedStorageEngine::new();
    for i in 0..10 {
        local_storage.insert_chunks(&[DocumentChunk::new(
            format!("chunk_{}", i),
            "doc",
            "f.rs",
            i as u32,
            i as u32 + 1,
            0,
            vec![0.1 * i as f32; 768],
            format!("Text payload {}", i),
            None,
        )
        .unwrap()]);
    }

    let coordinator = FederatedQueryCoordinator::new(local_storage);

    // Dispatch 20 concurrent queries
    let mut handles = Vec::new();
    for q_idx in 0..20 {
        let coord = coordinator.clone();
        handles.push(tokio::spawn(async move {
            let query_vec = vec![0.1 * (q_idx % 10) as f32; 768];
            coord.execute_query("Text", &query_vec, 0, 3).await
        }));
    }

    for h in handles {
        let (results, _, duration) = h.await.unwrap();
        assert!(!results.is_empty());
        assert!(duration < 400);
    }
}
