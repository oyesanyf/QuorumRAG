use chrono::Utc;
use quorum_coordinator::crypto::{sign_request, verify_request};
use quorum_coordinator::error::CoordinatorError;
use quorum_coordinator::fusion::RrfCombiner;
use quorum_coordinator::mesh::OsoosiMeshInboundHandler;
use quorum_coordinator::scatter_gather::StorageSearcher;
use quorum_network::{
    derive_peer_id_from_pubkey, is_allowed_dial_address, InboundQueryHandler, Multiaddr,
};
use quorum_types::{
    AccessTier, CandidateChunkDto, DocumentChunk, FederatedQueryRequest, ScoredChunk,
};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Mock tracking storage searcher for empirical testing
struct MockTrackingStorage {
    hybrid_search_count: AtomicUsize,
    sample_chunk: ScoredChunk,
}

impl MockTrackingStorage {
    fn new(sample_chunk: ScoredChunk) -> Self {
        Self {
            hybrid_search_count: AtomicUsize::new(0),
            sample_chunk,
        }
    }
}

#[async_trait::async_trait]
impl StorageSearcher for MockTrackingStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        self.hybrid_search_count.fetch_add(1, Ordering::SeqCst);
        vec![self.sample_chunk.clone()]
    }

    async fn search_vector(
        &self,
        _vector: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        vec![self.sample_chunk.clone()]
    }

    async fn search_text(
        &self,
        _query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        vec![self.sample_chunk.clone()]
    }
}

fn sample_chunk(id: &str, text: &str) -> ScoredChunk {
    let doc = DocumentChunk {
        chunk_id: id.to_string(),
        document_id: "doc1".to_string(),
        file_path: r"D:\harfile\QuorumRAG\docs\test.txt".to_string(),
        line_start: 1,
        line_end: 10,
        blake3_hash: DocumentChunk::compute_blake3_hash(text),
        access_tier: 0,
        vector: vec![0.1; 768],
        text_content: text.to_string(),
        metadata_json: "{}".to_string(),
    };
    ScoredChunk::new(doc, 0.95, "local", false)
}

fn create_keypair(seed_byte: u8) -> ([u8; 32], [u8; 32], String) {
    let seed = [seed_byte; 32];
    let secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed).unwrap();
    let ed_kp = quorum_network::libp2p::identity::ed25519::Keypair::from(secret);
    let pubkey_bytes = ed_kp.public().to_bytes();
    let pk = quorum_network::libp2p::identity::PublicKey::from(ed_kp.public());
    let peer_id = quorum_network::libp2p::PeerId::from_public_key(&pk).to_string();
    (seed, pubkey_bytes, peer_id)
}

// =========================================================================
// Test Group 1: Cryptographic Handshake & Identity Spoofing Rejections
// =========================================================================

#[tokio::test]
async fn test_adv_mismatched_pubkey_vs_peer_id_rejected() {
    let chunk = sample_chunk("c1", "classified local chunk data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));

    let (seed_a, pubkey_a, peer_id_a) = create_keypair(11);
    let (_seed_b, _pubkey_b, peer_id_b) = create_keypair(22);

    let handler = OsoosiMeshInboundHandler::new(storage.clone(), &peer_id_a);

    // Attack 1: Keypair A signs request, but claims peer ID B
    let mut spoofed_req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id_b.clone(), // Claiming peer B!
        sender_pubkey: pubkey_a,            // Actual pubkey A
        query_text: "adversarial spoof attack".to_string(),
        embedding: vec![0.02; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed_a, &mut spoofed_req, AccessTier::Tier0Public);

    let resp = handler.handle_query(spoofed_req).await;
    assert!(
        resp.chunks.is_empty(),
        "Spoofed sender_peer_id != derived pubkey MUST return 0 chunks"
    );
    assert_eq!(
        storage.hybrid_search_count.load(Ordering::SeqCst),
        0,
        "Storage MUST NOT be queried on spoofed identity"
    );

    // Verify low-level peer derivation returns distinct ID
    let derived = derive_peer_id_from_pubkey(&pubkey_a).unwrap();
    assert_ne!(derived.to_string(), peer_id_b);
}

#[tokio::test]
async fn test_adv_invalid_or_garbage_pubkey_rejected() {
    let chunk = sample_chunk("c1", "classified local chunk data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));
    let (_seed_a, _pubkey_a, peer_id_a) = create_keypair(33);

    let handler = OsoosiMeshInboundHandler::new(storage.clone(), &peer_id_a);

    // Attack 2: Non-canonical invalid public key (all 0xFF, invalid point on curve)
    let invalid_pubkeys: Vec<[u8; 32]> = vec![
        [0xff; 32],
        [0xee; 32],
        [0x00; 32],
    ];

    for bad_pubkey in invalid_pubkeys {
        let req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: peer_id_a.clone(),
            sender_pubkey: bad_pubkey,
            query_text: "garbage pubkey test".to_string(),
            embedding: vec![0.02; 768],
            top_k: 5,
            timestamp: Utc::now().timestamp(),
            signature: [0u8; 64],
        };

        let resp = handler.handle_query(req.clone()).await;
        assert!(
            resp.chunks.is_empty(),
            "Garbage pubkey must be rejected with 0 chunks"
        );

        // Crypto verify_request should return error
        let err = verify_request(&req, AccessTier::Tier0Public, 60);
        assert!(err.is_err(), "verify_request must fail on invalid pubkey");
    }
}

#[tokio::test]
async fn test_adv_forged_or_tampered_signature_rejected() {
    let chunk = sample_chunk("c1", "classified local chunk data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));
    let (seed_a, _pubkey_a, peer_id_a) = create_keypair(44);

    let handler = OsoosiMeshInboundHandler::new(storage.clone(), &peer_id_a);

    // 1. Bit flip in signature
    let mut req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id_a.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "authentic query text".to_string(),
        embedding: vec![0.02; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed_a, &mut req, AccessTier::Tier0Public);
    req.signature[0] ^= 0x01; // Tamper with signature

    let resp = handler.handle_query(req.clone()).await;
    assert!(resp.chunks.is_empty(), "Tampered signature must return 0 chunks");
    match verify_request(&req, AccessTier::Tier0Public, 60) {
        Err(CoordinatorError::InvalidSignature(_)) => {}
        other => panic!("Expected InvalidSignature error, got {:?}", other),
    }

    // 2. Tampered query_text after signing
    let mut req2 = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id_a.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "legitimate query".to_string(),
        embedding: vec![0.02; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed_a, &mut req2, AccessTier::Tier0Public);
    req2.query_text = "tampered query payload".to_string();

    let resp2 = handler.handle_query(req2.clone()).await;
    assert!(resp2.chunks.is_empty(), "Tampered query text must return 0 chunks");
    match verify_request(&req2, AccessTier::Tier0Public, 60) {
        Err(CoordinatorError::InvalidSignature(_)) => {}
        other => panic!("Expected InvalidSignature error, got {:?}", other),
    }

    // 3. Tampered embedding vector element after signing
    let mut req3 = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id_a.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "query with tampered vector".to_string(),
        embedding: vec![0.02; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed_a, &mut req3, AccessTier::Tier0Public);
    req3.embedding[42] = 0.999;

    let resp3 = handler.handle_query(req3.clone()).await;
    assert!(resp3.chunks.is_empty(), "Tampered embedding must return 0 chunks");
    match verify_request(&req3, AccessTier::Tier0Public, 60) {
        Err(CoordinatorError::InvalidSignature(_)) => {}
        other => panic!("Expected InvalidSignature error, got {:?}", other),
    }
}

// =========================================================================
// Test Group 2: Timestamp Anti-Replay & Drift Window Tests
// =========================================================================

#[tokio::test]
async fn test_adv_timestamp_drift_past_expired_rejected() {
    let chunk = sample_chunk("c1", "secret data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));
    let (seed, _pubkey, peer_id) = create_keypair(55);
    let handler = OsoosiMeshInboundHandler::new(storage, &peer_id);

    let now = Utc::now().timestamp();
    let expired_timestamps = vec![
        now - 61,       // 1 second past threshold
        now - 120,      // 2 minutes ago
        now - 3600,     // 1 hour ago
        now - 86400,    // 1 day ago
        0,              // 1970 Unix epoch replay
    ];

    for ts in expired_timestamps {
        let mut req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: peer_id.clone(),
            sender_pubkey: [0u8; 32],
            query_text: "expired timestamp query".to_string(),
            embedding: vec![0.05; 768],
            top_k: 5,
            timestamp: ts,
            signature: [0u8; 64],
        };
        sign_request(&seed, &mut req, AccessTier::Tier0Public);

        let resp = handler.handle_query(req.clone()).await;
        assert!(
            resp.chunks.is_empty(),
            "Expired timestamp ({}) must be rejected with 0 chunks",
            ts
        );

        match verify_request(&req, AccessTier::Tier0Public, 60) {
            Err(CoordinatorError::StaleTimestamp { drift_secs, limit, .. }) => {
                assert!(drift_secs > limit, "Drift must exceed limit");
            }
            other => panic!("Expected StaleTimestamp for timestamp {}, got {:?}", ts, other),
        }
    }
}

#[tokio::test]
async fn test_adv_timestamp_drift_future_rejected() {
    let chunk = sample_chunk("c1", "secret data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));
    let (seed, _pubkey, peer_id) = create_keypair(66);
    let handler = OsoosiMeshInboundHandler::new(storage, &peer_id);

    let now = Utc::now().timestamp();
    let future_timestamps = vec![
        now + 61,           // 1 second ahead of threshold
        now + 120,          // 2 minutes in future
        now + 3600,         // 1 hour in future
        now + 86400,        // 1 day in future
        now + 1_000_000_000,// far future
    ];

    for ts in future_timestamps {
        let mut req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: peer_id.clone(),
            sender_pubkey: [0u8; 32],
            query_text: "future timestamp query".to_string(),
            embedding: vec![0.05; 768],
            top_k: 5,
            timestamp: ts,
            signature: [0u8; 64],
        };
        sign_request(&seed, &mut req, AccessTier::Tier0Public);

        let resp = handler.handle_query(req.clone()).await;
        assert!(
            resp.chunks.is_empty(),
            "Future timestamp ({}) must be rejected with 0 chunks",
            ts
        );

        match verify_request(&req, AccessTier::Tier0Public, 60) {
            Err(CoordinatorError::StaleTimestamp { drift_secs, limit, .. }) => {
                assert!(drift_secs > limit, "Future drift must exceed limit");
            }
            other => panic!("Expected StaleTimestamp for future timestamp {}, got {:?}", ts, other),
        }
    }
}

#[tokio::test]
async fn test_adv_timestamp_boundary_acceptance_and_rejection() {
    let chunk = sample_chunk("c1", "secret data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));
    let (seed, _pubkey, peer_id) = create_keypair(77);
    let handler = OsoosiMeshInboundHandler::new(storage, &peer_id);

    let now = Utc::now().timestamp();

    // Within limit: now - 50s and now + 50s (limit is 60s)
    let valid_boundaries = vec![now - 50, now + 50];
    for ts in valid_boundaries {
        let mut req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: peer_id.clone(),
            sender_pubkey: [0u8; 32],
            query_text: "boundary within limit".to_string(),
            embedding: vec![0.05; 768],
            top_k: 5,
            timestamp: ts,
            signature: [0u8; 64],
        };
        sign_request(&seed, &mut req, AccessTier::Tier0Public);

        let resp = handler.handle_query(req.clone()).await;
        assert!(
            !resp.chunks.is_empty(),
            "Timestamp {} within 60s drift must be accepted",
            ts
        );
        assert!(
            verify_request(&req, AccessTier::Tier0Public, 60).is_ok(),
            "verify_request within 60s drift must succeed"
        );
    }

    // Beyond limit: now - 70s and now + 70s
    let invalid_boundaries = vec![now - 70, now + 70];
    for ts in invalid_boundaries {
        let mut req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: peer_id.clone(),
            sender_pubkey: [0u8; 32],
            query_text: "boundary beyond limit".to_string(),
            embedding: vec![0.05; 768],
            top_k: 5,
            timestamp: ts,
            signature: [0u8; 64],
        };
        sign_request(&seed, &mut req, AccessTier::Tier0Public);

        let resp = handler.handle_query(req.clone()).await;
        assert!(
            resp.chunks.is_empty(),
            "Timestamp {} beyond 60s drift must be rejected",
            ts
        );
        assert!(
            verify_request(&req, AccessTier::Tier0Public, 60).is_err(),
            "verify_request beyond 60s drift must fail"
        );
    }
}

// =========================================================================
// Test Group 3: Payload Validation & Sanitization Tests
// =========================================================================

#[tokio::test]
async fn test_adv_payload_nan_and_inf_embedding_rejected() {
    let chunk = sample_chunk("c1", "secret data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));
    let (seed, _pubkey, peer_id) = create_keypair(88);
    let handler = OsoosiMeshInboundHandler::new(storage, &peer_id);

    let test_cases = vec![
        ("NaN at index 0", {
            let mut v = vec![0.01; 768];
            v[0] = f32::NAN;
            v
        }),
        ("NaN at index 384", {
            let mut v = vec![0.01; 768];
            v[384] = f32::NAN;
            v
        }),
        ("NaN at index 767", {
            let mut v = vec![0.01; 768];
            v[767] = f32::NAN;
            v
        }),
        ("+Infinity", {
            let mut v = vec![0.01; 768];
            v[100] = f32::INFINITY;
            v
        }),
        ("-Infinity", {
            let mut v = vec![0.01; 768];
            v[500] = f32::NEG_INFINITY;
            v
        }),
    ];

    for (desc, emb) in test_cases {
        let mut req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: peer_id.clone(),
            sender_pubkey: [0u8; 32],
            query_text: format!("test {}", desc),
            embedding: emb,
            top_k: 5,
            timestamp: Utc::now().timestamp(),
            signature: [0u8; 64],
        };
        sign_request(&seed, &mut req, AccessTier::Tier0Public);

        let resp = handler.handle_query(req).await;
        assert!(
            resp.chunks.is_empty(),
            "Non-finite embedding ({}) MUST be rejected with 0 chunks",
            desc
        );
    }
}

#[tokio::test]
async fn test_adv_payload_invalid_embedding_dimensions_rejected() {
    let chunk = sample_chunk("c1", "secret data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));
    let (seed, _pubkey, peer_id) = create_keypair(99);
    let handler = OsoosiMeshInboundHandler::new(storage, &peer_id);

    let invalid_lengths = vec![0, 1, 128, 384, 767, 769, 1024, 2048, 4096];

    for len in invalid_lengths {
        let mut req = FederatedQueryRequest {
            query_id: Uuid::new_v4(),
            sender_peer_id: peer_id.clone(),
            sender_pubkey: [0u8; 32],
            query_text: format!("dimension len {}", len),
            embedding: vec![0.01; len],
            top_k: 5,
            timestamp: Utc::now().timestamp(),
            signature: [0u8; 64],
        };
        sign_request(&seed, &mut req, AccessTier::Tier0Public);

        let resp = handler.handle_query(req).await;
        assert!(
            resp.chunks.is_empty(),
            "Embedding with dimension {} != 768 MUST be rejected with 0 chunks",
            len
        );
    }
}

#[tokio::test]
async fn test_adv_payload_query_text_boundaries_and_top_k() {
    let chunk = sample_chunk("c1", "secret data");
    let storage = Arc::new(MockTrackingStorage::new(chunk));
    let (seed, _pubkey, peer_id) = create_keypair(101);
    let handler = OsoosiMeshInboundHandler::new(storage, &peer_id);

    // 1. Text length exactly 4096: Accepted
    let mut req_4096 = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "a".repeat(4096),
        embedding: vec![0.05; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut req_4096, AccessTier::Tier0Public);
    let resp_4096 = handler.handle_query(req_4096).await;
    assert!(
        !resp_4096.chunks.is_empty(),
        "Query text length 4096 must be accepted"
    );

    // 2. Text length 4097: Rejected
    let mut req_4097 = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "a".repeat(4097),
        embedding: vec![0.05; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut req_4097, AccessTier::Tier0Public);
    let resp_4097 = handler.handle_query(req_4097).await;
    assert!(
        resp_4097.chunks.is_empty(),
        "Query text length 4097 must be rejected"
    );

    // 3. Oversized text (64 KB): Rejected
    let mut req_64k = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "a".repeat(65536),
        embedding: vec![0.05; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut req_64k, AccessTier::Tier0Public);
    let resp_64k = handler.handle_query(req_64k).await;
    assert!(
        resp_64k.chunks.is_empty(),
        "Query text length 64KB must be rejected"
    );

    // 4. top_k == 0: Rejected
    let mut req_zero_top_k = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "zero top k".to_string(),
        embedding: vec![0.05; 768],
        top_k: 0,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&seed, &mut req_zero_top_k, AccessTier::Tier0Public);
    let resp_zero_top_k = handler.handle_query(req_zero_top_k).await;
    assert!(
        resp_zero_top_k.chunks.is_empty(),
        "top_k == 0 must be rejected"
    );
}

// =========================================================================
// Test Group 4: Dial Address Filtering Stress Tests (`transport.rs`)
// =========================================================================

#[test]
fn test_adv_dial_wan_public_ips_strictly_rejected() {
    let rejected_addresses = vec![
        // Mission required WAN IPs
        "/ip4/8.8.8.8/tcp/9000",
        "/ip4/1.1.1.1/tcp/9000",
        "/ip4/142.250.190.46/tcp/9000",
        "/ip6/2607:f8b0::/tcp/9000",

        // Other public WAN addresses
        "/ip4/208.67.222.222/tcp/9000",
        "/ip4/4.4.4.4/tcp/9000",
        "/ip4/104.21.5.199/tcp/9000",
        "/ip6/2001:4860:4860::8888/tcp/9000",
        "/ip6/2606:4700:4700::1111/tcp/9000",

        // Subnet boundary WAN checks
        "/ip4/9.255.255.255/tcp/9000",   // Just below 10.0.0.0/8
        "/ip4/11.0.0.0/tcp/9000",         // Just above 10.0.0.0/8
        "/ip4/172.15.255.255/tcp/9000",   // Just below 172.16.0.0/12
        "/ip4/172.32.0.0/tcp/9000",       // Just above 172.16.0.0/12
        "/ip4/192.167.255.255/tcp/9000",  // Just below 192.168.0.0/16
        "/ip4/192.169.0.0/tcp/9000",      // Just above 192.168.0.0/16
        "/ip4/126.255.255.255/tcp/9000",  // Just below 127.0.0.0/8
        "/ip4/128.0.0.0/tcp/9000",        // Just above 127.0.0.0/8
        "/ip4/169.253.255.255/tcp/9000",  // Just below 169.254.0.0/16
        "/ip4/169.255.0.0/tcp/9000",      // Just above 169.254.0.0/16
        "/ip4/100.64.0.1/tcp/9000",       // CGNAT (RFC 6598)

        // IPv4-mapped WAN IPv6
        "/ip6/::ffff:8.8.8.8/tcp/9000",
        "/ip6/::ffff:142.250.190.46/tcp/9000",

        // Public DNS hostnames
        "/dns4/google.com/tcp/4001",
        "/dns4/cloudflare.com/tcp/4001",
        "/dns6/ipv6.google.com/tcp/4001",
        "/dnsaddr/bootstrap.libp2p.io",
        "/dns4/evil.local.com/tcp/4001",
        "/dns4/fake.localhost.com/tcp/4001",
        "/dns4/badlocalhost/tcp/4001",
    ];

    for addr_str in rejected_addresses {
        let addr = Multiaddr::from_str(addr_str)
            .unwrap_or_else(|e| panic!("Failed to parse Multiaddr {}: {}", addr_str, e));
        assert!(
            !is_allowed_dial_address(&addr),
            "WAN or external address MUST be rejected: {}",
            addr_str
        );
    }
}

#[test]
fn test_adv_dial_private_and_loopback_accepted() {
    let accepted_addresses = vec![
        // Loopback IPv4
        "/ip4/127.0.0.1/tcp/9000",
        "/ip4/127.254.1.2/tcp/9000",

        // RFC1918 10.0.0.0/8
        "/ip4/10.0.0.1/tcp/9000",
        "/ip4/10.254.254.254/tcp/9000",

        // RFC1918 172.16.0.0/12
        "/ip4/172.16.0.1/tcp/9000",
        "/ip4/172.31.255.254/tcp/9000",

        // RFC1918 192.168.0.0/16
        "/ip4/192.168.0.1/tcp/9000",
        "/ip4/192.168.255.254/tcp/9000",

        // Link-local 169.254.0.0/16
        "/ip4/169.254.0.1/tcp/9000",
        "/ip4/169.254.255.254/tcp/9000",

        // Unspecified 0.0.0.0
        "/ip4/0.0.0.0/tcp/9000",

        // Loopback IPv6
        "/ip6/::1/tcp/9000",

        // Unspecified IPv6
        "/ip6/::/tcp/9000",

        // Unique Local Address (ULA) fc00::/7
        "/ip6/fc00::1/tcp/9000",
        "/ip6/fd12:3456:789a:bcde::1/tcp/9000",

        // Link-local IPv6 fe80::/10
        "/ip6/fe80::1/tcp/9000",
        "/ip6/fe80::abcd:ef01/tcp/9000",

        // IPv4-mapped private IPv6
        "/ip6/::ffff:127.0.0.1/tcp/9000",
        "/ip6/::ffff:192.168.1.1/tcp/9000",
        "/ip6/::ffff:10.0.0.5/tcp/9000",

        // Local DNS names
        "/dns4/localhost/tcp/9000",
        "/dns4/node1.local/tcp/9000",
        "/dns6/swarm.local/tcp/9000",
    ];

    for addr_str in accepted_addresses {
        let addr = Multiaddr::from_str(addr_str)
            .unwrap_or_else(|e| panic!("Failed to parse Multiaddr {}: {}", addr_str, e));
        assert!(
            is_allowed_dial_address(&addr),
            "Private or loopback address MUST be accepted: {}",
            addr_str
        );
    }
}

// =========================================================================
// Test Group 5: Byzantine Sybil Score Stuffing Resistance
// =========================================================================

#[test]
fn test_adv_byzantine_sybil_score_stuffing_100_chunks() {
    let local = vec![sample_chunk("local_legit", "authentic local document")];

    // Attacker floods 100 identical chunks under fabricated IDs
    let malicious_text = "sybil payload attempting score stuffing";
    let mut attacker_candidates = Vec::new();
    for i in 0..100 {
        attacker_candidates.push(CandidateChunkDto {
            chunk_id: format!("spoofed_chunk_{}", i),
            file_path: format!("remote/fake_{}.txt", i),
            line_start: 1,
            line_end: 10,
            access_tier: 0,
            score: 0.99,
            content: malicious_text.to_string(),
        });
    }

    let fused = RrfCombiner::fuse_rankings(local, vec![attacker_candidates], 60.0, 50);

    let appearances = fused
        .iter()
        .filter(|c| c.chunk.text_content == malicious_text)
        .count();
    assert_eq!(
        appearances, 1,
        "Sybil attack with 100 identical chunks must be deduplicated to exactly 1"
    );

    let sybil_result = fused
        .iter()
        .find(|c| c.chunk.text_content == malicious_text)
        .unwrap();
    let expected_single_score = 1.0 / (60.0 + 1.0);
    assert!(
        (sybil_result.score - expected_single_score).abs() < 1e-6,
        "Score must not be inflated: got {}, expected {}",
        sybil_result.score,
        expected_single_score
    );
}
