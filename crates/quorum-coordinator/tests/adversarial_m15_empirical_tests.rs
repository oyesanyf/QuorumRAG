use chrono::Utc;
use quorum_contract::{
    verify_contract_handshake, verify_contract_handshake_hex, ContractError, EmbeddingContract,
};
use quorum_coordinator::crypto::sign_request;
use quorum_coordinator::dlp_mesh::global_mesh_dlp_controller;
use quorum_coordinator::mesh::OsoosiMeshInboundHandler;
use quorum_coordinator::StorageSearcher;
use quorum_network::{
    derive_peer_id_from_pubkey, load_or_generate_node_seed, start_network_node,
    InboundQueryHandler, NetworkConfig, NetworkEvent,
};
use quorum_types::{AccessTier, DocumentChunk, FederatedQueryRequest, ScoredChunk};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

struct TestMockStorage;

#[async_trait::async_trait]
impl StorageSearcher for TestMockStorage {
    async fn search_hybrid(
        &self,
        _query_text: &str,
        _query_vec: &[f32],
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        let chunk = DocumentChunk::new(
            "mock_chunk_1",
            "doc_1",
            "C:\\SharedFolder\\document.pdf",
            1,
            10,
            0,
            vec![0.1; 768],
            "Secure content payload for authorized peer.",
            None,
        )
        .unwrap();
        vec![ScoredChunk::new(chunk, 0.99, "local", false)]
    }

    async fn search_text(
        &self,
        _query: &str,
        _max_tier: u8,
        _top_k: usize,
    ) -> Vec<ScoredChunk> {
        Vec::new()
    }
}

/// EMPIRICAL TEST 1: Identity persistence & deterministic derivation across 100 trials,
/// including corrupt disk seed self-healing and path auto-creation.
#[test]
fn test_empirical_identity_persistence_and_determinism() {
    let temp = tempfile::tempdir().expect("tempdir failed");
    let deep_dir = temp.path().join("nested").join("daemon").join("keys");

    // 1. Initial generation creates file and directory
    let seed1 = load_or_generate_node_seed(&deep_dir).expect("seed1 generation failed");
    assert_ne!(seed1, [0u8; 32], "Generated seed must not be all zeros");

    let seed_file = deep_dir.join("node_identity.seed");
    assert!(seed_file.is_file(), "node_identity.seed must exist on disk");

    // 2. 100 sequential re-reads must yield identical 32-byte seed and identical PeerId
    let secret1 = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(seed1).unwrap();
    let ed_kp1 = quorum_network::libp2p::identity::ed25519::Keypair::from(secret1);
    let expected_peer_id = quorum_network::libp2p::identity::Keypair::from(ed_kp1.clone()).public().to_peer_id();
    let expected_pubkey_bytes: [u8; 32] = ed_kp1.public().to_bytes();
    let derived_peer_id = derive_peer_id_from_pubkey(&expected_pubkey_bytes).unwrap();
    assert_eq!(expected_peer_id, derived_peer_id);

    for trial in 0..100 {
        let reloaded = load_or_generate_node_seed(&deep_dir).expect("reload failed");
        assert_eq!(seed1, reloaded, "Trial {trial}: reloaded seed mismatch");

        let secret_r = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(reloaded).unwrap();
        let ed_kp_r = quorum_network::libp2p::identity::ed25519::Keypair::from(secret_r);
        let pid_r = quorum_network::libp2p::identity::Keypair::from(ed_kp_r.clone()).public().to_peer_id();
        assert_eq!(expected_peer_id, pid_r, "Trial {trial}: derived peer_id mismatch");
    }

    // 3. Self-healing on corrupted seed file (e.g. truncated 16 bytes)
    std::fs::write(&seed_file, vec![0xAA; 16]).expect("corrupt write failed");
    let healed_seed = load_or_generate_node_seed(&deep_dir).expect("healed load failed");
    assert_ne!(healed_seed, [0u8; 32]);
    let disk_bytes = std::fs::read(&seed_file).expect("read healed failed");
    assert_eq!(disk_bytes.len(), 32);
    assert_eq!(disk_bytes.as_slice(), &healed_seed);
}

/// EMPIRICAL TEST 2: Adversarial spoofing gauntlet against OsoosiMeshInboundHandler.
/// Every variant of forged sender_peer_id, forged pubkey, and signature tampering
/// MUST be unconditionally rejected.
#[tokio::test]
async fn test_empirical_inbound_handler_spoofing_gauntlet() {
    // Configure DLP controller to allow mesh sharing for test
    {
        let ctrl = global_mesh_dlp_controller();
        let mut s = ctrl.settings.write().unwrap();
        s.mesh.p2p_enabled = true;
        s.mesh.require_explicit_folder_share = false;
        s.ui.default_peer_access_tier = 1;
    }

    let temp = tempfile::tempdir().unwrap();
    let authentic_seed = load_or_generate_node_seed(temp.path()).unwrap();
    let secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(authentic_seed).unwrap();
    let authentic_kp = quorum_network::libp2p::identity::ed25519::Keypair::from(secret);
    let authentic_peer_id = quorum_network::libp2p::identity::Keypair::from(authentic_kp.clone())
        .public()
        .to_peer_id()
        .to_string();

    let attacker_seed = [0xEE; 32];
    let attacker_secret = quorum_network::libp2p::identity::ed25519::SecretKey::try_from_bytes(attacker_seed).unwrap();
    let attacker_kp = quorum_network::libp2p::identity::ed25519::Keypair::from(attacker_secret);
    let attacker_peer_id = quorum_network::libp2p::identity::Keypair::from(attacker_kp.clone())
        .public()
        .to_peer_id()
        .to_string();

    let ctrl = quorum_coordinator::dlp_mesh::global_mesh_dlp_controller();
    {
        let mut s = ctrl.settings.write().unwrap();
        s.mesh.p2p_enabled = true;
        s.mesh.require_explicit_folder_share = false;
    }

    let storage = Arc::new(TestMockStorage);
    let inbound = OsoosiMeshInboundHandler::new(storage, "12D3KooWReceiverGuardian".to_string());

    // 1. Baseline: Authentic query signed by authentic node
    let mut req_valid = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: authentic_peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "legitimate query text".to_string(),
        embedding: vec![0.05; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&authentic_seed, &mut req_valid, AccessTier::Tier0Public);
    let resp_valid = inbound.handle_query(req_valid.clone()).await;
    assert_eq!(resp_valid.responder_peer_id, "12D3KooWReceiverGuardian");
    assert_eq!(resp_valid.chunks.len(), 1, "Legitimate query must return storage results");

    // 2. Attack Vector A: Claiming authentic_peer_id but signed by attacker's seed
    // (Attacker tries to impersonate authentic node using attacker's own keypair)
    let mut req_attack_a = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: authentic_peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "spoof attack A".to_string(),
        embedding: vec![0.05; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&attacker_seed, &mut req_attack_a, AccessTier::Tier0Public);
    let resp_a = inbound.handle_query(req_attack_a).await;
    assert!(resp_a.chunks.is_empty(), "Attack A (impersonation via attacker key) must be rejected");

    // 3. Attack Vector B: Claiming attacker's peer id, but signing with authentic seed
    let mut req_attack_b = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: attacker_peer_id.clone(),
        sender_pubkey: [0u8; 32],
        query_text: "spoof attack B".to_string(),
        embedding: vec![0.05; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };
    sign_request(&authentic_seed, &mut req_attack_b, AccessTier::Tier0Public);
    let resp_b = inbound.handle_query(req_attack_b).await;
    assert!(resp_b.chunks.is_empty(), "Attack B (mismatched claimed peer) must be rejected");

    // 4. Attack Vector C: Tampered sender_pubkey with forged random bytes
    let mut req_attack_c = req_valid.clone();
    req_attack_c.sender_pubkey = [0x13; 32];
    let resp_c = inbound.handle_query(req_attack_c).await;
    assert!(resp_c.chunks.is_empty(), "Attack C (tampered pubkey) must be rejected");

    // 5. Attack Vector D: Tampered signature (single byte flip)
    let mut req_attack_d = req_valid.clone();
    req_attack_d.signature[0] ^= 0x01;
    let resp_d = inbound.handle_query(req_attack_d).await;
    assert!(resp_d.chunks.is_empty(), "Attack D (flipped signature bit) must be rejected");

    // 6. Attack Vector E: Expired timestamp (>60s drift)
    let mut req_attack_e = req_valid.clone();
    req_attack_e.timestamp = Utc::now().timestamp() - 65;
    sign_request(&authentic_seed, &mut req_attack_e, AccessTier::Tier0Public);
    let resp_e = inbound.handle_query(req_attack_e).await;
    assert!(resp_e.chunks.is_empty(), "Attack E (stale timestamp >60s) must be rejected");

    // 7. Attack Vector F: Future timestamp (>60s drift)
    let mut req_attack_f = req_valid.clone();
    req_attack_f.timestamp = Utc::now().timestamp() + 75;
    sign_request(&authentic_seed, &mut req_attack_f, AccessTier::Tier0Public);
    let resp_f = inbound.handle_query(req_attack_f).await;
    assert!(resp_f.chunks.is_empty(), "Attack F (future timestamp >60s) must be rejected");

    // 8. Attack Vector G: Invalid embedding dimension (767 instead of 768)
    let mut req_attack_g = req_valid.clone();
    req_attack_g.embedding = vec![0.05; 767];
    sign_request(&authentic_seed, &mut req_attack_g, AccessTier::Tier0Public);
    let resp_g = inbound.handle_query(req_attack_g).await;
    assert!(resp_g.chunks.is_empty(), "Attack G (dimension 767) must be rejected");

    // 9. Attack Vector H: Non-finite embedding (contains NaN)
    let mut req_attack_h = req_valid.clone();
    req_attack_h.embedding[0] = f32::NAN;
    sign_request(&authentic_seed, &mut req_attack_h, AccessTier::Tier0Public);
    let resp_h = inbound.handle_query(req_attack_h).await;
    assert!(resp_h.chunks.is_empty(), "Attack H (NaN in embedding) must be rejected");
}

/// EMPIRICAL TEST 3: Contract differentiation between DeterministicOffline and GemmaCandle.
/// Demonstrates distinct BLAKE3 hashes, large Hamming distance, handshake failure,
/// and live wire disconnection over libp2p loopback swarm.
#[tokio::test]
async fn test_empirical_contract_differentiation_and_wire_handshake_rejection() {
    let contract_offline = EmbeddingContract::canonical_deterministic_offline();
    let contract_gemma = EmbeddingContract::canonical_gemma_300m();

    // 1. Verify engine_mode fields are explicitly set
    assert_eq!(contract_offline.engine_mode, "DeterministicOffline");
    assert_eq!(contract_gemma.engine_mode, "GemmaCandle");

    // 2. Derive 32-byte BLAKE3 hashes
    let hash_offline = contract_offline.derive_contract_hash();
    let hash_gemma = contract_gemma.derive_contract_hash();
    assert_ne!(hash_offline, hash_gemma, "Hashes must be mutually distinct");

    // 3. Cryptographic diffusion check: count differing bits (Hamming distance)
    let mut differing_bits = 0;
    for i in 0..32 {
        let diff = hash_offline[i] ^ hash_gemma[i];
        differing_bits += diff.count_ones();
    }
    // High diffusion expected across 256 bits (typically ~128 bits)
    assert!(
        differing_bits >= 90,
        "Expected substantial Hamming distance (>90 bits) between contract hashes, got {differing_bits}"
    );

    // 4. Verify handshake functions fail closed with ContractMismatch
    let hex_offline = contract_offline.derive_contract_hash_hex();
    let hex_gemma = contract_gemma.derive_contract_hash_hex();
    assert_ne!(hex_offline, hex_gemma);

    let verify_byte_res = verify_contract_handshake(&hash_offline, &hash_gemma);
    match verify_byte_res {
        Err(ContractError::ContractMismatch { local_hex, remote_hex }) => {
            assert_eq!(local_hex, hex_offline);
            assert_eq!(remote_hex, hex_gemma);
        }
        other => panic!("Expected ContractMismatch, got {:?}", other),
    }

    let verify_hex_res = verify_contract_handshake_hex(&hex_offline, &hex_gemma);
    assert!(matches!(verify_hex_res, Err(ContractError::ContractMismatch { .. })));

    // 5. Live wire libp2p test: DeterministicOffline node dials GemmaCandle node
    let mut config_gemma = NetworkConfig::new_localhost();
    config_gemma.contract_hash_hex = hex_gemma.clone();
    let (_jh_gemma, handle_gemma) = start_network_node(config_gemma, None).await.unwrap();

    let addrs_gemma = handle_gemma.listen_addresses().await.unwrap();
    let tcp_gemma = addrs_gemma
        .iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .cloned()
        .expect("Gemma node must have TCP listen address");

    let mut config_offline = NetworkConfig::new_localhost();
    config_offline.contract_hash_hex = hex_offline.clone();
    let (_jh_offline, handle_offline) = start_network_node(config_offline, None).await.unwrap();

    let mut events_offline = handle_offline.subscribe_events();

    // DeterministicOffline node dials GemmaCandle node
    handle_offline.dial(tcp_gemma.clone()).await.unwrap();

    // Verify rejection is received on the wire
    let mut offline_rejected = false;
    for _ in 0..20 {
        tokio::select! {
            Ok(ev) = events_offline.recv() => {
                if let NetworkEvent::PeerRejected { peer_id, reason } = ev {
                    if peer_id == handle_gemma.local_peer_id() {
                        assert!(reason.contains("contract hash mismatch"));
                        offline_rejected = true;
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    assert!(offline_rejected, "Offline node must be rejected by Gemma node on contract mismatch");

    // Verify connection was torn down
    tokio::time::sleep(Duration::from_millis(150)).await;
    let peers_gemma = handle_gemma.connected_peers().await.unwrap();
    assert!(
        !peers_gemma.contains(&handle_offline.local_peer_id()),
        "Gemma node must NOT maintain connection with mismatched Offline node"
    );

    // 6. Verify identical contract succeeds on the wire
    let mut config_gemma_peer = NetworkConfig::new_localhost();
    config_gemma_peer.contract_hash_hex = hex_gemma.clone();
    let (_jh_peer, handle_peer) = start_network_node(config_gemma_peer, None).await.unwrap();

    handle_peer.dial(tcp_gemma).await.unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;

    let peers_gemma_final = handle_gemma.connected_peers().await.unwrap();
    assert!(
        peers_gemma_final.contains(&handle_peer.local_peer_id()),
        "Compatible Gemma peer must be accepted and connected"
    );

    let _ = handle_gemma.shutdown().await;
    let _ = handle_offline.shutdown().await;
    let _ = handle_peer.shutdown().await;
}
