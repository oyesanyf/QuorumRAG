use chrono::Utc;
use quorum_contract::EmbeddingContract;
use quorum_network::{
    extract_contract_hash, start_network_node, verify_peer_contract, InboundQueryHandler,
    NetworkConfig, NetworkEvent,
};
use quorum_types::{CandidateChunkDto, FederatedQueryRequest, FederatedQueryResponse};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

struct EchoQueryHandler {
    node_name: String,
}

#[async_trait::async_trait]
impl InboundQueryHandler for EchoQueryHandler {
    async fn handle_query(&self, req: FederatedQueryRequest) -> FederatedQueryResponse {
        FederatedQueryResponse {
            query_id: req.query_id,
            responder_peer_id: self.node_name.clone(),
            chunks: vec![CandidateChunkDto {
                chunk_id: format!("chunk_echo_{}", req.query_id),
                file_path: "adversarial_echo.rs".to_string(),
                line_start: 1,
                line_end: 10,
                content: format!("[{}] Echo: {}", self.node_name, req.query_text),
                score: 0.99,
                access_tier: 0,
            }],
        }
    }
}

/// Adversarial Test 1: Handshake hash extraction and constant-time verification boundary stress.
#[test]
fn test_adversarial_contract_hash_edge_cases() {
    let canonical = EmbeddingContract::canonical_gemma_300m();
    let valid_hex = canonical.derive_contract_hash_hex();
    assert_eq!(valid_hex.len(), 64);

    // Valid protocol and agent strings
    let valid_proto = format!("/quorum-rag/1.0.0/contract-{}", valid_hex);
    let valid_agent = format!("quorumrag/0.1.0/{}", valid_hex);
    assert_eq!(extract_contract_hash(&valid_proto), Some(valid_hex.clone()));
    assert_eq!(extract_contract_hash(&valid_agent), Some(valid_hex.clone()));

    // Edge Case: Empty string
    assert_eq!(extract_contract_hash(""), None);

    // Edge Case: Prefix only
    assert_eq!(extract_contract_hash("/quorum-rag/1.0.0/contract-"), None);

    // Edge Case: Truncated 63 chars (off by one)
    let truncated = &valid_hex[..63];
    assert_eq!(
        extract_contract_hash(&format!("/quorum-rag/1.0.0/contract-{}", truncated)),
        None
    );

    // Edge Case: Invalid non-hex character injected
    let mut invalid_hex = valid_hex.clone();
    invalid_hex.replace_range(10..11, "z");
    assert_eq!(
        extract_contract_hash(&format!("/quorum-rag/1.0.0/contract-{}", invalid_hex)),
        None
    );

    // Edge Case: Exact 64 hex characters but altered hash (tampered last byte)
    let mut altered_hex = valid_hex.clone();
    let last_char = altered_hex.pop().unwrap();
    let new_char = if last_char == '0' { '1' } else { '0' };
    altered_hex.push(new_char);

    assert_eq!(
        extract_contract_hash(&format!("/quorum-rag/1.0.0/contract-{}", altered_hex)),
        Some(altered_hex.clone())
    );

    // Verify constant-time check fails closed on altered hash
    let verify_res = verify_peer_contract("peer_rogue", &valid_hex, &altered_hex);
    assert!(verify_res.is_err(), "Altered contract hash MUST fail verification");
}

/// Adversarial Test 2: Stress-test concurrent point-to-point queries over loopback Swarm.
#[tokio::test]
async fn test_adversarial_concurrent_point_to_point_queries() {
    let config_b = NetworkConfig::new_localhost();
    let handler_b = Arc::new(EchoQueryHandler {
        node_name: "responder_node_b".to_string(),
    });
    let (_jh_b, handle_b) = start_network_node(config_b, Some(handler_b)).await.unwrap();

    let addrs_b = handle_b.listen_addresses().await.unwrap();
    let tcp_addr = addrs_b
        .iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .cloned()
        .expect("Node B must have TCP address");

    let config_a = NetworkConfig::new_localhost();
    let (_jh_a, handle_a) = start_network_node(config_a, None).await.unwrap();

    handle_a.dial(tcp_addr).await.expect("Dial must succeed");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Dispatch 20 concurrent queries from Node A to Node B
    let mut query_handles = Vec::new();
    for i in 0..20 {
        let handle = handle_a.clone();
        let target_peer = handle_b.local_peer_id();
        let q_id = Uuid::new_v4();
        let q_text = format!("Concurrent query #{}", i);

        query_handles.push(tokio::spawn(async move {
            let req = FederatedQueryRequest {
                query_id: q_id,
                sender_peer_id: handle.local_peer_id().to_string(),
                sender_pubkey: [0u8; 32],
                query_text: q_text.clone(),
                embedding: vec![0.5; 768],
                top_k: 5,
                timestamp: Utc::now().timestamp(),
                signature: [0u8; 64],
            };
            let resp = handle.send_query(target_peer, req).await;
            (q_id, q_text, resp)
        }));
    }

    for jh in query_handles {
        let (expected_qid, expected_text, resp_res) = jh.await.unwrap();
        let resp = resp_res.expect("All concurrent queries must resolve successfully");
        assert_eq!(resp.query_id, expected_qid, "Query ID must match exactly");
        assert_eq!(resp.responder_peer_id, "responder_node_b");
        assert_eq!(resp.chunks.len(), 1);
        assert!(resp.chunks[0].content.contains(&expected_text));
    }

    let _ = handle_a.shutdown().await;
    let _ = handle_b.shutdown().await;
}

/// Adversarial Test 3: Bidirectional simultaneous queries between two active Swarm nodes.
#[tokio::test]
async fn test_adversarial_bidirectional_simultaneous_queries() {
    let config_a = NetworkConfig::new_localhost();
    let handler_a = Arc::new(EchoQueryHandler {
        node_name: "node_alpha".to_string(),
    });
    let (_jh_a, handle_a) = start_network_node(config_a, Some(handler_a)).await.unwrap();

    let config_b = NetworkConfig::new_localhost();
    let handler_b = Arc::new(EchoQueryHandler {
        node_name: "node_beta".to_string(),
    });
    let (_jh_b, handle_b) = start_network_node(config_b, Some(handler_b)).await.unwrap();

    let addrs_b = handle_b.listen_addresses().await.unwrap();
    let tcp_addr = addrs_b
        .iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .cloned()
        .unwrap();

    handle_a.dial(tcp_addr).await.expect("A dials B");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Concurrently: A queries B (10 times) while B queries A (10 times)
    let mut tasks = Vec::new();

    // A -> B
    for i in 0..10 {
        let ha = handle_a.clone();
        let pb = handle_b.local_peer_id();
        tasks.push(tokio::spawn(async move {
            let q_id = Uuid::new_v4();
            let req = FederatedQueryRequest {
                query_id: q_id,
                sender_peer_id: ha.local_peer_id().to_string(),
                sender_pubkey: [0u8; 32],
                query_text: format!("A_to_B_{}", i),
                embedding: vec![0.1; 768],
                top_k: 3,
                timestamp: Utc::now().timestamp(),
                signature: [0u8; 64],
            };
            let resp = ha.send_query(pb, req).await.unwrap();
            assert_eq!(resp.responder_peer_id, "node_beta");
            assert_eq!(resp.query_id, q_id);
        }));
    }

    // B -> A
    for i in 0..10 {
        let hb = handle_b.clone();
        let pa = handle_a.local_peer_id();
        tasks.push(tokio::spawn(async move {
            let q_id = Uuid::new_v4();
            let req = FederatedQueryRequest {
                query_id: q_id,
                sender_peer_id: hb.local_peer_id().to_string(),
                sender_pubkey: [0u8; 32],
                query_text: format!("B_to_A_{}", i),
                embedding: vec![0.2; 768],
                top_k: 3,
                timestamp: Utc::now().timestamp(),
                signature: [0u8; 64],
            };
            let resp = hb.send_query(pa, req).await.unwrap();
            assert_eq!(resp.responder_peer_id, "node_alpha");
            assert_eq!(resp.query_id, q_id);
        }));
    }

    for t in tasks {
        t.await.unwrap();
    }

    let _ = handle_a.shutdown().await;
    let _ = handle_b.shutdown().await;
}

/// Adversarial Test 4: Dynamic port binding across multiple concurrent nodes.
#[tokio::test]
async fn test_adversarial_dynamic_port_binding_no_collision() {
    let mut nodes = Vec::new();
    let mut all_ports = HashSet::new();

    // Start 3 separate nodes simultaneously with port 0
    for _ in 0..3 {
        let config = NetworkConfig::new_localhost();
        let (_jh, handle) = start_network_node(config, None).await.unwrap();
        let addrs = handle.listen_addresses().await.unwrap();

        assert!(!addrs.is_empty(), "Each node must have bound listen addresses");

        for addr in &addrs {
            let s = addr.to_string();
            if let Some(pos) = s.find("/tcp/") {
                let port_str = &s[pos + 5..];
                if let Ok(p) = port_str.parse::<u16>() {
                    assert!(p > 0, "Bound TCP port must be non-zero");
                    assert!(all_ports.insert(("tcp", p)), "TCP port collision detected: {}", p);
                }
            }
            if let Some(pos) = s.find("/udp/") {
                let rest = &s[pos + 5..];
                let port_part = rest.split('/').next().unwrap();
                if let Ok(p) = port_part.parse::<u16>() {
                    assert!(p > 0, "Bound UDP port must be non-zero");
                    assert!(all_ports.insert(("udp", p)), "UDP port collision detected: {}", p);
                }
            }
        }
        nodes.push(handle);
    }

    for h in nodes {
        let _ = h.shutdown().await;
    }
}

/// Adversarial Test 5: Contract mismatch prevents connection retention and enables valid peer.
#[tokio::test]
async fn test_adversarial_contract_mismatch_isolation() {
    // Node A (canonical contract)
    let config_a = NetworkConfig::new_localhost();
    let (_jh_a, handle_a) = start_network_node(config_a, None).await.unwrap();
    let addrs_a = handle_a.listen_addresses().await.unwrap();
    let tcp_addr_a = addrs_a
        .iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .cloned()
        .unwrap();

    // Node B (Rogue node with divergent contract hash)
    let mut config_b = NetworkConfig::new_localhost();
    config_b.contract_hash_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    let (_jh_b, handle_b) = start_network_node(config_b, None).await.unwrap();
    let mut events_b = handle_b.subscribe_events();

    handle_b.dial(tcp_addr_a.clone()).await.unwrap();

    // Node B must observe rejection
    let mut rejected = false;
    for _ in 0..15 {
        tokio::select! {
            Ok(ev) = events_b.recv() => {
                if let NetworkEvent::PeerRejected { peer_id, .. } = ev {
                    if peer_id == handle_a.local_peer_id() {
                        rejected = true;
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    assert!(rejected, "Rogue Node B must be rejected by Node A");

    // Allow disconnect to propagate
    tokio::time::sleep(Duration::from_millis(150)).await;
    let peers_a = handle_a.connected_peers().await.unwrap();
    assert!(
        !peers_a.contains(&handle_b.local_peer_id()),
        "Node A must not maintain connection with rejected Node B"
    );

    // Node C (Legitimate node with matching canonical contract)
    let config_c = NetworkConfig::new_localhost();
    let (_jh_c, handle_c) = start_network_node(config_c, None).await.unwrap();
    handle_c.dial(tcp_addr_a).await.unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;
    let peers_a_after = handle_a.connected_peers().await.unwrap();
    assert!(
        peers_a_after.contains(&handle_c.local_peer_id()),
        "Legitimate Node C must be retained as connected peer"
    );

    let _ = handle_a.shutdown().await;
    let _ = handle_b.shutdown().await;
    let _ = handle_c.shutdown().await;
}
