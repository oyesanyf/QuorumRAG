use chrono::Utc;
use quorum_network::{
    start_network_node, InboundQueryHandler, NetworkConfig, NetworkEvent,
};
use quorum_types::{CandidateChunkDto, FederatedQueryRequest, FederatedQueryResponse};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

struct TestQueryHandler {
    responder_id: String,
}

#[async_trait::async_trait]
impl InboundQueryHandler for TestQueryHandler {
    async fn handle_query(&self, req: FederatedQueryRequest) -> FederatedQueryResponse {
        FederatedQueryResponse {
            query_id: req.query_id,
            responder_peer_id: self.responder_id.clone(),
            chunks: vec![CandidateChunkDto {
                chunk_id: "chunk_net_1".to_string(),
                file_path: "p2p_network.rs".to_string(),
                line_start: 1,
                line_end: 10,
                content: format!("Content in response to: {}", req.query_text),
                score: 0.95,
                access_tier: 0,
            }],
        }
    }
}

#[tokio::test]
async fn test_network_node_startup_and_local_binding() {
    let config = NetworkConfig::new_localhost();
    let (_jh, handle) = start_network_node(config, None).await.unwrap();

    let addrs = handle.listen_addresses().await.unwrap();
    assert!(!addrs.is_empty(), "Swarm must bind to at least one listen address");

    let peers = handle.connected_peers().await.unwrap();
    assert!(peers.is_empty(), "Freshly started node has 0 connected peers");

    let _ = handle.shutdown().await;
}

#[tokio::test]
async fn test_dual_node_point_to_point_cbor_query() {
    let config_b = NetworkConfig::new_localhost();
    let handler_b = Arc::new(TestQueryHandler {
        responder_id: "node_b_responder".to_string(),
    });
    let (_jh_b, handle_b) = start_network_node(config_b, Some(handler_b)).await.unwrap();

    let addrs_b = handle_b.listen_addresses().await.unwrap();
    assert!(!addrs_b.is_empty());

    let config_a = NetworkConfig::new_localhost();
    let (_jh_a, handle_a) = start_network_node(config_a, None).await.unwrap();

    // Node A dials Node B (choose TCP address)
    let tcp_addr = addrs_b
        .iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .cloned()
        .expect("Node B should have TCP address");

    handle_a.dial(tcp_addr).await.expect("Dial must succeed");

    // Allow connection and identify handshake to establish
    tokio::time::sleep(Duration::from_millis(250)).await;

    let req = FederatedQueryRequest {
        query_id: Uuid::new_v4(),
        sender_peer_id: handle_a.local_peer_id().to_string(),
        sender_pubkey: [0u8; 32],
        query_text: "Federated peer retrieval query".to_string(),
        embedding: vec![1.0; 768],
        top_k: 5,
        timestamp: Utc::now().timestamp(),
        signature: [0u8; 64],
    };

    let response = handle_a
        .send_query(handle_b.local_peer_id(), req)
        .await
        .expect("Query response must succeed");

    assert_eq!(response.responder_peer_id, "node_b_responder");
    assert_eq!(response.chunks.len(), 1);
    assert_eq!(response.chunks[0].chunk_id, "chunk_net_1");

    let _ = handle_a.shutdown().await;
    let _ = handle_b.shutdown().await;
}

#[tokio::test]
async fn test_contract_mismatch_disconnects_peer() {
    let config_b = NetworkConfig::new_localhost();
    let (_jh_b, handle_b) = start_network_node(config_b, None).await.unwrap();
    let addrs_b = handle_b.listen_addresses().await.unwrap();
    let tcp_addr = addrs_b
        .iter()
        .find(|a| a.to_string().contains("/tcp/"))
        .cloned()
        .unwrap();

    // Node A with mismatched contract hash
    let mut config_a = NetworkConfig::new_localhost();
    config_a.contract_hash_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string();

    let (_jh_a, handle_a) = start_network_node(config_a, None).await.unwrap();
    let mut events_a = handle_a.subscribe_events();

    handle_a.dial(tcp_addr).await.expect("Initial dial succeeds");

    // Wait for Identify handshake and rejection
    let mut rejected = false;
    for _ in 0..10 {
        tokio::select! {
            Ok(ev) = events_a.recv() => {
                if let NetworkEvent::PeerRejected { peer_id, reason } = ev {
                    if peer_id == handle_b.local_peer_id() {
                        assert!(reason.contains("Gemma contract"));
                        rejected = true;
                        break;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }

    assert!(rejected, "Peer with mismatched contract hash must be rejected");

    let _ = handle_a.shutdown().await;
    let _ = handle_b.shutdown().await;
}
