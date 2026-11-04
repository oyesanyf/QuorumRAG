use libp2p::Multiaddr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Ed25519 seed for persistent identity (if None, random generated)
    pub ed25519_seed: Option<[u8; 32]>,
    /// TCP listen multiaddresses (e.g. `/ip4/0.0.0.0/tcp/0`)
    pub tcp_listen_addrs: Vec<Multiaddr>,
    /// QUIC listen multiaddresses (e.g. `/ip4/0.0.0.0/udp/0/quic-v1`)
    pub quic_listen_addrs: Vec<Multiaddr>,
    /// Explicit bootstrap peers to dial on startup
    pub bootstrap_peers: Vec<Multiaddr>,
    /// GossipSub query broadcast topic name
    pub gossip_topic: String,
    /// Enable mDNS LAN discovery
    pub enable_mdns: bool,
    /// Request-Response timeout (default: 400ms)
    pub request_timeout: Duration,
    /// Gemma embedding contract hash hex for handshake verification
    pub contract_hash_hex: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        let contract = quorum_contract::EmbeddingContract::canonical_gemma_300m();
        Self {
            ed25519_seed: None,
            tcp_listen_addrs: vec!["/ip4/0.0.0.0/tcp/0".parse().expect("valid multiaddr")],
            quic_listen_addrs: vec!["/ip4/0.0.0.0/udp/0/quic-v1".parse().expect("valid multiaddr")],
            bootstrap_peers: Vec::new(),
            gossip_topic: "quorum-rag-query-broadcast".to_string(),
            enable_mdns: true,
            request_timeout: Duration::from_millis(400),
            contract_hash_hex: contract.derive_contract_hash_hex(),
        }
    }
}

impl NetworkConfig {
    pub fn new_localhost() -> Self {
        Self {
            tcp_listen_addrs: vec!["/ip4/127.0.0.1/tcp/0".parse().expect("valid multiaddr")],
            quic_listen_addrs: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("valid multiaddr")],
            enable_mdns: false, // disable multicast flood in localhost unit tests
            ..Default::default()
        }
    }
}
