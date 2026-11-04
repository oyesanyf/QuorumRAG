pub mod actor;
pub mod behaviour;
pub mod config;
pub mod error;
pub mod handle;
pub mod handshake;
pub mod transport;

pub use actor::NetworkSwarmActor;
pub use config::NetworkConfig;
pub use error::NetworkError;
pub use handle::{NetworkCommand, NetworkEvent, NetworkSwarmHandle};
pub use handshake::{
    extract_contract_hash, make_agent_version, make_protocol_version, verify_peer_contract,
};
pub use transport::{is_allowed_dial_address, is_private_or_loopback_ip4, is_private_or_loopback_ip6};
pub use libp2p::{self, Multiaddr};

/// Derives a libp2p `PeerId` from 32-byte Ed25519 public key bytes.
pub fn derive_peer_id_from_pubkey(pubkey: &[u8; 32]) -> Result<libp2p::PeerId, String> {
    let ed_pk = libp2p::identity::ed25519::PublicKey::try_from_bytes(pubkey)
        .map_err(|e| format!("Invalid ed25519 public key: {e}"))?;
    let pk = libp2p::identity::PublicKey::from(ed_pk);
    Ok(libp2p::PeerId::from_public_key(&pk))
}

/// Loads a persistent 32-byte Ed25519 seed from `<data_dir>/node_identity.seed`, or creates it if not present.
pub fn load_or_generate_node_seed(data_dir: &std::path::Path) -> Result<[u8; 32], std::io::Error> {
    let seed_path = data_dir.join("node_identity.seed");
    if seed_path.is_file() {
        let bytes = std::fs::read(&seed_path)?;
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return Ok(seed);
        }
    }
    let ed_kp = libp2p::identity::ed25519::Keypair::generate();
    let mut seed = [0u8; 32];
    let secret = ed_kp.secret();
    let secret_bytes = secret.as_ref();
    if secret_bytes.len() >= 32 {
        seed.copy_from_slice(&secret_bytes[..32]);
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Generated keypair secret bytes invalid length",
        ));
    }
    if let Some(parent) = seed_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&seed_path, seed)?;
    Ok(seed)
}

use quorum_types::{FederatedQueryRequest, FederatedQueryResponse};
use std::collections::HashMap;
use std::sync::Arc;

#[async_trait::async_trait]
pub trait InboundQueryHandler: Send + Sync {
    async fn handle_query(&self, req: FederatedQueryRequest) -> FederatedQueryResponse;
}

#[derive(Debug, Default, Clone)]
pub struct DefaultInboundQueryHandler;

#[async_trait::async_trait]
impl InboundQueryHandler for DefaultInboundQueryHandler {
    async fn handle_query(&self, req: FederatedQueryRequest) -> FederatedQueryResponse {
        FederatedQueryResponse {
            query_id: req.query_id,
            responder_peer_id: String::new(),
            chunks: Vec::new(),
        }
    }
}

pub async fn start_network_node(
    config: NetworkConfig,
    inbound_handler: Option<Arc<dyn InboundQueryHandler>>,
) -> Result<(tokio::task::JoinHandle<()>, NetworkSwarmHandle), NetworkError> {
    let keypair = match config.ed25519_seed {
        Some(seed) => {
            let secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(seed)
                .map_err(|e| NetworkError::KeypairError(e.to_string()))?;
            let ed_kp = libp2p::identity::ed25519::Keypair::from(secret);
            libp2p::identity::Keypair::from(ed_kp)
        }
        None => libp2p::identity::Keypair::generate_ed25519(),
    };

    let local_peer_id = keypair.public().to_peer_id();
    let mut swarm = transport::build_swarm(&config, keypair)?;

    for addr in &config.tcp_listen_addrs {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| NetworkError::TransportError(e.to_string()))?;
    }
    for addr in &config.quic_listen_addrs {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| NetworkError::TransportError(e.to_string()))?;
    }

    for peer in &config.bootstrap_peers {
        if transport::is_allowed_dial_address(peer) {
            let _ = swarm.dial(peer.clone());
        } else {
            tracing::warn!("Rejecting bootstrap peer dial to non-airgapped multiaddr: {}", peer);
        }
    }

    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(128);
    let (evt_tx, _) = tokio::sync::broadcast::channel(256);
    let listen_addrs = Arc::new(tokio::sync::RwLock::new(Vec::new()));

    let handle = NetworkSwarmHandle {
        local_peer_id,
        command_tx: cmd_tx.clone(),
        event_tx: evt_tx.clone(),
        listen_addrs: Arc::clone(&listen_addrs),
    };

    let handler = inbound_handler.unwrap_or_else(|| Arc::new(DefaultInboundQueryHandler));

    let actor = NetworkSwarmActor {
        swarm,
        command_rx: cmd_rx,
        command_tx: cmd_tx,
        event_tx: evt_tx,
        listen_addrs,
        inbound_handler: handler,
        pending_requests: HashMap::new(),
        config,
    };

    let join_handle = tokio::spawn(async move {
        actor.run().await;
    });

    // Wait briefly (up to 200ms) for initial listen addresses to register
    for _ in 0..20 {
        if let Ok(addrs) = handle.listen_addresses().await {
            if !addrs.is_empty() {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    Ok((join_handle, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_node_seed_generation_and_reload() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path();

        let seed1 = load_or_generate_node_seed(path).expect("generate seed");
        assert_ne!(seed1, [0u8; 32]);

        let seed_file = path.join("node_identity.seed");
        assert!(seed_file.is_file());
        let on_disk = std::fs::read(&seed_file).expect("read file");
        assert_eq!(on_disk.len(), 32);
        assert_eq!(on_disk.as_slice(), &seed1);

        // Reload existing seed
        let seed2 = load_or_generate_node_seed(path).expect("reload seed");
        assert_eq!(seed1, seed2);

        // Verify keypair derivation and PeerId match derive_peer_id_from_pubkey
        let secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(seed1).expect("secret");
        let ed_kp = libp2p::identity::ed25519::Keypair::from(secret);
        let peer_id = libp2p::identity::Keypair::from(ed_kp.clone()).public().to_peer_id();

        let pubkey_bytes: [u8; 32] = ed_kp.public().to_bytes();
        let derived_peer_id = derive_peer_id_from_pubkey(&pubkey_bytes).expect("derive peer id");
        assert_eq!(peer_id, derived_peer_id);
    }
}
