use libp2p::Multiaddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Failed to build libp2p Swarm: {0}")]
    SwarmBuildError(String),

    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Dial error to {addr}: {source}")]
    DialError {
        addr: Multiaddr,
        source: Box<libp2p::swarm::DialError>,
    },

    #[error("Query request failed or timed out: {0}")]
    RequestFailed(String),

    #[error("Gossipsub publish error: {0}")]
    GossipsubError(String),

    #[error("Contract hash mismatch with peer {peer_id}: local={local_hex}, remote={remote_hex}")]
    ContractMismatch {
        peer_id: String,
        local_hex: String,
        remote_hex: String,
    },

    #[error("Peer not found or not connected: {0}")]
    PeerNotConnected(String),

    #[error("Network controller channel closed")]
    ChannelClosed,

    #[error("Keypair or identity derivation error: {0}")]
    KeypairError(String),

    #[error("Query signature or validation error: {0}")]
    ValidationError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
