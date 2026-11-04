use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use quorum_types::{FederatedQueryRequest, FederatedQueryResponse};

#[derive(NetworkBehaviour)]
pub struct QuorumNetworkBehaviour {
    pub mdns: Toggle<libp2p::mdns::tokio::Behaviour>,
    pub kademlia: libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>,
    pub gossipsub: libp2p::gossipsub::Behaviour,
    pub request_response:
        libp2p::request_response::cbor::Behaviour<FederatedQueryRequest, FederatedQueryResponse>,
    pub identify: libp2p::identify::Behaviour,
}
