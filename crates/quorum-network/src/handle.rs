use crate::error::NetworkError;
use libp2p::{Multiaddr, PeerId};
use quorum_types::{FederatedQueryRequest, FederatedQueryResponse};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    PeerDiscovered { peer_id: PeerId, address: Multiaddr },
    PeerExpired { peer_id: PeerId },
    PeerConnected { peer_id: PeerId },
    PeerDisconnected { peer_id: PeerId },
    PeerHandshakeVerified { peer_id: PeerId },
    PeerRejected { peer_id: PeerId, reason: String },
    GossipQueryReceived { request: FederatedQueryRequest },
}

pub enum NetworkCommand {
    Dial {
        addr: Multiaddr,
        reply: oneshot::Sender<Result<(), NetworkError>>,
    },
    SendQuery {
        peer_id: PeerId,
        request: FederatedQueryRequest,
        reply: oneshot::Sender<Result<FederatedQueryResponse, NetworkError>>,
    },
    BroadcastQuery {
        request: FederatedQueryRequest,
        reply: oneshot::Sender<Result<(), NetworkError>>,
    },
    GetConnectedPeers {
        reply: oneshot::Sender<Vec<PeerId>>,
    },
    GetListenAddresses {
        reply: oneshot::Sender<Vec<Multiaddr>>,
    },
    SendInboundReply {
        channel: libp2p::request_response::ResponseChannel<FederatedQueryResponse>,
        response: FederatedQueryResponse,
    },
    Shutdown,
}

#[derive(Clone)]
pub struct NetworkSwarmHandle {
    pub(crate) local_peer_id: PeerId,
    pub(crate) command_tx: mpsc::Sender<NetworkCommand>,
    pub(crate) event_tx: broadcast::Sender<NetworkEvent>,
    pub(crate) listen_addrs: Arc<RwLock<Vec<Multiaddr>>>,
}

impl NetworkSwarmHandle {
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    pub async fn dial(&self, addr: Multiaddr) -> Result<(), NetworkError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NetworkCommand::Dial { addr, reply: tx })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    pub async fn send_query(
        &self,
        peer_id: PeerId,
        request: FederatedQueryRequest,
    ) -> Result<FederatedQueryResponse, NetworkError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NetworkCommand::SendQuery {
                peer_id,
                request,
                reply: tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    pub async fn broadcast_query(
        &self,
        request: FederatedQueryRequest,
    ) -> Result<(), NetworkError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NetworkCommand::BroadcastQuery {
                request,
                reply: tx,
            })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkError::ChannelClosed)?
    }

    pub async fn connected_peers(&self) -> Result<Vec<PeerId>, NetworkError> {
        let (tx, rx) = oneshot::channel();
        self.command_tx
            .send(NetworkCommand::GetConnectedPeers { reply: tx })
            .await
            .map_err(|_| NetworkError::ChannelClosed)?;
        rx.await.map_err(|_| NetworkError::ChannelClosed)
    }

    pub async fn listen_addresses(&self) -> Result<Vec<Multiaddr>, NetworkError> {
        Ok(self.listen_addrs.read().await.clone())
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<NetworkEvent> {
        self.event_tx.subscribe()
    }

    pub async fn shutdown(&self) -> Result<(), NetworkError> {
        self.command_tx
            .send(NetworkCommand::Shutdown)
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }
}
