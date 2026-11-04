use crate::behaviour::{QuorumNetworkBehaviour, QuorumNetworkBehaviourEvent};
use crate::config::NetworkConfig;
use crate::error::NetworkError;
use crate::handle::{NetworkCommand, NetworkEvent};
use crate::handshake::{extract_contract_hash, verify_peer_contract};
use crate::InboundQueryHandler;
use futures::StreamExt;
use libp2p::request_response::OutboundRequestId;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, identify, mdns, request_response, Multiaddr, Swarm};
use quorum_types::{FederatedQueryRequest, FederatedQueryResponse};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};

pub struct NetworkSwarmActor {
    pub(crate) swarm: Swarm<QuorumNetworkBehaviour>,
    pub(crate) command_rx: mpsc::Receiver<NetworkCommand>,
    pub(crate) command_tx: mpsc::Sender<NetworkCommand>,
    pub(crate) event_tx: broadcast::Sender<NetworkEvent>,
    pub(crate) listen_addrs: Arc<RwLock<Vec<Multiaddr>>>,
    pub(crate) inbound_handler: Arc<dyn InboundQueryHandler>,
    pub(crate) pending_requests:
        HashMap<OutboundRequestId, oneshot::Sender<Result<FederatedQueryResponse, NetworkError>>>,
    pub(crate) config: NetworkConfig,
}

impl NetworkSwarmActor {
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                cmd = self.command_rx.recv() => {
                    match cmd {
                        Some(NetworkCommand::Dial { addr, reply }) => {
                            let res = if !crate::transport::is_allowed_dial_address(&addr) {
                                let err = std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    format!("dial to non-airgapped multiaddr {} rejected by security policy", addr),
                                );
                                Err(NetworkError::DialError {
                                    addr: addr.clone(),
                                    source: Box::new(libp2p::swarm::DialError::Denied {
                                        cause: libp2p::swarm::ConnectionDenied::new(err),
                                    }),
                                })
                            } else {
                                self.swarm.dial(addr.clone()).map_err(|e| NetworkError::DialError { addr, source: Box::new(e) })
                            };
                            let _ = reply.send(res);
                        }
                        Some(NetworkCommand::SendQuery { peer_id, request, reply }) => {
                            let req_id = self.swarm.behaviour_mut().request_response.send_request(&peer_id, request);
                            self.pending_requests.insert(req_id, reply);
                        }
                        Some(NetworkCommand::BroadcastQuery { request, reply }) => {
                            let res = match serde_json::to_vec(&request) {
                                Ok(bytes) => {
                                    let topic = gossipsub::IdentTopic::new(&self.config.gossip_topic);
                                    self.swarm.behaviour_mut().gossipsub.publish(topic, bytes)
                                        .map(|_| ())
                                        .map_err(|e| NetworkError::GossipsubError(e.to_string()))
                                }
                                Err(e) => Err(NetworkError::Serialization(e.to_string())),
                            };
                            let _ = reply.send(res);
                        }
                        Some(NetworkCommand::GetConnectedPeers { reply }) => {
                            let peers = self.swarm.connected_peers().copied().collect();
                            let _ = reply.send(peers);
                        }
                        Some(NetworkCommand::GetListenAddresses { reply }) => {
                            let addrs = self.swarm.listeners().cloned().collect();
                            let _ = reply.send(addrs);
                        }
                        Some(NetworkCommand::SendInboundReply { channel, response }) => {
                            let _ = self.swarm.behaviour_mut().request_response.send_response(channel, response);
                        }
                        Some(NetworkCommand::Shutdown) | None => {
                            tracing::info!("Network swarm actor shutting down");
                            break;
                        }
                    }
                }
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
            }
        }
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<QuorumNetworkBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                let mut w = self.listen_addrs.write().await;
                if !w.contains(&address) {
                    w.push(address);
                }
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                let mut w = self.listen_addrs.write().await;
                w.retain(|a| a != &address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                let _ = self.event_tx.send(NetworkEvent::PeerConnected { peer_id });
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                let _ = self.event_tx.send(NetworkEvent::PeerDisconnected { peer_id });
            }
            SwarmEvent::Behaviour(QuorumNetworkBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                let remote_hash = extract_contract_hash(&info.protocol_version)
                    .or_else(|| extract_contract_hash(&info.agent_version));
                let is_ok = match remote_hash {
                    Some(ref rh) => verify_peer_contract(
                        &peer_id.to_string(),
                        &self.config.contract_hash_hex,
                        rh,
                    )
                    .is_ok(),
                    None => false,
                };

                if is_ok {
                    for addr in info.listen_addrs {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr);
                    }
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer_id);
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::PeerHandshakeVerified { peer_id });
                } else {
                    tracing::warn!(
                        %peer_id,
                        "Disconnecting peer due to Gemma contract hash mismatch"
                    );
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer_id);
                    let _ = self.event_tx.send(NetworkEvent::PeerRejected {
                        peer_id,
                        reason: "Gemma contract hash mismatch".to_string(),
                    });
                }
            }
            SwarmEvent::Behaviour(QuorumNetworkBehaviourEvent::Mdns(mdns_ev)) => match mdns_ev {
                mdns::Event::Discovered(list) => {
                    for (peer_id, addr) in list {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr.clone());
                        let _ = self
                            .event_tx
                            .send(NetworkEvent::PeerDiscovered { peer_id, address: addr });
                    }
                }
                mdns::Event::Expired(list) => {
                    for (peer_id, _) in list {
                        let _ = self.event_tx.send(NetworkEvent::PeerExpired { peer_id });
                    }
                }
            },
            SwarmEvent::Behaviour(QuorumNetworkBehaviourEvent::Gossipsub(
                gossipsub::Event::Message { message, .. },
            )) => {
                if let Ok(req) = serde_json::from_slice::<FederatedQueryRequest>(&message.data) {
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::GossipQueryReceived { request: req });
                }
            }
            SwarmEvent::Behaviour(QuorumNetworkBehaviourEvent::RequestResponse(rr_ev)) => {
                match rr_ev {
                    request_response::Event::Message { message, .. } => match message {
                        request_response::Message::Request {
                            request, channel, ..
                        } => {
                            let handler = Arc::clone(&self.inbound_handler);
                            let cmd_tx = self.command_tx.clone();
                            tokio::spawn(async move {
                                let response = handler.handle_query(request).await;
                                let _ = cmd_tx
                                    .send(NetworkCommand::SendInboundReply { channel, response })
                                    .await;
                            });
                        }
                        request_response::Message::Response {
                            request_id,
                            response,
                        } => {
                            if let Some(reply) = self.pending_requests.remove(&request_id) {
                                let _ = reply.send(Ok(response));
                            }
                        }
                    },
                    request_response::Event::OutboundFailure {
                        request_id, error, ..
                    } => {
                        if let Some(reply) = self.pending_requests.remove(&request_id) {
                            let _ = reply.send(Err(NetworkError::RequestFailed(error.to_string())));
                        }
                    }
                    request_response::Event::InboundFailure { error, .. } => {
                        tracing::debug!("Inbound request-response failure: {:?}", error);
                    }
                    request_response::Event::ResponseSent { .. } => {}
                }
            }
            _ => {}
        }
    }
}
