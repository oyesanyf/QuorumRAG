use crate::behaviour::{QuorumNetworkBehaviour, QuorumNetworkBehaviourEvent};
use crate::config::NetworkConfig;
use crate::error::NetworkError;
use crate::handle::{NetworkCommand, NetworkEvent};
use crate::handshake::{extract_contract_hash, verify_peer_contract};
use crate::InboundQueryHandler;
use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::OutboundRequestId;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, identify, mdns, request_response, Multiaddr, PeerId, Swarm};
use quorum_types::{FederatedQueryRequest, FederatedQueryResponse};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};

pub struct NetworkSwarmActor {
    pub(crate) swarm: Swarm<QuorumNetworkBehaviour>,
    pub(crate) command_rx: mpsc::Receiver<NetworkCommand>,
    pub(crate) command_tx: mpsc::Sender<NetworkCommand>,
    pub(crate) event_tx: broadcast::Sender<NetworkEvent>,
    pub(crate) listen_addrs: Arc<RwLock<Vec<Multiaddr>>>,
    pub(crate) peer_addrs: Arc<std::sync::RwLock<HashMap<PeerId, Multiaddr>>>,
    pub(crate) inbound_handler: Arc<dyn InboundQueryHandler>,
    pub(crate) pending_requests:
        HashMap<OutboundRequestId, oneshot::Sender<Result<FederatedQueryResponse, NetworkError>>>,
    pub(crate) config: NetworkConfig,
}

fn extract_ipv4(addr: &Multiaddr) -> Option<Ipv4Addr> {
    for proto in addr.iter() {
        if let Protocol::Ip4(ip) = proto {
            return Some(ip);
        }
    }
    None
}

fn strip_p2p_suffix(addr: &Multiaddr) -> Multiaddr {
    let mut out = Multiaddr::empty();
    for proto in addr.iter() {
        if !matches!(proto, Protocol::P2p(_)) {
            out.push(proto);
        }
    }
    out
}

fn is_preferred_lan_tcp_addr(addr: &Multiaddr) -> bool {
    let mut has_private_lan_ip4 = false;
    let mut has_tcp = false;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) if !ip.is_loopback() && !ip.is_unspecified() => {
                has_private_lan_ip4 = crate::transport::is_private_or_loopback_ip4(&ip);
            }
            Protocol::Tcp(_) => {
                has_tcp = true;
            }
            _ => {}
        }
    }
    has_private_lan_ip4 && has_tcp
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
                        Some(NetworkCommand::DialTrusted { addr, reply }) => {
                            let res = if !crate::transport::is_allowed_trusted_bootstrap_address(&addr) {
                                let err = std::io::Error::new(
                                    std::io::ErrorKind::PermissionDenied,
                                    format!("dial_trusted to disallowed multiaddr {} rejected by policy", addr),
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
                        Some(NetworkCommand::DisconnectPeer { peer_id, reply }) => {
                            let _ = self.swarm.disconnect_peer_id(peer_id);
                            if let Ok(mut w) = self.peer_addrs.write() {
                                w.remove(&peer_id);
                            }
                            let _ = reply.send(Ok(()));
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
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                let remote_addr = strip_p2p_suffix(endpoint.get_remote_address());
                if let Ok(mut w) = self.peer_addrs.write() {
                    let should_update = match w.get(&peer_id) {
                        None => true,
                        Some(existing) => {
                            !is_preferred_lan_tcp_addr(existing)
                                && is_preferred_lan_tcp_addr(&remote_addr)
                        }
                    };
                    if should_update {
                        w.insert(peer_id, remote_addr);
                    }
                }
                let _ = self.event_tx.send(NetworkEvent::PeerConnected { peer_id });
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                if num_established == 0 {
                    if let Ok(mut w) = self.peer_addrs.write() {
                        w.remove(&peer_id);
                    }
                    let _ = self
                        .event_tx
                        .send(NetworkEvent::PeerDisconnected { peer_id });
                }
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
                    // Learn our observed external address from verified peers so NAT'd listen addresses are advertised
                    if !info.observed_addr.is_empty()
                        && !extract_ipv4(&info.observed_addr)
                            .map(|ip| ip.is_loopback() || ip.is_unspecified())
                            .unwrap_or(false)
                    {
                        self.swarm.add_external_address(info.observed_addr.clone());
                    }
                    // Upgrade ephemeral inbound remote port to the peer's advertised TCP listen port on the same IP
                    let mut best_listen_for_ip: Option<Multiaddr> = None;
                    let current_ip = self
                        .peer_addrs
                        .read()
                        .ok()
                        .and_then(|r| r.get(&peer_id).and_then(extract_ipv4));
                    for addr in info.listen_addrs {
                        let clean_addr = strip_p2p_suffix(&addr);
                        if let Some(ip) = current_ip {
                            if extract_ipv4(&clean_addr) == Some(ip)
                                && clean_addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
                            {
                                best_listen_for_ip = Some(clean_addr.clone());
                            }
                        } else if best_listen_for_ip.is_none()
                            && is_preferred_lan_tcp_addr(&clean_addr)
                        {
                            best_listen_for_ip = Some(clean_addr.clone());
                        }
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr);
                    }
                    if let Some(best) = best_listen_for_ip {
                        if let Ok(mut w) = self.peer_addrs.write() {
                            w.insert(peer_id, best);
                        }
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
                    if let Ok(mut w) = self.peer_addrs.write() {
                        w.remove(&peer_id);
                    }
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
                        if crate::transport::is_allowed_dial_address(&addr) {
                            let clean_addr = strip_p2p_suffix(&addr);
                            if is_preferred_lan_tcp_addr(&clean_addr) {
                                if let Ok(mut w) = self.peer_addrs.write() {
                                    w.entry(peer_id).or_insert(clean_addr);
                                }
                            }
                            if !self.swarm.is_connected(&peer_id) {
                                let _ = self.swarm.dial(addr.clone());
                            }
                        }
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
