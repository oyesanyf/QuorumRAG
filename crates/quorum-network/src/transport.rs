use crate::behaviour::QuorumNetworkBehaviour;
use crate::config::NetworkConfig;
use crate::error::NetworkError;
use crate::handshake::{make_agent_version, make_protocol_version};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{
    gossipsub, identify, kad, mdns, noise, request_response, tcp, yamux,
    StreamProtocol, Swarm, SwarmBuilder,
};
use std::time::Duration;

pub fn build_swarm(
    config: &NetworkConfig,
    keypair: libp2p::identity::Keypair,
) -> Result<Swarm<QuorumNetworkBehaviour>, NetworkError> {
    let local_peer_id = keypair.public().to_peer_id();

    let protocol_version = make_protocol_version(&config.contract_hash_hex);
    let agent_version = make_agent_version(&config.contract_hash_hex);

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| NetworkError::TransportError(e.to_string()))?
        .with_quic()
        .with_dns()
        .map_err(|e| NetworkError::TransportError(e.to_string()))?
        .with_behaviour(|key| {
            // 1. mDNS (Toggle for optional LAN discovery)
            let mdns = if config.enable_mdns {
                let m = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    local_peer_id,
                )
                .map_err(|e| NetworkError::SwarmBuildError(e.to_string()))?;
                Toggle::from(Some(m))
            } else {
                Toggle::from(None)
            };

            // 2. Kademlia DHT
            let mut kademlia = kad::Behaviour::new(
                local_peer_id,
                kad::store::MemoryStore::new(local_peer_id),
            );
            kademlia.set_mode(Some(kad::Mode::Server));

            // 3. GossipSub
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(|msg| {
                    let digest = blake3::hash(&msg.data);
                    gossipsub::MessageId::from(digest.as_bytes().to_vec())
                })
                .build()
                .map_err(|e| NetworkError::SwarmBuildError(e.to_string()))?;

            let mut gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )
            .map_err(|e| NetworkError::SwarmBuildError(e.to_string()))?;

            let topic = gossipsub::IdentTopic::new(&config.gossip_topic);
            let _ = gossipsub.subscribe(&topic);

            // 4. Request-Response (CBOR)
            let protocols = [(
                StreamProtocol::new("/quorum-rag/query/1.0.0"),
                request_response::ProtocolSupport::Full,
            )];
            let rr_config = request_response::Config::default()
                .with_request_timeout(config.request_timeout);
            let request_response = request_response::cbor::Behaviour::new(protocols, rr_config);

            // 5. Identify
            let id_config = identify::Config::new(protocol_version, key.public())
                .with_agent_version(agent_version);
            let identify = identify::Behaviour::new(id_config);

            Ok(QuorumNetworkBehaviour {
                mdns,
                kademlia,
                gossipsub,
                request_response,
                identify,
            })
        })
        .map_err(|e| NetworkError::SwarmBuildError(e.to_string()))?
        .with_swarm_config(|cfg| {
            cfg.with_idle_connection_timeout(Duration::from_secs(60))
        })
        .build();

    Ok(swarm)
}

use std::net::{Ipv4Addr, Ipv6Addr};
use libp2p::multiaddr::Protocol;

/// Mathematically validates if an IPv4 address is loopback or private RFC1918 / link-local.
pub fn is_private_or_loopback_ip4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    // Loopback: 127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }
    // RFC1918:
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // Link-local: 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // Unspecified: 0.0.0.0
    if ip.is_unspecified() {
        return true;
    }
    false
}

/// Mathematically validates if an IPv6 address is loopback or private / unique-local / link-local.
pub fn is_private_or_loopback_ip6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let segments = ip.segments();
    // Unique local address: fc00::/7
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // Link-local unicast: fe80::/10
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // IPv4-mapped IPv6 (::ffff:0:0/96)
    if let Some(ip4) = ip.to_ipv4() {
        return is_private_or_loopback_ip4(&ip4);
    }
    false
}

/// Air-gapped offline dial address gate: restricts swarm dialing to loopback and private subnets (RFC1918).
/// Rejects public WAN addresses and arbitrary internet DNS names.
pub fn is_allowed_dial_address(addr: &libp2p::Multiaddr) -> bool {
    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(ip) => {
                if !is_private_or_loopback_ip4(&ip) {
                    return false;
                }
            }
            Protocol::Ip6(ip) => {
                if !is_private_or_loopback_ip6(&ip) {
                    return false;
                }
            }
            Protocol::Dns(host) | Protocol::Dns4(host) | Protocol::Dns6(host) | Protocol::Dnsaddr(host) => {
                let host_str = host.as_ref();
                if host_str != "localhost" && !host_str.ends_with(".local") {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}
