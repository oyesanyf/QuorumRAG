use quorum_coordinator::mesh::{
    collect_trusted_bootstrap_multiaddrs, extract_multiaddr_host_str, normalize_duckdns_fqdn,
};
use quorum_coordinator::OsoosiMeshSettings;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{OnceLock, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Cached runtime telemetry from background UPnP IGD, DuckDNS resolution, and Tailscale overlay probes.
#[derive(Debug, Clone, Default)]
pub struct WanMeshRuntimeTelemetry {
    pub external_wan_ip: Option<String>,
    pub upnp_gateway: Option<String>,
    pub upnp_tcp_mapped: bool,
    pub upnp_udp_mapped: bool,
    pub tailscale_self_ips: Vec<String>,
    pub tailscale_peer_addrs: Vec<String>,
    pub duckdns_fqdn: Option<String>,
    pub duckdns_resolved_ips: Vec<String>,
    pub is_duckdns_host: bool,
    pub updated_at: Option<String>,
}

static WAN_TELEMETRY: OnceLock<RwLock<WanMeshRuntimeTelemetry>> = OnceLock::new();

pub fn cached_wan_telemetry() -> WanMeshRuntimeTelemetry {
    WAN_TELEMETRY
        .get_or_init(|| RwLock::new(WanMeshRuntimeTelemetry::default()))
        .read()
        .map(|g| g.clone())
        .unwrap_or_default()
}

fn update_wan_telemetry<F: FnOnce(&mut WanMeshRuntimeTelemetry)>(f: F) {
    let lock = WAN_TELEMETRY.get_or_init(|| RwLock::new(WanMeshRuntimeTelemetry::default()));
    if let Ok(mut w) = lock.write() {
        f(&mut w);
        w.updated_at = Some(chrono::Utc::now().to_rfc3339());
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TailscaleSnapshot {
    pub self_ips: Vec<String>,
    pub peer_multiaddrs: Vec<String>,
}

/// Parses `tailscale status --json` output into self overlay IPs and online peer QUIC/TCP multiaddrs.
pub fn parse_tailscale_status_json(raw_json: &str, preferred_ports: &[u16]) -> TailscaleSnapshot {
    let mut snap = TailscaleSnapshot::default();
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw_json) else {
        return snap;
    };

    if let Some(ips) = val
        .get("Self")
        .and_then(|s| s.get("TailscaleIPs"))
        .and_then(|a| a.as_array())
    {
        for ip in ips {
            if let Some(s) = ip.as_str() {
                let s = s.trim();
                if !s.is_empty() {
                    snap.self_ips.push(s.to_string());
                }
            }
        }
    }

    let mut ports = Vec::new();
    for &p in preferred_ports {
        if p > 0 && p != 4001 && !ports.contains(&p) {
            ports.push(p);
        }
    }
    if ports.is_empty() {
        ports.push(3032);
    }

    if let Some(peers) = val.get("Peer").and_then(|p| p.as_object()) {
        for (_k, peer_obj) in peers {
            let online = peer_obj
                .get("Online")
                .and_then(|o| o.as_bool())
                .unwrap_or(false);
            if !online {
                continue;
            }
            if let Some(ips) = peer_obj.get("TailscaleIPs").and_then(|a| a.as_array()) {
                for ip_val in ips {
                    let Some(ip_str) = ip_val.as_str().map(str::trim) else {
                        continue;
                    };
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        for &port in &ports {
                            match ip {
                                IpAddr::V4(v4) => {
                                    snap.peer_multiaddrs.push(format!("/ip4/{}/tcp/{}", v4, port));
                                    snap.peer_multiaddrs
                                        .push(format!("/ip4/{}/udp/{}/quic-v1", v4, port));
                                }
                                IpAddr::V6(v6) => {
                                    snap.peer_multiaddrs.push(format!("/ip6/{}/tcp/{}", v6, port));
                                    snap.peer_multiaddrs
                                        .push(format!("/ip6/{}/udp/{}/quic-v1", v6, port));
                                }
                            }
                        }
                    }
                }
            }
            if let Some(dns_name) = peer_obj.get("DNSName").and_then(|d| d.as_str()) {
                let clean = dns_name.trim().trim_end_matches('.');
                if !clean.is_empty() && clean.contains('.') {
                    for &port in &ports {
                        snap.peer_multiaddrs.push(format!("/dns4/{}/tcp/{}", clean, port));
                    }
                }
            }
        }
    }

    snap
}

/// Runs `tailscale status --json` locally with a strict 1.5s timeout (`CREATE_NO_WINDOW` on Windows).
pub async fn probe_tailscale_status(mesh_port: u16) -> TailscaleSnapshot {
    let mut cmd = tokio::process::Command::new("tailscale");
    cmd.args(["status", "--json"]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let out = match tokio::time::timeout(Duration::from_millis(1500), cmd.output()).await {
        Ok(Ok(o)) if o.status.success() => o,
        _ => return TailscaleSnapshot::default(),
    };

    let stdout = String::from_utf8_lossy(&out.stdout);
    let snap = parse_tailscale_status_json(&stdout, &[mesh_port, 3032, 3031]);
    update_wan_telemetry(|t| {
        t.tailscale_self_ips = snap.self_ips.clone();
        t.tailscale_peer_addrs = snap.peer_multiaddrs.clone();
    });
    snap
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivateLanGatewayUrl {
    pub host_ip: Ipv4Addr,
    pub port: u16,
    pub path: String,
    pub host_header: String,
}

/// SSRF-hardened parser accepting ONLY `http://<private-rfc1918-ip>[:port]/<path>` URLs returned by LAN UPnP SSDP IGDs.
pub(crate) fn parse_private_lan_upnp_url(raw_url: &str) -> Option<PrivateLanGatewayUrl> {
    let rest = raw_url.trim().strip_prefix("http://")?;
    let (authority, path_raw) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') || path_raw.contains("..") {
        return None;
    }
    let (host_str, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (authority, 80),
    };
    let ip: Ipv4Addr = host_str.parse().ok()?;
    if !quorum_network::is_private_or_loopback_ip4(&ip)
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
    {
        return None;
    }
    Some(PrivateLanGatewayUrl {
        host_ip: ip,
        port,
        path: if path_raw.is_empty() {
            "/".to_string()
        } else {
            path_raw.to_string()
        },
        host_header: authority.to_string(),
    })
}

fn extract_xml_tag_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let low = xml.to_ascii_lowercase();
    let start = low.find(&open.to_ascii_lowercase())?;
    let after_open = xml[start..].find('>')? + start + 1;
    let end = low[after_open..].find(&close.to_ascii_lowercase())? + after_open;
    let val = xml[after_open..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

/// Extracts `(service_type, control_url)` for UPnP WANIPConnection / WANPPPConnection from an IGD XML description.
pub(crate) fn extract_igd_control_service(xml: &str) -> Option<(String, String)> {
    const SERVICE_TYPES: &[&str] = &[
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ];
    let low = xml.to_ascii_lowercase();
    for st in SERVICE_TYPES {
        if let Some(pos) = low.find(&st.to_ascii_lowercase()) {
            let service_end = low[pos..]
                .find("</service>")
                .map(|rel| pos + rel)
                .unwrap_or_else(|| (pos + 1024).min(xml.len()));
            let service_slice = &xml[pos..service_end];
            if let Some(ctrl) = extract_xml_tag_value(service_slice, "controlURL") {
                return Some(((*st).to_string(), ctrl));
            }
        }
    }
    None
}

async fn lan_http_exchange(
    gateway: &PrivateLanGatewayUrl,
    req_bytes: &[u8],
    timeout_ms: u64,
) -> Option<String> {
    let sock = SocketAddr::V4(SocketAddrV4::new(gateway.host_ip, gateway.port));
    let mut stream = tokio::time::timeout(Duration::from_millis(timeout_ms), TcpStream::connect(sock))
        .await
        .ok()?
        .ok()?;
    tokio::time::timeout(Duration::from_millis(timeout_ms), stream.write_all(req_bytes))
        .await
        .ok()?
        .ok()?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while buf.len() < 128 * 1024 {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            break;
        }
        match tokio::time::timeout(rem, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

async fn send_upnp_soap_action(
    gateway: &PrivateLanGatewayUrl,
    control_path: &str,
    service_type: &str,
    action: &str,
    body_xml: &str,
) -> Option<String> {
    let path = if control_path.starts_with('/') {
        control_path.to_string()
    } else {
        format!("/{}", control_path)
    };
    let envelope = format!(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n\
         <s:Body>{}</s:Body>\r\n\
         </s:Envelope>",
        body_xml
    );
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{}#{}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        gateway.host_header,
        service_type,
        action,
        envelope.len(),
        envelope
    );
    lan_http_exchange(gateway, req.as_bytes(), 1200).await
}

/// Best-effort SSDP UPnP IGD NAT port mapping for TCP & UDP `mesh_port` -> `local_lan_ip`, plus `GetExternalIPAddress`.
/// Never fails closed startup or talks to non-RFC1918 hosts.
pub async fn try_upnp_igd_map_mesh_ports(
    local_lan_ip: Ipv4Addr,
    mesh_port: u16,
) -> WanMeshRuntimeTelemetry {
    if !quorum_network::is_private_or_loopback_ip4(&local_lan_ip) || local_lan_ip.is_loopback() {
        return cached_wan_telemetry();
    }

    let Ok(udp) = UdpSocket::bind("0.0.0.0:0").await else {
        return cached_wan_telemetry();
    };
    let _ = udp.set_broadcast(true);
    let ssdp_target: SocketAddr = "239.255.255.250:1900".parse().unwrap();

    for st in [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
    ] {
        let msearch = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {}\r\n\r\n",
            st
        );
        let _ = udp.send_to(msearch.as_bytes(), ssdp_target).await;
    }

    let mut discovered_urls: Vec<PrivateLanGatewayUrl> = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(850);
    let mut recv_buf = [0u8; 2048];
    while tokio::time::Instant::now() < deadline && discovered_urls.len() < 4 {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(rem, udp.recv_from(&mut recv_buf)).await {
            Ok(Ok((n, _peer))) => {
                let text = String::from_utf8_lossy(&recv_buf[..n]);
                for line in text.lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("location") {
                            if let Some(gw) = parse_private_lan_upnp_url(v.trim()) {
                                if !discovered_urls.contains(&gw) {
                                    discovered_urls.push(gw);
                                }
                            }
                        }
                    }
                }
            }
            _ => break,
        }
    }

    for gw in discovered_urls {
        let get_req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            gw.path, gw.host_header
        );
        let Some(desc_xml) = lan_http_exchange(&gw, get_req.as_bytes(), 1200).await else {
            continue;
        };
        let Some((service_type, control_url)) = extract_igd_control_service(&desc_xml) else {
            continue;
        };
        let ctrl_target = if control_url.starts_with("http://") {
            match parse_private_lan_upnp_url(&control_url) {
                Some(parsed) => parsed,
                None => continue,
            }
        } else {
            PrivateLanGatewayUrl {
                host_ip: gw.host_ip,
                port: gw.port,
                path: control_url.clone(),
                host_header: gw.host_header.clone(),
            }
        };

        let ext_ip_resp = send_upnp_soap_action(
            &ctrl_target,
            &ctrl_target.path,
            &service_type,
            "GetExternalIPAddress",
            &format!(
                "<u:GetExternalIPAddress xmlns:u=\"{}\"></u:GetExternalIPAddress>",
                service_type
            ),
        )
        .await;
        let ext_ip = ext_ip_resp
            .as_deref()
            .and_then(|x| extract_xml_tag_value(x, "NewExternalIPAddress"))
            .filter(|ip_s| {
                ip_s.parse::<Ipv4Addr>()
                    .map(|ip| !ip.is_unspecified() && !ip.is_private() && !ip.is_loopback())
                    .unwrap_or(false)
            });

        let mut tcp_mapped = false;
        let mut udp_mapped = false;
        for proto in ["TCP", "UDP"] {
            let body = format!(
                "<u:AddPortMapping xmlns:u=\"{}\">\
                 <NewRemoteHost></NewRemoteHost>\
                 <NewExternalPort>{}</NewExternalPort>\
                 <NewProtocol>{}</NewProtocol>\
                 <NewInternalPort>{}</NewInternalPort>\
                 <NewInternalClient>{}</NewInternalClient>\
                 <NewEnabled>1</NewEnabled>\
                 <NewPortMappingDescription>QuorumRAG P2P Mesh</NewPortMappingDescription>\
                 <NewLeaseDuration>3600</NewLeaseDuration>\
                 </u:AddPortMapping>",
                service_type, mesh_port, proto, mesh_port, local_lan_ip
            );
            if let Some(resp) = send_upnp_soap_action(
                &ctrl_target,
                &ctrl_target.path,
                &service_type,
                "AddPortMapping",
                &body,
            )
            .await
            {
                let is_ok = resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200");
                if is_ok {
                    if proto == "TCP" {
                        tcp_mapped = true;
                    } else {
                        udp_mapped = true;
                    }
                }
            }
        }

        update_wan_telemetry(|t| {
            t.upnp_gateway = Some(gw.host_ip.to_string());
            if ext_ip.is_some() {
                t.external_wan_ip = ext_ip.clone();
            }
            t.upnp_tcp_mapped |= tcp_mapped;
            t.upnp_udp_mapped |= udp_mapped;
        });
        break;
    }

    cached_wan_telemetry()
}

/// Removes multiaddrs whose host matches our own machine's LAN, Tailscale, or external WAN IP
/// so nodes never waste sockets dialing themselves when at home or traveling.
pub fn filter_self_dial_targets(targets: Vec<String>, self_ips: &[String]) -> Vec<String> {
    if self_ips.is_empty() {
        return targets;
    }
    let self_set: BTreeSet<String> = self_ips
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    targets
        .into_iter()
        .filter(|ma| {
            let host = extract_multiaddr_host_str(ma)
                .map(|h| h.to_ascii_lowercase())
                .unwrap_or_default();
            !self_set.contains(&host)
        })
        .collect()
}

/// Resolves DuckDNS, Tailscale overlay peers, configured `bootstrap_peers`, and known peers into trusted dial targets.
pub async fn collect_wan_and_overlay_dial_targets(
    mesh: &OsoosiMeshSettings,
    known_multiaddrs: &[String],
    local_lan_ips: &[Ipv4Addr],
) -> Vec<String> {
    let ts_fut = probe_tailscale_status(mesh.mesh_port);
    let fqdn_opt = if mesh.auto_bootstrap_duckdns {
        mesh.duckdns_domain.as_deref().and_then(normalize_duckdns_fqdn)
    } else {
        None
    };

    let dns_fut = async {
        let Some(ref fqdn) = fqdn_opt else {
            return Vec::new();
        };
        let port = mesh.mesh_port.max(1);
        match tokio::time::timeout(
            Duration::from_millis(1200),
            tokio::net::lookup_host((fqdn.as_str(), port)),
        )
        .await
        {
            Ok(Ok(iter)) => iter.map(|sa| sa.ip().to_string()).collect::<Vec<_>>(),
            _ => Vec::new(),
        }
    };

    let (ts_snap, resolved_ips) = tokio::join!(ts_fut, dns_fut);

    let mut targets = collect_trusted_bootstrap_multiaddrs(mesh, known_multiaddrs);
    for ip_str in &resolved_ips {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            let mut ports = Vec::new();
            for p in [mesh.mesh_port, 3032, 3031] {
                if p > 0 && p != 4001 && !ports.contains(&p) {
                    ports.push(p);
                }
            }
            for p in ports {
                let (tcp_ma, quic_ma) = match ip {
                    IpAddr::V4(v4) => (
                        format!("/ip4/{}/tcp/{}", v4, p),
                        format!("/ip4/{}/udp/{}/quic-v1", v4, p),
                    ),
                    IpAddr::V6(v6) => (
                        format!("/ip6/{}/tcp/{}", v6, p),
                        format!("/ip6/{}/udp/{}/quic-v1", v6, p),
                    ),
                };
                if !targets.contains(&tcp_ma) {
                    targets.push(tcp_ma);
                }
                if !targets.contains(&quic_ma) {
                    targets.push(quic_ma);
                }
            }
        }
    }
    for ma in ts_snap.peer_multiaddrs {
        if !targets.contains(&ma) {
            targets.push(ma);
        }
    }

    let cached = cached_wan_telemetry();
    let is_duckdns_host = cached
        .external_wan_ip
        .as_ref()
        .map(|ext| resolved_ips.iter().any(|r| r == ext))
        .unwrap_or(false)
        || ts_snap
            .self_ips
            .iter()
            .any(|tip| resolved_ips.iter().any(|r| r == tip));

    update_wan_telemetry(|t| {
        t.duckdns_fqdn = fqdn_opt.clone();
        t.duckdns_resolved_ips = resolved_ips.clone();
        t.is_duckdns_host = is_duckdns_host;
    });

    let mut self_ips: Vec<String> = local_lan_ips.iter().map(|ip| ip.to_string()).collect();
    self_ips.push("127.0.0.1".to_string());
    self_ips.push("::1".to_string());
    self_ips.extend(ts_snap.self_ips);
    if let Some(ref ext) = cached.external_wan_ip {
        self_ips.push(ext.clone());
    }
    if is_duckdns_host {
        if let Some(fqdn) = fqdn_opt {
            self_ips.push(fqdn);
        }
    }

    filter_self_dial_targets(targets, &self_ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssdp_url_ssrf_guard_allows_rfc1918_and_blocks_wan_and_loopback() {
        assert!(parse_private_lan_upnp_url("http://192.168.1.1:5000/rootDesc.xml").is_some());
        assert!(parse_private_lan_upnp_url("http://10.0.0.1:49152/igd.xml").is_some());
        assert!(parse_private_lan_upnp_url("http://127.0.0.1:5000/igd.xml").is_none());
        assert!(parse_private_lan_upnp_url("http://8.8.8.8:80/igd.xml").is_none());
        assert!(parse_private_lan_upnp_url("http://evil.example.com/igd.xml").is_none());
        assert!(parse_private_lan_upnp_url("https://192.168.1.1/igd.xml").is_none());
    }

    #[test]
    fn test_extract_igd_control_service_and_external_ip() {
        let xml = r#"
        <root><device><serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
            <controlURL>/upnp/control/WANIPConn1</controlURL>
          </service>
        </serviceList></device></root>"#;
        let (st, ctrl) = extract_igd_control_service(xml).expect("must find WANIPConnection");
        assert_eq!(st, "urn:schemas-upnp-org:service:WANIPConnection:1");
        assert_eq!(ctrl, "/upnp/control/WANIPConn1");

        let soap = "<s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>73.112.44.19</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body>";
        assert_eq!(
            extract_xml_tag_value(soap, "NewExternalIPAddress").as_deref(),
            Some("73.112.44.19")
        );
    }

    #[test]
    fn test_parse_tailscale_status_json_extracts_online_peers_and_skips_offline() {
        let sample = r#"{
            "Self": { "TailscaleIPs": ["100.77.10.2", "fd7a:115c::1"] },
            "Peer": {
                "nodekey:1": {
                    "DNSName": "home-desktop.tailnet-abc.ts.net.",
                    "TailscaleIPs": ["100.88.20.9"],
                    "Online": true
                },
                "nodekey:2": {
                    "DNSName": "offline-laptop.tailnet-abc.ts.net.",
                    "TailscaleIPs": ["100.88.20.99"],
                    "Online": false
                }
            }
        }"#;
        let snap = parse_tailscale_status_json(sample, &[3032]);
        assert_eq!(snap.self_ips, vec!["100.77.10.2", "fd7a:115c::1"]);
        assert!(snap.peer_multiaddrs.contains(&"/ip4/100.88.20.9/tcp/3032".to_string()));
        assert!(snap.peer_multiaddrs.contains(&"/ip4/100.88.20.9/udp/3032/quic-v1".to_string()));
        assert!(snap.peer_multiaddrs.contains(&"/dns4/home-desktop.tailnet-abc.ts.net/tcp/3032".to_string()));
        assert!(!snap.peer_multiaddrs.iter().any(|m| m.contains("100.88.20.99")));

        let filtered = filter_self_dial_targets(
            vec![
                "/ip4/100.77.10.2/tcp/3032".to_string(),
                "/ip4/100.88.20.9/tcp/3032".to_string(),
                "/dns4/oshoosi.duckdns.org/tcp/3032".to_string(),
            ],
            &["100.77.10.2".to_string(), "10.0.0.155".to_string()],
        );
        assert_eq!(
            filtered,
            vec![
                "/ip4/100.88.20.9/tcp/3032".to_string(),
                "/dns4/oshoosi.duckdns.org/tcp/3032".to_string(),
            ]
        );
    }
}
