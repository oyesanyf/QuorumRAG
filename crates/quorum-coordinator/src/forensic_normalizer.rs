//! Forensic Structural Normalizer with Keyed BLAKE3 Pseudonymization.
//!
//! Replaces host-specific identifiers (usernames, hostnames, SIDs, internal IPs,
//! SMB share paths, MAC addresses) with consistent, session-scoped pseudonyms
//! derived from keyed BLAKE3 hashes. Preserves investigation topology and causal graph.

use crate::marketplace_engine::RawTrajectoryCandidate;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::OnceLock;

/// Result structure for live normalizer preview in the WebUI and daemon API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizerPreview {
    pub original_text: String,
    pub normalized_text: String,
    pub usernames_replaced: usize,
    pub hostnames_replaced: usize,
    pub sids_replaced: usize,
    pub ips_replaced: usize,
    pub smb_shares_replaced: usize,
    pub macs_replaced: usize,
    pub total_replacements: usize,
    pub pseudonym_mappings: HashMap<String, String>,
}

/// Session-scoped structural normalizer.
pub struct ForensicStructuralNormalizer {
    session_key: [u8; 32],
    username_map: HashMap<String, String>,
    hostname_map: HashMap<String, String>,
    sid_map: HashMap<String, String>,
    ip_map: HashMap<String, String>,
    share_map: HashMap<String, String>,
    mac_map: HashMap<String, String>,
}

impl ForensicStructuralNormalizer {
    /// Construct a normalizer directly with a 32-byte session secret.
    pub fn new(session_key: [u8; 32]) -> Self {
        Self {
            session_key,
            username_map: HashMap::new(),
            hostname_map: HashMap::new(),
            sid_map: HashMap::new(),
            ip_map: HashMap::new(),
            share_map: HashMap::new(),
            mac_map: HashMap::new(),
        }
    }

    /// Derive an ephemeral session key from the node's persistent seed and session/batch salt.
    pub fn from_node_seed(node_seed: &[u8; 32], session_id: &str) -> Self {
        let master_key = blake3::derive_key("QuorumRAG-ForensicNormalizer-v1", node_seed);
        let mut hasher = blake3::Hasher::new_keyed(&master_key);
        hasher.update(session_id.trim().as_bytes());
        let session_key = *hasher.finalize().as_bytes();
        Self::new(session_key)
    }

    fn derive_pseudonym(&self, category: &str, entity: &str) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.session_key);
        hasher.update(category.as_bytes());
        hasher.update(b":");
        hasher.update(entity.trim().to_ascii_lowercase().as_bytes());
        let hex = hasher.finalize().to_hex();
        let short = &hex[..8];
        match category {
            "user" => format!("USER_{}", short),
            "host" => format!("HOST_{}", short),
            "sid" => format!("SID_{}", short),
            "ip" => format!("IP_{}", short),
            "share" => format!("SHARE_{}", short),
            "mac" => format!("MAC_{}", short),
            _ => format!("PSEUDO_{}", short),
        }
    }

    pub fn pseudonymize_username(&mut self, username: &str) -> String {
        let trimmed = username.trim().trim_matches('"').trim_end_matches(['.', ',', ';', ':', '!', '?']);
        // Preserve standard system built-in accounts
        match trimmed.to_ascii_lowercase().as_str() {
            "system"
            | "nt authority\\system"
            | "local service"
            | "network service"
            | "root"
            | "nobody"
            | "daemon" => {
                return trimmed.to_string();
            }
            _ => {}
        }
        let key = trimmed.to_ascii_lowercase();
        if let Some(existing) = self.username_map.get(&key) {
            return existing.clone();
        }
        let pseudo = self.derive_pseudonym("user", trimmed);
        self.username_map.insert(key, pseudo.clone());
        pseudo
    }

    pub fn pseudonymize_hostname(&mut self, hostname: &str) -> String {
        let trimmed = hostname.trim().trim_matches('"').trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if trimmed.eq_ignore_ascii_case("localhost") {
            return "localhost".to_string();
        }
        let key = trimmed.to_ascii_lowercase();
        if let Some(existing) = self.hostname_map.get(&key) {
            return existing.clone();
        }
        let pseudo = self.derive_pseudonym("host", trimmed);
        self.hostname_map.insert(key, pseudo.clone());
        pseudo
    }

    pub fn pseudonymize_sid(&mut self, sid: &str) -> String {
        let trimmed = sid.trim();
        // Preserve standard well-known SIDs (Local System, Local Service, Network Service, Admins)
        match trimmed {
            "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-32-544" => return trimmed.to_string(),
            _ => {}
        }
        let key = trimmed.to_ascii_lowercase();
        if let Some(existing) = self.sid_map.get(&key) {
            return existing.clone();
        }
        let pseudo = self.derive_pseudonym("sid", trimmed);
        self.sid_map.insert(key, pseudo.clone());
        pseudo
    }

    pub fn pseudonymize_ip(&mut self, ip_str: &str) -> String {
        let trimmed = ip_str.trim();
        let key = trimmed.to_ascii_lowercase();
        if let Some(existing) = self.ip_map.get(&key) {
            return existing.clone();
        }
        let pseudo = self.derive_pseudonym("ip", trimmed);
        self.ip_map.insert(key, pseudo.clone());
        pseudo
    }

    pub fn pseudonymize_smb_share(&mut self, unc_path: &str) -> String {
        let trimmed = unc_path.trim().trim_end_matches(['.', ',', ';', ':', '!', '?']);
        let key = trimmed.to_ascii_lowercase();
        if let Some(existing) = self.share_map.get(&key) {
            return existing.clone();
        }
        // Parse \\Host\Share\Remaining
        let stripped = trimmed.trim_start_matches('\\').trim_start_matches('/');
        let parts: Vec<&str> = stripped.split(['\\', '/']).collect();
        let pseudo = if parts.len() >= 2 {
            let host_pseudo = self.pseudonymize_hostname(parts[0]);
            let share_pseudo = self.derive_pseudonym("share", parts[1]);
            let remaining = parts[2..].join("\\");
            if remaining.is_empty() {
                format!("\\\\{}\\{}", host_pseudo, share_pseudo)
            } else {
                format!("\\\\{}\\{}\\{}", host_pseudo, share_pseudo, remaining)
            }
        } else {
            self.derive_pseudonym("share", trimmed)
        };
        self.share_map.insert(key, pseudo.clone());
        pseudo
    }

    pub fn pseudonymize_mac(&mut self, mac: &str) -> String {
        let trimmed = mac.trim();
        let key = trimmed.to_ascii_lowercase();
        if let Some(existing) = self.mac_map.get(&key) {
            return existing.clone();
        }
        let pseudo = self.derive_pseudonym("mac", trimmed);
        self.mac_map.insert(key, pseudo.clone());
        pseudo
    }

    /// Full text normalization pass replacing all host-specific identifiers.
    pub fn normalize_text(&mut self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        let mut out = text.to_string();

        // 1. Windows SIDs: \bS-1-(?:\d+)(?:-\d+)+\b
        static SID_RE: OnceLock<Regex> = OnceLock::new();
        let sid_re = SID_RE.get_or_init(|| {
            Regex::new(r"\bS-1-(?:\d+)(?:-\d+)+\b").expect("sid regex")
        });
        let sids: Vec<String> = sid_re.find_iter(&out).map(|m| m.as_str().to_string()).collect();
        for sid in sids {
            let pseudo = self.pseudonymize_sid(&sid);
            if pseudo != sid {
                out = out.replace(&sid, &pseudo);
            }
        }

        // 2. SMB UNC paths: \\\\[A-Za-z0-9_.-]+\\[A-Za-z0-9_$.-]+(?:\\[A-Za-z0-9_$.-]+)*
        static UNC_RE: OnceLock<Regex> = OnceLock::new();
        let unc_re = UNC_RE.get_or_init(|| {
            Regex::new(r"(?i)\\\\[A-Za-z0-9_.-]+\\[A-Za-z0-9_$.-]+(?:\\[A-Za-z0-9_$.-]+)*").expect("unc regex")
        });
        let uncs: Vec<String> = unc_re
            .find_iter(&out)
            .map(|m| m.as_str().trim_end_matches(['.', ',', ';', ':', '!', '?']).to_string())
            .collect();
        for unc in uncs {
            let pseudo = self.pseudonymize_smb_share(&unc);
            out = out.replace(&unc, &pseudo);
        }

        // 3. MAC addresses: ([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}
        static MAC_RE: OnceLock<Regex> = OnceLock::new();
        let mac_re = MAC_RE.get_or_init(|| {
            Regex::new(r"(?i)\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b").expect("mac regex")
        });
        let macs: Vec<String> = mac_re.find_iter(&out).map(|m| m.as_str().to_string()).collect();
        for mac in macs {
            let pseudo = self.pseudonymize_mac(&mac);
            out = out.replace(&mac, &pseudo);
        }

        // 4. Internal RFC1918 / Loopback / Link-Local IP addresses
        static IP_RE: OnceLock<Regex> = OnceLock::new();
        let ip_re = IP_RE.get_or_init(|| {
            Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("ip regex")
        });
        let mut ips: Vec<String> = ip_re.find_iter(&out).map(|m| m.as_str().to_string()).collect();
        for mapped_ip in self.ip_map.keys() {
            if !ips.iter().any(|existing| existing.eq_ignore_ascii_case(mapped_ip)) {
                ips.push(mapped_ip.clone());
            }
        }
        // Sort candidate IP addresses by string length in descending order before replacing
        // ensuring e.g. 10.0.0.10 is replaced before 10.0.0.1
        ips.sort_by(|a, b| b.len().cmp(&a.len()));
        ips.dedup();
        for ip_candidate in ips {
            if let Ok(parsed) = ip_candidate.parse::<IpAddr>() {
                if is_internal_private_ip(parsed) {
                    let pseudo = self.pseudonymize_ip(&ip_candidate);
                    if let Ok(token_re) = Regex::new(&format!(r"\b{}\b", regex::escape(&ip_candidate))) {
                        out = token_re.replace_all(&out, pseudo.as_str()).to_string();
                    } else {
                        out = out.replace(&ip_candidate, &pseudo);
                    }
                }
            }
        }

        static IPV6_RE: OnceLock<Regex> = OnceLock::new();
        let ipv6_re = IPV6_RE.get_or_init(|| {
            Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|\bfe80:[0-9a-f:]+\b|\bfc00:[0-9a-f:]+\b|\bfd00:[0-9a-f:]+\b|\b::1\b").expect("ipv6 regex")
        });
        let mut ipv6s: Vec<String> = ipv6_re.find_iter(&out).map(|m| m.as_str().to_string()).collect();
        ipv6s.sort_by(|a, b| b.len().cmp(&a.len()));
        ipv6s.dedup();
        for ip6 in ipv6s {
            if let Ok(parsed) = ip6.parse::<IpAddr>() {
                if is_internal_private_ip(parsed) {
                    let pseudo = self.pseudonymize_ip(&ip6);
                    out = out.replace(&ip6, &pseudo);
                }
            }
        }

        // 5. Usernames & Hostnames in labeled forensic telemetry
        static LABELED_USER_RE: OnceLock<Regex> = OnceLock::new();
        let user_re = LABELED_USER_RE.get_or_init(|| {
            Regex::new(r#"(?i)\b(?:User|Account Name|TargetUserName|SubjectUserName|user|uid)\s*[:=]\s*"?((?:NT AUTHORITY\\[A-Za-z0-9_.-]+|Local Service|Network Service|[^"\s,}\]]+))"?"#).expect("user regex")
        });
        for cap in user_re.captures_iter(&out) {
            if let Some(matched) = cap.get(1) {
                let uname = matched
                    .as_str()
                    .trim_matches('"')
                    .trim_end_matches(['.', ',', ';', ':', '!', '?'])
                    .to_string();
                let _ = self.pseudonymize_username(&uname);
            }
        }

        static LABELED_HOST_RE: OnceLock<Regex> = OnceLock::new();
        let host_re = LABELED_HOST_RE.get_or_init(|| {
            Regex::new(r#"(?i)\b(?:ComputerName|Computer|Hostname|host|Workstation)\s*[:=]\s*"?([^"\s,}\]]+)"?"#).expect("host regex")
        });
        for cap in host_re.captures_iter(&out) {
            if let Some(matched) = cap.get(1) {
                let hname = matched
                    .as_str()
                    .trim_matches('"')
                    .trim_end_matches(['.', ',', ';', ':', '!', '?'])
                    .to_string();
                let _ = self.pseudonymize_hostname(&hname);
            }
        }

        // 6. Replay all known mapped usernames and hostnames across the text
        let mut known_users: Vec<(String, String)> = self
            .username_map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        known_users.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (uname, pseudo) in known_users {
            let pattern = if uname.chars().next().map_or(false, |c| c.is_alphanumeric())
                && uname.chars().last().map_or(false, |c| c.is_alphanumeric())
            {
                format!(r"(?i)\b{}\b", regex::escape(&uname))
            } else {
                format!(r"(?i){}", regex::escape(&uname))
            };
            if let Ok(token_re) = Regex::new(&pattern) {
                out = token_re.replace_all(&out, pseudo.as_str()).to_string();
            } else {
                out = out.replace(&uname, &pseudo);
            }
        }

        let mut known_hosts: Vec<(String, String)> = self
            .hostname_map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        known_hosts.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        for (hname, pseudo) in known_hosts {
            let pattern = if hname.chars().next().map_or(false, |c| c.is_alphanumeric())
                && hname.chars().last().map_or(false, |c| c.is_alphanumeric())
            {
                format!(r"(?i)\b{}\b", regex::escape(&hname))
            } else {
                format!(r"(?i){}", regex::escape(&hname))
            };
            if let Ok(token_re) = Regex::new(&pattern) {
                out = token_re.replace_all(&out, pseudo.as_str()).to_string();
            } else {
                out = out.replace(&hname, &pseudo);
            }
        }

        out
    }

    /// Normalizes a candidate trajectory before harvest staging.
    pub fn normalize_candidate(&mut self, candidate: &RawTrajectoryCandidate) -> RawTrajectoryCandidate {
        let mut cloned = candidate.clone();
        cloned.prompt = self.normalize_text(&cloned.prompt);
        cloned.chosen_response = self.normalize_text(&cloned.chosen_response);
        if let Some(ref rej) = cloned.rejected_response {
            cloned.rejected_response = Some(self.normalize_text(rej));
        }
        for step in &mut cloned.rlm_trajectory {
            step.sanitized_query_or_pattern = self.normalize_text(&step.sanitized_query_or_pattern);
            step.abstracted_takeaway = self.normalize_text(&step.abstracted_takeaway);
        }
        for (citation_slice, quote) in &mut cloned.citations {
            *citation_slice = self.normalize_text(citation_slice);
            *quote = self.normalize_text(quote);
        }
        cloned
    }

    /// Generates a live interactive preview for the WebUI.
    pub fn preview_normalization(&mut self, sample_text: &str) -> NormalizerPreview {
        let normalized = self.normalize_text(sample_text);
        let mut mappings = HashMap::new();
        mappings.extend(self.username_map.iter().map(|(k, v)| (format!("user:{}", k), v.clone())));
        mappings.extend(self.hostname_map.iter().map(|(k, v)| (format!("host:{}", k), v.clone())));
        mappings.extend(self.sid_map.iter().map(|(k, v)| (format!("sid:{}", k), v.clone())));
        mappings.extend(self.ip_map.iter().map(|(k, v)| (format!("ip:{}", k), v.clone())));
        mappings.extend(self.share_map.iter().map(|(k, v)| (format!("share:{}", k), v.clone())));
        mappings.extend(self.mac_map.iter().map(|(k, v)| (format!("mac:{}", k), v.clone())));

        let total = self.username_map.len()
            + self.hostname_map.len()
            + self.sid_map.len()
            + self.ip_map.len()
            + self.share_map.len()
            + self.mac_map.len();

        NormalizerPreview {
            original_text: sample_text.to_string(),
            normalized_text: normalized,
            usernames_replaced: self.username_map.len(),
            hostnames_replaced: self.hostname_map.len(),
            sids_replaced: self.sid_map.len(),
            ips_replaced: self.ip_map.len(),
            smb_shares_replaced: self.share_map.len(),
            macs_replaced: self.mac_map.len(),
            total_replacements: total,
            pseudonym_mappings: mappings,
        }
    }
}

/// Evaluates internal private IP addresses under Rule `<containment_ring_breakout_invariants.md>`.
pub fn is_internal_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 0.0.0.0/8 (unspecified)
            octets[0] == 0
            // 10.0.0.0/8 (RFC1918)
            || octets[0] == 10
            // 100.64.0.0/10 (CGNAT RFC6598)
            || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
            // 127.0.0.0/8 (loopback)
            || octets[0] == 127
            // 169.254.0.0/16 (link-local / cloud metadata)
            || (octets[0] == 169 && octets[1] == 254)
            // 172.16.0.0/12 (RFC1918)
            || (octets[0] == 172 && (octets[1] & 0xf0) == 16)
            // 192.168.0.0/16 (RFC1918)
            || (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            // :: (unspecified) or ::1 (loopback)
            v6.is_unspecified() || v6.is_loopback()
            // unique local IPv6 (fc00::/7)
            || ((seg[0] & 0xfe00) == 0xfc00)
            // link-local (fe80::/10)
            || ((seg[0] & 0xffc0) == 0xfe80)
            // IPv4-mapped IPv6 (::ffff:0:0/96)
            || (seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0xffff && {
                let v4 = std::net::Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                is_internal_private_ip(IpAddr::V4(v4))
            })
        }
    }
}

/// Gate enforcing strict allowlisting of forensic categories before staging marketplace batches.
#[derive(Debug, Clone)]
pub struct ArtifactCategoryGate {
    pub allowed_categories: HashSet<String>,
    pub prohibited_categories: HashSet<String>,
}

impl Default for ArtifactCategoryGate {
    fn default() -> Self {
        Self::new(&crate::artemis_airgap::default_allowed_categories())
    }
}

impl ArtifactCategoryGate {
    pub fn new(allowed: &[String]) -> Self {
        let allowed_categories: HashSet<String> = allowed
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .collect();
        let prohibited_categories: HashSet<String> = crate::artemis_airgap::prohibited_categories()
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        Self {
            allowed_categories,
            prohibited_categories,
        }
    }

    /// Evaluates candidate domain tags and paths for category compliance.
    pub fn evaluate_candidate(&self, candidate: &RawTrajectoryCandidate) -> Result<(), String> {
        for tag in &candidate.domain_tags {
            let lower = tag.trim().to_ascii_lowercase();
            if self.prohibited_categories.iter().any(|p| lower.contains(p) || p.contains(&lower)) {
                return Err(format!(
                    "Rejected by Category Gate: candidate contains prohibited category tag '{}'",
                    tag
                ));
            }
            if let Ok(t) = lower.parse::<quorum_contract::ForensicTelemetryType>() {
                if !t.is_marketplace_harvest_allowed() {
                    return Err(format!(
                        "Rejected by Category Gate: telemetry type '{}' is barred from marketplace harvest",
                        t.as_str()
                    ));
                }
            }
        }
        if let Some(ref path) = candidate.source_file_path {
            let p_lower = path.to_ascii_lowercase();
            for prohibited in &self.prohibited_categories {
                if p_lower.contains(prohibited) {
                    return Err(format!(
                        "Rejected by Category Gate: source path '{}' contains prohibited category '{}'",
                        path, prohibited
                    ));
                }
            }
            if p_lower.contains("cookie")
                || p_lower.contains("oauth")
                || p_lower.contains("credential")
                || p_lower.contains("/shadow")
                || p_lower.contains("\\shadow")
                || p_lower.ends_with("shadow")
                || p_lower.contains("/sam")
                || p_lower.contains("\\sam")
                || p_lower.ends_with("sam")
                || (!p_lower.ends_with(".evtx") && (
                    p_lower.contains("/config/security")
                    || p_lower.contains("\\config\\security")
                    || p_lower.contains("/security")
                    || p_lower.contains("\\security")
                    || p_lower.ends_with("security")
                ))
                || p_lower.contains("dpapi")
                || p_lower.contains("keychain")
                || p_lower.contains("consolehost_history")
                || p_lower.contains(".bash_history")
            {
                return Err(format!(
                    "Rejected by Category Gate: source path '{}' contains sensitive/prohibited artifact path pattern",
                    path
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalizer_pseudonymization_determinism() {
        let seed = [42u8; 32];
        let mut n1 = ForensicStructuralNormalizer::from_node_seed(&seed, "batch-1");
        let mut n2 = ForensicStructuralNormalizer::from_node_seed(&seed, "batch-1");

        let p1 = n1.pseudonymize_username("test_user");
        let p2 = n2.pseudonymize_username("test_user");
        assert_eq!(p1, p2);
        assert!(p1.starts_with("USER_"));
    }

    #[test]
    fn test_normalizer_session_isolation() {
        let seed = [42u8; 32];
        let mut n1 = ForensicStructuralNormalizer::from_node_seed(&seed, "batch-1");
        let mut n2 = ForensicStructuralNormalizer::from_node_seed(&seed, "batch-2");

        let p1 = n1.pseudonymize_username("test_user");
        let p2 = n2.pseudonymize_username("test_user");
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_preserved_system_entities() {
        let mut normalizer = ForensicStructuralNormalizer::new([7u8; 32]);
        assert_eq!(normalizer.pseudonymize_username("SYSTEM"), "SYSTEM");
        assert_eq!(normalizer.pseudonymize_username("root"), "root");
        assert_eq!(normalizer.pseudonymize_username("NT AUTHORITY\\SYSTEM"), "NT AUTHORITY\\SYSTEM");
        assert_eq!(normalizer.pseudonymize_hostname("localhost"), "localhost");
        assert_eq!(normalizer.pseudonymize_sid("S-1-5-18"), "S-1-5-18");
        assert_eq!(normalizer.pseudonymize_sid("S-1-5-32-544"), "S-1-5-32-544");
    }

    #[test]
    fn test_internal_ip_detection() {
        assert!(is_internal_private_ip("10.1.2.3".parse().unwrap()));
        assert!(is_internal_private_ip("192.168.1.100".parse().unwrap()));
        assert!(is_internal_private_ip("172.16.5.4".parse().unwrap()));
        assert!(is_internal_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_internal_private_ip("169.254.169.254".parse().unwrap()));
        assert!(is_internal_private_ip("100.64.0.1".parse().unwrap())); // CGNAT
        assert!(!is_internal_private_ip("8.8.8.8".parse().unwrap())); // Public
        assert!(!is_internal_private_ip("1.1.1.1".parse().unwrap())); // Public
    }

    #[test]
    fn test_category_gate_rejection() {
        let gate = ArtifactCategoryGate::default();
        let mut candidate = RawTrajectoryCandidate {
            record_id: "cand-1".to_string(),
            origin_node_id: "node-1".to_string(),
            format: quorum_contract::TrainingRecordFormat::DpoPreferencePair,
            domain_tags: vec!["browser_cookies".to_string()],
            prompt: "cookie dump".to_string(),
            rlm_trajectory: Vec::new(),
            chosen_response: "resp".to_string(),
            rejected_response: None,
            citations: Vec::new(),
            extra_redact_terms: Vec::new(),
            created_unix_secs: 100,
            source_file_path: None,
            interaction_nonce_hex: None,
        };
        assert!(gate.evaluate_candidate(&candidate).is_err());

        candidate.domain_tags = vec!["process_execution".to_string()];
        assert!(gate.evaluate_candidate(&candidate).is_ok());

        candidate.source_file_path = Some("C:\\Users\\admin\\AppData\\Chrome\\Cookies".to_string());
        assert!(gate.evaluate_candidate(&candidate).is_err());
    }
}
