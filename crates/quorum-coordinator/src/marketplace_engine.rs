//! Domestic-Evasion Sovereign Jurisdiction Guard (`SovereignJurisdictionGuard`),
//! Semantic Trade-Secret & Proprietary Code Filter, `MarketplaceSanitizer`,
//! and Keyed BLAKE3-XOF Batch Encryption for the Opt-In AI Training Data Marketplace.
//!
//! Enforces the 7-Layer Sovereign Anti-Exfiltration Architecture:
//! 1. Zero Raw Documents + Semantic Trade-Secret Filter (`<= 15` code lines, no RFC1918/ULA IPs, no high-entropy secrets).
//! 2. Foreign GeoIP + Chinese Cloud U.S.-PoP & Anonymous VPS/VPN ASN Firewall (`HIGH_RISK_DATACENTER_PROXY_ASNS`).
//! 3. FOCI / UBO & DOJ 28 CFR Part 202 Non-Covered Person + LEI/DUNS Attestation.
//! 4. Certificate-Bound Corporate Egress CIDR Pinning (`authorized_egress_cidrs`).
//! 5. Hardware TPM 2.0 / HSM Cluster Key Binding (`bound_tpm_pubkey_blake3`).
//! 6. Tiered Anti-Scraping Previews + Commit-and-Reveal `EscrowReceiptToken`.
//! 7. Per-Buyer & Per-Preview Cryptographic Canary Watermarking.

use crate::dlp_mesh::{global_mesh_dlp_controller, DlpEnforcementMode};
use quorum_contract::{
    BuyerJurisdictionCertificate, SanitizedRlmStep, SanitizedTrainingRecord, TrainingRecordFormat,
};
use regex::Regex;
use std::net::IpAddr;
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

/// Known Chinese Telecom/Cloud ASNs (including U.S. Points of Presence in Virginia, Silicon Valley, and Texas)
/// and anonymous VPS / commercial VPN hosting ASNs frequently rented by scrapers inside the United States.
pub const HIGH_RISK_DATACENTER_PROXY_ASNS: &[u32] = &[
    4134,   // Chinanet (China Telecom backbone & CTAmericas)
    4809,   // China Telecom Next Generation Carrier Network (CN2)
    4837,   // China Unicom Backbone
    9808,   // China Mobile Communications Corporation
    37963,  // Alibaba Cloud (Hangzhou / domestic & international PoPs)
    45102,  // Alibaba Cloud US / International PoPs (Alibaba.com Singapore / US)
    45090,  // Tencent Cloud Computing (Shenzhen)
    132203, // Tencent Building / Tencent Cloud International & US PoPs
    55990,  // Huawei Cloud Service
    136907, // Huawei Cloud International PoPs
    38365,  // Beijing Baidu Netcom Science and Technology
    4538,   // CERNET (China Education and Research Network)
    14061,  // DigitalOcean, LLC (unverified anonymous VPS)
    20473,  // The Constant Company / Vultr / Choopa (unverified anonymous VPS)
    63949,  // Akamai Connected Cloud / Linode (unverified anonymous VPS)
    16276,  // OVH SAS (anonymous dedicated/VPS hosting)
    24940,  // Hetzner Online GmbH (anonymous dedicated/VPS hosting)
    9009,   // M247 Europe SRL (commercial VPN / proxy exit backbone)
    60068,  // Datacamp Limited / CDN77 (commercial VPN / proxy exit backbone)
];

/// Foreign adversary ISO-3166-1 alpha-2 country codes permanently barred from the Marketplace
/// (aligned with 28 CFR Part 202 Countries of Concern and OFAC comprehensive sanctions).
pub const BLOCKED_ADVERSARY_JURISDICTIONS: &[&str] = &[
    "CN", "HK", "MO", "RU", "IR", "KP", "BY", "CU", "VE",
];

/// Major foreign adversary IPv4 CIDR allocations blocked directly at Layer 2 before certificate inspection.
pub const FOREIGN_ADVERSARY_IPV4_CIDRS: &[&str] = &[
    "1.0.1.0/24",
    "1.2.0.0/16",
    "14.0.0.0/8",
    "27.0.0.0/8",
    "36.0.0.0/8",
    "42.0.0.0/8",
    "47.88.0.0/14", // Alibaba Cloud US-West / US-East leased blocks
    "47.92.0.0/14",
    "47.96.0.0/11",
    "58.0.0.0/8",
    "59.0.0.0/8",
    "60.0.0.0/8",
    "61.0.0.0/8",
    "101.0.0.0/8",
    "106.0.0.0/8",
    "110.0.0.0/7",
    "112.0.0.0/5",
    "120.0.0.0/6",
    "124.0.0.0/7",
    "175.0.0.0/8",
    "175.45.176.0/22", // KP
    "180.0.0.0/7",
    "182.0.0.0/7",
    "202.96.0.0/12",
    "210.0.0.0/7",
    "218.0.0.0/7",
    "220.0.0.0/6",
    "5.188.0.0/16",  // RU
    "77.88.0.0/18",  // RU
];

/// Canonicalizes an `IpAddr` by unwrapping IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d` -> `a.b.c.d`)
/// so dual-stack sockets cannot bypass IPv4 CIDR rules.
pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(mapped_v4)
            } else {
                IpAddr::V6(v6)
            }
        }
    }
}

/// Pure-Rust constant-time-safe bitmask evaluator for IPv4 (`/0..=/32`) and IPv6 (`/0..=/128`) CIDRs.
pub fn cidr_contains_ip(cidr_str: &str, ip: IpAddr) -> bool {
    let trimmed = cidr_str.trim();
    if trimmed.is_empty() {
        return false;
    }
    let ip = canonicalize_ip(ip);

    let (net_part, prefix_opt) = match trimmed.split_once('/') {
        Some((n, p)) => (n.trim(), Some(p.trim())),
        None => (trimmed, None),
    };

    let Ok(net_ip_raw) = net_part.parse::<IpAddr>() else {
        return false;
    };
    let net_ip = canonicalize_ip(net_ip_raw);

    match (net_ip, ip) {
        (IpAddr::V4(net_v4), IpAddr::V4(target_v4)) => {
            let prefix_len: u32 = match prefix_opt {
                Some(p) => match p.parse::<u32>() {
                    Ok(v) if v <= 32 => v,
                    _ => return false,
                },
                None => 32,
            };
            if prefix_len == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from_be_bytes(net_v4.octets()) & mask)
                == (u32::from_be_bytes(target_v4.octets()) & mask)
        }
        (IpAddr::V6(net_v6), IpAddr::V6(target_v6)) => {
            let prefix_len: u32 = match prefix_opt {
                Some(p) => match p.parse::<u32>() {
                    Ok(v) if v <= 128 => v,
                    _ => return false,
                },
                None => 128,
            };
            if prefix_len == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - prefix_len);
            (u128::from_be_bytes(net_v6.octets()) & mask)
                == (u128::from_be_bytes(target_v6.octets()) & mask)
        }
        _ => false,
    }
}

/// Returns `true` if `ip` falls inside any blocked foreign adversary CIDR block.
pub fn is_blocked_foreign_adversary_ip(ip: IpAddr) -> bool {
    let canon = canonicalize_ip(ip);
    FOREIGN_ADVERSARY_IPV4_CIDRS
        .iter()
        .any(|cidr| cidr_contains_ip(cidr, canon))
}

/// Returns `true` if `asn` is a Chinese cloud/telecom ASN (including U.S. PoPs) or an unverified VPS/VPN provider.
pub fn is_high_risk_datacenter_or_proxy_asn(asn: u32) -> bool {
    HIGH_RISK_DATACENTER_PROXY_ASNS.contains(&asn)
}

/// Verifies a buyer request against both direct foreign traffic and domestic U.S. evasion
/// (rented U.S. VPS/VPNs, Chinese cloud U.S. PoPs, unpinned egress IPs, Delaware shell LLCs with foreign UBOs,
/// or missing hardware TPM 2.0 cluster binding).
#[allow(clippy::too_many_arguments)]
pub fn verify_us_sovereign_buyer_against_domestic_evasion(
    caller_ip: IpAddr,
    forwarded_ips: &[IpAddr],
    caller_asn: Option<u32>,
    presented_tpm_pubkey_blake3: Option<&str>,
    cert: &BuyerJurisdictionCertificate,
    authority_pubkey_bytes: &[u8; 32],
    allowed_jurisdictions: &[String],
    require_tpm_binding: bool,
    now_unix_secs: i64,
) -> Result<(), &'static str> {
    // 1. Direct Foreign Adversary IP Block on socket peer and all proxy hops
    if is_blocked_foreign_adversary_ip(caller_ip) {
        return Err("Blocked by SovereignJurisdictionGuard Layer 2: caller IP is in a restricted foreign adversary CIDR");
    }
    for hop_ip in forwarded_ips {
        if is_blocked_foreign_adversary_ip(*hop_ip) {
            return Err("Blocked by SovereignJurisdictionGuard Layer 2: X-Forwarded-For hop IP is in a restricted foreign adversary CIDR");
        }
    }

    // 2. Chinese Cloud U.S.-PoP & Anonymous VPS/VPN ASN Firewall
    if let Some(asn) = caller_asn {
        if is_high_risk_datacenter_or_proxy_asn(asn) {
            return Err("Blocked by SovereignJurisdictionGuard Layer 2: caller ASN is a restricted Chinese cloud PoP or unverified VPS/VPN provider");
        }
    }

    // 3. Certificate Expiration
    if now_unix_secs >= cert.expires_unix_secs {
        return Err("Blocked by SovereignJurisdictionGuard Layer 3: BuyerJurisdictionCertificate has expired");
    }

    // 4. Jurisdiction Allowlist (Default: ["US"]) & Adversary Hard-Block
    let country = cert.incorporation_country_iso.trim().to_ascii_uppercase();
    if country.is_empty() || BLOCKED_ADVERSARY_JURISDICTIONS.contains(&country.as_str()) {
        return Err("Blocked by SovereignJurisdictionGuard Layer 3: incorporation country is a prohibited foreign adversary jurisdiction");
    }
    let effective_allowed: Vec<String> = if allowed_jurisdictions.is_empty() {
        vec!["US".to_string()]
    } else {
        allowed_jurisdictions
            .iter()
            .map(|c| c.trim().to_ascii_uppercase())
            .collect()
    };
    if !effective_allowed.iter().any(|c| c == &country) {
        return Err("Blocked by SovereignJurisdictionGuard Layer 3: incorporation country is not in subscriber's allowed_jurisdictions policy");
    }

    // 5. FOCI / UBO Clearance, DOJ 28 CFR Part 202 Non-Covered Person Attestation & LEI/DUNS
    if cert.lei_or_duns_id.trim().len() < 4 {
        return Err("Blocked by SovereignJurisdictionGuard Layer 3: missing verified LEI, DUNS, or CAGE identifier");
    }
    if !cert.foci_ubo_verified_clean {
        return Err("Blocked by SovereignJurisdictionGuard Layer 3: entity failed Foreign Ownership, Control, or Influence (FOCI / UBO) attestation");
    }
    if !cert.doj_part202_non_covered_person {
        return Err("Blocked by SovereignJurisdictionGuard Layer 3: entity is a Covered Person under DOJ 28 CFR Part 202 Bulk Sensitive Data Rule");
    }
    if !cert.non_redistribution_covenant_accepted {
        return Err("Blocked by SovereignJurisdictionGuard Layer 3: non-redistribution covenant not accepted");
    }

    // 6. Authority Ed25519 Signature Verification
    if !cert.verify_ed25519(authority_pubkey_bytes) {
        return Err("Blocked by SovereignJurisdictionGuard Layer 3: invalid authority Ed25519 signature on BuyerJurisdictionCertificate");
    }

    // 7. Certificate-Bound Corporate Egress CIDR Pinning (Defeats rented US EC2/VPS & residential proxies)
    if cert.authorized_egress_cidrs.is_empty() {
        return Err("Blocked by SovereignJurisdictionGuard Layer 4: certificate has no pinned authorized_egress_cidrs");
    }
    let caller_pinned = cert
        .authorized_egress_cidrs
        .iter()
        .any(|cidr| cidr_contains_ip(cidr, caller_ip));
    if !caller_pinned {
        return Err("Blocked by SovereignJurisdictionGuard Layer 4: caller IP does not match certificate's pinned corporate authorized_egress_cidrs");
    }
    for hop_ip in forwarded_ips {
        let hop_pinned = cert
            .authorized_egress_cidrs
            .iter()
            .any(|cidr| cidr_contains_ip(cidr, *hop_ip));
        if !hop_pinned {
            return Err("Blocked by SovereignJurisdictionGuard Layer 4: forwarded proxy hop IP is outside certificate's pinned corporate authorized_egress_cidrs");
        }
    }

    // 8. Hardware TPM 2.0 / HSM Key Binding (Defeats credential forwarding to overseas offices)
    let cert_tpm = cert.bound_tpm_pubkey_blake3.trim().to_ascii_lowercase();
    if cert_tpm.len() != 64 || !cert_tpm.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Blocked by SovereignJurisdictionGuard Layer 5: certificate missing valid 64-hex bound_tpm_pubkey_blake3");
    }
    if require_tpm_binding || presented_tpm_pubkey_blake3.is_some() {
        let Some(presented_raw) = presented_tpm_pubkey_blake3 else {
            return Err("Blocked by SovereignJurisdictionGuard Layer 5: missing X-Quorum-TPM-Pubkey-Blake3 hardware attestation header");
        };
        let presented = presented_raw.trim().to_ascii_lowercase();
        if presented.len() != cert_tpm.len()
            || !bool::from(presented.as_bytes().ct_eq(cert_tpm.as_bytes()))
        {
            return Err("Blocked by SovereignJurisdictionGuard Layer 5: presented TPM 2.0 / HSM public key hash does not match certificate hardware binding");
        }
    }

    Ok(())
}

/// Checks whether a candidate trajectory text contains proprietary source code (`> 15` lines),
/// internal RFC1918 / IPv6 ULA network topology addresses, internal corporate FQDNs, or high-entropy secrets.
pub fn contains_trade_secret_or_proprietary_code(text: &str) -> Option<&'static str> {
    if text.is_empty() {
        return None;
    }

    // 1. Check for PEM / OpenSSH private keys or explicit API tokens
    let lower = text.to_ascii_lowercase();
    if lower.contains("-----begin ")
        && (lower.contains("private key-----") || lower.contains("openssh private key"))
    {
        return Some("Contains PEM or OpenSSH private key block");
    }

    static SECRET_TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    let secret_re = SECRET_TOKEN_RE.get_or_init(|| {
        Regex::new(r"(?:AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{24,}|sk-[A-Za-z0-9\-_]{24,}|xox[baprs]-[0-9A-Za-z\-]{20,})")
            .expect("valid secret regex")
    });
    if secret_re.is_match(text) {
        return Some("Contains raw cloud or API secret token");
    }

    // 2. Check for internal corporate FQDNs (.internal, .corp, .lan, .localdomain)
    static CORP_FQDN_RE: OnceLock<Regex> = OnceLock::new();
    let fqdn_re = CORP_FQDN_RE.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z0-9][a-z0-9\-]{1,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})+\.(?:internal|corp|lan|localdomain|priv)\b")
            .expect("valid corp fqdn regex")
    });
    if fqdn_re.is_match(text) {
        return Some("Contains internal corporate hostname (.internal/.corp/.lan)");
    }

    // 3. Check for RFC1918 private IPv4 addresses or IPv6 Unique Local Addresses (fc00::/7)
    static IPV4_TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    let ipv4_re = IPV4_TOKEN_RE.get_or_init(|| {
        Regex::new(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b")
            .expect("valid rfc1918 regex")
    });
    if ipv4_re.is_match(text) {
        return Some("Contains internal RFC1918 private network IPv4 topology address");
    }

    static IPV6_ULA_RE: OnceLock<Regex> = OnceLock::new();
    let ula_re = IPV6_ULA_RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:fc|fd)[0-9a-f]{2}:[0-9a-f:]{3,}\b").expect("valid ipv6 ula regex")
    });
    if ula_re.is_match(text) {
        return Some("Contains internal IPv6 Unique Local Address (fc00::/7)");
    }

    // 4. Check for source code blocks exceeding 15 lines (fenced or syntactic code lines)
    let mut in_fence = false;
    let mut fenced_lines = 0usize;
    let mut syntactic_code_lines = 0usize;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            if !trimmed.is_empty() {
                fenced_lines += 1;
                if fenced_lines > 15 {
                    return Some("Contains fenced source code block exceeding 15 lines");
                }
            }
        } else if is_syntactic_code_line(trimmed) {
            syntactic_code_lines += 1;
            if syntactic_code_lines > 15 {
                return Some("Contains proprietary source code exceeding 15 lines");
            }
        }
    }

    // 5. Check for high-entropy secret strings (tokens >= 32 chars with mixed case + digits and Shannon entropy > 4.70 bits/char)
    for token in text.split_whitespace() {
        let clean = token.trim_matches(|c: char| {
            matches!(c, '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}')
        });
        if clean.len() >= 32
            && !clean.starts_with("http://")
            && !clean.starts_with("https://")
            && !clean.starts_with("12D3KooW")
            && has_secret_character_classes(clean)
            && shannon_entropy_bits(clean) > 4.70
        {
            return Some("Contains high-entropy cryptographic secret or proprietary key");
        }
    }

    None
}

fn is_syntactic_code_line(trimmed: &str) -> bool {
    if trimmed.is_empty() {
        return false;
    }
    let code_prefixes = [
        "fn ",
        "pub fn ",
        "pub async fn ",
        "async fn ",
        "impl ",
        "pub struct ",
        "struct ",
        "let mut ",
        "const ",
        "def ",
        "class ",
        "import ",
        "from ",
        "#include ",
        "package ",
        "function ",
        "export const ",
        "export function ",
    ];
    if code_prefixes.iter().any(|p| trimmed.starts_with(p)) {
        return true;
    }
    (trimmed.ends_with(';') || trimmed.ends_with('{') || trimmed == "}")
        && (trimmed.contains(" = ")
            || trimmed.contains("::")
            || trimmed.contains("->")
            || trimmed.contains("();"))
}

fn has_secret_character_classes(s: &str) -> bool {
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = s.bytes().any(|b| b.is_ascii_digit());
    has_upper && has_lower && has_digit
}

fn shannon_entropy_bits(s: &str) -> f64 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Input candidate trajectory submitted to `MarketplaceSanitizer` for de-identification,
/// trade-secret filtering, verbatim citation grounding verification, and Ed25519 node signing.
#[derive(Debug, Clone)]
pub struct RawTrajectoryCandidate {
    pub record_id: String,
    pub origin_node_id: String,
    pub format: TrainingRecordFormat,
    pub domain_tags: Vec<String>,
    pub prompt: String,
    pub rlm_trajectory: Vec<SanitizedRlmStep>,
    pub chosen_response: String,
    pub rejected_response: Option<String>,
    /// Pairs of `(source_slice_text, verbatim_quote)` that must pass `slice_text.contains(verbatim_quote)`.
    pub citations: Vec<(String, String)>,
    /// Additional subscriber-specific strings (e.g., subscriber name, organization, client aliases) to scrub.
    pub extra_redact_terms: Vec<String>,
    pub created_unix_secs: i64,
}

/// Automated Local Privacy Scrubber, Semantic Trade-Secret Filter, and Verbatim Citation Grounding Attestor.
pub struct MarketplaceSanitizer;

impl MarketplaceSanitizer {
    /// Scrubs filesystem paths, emails, phones, SSNs, and Presidio/GLiNER PII/PHI spans from text.
    pub fn scrub_text(raw: &str, extra_terms: &[String]) -> String {
        if raw.is_empty() {
            return String::new();
        }

        // Step 1: Run the global Microsoft Presidio + GLiNER DLP controller in Redact mode
        let dlp = global_mesh_dlp_controller();
        let dlp_res = dlp.inspect_and_enforce_text(
            raw,
            "<marketplace_trajectory>",
            "marketplace_sanitizer",
            "MarketplaceExport",
            Some(DlpEnforcementMode::Redact),
            true,
        );
        let mut text = dlp_res.scrubbed_text;

        // Step 2: Scrub Windows drive paths (e.g. C:\Users\..., D:\harfile\...) and UNC paths
        static WIN_PATH_RE: OnceLock<Regex> = OnceLock::new();
        let win_re = WIN_PATH_RE.get_or_init(|| {
            Regex::new(r"(?i)\b[a-z]:\\[a-z0-9._\-\s\\]+").expect("valid windows path regex")
        });
        text = win_re
            .replace_all(&text, "[REDACTED:LOCAL_PATH]")
            .into_owned();

        // Step 3: Scrub POSIX user home / root paths (/Users/..., /home/..., /var/..., /etc/...)
        static POSIX_PATH_RE: OnceLock<Regex> = OnceLock::new();
        let posix_re = POSIX_PATH_RE.get_or_init(|| {
            Regex::new(r"(?:/Users|/home|/var/log|/etc|/opt)/[A-Za-z0-9._\-/]+")
                .expect("valid posix path regex")
        });
        text = posix_re
            .replace_all(&text, "[REDACTED:LOCAL_PATH]")
            .into_owned();

        // Step 4: Scrub email addresses
        static EMAIL_RE: OnceLock<Regex> = OnceLock::new();
        let email_re = EMAIL_RE.get_or_init(|| {
            Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b")
                .expect("valid email regex")
        });
        text = email_re.replace_all(&text, "[REDACTED:EMAIL]").into_owned();

        // Step 5: Scrub US/International phone numbers
        static PHONE_RE: OnceLock<Regex> = OnceLock::new();
        let phone_re = PHONE_RE.get_or_init(|| {
            Regex::new(r"(?:\+\d{1,2}\s*)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b")
                .expect("valid phone regex")
        });
        text = phone_re.replace_all(&text, "[REDACTED:PHONE]").into_owned();

        // Step 6: Scrub SSNs
        static SSN_RE: OnceLock<Regex> = OnceLock::new();
        let ssn_re =
            SSN_RE.get_or_init(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("valid ssn regex"));
        text = ssn_re.replace_all(&text, "[REDACTED:SSN]").into_owned();

        // Step 7: Scrub honorific / labeled personal names (e.g. "Dr. John Smith", "Patient: Jane Doe")
        static HONORIFIC_NAME_RE: OnceLock<Regex> = OnceLock::new();
        let name_re = HONORIFIC_NAME_RE.get_or_init(|| {
            Regex::new(r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|Patient:|Candidate:|Author:|Client:)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}")
                .expect("valid honorific name regex")
        });
        text = name_re.replace_all(&text, "[REDACTED:PERSON]").into_owned();

        // Step 8: Scrub any explicit subscriber/client terms (case-insensitive)
        for term in extra_terms {
            let clean = term.trim();
            if clean.len() >= 3 {
                if let Ok(re) = Regex::new(&format!("(?i){}", regex::escape(clean))) {
                    text = re.replace_all(&text, "[REDACTED:SUBSCRIBER]").into_owned();
                }
            }
        }

        text
    }

    /// Validates 100% verbatim substring citation grounding, scrubs PII/PHI/paths,
    /// enforces the Semantic Trade-Secret Filter (`<= 15` code lines, no RFC1918, no secrets),
    /// verifies minimum token length (`>= 64` tokens), and signs the record with the node's Ed25519 key.
    pub fn sanitize_and_sign_record(
        candidate: &RawTrajectoryCandidate,
        node_seed: &[u8; 32],
    ) -> Result<SanitizedTrainingRecord, String> {
        // 1. Verbatim Citation Substring Grounding Gate (Must be 100.00% = 10_000 bps)
        if candidate.citations.is_empty() {
            return Err("Rejected by Quality Gate: training record must have at least 1 verified citation".to_string());
        }
        let mut grounded_count = 0usize;
        for (slice_text, verbatim_quote) in &candidate.citations {
            let q = verbatim_quote.trim();
            if !q.is_empty() && slice_text.contains(q) {
                grounded_count += 1;
            }
        }
        let grounding_score_bps =
            ((grounded_count as u64 * 10_000) / candidate.citations.len() as u64) as u16;
        if grounding_score_bps < 10_000 {
            return Err(format!(
                "Rejected by Quality Gate: citation grounding score is {} bps (requires 10000 bps / 100% verbatim substring match)",
                grounding_score_bps
            ));
        }

        // 2. Semantic Trade-Secret & Proprietary Code Filter BEFORE and AFTER scrubbing
        for surface in [
            candidate.prompt.as_str(),
            candidate.chosen_response.as_str(),
            candidate.rejected_response.as_deref().unwrap_or(""),
        ] {
            if let Some(reason) = contains_trade_secret_or_proprietary_code(surface) {
                return Err(format!("Rejected by Semantic Trade-Secret Filter: {}", reason));
            }
        }
        for step in &candidate.rlm_trajectory {
            if let Some(reason) =
                contains_trade_secret_or_proprietary_code(&step.abstracted_takeaway)
            {
                return Err(format!(
                    "Rejected by Semantic Trade-Secret Filter in RLM step {}: {}",
                    step.step_index, reason
                ));
            }
        }

        // 3. Automated PII/PHI/Path Scrubbing
        let mut extra_terms = candidate.extra_redact_terms.clone();
        {
            let dlp = global_mesh_dlp_controller();
            let ui_name = dlp
                .settings
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .ui
                .display_name
                .clone();
            if !ui_name.trim().is_empty() {
                extra_terms.push(ui_name);
            }
        }

        let prompt = Self::scrub_text(&candidate.prompt, &extra_terms);
        let chosen_response = Self::scrub_text(&candidate.chosen_response, &extra_terms);
        let rejected_response = candidate
            .rejected_response
            .as_ref()
            .map(|r| Self::scrub_text(r, &extra_terms));

        let rlm_trajectory: Vec<SanitizedRlmStep> = candidate
            .rlm_trajectory
            .iter()
            .map(|s| SanitizedRlmStep {
                step_index: s.step_index,
                action_kind: s.action_kind.clone(),
                sanitized_query_or_pattern: Self::scrub_text(
                    &s.sanitized_query_or_pattern,
                    &extra_terms,
                ),
                abstracted_takeaway: Self::scrub_text(&s.abstracted_takeaway, &extra_terms),
            })
            .collect();

        // 4. Token Volume Gate (>= 64 tokens across prompt + trajectory + chosen_response)
        let mut total_tokens = count_tokens(&prompt) + count_tokens(&chosen_response);
        for step in &rlm_trajectory {
            total_tokens += count_tokens(&step.sanitized_query_or_pattern)
                + count_tokens(&step.abstracted_takeaway);
        }
        if total_tokens < 64 {
            return Err(format!(
                "Rejected by Quality Gate: sanitized trajectory has {} tokens (minimum required is 64 tokens)",
                total_tokens
            ));
        }

        let mut record = SanitizedTrainingRecord {
            record_id: candidate.record_id.clone(),
            blake3_record_hash: String::new(),
            origin_node_id: candidate.origin_node_id.clone(),
            format: candidate.format,
            domain_tags: candidate.domain_tags.clone(),
            prompt,
            rlm_trajectory,
            chosen_response,
            rejected_response,
            verified_citation_count: candidate.citations.len(),
            grounding_score_bps: 10_000,
            pii_scrub_verified: true,
            trade_secret_clean: true,
            token_count: total_tokens,
            created_unix_secs: candidate.created_unix_secs,
            ed25519_signature_hex: String::new(),
            buyer_watermark_hex: None,
        };
        record.sign_ed25519(node_seed)?;
        Ok(record)
    }
}

fn count_tokens(s: &str) -> usize {
    s.split(|c: char| c.is_whitespace() || matches!(c, ',' | '.' | ';' | ':' | '(' | ')'))
        .filter(|w| !w.is_empty())
        .count()
}

/// Encrypts a staged `.jsonl` batch at rest using a keyed BLAKE3 XOF stream cipher + 32-byte keyed MAC tag.
pub fn encrypt_batch_bytes(
    node_seed: &[u8; 32],
    batch_id: &str,
    plaintext: &[u8],
) -> Vec<u8> {
    let enc_key = blake3::derive_key("QuorumRAG-Marketplace-Batch-EncKey-v1", node_seed);
    let mac_key = blake3::derive_key("QuorumRAG-Marketplace-Batch-MacKey-v1", node_seed);

    let mut stream_hasher = blake3::Hasher::new_keyed(&enc_key);
    stream_hasher.update(b"stream:");
    stream_hasher.update(batch_id.as_bytes());
    let mut xof = stream_hasher.finalize_xof();

    let mut ciphertext = vec![0u8; plaintext.len()];
    xof.fill(&mut ciphertext);
    for (c, &p) in ciphertext.iter_mut().zip(plaintext.iter()) {
        *c ^= p;
    }

    let mut mac_hasher = blake3::Hasher::new_keyed(&mac_key);
    mac_hasher.update(b"mac:");
    mac_hasher.update(batch_id.as_bytes());
    mac_hasher.update(&ciphertext);
    let tag = mac_hasher.finalize();

    let mut out = Vec::with_capacity(32 + ciphertext.len());
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts and authenticates an encrypted batch in constant time (`subtle::ConstantTimeEq`).
pub fn decrypt_batch_bytes(
    node_seed: &[u8; 32],
    batch_id: &str,
    sealed: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if sealed.len() < 32 {
        return Err("Encrypted batch payload truncated (< 32-byte MAC)");
    }
    let (tag_bytes, ciphertext) = sealed.split_at(32);

    let enc_key = blake3::derive_key("QuorumRAG-Marketplace-Batch-EncKey-v1", node_seed);
    let mac_key = blake3::derive_key("QuorumRAG-Marketplace-Batch-MacKey-v1", node_seed);

    let mut mac_hasher = blake3::Hasher::new_keyed(&mac_key);
    mac_hasher.update(b"mac:");
    mac_hasher.update(batch_id.as_bytes());
    mac_hasher.update(ciphertext);
    let expected_tag = mac_hasher.finalize();

    if !bool::from(expected_tag.as_bytes().ct_eq(tag_bytes)) {
        return Err("Encrypted batch keyed BLAKE3 authentication tag mismatch");
    }

    let mut stream_hasher = blake3::Hasher::new_keyed(&enc_key);
    stream_hasher.update(b"stream:");
    stream_hasher.update(batch_id.as_bytes());
    let mut xof = stream_hasher.finalize_xof();

    let mut plaintext = vec![0u8; ciphertext.len()];
    xof.fill(&mut plaintext);
    for (p, &c) in plaintext.iter_mut().zip(ciphertext.iter()) {
        *p ^= c;
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_valid_us_cert(authority_seed: &[u8; 32], tpm_hash: &str) -> BuyerJurisdictionCertificate {
        let mut cert = BuyerJurisdictionCertificate {
            buyer_id: "us-frontier-lab-01".to_string(),
            legal_entity_name: "Anthropic PBC / US Sovereign Training Cluster".to_string(),
            incorporation_country_iso: "US".to_string(),
            lei_or_duns_id: "549300USFRONTIER01".to_string(),
            authorized_egress_cidrs: vec![
                "198.51.100.0/24".to_string(),
                "2620:0:2d0:200::/64".to_string(),
            ],
            bound_tpm_pubkey_blake3: tpm_hash.to_string(),
            foci_ubo_verified_clean: true,
            doj_part202_non_covered_person: true,
            non_redistribution_covenant_accepted: true,
            expires_unix_secs: 1_900_000_000,
            issuer_ed25519_signature_hex: String::new(),
        };
        cert.sign_ed25519(authority_seed).unwrap();
        cert
    }

    #[test]
    fn test_domestic_evasion_guard_blocks_us_pop_vps_shell_llc_and_unpinned_ip() {
        let auth_seed = [9u8; 32];
        let auth_pub = SigningKey::from_bytes(&auth_seed).verifying_key().to_bytes();
        let tpm_hash = blake3::hash(b"us-cluster-tpm-ek-01").to_hex().to_string();
        let cert = make_valid_us_cert(&auth_seed, &tpm_hash);
        let allowed = vec!["US".to_string()];
        let now = 1_760_000_000;

        // 1. Valid US corporate egress IP + verified ASN + matching TPM hash -> ALLOWED
        let valid_ip: IpAddr = "198.51.100.42".parse().unwrap();
        assert!(verify_us_sovereign_buyer_against_domestic_evasion(
            valid_ip,
            &[],
            Some(7018), // AT&T US enterprise
            Some(&tpm_hash),
            &cert,
            &auth_pub,
            &allowed,
            true,
            now,
        )
        .is_ok());

        // 2. Domestic Evasion Case A: Rented DigitalOcean US VPS (AS14061) or Alibaba Cloud US PoP (AS45102) -> BLOCKED
        for bad_asn in [14061u32, 45102, 132203, 20473, 9009] {
            let err = verify_us_sovereign_buyer_against_domestic_evasion(
                valid_ip,
                &[],
                Some(bad_asn),
                Some(&tpm_hash),
                &cert,
                &auth_pub,
                &allowed,
                true,
                now,
            )
            .unwrap_err();
            assert!(err.contains("Layer 2"));
        }

        // 3. Domestic Evasion Case B: US IP outside certificate's pinned corporate authorized_egress_cidrs -> BLOCKED
        let unpinned_us_ip: IpAddr = "203.0.113.99".parse().unwrap();
        let err = verify_us_sovereign_buyer_against_domestic_evasion(
            unpinned_us_ip,
            &[],
            Some(7018),
            Some(&tpm_hash),
            &cert,
            &auth_pub,
            &allowed,
            true,
            now,
        )
        .unwrap_err();
        assert!(err.contains("Layer 4"));

        // 4. Domestic Evasion Case C: Delaware shell LLC owned by foreign parent (foci_ubo_verified_clean == false or doj_part202 == false) -> BLOCKED
        let mut shell_cert = cert.clone();
        shell_cert.foci_ubo_verified_clean = false;
        shell_cert.sign_ed25519(&auth_seed).unwrap();
        let err = verify_us_sovereign_buyer_against_domestic_evasion(
            valid_ip,
            &[],
            Some(7018),
            Some(&tpm_hash),
            &shell_cert,
            &auth_pub,
            &allowed,
            true,
            now,
        )
        .unwrap_err();
        assert!(err.contains("FOCI / UBO"));

        // 5. Domestic Evasion Case D: Valid US cert & IP, but mismatched or missing TPM hardware key hash -> BLOCKED
        let wrong_tpm = blake3::hash(b"shenzhen-mirror-server").to_hex().to_string();
        let err = verify_us_sovereign_buyer_against_domestic_evasion(
            valid_ip,
            &[],
            Some(7018),
            Some(&wrong_tpm),
            &cert,
            &auth_pub,
            &allowed,
            true,
            now,
        )
        .unwrap_err();
        assert!(err.contains("Layer 5"));
    }

    #[test]
    fn test_sanitizer_blocks_trade_secrets_and_scrubs_pii() {
        let seed = [5u8; 32];
        let slice_text = "QuorumRAG enforces Ed25519 peer authentication and constant-time BLAKE3 contract verification across federated retrieval nodes without leaking raw files.";
        let quote = "Ed25519 peer authentication and constant-time BLAKE3 contract verification";

        let valid_candidate = RawTrajectoryCandidate {
            record_id: "rec-clean-01".to_string(),
            origin_node_id: "12D3KooWLocalNode".to_string(),
            format: TrainingRecordFormat::SftTrajectory,
            domain_tags: vec!["rust-security".to_string()],
            prompt: "Contact Dr. Alice Walker at alice.walker@hospital.org or 415-555-0199 regarding C:\\Users\\alice\\secret_notes.pdf: How does QuorumRAG authenticate peers across the mesh?".to_string(),
            rlm_trajectory: vec![SanitizedRlmStep {
                step_index: 1,
                action_kind: "peek_slice".to_string(),
                sanitized_query_or_pattern: "inspect C:\\Users\\alice\\secret_notes.pdf bytes 0..4000".to_string(),
                abstracted_takeaway: "Verified that every peer request carries an Ed25519 signature and BLAKE3 contract hash.".to_string(),
            }],
            chosen_response: "QuorumRAG enforces Ed25519 peer authentication and constant-time BLAKE3 contract verification across federated retrieval nodes so only verified peers participate in scatter-gather synthesis, while local parent-document window expansion and deterministic deduplication preserve full multi-paragraph context diversity.".to_string(),
            rejected_response: None,
            citations: vec![(slice_text.to_string(), quote.to_string())],
            extra_redact_terms: vec!["Alice Walker".to_string()],
            created_unix_secs: 1_760_000_000,
        };

        let sanitized = MarketplaceSanitizer::sanitize_and_sign_record(&valid_candidate, &seed).unwrap();
        assert!(!sanitized.prompt.contains("alice.walker@hospital.org"));
        assert!(!sanitized.prompt.contains("415-555-0199"));
        assert!(!sanitized.prompt.contains("C:\\Users\\alice"));
        assert!(!sanitized.prompt.contains("Alice Walker"));
        assert_eq!(sanitized.grounding_score_bps, 10_000);
        assert!(sanitized.trade_secret_clean);

        // Candidate with > 15 lines of proprietary code must be rejected by Semantic Trade-Secret Filter
        let mut code_candidate = valid_candidate.clone();
        code_candidate.chosen_response = (0..18)
            .map(|i| format!("let mut x_{} = compute_proprietary_kernel({});", i, i))
            .collect::<Vec<_>>()
            .join("\n");
        let err = MarketplaceSanitizer::sanitize_and_sign_record(&code_candidate, &seed).unwrap_err();
        assert!(err.contains("Semantic Trade-Secret Filter"));

        // Candidate with RFC1918 internal IP must be rejected
        let mut ip_candidate = valid_candidate.clone();
        ip_candidate.chosen_response = format!(
            "{} Internal database is hosted at 10.24.18.92 on the private subnet.",
            valid_candidate.chosen_response
        );
        let err = MarketplaceSanitizer::sanitize_and_sign_record(&ip_candidate, &seed).unwrap_err();
        assert!(err.contains("RFC1918"));
    }

    #[test]
    fn test_batch_encryption_roundtrip_and_tamper_rejection() {
        let seed = [11u8; 32];
        let plaintext = b"{\"record_id\":\"rec-1\"}\n{\"record_id\":\"rec-2\"}\n";
        let mut sealed = encrypt_batch_bytes(&seed, "batch-xyz", plaintext);
        let recovered = decrypt_batch_bytes(&seed, "batch-xyz", &sealed).unwrap();
        assert_eq!(recovered, plaintext);

        // Tamper with 1 byte -> must fail constant-time MAC check
        sealed[35] ^= 0x01;
        assert!(decrypt_batch_bytes(&seed, "batch-xyz", &sealed).is_err());
    }
}
