//! Pre-index secret redaction engine for Artemis DFIR forensic telemetry.
//!
//! Provides two complementary layers of secret scrubbing:
//! 1. **Regex Redactor**: Targets known credential formats including Bearer tokens,
//!    OpenAI/Anthropic/GitHub/AWS/Slack/Google API keys, PEM private keys, database
//!    connection URIs, CLI password flags, and environment variable assignments.
//! 2. **Shannon Entropy Detector**: Detects cryptographically dense secret tokens
//!    ($H > 4.20$ bits/character for length $\ge 16$) with mixed character classes,
//!    while exempting URIs, UUIDs, filesystem paths, and normal prose.

use regex::Regex;
use std::sync::LazyLock;
use uuid::Uuid;

static RE_BEARER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)bearer\s+[A-Za-z0-9_\-\.]{16,}").expect("valid bearer regex")
});

static RE_OPENAI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"sk-[A-Za-z0-9_-]{20,}").expect("valid openai regex")
});

static RE_ANTHROPIC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").expect("valid anthropic regex")
});

static RE_GITHUB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").expect("valid github regex")
});

static RE_AWS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid aws regex")
});

static RE_SLACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"xox[baprs]-[0-9a-zA-Z-]{10,}").expect("valid slack regex")
});

static RE_GOOGLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"AIza[0-9A-Za-z-_]{35,}").expect("valid google api regex")
});

static RE_PEM_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        .expect("valid pem private key regex")
});

static RE_DB_URI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:postgres|postgresql|mysql|mongodb|redis|mssql|amqp|couchdb)://[^:\s]+:[^@\s]+@[^\s]+")
        .expect("valid db uri regex")
});

static RE_CLI_PASSWORD_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(--?[A-Za-z0-9_]*(?:password|passwd|pass|pwd|secret|token|api-key|apikey|auth-token)[A-Za-z0-9_-]*|-p|/p:)[=\s]+(?:["']([^"']+)["']|([^\s"']+))"#)
        .expect("valid cli password flag regex")
});

static RE_CLI_P_ADJACENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|\s)-p([A-Za-z0-9!@#$%^&*()_+=~`\-]{6,})(\s|$)")
        .expect("valid adjacent -p flag regex")
});

static RE_ENV_VAR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)([A-Za-z0-9_]*(?:PASSWORD|PASSWD|PASS|PWD|SECRET|TOKEN|API_KEY|APIKEY|AUTH_TOKEN|ACCESS_KEY|PRIVATE_KEY)[A-Za-z0-9_]*)=(?:["']([^"']+)["']|([^\s"']+))"#)
        .expect("valid env var regex")
});

/// Computes Shannon entropy in bits per character:
/// $$H = -\sum_{i=1}^{n} p_i \log_2(p_i)$$
pub fn shannon_entropy_bits(s: &str) -> f64 {
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

/// Checks whether a token contains at least two distinct character classes:
/// uppercase letters, lowercase letters, digits, and special characters.
pub fn has_mixed_classes(token: &str) -> bool {
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_special = false;
    for ch in token.chars() {
        if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if ch.is_ascii_lowercase() {
            has_lower = true;
        } else if ch.is_ascii_digit() {
            has_digit = true;
        } else {
            has_special = true;
        }
    }
    let classes = (has_upper as u8) + (has_lower as u8) + (has_digit as u8) + (has_special as u8);
    classes >= 2
}

/// Checks whether a token is a UUID, filesystem path, or network URI
/// that should be exempted from entropy-based secret scrubbing.
pub fn is_uuid_or_path(s: &str) -> bool {
    if Uuid::parse_str(s).is_ok() {
        return true;
    }
    if s.contains('\\') || s.contains('/') {
        return true;
    }
    if s.starts_with("http://") || s.starts_with("https://") || s.starts_with("artemis://") {
        return true;
    }
    false
}

fn is_port_spec(part: &str) -> bool {
    if part.is_empty() {
        return false;
    }
    part.split('-')
        .all(|sub| !sub.is_empty() && sub.chars().all(|c| c.is_ascii_digit()))
}

/// Checks whether a token is purely numeric or a valid port/Docker port mapping
/// (e.g. "8080", "8080:8080", "127.0.0.1:8080:8080", "0.0.0.0:443:443", "8080:8080/tcp", "8080/udp").
pub fn is_port_or_numeric(s: &str) -> bool {
    let s = s.trim_matches(|c| c == '"' || c == '\'');
    if s.is_empty() {
        return false;
    }

    // Strip optional protocol suffix: /tcp, /udp, /sctp
    let s = if let Some(stripped) = s
        .strip_suffix("/tcp")
        .or_else(|| s.strip_suffix("/TCP"))
        .or_else(|| s.strip_suffix("/udp"))
        .or_else(|| s.strip_suffix("/UDP"))
        .or_else(|| s.strip_suffix("/sctp"))
        .or_else(|| s.strip_suffix("/SCTP"))
    {
        stripped
    } else {
        s
    };

    if s.is_empty() {
        return false;
    }

    // If no colons, must be a single port or port range (e.g. "8080" or "8000-8010")
    if !s.contains(':') {
        return is_port_spec(s);
    }

    let parts: Vec<&str> = s.split(':').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return false;
    }

    // Case 1: All parts are port specs (e.g. "8080:8080", "80:80:80")
    if parts.iter().all(|p| is_port_spec(p)) {
        return true;
    }

    // Case 2: Host IP / localhost prefix followed by port specs
    // E.g. "127.0.0.1:8080:8080", "[::1]:8080:8080"
    let host = parts[0].trim_matches(|c| c == '[' || c == ']');
    let is_host = host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::IpAddr>().is_ok();

    if is_host && parts.len() >= 2 && parts[1..].iter().all(|p| is_port_spec(p)) {
        return true;
    }

    false
}

/// Evaluates whether a candidate word is a high-entropy secret token.
/// Criteria: length >= 16, Shannon entropy > 4.20 bits/char, mixed character classes,
/// not already redacted, and not a UUID, filesystem path, or network URI.
pub fn is_high_entropy_secret(token: &str) -> bool {
    let clean = token.trim_matches(|c: char| {
        matches!(c, '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}')
    });
    if clean.len() < 16 {
        return false;
    }
    if clean.contains("REDACTED") {
        return false;
    }
    if is_uuid_or_path(clean) {
        return false;
    }
    if !has_mixed_classes(clean) {
        return false;
    }
    shannon_entropy_bits(clean) > 4.20
}

/// Scrubs high-entropy secret tokens from text, replacing them with
/// `[REDACTED_HIGH_ENTROPY_SECRET]`.
pub fn scrub_high_entropy_tokens(text: &str) -> String {
    let mut out = Vec::new();
    for word in text.split_whitespace() {
        if is_high_entropy_secret(word) {
            out.push("[REDACTED_HIGH_ENTROPY_SECRET]");
        } else {
            out.push(word);
        }
    }
    out.join(" ")
}

/// Scrubs known credential patterns from text using regular expressions.
pub fn scrub_regex_secrets(input: &str) -> String {
    let mut s = input.to_string();

    // 1. Bearer tokens: Bearer <token>=16+
    s = RE_BEARER
        .replace_all(&s, "Bearer [REDACTED_BEARER_TOKEN]")
        .to_string();

    // 2. OpenAI & Anthropic API keys
    s = RE_OPENAI
        .replace_all(&s, "[REDACTED_API_KEY]")
        .to_string();
    s = RE_ANTHROPIC
        .replace_all(&s, "[REDACTED_API_KEY]")
        .to_string();

    // 3. GitHub tokens: ghp_, gho_, ghu_, ghs_, ghr_
    s = RE_GITHUB
        .replace_all(&s, "[REDACTED_GITHUB_TOKEN]")
        .to_string();

    // 4. AWS keys
    s = RE_AWS
        .replace_all(&s, "[REDACTED_AWS_KEY]")
        .to_string();

    // 5. Slack tokens
    s = RE_SLACK
        .replace_all(&s, "[REDACTED_SLACK_TOKEN]")
        .to_string();

    // 6. Google API keys
    s = RE_GOOGLE
        .replace_all(&s, "[REDACTED_GOOGLE_API_KEY]")
        .to_string();

    // 7. PEM Private Keys
    s = RE_PEM_KEY
        .replace_all(&s, "[REDACTED_PRIVATE_KEY]")
        .to_string();

    // 8. Database connection URIs
    s = RE_DB_URI
        .replace_all(&s, "[REDACTED_CONNECTION_STRING]")
        .to_string();

    // 9. CLI password arguments
    s = RE_CLI_PASSWORD_FLAG
        .replace_all(&s, |caps: &regex::Captures| {
            let flag = &caps[1];
            let val = caps
                .get(2)
                .or_else(|| caps.get(3))
                .map(|m| m.as_str())
                .unwrap_or("");
            if val.starts_with("[REDACTED") || (flag.eq_ignore_ascii_case("-p") && is_port_or_numeric(val)) {
                caps[0].to_string()
            } else {
                format!("{}=[REDACTED_CLI_ARG]", flag)
            }
        })
        .to_string();

    // Adjacent -p password flags (e.g. mysql -u root -pPassword123!)
    s = RE_CLI_P_ADJACENT
        .replace_all(&s, |caps: &regex::Captures| {
            let prefix = &caps[1];
            let val = &caps[2];
            let suffix = &caps[3];
            if is_port_or_numeric(val) || val.starts_with("[REDACTED") {
                caps[0].to_string()
            } else {
                format!("{}-p[REDACTED_CLI_ARG]{}", prefix, suffix)
            }
        })
        .to_string();

    // 10. Environment variable assignments
    s = RE_ENV_VAR
        .replace_all(&s, |caps: &regex::Captures| {
            let val = caps
                .get(2)
                .or_else(|| caps.get(3))
                .map(|m| m.as_str())
                .unwrap_or("");
            if val.starts_with("[REDACTED") {
                caps[0].to_string()
            } else {
                format!("{}=[REDACTED_ENV_VAR]", &caps[1])
            }
        })
        .to_string();

    s
}

/// Combined entry point: scrubs regex patterns first, then Shannon high-entropy tokens.
pub fn scrub_text(input: &str) -> String {
    SecretScrubber::scrub_text(input)
}

/// Unified pre-index secret scrubber combining regex and Shannon entropy detection.
pub struct SecretScrubber;

impl SecretScrubber {
    /// Combined entry point: scrubs regex patterns first, then Shannon high-entropy tokens.
    pub fn scrub_text(input: &str) -> String {
        let regex_scrubbed = scrub_regex_secrets(input);
        scrub_high_entropy_tokens(&regex_scrubbed)
    }

    /// Scrubs regex credential patterns.
    pub fn scrub_regex_secrets(input: &str) -> String {
        scrub_regex_secrets(input)
    }

    /// Scrubs high-entropy tokens ($H > 4.20$ bits/char for len >= 16).
    pub fn scrub_high_entropy_tokens(text: &str) -> String {
        scrub_high_entropy_tokens(text)
    }

    /// Shannon entropy in bits per character.
    pub fn shannon_entropy_bits(s: &str) -> f64 {
        shannon_entropy_bits(s)
    }

    /// Checks if a token contains mixed character classes.
    pub fn has_mixed_classes(token: &str) -> bool {
        has_mixed_classes(token)
    }

    /// Checks if a string is a UUID, path, or URI.
    pub fn is_uuid_or_path(s: &str) -> bool {
        is_uuid_or_path(s)
    }

    /// Checks if a token qualifies as a high-entropy secret.
    pub fn is_high_entropy_secret(token: &str) -> bool {
        is_high_entropy_secret(token)
    }

    /// Checks whether a token is a port or network binding.
    pub fn is_port_or_numeric(s: &str) -> bool {
        is_port_or_numeric(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_calculation() {
        assert_eq!(shannon_entropy_bits(""), 0.0);
        assert_eq!(shannon_entropy_bits("aaaaaaaaaaaaaaaa"), 0.0);

        let alt = "abababababababab";
        assert!((shannon_entropy_bits(alt) - 1.0).abs() < 1e-6);

        // High entropy base64 token
        let token = "K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH";
        let h = shannon_entropy_bits(token);
        assert!(h > 4.20, "Expected entropy > 4.20, got {}", h);
    }

    #[test]
    fn test_mixed_classes() {
        assert!(has_mixed_classes("Abcdef123"));
        assert!(has_mixed_classes("abc123"));
        assert!(has_mixed_classes("ABC123"));
        assert!(has_mixed_classes("abc!@#"));
        assert!(!has_mixed_classes("abcdefgh"));
        assert!(!has_mixed_classes("ABCDEFGH"));
        assert!(!has_mixed_classes("12345678"));
    }

    #[test]
    fn test_uuid_and_path_exemptions() {
        assert!(is_uuid_or_path("f079fca0-097e-4913-bd00-d16c999eb7ee"));
        assert!(is_uuid_or_path("F079FCA0-097E-4913-BD00-D16C999EB7EE"));
        assert!(is_uuid_or_path("C:\\Windows\\System32\\cmd.exe"));
        assert!(is_uuid_or_path("/usr/bin/bash"));
        assert!(is_uuid_or_path("https://api.github.com/v3"));
        assert!(is_uuid_or_path("artemis://windows/eventlog/Security"));
        assert!(!is_uuid_or_path("RandomHighEntropyTokenString1234!"));
    }

    #[test]
    fn test_scrub_bearer_and_api_keys() {
        let raw = "curl -H 'Authorization: Bearer sk_live_abcdef12345678901234' https://api.stripe.com";
        let scrubbed = SecretScrubber::scrub_text(raw);
        assert!(!scrubbed.contains("sk_live_abcdef12345678901234"));
        assert!(scrubbed.contains("Bearer [REDACTED_BEARER_TOKEN]"));

        let openai = "OPENAI_KEY=sk-1234567890abcdef1234567890";
        let scrubbed_oai = SecretScrubber::scrub_text(openai);
        assert!(!scrubbed_oai.contains("sk-1234567890abcdef1234567890"));
        assert!(scrubbed_oai.contains("[REDACTED_API_KEY]") || scrubbed_oai.contains("[REDACTED_ENV_VAR]"));

        let anthropic = "curl -H 'x-api-key: sk-ant-api03-abcdef123456789012345678'";
        let scrubbed_ant = SecretScrubber::scrub_text(anthropic);
        assert!(!scrubbed_ant.contains("sk-ant-api03-abcdef123456789012345678"));
        assert!(scrubbed_ant.contains("[REDACTED_API_KEY]"));

        let gh = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        let scrubbed_gh = SecretScrubber::scrub_text(gh);
        assert_eq!(scrubbed_gh, "[REDACTED_GITHUB_TOKEN]");

        let aws = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let scrubbed_aws = SecretScrubber::scrub_text(aws);
        assert!(!scrubbed_aws.contains("AKIAIOSFODNN7EXAMPLE"));

        let slack = "token=xoxb-1234567890-abcdef1234";
        let scrubbed_slack = SecretScrubber::scrub_text(slack);
        assert!(!scrubbed_slack.contains("xoxb-1234567890-abcdef1234"));

        let google = "AIzaSyD-1234567890abcdefghijklmnopqrstuv";
        let scrubbed_google = SecretScrubber::scrub_text(google);
        assert_eq!(scrubbed_google, "[REDACTED_GOOGLE_API_KEY]");
    }

    #[test]
    fn test_scrub_private_key_and_db_uri() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...\n-----END RSA PRIVATE KEY-----";
        let scrubbed_pem = SecretScrubber::scrub_text(pem);
        assert_eq!(scrubbed_pem, "[REDACTED_PRIVATE_KEY]");

        let db = "DATABASE_URL=postgres://appuser:SecretPassword123!@db.internal:5432/production";
        let scrubbed_db = SecretScrubber::scrub_text(db);
        assert!(!scrubbed_db.contains("SecretPassword123!"));
        assert!(scrubbed_db.contains("[REDACTED_CONNECTION_STRING]") || scrubbed_db.contains("[REDACTED_ENV_VAR]"));
    }

    #[test]
    fn test_scrub_cli_flags_and_env_vars() {
        let cmd = "backup.sh --password=SuperSecretRootPwd! --user=admin";
        let scrubbed_cmd = SecretScrubber::scrub_text(cmd);
        assert!(!scrubbed_cmd.contains("SuperSecretRootPwd!"));
        assert!(scrubbed_cmd.contains("--password=[REDACTED_CLI_ARG]"));
        assert!(scrubbed_cmd.contains("--user=admin"));

        let env = "SECRET_KEY=MyVeryLongSecretKey123! NORMAL_VAR=hello";
        let scrubbed_env = SecretScrubber::scrub_text(env);
        assert!(!scrubbed_env.contains("MyVeryLongSecretKey123!"));
        assert!(scrubbed_env.contains("SECRET_KEY=[REDACTED_ENV_VAR]"));
        assert!(scrubbed_env.contains("NORMAL_VAR=hello"));
    }

    #[test]
    fn test_high_entropy_token_scrubbing_and_exclusions() {
        let secret_token = "K8xL9pQ2mN5vR1tW4yZ7bA3cD6eF0gH";
        let input = format!("auth_token is {}", secret_token);
        let scrubbed = SecretScrubber::scrub_text(&input);
        assert!(!scrubbed.contains(secret_token));
        assert!(scrubbed.contains("[REDACTED_HIGH_ENTROPY_SECRET]"));

        let path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
        assert_eq!(SecretScrubber::scrub_text(path), path);

        let uuid_val = "f079fca0-097e-4913-bd00-d16c999eb7ee";
        assert_eq!(SecretScrubber::scrub_text(uuid_val), uuid_val);

        let english = "The quick brown fox jumps over the lazy dog";
        assert_eq!(SecretScrubber::scrub_text(english), english);
    }

    #[test]
    fn test_interleaved_multiple_secrets_and_docker_port_preservation() {
        let raw = "docker run -e DB_PASS=SecretPass999! -e API_KEY=sk-proj-999888777666555444333222 -p 8080:8080 --password=RootMasterPass! my_image";
        let scrubbed = SecretScrubber::scrub_text(raw);

        assert!(!scrubbed.contains("SecretPass999!"));
        assert!(!scrubbed.contains("sk-proj-999888777666555444333222"));
        assert!(!scrubbed.contains("RootMasterPass!"));
        assert!(scrubbed.contains("-p 8080:8080"), "Port flag -p 8080:8080 must be preserved");
        assert!(scrubbed.contains("docker run"));
        assert!(scrubbed.contains("my_image"));
        assert!(scrubbed.contains("--password=[REDACTED_CLI_ARG]"));
    }

    #[test]
    fn test_all_github_slack_and_pem_variants() {
        // GitHub token variants: gho_, ghu_, ghs_, ghr_
        for prefix in ["gho_", "ghu_", "ghs_", "ghr_"] {
            let tok = format!("{}123456789012345678901234567890123456", prefix);
            let raw = format!("git config github.token {}", tok);
            let scrubbed = SecretScrubber::scrub_text(&raw);
            assert!(!scrubbed.contains(&tok));
            assert!(scrubbed.contains("[REDACTED_GITHUB_TOKEN]"));
        }

        // Slack token variants
        for prefix in ["xoxp-", "xoxa-", "xoxr-", "xoxs-"] {
            let tok = format!("{}1234567890-abcdef1234", prefix);
            let raw = format!("slack-cli --token {}", tok);
            let scrubbed = SecretScrubber::scrub_text(&raw);
            assert!(!scrubbed.contains(&tok));
            assert!(scrubbed.contains("[REDACTED_SLACK_TOKEN]") || scrubbed.contains("[REDACTED_CLI_ARG]"));
        }

        // PEM variants
        for key_type in ["EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "DSA PRIVATE KEY"] {
            let pem = format!("-----BEGIN {}-----\nMIGqAgEAAiEA...\n-----END {}-----", key_type, key_type);
            let scrubbed = SecretScrubber::scrub_text(&pem);
            assert_eq!(scrubbed, "[REDACTED_PRIVATE_KEY]");
        }

        // DB URI variants
        for scheme in ["mysql", "mongodb", "redis", "mssql", "amqp", "couchdb"] {
            let uri = format!("{}://admin:SecretPass99!@cluster.internal:27017/db", scheme);
            let scrubbed = SecretScrubber::scrub_text(&uri);
            assert!(!scrubbed.contains("SecretPass99!"));
            assert!(scrubbed.contains("[REDACTED_CONNECTION_STRING]"));
        }
    }

    #[test]
    fn test_single_class_high_length_tokens_are_not_falsely_redacted() {
        // All digits (length >= 16)
        let digits = "12345678901234567890";
        assert_eq!(SecretScrubber::scrub_text(digits), digits);

        // All lowercase (length >= 16)
        let lowers = "abcdefghijklmnopqrstuvwxyz";
        assert_eq!(SecretScrubber::scrub_text(lowers), lowers);

        // All uppercase (length >= 16)
        let uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        assert_eq!(SecretScrubber::scrub_text(uppers), uppers);
    }

    #[test]
    fn test_quoted_cli_flags_and_env_vars() {
        let cmd_double = "app.exe --password=\"SecretPassword123!\" --user=admin";
        let scrubbed_double = SecretScrubber::scrub_text(cmd_double);
        assert!(!scrubbed_double.contains("SecretPassword123!"));
        assert!(scrubbed_double.contains("--password=[REDACTED_CLI_ARG]"));

        let cmd_single = "app.exe --password='SecretPassword123!' --user=admin";
        let scrubbed_single = SecretScrubber::scrub_text(cmd_single);
        assert!(!scrubbed_single.contains("SecretPassword123!"));
        assert!(scrubbed_single.contains("--password=[REDACTED_CLI_ARG]"));

        let cmd_pwd = "tool.exe --pwd=\"xyz\" --action=start";
        let scrubbed_pwd = SecretScrubber::scrub_text(cmd_pwd);
        assert!(!scrubbed_pwd.contains("xyz"));
        assert!(scrubbed_pwd.contains("--pwd=[REDACTED_CLI_ARG]"));

        let env_pass = "PASSWORD=\"secret\" KEY=\"prod\"";
        let scrubbed_pass = SecretScrubber::scrub_text(env_pass);
        assert!(!scrubbed_pass.contains("secret"));
        assert!(scrubbed_pass.contains("PASSWORD=[REDACTED_ENV_VAR]"));

        let env_secret = "export SECRET='secret'";
        let scrubbed_secret = SecretScrubber::scrub_text(env_secret);
        assert!(!scrubbed_secret.contains("secret"));
        assert!(scrubbed_secret.contains("SECRET=[REDACTED_ENV_VAR]"));
    }

    #[test]
    fn test_docker_ip_and_protocol_port_exemptions() {
        let docker_ip = "docker run -d -p 127.0.0.1:8080:8080 nginx";
        let scrubbed_ip = SecretScrubber::scrub_text(docker_ip);
        assert!(!scrubbed_ip.contains("[REDACTED_CLI_ARG]"));
        assert!(scrubbed_ip.contains("-p 127.0.0.1:8080:8080"));

        let docker_zero = "docker run -d -p 0.0.0.0:443:443 web";
        let scrubbed_zero = SecretScrubber::scrub_text(docker_zero);
        assert!(!scrubbed_zero.contains("[REDACTED_CLI_ARG]"));
        assert!(scrubbed_zero.contains("-p 0.0.0.0:443:443"));

        let docker_tcp = "docker run -d -p 8080:8080/tcp nginx";
        let scrubbed_tcp = SecretScrubber::scrub_text(docker_tcp);
        assert!(!scrubbed_tcp.contains("[REDACTED_CLI_ARG]"));
        assert!(scrubbed_tcp.contains("-p 8080:8080/tcp"));

        let docker_udp = "docker run -d -p 8080/udp dns";
        let scrubbed_udp = SecretScrubber::scrub_text(docker_udp);
        assert!(!scrubbed_udp.contains("[REDACTED_CLI_ARG]"));
        assert!(scrubbed_udp.contains("-p 8080/udp"));

        // Passwords with -p must still be redacted
        let mysql_p = "mysql -u root -p SecretPassword123! -h 127.0.0.1";
        let scrubbed_mysql = SecretScrubber::scrub_text(mysql_p);
        assert!(!scrubbed_mysql.contains("SecretPassword123!"));
        assert!(scrubbed_mysql.contains("-p=[REDACTED_CLI_ARG]"));
    }
}

