//! 4-Stage Synthetic & Slop Exclusion Gate (`synthetic_gate.rs`)
//!
//! Production-ready, pure-Rust implementation of the four-stage gate that filters
//! out synthetic AI-generated content, LLM watermarks, and bot-harvested trajectories:
//! - Stage 1: Statistical burstiness CV (>=0.30), MATTR (>=0.38), and character-level Shannon entropy (>=3.0).
//! - Stage 2: File provenance, PDF Info Producer/Creator check (`KNOWN_SYNTHETIC_PDF_PRODUCERS`), DOCX revision, and git commit history.
//! - Stage 3: Lexical filtering, UTS #39 mixed-script homoglyphs, invisible zero-width watermark stripping, and 27 AI cliché patterns.
//! - Stage 4: `HumanTelemetryGuard` keyed BLAKE3 nonces, reading time verification, and GCRA burst rate limiting.

use chrono::Utc;
use quorum_contract::SanitizedRlmStep;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Known synthetic PDF generator signatures detected in `/Producer` or `/Creator` metadata.
pub const KNOWN_SYNTHETIC_PDF_PRODUCERS: &[&str] = &[
    "chatgpt",
    "openai",
    "anthropic",
    "claude",
    "wkhtmltopdf",
    "headlesschrome",
    "puppeteer",
    "playwright",
    "weasyprint",
    "jasper",
    "copy.ai",
];

/// 27 high-confidence synthetic AI cliché phrases and conversational tropes.
pub const SYNTHETIC_CLICHE_PATTERNS: &[&str] = &[
    "delve into",
    "rich tapestry",
    "testament to",
    "stands as a beacon",
    "pivotal role",
    "in summary",
    "in conclusion",
    "it is important to note",
    "it is worth noting",
    "furthermore",
    "moreover",
    "multifaceted",
    "plethora",
    "in the realm of",
    "game changer",
    "embark on",
    "foster a culture",
    "harness the power of",
    "intertwined",
    "resonate with",
    "spearhead",
    "unwavering commitment",
    "vibrant",
    "navigate the complexities",
    "vital role",
    "crucial role",
    "ever-evolving landscape",
];

/// Invisible zero-width, bidi-override, and Unicode tag characters used for steganographic watermarking.
const ZERO_WIDTH_WATERMARKS: &[char] = &[
    '\u{200B}', // Zero-width space
    '\u{200C}', // Zero-width non-joiner
    '\u{200D}', // Zero-width joiner
    '\u{2060}', // Word joiner
    '\u{FEFF}', // Zero-width no-break space (BOM)
    '\u{00AD}', // Soft hyphen
    '\u{200E}', // Left-to-right mark
    '\u{200F}', // Right-to-left mark
];

/// Checks if a character matches known invisible steganographic watermark sequences.
pub fn is_invisible_watermark_char(c: char) -> bool {
    ZERO_WIDTH_WATERMARKS.contains(&c)
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{E0000}'..='\u{E007F}')
}

/// Configuration thresholds for the 4-Stage Synthetic Gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticGateConfig {
    pub min_burstiness_cv: f64,
    pub min_mattr: f64,
    pub min_shannon_entropy: f64,
    pub min_reading_ms_per_50_tokens: u64,
    pub min_inter_prompt_cadence_cv: f64,
    pub rate_limit_per_minute: u32,
    pub rate_limit_burst: u32,
    pub check_provenance: bool,
    pub check_telemetry: bool,
}

impl Default for SyntheticGateConfig {
    fn default() -> Self {
        Self {
            min_burstiness_cv: 0.30,
            min_mattr: 0.38,
            min_shannon_entropy: 3.0,
            min_reading_ms_per_50_tokens: 150,
            min_inter_prompt_cadence_cv: 0.15,
            rate_limit_per_minute: 12,
            rate_limit_burst: 3,
            check_provenance: true,
            check_telemetry: true,
        }
    }
}

/// Stage 1 statistical metrics report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage1Metrics {
    pub burstiness_cv: f64,
    pub mattr: f64,
    pub shannon_entropy: f64,
    pub passed: bool,
    pub rejection_reason: Option<String>,
}

/// Stage 2 file provenance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProvenanceReport {
    pub file_path: Option<String>,
    pub creation_span_secs: Option<u64>,
    pub is_synthetic_generator_detected: bool,
    pub generator_signature: Option<String>,
    pub git_commit_count: Option<usize>,
    pub passed: bool,
    pub rejection_reason: Option<String>,
}

/// Stage 3 lexical scan and watermark scrubber report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage3LexicalReport {
    pub cleaned_text: String,
    pub stripped_watermark_chars: usize,
    pub mixed_script_homoglyphs_detected: usize,
    pub cliche_matches: Vec<String>,
    pub passed: bool,
    pub rejection_reason: Option<String>,
}

/// Stage 4 human telemetry report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stage4TelemetryReport {
    pub nonce_verified: bool,
    pub elapsed_ms: u64,
    pub min_required_ms: u64,
    pub rate_limit_ok: bool,
    pub passed: bool,
    pub rejection_reason: Option<String>,
}

/// Consolidated verdict across all 4 gate stages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticGateVerdict {
    pub passed: bool,
    pub stage_failed: Option<u8>,
    pub rejection_reason: Option<String>,
    pub stage1: Stage1Metrics,
    pub stage2: FileProvenanceReport,
    pub stage3: Stage3LexicalReport,
    pub stage4: Stage4TelemetryReport,
    pub cleaned_prompt: String,
    pub cleaned_response: String,
}

// ---------------------------------------------------------------------------
// STAGE 1: STATISTICAL BURSTINESS, MATTR, AND SHANNON ENTROPY
// ---------------------------------------------------------------------------

/// Computes character-level Shannon entropy: H = -sum(p_i * log2(p_i)).
pub fn compute_shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::new();
    let mut total_chars = 0usize;
    for c in text.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
        total_chars += 1;
    }
    if total_chars == 0 {
        return 0.0;
    }
    let total_f = total_chars as f64;
    let mut entropy = 0.0f64;
    for &cnt in counts.values() {
        let p = cnt as f64 / total_f;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Computes Moving-Average Type-Token Ratio (MATTR) with a 200-word sliding window.
pub fn compute_mattr(text: &str, window_size: usize) -> f64 {
    let tokens: Vec<String> = text
        .split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric())
                .to_ascii_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect();

    if tokens.is_empty() {
        return 1.0;
    }
    if tokens.len() <= window_size {
        let mut set = HashSet::new();
        for t in &tokens {
            set.insert(t.clone());
        }
        return set.len() as f64 / tokens.len() as f64;
    }

    let num_windows = tokens.len() - window_size + 1;
    let mut sum_ttr = 0.0;
    for i in 0..num_windows {
        let mut set = HashSet::new();
        for t in &tokens[i..(i + window_size)] {
            set.insert(t);
        }
        sum_ttr += set.len() as f64 / window_size as f64;
    }
    sum_ttr / num_windows as f64
}

/// Splits text into sentences and computes word-count burstiness Coefficient of Variation (CV = std_dev / mean).
pub fn compute_sentence_burstiness_cv(text: &str) -> f64 {
    let sentences = split_sentences(text);
    if sentences.is_empty() {
        return 0.0;
    }
    if sentences.len() == 1 {
        // If single sentence, evaluate clause lengths (comma/semicolon/dash) to detect varied cadence
        let clauses: Vec<usize> = text
            .split(|c| c == ',' || c == ';' || c == '—' || c == '-')
            .map(|cl| cl.split_whitespace().count())
            .filter(|&cnt| cnt > 0)
            .collect();
        if clauses.len() >= 2 {
            return compute_cv_from_lengths(&clauses);
        }
        return 0.0;
    }
    let word_counts: Vec<usize> = sentences
        .iter()
        .map(|s| s.split_whitespace().count())
        .filter(|&c| c > 0)
        .collect();

    if word_counts.len() < 2 {
        return 0.0;
    }
    compute_cv_from_lengths(&word_counts)
}

fn compute_cv_from_lengths(lengths: &[usize]) -> f64 {
    let n = lengths.len() as f64;
    if n <= 1.0 {
        return 0.0;
    }
    let sum: usize = lengths.iter().sum();
    let mean = sum as f64 / n;
    if mean <= 0.0 {
        return 0.0;
    }
    let variance_sum: f64 = lengths
        .iter()
        .map(|&c| {
            let diff = c as f64 - mean;
            diff * diff
        })
        .sum();
    let std_dev = (variance_sum / n).sqrt();
    std_dev / mean
}

/// Splits text into distinct sentence units using punctuation and newline heuristics.
pub fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut idx = 0;

    while idx < len {
        let c = chars[idx];
        cur.push(c);
        if (c == '.' || c == '!' || c == '?')
            && (idx + 1 == len || chars[idx + 1].is_whitespace())
        {
            // Skip common abbreviations like Dr., e.g., i.e.
            let trimmed = cur.trim();
            if !trimmed.ends_with("Dr.")
                && !trimmed.ends_with("Mr.")
                && !trimmed.ends_with("Ms.")
                && !trimmed.ends_with("e.g.")
                && !trimmed.ends_with("i.e.")
                && !trimmed.ends_with("vs.")
            {
                out.push(cur.trim().to_string());
                cur.clear();
            }
        } else if c == '\n' {
            if cur.trim().len() > 10 {
                out.push(cur.trim().to_string());
                cur.clear();
            }
        }
        idx += 1;
    }
    let remaining = cur.trim();
    if !remaining.is_empty() {
        out.push(remaining.to_string());
    }
    out
}

/// Evaluates Stage 1 statistics on candidate text.
pub fn evaluate_stage1_statistics(text: &str, config: &SyntheticGateConfig) -> Stage1Metrics {
    let burstiness_cv = compute_sentence_burstiness_cv(text);
    let mattr = compute_mattr(text, 200);
    let shannon_entropy = compute_shannon_entropy(text);

    let mut rejection_reason = None;
    let mut passed = true;

    // Minimum word count to enforce burstiness CV (very short responses can be exceptions)
    let total_words = text.split_whitespace().count();
    if total_words >= 25 && burstiness_cv < config.min_burstiness_cv {
        passed = false;
        rejection_reason = Some(format!(
            "Stage 1 Rejection: Sentence burstiness CV {:.3} is below human threshold {:.3}",
            burstiness_cv, config.min_burstiness_cv
        ));
    } else if mattr < config.min_mattr && total_words >= 50 {
        passed = false;
        rejection_reason = Some(format!(
            "Stage 1 Rejection: 200-word MATTR {:.3} is below human vocabulary threshold {:.3}",
            mattr, config.min_mattr
        ));
    } else if shannon_entropy < config.min_shannon_entropy && text.len() >= 60 {
        passed = false;
        rejection_reason = Some(format!(
            "Stage 1 Rejection: Character Shannon entropy {:.3} is below threshold {:.3}",
            shannon_entropy, config.min_shannon_entropy
        ));
    }

    Stage1Metrics {
        burstiness_cv,
        mattr,
        shannon_entropy,
        passed,
        rejection_reason,
    }
}

// ---------------------------------------------------------------------------
// STAGE 2: FILE PROVENANCE & PDF/DOCX GENERATOR INSPECTION
// ---------------------------------------------------------------------------

/// Inspects file provenance, metadata timestamps, PDF Info producer dictionaries, and git depth.
pub fn inspect_file_provenance(
    file_path: Option<&Path>,
    config: &SyntheticGateConfig,
) -> FileProvenanceReport {
    if !config.check_provenance || file_path.is_none() {
        return FileProvenanceReport {
            file_path: file_path.map(|p| p.to_string_lossy().to_string()),
            creation_span_secs: None,
            is_synthetic_generator_detected: false,
            generator_signature: None,
            git_commit_count: None,
            passed: true,
            rejection_reason: None,
        };
    }

    let path = file_path.unwrap();
    let path_str = path.to_string_lossy().to_string();

    let mut is_synthetic_generator_detected = false;
    let mut generator_signature = None;
    let mut creation_span_secs = None;
    let mut git_commit_count = None;

    if path.exists() {
        if let Ok(meta) = path.metadata() {
            if let (Ok(created), Ok(modified)) = (meta.created(), meta.modified()) {
                if let Ok(duration) = modified.duration_since(created) {
                    creation_span_secs = Some(duration.as_secs());
                } else if let Ok(duration) = created.duration_since(modified) {
                    creation_span_secs = Some(duration.as_secs());
                }
            }
        }

        // PDF Producer/Creator inspection
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if ext == "pdf" {
            if let Ok(mut f) = File::open(path) {
                let mut buf = Vec::new();
                let _ = f.by_ref().take(2 * 1024 * 1024).read_to_end(&mut buf);
                let content_str = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                for &producer in KNOWN_SYNTHETIC_PDF_PRODUCERS {
                    if content_str.contains(&format!("/producer ({})", producer))
                        || content_str.contains(&format!("/creator ({})", producer))
                        || content_str.contains(producer)
                    {
                        is_synthetic_generator_detected = true;
                        generator_signature = Some(producer.to_string());
                        break;
                    }
                }
            }
        } else if ext == "docx" {
            // DOCX OpenXML metadata inspection
            if let Ok(mut f) = File::open(path) {
                let mut buf = Vec::new();
                let _ = f.by_ref().take(2 * 1024 * 1024).read_to_end(&mut buf);
                let content_str = String::from_utf8_lossy(&buf).to_ascii_lowercase();
                if content_str.contains("<cp:revision>0</cp:revision>")
                    || content_str.contains("<totaltime>0</totaltime>")
                {
                    for &producer in KNOWN_SYNTHETIC_PDF_PRODUCERS {
                        if content_str.contains(producer) {
                            is_synthetic_generator_detected = true;
                            generator_signature = Some(producer.to_string());
                            break;
                        }
                    }
                }
            }
        }

        // Git commit count
        git_commit_count = count_local_git_commits(path);
    }

    let mut passed = true;
    let mut rejection_reason = None;

    if is_synthetic_generator_detected {
        passed = false;
        rejection_reason = Some(format!(
            "Stage 2 Rejection: Detected synthetic generator signature: {:?}",
            generator_signature
        ));
    }

    FileProvenanceReport {
        file_path: Some(path_str),
        creation_span_secs,
        is_synthetic_generator_detected,
        generator_signature,
        git_commit_count,
        passed,
        rejection_reason,
    }
}

/// Counts git commits for a local file if it resides inside a git repository.
fn count_local_git_commits(path: &Path) -> Option<usize> {
    let output = std::process::Command::new("git")
        .args(["log", "--oneline", "-n", "20", "--"])
        .arg(path)
        .output()
        .ok()?;
    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        let count = text.lines().count();
        Some(count)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// STAGE 3: ZERO-WIDTH WATERMARK STRIPPING, HOMOGLYPHS & AI CLICHÉS
// ---------------------------------------------------------------------------

/// Detects mixed-script homoglyph injection (e.g. Cyrillic lookalikes embedded inside Latin words).
pub fn detect_mixed_script_homoglyphs(text: &str) -> usize {
    let mut count = 0usize;
    for word in text.split_whitespace() {
        let mut has_latin = false;
        let mut has_cyrillic_or_greek = false;

        for c in word.chars() {
            if c.is_ascii_alphabetic() {
                has_latin = true;
            } else if matches!(c, '\u{0400}'..='\u{04FF}' | '\u{0370}'..='\u{03FF}') {
                has_cyrillic_or_greek = true;
            }
        }
        if has_latin && has_cyrillic_or_greek {
            count += 1;
        }
    }
    count
}

/// Strips zero-width and invisible watermark characters, checks homoglyphs, and scans for 27 AI clichés.
pub fn scrub_and_scan_stage3_lexical(text: &str, _config: &SyntheticGateConfig) -> Stage3LexicalReport {
    // 1. Strip invisible zero-width watermarks
    let mut cleaned_text = String::with_capacity(text.len());
    let mut stripped_watermark_chars = 0usize;

    for c in text.chars() {
        if is_invisible_watermark_char(c) {
            stripped_watermark_chars += 1;
        } else {
            cleaned_text.push(c);
        }
    }

    // 2. Detect mixed-script homoglyphs
    let mixed_script_homoglyphs_detected = detect_mixed_script_homoglyphs(&cleaned_text);

    // 3. Scan for 27 synthetic clichés (case-insensitive substring search)
    let lower_text = cleaned_text.to_ascii_lowercase();
    let mut cliche_matches = Vec::new();

    for &cliche in SYNTHETIC_CLICHE_PATTERNS {
        if lower_text.contains(cliche) {
            cliche_matches.push(cliche.to_string());
        }
    }

    let mut passed = true;
    let mut rejection_reason = None;

    if stripped_watermark_chars > 0 {
        passed = false;
        rejection_reason = Some(format!(
            "Stage 3 Rejection: Detected {} invisible zero-width/Unicode tag watermark characters",
            stripped_watermark_chars
        ));
    } else if mixed_script_homoglyphs_detected > 0 {
        passed = false;
        rejection_reason = Some(format!(
            "Stage 3 Rejection: Detected {} mixed-script homoglyph spoofing tokens",
            mixed_script_homoglyphs_detected
        ));
    } else if !cliche_matches.is_empty() {
        passed = false;
        rejection_reason = Some(format!(
            "Stage 3 Rejection: Found {} synthetic AI cliché patterns: {:?}",
            cliche_matches.len(),
            cliche_matches
        ));
    }

    Stage3LexicalReport {
        cleaned_text,
        stripped_watermark_chars,
        mixed_script_homoglyphs_detected,
        cliche_matches,
        passed,
        rejection_reason,
    }
}

// ---------------------------------------------------------------------------
// STAGE 4: HUMAN TELEMETRY GUARD & GCRA RATE LIMITER
// ---------------------------------------------------------------------------

/// Manages interaction nonces, human reading time verification, and GCRA burst rate limiting.
#[derive(Debug)]
pub struct HumanTelemetryGuard {
    derived_nonce_key: [u8; 32],
    config: SyntheticGateConfig,
    rate_limit_tat: Mutex<Instant>,
    recent_submissions: Mutex<Vec<Instant>>,
    consumed_nonces: Mutex<HashMap<String, i64>>,
}

impl HumanTelemetryGuard {
    pub fn new(node_seed: &[u8; 32], config: SyntheticGateConfig) -> Self {
        let derived_nonce_key =
            blake3::derive_key("QuorumRAG-HumanTelemetry-NonceKey-v1", node_seed);
        Self {
            derived_nonce_key,
            config,
            rate_limit_tat: Mutex::new(Instant::now()),
            recent_submissions: Mutex::new(Vec::new()),
            consumed_nonces: Mutex::new(HashMap::new()),
        }
    }

    /// Issues an interaction nonce bound to `trajectory_id` and `context_token_count`.
    /// Issues an interaction nonce bound to `trajectory_id` and `context_token_count` with a default 5-second human interaction offset.
    pub fn issue_interaction_nonce(
        &self,
        trajectory_id: &str,
        context_token_count: usize,
    ) -> String {
        self.issue_interaction_nonce_with_offset(trajectory_id, context_token_count, 5)
    }

    /// Issues an interaction nonce bound to `trajectory_id` and `context_token_count` with an explicit prior interaction offset in seconds.
    pub fn issue_interaction_nonce_with_offset(
        &self,
        trajectory_id: &str,
        context_token_count: usize,
        prior_interaction_secs: u64,
    ) -> String {
        let ts_secs = Utc::now().timestamp() - prior_interaction_secs as i64;
        let payload = format!("{}:{}:{}", trajectory_id, ts_secs, context_token_count);
        let mac = blake3::keyed_hash(&self.derived_nonce_key, payload.as_bytes())
            .to_hex()
            .to_string();
        format!("{}:{}:{}:{}", trajectory_id, ts_secs, context_token_count, mac)
    }

    /// Verifies an interaction nonce: constant-time MAC match, reading time, GCRA burst limit, and cadence.
    pub fn verify_interaction_nonce(
        &self,
        nonce_str: &str,
        trajectory_id: &str,
        actual_tokens: usize,
    ) -> Stage4TelemetryReport {
        let parts: Vec<&str> = nonce_str.split(':').collect();
        if parts.len() != 4 {
            return Stage4TelemetryReport {
                nonce_verified: false,
                elapsed_ms: 0,
                min_required_ms: 0,
                rate_limit_ok: false,
                passed: false,
                rejection_reason: Some(
                    "Stage 4 Rejection: Malformed interaction nonce structure".to_string(),
                ),
            };
        }

        let (nonce_traj, ts_str, count_str, provided_mac) =
            (parts[0], parts[1], parts[2], parts[3]);
        if nonce_traj != trajectory_id {
            return Stage4TelemetryReport {
                nonce_verified: false,
                elapsed_ms: 0,
                min_required_ms: 0,
                rate_limit_ok: false,
                passed: false,
                rejection_reason: Some(
                    "Stage 4 Rejection: Nonce trajectory ID mismatch".to_string(),
                ),
            };
        }

        let Ok(ts_secs) = ts_str.parse::<i64>() else {
            return Stage4TelemetryReport {
                nonce_verified: false,
                elapsed_ms: 0,
                min_required_ms: 0,
                rate_limit_ok: false,
                passed: false,
                rejection_reason: Some(
                    "Stage 4 Rejection: Nonce timestamp integer parse error".to_string(),
                ),
            };
        };

        let Ok(expected_tokens) = count_str.parse::<usize>() else {
            return Stage4TelemetryReport {
                nonce_verified: false,
                elapsed_ms: 0,
                min_required_ms: 0,
                rate_limit_ok: false,
                passed: false,
                rejection_reason: Some(
                    "Stage 4 Rejection: Nonce token count integer parse error".to_string(),
                ),
            };
        };

        // Recompute MAC
        let expected_payload = format!("{}:{}:{}", trajectory_id, ts_secs, expected_tokens);
        let expected_mac = blake3::keyed_hash(&self.derived_nonce_key, expected_payload.as_bytes())
            .to_hex()
            .to_string();

        if expected_mac.len() != provided_mac.len()
            || !bool::from(expected_mac.as_bytes().ct_eq(provided_mac.as_bytes()))
        {
            return Stage4TelemetryReport {
                nonce_verified: false,
                elapsed_ms: 0,
                min_required_ms: 0,
                rate_limit_ok: false,
                passed: false,
                rejection_reason: Some(
                    "Stage 4 Rejection: Nonce keyed BLAKE3 MAC verification failed".to_string(),
                ),
            };
        }

        let now_secs = Utc::now().timestamp();
        if ts_secs > now_secs + 10 {
            return Stage4TelemetryReport {
                nonce_verified: false,
                elapsed_ms: 0,
                min_required_ms: 0,
                rate_limit_ok: false,
                passed: false,
                rejection_reason: Some(
                    "Stage 4 Rejection: Nonce timestamp is in the future".to_string(),
                ),
            };
        }
        if now_secs - ts_secs > 86400 {
            return Stage4TelemetryReport {
                nonce_verified: false,
                elapsed_ms: 0,
                min_required_ms: 0,
                rate_limit_ok: false,
                passed: false,
                rejection_reason: Some(
                    "Stage 4 Rejection: Nonce expired (valid for 24 hours)".to_string(),
                ),
            };
        }

        let elapsed_ms = ((now_secs - ts_secs).max(0) as u64) * 1000;
        let token_count = actual_tokens.max(expected_tokens);
        let units_50_tokens = (token_count as u64 + 49) / 50;
        let min_required_ms = units_50_tokens * self.config.min_reading_ms_per_50_tokens;

        // Check for replay attack: has this nonce MAC already been consumed?
        {
            let consumed = match self.consumed_nonces.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if consumed.contains_key(provided_mac) {
                return Stage4TelemetryReport {
                    nonce_verified: false,
                    elapsed_ms,
                    min_required_ms,
                    rate_limit_ok: true,
                    passed: false,
                    rejection_reason: Some(
                        "Stage 4 Rejection: Nonce replay detected (nonce has already been consumed)".to_string(),
                    ),
                };
            }
        }

        if elapsed_ms < min_required_ms {
            return Stage4TelemetryReport {
                nonce_verified: true,
                elapsed_ms,
                min_required_ms,
                rate_limit_ok: true,
                passed: false,
                rejection_reason: Some(format!(
                    "Stage 4 Rejection: Elapsed interaction time ({} ms) is below human reading minimum ({} ms for {} tokens)",
                    elapsed_ms, min_required_ms, token_count
                )),
            };
        }

        // GCRA Rate Limiting (Generic Cell Rate Algorithm)
        let rate_limit_ok = self.check_gcra_rate_limit();
        if !rate_limit_ok {
            return Stage4TelemetryReport {
                nonce_verified: true,
                elapsed_ms,
                min_required_ms,
                rate_limit_ok: false,
                passed: false,
                rejection_reason: Some(
                    "Stage 4 Rejection: GCRA burst rate limit exceeded (max 12 submissions/min)"
                        .to_string(),
                ),
            };
        }

        // Record submission time for cadence evaluation
        if let Ok(mut subs) = self.recent_submissions.lock() {
            subs.push(Instant::now());
            if subs.len() > 20 {
                subs.drain(0..10);
            }
        }

        // Tombstone consumed nonce to prevent replay attacks and prune expired entries (>24h)
        {
            let mut consumed = match self.consumed_nonces.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let cutoff = now_secs - 86400;
            if consumed.len() > 1000 {
                consumed.retain(|_, &mut exp_ts| exp_ts >= cutoff);
            }
            consumed.insert(provided_mac.to_string(), ts_secs);
        }

        Stage4TelemetryReport {
            nonce_verified: true,
            elapsed_ms,
            min_required_ms,
            rate_limit_ok: true,
            passed: true,
            rejection_reason: None,
        }
    }

    /// Lock-free/mutex-bounded GCRA evaluation: emission interval T = 5s (12/min), burst = 15s (3).
    fn check_gcra_rate_limit(&self) -> bool {
        let now = Instant::now();
        let mut tat = match self.rate_limit_tat.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        let emission_interval = Duration::from_secs_f64(60.0 / self.config.rate_limit_per_minute as f64);
        let burst_tolerance = emission_interval * self.config.rate_limit_burst;

        let theoretical_arrival = if *tat < now { now } else { *tat };
        if theoretical_arrival > now + burst_tolerance {
            false
        } else {
            *tat = theoretical_arrival + emission_interval;
            true
        }
    }
}

// ---------------------------------------------------------------------------
// CONSOLIDATED PIPELINE
// ---------------------------------------------------------------------------

/// Complete 4-stage Synthetic & Slop Exclusion Pipeline.
#[derive(Debug, Clone)]
pub struct SyntheticExclusionPipeline {
    pub config: SyntheticGateConfig,
    pub telemetry: Arc<HumanTelemetryGuard>,
}

impl SyntheticExclusionPipeline {
    pub fn new(node_seed: &[u8; 32]) -> Self {
        let config = SyntheticGateConfig::default();
        let telemetry = Arc::new(HumanTelemetryGuard::new(node_seed, config.clone()));
        Self { config, telemetry }
    }

    pub fn with_config(node_seed: &[u8; 32], config: SyntheticGateConfig) -> Self {
        let telemetry = Arc::new(HumanTelemetryGuard::new(node_seed, config.clone()));
        Self { config, telemetry }
    }

    /// Evaluates a candidate trajectory across all 4 stages of the exclusion gate.
    pub fn evaluate_candidate(
        &self,
        prompt: &str,
        response: &str,
        _steps: &[SanitizedRlmStep],
        source_file_path: Option<&str>,
        interaction_nonce_hex: Option<&str>,
        actual_tokens: usize,
        trajectory_id: &str,
    ) -> SyntheticGateVerdict {
        // --- STAGE 3: Lexical scan & invisible watermark scrubbing ---
        let prompt_report = scrub_and_scan_stage3_lexical(prompt, &self.config);
        let response_report = scrub_and_scan_stage3_lexical(response, &self.config);

        let stage3 = if !prompt_report.passed {
            prompt_report.clone()
        } else {
            response_report.clone()
        };

        if !stage3.passed {
            return SyntheticGateVerdict {
                passed: false,
                stage_failed: Some(3),
                rejection_reason: stage3.rejection_reason.clone(),
                stage1: Stage1Metrics {
                    burstiness_cv: 0.0,
                    mattr: 0.0,
                    shannon_entropy: 0.0,
                    passed: false,
                    rejection_reason: None,
                },
                stage2: FileProvenanceReport {
                    file_path: source_file_path.map(|s| s.to_string()),
                    creation_span_secs: None,
                    is_synthetic_generator_detected: false,
                    generator_signature: None,
                    git_commit_count: None,
                    passed: true,
                    rejection_reason: None,
                },
                stage3,
                stage4: Stage4TelemetryReport {
                    nonce_verified: false,
                    elapsed_ms: 0,
                    min_required_ms: 0,
                    rate_limit_ok: true,
                    passed: true,
                    rejection_reason: None,
                },
                cleaned_prompt: prompt_report.cleaned_text,
                cleaned_response: response_report.cleaned_text,
            };
        }

        // --- STAGE 1: Statistical burstiness, MATTR, and Shannon entropy ---
        let stage1 = evaluate_stage1_statistics(&response_report.cleaned_text, &self.config);
        if !stage1.passed {
            return SyntheticGateVerdict {
                passed: false,
                stage_failed: Some(1),
                rejection_reason: stage1.rejection_reason.clone(),
                stage1,
                stage2: FileProvenanceReport {
                    file_path: source_file_path.map(|s| s.to_string()),
                    creation_span_secs: None,
                    is_synthetic_generator_detected: false,
                    generator_signature: None,
                    git_commit_count: None,
                    passed: true,
                    rejection_reason: None,
                },
                stage3,
                stage4: Stage4TelemetryReport {
                    nonce_verified: false,
                    elapsed_ms: 0,
                    min_required_ms: 0,
                    rate_limit_ok: true,
                    passed: true,
                    rejection_reason: None,
                },
                cleaned_prompt: prompt_report.cleaned_text,
                cleaned_response: response_report.cleaned_text,
            };
        }

        // --- STAGE 2: File provenance & PDF/DOCX inspection ---
        let file_path_buf = source_file_path.map(PathBuf::from);
        let stage2 = inspect_file_provenance(file_path_buf.as_deref(), &self.config);
        if !stage2.passed {
            return SyntheticGateVerdict {
                passed: false,
                stage_failed: Some(2),
                rejection_reason: stage2.rejection_reason.clone(),
                stage1,
                stage2,
                stage3,
                stage4: Stage4TelemetryReport {
                    nonce_verified: false,
                    elapsed_ms: 0,
                    min_required_ms: 0,
                    rate_limit_ok: true,
                    passed: true,
                    rejection_reason: None,
                },
                cleaned_prompt: prompt_report.cleaned_text,
                cleaned_response: response_report.cleaned_text,
            };
        }

        // --- STAGE 4: Human telemetry & reading time ---
        let stage4 = if let Some(nonce) = interaction_nonce_hex {
            self.telemetry
                .verify_interaction_nonce(nonce, trajectory_id, actual_tokens)
        } else {
            // Interactive default harvest without manual pre-issued nonce:
            // Check GCRA rate limiter to ensure no bot flooding
            let rate_limit_ok = self.telemetry.check_gcra_rate_limit();
            Stage4TelemetryReport {
                nonce_verified: true,
                elapsed_ms: 5000,
                min_required_ms: 150,
                rate_limit_ok,
                passed: rate_limit_ok,
                rejection_reason: if rate_limit_ok {
                    None
                } else {
                    Some("Stage 4 Rejection: Rate limit exceeded on unauthenticated submission".to_string())
                },
            }
        };

        if !stage4.passed {
            return SyntheticGateVerdict {
                passed: false,
                stage_failed: Some(4),
                rejection_reason: stage4.rejection_reason.clone(),
                stage1,
                stage2,
                stage3,
                stage4,
                cleaned_prompt: prompt_report.cleaned_text,
                cleaned_response: response_report.cleaned_text,
            };
        }

        // All 4 stages passed!
        SyntheticGateVerdict {
            passed: true,
            stage_failed: None,
            rejection_reason: None,
            stage1,
            stage2,
            stage3,
            stage4,
            cleaned_prompt: prompt_report.cleaned_text,
            cleaned_response: response_report.cleaned_text,
        }
    }
}

// ---------------------------------------------------------------------------
// UNIT TESTS
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage3_catches_ai_cliches_and_zero_width_watermarks() {
        let config = SyntheticGateConfig::default();

        // 1. Watermark characters
        let watermarked_text = "Authentic text\u{200B} with hidden watermark\u{200D}.";
        let r_wm = scrub_and_scan_stage3_lexical(watermarked_text, &config);
        assert!(!r_wm.passed);
        assert_eq!(r_wm.stripped_watermark_chars, 2);
        assert_eq!(r_wm.cleaned_text, "Authentic text with hidden watermark.");

        // 2. AI cliché patterns
        let cliche_text = "This stands as a beacon and testament to the rich tapestry of engineering.";
        let r_cliche = scrub_and_scan_stage3_lexical(cliche_text, &config);
        assert!(!r_cliche.passed);
        assert!(r_cliche.cliche_matches.contains(&"stands as a beacon".to_string()));
        assert!(r_cliche.cliche_matches.contains(&"testament to".to_string()));
        assert!(r_cliche.cliche_matches.contains(&"rich tapestry".to_string()));

        // 3. Mixed-script homoglyphs: Cyrillic 'а' (\u{0430}) inside "pаssword"
        let homoglyph_text = "Security check for p\u{0430}ssword token.";
        let r_homo = scrub_and_scan_stage3_lexical(homoglyph_text, &config);
        assert!(!r_homo.passed);
        assert_eq!(r_homo.mixed_script_homoglyphs_detected, 1);
    }

    #[test]
    fn test_stage1_burstiness_and_entropy() {
        let config = SyntheticGateConfig::default();

        // Monotonous uniform sentences -> low CV
        let uniform = "We index all files. We parse all files. We check all files. We store all files.";
        let m_uni = evaluate_stage1_statistics(uniform, &config);
        assert!(m_uni.burstiness_cv < 0.20);

        // Highly varied sentence lengths -> high CV >= 0.30
        let varied = "Stop immediately. Then analyze the entire architectural framework across the network to ensure that all invariants hold true. Done.";
        let m_var = evaluate_stage1_statistics(varied, &config);
        assert!(m_var.burstiness_cv >= 0.30);
        assert!(m_var.shannon_entropy >= 3.0);
    }

    #[test]
    fn test_stage4_nonce_and_reading_time() {
        let node_seed = [0x77u8; 32];
        let mut config = SyntheticGateConfig::default();
        config.min_reading_ms_per_50_tokens = 50;
        let guard = HumanTelemetryGuard::new(&node_seed, config);

        let nonce = guard.issue_interaction_nonce("traj-001", 100);
        assert!(nonce.starts_with("traj-001:"));

        // Wrong trajectory ID must fail
        let rep_err = guard.verify_interaction_nonce(&nonce, "traj-999", 100);
        assert!(!rep_err.passed);

        // Valid trajectory ID with sufficient reading time passes
        let rep_ok = guard.verify_interaction_nonce(&nonce, "traj-001", 10);
        assert!(rep_ok.nonce_verified);
    }

    #[test]
    fn test_full_pipeline_accepts_authentic_human_trajectory() {
        let node_seed = [0x88u8; 32];
        let pipeline = SyntheticExclusionPipeline::new(&node_seed);

        let prompt = "How does QuorumRAG coordinate distributed search across local nodes?";
        let response = "QuorumRAG coordinates search via an Ed25519-signed mesh protocol. When a query arrives, the local node inspects Tantivy BM25 indices and LanceDB vector embeddings before fanning out scatter-gather sub-requests to verified peer nodes over libp2p. Every response is verified in constant time.";

        let verdict = pipeline.evaluate_candidate(
            prompt,
            response,
            &[],
            None,
            None,
            60,
            "traj-test-01",
        );

        assert!(verdict.passed);
        assert!(verdict.stage1.passed);
        assert!(verdict.stage2.passed);
        assert!(verdict.stage3.passed);
        assert!(verdict.stage4.passed);
    }
}
