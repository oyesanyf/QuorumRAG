//! Typed Nimble decision contracts, rubric schemas, and safe token input guards for QuorumRAG.
//!
//! Provides canonical serialization structures for Nimble-9B decisions, including:
//! - `NimbleDecisionResult`: Calibrated decision output with full distribution map, latency, and fallback status.
//! - `RlmSufficiencyChoice`: 4-way decision rubric for RLM context expansion and sufficiency.
//! - `DfirThreatLevel`: 4-level rubric for Artemis DFIR telemetry classification.
//! - `NimbleBooleanChoice`: Binary Yes/No decision rubric.
//! - `guard_nimble_input_context`: Strict 8,192-token input guard safely truncated on UTF-8 boundaries.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Maximum context tokens supported by Bespoke-Nimble-9B in standard configuration.
pub const NIMBLE_MAX_CONTEXT_TOKENS: usize = 8192;

/// Average character-to-token ratio used for fast zero-allocation context truncation.
pub const CHARS_PER_TOKEN_ESTIMATE: usize = 4;

/// Result of a single-pass constrained Nimble-9B decision query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NimbleDecisionResult {
    /// The winning schema choice string (e.g. "SufficientAsIs", "Yes", etc.).
    pub selected_choice: String,

    /// Calibrated probability $P(\text{selected\_choice}) \in [0.0, 1.0]$.
    pub calibrated_probability: f64,

    /// Full normalized probability distribution over all allowed schema choices.
    pub probabilities: HashMap<String, f64>,

    /// Identifier of the model that generated the decision (or "deterministic-fallback").
    pub model_tag: String,

    /// Whether this result was produced by the fast deterministic heuristic fallback.
    pub used_fallback: bool,

    /// Elapsed query latency in milliseconds.
    pub latency_ms: u64,
}

impl NimbleDecisionResult {
    /// Create a new `NimbleDecisionResult`.
    pub fn new(
        selected_choice: impl Into<String>,
        calibrated_probability: f64,
        probabilities: HashMap<String, f64>,
        model_tag: impl Into<String>,
        used_fallback: bool,
        latency_ms: u64,
    ) -> Self {
        Self {
            selected_choice: selected_choice.into(),
            calibrated_probability,
            probabilities,
            model_tag: model_tag.into(),
            used_fallback,
            latency_ms,
        }
    }

    /// Check if the probability distribution is mathematically valid (non-negative, sums to ~1.0).
    pub fn is_valid_distribution(&self) -> bool {
        if self.probabilities.is_empty() {
            return false;
        }
        let mut sum = 0.0f64;
        for &p in self.probabilities.values() {
            if p.is_nan() || p < 0.0 || p > 1.0 {
                return false;
            }
            sum += p;
        }
        (sum - 1.0).abs() < 1e-4
    }

    /// Returns probability for a specific choice label, or 0.0 if not present.
    pub fn probability_of(&self, choice: &str) -> f64 {
        self.probabilities.get(choice).copied().unwrap_or(0.0)
    }
}

/// RLM Context Sufficiency and Window Expansion Rubric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RlmSufficiencyChoice {
    /// Context span is self-contained and answers the target subquery directly.
    SufficientAsIs,
    /// Context span references adjacent facts; expand document window by 10,000 bytes.
    ExpandParent10KB,
    /// Context is incomplete or introduces a new entity requiring an independent retrieval hop.
    SpawnFollowUpSubquery,
    /// Context is false-positive noise, lexical boilerplate, or unrelated distractor.
    DropIrrelevantSpan,
}

impl RlmSufficiencyChoice {
    /// String representation matching schema tokens.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SufficientAsIs => "SufficientAsIs",
            Self::ExpandParent10KB => "ExpandParent10KB",
            Self::SpawnFollowUpSubquery => "SpawnFollowUpSubquery",
            Self::DropIrrelevantSpan => "DropIrrelevantSpan",
        }
    }

    /// All schema choice string labels in canonical order.
    pub const fn all_choices() -> &'static [&'static str] {
        &[
            "SufficientAsIs",
            "ExpandParent10KB",
            "SpawnFollowUpSubquery",
            "DropIrrelevantSpan",
        ]
    }

    /// Parse case-insensitively from a string slice.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("SufficientAsIs") {
            Some(Self::SufficientAsIs)
        } else if trimmed.eq_ignore_ascii_case("ExpandParent10KB") {
            Some(Self::ExpandParent10KB)
        } else if trimmed.eq_ignore_ascii_case("SpawnFollowUpSubquery") {
            Some(Self::SpawnFollowUpSubquery)
        } else if trimmed.eq_ignore_ascii_case("DropIrrelevantSpan") {
            Some(Self::DropIrrelevantSpan)
        } else {
            None
        }
    }
}

impl fmt::Display for RlmSufficiencyChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RlmSufficiencyChoice {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s).ok_or_else(|| format!("Unknown RlmSufficiencyChoice: '{}'", s))
    }
}

/// 4-Level DFIR Threat Rubric for Artemis Telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DfirThreatLevel {
    /// Digitally signed, verified operating system background service (e.g. svchost.exe Dnscache, systemd-resolved).
    BenignVerifiedOsService,
    /// Legitimate user or developer application without anomalous behavior or network persistence.
    BenignUserApplication,
    /// Execution or network anomaly requiring forensic analyst investigation.
    AnomalousNeedsInvestigation,
    /// High-confidence malicious indicator (C2 beaconing, DNS tunneling, credential dumping, process hollowing).
    HighConfidenceMaliciousIndicator,
}

impl DfirThreatLevel {
    /// String representation matching schema tokens.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::BenignVerifiedOsService => "BenignVerifiedOsService",
            Self::BenignUserApplication => "BenignUserApplication",
            Self::AnomalousNeedsInvestigation => "AnomalousNeedsInvestigation",
            Self::HighConfidenceMaliciousIndicator => "HighConfidenceMaliciousIndicator",
        }
    }

    /// All schema choice string labels in canonical order.
    pub const fn all_choices() -> &'static [&'static str] {
        &[
            "BenignVerifiedOsService",
            "BenignUserApplication",
            "AnomalousNeedsInvestigation",
            "HighConfidenceMaliciousIndicator",
        ]
    }

    /// Parse case-insensitively from a string slice.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("BenignVerifiedOsService") {
            Some(Self::BenignVerifiedOsService)
        } else if trimmed.eq_ignore_ascii_case("BenignUserApplication") {
            Some(Self::BenignUserApplication)
        } else if trimmed.eq_ignore_ascii_case("AnomalousNeedsInvestigation") {
            Some(Self::AnomalousNeedsInvestigation)
        } else if trimmed.eq_ignore_ascii_case("HighConfidenceMaliciousIndicator") {
            Some(Self::HighConfidenceMaliciousIndicator)
        } else {
            None
        }
    }

    /// Whether this level indicates an anomalous or hostile event.
    pub const fn is_suspicious_or_hostile(&self) -> bool {
        matches!(self, Self::AnomalousNeedsInvestigation | Self::HighConfidenceMaliciousIndicator)
    }
}

impl fmt::Display for DfirThreatLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DfirThreatLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s).ok_or_else(|| format!("Unknown DfirThreatLevel: '{}'", s))
    }
}

/// Binary Boolean Choice Rubric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum NimbleBooleanChoice {
    Yes,
    No,
}

impl NimbleBooleanChoice {
    /// String representation matching schema tokens.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Yes => "Yes",
            Self::No => "No",
        }
    }

    /// All schema choice string labels.
    pub const fn all_choices() -> &'static [&'static str] {
        &["Yes", "No"]
    }

    /// Parse case-insensitively from a string slice.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("Yes") || trimmed.eq_ignore_ascii_case("True") {
            Some(Self::Yes)
        } else if trimmed.eq_ignore_ascii_case("No") || trimmed.eq_ignore_ascii_case("False") {
            Some(Self::No)
        } else {
            None
        }
    }

    /// Convert to primitive boolean.
    pub const fn to_bool(&self) -> bool {
        matches!(self, Self::Yes)
    }

    /// Convert from primitive boolean.
    pub const fn from_bool(val: bool) -> Self {
        if val {
            Self::Yes
        } else {
            Self::No
        }
    }
}

impl fmt::Display for NimbleBooleanChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NimbleBooleanChoice {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str(s).ok_or_else(|| format!("Unknown NimbleBooleanChoice: '{}'", s))
    }
}

/// Strict input guard that approximates token count and safely truncates text
/// at the nearest preceding valid UTF-8 character boundary without slicing mid-codepoint.
///
/// Ensures inputs sent to Nimble-9B never exceed model context limits (default 8,192 tokens),
/// preventing context overflow crashes or silent truncation errors.
pub fn guard_nimble_input_context(text: &str, max_tokens: usize) -> &str {
    let max_bytes = max_tokens.saturating_mul(CHARS_PER_TOKEN_ESTIMATE);
    if text.len() <= max_bytes {
        return text;
    }

    // Step backwards from max_bytes to find the nearest valid UTF-8 character boundary
    let mut boundary = max_bytes;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }

    &text[..boundary]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nimble_decision_result_serialization() {
        let mut probs = HashMap::new();
        probs.insert("SufficientAsIs".to_string(), 0.85);
        probs.insert("ExpandParent10KB".to_string(), 0.10);
        probs.insert("SpawnFollowUpSubquery".to_string(), 0.03);
        probs.insert("DropIrrelevantSpan".to_string(), 0.02);

        let res = NimbleDecisionResult::new(
            "SufficientAsIs",
            0.85,
            probs.clone(),
            "bespoke-nimble:9b",
            false,
            42,
        );

        assert!(res.is_valid_distribution());
        assert_eq!(res.probability_of("SufficientAsIs"), 0.85);
        assert_eq!(res.probability_of("NonExistent"), 0.0);

        let json = serde_json::to_string(&res).expect("serialization failed");
        let deserialized: NimbleDecisionResult =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(res, deserialized);
        assert_eq!(deserialized.selected_choice, "SufficientAsIs");
        assert_eq!(deserialized.latency_ms, 42);
        assert!(!deserialized.used_fallback);
    }

    #[test]
    fn test_rlm_sufficiency_choice_enum_properties() {
        let choices = RlmSufficiencyChoice::all_choices();
        assert_eq!(choices.len(), 4);
        assert_eq!(choices[0], "SufficientAsIs");
        assert_eq!(choices[1], "ExpandParent10KB");
        assert_eq!(choices[2], "SpawnFollowUpSubquery");
        assert_eq!(choices[3], "DropIrrelevantSpan");

        for &choice_str in choices {
            let parsed = RlmSufficiencyChoice::from_str(choice_str).expect("failed to parse");
            assert_eq!(parsed.as_str(), choice_str);
            assert_eq!(parsed.to_string(), choice_str);

            let json = serde_json::to_string(&parsed).expect("json serialize");
            let from_json: RlmSufficiencyChoice =
                serde_json::from_str(&json).expect("json deserialize");
            assert_eq!(parsed, from_json);
        }

        assert!(RlmSufficiencyChoice::from_str("InvalidChoice").is_none());
    }

    #[test]
    fn test_dfir_threat_level_enum_properties() {
        let choices = DfirThreatLevel::all_choices();
        assert_eq!(choices.len(), 4);

        for &choice_str in choices {
            let parsed = DfirThreatLevel::from_str(choice_str).expect("failed to parse");
            assert_eq!(parsed.as_str(), choice_str);
            assert_eq!(parsed.to_string(), choice_str);

            let json = serde_json::to_string(&parsed).expect("json serialize");
            let from_json: DfirThreatLevel = serde_json::from_str(&json).expect("json deserialize");
            assert_eq!(parsed, from_json);
        }

        assert!(DfirThreatLevel::HighConfidenceMaliciousIndicator.is_suspicious_or_hostile());
        assert!(DfirThreatLevel::AnomalousNeedsInvestigation.is_suspicious_or_hostile());
        assert!(!DfirThreatLevel::BenignVerifiedOsService.is_suspicious_or_hostile());
        assert!(!DfirThreatLevel::BenignUserApplication.is_suspicious_or_hostile());
    }

    #[test]
    fn test_nimble_boolean_choice_enum_properties() {
        assert_eq!(NimbleBooleanChoice::Yes.to_bool(), true);
        assert_eq!(NimbleBooleanChoice::No.to_bool(), false);
        assert_eq!(NimbleBooleanChoice::from_bool(true), NimbleBooleanChoice::Yes);
        assert_eq!(NimbleBooleanChoice::from_bool(false), NimbleBooleanChoice::No);

        assert_eq!(NimbleBooleanChoice::from_str("yes"), Some(NimbleBooleanChoice::Yes));
        assert_eq!(NimbleBooleanChoice::from_str("true"), Some(NimbleBooleanChoice::Yes));
        assert_eq!(NimbleBooleanChoice::from_str("no"), Some(NimbleBooleanChoice::No));
        assert_eq!(NimbleBooleanChoice::from_str("false"), Some(NimbleBooleanChoice::No));
        assert_eq!(NimbleBooleanChoice::from_str("maybe"), None);
    }

    #[test]
    fn test_guard_nimble_input_context_basic() {
        let short = "Hello world";
        assert_eq!(guard_nimble_input_context(short, 100), short);

        let text = "abcdefghijklmnopqrstuvwxyz";
        // max 2 tokens -> 8 bytes -> "abcdefgh"
        let guarded = guard_nimble_input_context(text, 2);
        assert_eq!(guarded, "abcdefgh");
    }

    #[test]
    fn test_guard_nimble_input_context_utf8_multibyte_safety() {
        // Multi-byte unicode:
        // '🦀' is 4 bytes (0xF0, 0x9F, 0xA6, 0x80)
        // '世' is 3 bytes (0xE4, 0xB8, 0x96)
        // '界' is 3 bytes (0xE7, 0x95, 0x8C)
        let unicode_text = "🦀🦀🦀世界";
        // 3 crabs (12 bytes) + 2 cjk (6 bytes) = 18 bytes total.

        // If max_bytes is 5 (e.g. 5 bytes), slicing at 5 would split the 2nd crab mid-codepoint (byte 4..8).
        // Our guard should safely rewind to byte 4 (1 crab).
        let guarded = guard_nimble_input_context(unicode_text, 1); // 1 token = 4 bytes
        assert_eq!(guarded, "🦀");

        // Test with max_bytes landing mid-CJK character
        let cjk_text = "世界你好"; // 12 bytes (4 chars * 3 bytes)
        // 1 token = 4 bytes. byte 4 is inside '界' (bytes 3..6). Should rewind to 3 ("世").
        let guarded_cjk = guard_nimble_input_context(cjk_text, 1);
        assert_eq!(guarded_cjk, "世");
    }

    #[test]
    fn test_guard_nimble_input_context_large_text() {
        let large_string = "a".repeat(100_000);
        let guarded = guard_nimble_input_context(&large_string, NIMBLE_MAX_CONTEXT_TOKENS);
        assert_eq!(guarded.len(), NIMBLE_MAX_CONTEXT_TOKENS * CHARS_PER_TOKEN_ESTIMATE);
        assert_eq!(guarded.len(), 32_768);
    }

    #[test]
    fn test_nimble_distribution_validation() {
        let mut valid_probs = HashMap::new();
        valid_probs.insert("Yes".to_string(), 0.7);
        valid_probs.insert("No".to_string(), 0.3);

        let res = NimbleDecisionResult::new("Yes", 0.7, valid_probs, "test", false, 10);
        assert!(res.is_valid_distribution());

        let mut invalid_sum = HashMap::new();
        invalid_sum.insert("Yes".to_string(), 0.9);
        invalid_sum.insert("No".to_string(), 0.3);
        let res_invalid = NimbleDecisionResult::new("Yes", 0.9, invalid_sum, "test", false, 10);
        assert!(!res_invalid.is_valid_distribution());

        let mut negative_prob = HashMap::new();
        negative_prob.insert("Yes".to_string(), -0.1);
        negative_prob.insert("No".to_string(), 1.1);
        let res_negative = NimbleDecisionResult::new("No", 1.1, negative_prob, "test", false, 10);
        assert!(!res_negative.is_valid_distribution());
    }
}
