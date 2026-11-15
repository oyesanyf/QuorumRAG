//! Bespoke-Nimble-9B decision client, single-pass Ollama logprob constrained scoring,
//! temperature-calibrated log-sum-exp softmax, dynamic memory law gating, and deterministic fallback.

use crate::error::CoordinatorError;
use crate::hardware::HardwareTelemetry;
use quorum_contract::{
    guard_nimble_input_context, NimbleDecisionResult, NIMBLE_MAX_CONTEXT_TOKENS,
};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default loopback endpoint for local Ollama HTTP API.
pub const DEFAULT_NIMBLE_ENDPOINT: &str = "http://127.0.0.1:11434";

/// Default model tag for Bespoke-Nimble-9B.
pub const DEFAULT_NIMBLE_MODEL: &str = "bespoke-nimble:9b";

/// Canonical Hugging Face GGUF source tag for Bespoke-Nimble-9B Q4_K_M.
pub const CANONICAL_NIMBLE_GGUF: &str = "hf.co/ggml-org/Bespoke-Nimble-9B-v3-GGUF:Q4_K_M";

/// Strict 400ms timeout for Ollama health/tag probes.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(400);

/// Minimum runtime free RAM required by Dynamic Available Memory Law (12.0 GB).
pub const MIN_FREE_RAM_GB: f64 = 12.0;

/// Minimum runtime free VRAM required by Dynamic Available Memory Law (6,000 MB).
pub const MIN_FREE_VRAM_MB: u64 = 6000;

/// Runtime client for querying the Bespoke-Nimble-9B decision model via local Ollama.
#[derive(Clone, Debug)]
pub struct NimbleClient {
    /// Ollama HTTP base endpoint (e.g. "http://127.0.0.1:11434").
    pub endpoint: String,
    /// Active model tag (e.g. "bespoke-nimble:9b").
    pub model_tag: String,
    /// Configured HTTP client for async requests.
    pub http_client: reqwest::Client,
}

impl Default for NimbleClient {
    fn default() -> Self {
        Self::default_local()
    }
}

impl NimbleClient {
    /// Create a new `NimbleClient` with custom endpoint and model tag.
    pub fn new(endpoint: impl Into<String>, model_tag: impl Into<String>) -> Self {
        let http_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            model_tag: model_tag.into(),
            http_client,
        }
    }

    /// Create client pointing to the default local Ollama instance and canonical Nimble tag.
    pub fn default_local() -> Self {
        Self::new(DEFAULT_NIMBLE_ENDPOINT, DEFAULT_NIMBLE_MODEL)
    }

    /// Evaluates the Dynamic Available Memory Law strictly on runtime free resources.
    ///
    /// Requires `free_ram_gb >= 12.0 || free_vram_mb >= 6000`.
    /// NEVER checks total physical RAM!
    pub fn check_dynamic_memory_law() -> bool {
        let hw = HardwareTelemetry::probe();
        hw.free_ram_gb >= MIN_FREE_RAM_GB || hw.free_vram_mb >= MIN_FREE_VRAM_MB
    }

    /// Probes local Ollama `GET /api/tags` with a strict 400ms timeout to discover installed models.
    pub async fn probe_ollama_tags(&self) -> Result<Vec<String>, String> {
        let tags_url = format!("{}/api/tags", self.endpoint);

        let resp = self
            .http_client
            .get(&tags_url)
            .timeout(PROBE_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("Probe /api/tags failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("Ollama /api/tags returned status {}", resp.status()));
        }

        let val: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("JSON parse error from /api/tags: {}", e))?;

        let mut models = Vec::new();
        if let Some(arr) = val.get("models").and_then(|m| m.as_array()) {
            for m in arr {
                if let Some(name) = m.get("name").and_then(|n| n.as_str()) {
                    models.push(name.trim().to_string());
                }
            }
        }

        Ok(models)
    }

    /// Determines if Nimble-9B is available for live execution:
    /// 1. Dynamic Available Memory Law passes (`free_ram_gb >= 12.0 || free_vram_mb >= 6000`).
    /// 2. Ollama `/api/tags` responds within 400ms.
    /// 3. The target model tag (or canonical GGUF) is present in installed tags.
    pub async fn is_model_available(&self) -> bool {
        if !Self::check_dynamic_memory_law() {
            tracing::debug!("Dynamic memory law rejected Nimble-9B: insufficient free RAM/VRAM");
            return false;
        }

        match self.probe_ollama_tags().await {
            Ok(models) => {
                let target_clean = self.model_tag.trim().to_ascii_lowercase();
                let canonical_clean = CANONICAL_NIMBLE_GGUF.to_ascii_lowercase();
                models.iter().any(|m| {
                    let m_clean = m.trim().to_ascii_lowercase();
                    m_clean == target_clean
                        || m_clean == canonical_clean
                        || m_clean.starts_with(&target_clean)
                        || target_clean.starts_with(&m_clean)
                })
            }
            Err(e) => {
                tracing::debug!("Ollama probe error: {}", e);
                false
            }
        }
    }

    /// Computes temperature-calibrated softmax over allowed schema choices using log-sum-exp.
    ///
    /// # Math
    /// Given candidate logprobs $\ell_i$ for allowed choices $c_i$:
    /// $$m = \max_j \ell_j, \quad z_j = \frac{\ell_j - m}{T}, \quad S = \sum_j \exp(z_j), \quad P(c_i) = \frac{\exp(z_i)}{S}$$
    ///
    /// Unobserved allowed choices are assigned a small floor logprob ($\approx -25.0$)
    /// so every choice receives non-zero calibrated probability.
    pub fn compute_constrained_softmax(
        logprobs: &[(&str, f64)],
        allowed_choices: &[&str],
        temperature: f64,
    ) -> (String, f64, HashMap<String, f64>) {
        if allowed_choices.is_empty() {
            return (String::new(), 0.0, HashMap::new());
        }

        // Clamp temperature to prevent division by zero
        let t = if temperature <= 0.001 { 1.0 } else { temperature };

        // Normalize logprobs tokens by trimming whitespace (e.g. " SufficientAsIs" -> "SufficientAsIs")
        let mut observed_map: HashMap<String, f64> = HashMap::with_capacity(logprobs.len());
        for &(tok, logprob) in logprobs {
            let norm = tok.trim().to_string();
            // Retain the highest logprob if duplicates occur after trimming
            observed_map
                .entry(norm)
                .and_modify(|existing| {
                    if logprob > *existing {
                        *existing = logprob;
                    }
                })
                .or_insert(logprob);
        }

        // Determine minimum observed logprob to calculate an unobserved floor
        let min_observed = observed_map
            .values()
            .copied()
            .filter(|&v| !v.is_nan() && v.is_finite())
            .fold(f64::INFINITY, f64::min);

        let floor_logprob = if min_observed.is_finite() {
            (min_observed - 15.0).min(-25.0)
        } else {
            -25.0
        };

        // Extract logprob for each allowed choice
        let mut choice_logprobs: Vec<(&str, f64)> = Vec::with_capacity(allowed_choices.len());
        for &choice in allowed_choices {
            let choice_norm = choice.trim();
            // Match exact or case-insensitive
            let lp = observed_map
                .get(choice_norm)
                .copied()
                .or_else(|| {
                    observed_map
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(choice_norm))
                        .map(|(_, &v)| v)
                })
                .unwrap_or(floor_logprob);

            choice_logprobs.push((choice, lp));
        }

        // Find max logprob for numerical stability in log-sum-exp
        let max_lp = choice_logprobs
            .iter()
            .map(|(_, lp)| *lp)
            .fold(f64::NEG_INFINITY, f64::max);

        // Compute sum of exp((lp - max_lp) / t)
        let mut exp_sum = 0.0f64;
        let mut exp_values: Vec<f64> = Vec::with_capacity(choice_logprobs.len());
        for &(_, lp) in &choice_logprobs {
            let z = (lp - max_lp) / t;
            let exp_val = z.exp();
            exp_sum += exp_val;
            exp_values.push(exp_val);
        }

        if exp_sum <= 0.0 || exp_sum.is_nan() {
            exp_sum = 1.0;
        }

        // Compute normalized probabilities and identify winner
        let mut distribution = HashMap::with_capacity(allowed_choices.len());
        let mut winner_choice = allowed_choices[0].to_string();
        let mut max_prob = -1.0f64;

        for (i, &(choice, _)) in choice_logprobs.iter().enumerate() {
            let prob = (exp_values[i] / exp_sum).clamp(0.0, 1.0);
            distribution.insert(choice.to_string(), prob);
            if prob > max_prob {
                max_prob = prob;
                winner_choice = choice.to_string();
            }
        }

        // Final normalization adjustment so sum equals exactly 1.0
        let total_prob: f64 = distribution.values().sum();
        if (total_prob - 1.0).abs() > 1e-6 && total_prob > 0.0 {
            for v in distribution.values_mut() {
                *v /= total_prob;
            }
            max_prob = distribution.get(&winner_choice).copied().unwrap_or(max_prob);
        }

        (winner_choice, max_prob, distribution)
    }

    /// Fast, non-panicking deterministic heuristic fallback executing in <1ms.
    ///
    /// Derives calibrated, valid probability distributions from context characteristics
    /// and cryptographic hashing, ensuring queries never block or fail even if Ollama is offline.
    pub fn decide_fallback(context: &str, allowed_choices: &[&str]) -> NimbleDecisionResult {
        let start = Instant::now();
        if allowed_choices.is_empty() {
            return NimbleDecisionResult::new(
                "",
                0.0,
                HashMap::new(),
                "deterministic-fallback",
                true,
                0,
            );
        }

        let ctx_lower = context.to_ascii_lowercase();

        // 1. RLM Sufficiency rubric evaluation
        let is_rlm_rubric = allowed_choices.iter().any(|&c| {
            c.eq_ignore_ascii_case("SufficientAsIs") || c.eq_ignore_ascii_case("ExpandParent10KB")
        });

        // 2. DFIR Threat rubric evaluation
        let is_dfir_rubric = allowed_choices.iter().any(|&c| {
            c.eq_ignore_ascii_case("BenignVerifiedOsService")
                || c.eq_ignore_ascii_case("HighConfidenceMaliciousIndicator")
        });

        // 3. Boolean rubric evaluation
        let is_boolean_rubric = allowed_choices.len() == 2
            && allowed_choices.iter().any(|&c| c.eq_ignore_ascii_case("Yes"))
            && allowed_choices.iter().any(|&c| c.eq_ignore_ascii_case("No"));

        let mut weights: HashMap<String, f64> = HashMap::with_capacity(allowed_choices.len());

        if is_rlm_rubric {
            let needs_expansion = ctx_lower.contains("need more context")
                || ctx_lower.contains("see above")
                || ctx_lower.contains("continued")
                || ctx_lower.contains("truncated")
                || ctx_lower.contains("incomplete")
                || ctx_lower.contains("...")
                || ctx_lower.contains("[...]");

            let is_noise = ctx_lower.contains("license")
                || ctx_lower.contains("copyright")
                || ctx_lower.contains("all rights reserved")
                || ctx_lower.contains("boilerplate")
                || ctx_lower.contains("unrelated")
                || ctx_lower.contains("privacy policy")
                || ctx_lower.contains("cookie policy")
                || ctx_lower.contains("terms of service")
                || ctx_lower.contains("disclaimer")
                || ctx_lower.contains("advertisement")
                || ctx_lower.contains("irrelevant")
                || ctx_lower.contains("low relevance");

            let needs_subquery = ctx_lower.contains("further investigation")
                || ctx_lower.contains("unknown entity")
                || ctx_lower.contains("separate query");

            for &choice in allowed_choices {
                let w = if choice.eq_ignore_ascii_case("DropIrrelevantSpan") {
                    if is_noise { 0.85 } else { 0.05 }
                } else if choice.eq_ignore_ascii_case("ExpandParent10KB") {
                    if needs_expansion { 0.80 } else { 0.15 }
                } else if choice.eq_ignore_ascii_case("SpawnFollowUpSubquery") {
                    if needs_subquery { 0.75 } else { 0.10 }
                } else if choice.eq_ignore_ascii_case("SufficientAsIs") {
                    if !needs_expansion && !is_noise && !needs_subquery { 0.88 } else { 0.12 }
                } else {
                    0.10
                };
                weights.insert(choice.to_string(), w);
            }
        } else if is_dfir_rubric {
            let is_known_os = ctx_lower.contains("svchost")
                || ctx_lower.contains("dnscache")
                || ctx_lower.contains("systemd-resolved")
                || ctx_lower.contains("signed by microsoft")
                || ctx_lower.contains("system32");

            let is_malicious = ctx_lower.contains("mimikatz")
                || ctx_lower.contains("powershell -enc")
                || ctx_lower.contains("meterpreter")
                || ctx_lower.contains("c2 beacon")
                || ctx_lower.contains("dns tunnel")
                || ctx_lower.contains("base64 payload");

            let is_anomaly = ctx_lower.contains("unusual port")
                || ctx_lower.contains("unsigned binary")
                || ctx_lower.contains("suspicious parent")
                || ctx_lower.contains("high entropy");

            for &choice in allowed_choices {
                let w = if choice.eq_ignore_ascii_case("HighConfidenceMaliciousIndicator") {
                    if is_malicious { 0.94 } else { 0.02 }
                } else if choice.eq_ignore_ascii_case("AnomalousNeedsInvestigation") {
                    if is_anomaly && !is_malicious { 0.82 } else { 0.08 }
                } else if choice.eq_ignore_ascii_case("BenignVerifiedOsService") {
                    if is_known_os && !is_malicious { 0.92 } else { 0.05 }
                } else if choice.eq_ignore_ascii_case("BenignUserApplication") {
                    if !is_known_os && !is_malicious && !is_anomaly { 0.80 } else { 0.10 }
                } else {
                    0.05
                };
                weights.insert(choice.to_string(), w);
            }
        } else if is_boolean_rubric {
            let affirmative = ctx_lower.contains("yes")
                || ctx_lower.contains("true")
                || ctx_lower.contains("relevant")
                || ctx_lower.contains("sufficient")
                || ctx_lower.contains("match");

            for &choice in allowed_choices {
                let w = if choice.eq_ignore_ascii_case("Yes") {
                    if affirmative { 0.82 } else { 0.18 }
                } else {
                    if affirmative { 0.18 } else { 0.82 }
                };
                weights.insert(choice.to_string(), w);
            }
        } else {
            // General uniform prior with deterministic BLAKE3 tie-breaking
            let hash = blake3::hash(context.as_bytes());
            let hash_bytes = hash.as_bytes();
            let prime_choice_idx = (hash_bytes[0] as usize) % allowed_choices.len();

            for (i, &choice) in allowed_choices.iter().enumerate() {
                let w = if i == prime_choice_idx { 0.70 } else { 0.30 / (allowed_choices.len() - 1).max(1) as f64 };
                weights.insert(choice.to_string(), w);
            }
        }

        // Normalize weights to sum to 1.0
        let total_weight: f64 = weights.values().sum();
        let mut distribution = HashMap::with_capacity(allowed_choices.len());
        let mut winner_choice = allowed_choices[0].to_string();
        let mut winner_prob = -1.0f64;

        for (k, v) in weights {
            let norm_prob = if total_weight > 0.0 { v / total_weight } else { 1.0 / allowed_choices.len() as f64 };
            if norm_prob > winner_prob {
                winner_prob = norm_prob;
                winner_choice = k.clone();
            }
            distribution.insert(k, norm_prob);
        }

        let elapsed = start.elapsed().as_millis().max(0) as u64;

        NimbleDecisionResult::new(
            winner_choice,
            winner_prob,
            distribution,
            "deterministic-fallback",
            true,
            elapsed,
        )
    }

    /// Evaluates a constrained decision query against Bespoke-Nimble-9B via local Ollama.
    ///
    /// # Process
    /// 1. Applies `guard_nimble_input_context` to safely truncate input to 8,192 tokens.
    /// 2. Checks Dynamic Available Memory Law; executes fallback immediately if insufficient.
    /// 3. Sends single-pass constrained HTTP `POST /api/generate` with options:
    ///    `raw: true`, `num_predict: 2`, `temperature: 0.0`, `num_ctx: 8192`, `logprobs: true`, `top_logprobs: 16`.
    /// 4. Extracts logprobs from response and computes temperature-calibrated softmax over allowed choices.
    /// 5. Automatically falls back to deterministic decision if Ollama is unreachable, slow, or unprovisioned.
    pub async fn decide_choice(
        &self,
        context: &str,
        prompt_instruction: &str,
        allowed_choices: &[&str],
        temperature: f64,
    ) -> Result<NimbleDecisionResult, CoordinatorError> {
        let start = Instant::now();

        if allowed_choices.is_empty() {
            return Ok(NimbleDecisionResult::new(
                "",
                0.0,
                HashMap::new(),
                &self.model_tag,
                false,
                0,
            ));
        }

        // 1. Strict UTF-8 input guard at 8,192 tokens
        let guarded_context = guard_nimble_input_context(context, NIMBLE_MAX_CONTEXT_TOKENS);

        // 2. Dynamic Available Memory Law check
        if !Self::check_dynamic_memory_law() {
            tracing::debug!("Dynamic Available Memory Law: skipping live model query, executing fallback");
            let mut fb = Self::decide_fallback(guarded_context, allowed_choices);
            fb.latency_ms = start.elapsed().as_millis() as u64;
            return Ok(fb);
        }

        // 3. Format structured constrained prompt
        let choices_formatted = allowed_choices.join(", ");
        let full_prompt = format!(
            "<|im_start|>system\nYou are a precise decision classifier. Select exactly one choice from the allowed choices.\nAllowed Choices: [{}]\n<|im_end|>\n<|im_start|>user\n[Context]\n{}\n\n[Instruction]\n{}\n<|im_end|>\n<|im_start|>assistant\n",
            choices_formatted, guarded_context, prompt_instruction
        );

        // 4. Build single-pass payload
        let payload = json!({
            "model": self.model_tag,
            "prompt": full_prompt,
            "raw": true,
            "stream": false,
            "options": {
                "temperature": 0.0,
                "num_predict": 2,
                "num_ctx": 8192,
                "logprobs": true,
                "top_logprobs": 16
            }
        });

        let generate_url = format!("{}/api/generate", self.endpoint);

        // 5. Send HTTP request
        let send_res = self
            .http_client
            .post(&generate_url)
            .json(&payload)
            .send()
            .await;

        let resp = match send_res {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::debug!("Ollama /api/generate HTTP status {}; falling back", r.status());
                let mut fb = Self::decide_fallback(guarded_context, allowed_choices);
                fb.latency_ms = start.elapsed().as_millis() as u64;
                return Ok(fb);
            }
            Err(e) => {
                tracing::debug!("Ollama /api/generate connection error: {}; falling back", e);
                let mut fb = Self::decide_fallback(guarded_context, allowed_choices);
                fb.latency_ms = start.elapsed().as_millis() as u64;
                return Ok(fb);
            }
        };

        // 6. Parse response JSON
        let val: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("Failed to parse /api/generate JSON: {}; falling back", e);
                let mut fb = Self::decide_fallback(guarded_context, allowed_choices);
                fb.latency_ms = start.elapsed().as_millis() as u64;
                return Ok(fb);
            }
        };

        // 7. Extract logprobs
        let mut extracted_logprobs: Vec<(String, f64)> = Vec::new();

        if let Some(logprobs_arr) = val.get("logprobs").and_then(|lp| lp.as_array()) {
            for entry in logprobs_arr {
                if let Some(top_arr) = entry.get("top_logprobs").and_then(|t| t.as_array()) {
                    for item in top_arr {
                        if let (Some(tok), Some(lp)) = (
                            item.get("token").and_then(|t| t.as_str()),
                            item.get("logprob").and_then(|l| l.as_f64()),
                        ) {
                            extracted_logprobs.push((tok.to_string(), lp));
                        }
                    }
                } else if let (Some(tok), Some(lp)) = (
                    entry.get("token").and_then(|t| t.as_str()),
                    entry.get("logprob").and_then(|l| l.as_f64()),
                ) {
                    extracted_logprobs.push((tok.to_string(), lp));
                }
            }
        }

        // If no logprobs extracted, check direct text response
        if extracted_logprobs.is_empty() {
            if let Some(text_resp) = val.get("response").and_then(|r| r.as_str()) {
                let trimmed = text_resp.trim();
                for &choice in allowed_choices {
                    if choice.eq_ignore_ascii_case(trimmed) {
                        extracted_logprobs.push((choice.to_string(), 0.0));
                    }
                }
            }
        }

        if extracted_logprobs.is_empty() {
            tracing::debug!("No logprobs or matching text in Ollama response; using fallback");
            let mut fb = Self::decide_fallback(guarded_context, allowed_choices);
            fb.latency_ms = start.elapsed().as_millis() as u64;
            return Ok(fb);
        }

        let slice_logprobs: Vec<(&str, f64)> = extracted_logprobs
            .iter()
            .map(|(s, f)| (s.as_str(), *f))
            .collect();

        let (winner, prob, distribution) =
            Self::compute_constrained_softmax(&slice_logprobs, allowed_choices, temperature);

        let elapsed = start.elapsed().as_millis() as u64;

        Ok(NimbleDecisionResult::new(
            winner,
            prob,
            distribution,
            &self.model_tag,
            false,
            elapsed,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    #[test]
    fn test_compute_constrained_softmax_calibration() {
        let allowed = ["SufficientAsIs", "ExpandParent10KB", "SpawnFollowUpSubquery", "DropIrrelevantSpan"];
        let logprobs = [
            (" SufficientAsIs", -0.15),
            ("ExpandParent10KB", -2.85),
            ("SpawnFollowUpSubquery", -4.50),
            ("DropIrrelevantSpan", -6.00),
        ];

        let (winner, prob, dist) =
            NimbleClient::compute_constrained_softmax(&logprobs, &allowed, 1.0);

        assert_eq!(winner, "SufficientAsIs");
        assert!(prob > 0.85, "Expected high calibrated probability for winner, got {}", prob);
        assert_eq!(dist.len(), 4);

        // Invariant: sum of probabilities == 1.0
        let sum: f64 = dist.values().sum();
        assert!((sum - 1.0).abs() < 1e-5, "Sum of probabilities must equal 1.0, got {}", sum);

        // Invariant: all non-negative
        for &p in dist.values() {
            assert!(p >= 0.0 && p <= 1.0);
        }
    }

    #[test]
    fn test_compute_constrained_softmax_unobserved_choices_floor() {
        let allowed = ["Yes", "No"];
        // Only "Yes" was observed in logprobs
        let logprobs = [("Yes", -0.05)];

        let (winner, prob, dist) =
            NimbleClient::compute_constrained_softmax(&logprobs, &allowed, 1.0);

        assert_eq!(winner, "Yes");
        assert!(prob > 0.95);
        let no_prob = dist.get("No").copied().unwrap_or(0.0);
        assert!(no_prob > 0.0, "Unobserved choice must receive epsilon floor probability");
        assert!((prob + no_prob - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_deterministic_fallback_execution() {
        let allowed = ["SufficientAsIs", "ExpandParent10KB", "SpawnFollowUpSubquery", "DropIrrelevantSpan"];
        let res = NimbleClient::decide_fallback("Here is the complete section with full answer.", &allowed);

        assert!(res.used_fallback);
        assert_eq!(res.model_tag, "deterministic-fallback");
        assert!(res.is_valid_distribution());
        assert_eq!(res.selected_choice, "SufficientAsIs");

        // Needs expansion keyword
        let res_exp = NimbleClient::decide_fallback("Short reference, need more context continued...", &allowed);
        assert_eq!(res_exp.selected_choice, "ExpandParent10KB");

        // Noise keyword
        let res_noise = NimbleClient::decide_fallback("Copyright 2026. All rights reserved. Boilerplate license.", &allowed);
        assert_eq!(res_noise.selected_choice, "DropIrrelevantSpan");

        // Subquery keyword
        let res_sub = NimbleClient::decide_fallback("Mentions an unknown entity requiring further investigation in a separate query.", &allowed);
        assert_eq!(res_sub.selected_choice, "SpawnFollowUpSubquery");
    }

    #[test]
    fn test_dfir_deterministic_fallback() {
        let allowed = [
            "BenignVerifiedOsService",
            "BenignUserApplication",
            "AnomalousNeedsInvestigation",
            "HighConfidenceMaliciousIndicator",
        ];

        let benign_ctx = "C:\\Windows\\System32\\svchost.exe -k NetworkService (Dnscache) signed by Microsoft";
        let res_benign = NimbleClient::decide_fallback(benign_ctx, &allowed);
        assert_eq!(res_benign.selected_choice, "BenignVerifiedOsService");

        let mal_ctx = "powershell -enc aW52b2tlLW1pbWlrYXR6 c2 beacon dns tunnel";
        let res_mal = NimbleClient::decide_fallback(mal_ctx, &allowed);
        assert_eq!(res_mal.selected_choice, "HighConfidenceMaliciousIndicator");
    }

    #[tokio::test]
    async fn test_wire_protocol_mock_ollama_successful_logprob_scoring() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let local_addr = listener.local_addr().expect("local addr");
        let endpoint = format!("http://{}", local_addr);

        let server_handle = tokio::task::spawn_blocking(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf);

                let mock_response = json!({
                    "model": "bespoke-nimble:9b",
                    "response": "SufficientAsIs",
                    "done": true,
                    "logprobs": [
                        {
                            "token": "SufficientAsIs",
                            "logprob": -0.08,
                            "top_logprobs": [
                                { "token": "SufficientAsIs", "logprob": -0.08 },
                                { "token": "ExpandParent10KB", "logprob": -3.10 },
                                { "token": "SpawnFollowUpSubquery", "logprob": -4.50 },
                                { "token": "DropIrrelevantSpan", "logprob": -5.20 }
                            ]
                        }
                    ]
                })
                .to_string();

                let http_response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    mock_response.len(),
                    mock_response
                );
                let _ = stream.write_all(http_response.as_bytes());
            }
        });

        let client = NimbleClient::new(endpoint, "bespoke-nimble:9b");
        let allowed = ["SufficientAsIs", "ExpandParent10KB", "SpawnFollowUpSubquery", "DropIrrelevantSpan"];

        // Test decision choice
        let res = client
            .decide_choice("Test context chunk", "Assess sufficiency", &allowed, 1.0)
            .await
            .expect("decide_choice succeeded");

        server_handle.await.expect("server completed");

        assert_eq!(res.selected_choice, "SufficientAsIs");
        assert!(res.is_valid_distribution());
        assert!(!res.used_fallback);
        assert_eq!(res.model_tag, "bespoke-nimble:9b");
        assert!(res.calibrated_probability > 0.85);
    }

    #[tokio::test]
    async fn test_wire_protocol_mock_ollama_400ms_timeout_fallback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let local_addr = listener.local_addr().expect("local addr");
        let endpoint = format!("http://{}", local_addr);

        // Server that delays longer than probe timeout
        let server_handle = tokio::task::spawn_blocking(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_millis(600));
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n{}");
            }
        });

        let client = NimbleClient::new(endpoint, "bespoke-nimble:9b");

        // Direct probe should fail with timeout within ~400ms
        let start = Instant::now();
        let probe_res = client.probe_ollama_tags().await;
        let elapsed = start.elapsed();

        assert!(probe_res.is_err(), "Probe must fail on slow mock server");
        assert!(elapsed < Duration::from_millis(800), "Probe timeout should be near 400ms, was {:?}", elapsed);

        // Fallback decision should execute without panic
        let allowed = ["Yes", "No"];
        let fb_res = NimbleClient::decide_fallback("Some text", &allowed);
        assert!(fb_res.used_fallback);
        assert!(fb_res.is_valid_distribution());

        server_handle.await.expect("server completed");
    }
}
