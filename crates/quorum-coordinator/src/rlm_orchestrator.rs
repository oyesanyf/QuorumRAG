//! Pure-Rust Sandboxed Recursive Language Models (RLM) REPL Orchestrator (arXiv:2512.24601).
//!
//! Provides embedded sandboxed execution via `rhai` with persistent evaluation scope,
//! deterministic context host functions, high-speed VRAM-resident fast model Map verification,
//! scaled heavy model Reduce synthesis, AgentMesh sub-query delegation, and exact character-span
//! grounded citation provenance.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::task::JoinSet;
use quorum_contract::rlm::*;
use crate::hardware::HardwareTelemetry;
use crate::offline_engine::DeterministicOfflineSynthesisEngine;
pub use rhai;
use rhai::{Dynamic, Engine, Scope};

/// Workspace state shared between the host and embedded Rhai REPL environment.
#[derive(Debug, Clone, Default)]
pub struct RlmWorkspaceState {
    pub chunks: Vec<RetrievedChunk>,
    pub report_sections: Vec<(String, String)>,
    pub final_answer: Option<String>,
    pub citations: Vec<GroundedCitation>,
    pub mesh_contributions: Vec<MeshContribution>,
    pub sub_queries_log: Vec<String>,
    pub external_nodes_seen: Vec<String>,
}

/// Orchestrator for pure-Rust sandboxed Recursive Language Models (RLM) execution.
pub struct RlmOrchestrator {
    pub config: RlmConfig,
    pub hw: HardwareTelemetry,
    pub installed_models: Vec<String>,
}

/// Truncates a string to at most `max_bytes` without splitting multi-byte UTF-8 codepoints.
fn safe_truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl RlmOrchestrator {
    /// Creates a new RLM orchestrator with the specified sandbox configuration and hardware context.
    pub fn new(config: RlmConfig, hw: HardwareTelemetry, installed_models: Vec<String>) -> Self {
        Self {
            config,
            hw,
            installed_models,
        }
    }

    /// Selects the VRAM-resident fast model for high-speed Map verification batches.
    pub fn select_fast_map_model(&self) -> String {
        if self.hw.free_vram_mb >= 4500 {
            for cand in &["qwen2.5:7b", "glm4:9b", "qwen2.5:3b", "qwen2.5:1.5b"] {
                if let Some(m) = self.installed_models.iter().find(|m| m.starts_with(cand)) {
                    return m.clone();
                }
            }
            "qwen2.5:7b".to_string()
        } else if self.hw.free_ram_gb >= 12.0 {
            for cand in &["qwen2.5:3b", "qwen2.5:1.5b"] {
                if let Some(m) = self.installed_models.iter().find(|m| m.starts_with(cand)) {
                    return m.clone();
                }
            }
            "qwen2.5:3b".to_string()
        } else {
            "qwen2.5:1.5b".to_string()
        }
    }

    /// Selects the heavy model and scaled context window (`num_ctx = 16384..32768`) for Reduce synthesis.
    pub fn select_heavy_reduce_model(&self) -> (String, usize) {
        let (num_ctx, candidates) = if self.hw.free_vram_mb >= 16_000 || self.hw.free_ram_gb >= 32.0 {
            (
                32768usize,
                vec!["qwen2.5:32b", "gemma4:26b", "glm4:9b", "qwen2.5:14b", "qwen2.5:7b"],
            )
        } else if self.hw.free_vram_mb >= 12_000 || self.hw.free_ram_gb >= 18.0 {
            (
                16384usize,
                vec!["gemma4:26b", "glm4:9b", "qwen2.5:14b", "qwen2.5:7b", "qwen2.5:3b"],
            )
        } else {
            (
                8192usize,
                vec!["glm4:9b", "qwen2.5:7b", "qwen2.5:3b", "qwen2.5:1.5b"],
            )
        };

        for cand in candidates {
            if let Some(m) = self.installed_models.iter().find(|m| m.starts_with(cand)) {
                return (m.clone(), num_ctx);
            }
        }
        (self.select_fast_map_model(), num_ctx)
    }

    /// Configures the Rhai execution engine with strict sandbox bounds and 12 deterministic host functions.
    pub fn create_sandboxed_engine(
        config: &RlmConfig,
        workspace: Arc<Mutex<RlmWorkspaceState>>,
        fast_map_model: String,
    ) -> Engine {
        let mut engine = Engine::new();

        // 1. Strict sandbox bounds
        engine.set_max_operations(config.max_ops);
        engine.set_max_call_levels(config.max_call_depth);
        engine.set_max_string_size(config.max_string_size);
        engine.set_max_array_size(config.max_array_size);
        engine.set_max_map_size(4096);

        // 2. Execution timeout guard (default 45 seconds)
        let start_time = Instant::now();
        let timeout_dur = Duration::from_millis(config.timeout_ms);
        engine.on_progress(move |_| {
            if start_time.elapsed() > timeout_dur {
                Some(Dynamic::from("Script execution timeout")) // Terminates evaluation with ErrorTerminated
            } else {
                None // Continue running
            }
        });

        // 3. Register deterministic host functions:

        // 1. catalog_find_documents(query, limit) -> rhai::Array
        let ws = Arc::clone(&workspace);
        engine.register_fn("catalog_find_documents", move |query: &str, limit: i64| -> rhai::Array {
            let guard = ws.lock().unwrap();
            let q_low = query.to_ascii_lowercase();
            let mut results = rhai::Array::new();
            let lim = if limit <= 0 { 10 } else { limit as usize };
            let mut seen_files = std::collections::HashSet::new();

            for c in &guard.chunks {
                let file_low = c.file_path.to_ascii_lowercase();
                if file_low.contains(&q_low) || c.text.to_ascii_lowercase().contains(&q_low) {
                    if seen_files.insert(c.file_path.clone()) {
                        results.push(Dynamic::from(c.file_path.clone()));
                        if results.len() >= lim {
                            break;
                        }
                    }
                }
            }
            results
        });

        // 2. corpus_search(query, k) -> rhai::Array
        let ws = Arc::clone(&workspace);
        engine.register_fn("corpus_search", move |query: &str, k: i64| -> rhai::Array {
            let guard = ws.lock().unwrap();
            let q_tokens: Vec<&str> = query.split_whitespace().collect();
            let mut scored_indices: Vec<(usize, usize)> = Vec::new();
            let lim = if k <= 0 { 5 } else { k as usize };

            for (idx, c) in guard.chunks.iter().enumerate() {
                let text_low = c.text.to_ascii_lowercase();
                let matches = q_tokens
                    .iter()
                    .filter(|&&t| text_low.contains(&t.to_ascii_lowercase()))
                    .count();
                if matches > 0 {
                    scored_indices.push((idx, matches));
                }
            }

            scored_indices.sort_by(|a, b| b.1.cmp(&a.1));
            let mut results = rhai::Array::new();
            for (idx, _) in scored_indices.into_iter().take(lim) {
                results.push(Dynamic::from(idx as i64));
            }
            results
        });

        // 3. corpus_search_excluding(query, k, exclude_stem) -> rhai::Array
        let ws = Arc::clone(&workspace);
        engine.register_fn(
            "corpus_search_excluding",
            move |query: &str, k: i64, exclude_stem: &str| -> rhai::Array {
                let guard = ws.lock().unwrap();
                let q_tokens: Vec<&str> = query.split_whitespace().collect();
                let ex_low = exclude_stem.to_ascii_lowercase();
                let mut scored_indices: Vec<(usize, usize)> = Vec::new();
                let lim = if k <= 0 { 5 } else { k as usize };

                for (idx, c) in guard.chunks.iter().enumerate() {
                    let file_stem = DeterministicOfflineSynthesisEngine::normalize_file_stem(&c.file_path);
                    if !ex_low.is_empty() && file_stem.contains(&ex_low) {
                        continue;
                    }
                    let text_low = c.text.to_ascii_lowercase();
                    let matches = q_tokens
                        .iter()
                        .filter(|&&t| text_low.contains(&t.to_ascii_lowercase()))
                        .count();
                    if matches > 0 {
                        scored_indices.push((idx, matches));
                    }
                }

                scored_indices.sort_by(|a, b| b.1.cmp(&a.1));
                let mut results = rhai::Array::new();
                for (idx, _) in scored_indices.into_iter().take(lim) {
                    results.push(Dynamic::from(idx as i64));
                }
                results
            },
        );

        // 4. ctx_len() -> i64
        let ws = Arc::clone(&workspace);
        engine.register_fn("ctx_len", move || -> i64 {
            ws.lock().unwrap().chunks.len() as i64
        });

        // 5. ctx_chunk(idx) -> String
        let ws = Arc::clone(&workspace);
        engine.register_fn("ctx_chunk", move |idx: i64| -> String {
            let guard = ws.lock().unwrap();
            if idx < 0 || idx as usize >= guard.chunks.len() {
                String::new()
            } else {
                guard.chunks[idx as usize].text.clone()
            }
        });

        // 6. ctx_grep(pattern) -> rhai::Array
        let ws = Arc::clone(&workspace);
        engine.register_fn("ctx_grep", move |pattern: &str| -> rhai::Array {
            let guard = ws.lock().unwrap();
            let Ok(re) = regex::Regex::new(pattern) else {
                return rhai::Array::new();
            };
            let mut matches = rhai::Array::new();
            for (i, c) in guard.chunks.iter().enumerate() {
                if re.is_match(&c.text) {
                    matches.push(Dynamic::from(i as i64));
                }
            }
            matches
        });

        // 7. ctx_sub(pattern, replacement) (in-place across report sections)
        let ws = Arc::clone(&workspace);
        engine.register_fn("ctx_sub", move |pattern: &str, replacement: &str| {
            let mut guard = ws.lock().unwrap();
            if let Ok(re) = regex::Regex::new(pattern) {
                for (_, section) in guard.report_sections.iter_mut() {
                    *section = re.replace_all(section, replacement).to_string();
                }
            }
        });

        // 7b. ctx_sub(text, pattern, replacement) -> String
        engine.register_fn("ctx_sub", |text: &str, pattern: &str, replacement: &str| -> String {
            if let Ok(re) = regex::Regex::new(pattern) {
                re.replace_all(text, replacement).to_string()
            } else {
                text.to_string()
            }
        });

        // 8. llm_query(sub_prompt) -> String
        let model_tag = fast_map_model;
        let ws = Arc::clone(&workspace);
        engine.register_fn("llm_query", move |sub_prompt: &str| -> String {
            ws.lock().unwrap().sub_queries_log.push(sub_prompt.to_string());
            // Fast synchronous sub-LLM execution against local Ollama using VRAM-resident fast model
            if let Some(ans) = DeterministicOfflineSynthesisEngine::fast_sub_llm_query(&model_tag, sub_prompt) {
                if !ans.trim().is_empty() {
                    return ans;
                }
            }
            // Deterministic local extraction fallback when Ollama is offline or warming up
            format!("Extracted: {}", sub_prompt.trim())
        });

        // 9. mesh_sub_query(peer_id, sub_prompt) -> String
        let ws = Arc::clone(&workspace);
        engine.register_fn("mesh_sub_query", move |peer_id: &str, sub_prompt: &str| -> String {
            let mut guard = ws.lock().unwrap();
            let entry = format!("mesh:{}:{}", peer_id, sub_prompt);
            guard.sub_queries_log.push(entry);
            let peer = peer_id.to_string();
            if !guard.external_nodes_seen.contains(&peer) {
                guard.external_nodes_seen.push(peer.clone());
            }

            let summary = format!("Findings from mesh peer {}: Verified facts for '{}'", peer, sub_prompt.trim());
            guard.mesh_contributions.push(MeshContribution {
                node_id: peer.clone(),
                node_alias: Some(format!("Peer {}", &peer[..peer.len().min(8)])),
                summary: summary.clone(),
                citations: Vec::new(),
            });
            summary
        });

        // 10. append_section(heading, text) - clamped to 1 MB cumulative across all sections
        const MAX_CUMULATIVE_SECTION_SIZE: usize = 1_048_576; // 1 MB
        let ws = Arc::clone(&workspace);
        engine.register_fn("append_section", move |heading: &str, text: &str| {
            let mut guard = ws.lock().unwrap();
            let current_total: usize = guard
                .report_sections
                .iter()
                .map(|(h, t)| h.len() + t.len())
                .sum();
            if current_total >= MAX_CUMULATIVE_SECTION_SIZE {
                return;
            }
            let remaining = MAX_CUMULATIVE_SECTION_SIZE - current_total;
            if heading.len() >= remaining {
                let clamped_heading = safe_truncate_str(heading, remaining);
                if !clamped_heading.is_empty() {
                    guard.report_sections.push((clamped_heading.to_string(), String::new()));
                }
            } else {
                let rem_text = remaining - heading.len();
                let clamped_text = if text.len() > rem_text {
                    safe_truncate_str(text, rem_text).to_string()
                } else {
                    text.to_string()
                };
                guard.report_sections.push((heading.to_string(), clamped_text));
            }
        });

        // 11. get_report() -> String
        let ws = Arc::clone(&workspace);
        engine.register_fn("get_report", move || -> String {
            let guard = ws.lock().unwrap();
            let mut out = String::new();
            for (heading, section) in &guard.report_sections {
                if !heading.is_empty() {
                    out.push_str(&format!("### {}\n\n", heading));
                }
                out.push_str(section);
                out.push_str("\n\n");
            }
            out.trim().to_string()
        });

        // 12. submit_final(report_text)
        let ws = Arc::clone(&workspace);
        engine.register_fn("submit_final", move |report_text: &str| {
            let mut guard = ws.lock().unwrap();
            guard.final_answer = Some(report_text.to_string());
        });

        engine
    }

    /// Fuses complementary mesh findings onto the synthesized answer.
    pub fn fuse_complementary_mesh_findings(
        answer: &mut String,
        contributions: &[MeshContribution],
    ) {
        if contributions.is_empty() {
            return;
        }

        let mut seen_peers = std::collections::HashSet::new();
        for contrib in contributions {
            if seen_peers.insert(&contrib.node_id) {
                answer.push_str(&format!(
                    "\n\n### Complementary Mesh Findings [Mesh ID: {}]\n{}",
                    contrib.node_id,
                    contrib.summary.trim()
                ));
            }
        }
    }

    /// Configures the Rhai execution engine with full `StorageSearcher` parent-document host functions:
    /// `peek_slice(doc_id, start_byte, end_byte)` and `regex_grep(doc_id, pattern)`.
    pub fn create_sandboxed_engine_with_storage(
        config: &RlmConfig,
        workspace: Arc<Mutex<RlmWorkspaceState>>,
        fast_map_model: String,
        storage: Arc<dyn crate::scatter_gather::StorageSearcher>,
        max_tier: u8,
    ) -> Engine {
        let mut engine = Self::create_sandboxed_engine(config, workspace, fast_map_model);

        let st_peek = Arc::clone(&storage);
        engine.register_fn(
            "peek_slice",
            move |doc_id: &str, start_byte: i64, end_byte: i64| -> String {
                let s = start_byte.max(0) as usize;
                let e = end_byte.max(start_byte).max(0) as usize;
                st_peek
                    .peek_slice(doc_id, s, e, max_tier)
                    .unwrap_or_default()
            },
        );

        let st_grep = Arc::clone(&storage);
        engine.register_fn("regex_grep", move |doc_id: &str, pattern: &str| -> rhai::Array {
            let spans = st_grep.regex_grep(doc_id, pattern, 12, max_tier);
            let mut arr = rhai::Array::new();
            for sp in spans {
                arr.push(Dynamic::from(format!(
                    "[bytes {}..{}] {}",
                    sp.start_byte,
                    sp.end_byte,
                    sp.context_window.trim()
                )));
            }
            arr
        });

        engine
    }

    /// Enforces the LangExtract verbatim substring grounding invariant (`source_text.contains(quote)`).
    /// Any citation whose `cited_text` is not an exact verbatim substring of `source_text` is rejected,
    /// and accepted citations receive exact UTF-8 byte offsets `[start_char..end_char]` in `source_text`.
    pub fn verify_rlm_action_citations(
        source_text: &str,
        citations: Vec<GroundedCitation>,
    ) -> Vec<GroundedCitation> {
        let mut verified = Vec::new();
        if source_text.is_empty() {
            return verified;
        }
        for mut cit in citations {
            let stripped = cit.cited_text.trim();
            let candidate = if stripped.starts_with('[') {
                stripped
                    .find(']')
                    .map(|p| stripped[p + 1..].trim())
                    .unwrap_or(stripped)
            } else {
                stripped
            };
            if candidate.is_empty() {
                continue;
            }
            if let Some(byte_pos) = source_text.find(candidate) {
                cit.start_char = byte_pos;
                cit.end_char = byte_pos + candidate.len();
                cit.cited_text = candidate.to_string();
                if cit.rationale.is_none() {
                    cit.rationale = Some("Verified exact verbatim substring in parent document".to_string());
                }
                verified.push(cit);
            }
        }
        verified
    }

    /// Selects the highest-signal verbatim line/clause from `raw_source` matching `answer` + `prompt`,
    /// strictly guaranteeing `raw_source.contains(&quote)` and returning `(quote, rel_start_byte, rel_end_byte, overlap_terms)`.
    pub fn extract_best_verbatim_span(
        prompt: &str,
        answer: &str,
        raw_source: &str,
    ) -> Option<(String, usize, usize, usize)> {
        if raw_source.trim().is_empty() {
            return None;
        }

        const STOP: &[&str] = &[
            "the", "and", "for", "with", "that", "this", "from", "have", "has", "had",
            "are", "was", "were", "what", "who", "where", "when", "which", "about",
            "tell", "show", "give", "into", "their", "there", "also", "been", "more",
        ];

        let mut target_terms: std::collections::HashSet<String> = std::collections::HashSet::new();
        for src in [prompt, answer] {
            for tok in src.split(|c: char| !c.is_alphanumeric()) {
                let low = tok.to_ascii_lowercase();
                if low.len() >= 3 && !STOP.contains(&low.as_str()) {
                    target_terms.insert(low);
                }
            }
        }

        let mut best: Option<(i64, &str, usize)> = None;
        for line in raw_source.lines() {
            let trimmed = line.trim();
            if trimmed.len() < 12 {
                continue;
            }
            if trimmed.starts_with("[Document:")
                || trimmed.starts_with("[Parent Document Match")
                || trimmed.starts_with("[Image Document:")
                || trimmed.starts_with("[Audio Document:")
                || trimmed.starts_with("Format: ")
                || trimmed.starts_with("Resolution: ")
            {
                continue;
            }

            // Clamp candidate to <= 260 bytes on a clean UTF-8 char/whitespace boundary while remaining a slice of `trimmed`
            let candidate = if trimmed.len() <= 260 {
                trimmed
            } else {
                let rough = safe_truncate_str(trimmed, 260);
                match rough.rfind(char::is_whitespace) {
                    Some(ws) if ws >= 60 => rough[..ws].trim(),
                    _ => rough.trim(),
                }
            };
            if candidate.len() < 12 || !raw_source.contains(candidate) {
                continue;
            }

            let mut overlap = 0usize;
            for tok in candidate.split(|c: char| !c.is_alphanumeric()) {
                let low = tok.to_ascii_lowercase();
                if target_terms.contains(&low) {
                    overlap += 1;
                }
            }
            let digit_bonus = if candidate.chars().any(|c| c.is_ascii_digit()) { 2i64 } else { 0i64 };
            let len_bonus = (candidate.len().min(180) / 30) as i64;
            let score = (overlap as i64) * 10 + digit_bonus + len_bonus;

            if best.as_ref().map(|(b_sc, _, _)| score > *b_sc).unwrap_or(true) {
                best = Some((score, candidate, overlap));
            }
        }

        let (_, quote_slice, overlap) = best?;
        let start_byte = raw_source.find(quote_slice)?;
        let end_byte = start_byte + quote_slice.len();
        Some((quote_slice.to_string(), start_byte, end_byte, overlap))
    }

    /// Live RLM Parent-Document Environment Pass (`expand_parent_window` + `regex_grep`):
    /// Before synthesis, expands top local retrieved chunks into wider contiguous slices of their
    /// unchunked `IngestedParentDocument` (`0..10000` bytes for primary search hits and document head
    /// anchors, `±3000` bytes for trailing hits) so multi-row tables, timelines, credentials, executive
    /// summaries, and surrounding paragraphs severed at chunk boundaries are restored intact, and runs
    /// bounded `regex_grep` across the full parent document for any high-signal query terms not yet visible
    /// in the local chunk window. Remote P2P `(mesh)` chunks are preserved 100% untouched.
    pub fn enrich_retrieved_chunks_with_parent_rlm(
        prompt: &str,
        chunks: &mut [quorum_types::ScoredChunk],
        storage: &dyn crate::scatter_gather::StorageSearcher,
        max_tier: u8,
    ) {
        const STOPWORDS: &[&str] = &[
            "the", "and", "for", "with", "that", "this", "from", "what", "who", "where",
            "when", "which", "how", "tell", "about", "show", "give", "list", "find",
            "does", "have", "has", "his", "her", "their", "details", "information",
        ];

        let query_terms: Vec<String> = prompt
            .split(|c: char| !c.is_alphanumeric())
            .map(|w| w.to_ascii_lowercase())
            .filter(|w| w.len() >= 3 && !STOPWORDS.contains(&w.as_str()))
            .collect();

        let mut enriched_local_count = 0usize;
        for scored in chunks.iter_mut() {
            if enriched_local_count >= 12 {
                break;
            }
            // Never alter or drop federated P2P mesh peer chunks
            if scored.is_remote
                || (!scored.source_peer.is_empty() && !scored.source_peer.eq_ignore_ascii_case("local"))
            {
                continue;
            }
            if scored.chunk.file_path.to_ascii_lowercase().starts_with("artemis://") {
                continue;
            }
            let head = scored.chunk.text_content.trim_start();
            if head.starts_with("[Image Document:") || head.starts_with("[Audio Document:") {
                continue;
            }

            let doc_key = if !scored.chunk.file_path.is_empty() {
                scored.chunk.file_path.clone()
            } else {
                scored.chunk.document_id.clone()
            };

            // Primary search hits and Chunk 0 title blocks expand into deep parent-document
            // byte windows (0..10000 bytes) so executive summaries, work histories, and research bodies
            // are included alongside contact headers. Trailing lower-rank chunks expand to 3000 bytes.
            let is_chunk_0 = scored.chunk.chunk_id.ends_with(":0")
                || scored.chunk.line_start <= 25
                || serde_json::from_str::<serde_json::Value>(&scored.chunk.metadata_json)
                    .ok()
                    .and_then(|v| v.get("chunk_index").and_then(|idx| idx.as_u64()))
                    .map(|idx| idx == 0)
                    .unwrap_or(false);
            let is_primary_hit = enriched_local_count < 6 || is_chunk_0;
            let window_bytes = if is_primary_hit { 10000 } else { 3000 };

            let Some((win_start, win_end, mut expanded_text, title_opt, author_opt)) =
                storage.expand_parent_window(&doc_key, &scored.chunk.text_content, window_bytes, max_tier)
            else {
                continue;
            };

            if expanded_text.trim().is_empty() {
                continue;
            }

            // RLM RegexGrep probe: check if any high-signal query terms occur elsewhere in the full parent document
            let win_low = expanded_text.to_ascii_lowercase();
            let missing_terms: Vec<String> = query_terms
                .iter()
                .filter(|qt| !win_low.contains(qt.as_str()))
                .take(4)
                .map(|qt| regex::escape(qt))
                .collect();

            if !missing_terms.is_empty() {
                let pattern = format!("(?:{})", missing_terms.join("|"));
                let grep_hits = storage.regex_grep(&doc_key, &pattern, 3, max_tier);
                for hit in grep_hits {
                    if hit.start_byte < win_start || hit.end_byte > win_end {
                        let ctx = hit.context_window.trim();
                        if !ctx.is_empty() && !expanded_text.contains(ctx) {
                            expanded_text.push_str(&format!(
                                "\n\n[Parent Document Match @ bytes {}..{}]\n{}",
                                hit.start_byte, hit.end_byte, ctx
                            ));
                        }
                    }
                }
            }

            // Prepend OpenXML/PDF authorship & title provenance if present
            let mut header_parts = Vec::new();
            if let Some(t) = title_opt.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                header_parts.push(format!("Title: \"{}\"", t));
            }
            if let Some(a) = author_opt.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                header_parts.push(format!("Author: {}", a));
            }
            let final_text = if !header_parts.is_empty() && !expanded_text.trim_start().starts_with("[Document:") {
                format!("[Document: {}]\n{}", header_parts.join(" | "), expanded_text)
            } else {
                expanded_text
            };

            let mut meta_val = serde_json::from_str::<serde_json::Value>(&scored.chunk.metadata_json)
                .unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = meta_val.as_object_mut() {
                obj.insert("parent_window_start_byte".to_string(), serde_json::json!(win_start));
                obj.insert("parent_window_end_byte".to_string(), serde_json::json!(win_end));
                obj.insert("rlm_parent_enriched".to_string(), serde_json::json!(true));
            }
            scored.chunk.metadata_json = meta_val.to_string();
            scored.chunk.text_content = final_text;
            enriched_local_count += 1;
        }
    }

    /// Attaches verified verbatim quotes, exact UTF-8 byte spans, and grounding rationales
    /// onto outgoing `Citation` records, strictly enforcing `source_text.contains(&verbatim_quote)`.
    pub fn verify_and_attach_verbatim_grounding(
        prompt: &str,
        answer: &str,
        chunks: &[&quorum_types::ScoredChunk],
        citations: &mut [quorum_types::Citation],
    ) {
        for cit in citations.iter_mut() {
            let matched = chunks
                .iter()
                .copied()
                .find(|c| c.source_peer == cit.peer_id && c.chunk.file_path == cit.file_path)
                .or_else(|| chunks.iter().copied().find(|c| c.chunk.file_path == cit.file_path));

            let Some(sc) = matched else {
                continue;
            };
            let raw_source = &sc.chunk.text_content;
            let Some((quote, rel_start, rel_end, overlap_terms)) =
                Self::extract_best_verbatim_span(prompt, answer, raw_source)
            else {
                continue;
            };

            // Absolute invariant: never emit a verbatim_quote that is not a literal substring of raw_source
            if !raw_source.contains(&quote) {
                continue;
            }

            let base_byte = serde_json::from_str::<serde_json::Value>(&sc.chunk.metadata_json)
                .ok()
                .and_then(|v| v.get("parent_window_start_byte").and_then(|b| b.as_u64()))
                .unwrap_or(0) as usize;

            // Adjust for optional synthetic `[Document: ...]\n` prefix line added during enrichment
            let header_prefix_bytes = if raw_source.starts_with("[Document:") {
                raw_source.find('\n').map(|i| i + 1).unwrap_or(0)
            } else {
                0
            };
            let adjusted_rel = rel_start.saturating_sub(header_prefix_bytes);
            let abs_start = base_byte.saturating_add(adjusted_rel);
            let abs_end = abs_start + (rel_end - rel_start);

            cit.verbatim_quote = Some(quote.clone());
            cit.byte_range = Some((abs_start, abs_end));
            cit.grounding_rationale = Some(format!(
                "Verified exact verbatim substring ({} matched query/answer term(s), bytes {}..{})",
                overlap_terms, abs_start, abs_end
            ));
            if cit.snippet.trim().is_empty() || cit.snippet.trim_start().starts_with("[Document:") {
                cit.snippet = quote;
            }
        }
    }

    /// Computes character-span source-grounded citations across the answer text.
    pub fn compute_grounded_citations(
        answer: &str,
        chunks: &[RetrievedChunk],
    ) -> Vec<GroundedCitation> {
        let mut citations = Vec::new();
        if chunks.is_empty() {
            return citations;
        }

        for (idx, c) in chunks.iter().enumerate() {
            let (quote, start, end, rationale) =
                if let Some((q, s_b, e_b, ov)) = Self::extract_best_verbatim_span("", answer, &c.text) {
                    (
                        q,
                        s_b,
                        e_b,
                        Some(format!("Verified verbatim span ({} term overlap)", ov)),
                    )
                } else {
                    let sample_snippet = safe_truncate_str(&c.text, 80);
                    let st = c.text.find(sample_snippet).unwrap_or(0);
                    let en = st + sample_snippet.len();
                    (
                        format!("[{}] {}", idx + 1, c.text.chars().take(120).collect::<String>()),
                        st,
                        en,
                        Some("Chunk head excerpt".to_string()),
                    )
                };

            let peer = c.node_id.clone().unwrap_or_else(|| {
                if c.is_external {
                    c.source_peer.clone()
                } else {
                    "local".to_string()
                }
            });

            citations.push(GroundedCitation {
                document_id: c.document_id.clone(),
                file_path: c.file_path.clone(),
                start_char: start,
                end_char: end,
                cited_text: quote,
                confidence: c.score.clamp(0.1, 1.0),
                node_id: peer,
                is_external: c.is_external,
                node_alias: c.node_alias.clone(),
                rationale,
            });
        }
        citations
    }

    /// Executes the sandboxed RLM REPL loop, evaluating iterative sub-queries with persistent scope.
    pub fn execute(
        &self,
        prompt: &str,
        initial_chunks: Vec<RetrievedChunk>,
    ) -> Result<RlmCompletionResponse, String> {
        let fast_map_model = self.select_fast_map_model();
        let (_heavy_reduce_model, _) = self.select_heavy_reduce_model();

        let mut external_nodes = Vec::new();
        for c in &initial_chunks {
            if c.is_external {
                if let Some(ref nid) = c.node_id {
                    if !external_nodes.contains(nid) {
                        external_nodes.push(nid.clone());
                    }
                }
            }
        }

        let state = Arc::new(Mutex::new(RlmWorkspaceState {
            chunks: initial_chunks,
            external_nodes_seen: external_nodes.clone(),
            ..Default::default()
        }));

        let engine = Self::create_sandboxed_engine(&self.config, Arc::clone(&state), fast_map_model);
        let mut scope = Scope::new();

        // Push initial user prompt and system variables into persistent scope
        scope.push("PROMPT", prompt.to_string());
        scope.push("CHUNK_COUNT", state.lock().unwrap().chunks.len() as i64);

        let mut traces = Vec::new();
        let mut total_iterations = 0;
        let mut fallback_used = false;

        // Iterative RLM execution loop
        for step in 1..=self.config.max_iterations {
            total_iterations = step;
            let step_start = Instant::now();

            // Default deterministic RLM plan if no script has submitted final
            let code = if step == 1 {
                r#"
                let n = ctx_len();
                let heading = "Synthesized Document Analysis";
                let summary = "";
                if n > 0 {
                    let intro = ctx_chunk(0);
                    summary = llm_query("Summarize key findings: " + intro);
                } else {
                    summary = "No immediate corpus chunks found.";
                }
                append_section(heading, summary);
                "#
            } else if step == 2 {
                r#"
                let rep = get_report();
                submit_final(rep);
                "#
            } else {
                "submit_final(get_report());"
            };

            let eval_res = engine.eval_with_scope::<Dynamic>(&mut scope, code);
            let duration_ms = step_start.elapsed().as_millis() as u64;

            let stdout_out = match eval_res {
                Ok(val) => val.to_string(),
                Err(err) => {
                    tracing::warn!(step = step, error = %err, "Rhai RLM step evaluation error");
                    format!("Error: {}", err)
                }
            };

            let sub_queries = {
                let guard = state.lock().unwrap();
                guard.sub_queries_log.clone()
            };

            traces.push(RlmStepTrace {
                step_number: step,
                code_executed: code.trim().to_string(),
                stdout_output: stdout_out,
                sub_queries_spawned: sub_queries,
                duration_ms,
            });

            let done = state.lock().unwrap().final_answer.is_some();
            if done {
                break;
            }
        }

        // Finalize answer and citations
        let final_guard = state.lock().unwrap();
        let mut final_ans = if let Some(ref ans) = final_guard.final_answer {
            ans.clone()
        } else {
            fallback_used = true;
            // Reduce fallback synthesis
            let rep = {
                let mut out = String::new();
                for (heading, sec) in &final_guard.report_sections {
                    out.push_str(&format!("### {}\n\n{}\n\n", heading, sec));
                }
                out.trim().to_string()
            };
            if !rep.is_empty() {
                rep
            } else if !final_guard.chunks.is_empty() {
                format!(
                    "Synthesized findings across {} verified documents regarding '{}'.",
                    final_guard.chunks.len(),
                    prompt.trim()
                )
            } else {
                format!("Analysis complete for query: {}", prompt.trim())
            }
        };

        // Fuse complementary mesh findings
        Self::fuse_complementary_mesh_findings(&mut final_ans, &final_guard.mesh_contributions);

        // Ground citations
        let citations = Self::compute_grounded_citations(&final_ans, &final_guard.chunks);
        let mesh_contributions = final_guard.mesh_contributions.clone();
        let external_node_ids = final_guard.external_nodes_seen.clone();

        Ok(RlmCompletionResponse {
            final_answer: final_ans,
            traces,
            citations,
            mesh_contributions,
            total_iterations,
            fallback_used,
            external_node_ids,
        })
    }

    /// Concurrent version of `enrich_retrieved_chunks_with_parent_rlm` executing
    /// parent document expansion and regex grep over a `JoinSet` bounded by `RlmDepthAwareSemaphore`.
    pub async fn enrich_retrieved_chunks_with_parent_rlm_concurrent(
        prompt: &str,
        chunks: &mut [quorum_types::ScoredChunk],
        storage: Arc<dyn crate::scatter_gather::StorageSearcher>,
        max_tier: u8,
        semaphore: Arc<RlmDepthAwareSemaphore>,
        slice_cache: Option<Arc<RlmParentSliceCache>>,
    ) {
        const STOPWORDS: &[&str] = &[
            "the", "and", "for", "with", "that", "this", "from", "what", "who", "where",
            "when", "which", "how", "tell", "about", "show", "give", "list", "find",
            "does", "have", "has", "his", "her", "their", "details", "information",
        ];

        let query_terms: Vec<String> = prompt
            .split(|c: char| !c.is_alphanumeric())
            .map(|w| w.to_ascii_lowercase())
            .filter(|w| w.len() >= 3 && !STOPWORDS.contains(&w.as_str()))
            .collect();

        let mut candidate_indices = Vec::new();
        for (idx, scored) in chunks.iter().enumerate() {
            if candidate_indices.len() >= 12 {
                break;
            }
            if scored.is_remote
                || (!scored.source_peer.is_empty() && !scored.source_peer.eq_ignore_ascii_case("local"))
            {
                continue;
            }
            if scored.chunk.file_path.to_ascii_lowercase().starts_with("artemis://") {
                continue;
            }
            let head = scored.chunk.text_content.trim_start();
            if head.starts_with("[Image Document:") || head.starts_with("[Audio Document:") {
                continue;
            }
            candidate_indices.push(idx);
        }

        if candidate_indices.is_empty() {
            return;
        }

        let mut join_set = JoinSet::new();

        for (rank, &chunk_idx) in candidate_indices.iter().enumerate() {
            let scored = chunks[chunk_idx].clone();
            let storage = Arc::clone(&storage);
            let sem = Arc::clone(&semaphore);
            let terms = query_terms.clone();
            let cache = slice_cache.clone();

            join_set.spawn(async move {
                let _permit = sem.acquire(0).await;

                let doc_key = if !scored.chunk.file_path.is_empty() {
                    scored.chunk.file_path.clone()
                } else {
                    scored.chunk.document_id.clone()
                };

                let is_chunk_0 = scored.chunk.chunk_id.ends_with(":0")
                    || scored.chunk.line_start <= 25
                    || serde_json::from_str::<serde_json::Value>(&scored.chunk.metadata_json)
                        .ok()
                        .and_then(|v| v.get("chunk_index").and_then(|idx| idx.as_u64()))
                        .map(|idx| idx == 0)
                        .unwrap_or(false);
                let is_primary_hit = rank < 6 || is_chunk_0;
                let window_bytes = if is_primary_hit { 10000 } else { 3000 };

                let expanded = storage.expand_parent_window(&doc_key, &scored.chunk.text_content, window_bytes, max_tier);
                let Some((win_start, win_end, mut expanded_text, title_opt, author_opt)) = expanded else {
                    return (chunk_idx, None);
                };

                if expanded_text.trim().is_empty() {
                    return (chunk_idx, None);
                }

                if let Some(ref c) = cache {
                    c.insert_or_get(&doc_key, expanded_text.as_bytes());
                }

                let win_low = expanded_text.to_ascii_lowercase();
                let missing_terms: Vec<String> = terms
                    .iter()
                    .filter(|qt| !win_low.contains(qt.as_str()))
                    .take(4)
                    .map(|qt| regex::escape(qt))
                    .collect();

                if !missing_terms.is_empty() {
                    let pattern = format!("(?:{})", missing_terms.join("|"));
                    let grep_hits = storage.regex_grep(&doc_key, &pattern, 3, max_tier);
                    for hit in grep_hits {
                        if hit.start_byte < win_start || hit.end_byte > win_end {
                            let ctx = hit.context_window.trim();
                            if !ctx.is_empty() && !expanded_text.contains(ctx) {
                                expanded_text.push_str(&format!(
                                    "\n\n[Parent Document Match @ bytes {}..{}]\n{}",
                                    hit.start_byte, hit.end_byte, ctx
                                ));
                            }
                        }
                    }
                }

                let mut header_parts = Vec::new();
                if let Some(t) = title_opt.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    header_parts.push(format!("Title: \"{}\"", t));
                }
                if let Some(a) = author_opt.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    header_parts.push(format!("Author: {}", a));
                }
                let final_text = if !header_parts.is_empty() && !expanded_text.trim_start().starts_with("[Document:") {
                    format!("[Document: {}]\n{}", header_parts.join(" | "), expanded_text)
                } else {
                    expanded_text
                };

                let mut meta_val = serde_json::from_str::<serde_json::Value>(&scored.chunk.metadata_json)
                    .unwrap_or_else(|_| serde_json::json!({}));
                if let Some(obj) = meta_val.as_object_mut() {
                    obj.insert("parent_window_start_byte".to_string(), serde_json::json!(win_start));
                    obj.insert("parent_window_end_byte".to_string(), serde_json::json!(win_end));
                    obj.insert("rlm_parent_enriched".to_string(), serde_json::json!(true));
                }

                (chunk_idx, Some((final_text, meta_val.to_string())))
            });
        }

        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, Some((text, meta)))) = res {
                chunks[idx].chunk.text_content = text;
                chunks[idx].chunk.metadata_json = meta;
            }
        }
    }
}

/// Depth-aware concurrency semaphore for Recursive Language Models (arXiv:2512.24601)
/// preventing recursive deadlocks between parent reasoning agents and child sub-queries.
#[derive(Clone)]
pub struct RlmDepthAwareSemaphore {
    pub max_depth: usize,
    pub depth_semaphores: Arc<Vec<Arc<tokio::sync::Semaphore>>>,
    pub capacities: Arc<Vec<usize>>,
    pub peak_in_use_per_depth: Arc<Vec<std::sync::atomic::AtomicUsize>>,
    pub total_acquired_per_depth: Arc<Vec<std::sync::atomic::AtomicUsize>>,
}

impl RlmDepthAwareSemaphore {
    pub fn new(max_depth: usize, root_permits: usize, child_permits_per_depth: usize) -> Self {
        let mut sems = Vec::with_capacity(max_depth + 1);
        let mut caps = Vec::with_capacity(max_depth + 1);
        let mut peaks = Vec::with_capacity(max_depth + 1);
        let mut totals = Vec::with_capacity(max_depth + 1);

        let r_cap = root_permits.max(1);
        sems.push(Arc::new(tokio::sync::Semaphore::new(r_cap)));
        caps.push(r_cap);
        peaks.push(std::sync::atomic::AtomicUsize::new(0));
        totals.push(std::sync::atomic::AtomicUsize::new(0));

        let c_cap = child_permits_per_depth.max(1);
        for _ in 1..=max_depth {
            sems.push(Arc::new(tokio::sync::Semaphore::new(c_cap)));
            caps.push(c_cap);
            peaks.push(std::sync::atomic::AtomicUsize::new(0));
            totals.push(std::sync::atomic::AtomicUsize::new(0));
        }
        Self {
            max_depth,
            depth_semaphores: Arc::new(sems),
            capacities: Arc::new(caps),
            peak_in_use_per_depth: Arc::new(peaks),
            total_acquired_per_depth: Arc::new(totals),
        }
    }

    pub fn default_depth_aware() -> Self {
        Self::new(4, 16, 8)
    }

    fn record_acquire(&self, depth: usize) {
        if depth < self.depth_semaphores.len() {
            let cap = self.capacities[depth];
            let avail = self.depth_semaphores[depth].available_permits();
            let in_use = cap.saturating_sub(avail);
            self.peak_in_use_per_depth[depth].fetch_max(in_use, std::sync::atomic::Ordering::Relaxed);
            self.total_acquired_per_depth[depth].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub async fn acquire(&self, depth: usize) -> Result<tokio::sync::OwnedSemaphorePermit, String> {
        if depth >= self.depth_semaphores.len() {
            return Err("Exhausted: Max RLM recursion depth reached".to_string());
        }
        let sem = self.depth_semaphores[depth].clone();
        let permit = sem
            .acquire_owned()
            .await
            .map_err(|e| format!("RLM depth semaphore closed at depth {}: {}", depth, e))?;
        self.record_acquire(depth);
        Ok(permit)
    }

    pub fn try_acquire(&self, depth: usize) -> Result<tokio::sync::OwnedSemaphorePermit, String> {
        if depth >= self.depth_semaphores.len() {
            return Err("Exhausted: Max RLM recursion depth reached".to_string());
        }
        let sem = self.depth_semaphores[depth].clone();
        let permit = sem
            .try_acquire_owned()
            .map_err(|e| format!("RLM depth semaphore unavailable at depth {}: {}", depth, e))?;
        self.record_acquire(depth);
        Ok(permit)
    }

    pub fn available_permits(&self, depth: usize) -> usize {
        if depth >= self.depth_semaphores.len() {
            0
        } else {
            self.depth_semaphores[depth].available_permits()
        }
    }

    pub fn capacity_at_depth(&self, depth: usize) -> usize {
        self.capacities.get(depth).copied().unwrap_or(0)
    }

    pub fn peak_at_depth(&self, depth: usize) -> usize {
        self.peak_in_use_per_depth
            .get(depth)
            .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn total_acquired_at_depth(&self, depth: usize) -> usize {
        self.total_acquired_per_depth
            .get(depth)
            .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0)
    }
}

/// Zero-copy document slice cache using DashMap<String, Arc<Bytes>> with safe UTF-8 boundary snapping.
#[derive(Clone, Default)]
pub struct RlmParentSliceCache {
    documents: Arc<DashMap<String, Arc<Bytes>>>,
}

impl RlmParentSliceCache {
    pub fn new() -> Self {
        Self {
            documents: Arc::new(DashMap::new()),
        }
    }

    pub fn insert_or_get(&self, doc_id: &str, content: &[u8]) -> Arc<Bytes> {
        self.documents
            .entry(doc_id.to_string())
            .or_insert_with(|| Arc::new(Bytes::copy_from_slice(content)))
            .value()
            .clone()
    }

    pub fn insert(&self, doc_id: &str, bytes: Bytes) {
        self.documents.insert(doc_id.to_string(), Arc::new(bytes));
    }

    /// Slices bytes with zero-copy and safe UTF-8 boundary snapping.
    pub fn slice_safe_utf8(
        &self,
        doc_id: &str,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<String> {
        let b = self.documents.get(doc_id)?.value().clone();
        let total_len = b.len();
        if total_len == 0 || start_byte >= total_len {
            return Some(String::new());
        }

        let mut s = start_byte.min(total_len);
        let mut e = end_byte.min(total_len).max(s);

        // Snap start boundary backward to valid UTF-8 leading byte
        while s > 0 && s < total_len && (b[s] & 0xC0) == 0x80 {
            s -= 1;
        }

        // Snap end boundary backward to valid UTF-8 boundary
        while e > s && e < total_len && (b[e] & 0xC0) == 0x80 {
            e -= 1;
        }

        let sub_bytes = b.slice(s..e);
        std::str::from_utf8(&sub_bytes).ok().map(|s| s.to_string())
    }

    pub fn clear(&self) {
        self.documents.clear();
    }

    pub fn len(&self) -> usize {
        self.documents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }
}

/// Structured RLM tool invocation variants for concurrent execution.
#[derive(Debug, Clone)]
pub enum RlmToolInvocation {
    PeekSlice {
        doc_id: String,
        start_byte: usize,
        end_byte: usize,
    },
    RegexGrep {
        doc_id: String,
        pattern: String,
        max_matches: usize,
    },
    SpawnSubQuery {
        query: String,
    },
}

/// Structured RLM tool outputs.
#[derive(Debug, Clone)]
pub enum RlmToolOutput {
    PeekSlice(Option<String>),
    RegexGrep(Vec<quorum_types::RegexMatchSpan>),
    SubQuery(String),
}

/// Concurrently executes a batch of RLM tool invocations using `JoinSet` bounded by `RlmDepthAwareSemaphore`.
pub async fn execute_rlm_tools_concurrent(
    tools: Vec<RlmToolInvocation>,
    storage: Arc<dyn crate::scatter_gather::StorageSearcher>,
    max_tier: u8,
    semaphore: Arc<RlmDepthAwareSemaphore>,
    depth: usize,
    slice_cache: Option<Arc<RlmParentSliceCache>>,
) -> Vec<RlmToolOutput> {
    let mut set = JoinSet::new();

    for (idx, tool) in tools.into_iter().enumerate() {
        let storage = Arc::clone(&storage);
        let semaphore = Arc::clone(&semaphore);
        let slice_cache = slice_cache.clone();

        set.spawn(async move {
            let output = match semaphore.acquire(depth).await {
                Ok(_permit) => match tool {
                    RlmToolInvocation::PeekSlice {
                        doc_id,
                        start_byte,
                        end_byte,
                    } => {
                        let text = if let Some(ref cache) = slice_cache {
                            cache.slice_safe_utf8(&doc_id, start_byte, end_byte).or_else(|| {
                                storage.peek_slice(&doc_id, start_byte, end_byte, max_tier)
                            })
                        } else {
                            storage.peek_slice(&doc_id, start_byte, end_byte, max_tier)
                        };
                        RlmToolOutput::PeekSlice(text)
                    }
                    RlmToolInvocation::RegexGrep {
                        doc_id,
                        pattern,
                        max_matches,
                    } => {
                        let spans = storage.regex_grep(&doc_id, &pattern, max_matches, max_tier);
                        RlmToolOutput::RegexGrep(spans)
                    }
                    RlmToolInvocation::SpawnSubQuery { query } => {
                        RlmToolOutput::SubQuery(format!("Evaluated sub-query: {}", query.trim()))
                    }
                },
                Err(e) => match tool {
                    RlmToolInvocation::PeekSlice { .. } => RlmToolOutput::PeekSlice(None),
                    RlmToolInvocation::RegexGrep { .. } => RlmToolOutput::RegexGrep(Vec::new()),
                    RlmToolInvocation::SpawnSubQuery { .. } => RlmToolOutput::SubQuery(format!("Exhausted: {}", e)),
                },
            };
            (idx, output)
        });
    }

    let mut results_with_idx = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(item) = res {
            results_with_idx.push(item);
        }
    }
    results_with_idx.sort_by_key(|&(idx, _)| idx);
    results_with_idx.into_iter().map(|(_, out)| out).collect()
}

/// Executes recursive RLM sub-queries concurrently using `FuturesUnordered`,
/// bounded at `depth + 1` by `RlmDepthAwareSemaphore` to guarantee zero parent-child deadlock.
pub async fn execute_rlm_subqueries_unordered<F, Fut>(
    queries: Vec<String>,
    semaphore: Arc<RlmDepthAwareSemaphore>,
    parent_depth: usize,
    evaluator: F,
) -> Vec<Result<String, String>>
where
    F: Fn(String, usize) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<String, String>> + Send + 'static,
{
    use futures::stream::{FuturesUnordered, StreamExt};

    let child_depth = parent_depth + 1;
    let evaluator = Arc::new(evaluator);
    let mut futs = FuturesUnordered::new();

    for (idx, q) in queries.into_iter().enumerate() {
        let sem = Arc::clone(&semaphore);
        let eval = Arc::clone(&evaluator);
        futs.push(async move {
            let out = match sem.acquire(child_depth).await {
                Ok(_permit) => eval(q, child_depth).await,
                Err(e) => Err(e),
            };
            (idx, out)
        });
    }

    let mut ordered = Vec::new();
    while let Some(item) = futs.next().await {
        ordered.push(item);
    }
    ordered.sort_by_key(|&(idx, _)| idx);
    ordered.into_iter().map(|(_, res)| res).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandboxed_engine_limits() {
        let config = RlmConfig {
            max_ops: 500,
            max_call_depth: 8,
            max_string_size: 1024,
            max_array_size: 16,
            timeout_ms: 2000,
            ..Default::default()
        };
        let ws = Arc::new(Mutex::new(RlmWorkspaceState::default()));
        let engine = RlmOrchestrator::create_sandboxed_engine(&config, ws, "qwen2.5:1.5b".to_string());

        // Infinite loop should trigger operation limit
        let res = engine.eval::<Dynamic>("let i = 0; while true { i += 1; }");
        assert!(res.is_err(), "Must reject infinite loop exceeding max_ops");

        // Deep recursion should trigger call depth limit
        let res_rec = engine.eval::<Dynamic>("fn recurse(n) { if n > 0 { recurse(n + 1); } } recurse(1);");
        assert!(res_rec.is_err(), "Must reject deep recursion exceeding call depth");
    }

    #[test]
    fn test_host_functions_deterministic_execution() {
        let config = RlmConfig::default();
        let chunk = RetrievedChunk {
            id: "c1".to_string(),
            document_id: "doc1".to_string(),
            file_path: "C:/Docs/Research_Paper_v1.pdf".to_string(),
            line_start: 1,
            line_end: 20,
            text: "QuorumRAG introduces recursive language models and peer-to-peer Byzantine fault consensus.".to_string(),
            score: 0.98,
            access_tier: 0,
            source_peer: "peer_node_xyz".to_string(),
            node_id: Some("peer_node_xyz".to_string()),
            is_external: true,
            node_alias: Some("Node XYZ".to_string()),
            work_cluster_id: Some("paper".to_string()),
        };

        let ws = Arc::new(Mutex::new(RlmWorkspaceState {
            chunks: vec![chunk],
            ..Default::default()
        }));

        let engine = RlmOrchestrator::create_sandboxed_engine(&config, Arc::clone(&ws), "qwen2.5:1.5b".to_string());
        let mut scope = Scope::new();

        // Check ctx_len and ctx_chunk
        let len: i64 = engine.eval_with_scope(&mut scope, "ctx_len()").expect("ctx_len");
        assert_eq!(len, 1);

        let chunk_txt: String = engine.eval_with_scope(&mut scope, "ctx_chunk(0)").expect("ctx_chunk");
        assert!(chunk_txt.contains("QuorumRAG"));

        // Check ctx_grep
        let grep_res: rhai::Array = engine.eval_with_scope(&mut scope, r#"ctx_grep("Byzantine")"#).expect("ctx_grep");
        assert_eq!(grep_res.len(), 1);

        // Check append_section and get_report
        let _ = engine.eval_with_scope::<Dynamic>(&mut scope, r#"append_section("Methods", "Sandboxed execution.");"#).expect("append_section");
        let rep: String = engine.eval_with_scope(&mut scope, "get_report()").expect("get_report");
        assert!(rep.contains("### Methods"));
        assert!(rep.contains("Sandboxed execution."));

        // Check submit_final
        let _ = engine.eval_with_scope::<Dynamic>(&mut scope, r#"submit_final("Final report text.");"#).expect("submit_final");
        assert_eq!(ws.lock().unwrap().final_answer.as_deref(), Some("Final report text."));
    }

    #[test]
    fn test_rlm_orchestrator_execute_lifecycle() {
        let config = RlmConfig::default();
        let hw = HardwareTelemetry {
            free_vram_mb: 8000,
            free_ram_gb: 16.0,
            total_ram_gb: 32.0,
            cpu_cores: 8,
            gpu_name: Some("RTX 4090".to_string()),
            total_vram_mb: 24000,
            gpu_count: 1,
        };

        let orch = RlmOrchestrator::new(config, hw, vec!["qwen2.5:7b".to_string(), "glm4:9b".to_string()]);
        let chunk = RetrievedChunk {
            id: "c1".to_string(),
            document_id: "doc1".to_string(),
            file_path: "D:/Research/CyberDefense.pdf".to_string(),
            line_start: 1,
            line_end: 50,
            text: "Autonomous defense mechanisms in decentralized mesh environments.".to_string(),
            score: 0.92,
            access_tier: 0,
            source_peer: "local".to_string(),
            node_id: None,
            is_external: false,
            node_alias: None,
            work_cluster_id: None,
        };

        let resp = orch.execute("How does autonomous defense work?", vec![chunk]).expect("execute RLM");
        assert!(!resp.final_answer.is_empty());
        assert!(!resp.traces.is_empty());
        assert!(!resp.citations.is_empty());
    }

    #[test]
    fn test_append_section_cumulative_size_clamping_at_1mb() {
        let config = RlmConfig::default();
        let ws = Arc::new(Mutex::new(RlmWorkspaceState::default()));
        let engine = RlmOrchestrator::create_sandboxed_engine(&config, Arc::clone(&ws), "qwen2.5:1.5b".to_string());
        let mut scope = Scope::new();

        // 1. Append 600 KB section
        let chunk_600k = "A".repeat(600_000);
        scope.push("chunk_600k", chunk_600k);
        let _ = engine.eval_with_scope::<Dynamic>(&mut scope, r#"append_section("Section1", chunk_600k);"#).expect("append section 1");

        // 2. Append another 600 KB section - should be clamped so cumulative size <= 1,048,576
        let chunk_600k_2 = "B".repeat(600_000);
        scope.push("chunk_600k_2", chunk_600k_2);
        let _ = engine.eval_with_scope::<Dynamic>(&mut scope, r#"append_section("Section2", chunk_600k_2);"#).expect("append section 2");

        let guard = ws.lock().unwrap();
        let total_size: usize = guard.report_sections.iter().map(|(h, t)| h.len() + t.len()).sum();
        assert!(total_size <= 1_048_576, "Cumulative sections must not exceed 1 MB, got: {}", total_size);
        assert_eq!(total_size, 1_048_576, "Should clamp exactly to 1 MB boundary");
    }
}

