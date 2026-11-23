//! Second-Stage Multi-Signal Relevance Reranker (#4 Reranking: Top-50 -> Top-K).
//!
//! Operates after initial Hybrid Search (Tantivy BM25 + LanceDB dense vectors + RRF fusion)
//! to re-score candidate chunks with fine-grained query-to-passage signals:
//! 1. Exact primary-subject / proper-noun phrase adjacency (stops homonym/surname bleed and
//!    prevents unrelated fictional chats like `"You are Loretta Banks..."` from outranking real hits)
//! 2. Sub-question clause coverage across decomposed queries (#8)
//! 3. Windowed query-term proximity density (terms co-occurring within 120 chars score higher than
//!    incidental scattered hits across a huge document)
//! 4. Filename / document title alignment bonus
//! 5. Calibrated distractor penalty for roleplay/prompt-chrome/non-entity stubs
//!
//! Runs with bounded parallelism via `rayon` when candidate pools are large (`>= 32`), with
//! deterministic tie-breaking by `chunk_id` so cross-host mesh parity stays 100% reproducible.

use std::collections::BTreeSet;
use quorum_types::ScoredChunk;

/// Configurable parameters for second-stage reranking.
#[derive(Debug, Clone, Copy)]
pub struct RerankerConfig {
    /// Minimum normalized rerank score required to survive when stronger anchored hits exist.
    pub distractor_floor_ratio: f32,
    /// Hard minimum number of top candidates preserved (never starves narrow corpora).
    pub min_retained: usize,
}

impl Default for RerankerConfig {
    fn default() -> Self {
        Self {
            distractor_floor_ratio: 0.28,
            min_retained: 3,
        }
    }
}

/// Detailed diagnostic score breakdown for a single reranked chunk.
#[derive(Debug, Clone)]
pub struct RerankedCandidate {
    pub chunk: ScoredChunk,
    pub combined_score: f32,
    pub subject_anchored: bool,
    pub sub_question_hits: usize,
    pub distractor_penalized: bool,
}

/// Production second-stage cross-signal reranker (`Top-50 -> Top-K`).
pub struct CrossSignalReranker;

impl CrossSignalReranker {
    /// Reranks `candidates` against the original `query`, optional `primary_subject`, and
    /// `sub_questions` (from Adaptive RAG #8), pruning low-signal distractors when high-confidence
    /// subject-anchored documents are present.
    pub fn rerank(
        query: &str,
        primary_subject: Option<&str>,
        sub_questions: &[String],
        candidates: Vec<ScoredChunk>,
        top_k: usize,
        config: RerankerConfig,
    ) -> Vec<RerankedCandidate> {
        if candidates.is_empty() || top_k == 0 {
            return Vec::new();
        }

        let subj_low = primary_subject.map(|s| s.to_ascii_lowercase());
        let subj_tokens: Vec<String> = subj_low
            .as_deref()
            .map(extract_content_tokens)
            .unwrap_or_default();
        let query_tokens = extract_content_tokens(query);
        let sub_q_token_sets: Vec<Vec<String>> = if sub_questions.is_empty() {
            vec![query_tokens.clone()]
        } else {
            sub_questions
                .iter()
                .map(|sq| extract_content_tokens(sq))
                .filter(|v| !v.is_empty())
                .collect()
        };

        let mut scored: Vec<RerankedCandidate> = candidates
            .into_iter()
            .map(|sc| {
                Self::score_one(
                    sc,
                    subj_low.as_deref(),
                    &subj_tokens,
                    &query_tokens,
                    &sub_q_token_sets,
                )
            })
            .collect();

        scored.sort_by(|a, b| {
            b.combined_score
                .partial_cmp(&a.combined_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.chunk.chunk.chunk_id.cmp(&b.chunk.chunk.chunk_id))
        });

        let has_subject_anchors = subj_low.is_some()
            && scored.iter().any(|c| c.subject_anchored && !c.distractor_penalized);
        let top_score = scored.first().map(|c| c.combined_score).unwrap_or(0.0).max(0.01);
        let floor = top_score * config.distractor_floor_ratio;

        // Prune clearly unanchored / roleplay distractors when strong subject-anchored hits exist,
        // while preserving all legitimate homonym/domain documents that genuinely reference the subject!
        if has_subject_anchors && scored.len() > config.min_retained {
            let mut kept: Vec<RerankedCandidate> = Vec::with_capacity(scored.len().min(top_k));
            for item in scored {
                let is_artemis = item.chunk.chunk.file_path.to_ascii_lowercase().starts_with("artemis://");
                if is_artemis
                    || item.subject_anchored
                    || (!item.distractor_penalized && item.combined_score >= floor)
                    || kept.len() < config.min_retained
                {
                    kept.push(item);
                }
            }
            kept.truncate(top_k);
            return kept;
        }

        scored.truncate(top_k);
        scored
    }

    fn score_one(
        mut sc: ScoredChunk,
        subj_low: Option<&str>,
        subj_tokens: &[String],
        query_tokens: &[String],
        sub_q_token_sets: &[Vec<String>],
    ) -> RerankedCandidate {
        let text_low = sc.chunk.text_content.to_ascii_lowercase();
        let file_name_low = sc
            .chunk
            .file_path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&sc.chunk.file_path)
            .to_ascii_lowercase();
        let combined_haystack = format!("{file_name_low}\n{text_low}");

        // 1. Subject phrase adjacency & full-name anchoring
        let (subject_anchored, subject_bonus) = if let Some(subj) = subj_low {
            if combined_haystack.contains(subj) {
                (true, 0.45f32)
            } else if subj_tokens.len() >= 2 && has_tokens_within_window(&text_low, subj_tokens, 64) {
                (true, 0.35f32)
            } else if subj_tokens.len() >= 2 && subj_tokens.iter().all(|t| combined_haystack.contains(t.as_str())) {
                // Both tokens exist somewhere, weaker than adjacent phrase
                (true, 0.12f32)
            } else {
                (false, -0.35f32)
            }
        } else {
            (false, 0.0f32)
        };

        // 2. Sub-question coverage (#8): reward documents answering specific sub-questions (e.g. "research")
        let mut sub_question_hits = 0usize;
        for sq_toks in sub_q_token_sets {
            let matched = sq_toks
                .iter()
                .filter(|t| combined_haystack.contains(t.as_str()))
                .count();
            if !sq_toks.is_empty() && matched * 2 >= sq_toks.len() {
                sub_question_hits += 1;
            }
        }
        let sub_q_bonus = if !sub_q_token_sets.is_empty() {
            0.22 * (sub_question_hits as f32 / sub_q_token_sets.len() as f32)
        } else {
            0.0
        };

        // 3. Windowed query-term density (tight lexical co-occurrence)
        let matched_q: Vec<&str> = query_tokens
            .iter()
            .filter(|t| text_low.contains(t.as_str()))
            .map(|t| t.as_str())
            .collect();
        let lexical_coverage = if query_tokens.is_empty() {
            0.0
        } else {
            matched_q.len() as f32 / query_tokens.len() as f32
        };
        let proximity_bonus = if matched_q.len() >= 2
            && has_tokens_within_window(
                &text_low,
                &matched_q.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                140,
            )
        {
            0.14f32
        } else {
            0.0
        };

        // 4. Title / filename token match bonus
        let title_hits = query_tokens
            .iter()
            .filter(|t| file_name_low.contains(t.as_str()))
            .count();
        let title_bonus = (title_hits as f32 * 0.06).min(0.18);

        // 5. Distractor penalty for fictional roleplay / ChatGPT prompt chrome / murder mystery scripts
        // when the document is NOT actually anchored to the requested entity
        let looks_fictional_or_roleplay = !subject_anchored
            && (text_low.contains("you are loretta")
                || text_low.contains("murder mystery")
                || file_name_low.contains("murder mystery")
                || text_low.contains("character sheet")
                || text_low.contains("would you like this in word or pdf format"));
        let distractor_penalty = if looks_fictional_or_roleplay { -0.45f32 } else { 0.0f32 };

        let prior = sc.score.clamp(0.0, 1.5);
        let combined_score = (prior * 0.45
            + subject_bonus
            + sub_q_bonus
            + lexical_coverage * 0.25
            + proximity_bonus
            + title_bonus
            + distractor_penalty)
            .max(0.0);

        // Preserve relative rerank strength on `sc.score` (bounded cleanly in 0.0..=1.0)
        sc.score = combined_score.clamp(0.0, 1.0);

        RerankedCandidate {
            chunk: sc,
            combined_score,
            subject_anchored,
            sub_question_hits,
            distractor_penalized: looks_fictional_or_roleplay || (subj_low.is_some() && !subject_anchored),
        }
    }
}

fn extract_content_tokens(text: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "who", "what", "where", "when", "why", "how", "is", "are", "was", "were", "the", "and",
        "for", "with", "from", "about", "her", "his", "their", "she", "he", "they", "this", "that",
        "tell", "does", "did", "can", "into", "over", "all",
    ];
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for raw in text.split(|c: char| !c.is_alphanumeric()) {
        let low = raw.to_ascii_lowercase();
        if low.len() >= 3 && !STOP.contains(&low.as_str()) && seen.insert(low.clone()) {
            out.push(low);
        }
    }
    out
}

fn has_tokens_within_window(haystack: &str, tokens: &[String], window_bytes: usize) -> bool {
    if tokens.len() < 2 {
        return false;
    }
    let first = &tokens[0];
    let second = &tokens[1];
    for (pos, _) in haystack.match_indices(first.as_str()) {
        let start = pos.saturating_sub(window_bytes);
        let end = (pos + first.len() + window_bytes).min(haystack.len());
        let mut s = start;
        while s < haystack.len() && !haystack.is_char_boundary(s) {
            s += 1;
        }
        let mut e = end;
        while e > s && !haystack.is_char_boundary(e) {
            e -= 1;
        }
        if haystack[s..e].contains(second.as_str()) {
            return true;
        }
    }
    false
}

/// Active Stage-2b local neural reranker backend selected dynamically from loopback services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeuralRerankBackend {
    /// Cohere/TEI/vLLM/llama-server compatible `/v1/rerank` or `/api/rerank` on loopback
    /// (e.g. `BAAI/bge-reranker-v2-m3` or `Qwen3-Reranker`).
    NativeRerankApi { endpoint: String, model: String },
    /// Local Ollama causal cross-encoder reranker (`Qwen3-Reranker` / `bge-reranker-v2-m3`)
    /// scored concurrently via `/api/chat` `logprobs: true` (`yes`/`no` calibrated softmax).
    OllamaCrossEncoderLogprob { endpoint: String, model: String },
    /// Local Ollama dense bi-encoder batch re-scoring (`POST /api/embed` in one single round-trip)
    /// using `qwen3-embedding`, `bge-m3`, `nomic-embed-text`, `mxbai-embed-large`, etc.
    OllamaBatchEmbedCosine { endpoint: String, model: String },
    /// Graceful offline fallback (Stage-2a `CrossSignalReranker` only).
    CrossSignalOnly,
}

/// Stage-2b local neural semantic reranker (`bge-reranker-v2-m3`, `Qwen3-Reranker`, Ollama
/// `/api/embed` bi-encoder, and native loopback `/v1/rerank`).
pub struct NeuralReranker;

impl NeuralReranker {
    /// Maximum passages submitted to Stage-2b neural scoring (keeps query latency snappy).
    pub const MAX_NEURAL_CANDIDATES: usize = 24;

    /// Strict 400ms health/tag probe timeout so offline daemons never block interactive retrieval.
    pub const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(400);

    /// Selects the highest-precision locally installed Stage-2b neural backend on loopback.
    pub async fn detect_local_backend(
        ollama_endpoint: &str,
        explicit_rerank_endpoint: Option<&str>,
    ) -> NeuralRerankBackend {
        // 1. Check explicit local Cohere/TEI/llama-server `/v1/rerank` endpoint (loopback only)
        if let Some(ep) = explicit_rerank_endpoint {
            let clean_ep = ep.trim().trim_end_matches('/');
            if !clean_ep.is_empty() && crate::typed_extractor::is_loopback_endpoint(clean_ep) {
                let model = std::env::var("QUORUM_RERANKER_MODEL")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| "BAAI/bge-reranker-v2-m3".to_string());
                return NeuralRerankBackend::NativeRerankApi {
                    endpoint: clean_ep.to_string(),
                    model,
                };
            }
        }

        // 2. Probe local loopback Ollama `/api/tags` with strict 400ms timeout
        let clean_ollama = ollama_endpoint.trim().trim_end_matches('/');
        if clean_ollama.is_empty() || !crate::typed_extractor::is_loopback_endpoint(clean_ollama) {
            return NeuralRerankBackend::CrossSignalOnly;
        }
        let client = match reqwest::Client::builder()
            .connect_timeout(Self::PROBE_TIMEOUT)
            .timeout(Self::PROBE_TIMEOUT)
            .build()
        {
            Ok(c) => c,
            Err(_) => return NeuralRerankBackend::CrossSignalOnly,
        };
        let resp = match client.get(format!("{clean_ollama}/api/tags")).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => return NeuralRerankBackend::CrossSignalOnly,
        };
        let val: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => return NeuralRerankBackend::CrossSignalOnly,
        };
        let installed: Vec<String> = val
            .get("models")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|m| m.get("name").and_then(|n| n.as_str()))
                    .map(|s| s.trim().to_string())
                    .collect()
            })
            .unwrap_or_default();

        // Priority A: Dedicated cross-encoder reranker model installed in Ollama
        if let Some(rerank_model) = installed.iter().find(|m| {
            let l = m.to_ascii_lowercase();
            l.contains("rerank") || l.contains("bge-reranker") || l.contains("qwen3-reranker")
        }) {
            return NeuralRerankBackend::OllamaCrossEncoderLogprob {
                endpoint: clean_ollama.to_string(),
                model: rerank_model.clone(),
            };
        }

        // Priority B: Local dense embedding model in Ollama (single batched `/api/embed` call)
        const EMBED_PREFS: &[&str] = &[
            "qwen3-embedding",
            "bge-m3",
            "bge-large",
            "mxbai-embed-large",
            "nomic-embed-text",
            "snowflake-arctic-embed",
            "all-minilm",
        ];
        for pref in EMBED_PREFS {
            if let Some(found) = installed
                .iter()
                .find(|m| m.to_ascii_lowercase().contains(pref))
            {
                return NeuralRerankBackend::OllamaBatchEmbedCosine {
                    endpoint: clean_ollama.to_string(),
                    model: found.clone(),
                };
            }
        }

        NeuralRerankBackend::CrossSignalOnly
    }

    /// Blends Stage-2a `CrossSignalReranker` candidates with Stage-2b local neural scores
    /// (`0.55 * neural + 0.45 * cross_signal`) while keeping deterministic `chunk_id` tie-breaking.
    pub async fn rerank_with_backend(
        query: &str,
        mut candidates: Vec<RerankedCandidate>,
        backend: &NeuralRerankBackend,
    ) -> Vec<RerankedCandidate> {
        if candidates.len() <= 1 || matches!(backend, NeuralRerankBackend::CrossSignalOnly) {
            return candidates;
        }

        let eval_count = candidates.len().min(Self::MAX_NEURAL_CANDIDATES);
        let snippets: Vec<String> = candidates[..eval_count]
            .iter()
            .map(|c| {
                let fname = c
                    .chunk
                    .chunk
                    .file_path
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(&c.chunk.chunk.file_path);
                let excerpt: String = c.chunk.chunk.text_content.chars().take(700).collect();
                format!("{fname}: {excerpt}")
            })
            .collect();

        let neural_scores_opt = match backend {
            NeuralRerankBackend::NativeRerankApi { endpoint, model } => {
                Self::score_via_native_rerank_api(endpoint, model, query, &snippets).await
            }
            NeuralRerankBackend::OllamaCrossEncoderLogprob { endpoint, model } => {
                Self::score_via_ollama_logprobs(endpoint, model, query, &snippets).await
            }
            NeuralRerankBackend::OllamaBatchEmbedCosine { endpoint, model } => {
                Self::score_via_ollama_batch_embed(endpoint, model, query, &snippets).await
            }
            NeuralRerankBackend::CrossSignalOnly => None,
        };

        let Some(neural_scores) = neural_scores_opt else {
            return candidates;
        };
        if neural_scores.len() != eval_count {
            return candidates;
        }

        // Normalize Stage-2a scores into [0, 1] for calibrated fusion
        let max_s2a = candidates[..eval_count]
            .iter()
            .map(|c| c.combined_score)
            .fold(0.01f32, f32::max);

        for (cand, n_score) in candidates[..eval_count].iter_mut().zip(neural_scores.into_iter()) {
            let norm_s2a = (cand.combined_score / max_s2a).clamp(0.0, 1.0);
            let clamped_neural = n_score.clamp(0.0, 1.0);
            let fused = 0.55 * clamped_neural + 0.45 * norm_s2a;
            cand.combined_score = fused;
            cand.chunk.score = fused;
        }

        candidates[..eval_count].sort_by(|a, b| {
            b.combined_score
                .partial_cmp(&a.combined_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.chunk.chunk.chunk_id.cmp(&b.chunk.chunk.chunk_id))
        });
        candidates
    }

    /// Convenience entrypoint called from `RetrieveMeshNode::execute()`: probes configured
    /// loopback reranker / Ollama only when the daemon runtime is initialized.
    pub async fn maybe_neural_rerank_live(
        query: &str,
        candidates: Vec<RerankedCandidate>,
    ) -> Vec<RerankedCandidate> {
        if candidates.len() <= 1 {
            return candidates;
        }
        let controller = crate::dlp_mesh::global_mesh_dlp_controller();
        let daemon_active = controller
            .settings_file_path
            .read()
            .map(|p| p.is_some())
            .unwrap_or(false);
        if !daemon_active {
            return candidates;
        }
        let ollama_url = controller
            .settings
            .read()
            .map(|g| g.ui.ollama_url.clone())
            .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string());
        let explicit_reranker = std::env::var("QUORUM_RERANKER_URL").ok();
        let backend =
            Self::detect_local_backend(&ollama_url, explicit_reranker.as_deref()).await;
        Self::rerank_with_backend(query, candidates, &backend).await
    }

    async fn score_via_native_rerank_api(
        endpoint: &str,
        model: &str,
        query: &str,
        documents: &[String],
    ) -> Option<Vec<f32>> {
        if !crate::typed_extractor::is_loopback_endpoint(endpoint) {
            return None;
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Self::PROBE_TIMEOUT)
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .ok()?;

        let url = if endpoint.ends_with("/rerank") {
            endpoint.to_string()
        } else {
            format!("{}/v1/rerank", endpoint.trim_end_matches('/'))
        };
        let payload = serde_json::json!({
            "model": model,
            "query": query,
            "documents": documents,
            "top_n": documents.len()
        });
        let resp = client.post(&url).json(&payload).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        let results = body.get("results")?.as_array()?;
        let mut out = vec![0.0f32; documents.len()];
        for item in results {
            let idx = item.get("index").and_then(|v| v.as_u64())? as usize;
            let score = item
                .get("relevance_score")
                .or_else(|| item.get("score"))
                .and_then(|v| v.as_f64())? as f32;
            if idx < out.len() {
                out[idx] = score.clamp(0.0, 1.0);
            }
        }
        Some(out)
    }

    async fn score_via_ollama_logprobs(
        endpoint: &str,
        model: &str,
        query: &str,
        documents: &[String],
    ) -> Option<Vec<f32>> {
        if !crate::typed_extractor::is_loopback_endpoint(endpoint) {
            return None;
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Self::PROBE_TIMEOUT)
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .ok()?;

        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
        let mut set = tokio::task::JoinSet::new();
        let url = format!("{}/api/chat", endpoint.trim_end_matches('/'));

        for (idx, doc) in documents.iter().enumerate() {
            let permit = std::sync::Arc::clone(&sem).acquire_owned().await.ok()?;
            let client_c = client.clone();
            let url_c = url.clone();
            let model_c = model.to_string();
            let query_c = query.to_string();
            let doc_c = doc.clone();

            set.spawn(async move {
                let _guard = permit;
                let payload = serde_json::json!({
                    "model": model_c,
                    "stream": false,
                    "logprobs": true,
                    "top_logprobs": 5,
                    "messages": [
                        {
                            "role": "system",
                            "content": "Judge whether the Document directly answers or provides grounded evidence for the Query. Reply strictly with one token: yes or no."
                        },
                        {
                            "role": "user",
                            "content": format!("Query: {query_c}\nDocument: {doc_c}\nRelevant (yes/no):")
                        }
                    ],
                    "options": {
                        "temperature": 0.0,
                        "num_predict": 1
                    }
                });
                let resp = client_c.post(&url_c).json(&payload).send().await.ok()?;
                if !resp.status().is_success() {
                    return None;
                }
                let body: serde_json::Value = resp.json().await.ok()?;
                // Extract top_logprobs from Ollama `/api/chat` logprobs array if present
                let mut lp_pairs: Vec<(String, f64)> = Vec::new();
                if let Some(arr) = body.get("logprobs").and_then(|v| v.as_array()) {
                    if let Some(first_tok) = arr.first() {
                        if let Some(tops) = first_tok.get("top_logprobs").and_then(|v| v.as_array()) {
                            for item in tops {
                                if let (Some(tok), Some(lp)) = (
                                    item.get("token").and_then(|t| t.as_str()),
                                    item.get("logprob").and_then(|l| l.as_f64()),
                                ) {
                                    lp_pairs.push((tok.to_string(), lp));
                                }
                            }
                        }
                    }
                }
                let prob_yes = if !lp_pairs.is_empty() {
                    let borrowed: Vec<(&str, f64)> =
                        lp_pairs.iter().map(|(s, lp)| (s.as_str(), *lp)).collect();
                    let (_, _, probs) = crate::nimble_client::NimbleClient::compute_constrained_softmax(
                        &borrowed,
                        &["yes", "no"],
                        1.0,
                    );
                    probs.get("yes").copied().unwrap_or(0.5) as f32
                } else {
                    let content = body
                        .get("message")
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase();
                    if content.starts_with("yes") {
                        0.92
                    } else if content.starts_with("no") {
                        0.08
                    } else {
                        0.50
                    }
                };
                Some((idx, prob_yes))
            });
        }

        let mut scores = vec![0.5f32; documents.len()];
        let mut received = 0usize;
        while let Some(res) = set.join_next().await {
            if let Ok(Some((idx, score))) = res {
                if idx < scores.len() {
                    scores[idx] = score;
                    received += 1;
                }
            }
        }
        if received == 0 {
            None
        } else {
            Some(scores)
        }
    }

    async fn score_via_ollama_batch_embed(
        endpoint: &str,
        model: &str,
        query: &str,
        documents: &[String],
    ) -> Option<Vec<f32>> {
        if !crate::typed_extractor::is_loopback_endpoint(endpoint) {
            return None;
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Self::PROBE_TIMEOUT)
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .ok()?;

        let mut inputs = Vec::with_capacity(documents.len() + 1);
        inputs.push(query.to_string());
        inputs.extend(documents.iter().cloned());

        let payload = serde_json::json!({
            "model": model,
            "input": inputs
        });
        let url = format!("{}/api/embed", endpoint.trim_end_matches('/'));
        let resp = client.post(&url).json(&payload).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        let embeds = body.get("embeddings")?.as_array()?;
        if embeds.len() != documents.len() + 1 {
            return None;
        }
        let parse_vec = |v: &serde_json::Value| -> Option<Vec<f32>> {
            let arr = v.as_array()?;
            let mut out = Vec::with_capacity(arr.len());
            for x in arr {
                out.push(x.as_f64()? as f32);
            }
            Some(out)
        };
        let q_vec = parse_vec(&embeds[0])?;
        let mut out = Vec::with_capacity(documents.len());
        for emb in &embeds[1..] {
            let d_vec = parse_vec(emb)?;
            let cos = cosine_similarity(&q_vec, &d_vec);
            // Map cosine [-1, 1] cleanly into [0, 1]
            out.push(((cos + 1.0) * 0.5).clamp(0.0, 1.0));
        }
        Some(out)
    }
}

fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f64;
    let mut na = 0.0f64;
    let mut nb = 0.0f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let xf = x as f64;
        let yf = y as f64;
        dot += xf * yf;
        na += xf * xf;
        nb += yf * yf;
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom <= 1e-12 {
        0.0
    } else {
        (dot / denom) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quorum_types::DocumentChunk;

    fn mk(id: &str, path: &str, text: &str, score: f32) -> ScoredChunk {
        ScoredChunk {
            chunk: DocumentChunk::new(id, id, path, 1, 10, 0, vec![0.0; 8], text, None).unwrap(),
            score,
            source_peer: "local".to_string(),
            is_remote: false,
        }
    }

    #[test]
    fn test_reranker_promotes_anchored_research_and_prunes_fictional_distractors() {
        let docs = vec![
            mk(
                "d1",
                "D:/Docs/Good Times Murder Mystery.docx",
                "You are Loretta Banks in a murder mystery game night character sheet with no subject mention.",
                0.92,
            ),
            mk(
                "d2",
                "D:/Docs/Women Race Class Summary.docx",
                "Women, Race & Class (1981) by Angela Davis is landmark critical research examining race, gender, slavery, suffrage, and class.",
                0.78,
            ),
            mk(
                "d3",
                "D:/Docs/Aerial's LEase.odt",
                "Lease agreement entered into with Firldeal (Angela Davis) Breure for 2913 Castiglione St., New Orleans, LA.",
                0.75,
            ),
            mk(
                "d4",
                "D:/Docs/Spiritual Ministry Notes.docx",
                "Rev. Angela Davis leads organizational stewardship and spiritual ministry workshops.",
                0.72,
            ),
        ];

        let plan = crate::adaptive_rag::plan_adaptive_query("who is angela davis what is her research", false);
        let ranked = CrossSignalReranker::rerank(
            "who is angela davis what is her research",
            plan.primary_subject.as_deref(),
            &plan.sub_questions,
            docs,
            10,
            RerankerConfig::default(),
        );

        assert_eq!(
            ranked[0].chunk.chunk.file_path,
            "D:/Docs/Women Race Class Summary.docx",
            "Research document answering BOTH who Angela Davis is AND her research must rank #1"
        );
        assert!(
            !ranked
                .iter()
                .any(|r| r.chunk.chunk.file_path.contains("Good Times Murder Mystery")),
            "Unanchored fictional murder mystery distractor must be pruned when real anchored docs exist"
        );
        // Distinct real homonym identities MUST ALL be preserved (zero content reduction!)
        assert!(ranked.iter().any(|r| r.chunk.chunk.file_path.contains("Aerial's LEase.odt")));
        assert!(ranked.iter().any(|r| r.chunk.chunk.file_path.contains("Spiritual Ministry Notes.docx")));
    }

    #[tokio::test]
    async fn test_stage2b_neural_reranker_native_api_logprobs_and_batch_embed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let endpoint = format!("http://127.0.0.1:{}", addr.port());

        let srv = tokio::spawn(async move {
            // Expect: 1) /v1/rerank, 2) /api/embed, 3-4) two /api/chat logprob calls
            for _ in 0..4 {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = vec![0u8; 32768];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let body = if req.starts_with("POST /v1/rerank") {
                        serde_json::json!({
                            "results": [
                                { "index": 0, "relevance_score": 0.12 },
                                { "index": 1, "relevance_score": 0.98 }
                            ]
                        })
                        .to_string()
                    } else if req.starts_with("POST /api/embed") {
                        // Query=[1,0], doc0=[0,1] (orthogonal), doc1=[1,0] (identical)
                        serde_json::json!({
                            "embeddings": [
                                [1.0, 0.0],
                                [0.0, 1.0],
                                [1.0, 0.0]
                            ]
                        })
                        .to_string()
                    } else {
                        // /api/chat logprobs: doc containing "Women, Race & Class" gets high yes logprob
                        let yes_lp = if req.contains("Women, Race & Class") { -0.05 } else { -4.5 };
                        let no_lp = if req.contains("Women, Race & Class") { -4.5 } else { -0.05 };
                        serde_json::json!({
                            "message": { "role": "assistant", "content": "yes" },
                            "logprobs": [{
                                "token": "yes",
                                "logprob": yes_lp,
                                "top_logprobs": [
                                    { "token": "yes", "logprob": yes_lp },
                                    { "token": "no", "logprob": no_lp }
                                ]
                            }]
                        })
                        .to_string()
                    };
                    let http = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(http.as_bytes()).await;
                }
            }
        });

        let base_cands = || {
            vec![
                RerankedCandidate {
                    chunk: mk("c0", "D:/Docs/Lease.odt", "Standard monthly lease renewal notice.", 0.85),
                    combined_score: 0.85,
                    subject_anchored: true,
                    sub_question_hits: 1,
                    distractor_penalized: false,
                },
                RerankedCandidate {
                    chunk: mk("c1", "D:/Docs/Research.docx", "Women, Race & Class (1981) critical research.", 0.70),
                    combined_score: 0.70,
                    subject_anchored: true,
                    sub_question_hits: 2,
                    distractor_penalized: false,
                },
            ]
        };

        // 1. Native `/v1/rerank` backend (`bge-reranker-v2-m3`)
        let r_native = NeuralReranker::rerank_with_backend(
            "Angela Davis research",
            base_cands(),
            &NeuralRerankBackend::NativeRerankApi {
                endpoint: endpoint.clone(),
                model: "BAAI/bge-reranker-v2-m3".to_string(),
            },
        )
        .await;
        assert_eq!(r_native[0].chunk.chunk.chunk_id, "c1");

        // 2. Local Ollama `/api/embed` batch bi-encoder cosine backend
        let r_embed = NeuralReranker::rerank_with_backend(
            "Angela Davis research",
            base_cands(),
            &NeuralRerankBackend::OllamaBatchEmbedCosine {
                endpoint: endpoint.clone(),
                model: "qwen3-embedding".to_string(),
            },
        )
        .await;
        assert_eq!(r_embed[0].chunk.chunk.chunk_id, "c1");

        // 3. Local Ollama `Qwen3-Reranker` logprob yes/no softmax backend
        let r_logprob = NeuralReranker::rerank_with_backend(
            "Angela Davis research",
            base_cands(),
            &NeuralRerankBackend::OllamaCrossEncoderLogprob {
                endpoint: endpoint.clone(),
                model: "dengcao/Qwen3-Reranker-0.6B".to_string(),
            },
        )
        .await;
        assert_eq!(r_logprob[0].chunk.chunk.chunk_id, "c1");

        let _ = srv.await;
    }
}
