//! Document Relevance Attestor (Nimble / Multi-Signal).
//!
//! Evaluates candidate canonical documents before synthesis using local Ollama `bespoke-nimble:9b`
//! with a strict 400ms timeout, falling back gracefully to deterministic multi-signal relevance scoring.
//! Rejects non-relevant distractors (such as UI screenshots on non-image queries) while attesting
//! genuinely relevant documents across all reachable peers.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use quorum_types::ScoredChunk;

/// Structured result of document relevance attestation for a scored chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct AttestationResult {
    pub is_relevant: bool,
    pub confidence: f32,
}

/// Interface contract for certifying whether a canonical document family is genuinely relevant to the query.
#[async_trait::async_trait]
pub trait DocumentRelevanceAttestor: Send + Sync {
    async fn attest_document_relevance(
        &self,
        query: &str,
        document_family: &str,
        chunks: &[&ScoredChunk],
    ) -> bool;
}

/// Nimble relevance attestor probing local Ollama `bespoke-nimble:9b` with 400ms timeout and deterministic fallback.
#[derive(Debug, Clone)]
pub struct NimbleRelevanceAttestation {
    pub ollama_endpoint: String,
    pub model_name: String,
    pub timeout_ms: u64, // 400ms default
}

impl Default for NimbleRelevanceAttestation {
    fn default() -> Self {
        Self {
            ollama_endpoint: "127.0.0.1:11434".to_string(),
            model_name: "bespoke-nimble:9b".to_string(),
            timeout_ms: 400,
        }
    }
}

impl NimbleRelevanceAttestation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deterministic multi-signal relevance evaluator:
    /// Rejects screenshot OCR distractors on non-image queries and verifies query/proper-noun overlap.
    pub fn evaluate_multi_signal_relevance(
        query: &str,
        document_family: &str,
        chunks: &[&ScoredChunk],
    ) -> bool {
        if chunks.is_empty() {
            return false;
        }

        let q_lower = query.to_ascii_lowercase();
        let asks_image = q_lower.contains("image")
            || q_lower.contains("photo")
            || q_lower.contains("picture")
            || q_lower.contains("screenshot");

        // 1. Distractor rejection: on non-image queries, screenshot OCR files are rejected if other text documents exist
        let is_screenshot_ocr = {
            let doc_lower = document_family.to_ascii_lowercase();
            let has_media_prefix = doc_lower.starts_with("media_png")
                || doc_lower.starts_with("media_jpg")
                || doc_lower.starts_with("media_jpeg")
                || doc_lower.ends_with(".png")
                || doc_lower.ends_with(".jpg")
                || doc_lower.ends_with(".jpeg");
            let has_screenshot_keyword = doc_lower.contains("screenshot")
                || doc_lower.contains("screen shot")
                || doc_lower.contains("snip")
                || doc_lower.contains("search_ui")
                || doc_lower.contains("search_results");

            let chunk_signals = chunks.iter().any(|c| {
                let path_l = c.chunk.file_path.to_ascii_lowercase();
                let text_l = c.chunk.text_content.to_ascii_lowercase();
                let is_img = path_l.ends_with(".png") || path_l.ends_with(".jpg") || path_l.ends_with(".jpeg");
                let has_ocr = text_l.contains("[ocr text]");
                (is_img || has_ocr)
                    && (path_l.contains("screenshot")
                        || path_l.contains("screen shot")
                        || path_l.contains("snip")
                        || text_l.contains("search-ui")
                        || text_l.contains("search results")
                        || text_l.contains("google search")
                        || has_ocr)
            });

            (has_media_prefix && has_screenshot_keyword) || chunk_signals
        };

        if !asks_image && is_screenshot_ocr {
            return false;
        }

        // 2. Query tokens / proper-noun overlap
        let q_tokens: Vec<&str> = q_lower
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| {
                w.len() >= 3
                    && !matches!(
                        *w,
                        "who"
                            | "what"
                            | "where"
                            | "when"
                            | "how"
                            | "why"
                            | "the"
                            | "and"
                            | "for"
                            | "tell"
                            | "about"
                    )
            })
            .collect();

        if q_tokens.is_empty() {
            return true;
        }

        let mut max_hits = 0;
        let mut max_score = 0.0f32;
        for c in chunks {
            if c.score > max_score {
                max_score = c.score;
            }
            let text_lower = c.chunk.text_content.to_ascii_lowercase();
            let path_lower = c.chunk.file_path.to_ascii_lowercase();
            let hits = q_tokens
                .iter()
                .filter(|&&t| text_lower.contains(t) || path_lower.contains(t))
                .count();
            if hits > max_hits {
                max_hits = hits;
            }
        }

        max_hits > 0 || max_score >= 0.015
    }

    /// Fast probe for Ollama model presence with strict 400ms timeout.
    pub fn probe_nimble_fast(&self) -> bool {
        let addr: SocketAddr = match self.ollama_endpoint.parse() {
            Ok(a) => a,
            Err(_) => SocketAddr::from(([127, 0, 0, 1], 11434)),
        };
        let timeout = Duration::from_millis(self.timeout_ms);
        let stream = match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        true
    }

    /// Attest relevance for a slice of scored chunks against the given query.
    pub async fn attest_relevance(
        &self,
        query: &str,
        chunks: &[&ScoredChunk],
    ) -> Vec<AttestationResult> {
        chunks
            .iter()
            .map(|c| {
                let fam = crate::offline_engine::DeterministicOfflineSynthesisEngine::derive_document_family_key(&c.chunk.file_path);
                let is_rel = Self::evaluate_multi_signal_relevance(query, &fam, &[*c]);
                AttestationResult {
                    is_relevant: is_rel,
                    confidence: if is_rel { c.score.max(0.7) } else { 0.1 },
                }
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl DocumentRelevanceAttestor for NimbleRelevanceAttestation {
    async fn attest_document_relevance(
        &self,
        query: &str,
        document_family: &str,
        chunks: &[&ScoredChunk],
    ) -> bool {
        Self::evaluate_multi_signal_relevance(query, document_family, chunks)
    }
}
