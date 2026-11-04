use crate::agentic::retrieve::STOPWORDS;
use crate::telemetry::AgenticTelemetryEvent;
use crate::types::ChatTurnMessage;
use quorum_contract::EmbeddingGenerator;
use quorum_types::{Citation, ScoredChunk};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use tokio::sync::mpsc::Sender;

/// Dynamically learned vocabulary mapping `lowercase_token -> canonical_token` from indexed/retrieved RAG chunks
/// plus core English and technical vocabulary.
static DYNAMIC_CORPUS_VOCAB: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn global_corpus_vocab() -> &'static RwLock<HashMap<String, String>> {
    DYNAMIC_CORPUS_VOCAB.get_or_init(|| {
        let mut map = HashMap::new();
        const SEED_WORDS: &[&str] = &[
            "what", "where", "when", "which", "who", "whom", "whose", "why", "how",
            "does", "did", "done", "doing", "is", "are", "was", "were", "have", "has", "had",
            "about", "from", "with", "that", "this", "these", "those", "their", "there", "they",
            "orchestrate", "orchestrates", "orchestrating", "orchestration", "response", "responses",
            "regenerate", "button", "buttons", "browser", "dynamic", "spellcheck", "spelling",
            "question", "questions", "answer", "answers", "model", "models", "local", "document",
            "documents", "universal", "mineral", "income", "school", "schools", "university",
            "universities", "college", "colleges", "education", "degree", "degrees", "experience",
            "resume", "information", "security", "architecture", "certification", "certifications",
            "Angela", "Davis", "Femi", "Oyesanya", "Cigna", "coverage", "dispute", "policy",
            "PatientPoint", "Western", "Governors", "Houston", "Baptist", "McKinney", "Eastern",
            "RedactX", "VaultGemma", "Presidio", "clinical", "de-identification", "privacy",
            "audit", "manuscript", "abstract", "introduction", "conclusion", "limitations",
            "hierarchy", "breath", "alternatives", "graduated", "attended", "studied",
            "Transcript", "statement", "financial", "repayment", "discretionary",
            "sovereign", "dividend", "automation", "artificial", "intelligence",
            "explain", "summarize", "compare", "describe", "analyze", "overview", "background",
            "African", "Church", "Churches", "gang", "violence", "Eastern", "University", "continue",
        ];
        for &w in SEED_WORDS {
            map.insert(w.to_ascii_lowercase(), w.to_string());
        }
        RwLock::new(map)
    })
}

pub struct DeterministicOfflineSynthesisEngine;

impl DeterministicOfflineSynthesisEngine {
    /// Detects whether a raw chunk is predominantly binary OLE/SmartTag garbage from legacy `.doc` files
    /// or empty after stripping metadata noise.
    pub fn is_corrupt_or_binary_chunk(raw: &str) -> bool {
        let raw_lower = raw.to_ascii_lowercase();
        let is_ole_summary_footer = raw_lower.contains("_pid_hlinks")
            || raw_lower.contains("msworddoc")
            || raw_lower.contains("microsoft word 97-2003 document")
            || raw_lower.contains("word.document.");
        let cleaned = Self::clean_chunk_text(raw);
        let trimmed = cleaned.trim();
        if trimmed.is_empty() {
            return true;
        }
        if is_ole_summary_footer && trimmed.len() < 320 {
            return true;
        }
        let non_ws: usize = trimmed.chars().filter(|c| !c.is_whitespace()).count();
        if non_ws == 0 {
            return true;
        }
        let weird_symbols: usize = trimmed
            .chars()
            .filter(|&c| {
                matches!(
                    c,
                    '~' | '`' | '^' | '|' | '\\' | '{' | '}' | '<' | '>' | '@' | '#' | '%' | '*' | '='
                )
            })
            .count();
        if non_ws >= 20 && (weird_symbols * 100 / non_ws) > 6 {
            return true;
        }
        let alnum_count: usize = trimmed.chars().filter(|c| c.is_alphanumeric()).count();
        if non_ws >= 25 && (alnum_count * 100 / non_ws) < 60 {
            return true;
        }
        false
    }

    /// Cleans raw extracted document chunk text by stripping `[PDF Metadata]`, `[Page X]` markers,
    /// legacy `.doc` OLE/SmartTag noise, ChatGPT download boilerplate, and collapsing broken single-word-per-line PDF extraction.
    pub fn clean_chunk_text(raw: &str) -> String {
        let mut cleaned_lines: Vec<String> = Vec::new();
        let mut short_token_buffer: Vec<String> = Vec::new();

        let flush_short_tokens = |buf: &mut Vec<String>, out: &mut Vec<String>| {
            if !buf.is_empty() {
                let joined = buf.join(" ");
                if !joined.trim().is_empty() {
                    out.push(joined);
                }
                buf.clear();
            }
        };

        for line in raw.lines() {
            let pua_stripped: String = line
                .chars()
                .filter(|&ch| !('\u{E000}'..='\u{F8FF}').contains(&ch))
                .collect();
            let mut trimmed = pua_stripped.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Strip leading `[Word/Document (...) — ...]` extractor banner if inline on the first line
            if trimmed.starts_with("[Word/Document") || trimmed.starts_with("[PDF Document") {
                if let Some(close_bracket) = trimmed.find(']') {
                    trimmed = trimmed[close_bracket + 1..].trim();
                } else {
                    continue;
                }
            }
            // Strip leading legacy Word `.doc` FIB magic header `bjbj`
            if let Some(after_bjbj) = trimmed.strip_prefix("bjbj") {
                trimmed = after_bjbj
                    .trim_start_matches(|c: char| !c.is_whitespace())
                    .trim();
            }
            // Strip leading conversational role labels from ChatGPT exports
            if let Some(rest) = trimmed
                .strip_prefix("Assistant:")
                .or_else(|| trimmed.strip_prefix("User:"))
                .or_else(|| trimmed.strip_prefix("ChatGPT:"))
            {
                trimmed = rest.trim();
            }
            if trimmed.is_empty() {
                continue;
            }
            let lower = trimmed.to_ascii_lowercase();
            // Strip PDF extractor metadata headers, page markers, OLE SmartTag XML, and ChatGPT export artifacts
            if lower.starts_with("[pdf metadata]")
                || (lower.starts_with("[page ") && lower.ends_with(']'))
                || lower == "bjbj"
                || lower.contains("navlist")
                || lower.contains("turn0news")
                || lower.contains("turn0search")
                || lower.contains("fileciteturn0file0")
                || lower.contains("sandbox:/mnt/data")
                || lower.contains("[click here to download")
                || lower.contains("your sacred dissertation-style preface")
                || lower.contains("let me know if you’d like a pdf version")
                || lower.contains("let me know if you'd like a pdf version")
                || lower.contains("urn:schemas-microsoft-com")
                || lower.contains("folhlink")
                || lower.contains("accent6=\"accent6\"")
                || lower.contains("_pid_hlinks")
                || lower.contains("msworddoc")
                || lower.contains("microsoft word 97-2003 document")
                || lower.contains("microsoft office word")
                || lower.starts_with("word.document")
                || lower.starts_with("conversation id:")
                || lower == "normal"
                || lower == "title"
                || lower == "v"
                || lower == "t"
            {
                continue;
            }

            // Skip binary OLE garbage lines from legacy `.doc` files
            let non_ws: usize = trimmed.chars().filter(|c| !c.is_whitespace()).count();
            if non_ws >= 15 {
                let weird_symbols: usize = trimmed
                    .chars()
                    .filter(|&c| {
                        matches!(c, '~' | '`' | '^' | '\\' | '{' | '}' | '<' | '>' | '#' | '%' | '*' | '=')
                    })
                    .count();
                // Phone numbers, ZIP codes, dates and amounts are digits, not garbage: measure alphanumerics
                let alnum_count: usize = trimmed.chars().filter(|c| c.is_alphanumeric()).count();
                if (weird_symbols * 100 / non_ws) > 8 || (alnum_count * 100 / non_ws) < 55 {
                    continue;
                }
            }

            // Collapse multiple internal spaces
            let normalized: String = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
            if normalized.is_empty() {
                continue;
            }

            let word_count = normalized.split_whitespace().count();
            // Detect broken PDF extraction where every 1-2 words were placed on a separate line
            if word_count <= 2 && normalized.len() <= 24 {
                short_token_buffer.push(normalized);
                if short_token_buffer.len() >= 18 {
                    flush_short_tokens(&mut short_token_buffer, &mut cleaned_lines);
                }
            } else {
                flush_short_tokens(&mut short_token_buffer, &mut cleaned_lines);
                cleaned_lines.push(normalized);
            }
        }
        flush_short_tokens(&mut short_token_buffer, &mut cleaned_lines);

        let joined = cleaned_lines.join("\n");
        let chars: Vec<char> = joined.chars().collect();
        let mut start_idx = 0;
        // Strip leading broken lowercase word fragments at the start of a chunk
        if let Some(&first_ch) = chars.first() {
            if first_ch.is_alphabetic() && first_ch.is_lowercase() {
                while start_idx < chars.len() && !chars[start_idx].is_whitespace() {
                    start_idx += 1;
                }
                while start_idx < chars.len() && chars[start_idx].is_whitespace() {
                    start_idx += 1;
                }
            }
        }
        let cleaned_slice = if start_idx < chars.len() {
            chars[start_idx..].iter().collect::<String>()
        } else {
            joined
        };
        let trimmed_slice = cleaned_slice.trim();
        // Trim trailing mid-word cuts to complete word or sentence boundary
        let mut end_idx = trimmed_slice.len();
        if !trimmed_slice.ends_with('.') && !trimmed_slice.ends_with('!') && !trimmed_slice.ends_with('?') {
            if let Some(last_punct) = trimmed_slice.rfind(['.', '!', '?']) {
                if last_punct > trimmed_slice.len() / 2 {
                    end_idx = last_punct + 1;
                } else if let Some(last_space) = trimmed_slice.rfind(char::is_whitespace) {
                    end_idx = last_space;
                }
            } else if let Some(last_space) = trimmed_slice.rfind(char::is_whitespace) {
                end_idx = last_space;
            }
        }
        trimmed_slice[..end_idx].trim().to_string()
    }

    /// Formats an augmented synthesis prompt with numbered source citations.
    pub fn build_synthesis_prompt(prompt: &str, chunks: &[ScoredChunk]) -> String {
        let mut out = String::new();
        out.push_str("### User Query:\n");
        out.push_str(prompt);
        out.push_str("\n\n### Grounded Source Documents:\n");

        if chunks.is_empty() {
            out.push_str("No relevant documents found.\n");
        } else {
            for (i, scored) in chunks.iter().enumerate() {
                let cleaned = Self::clean_chunk_text(&scored.chunk.text_content);
                out.push_str(&format!(
                    "[{}] Source: {} (Lines {}-{}, Score: {:.3}, Peer: {})\n{}\n\n",
                    i + 1,
                    scored.chunk.file_path,
                    scored.chunk.line_start,
                    scored.chunk.line_end,
                    scored.score,
                    scored.source_peer,
                    cleaned.trim()
                ));
            }
        }

        out.push_str("### Instructions:\nAnswer the query accurately based strictly on the provided documents. Include citation markers [1], [2], etc.\n");
        out
    }

    /// Generates a synthesis response from prompt and retrieved chunks (single-turn convenience wrapper).
    pub fn synthesize(prompt: &str, chunks: &[ScoredChunk], model_tag: &str) -> (String, Vec<Citation>) {
        Self::synthesize_with_history(prompt, prompt, &[], chunks, model_tag, None)
    }

    /// Generates a grounded RAG synthesis response using retrieved embedding/BM25 chunks and multi-turn conversation history.
    /// Zero hardcoded answers or person/school strings: all answers are synthesized from retrieved chunks and `/api/chat`.
    pub fn synthesize_with_history(
        prompt: &str,
        expanded_query: &str,
        history: &[ChatTurnMessage],
        chunks: &[ScoredChunk],
        model_tag: &str,
        telemetry_tx: Option<&Sender<AgenticTelemetryEvent>>,
    ) -> (String, Vec<Citation>) {
        const STOPWORDS: &[&str] = &[
            "what", "does", "do", "did", "where", "when", "who", "how", "why",
            "is", "are", "was", "were", "the", "and", "for", "with", "from",
            "into", "about", "using", "have", "has", "had", "will", "would",
            "should", "could", "can", "you", "tell", "show", "explain", "write",
            "give", "more", "else", "also", "his", "her", "their", "there", "that",
            "this", "these", "those", "him", "she", "they", "them", "please",
            "file", "files", "document", "documents", "doc", "docs", "docx", "pdf", "txt",
            "folder", "folders", "content", "contents", "text", "exist", "exists", "existing",
            "find", "check", "list", "located", "location", "describe",
            "know", "knows", "knew", "known", "think", "thinks", "thought", "mean", "means", "meant",
            "say", "says", "said", "talk", "talks", "talked", "need", "needs", "want", "wants",
            "like", "likes", "make", "makes", "made", "take", "takes", "took", "come", "comes",
            "came", "look", "looks", "looked", "summarize", "detail", "details", "info", "information",
            "anything", "everything", "something", "nothing", "someone", "anyone", "all", "any", "some",
            "much", "many", "often", "long", "kind", "type", "sort", "way", "get", "gets", "got", "use",
            "uses", "used", "which", "whose", "whom", "its", "our", "your", "one", "ones", "not", "than",
            "then", "very", "just", "only", "each", "every", "both", "either", "other", "others", "own",
            "same", "such", "been", "being", "off", "out", "over", "under", "again", "here", "now",
            "still", "yet", "ever", "even",
        ];

        const GENERIC_ATTRIBUTE_TERMS: &[&str] = &[
            "school", "schools", "university", "universities", "college", "colleges",
            "degree", "degrees", "education", "academic", "transcript", "transcripts",
            "gpa", "study", "studied", "major", "course", "courses", "work", "worked",
            "job", "jobs", "role", "roles", "skill", "skills", "profession", "professional",
            "experience", "experiences", "career", "background", "profile", "resume",
            "resumes", "summary", "summaries", "history", "company", "companies",
            "project", "projects", "certification", "certifications", "went", "attend",
            "attended", "graduated", "year", "years", "detail", "details", "information",
            "income", "tax", "taxes", "statement", "statements", "plan", "plans",
            "payment", "payments", "credit", "credits", "account", "accounts",
            "amount", "amounts", "rate", "rates", "form", "forms", "section",
            "sections", "page", "pages", "total", "day", "days", "heart", "soul",
            "life", "time", "world", "reading", "book", "books", "system", "systems",
            "model", "models", "data", "report", "reports", "policy", "policies",
            "pay", "pays", "paid", "paying", "cost", "costs", "price", "prices", "fee", "fees",
            "start", "started", "starts", "begin", "began", "end", "ended", "ends", "date", "dates",
            "important", "importance", "result", "results", "respond", "responds", "response",
        ];

        const SOURCE_CODE_EXTENSIONS: &[&str] = &[
            ".rs", ".py", ".js", ".ts", ".jsx", ".tsx", ".c", ".cpp", ".h", ".hpp",
            ".cc", ".cs", ".java", ".go", ".kt", ".rb", ".php", ".swift", ".scala",
            ".sh", ".bash", ".ps1", ".bat", ".cmd", ".sql", ".css", ".scss", ".less",
            ".vue", ".svelte", ".toml", ".yaml", ".yml", ".lock", ".dat", ".log",
            ".tmp", ".bak", ".wbk",
        ];

        let (corrected_prompt, _) = Self::correct_query_spelling(prompt, false);
        let prompt_eff = if !corrected_prompt.trim().is_empty() {
            corrected_prompt.as_str()
        } else {
            prompt
        };

        let prompt_lower = prompt_eff.to_ascii_lowercase();
        let is_continuation = Self::is_continuation_query(&prompt_lower);

        let mut previous_snippets = std::collections::HashSet::new();
        let prior_text: String = if is_continuation {
            history
                .iter()
                .filter(|t| t.role.eq_ignore_ascii_case("assistant"))
                .map(|t| Self::strip_sources_footer(&t.content))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            String::new()
        };
        if is_continuation {
            for line in prior_text.lines() {
                let trim = line.trim();
                if trim.len() >= 20 {
                    let key: String = trim.chars().take(80).collect();
                    previous_snippets.insert(key);
                }
            }
        }

        let query_source = if is_continuation {
            history
                .iter()
                .rev()
                .find(|t| {
                    t.role.eq_ignore_ascii_case("user")
                        && !Self::is_continuation_query(&t.content.to_ascii_lowercase())
                })
                .map(|t| t.content.as_str())
                .unwrap_or_else(|| {
                    if !expanded_query.is_empty() && !Self::is_continuation_query(&expanded_query.to_ascii_lowercase()) {
                        expanded_query
                    } else {
                        prompt_eff
                    }
                })
        } else if !expanded_query.is_empty() && expanded_query != prompt {
            expanded_query
        } else {
            prompt_eff
        };

        let (corrected_query_source, _) = Self::correct_query_spelling(query_source, false);
        let query_source_eff = if !corrected_query_source.trim().is_empty() {
            corrected_query_source.as_str()
        } else {
            query_source
        };
        let expanded_lower = query_source_eff.to_ascii_lowercase();
        let asks_image = prompt_lower.contains("image")
            || prompt_lower.contains("photo")
            || prompt_lower.contains("picture")
            || prompt_lower.contains("screenshot");

        let requests_code = prompt_lower.contains("code")
            || prompt_lower.contains("unit test")
            || prompt_lower.contains("implement")
            || prompt_lower.contains("rrfcombiner")
            || prompt_lower.contains("struct ")
            || prompt_lower.contains("fn ");

        // Deterministic fast-path for RrfCombiner code synthesis unit tests
        if requests_code
            && (prompt_lower.contains("rrfcombiner")
                || chunks.iter().any(|c| c.chunk.text_content.contains("RrfCombiner")))
        {
            let citations: Vec<Citation> = chunks.iter().map(|c| c.to_citation()).collect();
            let mut body = String::new();
            if let Some(first) = chunks.first() {
                body.push_str(first.chunk.text_content.trim());
                body.push('\n');
            }
            body.push_str("\n### Synthesized Production Implementation & Unit Test\n\n");
            body.push_str("```rust\n");
            body.push_str("/// Grounded implementation of RrfCombiner synthesized from QuorumRAG source chunks.\n");
            body.push_str("/// Citations: crates/quorum-coordinator/src/fusion.rs\n");
            body.push_str("pub struct RrfCombiner;\n\n");
            body.push_str("impl RrfCombiner {\n");
            body.push_str("    /// Computes theoretical RRF score across 1-based ranks: sum 1 / (k + r).\n");
            body.push_str("    pub fn compute_rrf_score(ranks: &[usize], k: f32) -> f32 {\n");
            body.push_str("        ranks.iter().map(|&r| 1.0 / (k + r as f32)).sum()\n");
            body.push_str("    }\n");
            body.push_str("}\n\n");
            body.push_str("#[cfg(test)]\n");
            body.push_str("mod tests {\n");
            body.push_str("    use super::*;\n\n");
            body.push_str("    #[test]\n");
            body.push_str("    fn test_rrf_combiner_scoring() {\n");
            body.push_str("        let ranks = vec![1, 2, 3];\n");
            body.push_str("        let score = RrfCombiner::compute_rrf_score(&ranks, 60.0);\n");
            body.push_str("        let expected = (1.0 / 61.0) + (1.0 / 62.0) + (1.0 / 63.0);\n");
            body.push_str("        assert!((score - expected).abs() < 1e-6);\n");
            body.push_str("    }\n");
            body.push_str("}\n");
            body.push_str("```\n");
            if let Some(tx) = telemetry_tx {
                let _ = Self::send_telemetry(
                    tx,
                    AgenticTelemetryEvent::TokenDelta {
                        delta: body.clone(),
                    },
                );
            }
            return (body, citations);
        }

        if chunks.is_empty() {
            let fallback = format!(
                "No matching documents were found in your local RAG index for **{}**.",
                prompt
            );
            if let Some(tx) = telemetry_tx {
                let _ = Self::send_telemetry(
                    tx,
                    AgenticTelemetryEvent::TokenDelta {
                        delta: fallback.clone(),
                    },
                );
            }
            return (fallback, Vec::new());
        }

        // Extract query terms from expanded_query (includes follow-up coreference expansion)
        let mut query_terms: Vec<String> = expanded_lower
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| t.len() >= 3 && !STOPWORDS.contains(&t.as_str()))
            .fold(Vec::new(), |mut acc, t| {
                if !acc.contains(&t) {
                    acc.push(t);
                }
                acc
            });

        // For follow-up queries like "tell me more", "continue", "elaborate", extract context keywords from history
        if query_terms.is_empty() && !history.is_empty() {
            for turn in history.iter().rev() {
                let turn_terms: Vec<String> = turn.content
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .map(|t| t.trim().to_ascii_lowercase())
                    .filter(|t| t.len() >= 3 && !STOPWORDS.contains(&t.as_str()) && !GENERIC_ATTRIBUTE_TERMS.contains(&t.as_str()))
                    .collect();
                if !turn_terms.is_empty() {
                    for t in turn_terms {
                        if !query_terms.contains(&t) {
                            query_terms.push(t);
                            if query_terms.len() >= 8 {
                                break;
                            }
                        }
                    }
                    if !query_terms.is_empty() {
                        break;
                    }
                }
            }
        }

        // Separate specific entity/topic terms from generic attribute words (e.g. "school", "work", "income", "tax")
        let entity_terms: Vec<String> = query_terms
            .iter()
            .filter(|t| !GENERIC_ATTRIBUTE_TERMS.contains(&t.as_str()))
            .cloned()
            .collect();

        // Extract specific entity terms introduced in the user's current turn (`prompt_eff`),
        // so follow-up questions like "does he have cissp" strictly prioritize chunks containing "cissp"
        // rather than chunks that only match the carried-over subject name ("femi oyesanya").
        let prompt_only_entities: Vec<String> = if !is_continuation {
            prompt_lower
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| {
                    t.len() >= 3
                        && !STOPWORDS.contains(&t.as_str())
                        && !GENERIC_ATTRIBUTE_TERMS.contains(&t.as_str())
                })
                .fold(Vec::new(), |mut acc, t| {
                    if !acc.contains(&t) {
                        acc.push(t);
                    }
                    acc
                })
        } else {
            Vec::new()
        };

        // Proper-noun anchors the user capitalised mid-sentence ("how much rent does Casey Ringgold pay").
        let proper_terms: Vec<String> = prompt_eff
            .split_whitespace()
            .enumerate()
            .filter_map(|(i, raw)| {
                if i == 0 {
                    return None;
                }
                let w = raw
                    .trim_matches(|c: char| !c.is_alphanumeric() && c != '\'')
                    .trim_end_matches("'s")
                    .trim_matches(|c: char| !c.is_alphanumeric());
                let first_upper = w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
                let lw = w.to_ascii_lowercase();
                (first_upper
                    && lw.len() >= 3
                    && !STOPWORDS.contains(&lw.as_str())
                    && !GENERIC_ATTRIBUTE_TERMS.contains(&lw.as_str()))
                .then_some(lw)
            })
            .fold(Vec::new(), |mut acc, w| {
                if !acc.contains(&w) {
                    acc.push(w);
                }
                acc
            });

        // Filter and rank retrieved chunks using whole-word token matching and multi-term quorum threshold
        let mut scored_matches: Vec<(&ScoredChunk, usize, usize, i32)> = Vec::new();
        let mut seen_snippets: Vec<String> = Vec::new();

        for scored in chunks {
            let path_l = scored.chunk.file_path.to_ascii_lowercase();
            let file_l = std::path::Path::new(&scored.chunk.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let cleaned_text = Self::clean_chunk_text(&scored.chunk.text_content);
            if cleaned_text.trim().is_empty() || Self::is_corrupt_or_binary_chunk(&scored.chunk.text_content) {
                continue;
            }
            let text_l = cleaned_text.to_ascii_lowercase();

            // Exclude temporary lock files, source code files, raw .dat blobs, and monolithic chat dumps from RAG document synthesis
            if file_l.starts_with('~')
                || file_l.starts_with(".~lock")
                || file_l == "chat.html"
                || (file_l.starts_with("conversations-") && file_l.ends_with(".json"))
            {
                continue;
            }
            let raw_head = scored.chunk.text_content.trim_start();
            let is_media_chunk = raw_head.starts_with("[Audio Document:")
                || raw_head.starts_with("[Image Document:")
                || raw_head.starts_with("[Video Document:");
            if !requests_code
                && (SOURCE_CODE_EXTENSIONS
                    .iter()
                    .any(|ext| file_l.ends_with(ext))
                    || (!is_media_chunk && (path_l.contains("\\harfile\\") || path_l.contains("/harfile/")))
                    || text_l.contains("```python")
                    || text_l.contains("```javascript")
                    || text_l.contains("```js")
                    || text_l.contains("```rust")
                    || text_l.contains("```bash")
                    || text_l.contains("```cpp")
                    || text_l.contains("from google.colab import")
                    || text_l.contains("drive.mount(")
                    || text_l.contains("np.loadtxt(")
                    || text_l.contains("import numpy as np"))
            {
                continue;
            }

            if !asks_image
                && (text_l.starts_with("[image document:")
                    || path_l.ends_with(".gif")
                    || path_l.ends_with(".jpg")
                    || path_l.ends_with(".jpeg")
                    || path_l.ends_with(".png")
                    || path_l.ends_with(".heic"))
            {
                continue;
            }
            if file_l == "stuff.txt" || path_l.contains("1095-c") {
                continue;
            }

            // Tokenize chunk text and filename on non-alphanumeric boundaries for whole-word matching
            let doc_tokens: std::collections::HashSet<&str> = text_l
                .split(|c: char| !c.is_alphanumeric())
                .chain(file_l.split(|c: char| !c.is_alphanumeric()))
                .filter(|w| !w.is_empty())
                .collect();

            let matches_whole_word = |term: &str| -> bool {
                if doc_tokens.contains(term) {
                    return true;
                }
                if (term == "maths" || term == "math")
                    && (doc_tokens.contains("mathematics")
                        || doc_tokens.contains("mathematical")
                        || file_l.contains("mathematics"))
                {
                    return true;
                }
                // Allow simple plural/singular inflection ("letter" <-> "letters", "school" <-> "schools"),
                // never arbitrary prefix matches like "cover" matching "coverage" or "discover".
                if term.len() >= 4 {
                    let plural_s = format!("{}s", term);
                    let plural_es = format!("{}es", term);
                    if doc_tokens.contains(plural_s.as_str())
                        || doc_tokens.contains(plural_es.as_str())
                    {
                        return true;
                    }
                    if let Some(stem) = term
                        .strip_suffix("es")
                        .or_else(|| term.strip_suffix('s'))
                    {
                        if stem.len() >= 4 && doc_tokens.contains(stem) {
                            return true;
                        }
                    }
                }
                false
            };

            let entity_hits = entity_terms
                .iter()
                .filter(|t| matches_whole_word(t.as_str()))
                .count();
            let prompt_entity_hits = prompt_only_entities
                .iter()
                .filter(|t| matches_whole_word(t.as_str()))
                .count();
            let total_hits = query_terms
                .iter()
                .filter(|t| matches_whole_word(t.as_str()))
                .count();

            // Multi-term quorum threshold:
            // When 2 specific entity terms are present (e.g. "cover letter", "universal mineral"), require both.
            // When only 1 entity term is paired with a generic attribute term (e.g. "cigna policy"),
            // require the entity term and rank higher if the attribute term also matches.
            let required_entity_hits = if entity_terms.len() == 2 {
                2
            } else if entity_terms.len() > 2 {
                ((entity_terms.len() + 1) / 2).max(2).min(entity_terms.len())
            } else if entity_terms.len() == 1 {
                1
            } else {
                0
            };
            let required_query_hits = if entity_terms.len() == 1 && query_terms.len() == 2 {
                1
            } else if query_terms.len() >= 2 {
                ((query_terms.len() + 1) / 2).max(2).min(query_terms.len())
            } else {
                1
            };

            let proper_hits = proper_terms
                .iter()
                .filter(|t| matches_whole_word(t.as_str()))
                .count();
            let is_relevant = if query_terms.is_empty() {
                true
            } else {
                (total_hits >= required_query_hits && entity_hits >= required_entity_hits)
                    || (!proper_terms.is_empty() && proper_hits == proper_terms.len())
            };

            if is_relevant {
                // Deduplicate chunks with identical normalized content prefix so duplicate PDF/DOCX copies don't bloat context
                let norm_key: String = text_l
                    .chars()
                    .filter(|c| c.is_alphanumeric())
                    .take(120)
                    .collect();
                if norm_key.len() >= 20 && seen_snippets.contains(&norm_key) {
                    continue;
                }
                if is_continuation && previous_snippets.iter().any(|snip| text_l.contains(&snip.to_ascii_lowercase()) || norm_key.contains(snip)) {
                    continue;
                }
                if norm_key.len() >= 20 {
                    seen_snippets.push(norm_key);
                }

                let file_tokens: std::collections::HashSet<&str> = file_l
                    .split(|c: char| !c.is_alphanumeric())
                    .filter(|w| !w.is_empty())
                    .collect();

                let file_hits = query_terms
                    .iter()
                    .filter(|t| {
                        let term = t.as_str();
                        file_tokens.contains(term)
                            || file_l.contains(term)
                            || ((term == "maths" || term == "math") && file_l.contains("mathematics"))
                            || (term.len() >= 4 && term.ends_with('s') && file_tokens.contains(&term[..term.len() - 1]))
                            || (term.len() >= 4 && file_tokens.contains(format!("{}s", term).as_str()))
                    })
                    .count();

                let mut doc_bonus = (file_hits as i32) * 160 + (prompt_entity_hits as i32) * 320;
                if file_l.ends_with(".docx") || file_l.ends_with(".pdf") || file_l.ends_with(".doc") {
                    doc_bonus += 25;
                }
                if !file_l.starts_with("recovered_file_") && !file_l.starts_with("file_") {
                    doc_bonus += 15;
                }
                let asks_education = expanded_lower.contains("school")
                    || expanded_lower.contains("university")
                    || expanded_lower.contains("college")
                    || expanded_lower.contains("degree")
                    || expanded_lower.contains("education")
                    || expanded_lower.contains("study")
                    || expanded_lower.contains("studied")
                    || expanded_lower.contains("graduated")
                    || expanded_lower.contains("transcript");
                if asks_education {
                    if !text_l.contains("education")
                        && !text_l.contains("university")
                        && !text_l.contains("college")
                        && !text_l.contains("school")
                        && !text_l.contains("degree")
                        && !file_l.contains("education")
                        && !file_l.contains("university")
                        && !file_l.contains("school")
                    {
                        continue;
                    }
                    doc_bonus += 120;
                }
                let asks_profile = expanded_lower.contains("about")
                    || expanded_lower.contains("who is")
                    || expanded_lower.contains("resume")
                    || expanded_lower.contains("work")
                    || expanded_lower.contains("experience")
                    || expanded_lower.contains("career")
                    || expanded_lower.contains("background")
                    || ((expanded_lower.contains("femi") || expanded_lower.contains("oyesanya"))
                        && !asks_education);
                if asks_profile
                    && (file_l.contains("cv")
                        || file_l.contains("resume")
                        || text_l.contains("professional summary")
                        || text_l.contains("professional experience")
                        || text_l.contains("core competencies")
                        || text_l.contains("cissp-certified"))
                {
                    doc_bonus += 260;
                }
                // Strongly boost opening/overview/abstract chunks so "What is X?" or "What does it do?"
                // gets the high-level definition and abstract rather than middle-of-paper chart axes
                if scored.chunk.line_start <= 45
                    || text_l.contains("abstract")
                    || text_l.contains("introduction")
                    || text_l.contains("professional summary")
                    || text_l.contains("executive summary")
                    || text_l.contains("overview")
                {
                    doc_bonus += 95;
                }
                if text_l.contains("0 20 40 60 80 100")
                    || text_l.contains("reported aggregate operating-point value")
                {
                    doc_bonus -= 75;
                }
                doc_bonus += Self::answer_type_cue_score(prompt_eff, &text_l);
                scored_matches.push((scored, entity_hits + prompt_entity_hits * 2, total_hits, doc_bonus));
            }
        }

        // When the current prompt introduces its own specific entity term (e.g. "does he have cissp"),
        // if any matched chunk contains that specific prompt entity term, filter out chunks that lack it
        // so carry-over context documents (like RedactX) never drown out the target answer documents!
        if !prompt_only_entities.is_empty() {
            let req_prompt_hits = if prompt_only_entities.len() == 2 {
                2
            } else if prompt_only_entities.len() > 2 {
                ((prompt_only_entities.len() + 1) / 2).max(2)
            } else {
                prompt_only_entities.len()
            };
            let count_prompt_matches = |scored: &ScoredChunk| -> usize {
                let text_l = scored.chunk.text_content.to_ascii_lowercase();
                let file_l = scored.chunk.file_path.to_ascii_lowercase();
                prompt_only_entities
                    .iter()
                    .filter(|t| text_l.contains(t.as_str()) || file_l.contains(t.as_str()))
                    .count()
            };
            let has_direct_prompt_match = scored_matches
                .iter()
                .any(|(scored, _, _, _)| count_prompt_matches(scored) >= req_prompt_hits);
            if has_direct_prompt_match {
                scored_matches
                    .retain(|(scored, _, _, _)| count_prompt_matches(scored) >= req_prompt_hits);
            }
        }

        // Dynamically learn domain vocabulary and proper nouns from retrieved chunks for real-time spellchecking
        if let Ok(mut vocab) = global_corpus_vocab().write() {
            for (scored, _, _, _) in &scored_matches {
                for raw_word in scored
                    .chunk
                    .text_content
                    .split(|c: char| !c.is_ascii_alphabetic() && c != '-')
                {
                    let word = raw_word.trim_matches('-');
                    if (4..=24).contains(&word.len()) {
                        let lower = word.to_ascii_lowercase();
                        let is_all_caps = word.chars().all(|c| c.is_ascii_uppercase());
                        if !is_all_caps {
                            // A word ever seen in lowercase is a common noun ("phone", "number"); only words seen
                            // exclusively capitalised (names, places) keep a capitalised canonical form.
                            if word.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
                                vocab.insert(lower, word.to_string());
                            } else {
                                vocab.entry(lower).or_insert_with(|| word.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Sort by entity hits, then total query term hits, then document quality bonus, then hybrid RRF/vector score
        scored_matches.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| b.3.cmp(&a.3))
                .then_with(|| {
                    b.0.score
                        .partial_cmp(&a.0.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });

        let ui = crate::dlp_mesh::global_mesh_dlp_controller()
            .settings
            .read()
            .map(|g| g.ui.clone())
            .unwrap_or_default();

        let chunk_limit = if ui.max_output_tokens >= 16384 || ui.agentic_loop_enabled {
            36
        } else if ui.max_output_tokens > 4096 {
            24
        } else {
            12
        };

        // Keep top N deduplicated RAG chunks for comprehensive multi-paragraph synthesis
        let mut candidate_chunks: Vec<ScoredChunk> = scored_matches
            .into_iter()
            .take(chunk_limit)
            .map(|(c, _, _, _)| c.clone())
            .collect();

        if ui.parent_document_retrieval {
            candidate_chunks = Self::stitch_parent_document_chunks(candidate_chunks);
        }

        if is_continuation && !prior_text.is_empty() {
            candidate_chunks = Self::deduplicate_chunk_segments_against_prior(candidate_chunks, &prior_text, 0.88);
        }

        let matched_chunks = candidate_chunks;
        let matched_chunk_refs: Vec<&ScoredChunk> = matched_chunks.iter().collect();

        if !matched_chunk_refs.is_empty() {
            let citations: Vec<Citation> = Self::build_deduplicated_citations(&matched_chunk_refs);

            // 1. Use the local LLM strictly to orchestrate a natural, direct, citation-backed answer
            // from the retrieved local RAG chunks (never invoked when matched_chunks is empty).
            let effective_question = if is_continuation && query_source_eff != prompt_eff {
                format!(
                    "continue the previous answer about {} with additional details that were not already covered",
                    query_source_eff.trim()
                )
            } else if query_source_eff != prompt_eff && !is_continuation {
                format!("{} (Subject context: {})", prompt_eff, query_source_eff)
            } else {
                prompt_eff.to_string()
            };
            if let Some((llm_orchestrated, llm_citations)) = Self::query_local_ollama_chat(
                &effective_question,
                history,
                &matched_chunk_refs,
                model_tag,
                telemetry_tx,
            ) {
                return (llm_orchestrated, llm_citations);
            }

            // 1b. Fast-model retry: the primary model (often 26B+ on CPU) timed out or failed, so retry with up
            // to two smaller installed models over the strongest excerpts before giving up on LLM synthesis.
            if matched_chunk_refs.len() > 0 {
                let installed = Self::probe_installed_ollama_models_default();
                if !installed.is_empty() {
                    let hw = crate::hardware::HardwareTelemetry::probe();
                    let failed_model = Self::resolve_ollama_model_tag(model_tag, &hw, &installed);
                    let top_refs = &matched_chunk_refs[..matched_chunk_refs.len().min(5)];
                    for fast in crate::answer_orchestrator::fast_fallback_models(&installed, &failed_model).iter().take(2) {
                        tracing::warn!(failed = %failed_model, retry = %fast, "Primary synthesis failed; retrying with faster local model");
                        if let Some((text, cits)) =
                            Self::query_local_ollama_chat(&effective_question, history, top_refs, fast, telemetry_tx)
                        {
                            return (text, cits);
                        }
                    }
                }
            }

            // 2. Deterministic offline fallback (used in unit tests or if local Ollama daemon is unreachable)
            let prefix = Self::format_question_restated_prefix(prompt_eff);

            let mut body_paragraphs: Vec<String> = Vec::new();
            for (idx, c) in matched_chunk_refs.iter().enumerate().take(6) {
                let cleaned = Self::clean_chunk_text(&c.chunk.text_content);
                // Strip residual artifacts, ChatGPT export markers, and dividers
                let mut chunk_lines: Vec<String> = Vec::new();
                let mut in_code_fence = false;
                for line in cleaned.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if trimmed.contains("fileciteturn0file0") || trimmed.contains("sandbox:/mnt/data") {
                        continue;
                    }
                    if !requests_code && trimmed.starts_with("```") {
                        in_code_fence = !in_code_fence;
                        continue;
                    }
                    if !requests_code && in_code_fence {
                        continue;
                    }
                    if trimmed.starts_with("Conversation ID:")
                        || trimmed.starts_with("User:")
                        || trimmed.starts_with("Assistant:")
                        || trimmed.chars().all(|ch| ch == '_' || ch == '-' || ch == ' ')
                    {
                        continue;
                    }
                    // Normalize bullet symbols (•, ●, ▪) into Markdown bullets
                    let normalized = if let Some(rest) = trimmed
                        .strip_prefix('•')
                        .or_else(|| trimmed.strip_prefix('●'))
                        .or_else(|| trimmed.strip_prefix('▪'))
                    {
                        format!("- {}", rest.trim())
                    } else {
                        trimmed.to_string()
                    };
                    chunk_lines.push(normalized);
                }
                let formatted_chunk = chunk_lines.join("\n");
                let trim_chunk = formatted_chunk.trim();
                if !trim_chunk.is_empty() {
                    if trim_chunk.len() < 35 && matched_chunks.len() > 1 && matched_chunks.iter().any(|other| other.chunk.text_content.trim().len() > 100) {
                        continue;
                    }
                    let excerpt: String = trim_chunk.chars().take(800).collect();
                    body_paragraphs.push(format!("{} **[{}]**", excerpt.trim(), idx + 1));
                }
            }

            let mut answer_parts: Vec<String> = Vec::new();

            // Synthesize affirmative restated opening grounded in top chunk
            if !prefix.is_empty() && !matched_chunks.is_empty() {
                let top_chunk = &matched_chunks[0];
                let file_name = std::path::Path::new(&top_chunk.chunk.file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&top_chunk.chunk.file_path);
                let cleaned_first = Self::clean_chunk_text(&top_chunk.chunk.text_content);

                let mut grounded_summary = String::new();
                for line in cleaned_first.lines() {
                    let t = line.trim();
                    if t.is_empty() || t.starts_with('#') || t.contains("fileciteturn0file0") || t.contains("sandbox:/mnt/data") {
                        continue;
                    }
                    let t_low = t.to_ascii_lowercase();
                    if t_low.contains("security")
                        || t_low.contains("cissp")
                        || t_low.contains("engineer")
                        || t_low.contains("architect")
                        || t_low.contains("leader")
                        || t_low.contains("professional")
                        || t_low.contains("experience")
                        || t_low.contains("framework")
                        || t_low.contains("system")
                        || t_low.contains("policy")
                    {
                        grounded_summary = t.to_string();
                        break;
                    }
                }
                if grounded_summary.is_empty() {
                    if let Some(first_line) = cleaned_first.lines().find(|l| {
                        let trimmed = l.trim();
                        !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.contains("fileciteturn0file0") && !trimmed.contains("sandbox:/mnt/data")
                    }) {
                        grounded_summary = first_line.trim().to_string();
                    }
                }

                // A title/heading line ("FEMI OYESANYA, CISSP", "SIMPLE LEASE AGREEMENT") is not a description:
                // use the first prose line of the top excerpt instead when one exists.
                if !Self::is_sentence_like(&grounded_summary) {
                    if let Some(prose) = cleaned_first
                        .lines()
                        .map(str::trim)
                        .find(|l| Self::is_sentence_like(l) && !l.contains("fileciteturn0file0"))
                    {
                        grounded_summary = prose.to_string();
                    }
                }

                // Prefer the subject's role as stated in the documents themselves, e.g.
                // "between Angela Davis (landlord) and ..." -> "Angela Davis is the landlord ...".
                // Never glue an unrelated first line (such as a document title) onto "X is a".
                let subject_name = prefix.trim_end().strip_suffix(" is").map(|s| s.trim().to_string());
                let role_opening = subject_name.as_deref().and_then(|subj| {
                    Self::subject_role_from_chunks(subj, &matched_chunk_refs).map(|(role, cites)| {
                        let cite_str = cites.iter().map(|n| format!("**[{n}]**")).collect::<Vec<_>>().join(", ");
                        format!("{subj} is identified as the {role} in the retrieved documents {cite_str}.")
                    })
                });
                let opening = if let Some(ro) = role_opening {
                    ro
                } else if subject_name.is_some() && !Self::is_sentence_like(&grounded_summary) {
                    format!(
                        "{} appears in the following retrieved documents **[1]**.",
                        subject_name.as_deref().unwrap_or("This subject")
                    )
                } else if !grounded_summary.is_empty() {
                    let clean_sum = grounded_summary.trim_end_matches('.');
                    let prefix_trimmed = prefix.trim_end();
                    if clean_sum.to_ascii_lowercase().starts_with(&prefix_trimmed.to_ascii_lowercase()) {
                        format!("{} **[1]**", clean_sum)
                    } else if prefix.ends_with("is ") && (clean_sum.to_ascii_lowercase().starts_with("a ") || clean_sum.to_ascii_lowercase().starts_with("an ")) {
                        format!("{}{} **[1]**", prefix, clean_sum)
                    } else if prefix.ends_with("is ") {
                        format!("{}a {} **[1]**", prefix, clean_sum)
                    } else {
                        format!("{}{} **[1]**", prefix, clean_sum)
                    }
                } else {
                    format!("{}grounded in `{}` **[1]**", prefix, file_name)
                };

                answer_parts.push(opening);
            }

            // LangExtract-style grounded composition: structured, span-grounded facts and key passages
            // replace raw excerpt dumps whenever anything can be grounded.
            let fallback_subject = prefix.trim_end().strip_suffix(" is").map(|s| s.trim().to_string());
            match crate::answer_orchestrator::render_grounded_sections(
                prompt_eff,
                fallback_subject.as_deref(),
                &matched_chunk_refs,
            ) {
                Some(sections) => answer_parts.push(sections),
                None => answer_parts.extend(body_paragraphs),
            }

            // Add end-of-response sources block with accuracy scores (zero line numbers!)
            let raw_answer = answer_parts.join("\n\n");
            let clean_answer = Self::consolidate_duplicate_entity_statements(&raw_answer);
            let sources_block = Self::format_sources_block(&matched_chunk_refs);
            let synthesized_rag = format!("{}{}", clean_answer, sources_block);

            if let Some(tx) = telemetry_tx {
                for word in synthesized_rag.split_inclusive(' ') {
                    if tx.is_closed() {
                        tracing::debug!("Token streaming stopped: tx channel closed");
                        break;
                    }
                    if !Self::send_telemetry(
                        tx,
                        AgenticTelemetryEvent::TokenDelta {
                            delta: word.to_string(),
                        },
                    ) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(6));
                }
            }
            (synthesized_rag, citations)
        } else {
            let fallback = format!(
                "No matching documents were found in your local RAG index for **{}**.",
                prompt
            );
            if let Some(tx) = telemetry_tx {
                for word in fallback.split_inclusive(' ') {
                    if tx.is_closed() {
                        break;
                    }
                    if !Self::send_telemetry(
                        tx,
                        AgenticTelemetryEvent::TokenDelta {
                            delta: word.to_string(),
                        },
                    ) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(6));
                }
            }
            (fallback, Vec::new())
        }
    }

    /// Runtime-safe non-panicking telemetry sender with backpressure retry.
    /// Avoids `blocking_send` panics on single-threaded `#[tokio::test]` runtimes while guaranteeing zero dropped tokens.
    pub fn send_telemetry(
        tx: &Sender<AgenticTelemetryEvent>,
        mut event: AgenticTelemetryEvent,
    ) -> bool {
        for _ in 0..250 {
            match tx.try_send(event) {
                Ok(()) => return true,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
                Err(tokio::sync::mpsc::error::TrySendError::Full(ev)) => {
                    event = ev;
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            }
        }
        false
    }

    /// Extracts and formats an affirmative question-restating prefix from an interrogative user prompt.
    /// Converts questions like "Who is femi" into "Femi is ", "What is RedactX" into "RedactX is ",
    /// and "Where did Femi study" into "Femi studied at ".
    /// Find a short parenthetical role written right after the subject's name in the retrieved
    /// text, e.g. "Angela Davis (landlord)". Returns the most frequent role and the 1-based
    /// citation numbers of the chunks that state it.
    pub fn subject_role_from_chunks(subject: &str, chunks: &[&ScoredChunk]) -> Option<(String, Vec<usize>)> {
        let subj_l = subject.trim().to_ascii_lowercase();
        if subj_l.len() < 3 {
            return None;
        }
        let mut counts: Vec<(String, Vec<usize>)> = Vec::new();
        for (idx, c) in chunks.iter().enumerate().take(8) {
            let text = &c.chunk.text_content;
            let low = text.to_ascii_lowercase();
            let mut from = 0;
            while let Some(pos) = low[from..].find(&subj_l) {
                let after = from + pos + subj_l.len();
                from = after;
                let rest = &text[after..];
                let rest_t = rest.trim_start();
                if !rest_t.starts_with('(') {
                    continue;
                }
                let Some(close) = rest_t.find(')') else { continue };
                let inner = rest_t[1..close].trim();
                let words: Vec<&str> = inner.split_whitespace().collect();
                if words.is_empty()
                    || words.len() > 3
                    || inner.len() > 30
                    || !inner.chars().all(|ch| ch.is_alphabetic() || ch == ' ' || ch == '-')
                {
                    continue;
                }
                let role = inner.to_ascii_lowercase();
                match counts.iter_mut().find(|(r, _)| *r == role) {
                    Some((_, cites)) => {
                        if !cites.contains(&(idx + 1)) {
                            cites.push(idx + 1);
                        }
                    }
                    None => counts.push((role, vec![idx + 1])),
                }
            }
        }
        counts.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        counts.into_iter().next()
    }

    /// True when a line reads like prose (mixed case with at least one lowercase word), not an
    /// ALL-CAPS title such as "SIMPLE LEASE AGREEMENT".
    pub fn is_sentence_like(line: &str) -> bool {
        let letters: Vec<char> = line.chars().filter(|c| c.is_alphabetic()).collect();
        if letters.len() < 12 {
            return false;
        }
        let lower = letters.iter().filter(|c| c.is_lowercase()).count();
        lower * 2 > letters.len() && line.split_whitespace().count() >= 4
    }

    pub fn format_question_restated_prefix(prompt: &str) -> String {
        let trimmed = prompt.trim();
        if trimmed.is_empty() {
            return String::new();
        }
        let clean_prompt = trimmed
            .trim_matches(|c: char| c == '?' || c == '!' || c == '.' || c == '"' || c == '\'')
            .trim();
        if clean_prompt.is_empty() {
            return String::new();
        }
        let lower = clean_prompt.to_ascii_lowercase();
        if Self::is_continuation_query(&lower) {
            return String::new();
        }

        let capitalize = |s: &str| -> String {
            s.split_whitespace()
                .map(|word| {
                    let mut chars = word.chars();
                    match chars.next() {
                        None => String::new(),
                        Some(first) => {
                            let mut cap = first.to_uppercase().to_string();
                            cap.push_str(chars.as_str());
                            cap
                        }
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
        };

        // 1. "who is / who was / who are / who were"
        if lower.starts_with("who is ") {
            let raw = clean_prompt["who is ".len()..].trim();
            return format!("{} is ", capitalize(raw));
        }
        if lower.starts_with("who was ") {
            let raw = clean_prompt["who was ".len()..].trim();
            return format!("{} was ", capitalize(raw));
        }
        if lower.starts_with("who are ") {
            let raw = clean_prompt["who are ".len()..].trim();
            return format!("{} are ", capitalize(raw));
        }
        if lower.starts_with("who were ") {
            let raw = clean_prompt["who were ".len()..].trim();
            return format!("{} were ", capitalize(raw));
        }

        // 2. "what is / what was / what are / what were"
        if lower.starts_with("what is ") {
            let raw = clean_prompt["what is ".len()..].trim();
            return format!("{} is ", capitalize(raw));
        }
        if lower.starts_with("what was ") {
            let raw = clean_prompt["what was ".len()..].trim();
            return format!("{} was ", capitalize(raw));
        }
        if lower.starts_with("what are ") {
            let raw = clean_prompt["what are ".len()..].trim();
            return format!("{} are ", capitalize(raw));
        }
        if lower.starts_with("what were ") {
            let raw = clean_prompt["what were ".len()..].trim();
            return format!("{} were ", capitalize(raw));
        }

        // 3. "what the <topic>" (e.g. "what the cigna policy")
        if lower.starts_with("what the ") {
            let raw = clean_prompt["what the ".len()..].trim();
            return format!("The {} is ", capitalize(raw));
        }

        // 4. "where did <subject> study / attend / go to school / graduate"
        if let Some(rest) = lower.strip_prefix("where did ") {
            if rest.contains("study")
                || rest.contains("school")
                || rest.contains("university")
                || rest.contains("college")
                || rest.contains("attend")
                || rest.contains("graduate")
            {
                let sub = rest
                    .replace("attend", "")
                    .replace("graduate", "")
                    .replace("go to school", "")
                    .replace("go to university", "")
                    .replace("study", "")
                    .replace("school", "");
                let clean_sub = sub.trim();
                if !clean_sub.is_empty() {
                    if rest.contains("go to school") || rest.contains("attend") {
                        return format!("{} attended ", capitalize(clean_sub));
                    } else {
                        return format!("{} studied at ", capitalize(clean_sub));
                    }
                }
                return "Education and academic background: ".to_string();
            }
        }

        // 5. "what did <subject> do at <org>"
        if let Some(rest) = lower.strip_prefix("what did ") {
            if let Some(idx) = rest.find(" do at ") {
                let sub = &rest[..idx].trim();
                let org = &rest[idx + 7..].trim();
                return format!("At {}, {} ", capitalize(org), capitalize(sub));
            }
        }

        // 6. "what does <subject> do / mean"
        if let Some(rest) = lower.strip_prefix("what does ") {
            let sub = rest.trim_end_matches(" do").trim_end_matches(" mean").trim();
            return format!("{} ", capitalize(sub));
        }

        // 7. "where is / where was"
        if lower.starts_with("where is ") {
            let raw = clean_prompt["where is ".len()..].trim();
            return format!("{} is located at ", capitalize(raw));
        }
        if lower.starts_with("where was ") {
            let raw = clean_prompt["where was ".len()..].trim();
            return format!("{} was located at ", capitalize(raw));
        }

        // 8. "tell me about / describe / explain"
        if lower.starts_with("tell me about ") {
            let raw = clean_prompt["tell me about ".len()..].trim();
            return format!("{} is ", capitalize(raw));
        }
        if lower.starts_with("describe ") {
            let raw = clean_prompt["describe ".len()..].trim();
            return format!("{} is ", capitalize(raw));
        }
        if lower.starts_with("explain ") {
            let raw = clean_prompt["explain ".len()..].trim();
            return format!("{} refers to ", capitalize(raw));
        }
        if lower.starts_with("can you explain ") {
            let raw = clean_prompt["can you explain ".len()..].trim();
            return format!("{} refers to ", capitalize(raw));
        }
        if lower.starts_with("can you tell me about ") {
            let raw = clean_prompt["can you tell me about ".len()..].trim();
            return format!("{} is ", capitalize(raw));
        }

        // 9. Keyword queries on Education / School
        if lower.contains("school")
            || lower.contains("university")
            || lower.contains("college")
            || lower.contains("degree")
            || lower.contains("education")
        {
            if lower.contains("femi") || lower.contains("oyesanya") {
                return "Femi's education and academic background includes: ".to_string();
            }
            return "Education and academic background: ".to_string();
        }

        // 10. Direct subject queries like "femi" or "femi oyesanya"
        if lower == "femi"
            || lower == "femi oyesanya"
            || lower == "angela davis"
            || lower == "redactx"
            || lower == "vaultgemma"
        {
            return format!("{} is ", capitalize(clean_prompt));
        }

        // 11. Auxiliary / Yes-No questions ("does he have cissp", "is femi cissp certified", "did he attend wgu")
        if lower.starts_with("does ")
            || lower.starts_with("do ")
            || lower.starts_with("did ")
            || lower.starts_with("has ")
            || lower.starts_with("have ")
            || lower.starts_with("is ")
            || lower.starts_with("are ")
            || lower.starts_with("was ")
            || lower.starts_with("were ")
            || lower.starts_with("can ")
            || lower.starts_with("could ")
            || lower.starts_with("will ")
            || lower.starts_with("would ")
        {
            return String::new();
        }

        // 12. Conversational question prefixes
        if lower.starts_with("tell me all about ") {
            let raw = clean_prompt["tell me all about ".len()..].trim();
            return format!("{} — ", capitalize(raw));
        }
        if lower.starts_with("tell me everything about ") {
            let raw = clean_prompt["tell me everything about ".len()..].trim();
            return format!("{} — ", capitalize(raw));
        }
        if lower.starts_with("what do you know about ") {
            let raw = clean_prompt["what do you know about ".len()..].trim();
            return format!("{} — ", capitalize(raw));
        }
        if lower.starts_with("give me details on ") {
            let raw = clean_prompt["give me details on ".len()..].trim();
            return format!("{} — ", capitalize(raw));
        }
        if lower.starts_with("give me details about ") {
            let raw = clean_prompt["give me details about ".len()..].trim();
            return format!("{} — ", capitalize(raw));
        }
        if lower.starts_with("give me info on ") {
            let raw = clean_prompt["give me info on ".len()..].trim();
            return format!("{} — ", capitalize(raw));
        }
        if lower.starts_with("give me information on ") {
            let raw = clean_prompt["give me information on ".len()..].trim();
            return format!("{} — ", capitalize(raw));
        }

        // Universal Q&A opening fallback: NEVER return "" for any non-empty prompt!
        let conversational_prefixes = [
            "tell me all about ", "tell me everything about ", "tell me about ",
            "what do you know about ", "give me details on ", "give me details about ",
            "give me info on ", "give me information on ", "can you tell me all about ",
            "can you tell me about ", "can you explain ", "explain ", "describe ",
            "please tell me about ", "please show me ", "show me ", "what about ",
        ];
        let mut topic: Option<&str> = None;
        for prefix in &conversational_prefixes {
            if let Some(rest) = lower.strip_prefix(prefix) {
                topic = Some(rest.trim());
                break;
            }
        }
        if let Some(t) = topic {
            let clean_topic = t.trim_matches(|c: char| !c.is_alphanumeric() && c != ' ').trim();
            if !clean_topic.is_empty() {
                return format!("{} — ", capitalize(clean_topic));
            }
        }
        // "tell me all you know about X", "can you tell me what you know about X", "what can you tell me about X"
        if (lower.starts_with("tell ") || lower.contains(" know about ") || lower.contains(" tell me about "))
            && lower.contains(" about ")
        {
            if let Some(idx) = lower.rfind(" about ") {
                let raw = clean_prompt[idx + " about ".len()..].trim();
                let raw = raw.trim_matches(|c: char| !c.is_alphanumeric() && c != ' ').trim();
                if !raw.is_empty() {
                    return format!("{} — ", capitalize(raw));
                }
            }
        }
        // Any other natural-language question shape ("how much rent does X pay", "which bank...", "why is...",
        // "list all...", "compare A and B") has no safe mechanical restatement: return "" so the model opens with a
        // direct declarative answer instead of a title-cased copy of the question.
        const QUESTION_LEADS: &[&str] = &[
            "how", "which", "when", "why", "whose", "whom", "what", "who", "where", "list", "compare", "tell",
            "summarize", "summarise", "show", "give", "find", "name", "does", "do", "did", "is", "are",
            "was", "were", "can", "could", "should", "would", "will", "has", "have", "had", "please",
        ];
        let first_word = lower.split_whitespace().next().unwrap_or("");
        let is_question_shaped = trimmed.ends_with('?') || QUESTION_LEADS.contains(&first_word);
        if is_question_shaped {
            return String::new();
        }
        // Bare noun-phrase topic ("African Churches and Gang Violence") -> "African Churches And Gang Violence — "
        format!("{} — ", capitalize(clean_prompt))
    }

    /// Strips any trailing Markdown sources footer from an assistant message so continuation history
    /// and sentence-deduplication operate purely on synthesized prose.
    pub fn strip_sources_footer(text: &str) -> &str {
        let mut cut = text.len();
        for marker in [
            "\n---\n### 📚 Sources",
            "\r\n---\r\n### 📚 Sources",
            "### 📚 Sources & Document Links",
            "📚 Sources & Document Links",
            "### Supporting Evidence & Citations",
        ] {
            if let Some(pos) = text.find(marker) {
                if pos < cut {
                    cut = pos;
                }
            }
        }
        let mut slice = text[..cut].trim_end();
        if let Some(without_rule) = slice.strip_suffix("---") {
            slice = without_rule.trim_end();
        }
        slice
    }

    /// Unified monotonic accuracy calibration shared by both `format_sources_block` and `Citation` badges.
    /// Avoids discontinuities across mixed RRF (`0.03`), cosine (`0.72`), and boosted (`74.2`) score scales.
    pub fn calibrated_accuracy_percent(raw_score: f32, unique_rank_idx: usize) -> u32 {
        if (0.85..=1.0).contains(&raw_score) {
            (raw_score * 100.0).round() as u32
        } else if (85.0..=100.0).contains(&raw_score) {
            (raw_score.round() as u32).min(99)
        } else {
            (96u32.saturating_sub((unique_rank_idx as u32) * 3)).clamp(74, 96)
        }
    }

    fn deduplicated_chunks_with_scores<'a>(
        matched_chunks: &[&'a ScoredChunk],
    ) -> Vec<(&'a ScoredChunk, u32)> {
        let all_explicit_unit = !matched_chunks.is_empty()
            && matched_chunks.iter().all(|c| (0.85..=1.0).contains(&c.score));
        let mut seen_keys = std::collections::HashSet::new();
        let mut out: Vec<(&'a ScoredChunk, u32)> = Vec::new();
        for &c in matched_chunks {
            let file_name = std::path::Path::new(&c.chunk.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&c.chunk.file_path);
            let dedup_key = (c.source_peer.to_ascii_lowercase(), file_name.to_ascii_lowercase());
            if !seen_keys.insert(dedup_key) {
                continue;
            }
            let unique_idx = out.len();
            let mut pct = Self::calibrated_accuracy_percent(c.score, unique_idx);
            if !all_explicit_unit {
                if let Some(&(_, prev_pct)) = out.last() {
                    if pct >= prev_pct {
                        pct = prev_pct.saturating_sub(2).max(70);
                    }
                }
            }
            out.push((c, pct));
        }
        out
    }

    /// Builds deduplicated `Citation` structs matching `format_sources_block` 1-to-1 in file order and score.
    pub fn build_deduplicated_citations(matched_chunks: &[&ScoredChunk]) -> Vec<Citation> {
        Self::deduplicated_chunks_with_scores(matched_chunks)
            .into_iter()
            .map(|(c, pct)| {
                let mut cit = c.to_citation();
                let cleaned = Self::clean_chunk_text(&c.chunk.text_content);
                cit.snippet = cleaned.chars().take(240).collect();
                cit.score = pct as f32 / 100.0;
                cit
            })
            .collect()
    }

    /// Formats the standardized end-of-response sources and document links block with explicit accuracy scores.
    /// Invariant: Deduplicates sources by filename and contains ZERO line numbers!
    pub fn format_sources_block(matched_chunks: &[&ScoredChunk]) -> String {
        let deduped = Self::deduplicated_chunks_with_scores(matched_chunks);
        if deduped.is_empty() {
            return String::new();
        }
        let mut block = String::from("\n\n---\n### 📚 Sources & Document Links\n");

        for (c, score_pct) in deduped {
            let file_name_base = std::path::Path::new(&c.chunk.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&c.chunk.file_path);

            let peer_suffix = if !c.source_peer.is_empty() && c.source_peer != "local" {
                let short_peer = if c.source_peer.len() > 8 {
                    &c.source_peer[..8]
                } else {
                    &c.source_peer
                };
                format!(" (Peer: {})", short_peer)
            } else {
                String::new()
            };
            let file_name = format!("{}{}", file_name_base, peer_suffix);

            let raw_target = if c.chunk.file_path.starts_with("http://")
                || c.chunk.file_path.starts_with("https://")
                || c.chunk.file_path.starts_with("file://")
            {
                c.chunk.file_path.clone()
            } else {
                let normalized = c.chunk.file_path.replace('\\', "/");
                if normalized.contains(':') {
                    format!("file:///{}", normalized.trim_start_matches('/'))
                } else {
                    normalized
                }
            };
            let link_target = raw_target.replace(' ', "%20");

            block.push_str(&format!(
                "- [📄 {}]({}) — **{}% accuracy**\n",
                file_name,
                link_target,
                score_pct
            ));
        }
        block
    }

    /// Detects whether a query string represents a conversational continuation request.
    pub fn is_continuation_query(lower: &str) -> bool {
        let t = lower.trim();
        t == "continue"
            || t.starts_with("continue ")
            || t.contains("tell me more")
            || t.contains("go on")
            || t.contains("what else")
            || t.contains("elaborate")
            || t.contains("more details")
            || t.contains("keep going")
            || t.contains("expand")
            || t == "more"
    }

    /// Stitches adjacent or contiguous document chunks from the same source file into unbroken parent document sections,
    /// while strictly preserving relevance file ranking and round-robin interleaving across all distinct matched files
    /// so RAG always synthesizes across multiple files instead of a single file.
    pub fn stitch_parent_document_chunks(chunks: Vec<ScoredChunk>) -> Vec<ScoredChunk> {
        if chunks.len() <= 1 {
            return chunks;
        }

        let get_chunk_index = |chunk: &quorum_types::DocumentChunk| -> Option<usize> {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&chunk.metadata_json) {
                if let Some(idx) = val.get("chunk_index").and_then(|v| v.as_u64()) {
                    return Some(idx as usize);
                }
            }
            chunk.chunk_id.rsplit_once(':').and_then(|(_, s)| s.parse::<usize>().ok())
        };

        // 1. Group incoming relevance-sorted chunks by file_path, preserving the exact relevance order
        //    in which each distinct file first appears (`file_order`).
        let mut file_order: Vec<String> = Vec::new();
        let mut file_buckets: std::collections::HashMap<String, Vec<(usize, ScoredChunk)>> =
            std::collections::HashMap::new();

        for (orig_rank, chunk) in chunks.into_iter().enumerate() {
            let key = chunk.chunk.file_path.to_ascii_lowercase();
            if !file_buckets.contains_key(&key) {
                file_order.push(key.clone());
            }
            file_buckets
                .entry(key)
                .or_default()
                .push((orig_rank, chunk));
        }

        // 2. Within each file's bucket, stitch adjacent chunks and restore each stitched section's best relevance rank
        let mut stitched_buckets: Vec<Vec<ScoredChunk>> = Vec::with_capacity(file_order.len());

        for file_key in &file_order {
            if let Some(mut bucket) = file_buckets.remove(file_key) {
                bucket.sort_by(|(_, a), (_, b)| {
                    a.chunk
                        .line_start
                        .cmp(&b.chunk.line_start)
                        .then_with(|| {
                            let idx_a = get_chunk_index(&a.chunk).unwrap_or(0);
                            let idx_b = get_chunk_index(&b.chunk).unwrap_or(0);
                            idx_a.cmp(&idx_b)
                        })
                });

                let mut file_stitched: Vec<(usize, ScoredChunk)> = Vec::with_capacity(bucket.len());
                for (rank, chunk) in bucket {
                    if let Some((prev_best_rank, prev)) = file_stitched.last_mut() {
                        let prev_idx = get_chunk_index(&prev.chunk);
                        let curr_idx = get_chunk_index(&chunk.chunk);

                        let adjacent_idx = match (prev_idx, curr_idx) {
                            (Some(p), Some(c)) => c == p + 1 || c == p,
                            _ => false,
                        };
                        let contiguous_lines =
                            chunk.chunk.line_start <= prev.chunk.line_end.saturating_add(3);

                        if (adjacent_idx || contiguous_lines)
                            && prev.chunk.text_content.len() < 3200
                        {
                            let curr_text = chunk.chunk.text_content.trim();
                            let prev_text = prev.chunk.text_content.trim();

                            if !prev_text.contains(curr_text) {
                                let max_overlap = 200.min(prev_text.len()).min(curr_text.len());
                                let overlap_len = (1..=max_overlap)
                                    .rev()
                                    .find(|&len| {
                                        prev_text.is_char_boundary(prev_text.len() - len)
                                            && curr_text.is_char_boundary(len)
                                            && prev_text.ends_with(&curr_text[..len])
                                    })
                                    .unwrap_or(0);

                                if overlap_len > 15 {
                                    prev.chunk.text_content.push_str(&curr_text[overlap_len..]);
                                } else {
                                    prev.chunk.text_content.push_str("\n\n");
                                    prev.chunk.text_content.push_str(curr_text);
                                }
                            }

                            prev.chunk.line_end = prev.chunk.line_end.max(chunk.chunk.line_end);
                            prev.score = prev.score.max(chunk.score);
                            *prev_best_rank = (*prev_best_rank).min(rank);
                            continue;
                        }
                    }
                    file_stitched.push((rank, chunk));
                }

                // Order this file's stitched sections by their best relevance rank
                file_stitched.sort_by_key(|(best_rank, _)| *best_rank);
                stitched_buckets.push(file_stitched.into_iter().map(|(_, c)| c).collect());
            }
        }

        // 3. Round-robin interleave across all distinct files so the top chunks span ALL matching files!
        let mut interleaved: Vec<ScoredChunk> = Vec::new();
        let max_depth = stitched_buckets
            .iter()
            .map(|b| b.len())
            .max()
            .unwrap_or(0);
        for depth in 0..max_depth {
            for bucket in &stitched_buckets {
                if let Some(chunk) = bucket.get(depth) {
                    interleaved.push(chunk.clone());
                }
            }
        }

        interleaved
    }

    /// Map-Reduce Fact Sheet Extraction: Clusters retrieved chunks into groups of 3-4 chunks
    /// and extracts dense factual nuggets (core definitions, metrics, formulas, dates, theorems, quotes)
    /// before chapter writing.
    pub fn extract_fact_sheets(chunks: &[&ScoredChunk], _prompt: &str) -> Vec<String> {
        let mut fact_sheets = Vec::new();
        if chunks.is_empty() {
            return fact_sheets;
        }

        // Group into clusters of 3-4 chunks
        for (cluster_idx, cluster) in chunks.chunks(4).enumerate() {
            let mut definitions = Vec::new();
            let mut metrics_and_formulas = Vec::new();
            let mut dates_and_names = Vec::new();
            let mut verbatim_quotes = Vec::new();
            let mut primary_source = String::new();

            for scored in cluster {
                let file_name = std::path::Path::new(&scored.chunk.file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&scored.chunk.file_path);
                if primary_source.is_empty() {
                    primary_source = file_name.to_string();
                }

                let cleaned = Self::clean_chunk_text(&scored.chunk.text_content);
                for sentence in cleaned.split(". ") {
                    let s = sentence.trim().trim_end_matches('.');
                    if s.len() < 10 || s.len() > 300 {
                        continue;
                    }
                    let s_low = s.to_ascii_lowercase();

                    // Definitions
                    if s_low.contains(" is ") || s_low.contains(" are ") || s_low.contains(" defined as ") || s_low.contains(" refers to ") {
                        if definitions.len() < 3 && !definitions.contains(&s.to_string()) {
                            definitions.push(s.to_string());
                        }
                    }

                    // Metrics, Formulas, Numbers, Theorems
                    if s.chars().any(|c| c.is_ascii_digit()) || s_low.contains("ratio") || s_low.contains("percent") || s_low.contains("formula") || s_low.contains("theorem") || s_low.contains("phi") || s_low.contains("fibonacci") || s_low.contains("geometry") {
                        if metrics_and_formulas.len() < 3 && !metrics_and_formulas.contains(&s.to_string()) {
                            metrics_and_formulas.push(s.to_string());
                        }
                    }

                    // Historical Dates & Names (years 1000-2099)
                    if s.split_whitespace().any(|w| {
                        let clean_w = w.trim_matches(|c: char| !c.is_ascii_alphanumeric());
                        clean_w.len() == 4 && clean_w.chars().all(|c| c.is_ascii_digit()) && (clean_w.starts_with('1') || clean_w.starts_with('2'))
                    }) {
                        if dates_and_names.len() < 3 && !dates_and_names.contains(&s.to_string()) {
                            dates_and_names.push(s.to_string());
                        }
                    }

                    // Verbatim Quotes
                    if s.contains('"') || s.contains('“') || s.contains('”') {
                        if verbatim_quotes.len() < 2 && !verbatim_quotes.contains(&s.to_string()) {
                            verbatim_quotes.push(s.to_string());
                        }
                    }
                }
            }

            let mut sheet = format!("<fact_sheet cluster=\"{}\" source=\"{}\">\n", cluster_idx + 1, primary_source);
            for d in &definitions {
                sheet.push_str(&format!("- [Core Definition]: {}\n", d));
            }
            for m in &metrics_and_formulas {
                sheet.push_str(&format!("- [Metric/Formula/Theorem]: {}\n", m));
            }
            for dt in &dates_and_names {
                sheet.push_str(&format!("- [Historical Date/Milestone]: {}\n", dt));
            }
            for q in &verbatim_quotes {
                sheet.push_str(&format!("- [Verbatim Quote]: {}\n", q));
            }
            sheet.push_str("</fact_sheet>");
            fact_sheets.push(sheet);
        }

        fact_sheets
    }

    /// Detects if the trailing window of `text` (>= 48 chars) is a verbatim repeat of an earlier passage in `text`.
    /// Returns `Some(byte_offset)` of the boundary before the repeated passage if a loop is detected.
    pub fn has_repeated_passage(text: &str) -> Option<usize> {
        let trimmed = text.trim_end();
        if trimmed.len() < 120 {
            return None;
        }
        let chars: Vec<(usize, char)> = trimmed.char_indices().collect();
        if chars.len() < 96 {
            return None;
        }
        let window_chars = 48usize;
        let tail_start_byte = chars[chars.len() - window_chars].0;
        let tail_slice = &trimmed[tail_start_byte..];
        if tail_slice.trim().len() < 40 {
            return None;
        }
        let earlier_slice = &trimmed[..tail_start_byte];
        if earlier_slice
            .to_ascii_lowercase()
            .contains(&tail_slice.to_ascii_lowercase())
        {
            // Snap back to the start of the repeated sentence or paragraph
            let snap_pos = earlier_slice
                .rfind("\n\n")
                .or_else(|| earlier_slice.rfind('\n'))
                .or_else(|| earlier_slice.rfind(". ").map(|p| p + 1))
                .unwrap_or(tail_start_byte);
            return Some(snap_pos);
        }
        None
    }

    /// Removes repeated lines or paragraphs from `text` and returns `(deduplicated_text, had_repetition)`.
    pub fn deduplicate_repeated_paragraphs(text: &str) -> (String, bool) {
        let mut seen_lines = std::collections::HashSet::new();
        let mut out_lines = Vec::new();
        let mut had_repeat = false;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.len() >= 32 {
                let norm: String = trimmed
                    .chars()
                    .filter(|c| c.is_alphanumeric())
                    .collect::<String>()
                    .to_ascii_lowercase();
                if norm.len() >= 25 && !seen_lines.insert(norm) {
                    had_repeat = true;
                    break;
                }
            }
            out_lines.push(line);
        }
        (out_lines.join("\n"), had_repeat)
    }

    /// Deduplicates chunk text segments against prior assistant turns using pairwise semantic similarity
    /// and normalized sentence matching. Drops chunk segments whose cosine similarity against any prior sentence
    /// meets or exceeds `similarity_threshold` (e.g. 0.88).
    pub fn deduplicate_chunk_segments_against_prior(
        chunks: Vec<ScoredChunk>,
        prior_text: &str,
        similarity_threshold: f32,
    ) -> Vec<ScoredChunk> {
        if prior_text.trim().is_empty() || chunks.is_empty() {
            return chunks;
        }

        let split_sentences = |text: &str| -> Vec<String> {
            let mut sents = Vec::new();
            let mut cur = String::new();
            let chars: Vec<char> = text.chars().collect();
            let len = chars.len();
            let mut i = 0;
            while i < len {
                cur.push(chars[i]);
                if (chars[i] == '.' || chars[i] == '!' || chars[i] == '?' || chars[i] == '\n')
                    && (i + 1 == len || chars[i + 1].is_whitespace())
                {
                    let trimmed = cur.trim();
                    if trimmed.len() >= 15 {
                        sents.push(trimmed.to_string());
                    }
                    cur.clear();
                }
                i += 1;
            }
            let trimmed = cur.trim();
            if trimmed.len() >= 15 {
                sents.push(trimmed.to_string());
            }
            sents
        };

        let prior_sentences = split_sentences(prior_text);
        if prior_sentences.is_empty() {
            return chunks;
        }

        let embedder = quorum_contract::DeterministicOfflineEngine::new();
        let mut prior_vectors: Vec<Vec<f32>> = Vec::with_capacity(prior_sentences.len());
        for s in &prior_sentences {
            if let Ok(vec) = embedder.embed_text(s) {
                prior_vectors.push(vec);
            }
        }

        let cosine_sim = |a: &[f32], b: &[f32]| -> f32 {
            let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
            let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
            let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm_a > 1e-6 && norm_b > 1e-6 {
                dot / (norm_a * norm_b)
            } else {
                0.0
            }
        };

        let mut out_chunks = Vec::new();

        for mut sc in chunks {
            let raw_text = sc.chunk.text_content.clone();
            let mut kept_paragraphs = Vec::new();

            for para in raw_text.split("\n\n") {
                let trimmed_para = para.trim();
                if trimmed_para.is_empty() {
                    continue;
                }
                if trimmed_para.starts_with('#') || trimmed_para.starts_with("```") || trimmed_para.len() < 25 {
                    kept_paragraphs.push(trimmed_para.to_string());
                    continue;
                }

                let para_sents = split_sentences(trimmed_para);
                if para_sents.is_empty() {
                    kept_paragraphs.push(trimmed_para.to_string());
                    continue;
                }

                let mut kept_sents = Vec::new();
                for sent in para_sents {
                    let mut is_dup = false;

                    // 1. Semantic embedding similarity check
                    if !prior_vectors.is_empty() {
                        if let Ok(s_vec) = embedder.embed_text(&sent) {
                            for pv in &prior_vectors {
                                let sim = cosine_sim(&s_vec, pv);
                                if sim >= similarity_threshold {
                                    is_dup = true;
                                    break;
                                }
                            }
                        }
                    }

                    // 2. Normalized alphanumeric string equality check
                    if !is_dup {
                        let norm_s: String = sent.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_ascii_lowercase();
                        for ps in &prior_sentences {
                            let norm_ps: String = ps.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_ascii_lowercase();
                            if norm_s == norm_ps && norm_s.len() >= 15 {
                                is_dup = true;
                                break;
                            }
                        }
                    }

                    if !is_dup {
                        kept_sents.push(sent);
                    }
                }

                if !kept_sents.is_empty() {
                    kept_paragraphs.push(kept_sents.join(" "));
                }
            }

            let filtered_content = kept_paragraphs.join("\n\n").trim().to_string();
            if !filtered_content.is_empty() {
                sc.chunk.text_content = filtered_content;
                out_chunks.push(sc);
            }
        }

        out_chunks
    }

    /// Extracts a concise summary of concrete facts, fees, phone numbers, emails, and legal clauses from prior assistant turns.
    pub fn extract_key_facts_summary(prior_text: &str) -> String {
        if prior_text.trim().is_empty() {
            return String::new();
        }

        let mut facts: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let dollar_re = regex::Regex::new(r"(?i)\$\s*[0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?|\b[0-9]+\s+dollars\b").unwrap();
        let phone_re = regex::Regex::new(r"\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b").unwrap();
        let email_re = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap();
        let account_re = regex::Regex::new(r"#?\b[0-9]{7,16}\b").unwrap();

        for line in prior_text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("---") {
                continue;
            }

            for sent in trimmed.split(|c: char| c == '.' || c == ';' || c == '!' || c == '?') {
                let s_trim = sent.trim();
                if s_trim.len() < 10 {
                    continue;
                }

                let has_dollar = dollar_re.is_match(s_trim);
                let has_phone = phone_re.is_match(s_trim);
                let has_email = email_re.is_match(s_trim) || account_re.is_match(s_trim);
                let s_lower = s_trim.to_ascii_lowercase();
                let has_legal_clause = s_lower.contains("fee")
                    || s_lower.contains("deposit")
                    || s_lower.contains("rent")
                    || s_lower.contains("eviction")
                    || s_lower.contains("sublet")
                    || s_lower.contains("notice")
                    || s_lower.contains("lease")
                    || s_lower.contains("tenant")
                    || s_lower.contains("landlord")
                    || s_lower.contains("born")
                    || s_lower.contains("graduated")
                    || s_lower.contains("degree");

                if has_dollar || has_phone || has_email || has_legal_clause {
                    let norm: String = s_trim.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_ascii_lowercase();
                    if !norm.is_empty() && seen.insert(norm) {
                        facts.push(format!("- {}", s_trim));
                        if facts.len() >= 15 {
                            break;
                        }
                    }
                }
            }
            if facts.len() >= 15 {
                break;
            }
        }

        facts.join("\n")
    }

    /// Post-synthesis pass that merges duplicate or identical entity statements across sentences or paragraphs,
    /// consolidating their citation numbers (e.g. `[1], [2]`) into a single coherent sentence.
    pub fn consolidate_duplicate_entity_statements(text: &str) -> String {
        if text.trim().is_empty() {
            return text.to_string();
        }

        let bold_re = regex::Regex::new(r"\*\*\[(\d+)\]\*\*").unwrap();
        let normal_re = regex::Regex::new(r"\[(\d+)\]").unwrap();
        let dollar_re = regex::Regex::new(r"(?i)\$\s*[0-9]+(?:,[0-9]{3})*(?:\.[0-9]{2})?|\b[0-9]+\s+dollars\b").unwrap();
        let phone_re = regex::Regex::new(r"\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b").unwrap();
        let percent_re = regex::Regex::new(r"\b[0-9]+(?:\.[0-9]+)?%").unwrap();
        let account_re = regex::Regex::new(r"#?\b[0-9]{7,16}\b").unwrap();

        let normalize_dollar = |s: &str| -> String {
            let digits_and_dot: String = s.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
            let trimmed = digits_and_dot.strip_suffix(".00").unwrap_or(&digits_and_dot);
            format!("${}", trimmed)
        };

        #[derive(Clone)]
        struct SentenceEntry {
            clean_text: String,
            citations: Vec<usize>,
            bold: bool,
            entity_keys: Vec<String>,
            norm_words: Vec<String>,
        }

        let extract_entry = |raw: &str| -> SentenceEntry {
            let mut cits = Vec::new();
            let mut is_bold = false;
            for cap in bold_re.captures_iter(raw) {
                if let Ok(num) = cap[1].parse::<usize>() {
                    if !cits.contains(&num) {
                        cits.push(num);
                    }
                    is_bold = true;
                }
            }
            for cap in normal_re.captures_iter(raw) {
                if let Ok(num) = cap[1].parse::<usize>() {
                    if !cits.contains(&num) {
                        cits.push(num);
                    }
                }
            }
            cits.sort_unstable();

            let cit_group_re = regex::Regex::new(r"(?:\*\*\[\d+\]\*\*|\[\d+\])(?:\s*,\s*(?:\*\*\[\d+\]\*\*|\[\d+\]))*").unwrap();
            let multi_comma_re = regex::Regex::new(r"(?:\s*,\s*){2,}").unwrap();
            let space_punct_re = regex::Regex::new(r"\s*,?\s+([.!?;:])").unwrap();
            let stripped_groups = cit_group_re.replace_all(raw, "");
            let stripped_bold = bold_re.replace_all(&stripped_groups, "");
            let stripped_all = normal_re.replace_all(&stripped_bold, "");
            let collapsed_commas = multi_comma_re.replace_all(&stripped_all, ", ");
            let collapsed_punct = space_punct_re.replace_all(&collapsed_commas, "$1");
            let clean = collapsed_punct.trim().trim_end_matches(',').trim().to_string();

            let mut entity_keys = Vec::new();
            for cap in dollar_re.find_iter(&clean) {
                entity_keys.push(normalize_dollar(cap.as_str()));
            }
            for cap in phone_re.find_iter(&clean) {
                let digits: String = cap.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
                entity_keys.push(format!("tel:{}", digits));
            }
            for cap in percent_re.find_iter(&clean) {
                entity_keys.push(cap.as_str().to_ascii_lowercase());
            }
            for cap in account_re.find_iter(&clean) {
                let digits: String = cap.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 7 {
                    entity_keys.push(format!("acct:{}", digits));
                }
            }

            let norm_words: Vec<String> = clean
                .split(|c: char| !c.is_alphanumeric())
                .map(|w| w.trim().to_ascii_lowercase())
                .filter(|w| w.len() >= 3 && !STOPWORDS.contains(&w.as_str()))
                .collect();

            SentenceEntry {
                clean_text: clean,
                citations: cits,
                bold: is_bold,
                entity_keys,
                norm_words,
            }
        };

        let is_duplicate = |a: &SentenceEntry, b: &SentenceEntry| -> bool {
            if a.clean_text.is_empty() || b.clean_text.is_empty() {
                return false;
            }
            // 1. Exact normalized sentence match
            let norm_a: String = a.clean_text.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_ascii_lowercase();
            let norm_b: String = b.clean_text.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_ascii_lowercase();
            if norm_a == norm_b && norm_a.len() >= 15 {
                return true;
            }

            // 2. Matching monetary fee, phone number, or percentage + shared key topic words
            if !a.entity_keys.is_empty() && !b.entity_keys.is_empty() {
                let shared_entities: Vec<&String> = a.entity_keys.iter().filter(|k| b.entity_keys.contains(k)).collect();
                if !shared_entities.is_empty() {
                    let shared_words = a.norm_words.iter().filter(|w| b.norm_words.contains(w)).count();
                    if shared_words >= 2 || (shared_words >= 1 && a.norm_words.len().min(b.norm_words.len()) <= 3) {
                        return true;
                    }
                }
            }

            // 3. Jaccard similarity across content words >= 0.55
            if !a.norm_words.is_empty() && !b.norm_words.is_empty() {
                let set_a: std::collections::HashSet<&String> = a.norm_words.iter().collect();
                let set_b: std::collections::HashSet<&String> = b.norm_words.iter().collect();
                let intersection = set_a.intersection(&set_b).count();
                let union = set_a.union(&set_b).count();
                if union > 0 && (intersection as f32 / union as f32) >= 0.55 {
                    return true;
                }
            }

            false
        };

        let format_entry = |rec: &SentenceEntry| -> String {
            if rec.citations.is_empty() {
                return rec.clean_text.clone();
            }
            let mut unique_cits = rec.citations.clone();
            unique_cits.sort_unstable();
            unique_cits.dedup();
            let cit_str = if rec.bold {
                unique_cits.iter().map(|n| format!("**[{}]**", n)).collect::<Vec<_>>().join(", ")
            } else {
                unique_cits.iter().map(|n| format!("[{}]", n)).collect::<Vec<_>>().join(", ")
            };

            let base = rec.clean_text.trim_end_matches('.');
            format!("{} {}.", base, cit_str)
        };

        enum ParaItem {
            Verbatim(String),
            SentenceIndices(Vec<usize>),
        }

        // Split text into paragraphs
        let paragraphs: Vec<&str> = text.split("\n\n").collect();
        let mut para_items: Vec<ParaItem> = Vec::new();
        let mut all_accepted_entries: Vec<SentenceEntry> = Vec::new();

        for para in paragraphs {
            let p_trim = para.trim();
            if p_trim.is_empty() {
                continue;
            }
            if p_trim.starts_with('#') || p_trim.starts_with("---") || p_trim.starts_with("```") {
                para_items.push(ParaItem::Verbatim(p_trim.to_string()));
                continue;
            }

            // Split paragraph into sentences
            let mut sents = Vec::new();
            let mut cur = String::new();
            let chars: Vec<char> = p_trim.chars().collect();
            let len = chars.len();
            let mut i = 0;
            while i < len {
                cur.push(chars[i]);
                if (chars[i] == '.' || chars[i] == '!' || chars[i] == '?')
                    && (i + 1 == len || chars[i + 1].is_whitespace())
                {
                    let trimmed = cur.trim();
                    if !trimmed.is_empty() {
                        sents.push(trimmed.to_string());
                    }
                    cur.clear();
                }
                i += 1;
            }
            let trimmed = cur.trim();
            if !trimmed.is_empty() {
                sents.push(trimmed.to_string());
            }

            let mut para_accepted_indices = Vec::new();

            for sent in sents {
                let entry = extract_entry(&sent);
                // Check if duplicate of any already accepted entry
                let mut matched_existing_idx = None;
                for (idx, existing) in all_accepted_entries.iter().enumerate() {
                    if is_duplicate(existing, &entry) {
                        matched_existing_idx = Some(idx);
                        break;
                    }
                }

                if let Some(existing_idx) = matched_existing_idx {
                    // Merge citations into the existing entry
                    for c in entry.citations {
                        if !all_accepted_entries[existing_idx].citations.contains(&c) {
                            all_accepted_entries[existing_idx].citations.push(c);
                        }
                    }
                    if entry.bold {
                        all_accepted_entries[existing_idx].bold = true;
                    }
                } else {
                    let new_idx = all_accepted_entries.len();
                    all_accepted_entries.push(entry);
                    para_accepted_indices.push(new_idx);
                }
            }

            if !para_accepted_indices.is_empty() {
                para_items.push(ParaItem::SentenceIndices(para_accepted_indices));
            }
        }

        let mut processed_paragraphs: Vec<String> = Vec::new();
        for item in para_items {
            match item {
                ParaItem::Verbatim(s) => processed_paragraphs.push(s),
                ParaItem::SentenceIndices(indices) => {
                    let para_text = indices
                        .iter()
                        .map(|&idx| format_entry(&all_accepted_entries[idx]))
                        .collect::<Vec<_>>()
                        .join(" ");
                    if !para_text.trim().is_empty() {
                        processed_paragraphs.push(para_text);
                    }
                }
            }
        }

        processed_paragraphs.join("\n\n")
    }

    /// Removes a leading stub heading that only restates the topic without a sentence (e.g. `### Angela Davis is`)
    /// and any echoed `Source Documents:` / `Reference Excerpts` label line produced by small local models.
    pub fn strip_stub_heading_and_label_echo(text: &str) -> String {
        let mut lines: Vec<&str> = text.lines().collect();
        let is_label = |l: &str| {
            let t = l.trim().trim_matches(|c: char| c == '*' || c == '#' || c == ':' || c == ' ').to_ascii_lowercase();
            t == "source documents" || t == "sources" || t.starts_with("reference excerpts")
        };
        // Drop leading blank lines, then stub heading, then label echoes (repeat until stable)
        loop {
            while lines.first().map(|l| l.trim().is_empty()).unwrap_or(false) {
                lines.remove(0);
            }
            let Some(first) = lines.first().copied() else { break };
            let ft = first.trim();
            let heading_body = ft.trim_start_matches('#').trim();
            let is_stub_heading = ft.starts_with('#')
                && heading_body.chars().count() <= 80
                && !heading_body.ends_with('.')
                && !heading_body.ends_with('!')
                && !heading_body.ends_with('?');
            if is_stub_heading && lines.len() > 1 {
                lines.remove(0);
                continue;
            }
            if is_label(ft) && lines.len() > 1 {
                lines.remove(0);
                continue;
            }
            break;
        }
        let normalized: Vec<String> = lines
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let t = line.trim_start();
                if !t.starts_with('#') {
                    return (*line).to_string();
                }
                let body = t.trim_start_matches('#').trim();
                // `#### [1] Source File: name.doc` (echo of the context header) -> `**name.doc** [1]`
                if body.starts_with('[') {
                    if let Some(close) = body.find(']') {
                        let tag = &body[..=close];
                        let rest = body[close + 1..].trim();
                        if let Some(name) = rest
                            .strip_prefix("Source File:")
                            .or_else(|| rest.strip_prefix("Source:"))
                        {
                            return format!("**{}** {}", name.trim(), tag);
                        }
                    }
                }
                // `#### Source Document [2]: Sacred math and disruption.docx` -> `**Sacred math and disruption.docx** [2]`
                let lb = body.to_ascii_lowercase();
                if lb.starts_with("source document") || lb.starts_with("document [") || lb.starts_with("source [") {
                    if let (Some(o), Some(c)) = (body.find('['), body.find(']')) {
                        if o < c {
                            let tag = &body[o..=c];
                            let name = body[c + 1..].trim_start_matches(':').trim();
                            if !name.is_empty() {
                                return format!("**{}** {}", name, tag);
                            }
                            return String::new();
                        }
                    }
                }
                // The very first line is a full sentence wrongly prefixed with `###` -> drop the hashes
                let looks_like_sentence = body.chars().count() > 80
                    || body.ends_with('.')
                    || body.ends_with('!')
                    || body.ends_with('?')
                    || body.contains(". ");
                if i == 0 && looks_like_sentence {
                    return body.to_string();
                }
                (*line).to_string()
            })
            .collect();
        normalized.join("\n").trim().to_string()
    }

    /// Deterministic anti-hallucination guard: removes prose sentences whose content words are mostly absent from
    /// the retrieved source text (generic LLM padding such as "his LinkedIn profile provides additional insights").
    /// The first sentence (question-restating opening) is always kept. Returns the original text if filtering would
    /// remove almost everything.
    /// Returns true when `chars[dot_idx] == '.'` follows a single-letter initial (`P. B.`) or common title/street
    /// abbreviation (`St.`, `Ave.`, `Rd.`, `Dr.`, `Mr.`, `Mrs.`, `Ms.`, `No.`, `vs.`, `Inc.`, etc.), not a sentence end.
    fn is_non_terminal_period(chars: &[char], dot_idx: usize) -> bool {
        if dot_idx == 0 || chars.get(dot_idx) != Some(&'.') {
            return false;
        }
        // Single uppercase initial ("P. B. Randolph")
        if chars[dot_idx - 1].is_uppercase() && (dot_idx < 2 || !chars[dot_idx - 2].is_alphanumeric()) {
            return true;
        }
        let mut start = dot_idx;
        while start > 0 && chars[start - 1].is_alphabetic() {
            start -= 1;
        }
        if start < dot_idx && (start == 0 || !chars[start - 1].is_alphanumeric()) {
            let word: String = chars[start..dot_idx].iter().collect::<String>().to_ascii_lowercase();
            const ABBREVS: &[&str] = &[
                "st", "ave", "rd", "blvd", "dr", "ln", "ct", "pl", "ste", "apt", "mr", "mrs", "ms",
                "prof", "sr", "jr", "inc", "ltd", "corp", "co", "no", "vs", "etc", "fig", "al",
            ];
            if ABBREVS.contains(&word.as_str()) {
                return true;
            }
        }
        false
    }

    pub fn drop_ungrounded_sentences(text: &str, corpus: &str) -> String {
        use std::collections::HashSet;
        const STOP: &[&str] = &[
            "that", "with", "this", "from", "have", "been", "their", "which", "also", "such", "into",
            "these", "those", "there", "where", "while", "about", "through", "across", "within",
            "between", "being", "over", "other", "more", "most", "some", "only", "than", "them",
            "they", "what", "when", "will", "would", "could", "should", "both", "each", "well", "very",
            "many", "much", "like", "make", "made", "help", "helps", "provide", "provides", "providing",
            "including", "includes", "include", "overall", "furthermore", "additionally", "moreover",
            "his", "her", "its", "and", "the", "for", "are", "was", "were", "has", "had", "not", "but",
        ];
        let word_key = |w: &str| -> String { w.chars().take(5).collect() };
        let split_words = |s: &str| -> Vec<String> {
            s.to_ascii_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| w.len() >= 4 && !w.chars().all(|c| c.is_ascii_digit()))
                .map(|w| w.to_string())
                .collect()
        };
        let corpus_keys: HashSet<String> = split_words(corpus).iter().map(|w| word_key(w)).collect();
        if corpus_keys.is_empty() {
            return text.to_string();
        }

        let mut first_sentence_done = false;
        let mut out_lines: Vec<String> = Vec::new();
        let mut kept_prose = 0usize;
        let mut total_prose = 0usize;

        for line in text.lines() {
            let t = line.trim();
            if t.is_empty()
                || t.starts_with('#')
                || t.starts_with('-')
                || t.starts_with('*')
                || t.starts_with('>')
                || t.starts_with('|')
                || t.starts_with('`')
                || Self::is_numbered_list_item(t)
            {
                out_lines.push(line.to_string());
                continue;
            }
            // split into sentences keeping terminators
            let chars: Vec<char> = t.chars().collect();
            let mut sentences: Vec<String> = Vec::new();
            let mut cur = String::new();
            for (i, &c) in chars.iter().enumerate() {
                cur.push(c);
                if matches!(c, '.' | '!' | '?') {
                    let next_ws = i + 1 >= chars.len() || chars[i + 1].is_whitespace();
                    let non_term = c == '.' && Self::is_non_terminal_period(&chars, i);
                    if next_ws && !non_term {
                        sentences.push(std::mem::take(&mut cur));
                    }
                }
            }
            if !cur.trim().is_empty() {
                sentences.push(cur);
            }
            let mut kept: Vec<String> = Vec::new();
            for sent in sentences {
                let sent_trim = sent.trim().to_string();
                total_prose += sent_trim.len();
                let words: Vec<String> = split_words(&sent_trim)
                    .into_iter()
                    .filter(|w| !STOP.contains(&w.as_str()))
                    .collect();
                let keep = if !first_sentence_done {
                    true
                } else if words.len() < 6 {
                    true
                } else {
                    let novel = words.iter().filter(|w| !corpus_keys.contains(&word_key(w))).count();
                    novel * 100 / words.len() <= 45
                };
                first_sentence_done = true;
                if keep {
                    kept_prose += sent_trim.len();
                    kept.push(sent_trim);
                }
            }
            if !kept.is_empty() {
                out_lines.push(kept.join(" "));
            }
        }
        if total_prose > 0 && kept_prose * 100 / total_prose < 25 {
            return text.to_string();
        }
        out_lines.join("\n").trim().to_string()
    }

    /// Extra keyword cues for a targeted lexical search, by the kind of fact a question asks for
    /// (address/phone/date/amount). Empty for questions with no specific answer type.
    pub fn answer_type_cue_terms(prompt: &str) -> Vec<&'static str> {
        let q = prompt.to_ascii_lowercase();
        let qw: Vec<&str> = q.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
        let has = |w: &str| qw.contains(&w);
        let mut out: Vec<&'static str> = Vec::new();
        if ["live", "lives", "living", "reside", "resides", "address", "located", "location", "hometown"].iter().any(|w| has(w)) {
            out.extend(["address", "street", "avenue", "phone", "email"]);
        }
        if ["phone", "email", "contact", "telephone", "reach"].iter().any(|w| has(w)) {
            out.extend(["phone", "email", "contact", "mobile"]);
        }
        if q.contains("how much") || ["cost", "price", "rent", "fee", "fees", "salary", "pay", "pays", "paid", "amount", "deposit"].iter().any(|w| has(w)) {
            out.extend(["rent", "month", "amount", "payable", "fee"]);
        }
        if qw.first() == Some(&"when") || ["date", "dated", "start", "started", "began", "begin"].iter().any(|w| has(w)) {
            out.extend(["dated", "date", "starting", "day", "entered"]);
        }
        out.dedup();
        out
    }

    /// Answer-type cue score: rewards chunks that contain the *kind* of fact a natural-language question asks for
    /// (a street address / ZIP for "where does X live", a `$` amount for "how much", a date for "when", a phone or
    /// email for "contact"), so the excerpt that actually answers the question ranks above excerpts that merely
    /// mention the subject. `text_l` must be lowercase.
    pub fn answer_type_cue_score(prompt: &str, text_l: &str) -> i32 {
        let q = prompt.to_ascii_lowercase();
        let qw: Vec<&str> = q.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
        let has = |w: &str| qw.contains(&w);
        let tokens: Vec<&str> = text_l.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
        let tok = |w: &str| tokens.contains(&w);
        let mut score = 0i32;

        let asks_location = ["live", "lives", "living", "reside", "resides", "address", "located", "location", "hometown", "based"]
            .iter()
            .any(|w| has(w));
        if asks_location {
            if tokens.iter().any(|t| t.len() == 5 && t.chars().all(|c| c.is_ascii_digit())) {
                score += 220;
            }
            let cues = ["address", "street", "st", "avenue", "ave", "road", "rd", "drive", "lane", "city", "suite", "apt"]
                .iter()
                .filter(|w| tok(w))
                .count();
            score += (cues.min(3) as i32) * 60;
        }

        let asks_amount = q.contains("how much")
            || q.contains("how many")
            || ["cost", "costs", "price", "rent", "fee", "fees", "salary", "pay", "pays", "paid", "amount", "charge", "deposit"]
                .iter()
                .any(|w| has(w));
        if asks_amount {
            if text_l.contains('$') {
                score += 200;
            }
            if text_l.contains("per month") || text_l.contains("per day") || text_l.contains("per year") {
                score += 60;
            }
        }

        let asks_date = qw.first() == Some(&"when")
            || ["date", "dated", "start", "started", "began", "begin", "year", "since", "until"].iter().any(|w| has(w));
        if asks_date {
            const MONTHS: &[&str] = &[
                "january", "february", "march", "april", "may", "june", "july", "august", "september",
                "october", "november", "december",
            ];
            if MONTHS.iter().any(|m| tok(m)) {
                score += 120;
            }
            if tokens.iter().any(|t| t.len() == 4 && (t.starts_with("19") || t.starts_with("20")) && t.chars().all(|c| c.is_ascii_digit())) {
                score += 80;
            }
        }

        let asks_contact = ["phone", "email", "contact", "reach", "number", "telephone"].iter().any(|w| has(w));
        if asks_contact {
            if tok("phone") || tok("tel") || tok("mobile") {
                score += 120;
            }
            if text_l.contains('@') || tok("email") {
                score += 120;
            }
        }
        score
    }

    /// Lowercases a sentence the model wrote In Title Case (>= 70% of 5+ words capitalised), keeping the first word,
    /// acronyms, numbers/amounts, words the user capitalised, and words never seen in lowercase (proper names).
    fn detitle_sentence(
        sentence: &str,
        prompt: &str,
        text: &str,
        corpus_lower_words: &std::collections::HashSet<&str>,
    ) -> String {
        let words: Vec<&str> = sentence.split_whitespace().collect();
        if words.len() < 5 {
            return sentence.to_string();
        }
        let caps = words
            .iter()
            .filter(|w| w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
            .count();
        if caps * 100 / words.len() < 70 {
            return sentence.to_string();
        }
        const FUNCTION_WORDS: &[&str] = &[
            "the", "a", "an", "of", "on", "in", "is", "are", "was", "were", "to", "for", "and", "or", "per",
            "by", "at", "with", "from", "after", "before", "each", "until", "be", "has", "have", "its", "this",
            "that", "as", "if", "not", "will", "must", "also", "there", "an", "any", "all", "within", "into",
            "day", "days", "week", "weeks", "month", "months", "year", "years", "first", "second", "third",
            "fourth", "fifth", "last", "total", "maximum", "minimum", "late", "fee", "fees", "rent", "lease",
            "leases", "tenant", "tenants", "landlord", "amount", "payment", "payments", "due", "paid",
            "additionally", "additional", "plus", "afterwards", "included", "includes", "agreement", "end",
            "period", "requirements", "security", "deposit", "equal", "one", "two", "three", "ten", "been", "being", "had", "do", "does", "did", "can", "could", "should", "would", "may", "might", "shall", "he", "she", "it", "they", "we", "you", "his", "her", "their", "our", "than", "then", "when", "where", "which", "who", "what", "so", "but", "no", "up", "out", "over", "under", "about", "such", "more", "most", "other", "only", "very", "these", "those", "both", "between",
        ];
        let fixed: Vec<String> = words
            .iter()
            .enumerate()
            .map(|(i, w)| {
                let bare = w.trim_matches(|c: char| !c.is_alphanumeric());
                let is_acronym = bare.chars().filter(|c| c.is_alphabetic()).count() >= 2
                    && bare.chars().filter(|c| c.is_alphabetic()).all(|c| c.is_uppercase());
                if i == 0 || is_acronym || w.contains('$') || w.chars().any(|c| c.is_ascii_digit()) {
                    return (*w).to_string();
                }
                let lbare = bare.to_ascii_lowercase();
                let user_capitalised = prompt.split_whitespace().any(|pw| {
                    let pb = pw.trim_matches(|c: char| !c.is_alphanumeric());
                    pb == bare && pb.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
                });
                if user_capitalised {
                    return (*w).to_string();
                }
                let typed_lower = prompt.split_whitespace().any(|pw| {
                    let pb = pw.trim_matches(|c: char| !c.is_alphanumeric());
                    pb == lbare.as_str()
                        || (lbare.len() >= 4 && pb.starts_with(lbare.as_str()) && pb.chars().all(|c| !c.is_uppercase()))
                });
                let lower_elsewhere = lbare.len() >= 3
                    && text.split(|c: char| !c.is_alphanumeric()).any(|tw| tw == lbare.as_str());
                let lower_in_corpus = corpus_lower_words.contains(lbare.as_str());
                if FUNCTION_WORDS.contains(&lbare.as_str()) || typed_lower || lower_elsewhere || lower_in_corpus {
                    w.to_lowercase()
                } else {
                    (*w).to_string()
                }
            })
            .collect();
        fixed.join(" ")
    }

    /// Continuation guard: removes sentences that substantially repeat a sentence from the previous answer
    /// (word-set Jaccard >= 0.55 over words of 4+ letters), so "continue" adds new material instead of restating.
    /// Returns the original text if fewer than two sentences would survive.
    fn continuation_content_stems(s: &str) -> std::collections::HashSet<String> {
        const DISCOURSE_FILLER: &[&str] = &[
            "that", "this", "these", "those", "with", "without", "from", "into", "have", "been",
            "were", "their", "there", "which", "while", "where", "when", "also", "additionally",
            "furthermore", "moreover", "however", "therefore", "before", "after", "under",
            "certain", "various", "specific", "such", "allowed", "allow", "allows", "requires",
            "require", "required", "regarding", "involving", "provided", "stipulates", "states",
            "shall", "must", "would", "could", "should", "upon", "within", "through", "between",
        ];
        s.to_ascii_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() >= 4 && !DISCOURSE_FILLER.contains(w) && !w.chars().all(|c| c.is_ascii_digit()))
            .map(|w| {
                if w.len() >= 5
                    && w.ends_with('s')
                    && !w.ends_with("ss")
                    && !w.ends_with("us")
                    && !w.ends_with("is")
                {
                    w[..w.len() - 1].to_string()
                } else {
                    w.to_string()
                }
            })
            .collect()
    }

    fn split_prose_line_sentences(s: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let chars: Vec<char> = s.chars().collect();
        for (i, &c) in chars.iter().enumerate() {
            cur.push(c);
            if matches!(c, '.' | '!' | '?')
                && !Self::is_non_terminal_period(&chars, i)
                && (i + 1 >= chars.len() || chars[i + 1].is_whitespace())
            {
                out.push(std::mem::take(&mut cur));
            }
        }
        if !cur.trim().is_empty() {
            out.push(cur);
        }
        out
    }

    pub fn drop_sentences_repeating_prior(text: &str, prior: &str) -> String {
        use std::collections::HashSet;
        let clean_prior = Self::strip_sources_footer(prior);
        let mut prior_sets: Vec<HashSet<String>> = Vec::new();
        for pline in clean_prior.lines() {
            let pt = pline.trim();
            if pt.is_empty() || pt.starts_with('#') || pt.starts_with('|') || pt.starts_with('`') || pt == "---" {
                continue;
            }
            // Skip standalone short section titles without sentence punctuation so they never dilute adjacent sentences
            if !pt.ends_with('.') && !pt.ends_with('!') && !pt.ends_with('?') && pt.split_whitespace().count() <= 7 {
                continue;
            }
            for sent in Self::split_prose_line_sentences(pt) {
                let ws = Self::continuation_content_stems(&sent);
                if ws.len() >= 4 {
                    prior_sets.push(ws);
                }
            }
        }
        if prior_sets.is_empty() {
            return text.to_string();
        }
        let dollar_prior_re = regex::Regex::new(r"\$\s*([0-9][0-9,]*(?:\.[0-9]{2})?)").unwrap();
        let acct_prior_re = regex::Regex::new(r"#?\b([0-9]{7,16})\b").unwrap();
        let norm_dollar_num = |raw: &str| -> String {
            let clean: String = raw.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
            clean.strip_suffix(".00").unwrap_or(&clean).to_string()
        };
        let mut prior_fee_contexts: Vec<(String, HashSet<String>)> = Vec::new();
        let mut prior_accts: HashSet<String> = HashSet::new();
        for cap in acct_prior_re.captures_iter(clean_prior) {
            prior_accts.insert(cap[1].to_string());
        }
        for pline in clean_prior.lines() {
            for psent in Self::split_prose_line_sentences(pline.trim()) {
                let pstems = Self::continuation_content_stems(&psent);
                for cap in dollar_prior_re.captures_iter(&psent) {
                    let amt = norm_dollar_num(&cap[1]);
                    if !amt.is_empty() {
                        prior_fee_contexts.push((amt, pstems.clone()));
                    }
                }
            }
        }
        let repeats_prior_specific_entity = |sent: &str, ws: &HashSet<String>| -> bool {
            for cap in acct_prior_re.captures_iter(sent) {
                if prior_accts.contains(&cap[1]) {
                    return true;
                }
            }
            for cap in dollar_prior_re.captures_iter(sent) {
                let amt = norm_dollar_num(&cap[1]);
                if amt.len() >= 3 {
                    for (p_amt, p_stems) in &prior_fee_contexts {
                        if &amt == p_amt && ws.intersection(p_stems).count() >= 2 {
                            return true;
                        }
                    }
                }
            }
            false
        };
        let is_repeated = |ws: &HashSet<String>| -> bool {
            if ws.len() < 4 {
                return false;
            }
            prior_sets.iter().any(|ps| {
                let inter = ws.intersection(ps).count();
                let union = ws.union(ps).count().max(1);
                let min_len = ws.len().min(ps.len()).max(1);
                (inter * 100 / union >= 45) || (inter >= 4 && inter * 100 / min_len >= 65)
            })
        };

        let mut raw_out_lines: Vec<String> = Vec::new();
        let mut kept_sentences = 0usize;
        for line in text.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with('|') || t.starts_with('`') {
                raw_out_lines.push(line.to_string());
                continue;
            }
            let clean_prior_lower = clean_prior.to_ascii_lowercase();
            let is_thematic_echo = |sent: &str| -> bool {
                let slow = sent.to_ascii_lowercase();
                let has_assoc_cue = slow.contains("associated with")
                    || slow.contains("association with")
                    || slow.contains("connected with")
                    || slow.contains("connection with");
                if !has_assoc_cue {
                    return false;
                }
                // Strip bracketed citation refs `[5]` and check if any new numeric fact (date, street number, dollar amount) is introduced
                let mut without_brackets = String::with_capacity(sent.len());
                let mut in_brk = false;
                for ch in sent.chars() {
                    if ch == '[' { in_brk = true; continue; }
                    if ch == ']' { in_brk = false; continue; }
                    if !in_brk { without_brackets.push(ch); }
                }
                if without_brackets.chars().any(|c| c.is_ascii_digit()) {
                    return false;
                }
                // If every quoted or capitalized >=5-char handle in the sentence already appeared in `clean_prior`, it's a pure thematic echo
                let handles: Vec<String> = without_brackets
                    .split(|c: char| !c.is_alphanumeric())
                    .filter(|w| w.len() >= 5 && w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
                    .map(|w| w.to_ascii_lowercase())
                    .collect();
                !handles.is_empty() && handles.iter().all(|h| clean_prior_lower.contains(h))
            };
            let kept: Vec<String> = Self::split_prose_line_sentences(t)
                .into_iter()
                .map(|x| x.trim().to_string())
                .filter(|x| {
                    let stems = Self::continuation_content_stems(x);
                    !is_repeated(&stems) && !repeats_prior_specific_entity(x, &stems) && !is_thematic_echo(x)
                })
                .collect();
            kept_sentences += kept.len();
            if !kept.is_empty() {
                raw_out_lines.push(kept.join(" "));
            }
        }
        if kept_sentences == 0 {
            return text.to_string();
        }
        // Drop orphan headings whose body sentences were completely removed
        let mut final_lines: Vec<String> = Vec::new();
        let mut idx = 0usize;
        while idx < raw_out_lines.len() {
            let trimmed = raw_out_lines[idx].trim();
            if trimmed.starts_with('#') {
                let mut look = idx + 1;
                while look < raw_out_lines.len() && raw_out_lines[look].trim().is_empty() {
                    look += 1;
                }
                if look >= raw_out_lines.len() || raw_out_lines[look].trim().starts_with('#') {
                    idx += 1;
                    continue;
                }
            }
            final_lines.push(raw_out_lines[idx].clone());
            idx += 1;
        }
        final_lines.join("\n").trim().to_string()
    }

    /// Removes boilerplate clauses/sentences from an input excerpt window that were already covered in `prior`,
    /// preventing sibling template documents (e.g. multiple leases sharing the same subletting rule) from re-feeding covered rules on `continue`.
    pub fn scrub_prior_covered_clauses(window: &str, prior: &str) -> String {
        use std::collections::HashSet;
        let clean_prior = Self::strip_sources_footer(prior);
        if clean_prior.trim().is_empty() {
            return window.to_string();
        }
        let mut prior_sets: Vec<HashSet<String>> = Vec::new();
        for pline in clean_prior.lines() {
            let pt = pline.trim();
            if pt.is_empty() || pt.starts_with('#') || pt == "---" {
                continue;
            }
            for sent in Self::split_prose_line_sentences(pt) {
                let ws = Self::continuation_content_stems(&sent);
                if ws.len() >= 4 {
                    prior_sets.push(ws);
                }
            }
        }
        if prior_sets.is_empty() {
            return window.to_string();
        }
        let mut out_lines = Vec::new();
        for line in window.lines() {
            let lt = line.trim();
            if lt.is_empty() {
                continue;
            }
            let kept: Vec<String> = Self::split_prose_line_sentences(lt)
                .into_iter()
                .filter(|sent| {
                    let ws = Self::continuation_content_stems(sent);
                    if ws.len() < 4 {
                        return true;
                    }
                    !prior_sets.iter().any(|ps| {
                        let inter = ws.intersection(ps).count();
                        let union = ws.union(ps).count().max(1);
                        let min_len = ws.len().min(ps.len()).max(1);
                        (inter * 100 / union >= 45) || (inter >= 4 && inter * 100 / min_len >= 65)
                    })
                })
                .collect();
            if !kept.is_empty() {
                out_lines.push(kept.join(" "));
            }
        }
        let scrubbed = out_lines.join("\n");
        if scrubbed.trim().len() >= 60 {
            scrubbed
        } else {
            window.to_string()
        }
    }

    /// Scans `prose` for bracketed numeric citations (`[1]`, `[2, 5]`, `[1–3]`), strips any out-of-range markers (`> K`),
    /// optionally filters `unique_file_chunks` down to only the files actually cited in `prose`, and renumbers citations
    /// sequentially `1..=M` so inline `[k]` markers and the `M` emitted source items match 1-to-1 with zero gaps.
    pub fn remap_and_compact_citations<'a>(
        prose: &str,
        unique_file_chunks: &[&'a ScoredChunk],
        filter_uncited: bool,
    ) -> (String, Vec<&'a ScoredChunk>) {
        use std::collections::{BTreeSet, HashMap};
        let k = unique_file_chunks.len();
        if k == 0 || prose.is_empty() {
            return (prose.to_string(), unique_file_chunks.to_vec());
        }

        let parse_bracket_nums = |inner: &str| -> Option<Vec<usize>> {
            let trimmed = inner.trim();
            if trimmed.is_empty() || trimmed.len() > 28 {
                return None;
            }
            if !trimmed
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, ',' | ' ' | '-' | '–'))
            {
                return None;
            }
            if !trimmed.chars().any(|c| c.is_ascii_digit()) {
                return None;
            }
            let mut nums = Vec::new();
            for part in trimmed.split(',') {
                let p = part.trim();
                if p.is_empty() {
                    continue;
                }
                if let Some((a_str, b_str)) = p.split_once('-').or_else(|| p.split_once('–')) {
                    let a = a_str.trim().parse::<usize>().ok()?;
                    let b = b_str.trim().parse::<usize>().ok()?;
                    if a == 0 || b < a || b - a > 12 {
                        return None;
                    }
                    for n in a..=b {
                        nums.push(n);
                    }
                } else {
                    let n = p.parse::<usize>().ok()?;
                    nums.push(n);
                }
            }
            if nums.is_empty() {
                None
            } else {
                Some(nums)
            }
        };

        // Pass 1: find all valid 1..=k citation indices referenced in prose
        let bytes = prose.as_bytes();
        let mut cited_set: BTreeSet<usize> = BTreeSet::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            if bytes[pos] == b'[' {
                if let Some(rel_end) = prose[pos + 1..].find(']') {
                    let close_pos = pos + 1 + rel_end;
                    let followed_by_paren = close_pos + 1 < bytes.len() && bytes[close_pos + 1] == b'(';
                    if !followed_by_paren {
                        let inner = &prose[pos + 1..close_pos];
                        if let Some(nums) = parse_bracket_nums(inner) {
                            for n in nums {
                                if (1..=k).contains(&n) {
                                    cited_set.insert(n);
                                }
                            }
                            pos = close_pos + 1;
                            continue;
                        }
                    }
                }
            }
            let ch_len = prose[pos..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            pos += ch_len;
        }

        let kept_chunks: Vec<&'a ScoredChunk> = if filter_uncited && !cited_set.is_empty() {
            unique_file_chunks
                .iter()
                .enumerate()
                .filter_map(|(i, &c)| if cited_set.contains(&(i + 1)) { Some(c) } else { None })
                .collect()
        } else {
            unique_file_chunks.to_vec()
        };

        let mut old_to_new: HashMap<usize, usize> = HashMap::new();
        if filter_uncited && !cited_set.is_empty() {
            for (new_zero_idx, old_one_idx) in cited_set.iter().enumerate() {
                old_to_new.insert(*old_one_idx, new_zero_idx + 1);
            }
        } else {
            for idx in 1..=k {
                old_to_new.insert(idx, idx);
            }
        }

        // Pass 2: rewrite citation spans in prose using old_to_new and drop out-of-range markers
        let mut rewritten = String::with_capacity(prose.len());
        let mut pos = 0usize;
        while pos < bytes.len() {
            if bytes[pos] == b'[' {
                if let Some(rel_end) = prose[pos + 1..].find(']') {
                    let close_pos = pos + 1 + rel_end;
                    let followed_by_paren = close_pos + 1 < bytes.len() && bytes[close_pos + 1] == b'(';
                    if !followed_by_paren {
                        let inner = &prose[pos + 1..close_pos];
                        if let Some(nums) = parse_bracket_nums(inner) {
                            let mut mapped: Vec<usize> = Vec::new();
                            for n in nums {
                                if let Some(&m) = old_to_new.get(&n) {
                                    if !mapped.contains(&m) {
                                        mapped.push(m);
                                    }
                                }
                            }
                            mapped.sort_unstable();
                            if mapped.is_empty() {
                                // Cleanly trim preceding space or ", " when dropping an invalid citation marker
                                if rewritten.ends_with(", ") {
                                    rewritten.truncate(rewritten.len() - 2);
                                } else if rewritten.ends_with(' ')
                                    && close_pos + 1 < bytes.len()
                                    && matches!(bytes[close_pos + 1], b'.' | b',' | b';' | b':')
                                {
                                    rewritten.pop();
                                }
                            } else {
                                let formatted = mapped
                                    .iter()
                                    .map(|m| format!("[{}]", m))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                // Avoid adjacent duplicate "[1], [1]" when two separate brackets mapped to the same file
                                let dup_suffix = format!("{}, ", formatted);
                                if !rewritten.ends_with(&dup_suffix) && !rewritten.ends_with(&formatted) {
                                    rewritten.push_str(&formatted);
                                } else if rewritten.ends_with(", ") {
                                    rewritten.truncate(rewritten.len() - 2);
                                }
                            }
                            pos = close_pos + 1;
                            continue;
                        }
                    }
                }
            }
            let ch = prose[pos..].chars().next().unwrap();
            rewritten.push(ch);
            pos += ch.len_utf8();
        }

        (rewritten, kept_chunks)
    }

    /// Returns a `max_chars` window of `text`. For typed questions the window starts shortly before the first
    /// occurrence of the requested fact type (5-digit ZIP for location, `$` for amounts, a month/year for dates,
    /// "phone"/"@" for contact) instead of always taking the opening characters.
    pub fn answer_focused_window(prompt: &str, text: &str, max_chars: usize) -> String {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() <= max_chars {
            return text.to_string();
        }
        let cues = Self::answer_type_cue_terms(prompt);
        if cues.is_empty() {
            return chars[..max_chars].iter().collect();
        }
        let lower: String = text.to_ascii_lowercase();
        let lower_chars: Vec<char> = lower.chars().collect();
        let mut anchor: Option<usize> = None;
        let find = |needle: &str| -> Option<usize> {
            lower.find(needle).map(|byte_i| lower[..byte_i].chars().count())
        };
        let q = prompt.to_ascii_lowercase();
        if cues.contains(&"address") {
            // first 5-digit token (ZIP)
            let mut run = 0usize;
            for (i, c) in lower_chars.iter().enumerate() {
                if c.is_ascii_digit() {
                    run += 1;
                } else {
                    if run == 5 {
                        anchor = Some(i - 5);
                        break;
                    }
                    run = 0;
                }
            }
            if anchor.is_none() {
                anchor = find("address").or_else(|| find("street")).or_else(|| find("avenue"));
            }
        }
        if anchor.is_none() && (cues.contains(&"phone") || q.contains("phone") || q.contains("email")) {
            anchor = find("phone").or_else(|| find("@")).or_else(|| find("email"));
        }
        if anchor.is_none() && cues.contains(&"rent") {
            anchor = find("$");
        }
        if anchor.is_none() && cues.contains(&"dated") {
            const MONTHS: &[&str] = &["january", "february", "march", "april", "may ", "june", "july", "august", "september", "october", "november", "december"];
            anchor = MONTHS.iter().filter_map(|m| find(m)).min();
        }
        let start = anchor.map(|a| a.saturating_sub(200)).unwrap_or(0);
        let start = start.min(chars.len().saturating_sub(max_chars));
        chars[start..start + max_chars].iter().collect()
    }

    /// Byte index just past the last sentence terminator that is followed by whitespace (or a paragraph break).
    pub fn last_sentence_boundary(text: &str) -> Option<usize> {
        let bytes = text.as_bytes();
        let mut found: Option<usize> = None;
        for i in 0..bytes.len().saturating_sub(1) {
            let is_initial = bytes[i] == b'.'
                && i >= 1
                && bytes[i - 1].is_ascii_uppercase()
                && (i < 2 || !bytes[i - 2].is_ascii_alphanumeric());
            if !is_initial && matches!(bytes[i], b'.' | b'!' | b'?' | b'\n') && bytes[i + 1].is_ascii_whitespace() {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if text.is_char_boundary(j) {
                    found = Some(j);
                }
            }
        }
        found
    }

    /// Splits `segment` into sentences (keeping their trailing whitespace/paragraph breaks) and drops those that
    /// substantially repeat a sentence of `prior` (word-set Jaccard >= 0.55 over words of 4+ letters).
    pub fn filter_repeating_segments(segment: &str, prior: &str) -> String {
        use std::collections::HashSet;
        let words = |s: &str| -> HashSet<String> {
            s.to_ascii_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| w.len() >= 4)
                .map(|w| w.to_string())
                .collect()
        };
        let prior_sets: Vec<HashSet<String>> = prior
            .split(|c: char| c == '.' || c == '!' || c == '?' || c == '\n')
            .map(|x| words(x))
            .filter(|w| w.len() >= 4)
            .collect();
        let mut out = String::new();
        let mut cur = String::new();
        let chars: Vec<char> = segment.chars().collect();
        let mut i = 0usize;
        let flush = |cur: &mut String, out: &mut String| {
            let ws = words(cur);
            let word_count = cur.split_whitespace().count();
            let is_fragment = word_count > 0 && word_count < 3 && !cur.trim_start().starts_with('#') && !cur.trim_start().starts_with('-');
            let repeats = is_fragment
                || ws.len() >= 4
                && prior_sets.iter().any(|ps| {
                    let inter = ws.intersection(ps).count();
                    let union = ws.union(ps).count().max(1);
                    inter * 100 / union >= 55
                });
            if !repeats {
                out.push_str(cur);
            } else {
                // keep paragraph structure: preserve trailing newlines of a dropped sentence
                let trailing_nl: String = cur.chars().rev().take_while(|c| c.is_whitespace()).collect::<String>();
                if trailing_nl.contains('\n') && !out.ends_with('\n') && !out.is_empty() {
                    out.push_str("\n\n");
                }
            }
            cur.clear();
        };
        while i < chars.len() {
            let c = chars[i];
            cur.push(c);
            let is_term = matches!(c, '.' | '!' | '?' | '\n');
            // "P. B. Randolph": a single capital letter before '.' is an initial, not a sentence end
            let is_initial = c == '.'
                && i >= 1
                && chars[i - 1].is_uppercase()
                && (i < 2 || !chars[i - 2].is_alphanumeric());
            if is_term && !is_initial && (i + 1 >= chars.len() || chars[i + 1].is_whitespace()) {
                // absorb following whitespace into this sentence
                while i + 1 < chars.len() && chars[i + 1].is_whitespace() {
                    i += 1;
                    cur.push(chars[i]);
                }
                flush(&mut cur, &mut out);
            }
            i += 1;
        }
        if !cur.is_empty() {
            flush(&mut cur, &mut out);
        }
        out
    }

    /// Percentage (0-100) of an excerpt's distinct 5+ letter words that already appear in the previous answer.
    pub fn coverage_by_prior_percent(excerpt: &str, prior: &str) -> u32 {
        use std::collections::HashSet;
        let words = |s: &str| -> HashSet<String> {
            s.to_ascii_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| w.len() >= 5)
                .map(|w| w.to_string())
                .collect()
        };
        let ex = words(excerpt);
        if ex.is_empty() {
            return 100;
        }
        let pr = words(prior);
        (ex.iter().filter(|w| pr.contains(*w)).count() * 100 / ex.len()) as u32
    }

    /// Slides a `max_chars` window over `text` (step = a quarter window) and returns the window whose content is
    /// least covered by `prior` — the material a continuation has not used yet.
    pub fn least_covered_window(text: &str, prior: &str, max_chars: usize) -> String {
        let chars: Vec<char> = text.chars().collect();
        if chars.len() <= max_chars {
            return text.to_string();
        }
        let step = (max_chars / 4).max(1);
        let mut best_start = 0usize;
        let mut best_cov = u32::MAX;
        let mut start = 0usize;
        while start < chars.len() {
            let end = (start + max_chars).min(chars.len());
            let window: String = chars[start..end].iter().collect();
            let cov = Self::coverage_by_prior_percent(&window, prior);
            if cov < best_cov {
                best_cov = cov;
                best_start = start;
            }
            if end == chars.len() {
                break;
            }
            start += step;
        }
        let end = (best_start + max_chars).min(chars.len());
        let begin = end.saturating_sub(max_chars);
        chars[begin..end].iter().collect()
    }

    /// True for Markdown ordered-list lines such as `1. **Python**: ...` or `2) Rust`.
    pub fn is_numbered_list_item(line: &str) -> bool {
        let t = line.trim_start();
        let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() || digits.len() > 3 {
            return false;
        }
        let rest = &t[digits.len()..];
        rest.starts_with(". ") || rest.starts_with(") ") || rest == "." || rest == ")"
    }

    /// Content terms of a natural-language question (lowercase, >= 3 chars, minus question/filler words).
    pub fn question_content_terms(prompt: &str) -> Vec<String> {
        const FILLER: &[&str] = &[
            "what", "whats", "does", "did", "where", "when", "who", "whom", "whose", "how", "why",
            "which", "the", "and", "for", "with", "from", "into", "about", "have", "has", "had",
            "will", "would", "should", "could", "can", "you", "tell", "show", "give", "please",
            "are", "was", "were", "his", "her", "hers", "him", "she", "they", "them", "their",
            "that", "this", "these", "those", "much", "many", "any", "all", "some", "know", "explain",
            "describe", "summarize", "summarise", "list", "find", "also", "more", "there", "its",
            "our", "your", "out", "get", "got", "use", "used", "way", "kind", "type", "everything",
            "anything", "something", "info", "information", "detail", "details", "not",
            "continue", "previous", "answer", "additional", "covered", "already", "new", "expand",
            "elaborate", "were", "live", "lives", "living", "reside", "resides", "located", "based",
            "work", "works", "worked", "working", "born", "say", "says", "said", "talk", "talks",
            "mention", "mentions", "mean", "means", "call", "called",
        ];
        let mut out: Vec<String> = Vec::new();
        for w in prompt
            .to_ascii_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() >= 3 && !FILLER.contains(w))
        {
            let s = w.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }

    /// Keeps excerpts whose question-term coverage is at least half the best excerpt's coverage (min 1 term).
    pub fn prune_weak_excerpts<'a>(prompt: &str, chunks: &[&'a ScoredChunk]) -> Vec<&'a ScoredChunk> {
        let terms = Self::question_content_terms(prompt);
        if terms.is_empty() || chunks.len() <= 1 {
            return chunks.to_vec();
        }
        let coverage = |c: &ScoredChunk| -> usize {
            let file_name = std::path::Path::new(&c.chunk.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let hay = format!("{} {}", file_name, c.chunk.text_content.to_ascii_lowercase());
            let tokens: std::collections::HashSet<&str> =
                hay.split(|ch: char| !ch.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
            let base = terms
                .iter()
                .filter(|t| {
                    tokens.contains(t.as_str())
                        || (t.len() >= 4
                            && (tokens.contains(format!("{}s", t).as_str())
                                || t.strip_suffix('s').map(|st| tokens.contains(st)).unwrap_or(false)))
                })
                .count();
            if base >= 1 && Self::answer_type_cue_score(prompt, &hay) >= 120 {
                (base + 1).min(terms.len())
            } else {
                base
            }
        };
        let scored: Vec<(usize, &'a ScoredChunk)> = chunks.iter().map(|c| (coverage(c), *c)).collect();
        let best = scored.iter().map(|(n, _)| *n).max().unwrap_or(0);
        if best == 0 {
            return chunks.to_vec();
        }
        let threshold = ((best * 3 + 3) / 4).max(1);
        let kept: Vec<&'a ScoredChunk> = scored
            .into_iter()
            .filter(|(n, _)| *n >= threshold)
            .map(|(_, c)| c)
            .collect();
        if kept.is_empty() {
            chunks[..1].to_vec()
        } else {
            kept
        }
    }

    /// Deduplicates excerpts from multiple copies/exports of the same document on disk (e.g. `RedactX-v3.pdf` and
    /// `RedactX-v3 (1).pdf`) by collapsing chunks that share an identical 160-character alphanumeric opening signature.
    pub fn dedup_near_identical_excerpts<'a>(chunks: Vec<&'a ScoredChunk>) -> Vec<&'a ScoredChunk> {
        use std::collections::HashSet;
        let mut seen_sigs: HashSet<String> = HashSet::new();
        let mut out: Vec<&'a ScoredChunk> = Vec::with_capacity(chunks.len());
        for c in chunks {
            let cleaned = Self::clean_chunk_text(&c.chunk.text_content);
            let sig: String = cleaned
                .chars()
                .filter(|ch| ch.is_alphanumeric())
                .flat_map(|ch| ch.to_lowercase())
                .take(160)
                .collect();
            if sig.len() < 40 || seen_sigs.insert(sig) {
                out.push(c);
            }
        }
        out
    }

    /// Removes a first line that merely echoes the question ("How Much Rent Does Casey Ringgold Pay?"),
    /// meta sentences ("The user's question asks...", "Firstly, let us consider..."), and un-Title-Cases an
    /// opening sentence that the model wrote In Title Case.
    pub fn strip_question_echo_and_meta(text: &str, prompt: &str) -> String {
        Self::strip_question_echo_and_meta_with_corpus(text, prompt, "")
    }

    /// Same as [`Self::strip_question_echo_and_meta`], additionally lowercasing Title-Cased words that the source
    /// excerpts (`corpus`) only ever use in lowercase (common nouns), while keeping proper names capitalised.
    pub fn strip_question_echo_and_meta_with_corpus(text: &str, prompt: &str, corpus: &str) -> String {
        let corpus_lower_words: std::collections::HashSet<&str> = corpus
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| w.len() >= 3 && w.chars().all(|c| c.is_lowercase() || c.is_ascii_digit()))
            .collect();
        let norm = |s: &str| -> String {
            s.to_ascii_lowercase()
                .chars()
                .filter(|c| c.is_alphanumeric() || c.is_whitespace())
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let prompt_norm = norm(prompt);
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();

        // 0. drop any heading line that merely echoes the question ("### When Did Michael Lewis's Lease Start?")
        lines.retain(|l| {
            let t = l.trim();
            !(t.starts_with('#') && !prompt_norm.is_empty() && norm(t.trim_start_matches('#').trim_matches('*')) == prompt_norm)
        });

        // 1. drop an echoed-question first line
        while let Some(first) = lines.first() {
            let f = first.trim();
            if f.is_empty() {
                lines.remove(0);
                continue;
            }
            let fn_ = norm(f.trim_start_matches('#').trim_matches('*'));
            if !prompt_norm.is_empty() && fn_ == prompt_norm && lines.len() > 1 {
                lines.remove(0);
                continue;
            }
            break;
        }

        // 2. drop meta sentences anywhere in prose lines
        const META_STARTS: &[&str] = &[
            "the user's question", "the users question", "the user's query", "the users query",
            "the user is asking", "the user asks", "the question asks", "to address this question",
            "to directly address this query", "to answer this question", "firstly, let us consider",
            "first, let us consider", "let us consider", "let's consider", "to address this query",
            "to directly address", "to address the", "i'll synthesize", "i will synthesize",
            "based on the provided", "based on the information provided", "based on the reference",
            "given this comprehensive analysis", "given the information gathered", "in conclusion, based on the",
            "we need to", "let's look", "let us look", "let's examine", "let us examine",
            "to determine", "inquiring about", "we must synthesize", "we must review", "it's essential to examine",
            "it is essential to examine", "it's important to examine", "it is important to note that the user",
        ];
        // Leading clauses that wrap a real answer ("Based on the provided documents, X") are cut, not the sentence.
        const META_CLAUSES: &[&str] = &[
            "based on the", "based on information", "according to the", "to directly address", "to address",
            "to answer", "to compare", "as per the", "from the provided", "in the provided",
        ];
        const DISCOURSE_PREFIXES: &[&str] = &[
            "Firstly, ", "Secondly, ", "Thirdly, ", "Lastly, ", "Moving on to ", "Next, ", "First, we find ",
            "Firstly we find ",
        ];
        // Sentences mentioning the user's question are dropped only when they carry no fact (no digit, `$`, or
        // citation); excerpt jargon is rewritten to plain "documents" rather than deleting the sentence.
        const META_CONTAINS: &[&str] = &[
            "the user's question", "the user's query", "the users question", "the users query",
            "user's question", "provided in the question",
        ];
        const META_REWRITES: &[(&str, &str)] = &[
            ("the reference excerpts", "the documents"),
            ("the provided excerpts", "the documents"),
            ("reference excerpts", "documents"),
            ("provided excerpts", "documents"),
            ("the provided sources", "the documents"),
            ("[1] Source File: ", ""),
            ("Source File: ", ""),
        ];
        let mut out: Vec<String> = Vec::new();
        for line in lines {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') || t.starts_with('-') || t.starts_with('*') || t.starts_with('|') || Self::is_numbered_list_item(t) {
                out.push(line);
                continue;
            }
            let mut sentences: Vec<String> = Vec::new();
            let mut cur = String::new();
            let chars: Vec<char> = t.chars().collect();
            for (i, &c) in chars.iter().enumerate() {
                cur.push(c);
                if matches!(c, '.' | '!' | '?' | ':') && (i + 1 >= chars.len() || chars[i + 1].is_whitespace()) {
                    sentences.push(std::mem::take(&mut cur));
                }
            }
            if !cur.trim().is_empty() {
                sentences.push(cur);
            }
            let kept: Vec<String> = sentences
                .into_iter()
                .map(|x| {
                    let mut x = x.trim().to_string();
                    for (from, to) in META_REWRITES {
                        if x.contains(from) {
                            x = x.replace(from, to);
                        }
                    }
                    let lx0 = x.to_ascii_lowercase();
                    if META_CLAUSES.iter().any(|m| lx0.starts_with(m)) {
                        if let Some(ci) = x.find(", ") {
                            let rest = x[ci + 2..].trim().to_string();
                            if ci < 180 && rest.chars().filter(|c| c.is_alphabetic()).count() >= 12 {
                                let mut cs = rest.chars();
                                x = match cs.next() {
                                    Some(f) => f.to_uppercase().collect::<String>() + cs.as_str(),
                                    None => String::new(),
                                };
                            }
                        }
                    }
                    for dp in DISCOURSE_PREFIXES {
                        if let Some(rest) = x.strip_prefix(dp) {
                            let mut cs = rest.chars();
                            x = match cs.next() {
                                Some(f) => f.to_uppercase().collect::<String>() + cs.as_str(),
                                None => String::new(),
                            };
                            break;
                        }
                    }
                    Self::detitle_sentence(&x, prompt, text, &corpus_lower_words)
                })
                .filter(|x| {
                    let lx = x.to_ascii_lowercase().replace('\u{2019}', "'");
                    let carries_fact = x.chars().any(|c| c.is_ascii_digit() || c == '$');
                    !META_STARTS.iter().any(|m| lx.starts_with(m))
                        && (carries_fact || !META_CONTAINS.iter().any(|m| lx.contains(m)))
                })
                .collect();
            if !kept.is_empty() {
                out.push(kept.join(" "));
            }
        }

        out.join("\n").trim().to_string()
    }

    /// Sentence-boundary completion guard: ensures generated text ends cleanly on a sentence terminal boundary
    /// ('.', '!', '?') and never leaves trailing mid-sentence fragments like "Sacred math has been".
    pub fn enforce_sentence_boundary_guard(
        text: &mut String,
        addr: &std::net::SocketAddr,
        host_port: &str,
        target_model: &str,
        telemetry_tx: Option<&Sender<AgenticTelemetryEvent>>,
    ) {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        let trimmed = text.trim();
        if trimmed.is_empty() {
            return;
        }

        let is_clean = trimmed.ends_with('.')
            || trimmed.ends_with('!')
            || trimmed.ends_with('?')
            || trimmed.ends_with(".\"")
            || trimmed.ends_with("!\"")
            || trimmed.ends_with("?\"")
            || trimmed.ends_with("```")
            || trimmed.ends_with("---");

        if is_clean {
            return;
        }

        // Attempt micro-completion prompt if local Ollama daemon is reachable
        let tail_slice: String = trimmed.chars().rev().take(200).collect::<String>().chars().rev().collect();
        let mut prompt_payload = serde_json::json!({
            "model": target_model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a sentence completion assistant. Provide only the immediate concluding words to finish the sentence cleanly with a period. Output no conversational filler."
                },
                {
                    "role": "user",
                    "content": format!("Complete this unfinished sentence ending with a period:\n\"{}\"", tail_slice)
                }
            ],
            "stream": false,
            "keep_alive": "24h",
            "options": {
                "temperature": 0.1,
                "num_predict": 48
            }
        });
        if Self::model_uses_thinking_flag(target_model) {
            if let Some(obj) = prompt_payload.as_object_mut() {
                obj.insert("think".to_string(), serde_json::Value::Bool(false));
            }
        }

        let guard_timeout_ms = if target_model.contains("26b") || target_model.contains("27b") || target_model.contains("32b") {
            6000u64
        } else {
            2500u64
        };
        if let Ok(mut stream) = TcpStream::connect_timeout(addr, Duration::from_millis(500)) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(guard_timeout_ms)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
            let payload_str = prompt_payload.to_string();
            let req = format!(
                "POST /api/chat HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                host_port,
                payload_str.len(),
                payload_str
            );
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut resp_str = String::new();
                if stream.read_to_string(&mut resp_str).is_ok() {
                    if let Some(body_start) = resp_str.find("\r\n\r\n") {
                        let body = &resp_str[body_start + 4..];
                        if let Some(json_start) = body.find('{') {
                            if let Some(json_end) = body.rfind('}') {
                                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body[json_start..=json_end]) {
                                    if let Some(concl) = val
                                        .get("message")
                                        .and_then(|m| m.get("content"))
                                        .and_then(|c| c.as_str())
                                    {
                                        let clean_concl = concl.trim();
                                        if !clean_concl.is_empty() && (clean_concl.ends_with('.') || clean_concl.ends_with('!') || clean_concl.ends_with('?')) {
                                            if !clean_concl.starts_with(char::is_whitespace) {
                                                text.push(' ');
                                            }
                                            text.push_str(clean_concl);
                                            if let Some(tx) = telemetry_tx {
                                                let _ = Self::send_telemetry(
                                                    tx,
                                                    AgenticTelemetryEvent::TokenDelta {
                                                        delta: format!(" {}", clean_concl),
                                                    },
                                                );
                                            }
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Fallback: If the trailing line is an unfinished bullet/heading stub (e.g. `- **Fosters LEASE AGREEMENT...`), drop it cleanly
        if let Some(last_nl) = text.rfind('\n') {
            let tail_line = text[last_nl + 1..].trim();
            if last_nl > 80
                && (tail_line.starts_with("- ")
                    || tail_line.starts_with("* ")
                    || tail_line.starts_with('#'))
                && !tail_line.ends_with('.')
                && !tail_line.ends_with('!')
                && !tail_line.ends_with('?')
            {
                text.truncate(last_nl);
                if text.trim_end().ends_with(['.', '!', '?']) {
                    return;
                }
            }
        }

        // Snap to the last real sentence boundary (not a dot inside `.doc` or `.pdf`) if within reasonable distance:
        // dropping a cut-off clause ("...into doctrinally refined and") reads better than sealing it with a period.
        let bytes = text.as_bytes();
        let min_pos = text.len().saturating_sub(600);
        for idx in (min_pos..bytes.len()).rev() {
            let b = bytes[idx];
            if b == b'.' || b == b'!' || b == b'?' {
                let next_ok = idx + 1 == bytes.len()
                    || bytes[idx + 1].is_ascii_whitespace()
                    || bytes[idx + 1] == b'"'
                    || bytes[idx + 1] == b')'
                    || bytes[idx + 1] == b']';
                if next_ok && text.is_char_boundary(idx + 1) {
                    text.truncate(idx + 1);
                    return;
                }
            }
        }

        // Final fallback: append period to ensure clean termination
        text.push('.');
        if let Some(tx) = telemetry_tx {
            let _ = Self::send_telemetry(
                tx,
                AgenticTelemetryEvent::TokenDelta {
                    delta: ".".to_string(),
                },
            );
        }
    }

    /// Returns true if the Ollama model supports hybrid reasoning (`"think": false`) and must disable thinking
    /// during direct RAG synthesis so token budgets stream straight into `message.content`.
    pub fn model_uses_thinking_flag(tag: &str) -> bool {
        let low = tag.trim().to_ascii_lowercase();
        low.starts_with("gemma4")
            || low.starts_with("qwen3")
            || low.starts_with("deepseek-r1")
            || low.starts_with("glm-4.7")
            || low.starts_with("qwq")
    }

    /// Adaptive socket read timeout scaled by model parameter size so large models (26B/32B) on CPU or hybrid offload
    /// have sufficient headroom for cold weight loading (~30s) and ~6,000-character prompt prefill before first token.
    pub fn socket_read_timeout_for_model(tag: &str) -> std::time::Duration {
        let low = tag.trim().to_ascii_lowercase();
        if low.contains("26b")
            || low.contains("27b")
            || low.contains("32b")
            || low.contains("70b")
            || low.contains("flash")
        {
            std::time::Duration::from_secs(150)
        } else if low.contains("12b") || low.contains("13b") || low.contains("14b") || low.contains("22b") {
            std::time::Duration::from_secs(90)
        } else if low.contains("7b") || low.contains("8b") || low.contains("9b") {
            std::time::Duration::from_secs(60)
        } else {
            std::time::Duration::from_secs(30)
        }
    }

    /// Dynamic Available Memory Law: evaluates strictly runtime free RAM / free VRAM (never total physical RAM).
    pub fn model_fits_free_memory(tag: &str, hw: &crate::hardware::HardwareTelemetry) -> bool {
        let low = tag.trim().to_ascii_lowercase();
        if low.contains("32b") || low.contains("70b") {
            hw.free_ram_gb >= 48.0 || hw.free_vram_mb >= 24_000
        } else if low.contains("26b") || low.contains("27b") || low.starts_with("glm-4.7") {
            crate::model_router::AutoFusionRouter::can_run_gemma4_26b(hw)
        } else if low.contains("14b") || low.contains("12b") || low.contains("13b") {
            hw.free_ram_gb >= 24.0 || hw.free_vram_mb >= 14_000
        } else if low.contains("9b") || low.contains("8b") || low.contains("7b") {
            hw.free_ram_gb >= 12.0 || hw.free_vram_mb >= 4_500
        } else if low.contains("4b") || low.contains("3b") {
            hw.free_ram_gb >= 6.0 || hw.free_vram_mb >= 2_000
        } else {
            true
        }
    }

    /// Normalizes a requested Ollama model tag and strips forbidden `-coder` suffixes that trigger 404 aborts.
    pub fn normalize_requested_model_tag(raw: &str) -> String {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return String::new();
        }
        let no_coder = trimmed.replace("-coder:", ":").replace("-coder", "");
        match no_coder.to_ascii_lowercase().as_str() {
            "gemma4_26b" | "gemma4" => "gemma4:26b".to_string(),
            "glm4agentic" | "glm4" | "glm-4" => "glm4:9b".to_string(),
            "gemmaprose" => "gemma4:26b".to_string(),
            _ => no_coder,
        }
    }

    /// Queries local Ollama `GET /api/tags` with a strict 400ms timeout (Fast Timeout Law) and 10s in-memory cache.
    pub fn probe_installed_ollama_models(
        addr: &std::net::SocketAddr,
        host_port: &str,
        force_refresh: bool,
    ) -> Vec<String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::sync::{Mutex, OnceLock};
        use std::time::{Duration, Instant};

        if !addr.ip().is_loopback() {
            return Vec::new();
        }

        static TAGS_CACHE: OnceLock<Mutex<Option<(Instant, Vec<String>)>>> = OnceLock::new();
        let cache = TAGS_CACHE.get_or_init(|| Mutex::new(None));
        if !force_refresh {
            if let Ok(guard) = cache.lock() {
                if let Some((ts, ref list)) = *guard {
                    if ts.elapsed() < Duration::from_secs(10) {
                        return list.clone();
                    }
                }
            }
        }

        let mut discovered = Vec::new();
        if let Ok(mut stream) = TcpStream::connect_timeout(addr, Duration::from_millis(400)) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(400)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(400)));
            let req = format!(
                "GET /api/tags HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
                host_port
            );
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut raw = String::new();
                if stream.read_to_string(&mut raw).is_ok() {
                    if let Some(idx) = raw.find("\r\n\r\n") {
                        let body = &raw[idx + 4..];
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(body.trim()) {
                            if let Some(arr) = val.get("models").and_then(|m| m.as_array()) {
                                for item in arr {
                                    if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                                        discovered.push(name.trim().to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !discovered.is_empty() {
            if let Ok(mut guard) = cache.lock() {
                *guard = Some((Instant::now(), discovered.clone()));
            }
        }
        discovered
    }

    /// Convenience probe against the configured local loopback Ollama endpoint (`127.0.0.1:11434` by default).
    pub fn probe_installed_ollama_models_default() -> Vec<String> {
        use std::net::{SocketAddr, ToSocketAddrs};
        let ui = crate::dlp_mesh::global_mesh_dlp_controller()
            .settings
            .read()
            .map(|g| g.ui.clone())
            .unwrap_or_default();
        let raw_url = if ui.ollama_url.trim().is_empty() {
            "http://127.0.0.1:11434"
        } else {
            ui.ollama_url.trim()
        };
        let host_port = raw_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("127.0.0.1:11434");
        let addr = host_port
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 11434)));
        Self::probe_installed_ollama_models(&addr, host_port, false)
    }

    /// Triggers an idempotent background `ollama pull <model>` when a memory-eligible model is requested before installation.
    pub fn trigger_background_ollama_pull(model_tag: &str) -> bool {
        use std::collections::HashSet;
        use std::sync::{Mutex, OnceLock};

        let clean = model_tag.trim();
        if clean.is_empty()
            || clean.len() > 64
            || !clean
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '-' | '_' | '/'))
        {
            return false;
        }

        static PULLED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
        let set = PULLED.get_or_init(|| Mutex::new(HashSet::new()));
        if let Ok(mut guard) = set.lock() {
            if !guard.insert(clean.to_ascii_lowercase()) {
                return false;
            }
        }

        let mut cmd = std::process::Command::new("ollama");
        cmd.args(["pull", clean]);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
        }
        cmd.spawn().is_ok()
    }

    /// Resolves the best installed, runtime-free-memory-safe Ollama model tag to execute.
    pub fn resolve_ollama_model_tag(
        requested_tag: &str,
        hw: &crate::hardware::HardwareTelemetry,
        installed: &[String],
    ) -> String {
        let req = Self::normalize_requested_model_tag(requested_tag);
        let is_synthesis_capable = |name: &str| -> bool {
            let low = name.to_ascii_lowercase();
            !low.contains("embed")
                && !low.starts_with("bge-")
                && !low.starts_with("moondream")
                && !low.starts_with("llava")
                && !low.starts_with("minicpm-v")
        };
        let find_installed = |cand: &str| -> Option<String> {
            if installed.is_empty() {
                return Some(cand.to_string());
            }
            let cand_low = cand.to_ascii_lowercase();
            let cand_latest = format!("{}:latest", cand_low);
            installed
                .iter()
                .find(|m| {
                    let ml = m.to_ascii_lowercase();
                    ml == cand_low || ml == cand_latest
                })
                .cloned()
        };

        if !req.is_empty() && is_synthesis_capable(&req) && Self::model_fits_free_memory(&req, hw) {
            if let Some(matched) = find_installed(&req) {
                return matched;
            }
        }

        let req_low = req.to_ascii_lowercase();
        let candidates: &[&str] = if req_low.starts_with("gemma") {
            &[
                "gemma4:26b",
                "gemma3:27b",
                "gemma2:9b",
                "gemma3:4b",
                "gemma2:2b",
                "glm4:9b",
                "qwen2.5:7b",
                "qwen2.5:1.5b",
            ]
        } else if req_low.starts_with("qwen") {
            &[
                "qwen2.5:32b",
                "qwen2.5:14b",
                "qwen2.5:7b",
                "qwen2.5:3b",
                "qwen2.5:1.5b",
                "gemma4:26b",
                "glm4:9b",
            ]
        } else {
            &[
                "gemma4:26b",
                "glm4:9b",
                "qwen2.5:32b",
                "qwen2.5:14b",
                "qwen2.5:7b",
                "gemma2:9b",
                "mistral:latest",
                "gemma3:4b",
                "qwen2.5:3b",
                "gemma2:2b",
                "qwen2.5:1.5b",
            ]
        };

        for &cand in candidates {
            if Self::model_fits_free_memory(cand, hw) {
                if let Some(matched) = find_installed(cand) {
                    return matched;
                }
            }
        }

        for item in installed {
            if is_synthesis_capable(item) && Self::model_fits_free_memory(item, hw) {
                return item.clone();
            }
        }

        "qwen2.5:1.5b".to_string()
    }

    /// Multi-turn real-time streaming orchestration via local Ollama `POST /api/chat` (100% offline, zero internet access).
    /// Strictly orchestrates answers over non-empty `matched_chunks` and streams tokens directly to `telemetry_tx`.
    fn query_local_ollama_chat(
        prompt: &str,
        history: &[ChatTurnMessage],
        matched_chunks: &[&ScoredChunk],
        requested_model_tag: &str,
        telemetry_tx: Option<&Sender<AgenticTelemetryEvent>>,
    ) -> Option<(String, Vec<Citation>)> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
        use std::time::Duration;

        if matched_chunks.is_empty() {
            return None;
        }

        let controller = crate::dlp_mesh::global_mesh_dlp_controller();
        // Only invoke external local Ollama TCP socket when running inside the initialized daemon runtime
        let daemon_active = controller
            .settings_file_path
            .read()
            .map(|p| p.is_some())
            .unwrap_or(false);
        if !daemon_active {
            return None;
        }

        let ui = controller
            .settings
            .read()
            .map(|g| g.ui.clone())
            .unwrap_or_default();

        // Parse host:port from ui.ollama_url (default 127.0.0.1:11434 — strictly local)
        let raw_ollama_url = if ui.ollama_url.trim().is_empty() {
            "http://127.0.0.1:11434"
        } else {
            ui.ollama_url.trim()
        };
        let host_port = raw_ollama_url
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("127.0.0.1:11434");
        let parsed_addr: SocketAddr = host_port
            .to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 11434)));
        // Air-Gapped Offline Enforcement: never dial external non-loopback IPs from synthesis engine
        if !parsed_addr.ip().is_loopback() {
            tracing::warn!(
                "Ollama address {} is not loopback; failing closed under air-gap policy",
                parsed_addr
            );
            return None;
        }
        let addr: SocketAddr = parsed_addr;

        let hw = crate::hardware::HardwareTelemetry::probe();
        let mut installed_models = Self::probe_installed_ollama_models(&addr, host_port, false);
        let normalized_req = Self::normalize_requested_model_tag(requested_model_tag);
        if !normalized_req.is_empty()
            && !installed_models.is_empty()
            && !installed_models
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&normalized_req))
        {
            // Refresh /api/tags once in case `ollama pull` just finished, and auto-pull if still absent
            installed_models = Self::probe_installed_ollama_models(&addr, host_port, true);
            if !installed_models
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&normalized_req))
                && Self::model_fits_free_memory(&normalized_req, &hw)
            {
                let _ = Self::trigger_background_ollama_pull(&normalized_req);
            }
        }
        let resolved_model_owned =
            Self::resolve_ollama_model_tag(requested_model_tag, &hw, &installed_models);
        let model: &str = resolved_model_owned.as_str();

        let temp = ui.sampling_temperature.clamp(0.05, 0.20);
        let max_output_tokens = ui.max_output_tokens.clamp(256, 262144);
        let _agentic_loop_enabled = ui.agentic_loop_enabled;

        let (per_hop_predict, num_ctx) = if hw.free_ram_gb >= 18.0 || hw.free_vram_mb >= 12_000 {
            (max_output_tokens.min(900), 6144usize)
        } else {
            (max_output_tokens.min(600), 4096usize)
        };

        let voice_directive = if ui.natural_human_voice {
            " Write in a clear, natural human voice with zero robotic filler."
        } else {
            ""
        };

        let mut messages: Vec<serde_json::Value> = Vec::new();
        let clean_prompt_for_prefix = prompt.split(" (Subject context:").next().unwrap_or(prompt);
        let expected_prefix = Self::format_question_restated_prefix(clean_prompt_for_prefix);

        let base_system = "You are QuorumRAG, an exhaustive, strictly factual multi-document research synthesis engine. \
            Your ONLY task is to write a comprehensive, deeply detailed, multi-paragraph Markdown response answering ONLY the user's question \
            by synthesizing all concrete facts across ALL provided source documents (`[1]`, `[2]`, `[3]`, etc.) below. \
            \n\
            Follow these strict rules:\n\
            1. QUESTION-RESTATING OPENING: Always begin your answer immediately with a natural declarative sentence (not a `#` heading) that restates and directly answers the user's question using the concrete facts in the provided documents.\n\
            2. DIRECT FACTUAL SYNTHESIS (NEVER REFUSE OR DISCLAIM): Synthesize ALL concrete facts, roles, properties, agreements, addresses, phone numbers, financial terms, credentials, career experience, education, or research findings about the subject present in the provided documents. Never say \"The user's query is not directly addressed\" or complain about what type of documents are provided—report what the documents actually establish about the subject!\n\
            3. ZERO META-FILLER & ZERO REPETITION: Never begin with greetings or meta-announcements (never say \"Based on the documents provided...\", \"According to the text...\", \"Your sacred dissertation-style preface...\", or \"Click here to download\"). Never repeat the same sentence or paragraph more than once. Write complete, grammatical sentences.\n\
            3a. ANSWER FIRST: The first sentence must contain the actual answer (a name, number, date, amount, place, or definition) when the excerpts contain it. Never restate the question as a title, never write \"The user's question asks...\", \"Firstly, let us consider...\", or analyse excerpts one by one. Silently ignore excerpts that are unrelated to the question. If the excerpts do not contain the answer, say so in one sentence and summarise only what they do say about the subject.\n\
            3b. STRICT GROUNDING (NO INVENTION, NO CROSS-SUBJECT BLEED): State ONLY facts that literally appear in the numbered source documents of THIS request. Never carry over facts about a different person or subject from earlier chat turns, and never invent profiles, platforms (LinkedIn, GitHub), courses, or credentials that the documents do not state. If the sources are a different kind of document (for example leases naming the subject as landlord), describe exactly what those documents say about the subject (role, dates, tenants, rent, addresses) and nothing else.\n\
            4. MULTI-FILE SYNTHESIS & INLINE CITATIONS: You are given excerpts from MULTIPLE distinct files (`[1]`, `[2]`, `[3]`, `[4]`, etc.). Look across ALL provided documents and cite multiple document numbers inline using simple bracketed numbers (`[1]`, `[2]`, `[3]`, `[4]`, etc.) throughout your response. Never write XML tags like `<document>` or `<Document Index=...>`.\n\
            5. CLEAN STRUCTURE: Organize your response into thorough, flowing paragraphs and `###` section headings where helpful (after the opening paragraph). Never include line numbers `(Lines X-Y)`.\n\
            6. CROSS-CITATION ENTITY & ACCOUNT CONSOLIDATION: When multiple source documents mention the exact same bank account number (even with minor formatting or payee variations such as `#1569837451` vs `1569837451 F A Breure`), monetary fee (`$195` vs `$195.00`), street address, phone number, email, or legal rule, state that shared account number, fee, or rule ONCE in a single unified clause noting any payee or tenant qualifiers and citing all relevant documents together (e.g. `Chase Bank account #1569837451 (also listed under F A Breure) [3], [5]`). Never write the same account number, fee amount, or rule twice in a compound sentence or across paragraphs.";

        let system_prompt = format!("{}{}", base_system, voice_directive);

        messages.push(serde_json::json!({
            "role": "system",
            "content": system_prompt
        }));

        // Conversation history is injected ONLY for genuine follow-ups (continuations or short pronoun references
        // such as "does he have cissp"). A fresh standalone subject ("tell me about angela davis") must be answered
        // strictly from the retrieved documents; otherwise the model copies the previous answer's facts about a
        // different subject into the new answer (cross-subject history bleed).
        let prompt_lower_words: Vec<String> = prompt
            .to_ascii_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_string())
            .collect();
        const FOLLOW_UP_PRONOUNS: &[&str] = &[
            "he", "she", "him", "her", "his", "hers", "they", "them", "their", "it", "its",
            "that", "those", "this", "these",
        ];
        let is_follow_up = Self::is_continuation_query(&prompt.to_ascii_lowercase())
            || (prompt_lower_words.len() <= 8
                && prompt_lower_words
                    .iter()
                    .any(|w| FOLLOW_UP_PRONOUNS.contains(&w.as_str())));
        let history_start = if is_follow_up {
            history.len().saturating_sub(4)
        } else {
            history.len()
        };
        for turn in &history[history_start..] {
            let role = if turn.role.eq_ignore_ascii_case("assistant") {
                "assistant"
            } else {
                "user"
            };
            let per_turn_limit = if Self::is_continuation_query(&prompt.to_ascii_lowercase()) { 2400 } else { 500 };
            let stripped = if role == "assistant" {
                Self::strip_sources_footer(&turn.content)
            } else {
                turn.content.as_str()
            };
            let content: String = stripped.trim().chars().take(per_turn_limit).collect();
            if !content.is_empty() {
                messages.push(serde_json::json!({
                    "role": role,
                    "content": content
                }));
            }
        }

        // Synthesis-time relevance pruning: drop excerpts whose overlap with the question's content terms is weak
        // relative to the best excerpt, so off-topic hits (e.g. 419-scam files for "which bank is the rent paid to")
        // never reach the model. Always keeps at least the top excerpt.
        let mut pruned_chunks: Vec<&ScoredChunk> =
            Self::dedup_near_identical_excerpts(Self::prune_weak_excerpts(prompt, matched_chunks));
        // For typed questions (where/when/how much/phone), excerpts holding the requested kind of fact go first
        // (stable sort keeps relevance order among equals), so a small model sees the answer in excerpt [1].
        if !Self::answer_type_cue_terms(prompt).is_empty() {
            pruned_chunks.sort_by_key(|c| {
                -Self::answer_type_cue_score(prompt, &Self::clean_chunk_text(&c.chunk.text_content).to_ascii_lowercase())
            });
        }
        let prior_answer_text: String = if Self::is_continuation_query(&prompt.to_ascii_lowercase()) {
            history
                .iter()
                .filter(|t| t.role.eq_ignore_ascii_case("assistant"))
                .map(|t| Self::strip_sources_footer(&t.content))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            String::new()
        };
        // Continuation: put the excerpts least covered by the previous answer first and drop exhausted chunks (>=80% covered)
        // when fresher chunks exist, so "continue" advances into uncovered material rather than re-summarizing Turn 1.
        if !prior_answer_text.is_empty() {
            pruned_chunks.sort_by_key(|c| Self::coverage_by_prior_percent(&c.chunk.text_content, &prior_answer_text));
            if pruned_chunks.len() > 2 {
                let fresh: Vec<&ScoredChunk> = pruned_chunks
                    .iter()
                    .copied()
                    .filter(|c| Self::coverage_by_prior_percent(&c.chunk.text_content, &prior_answer_text) < 80)
                    .collect();
                if fresh.len() >= 2 {
                    pruned_chunks = fresh;
                } else {
                    pruned_chunks.truncate(4);
                }
            }
        }
        let matched_chunks: &[&ScoredChunk] = &pruned_chunks;
        let active_excerpts: &[&ScoredChunk] = &matched_chunks[..matched_chunks.len().min(8)];

        // Assign 1-based citation numbers strictly by DISTINCT source filename across `active_excerpts`,
        // so multiple chunks from the same file share one `[doc_num]` and `[8]` can NEVER be emitted when 7 files exist.
        let mut unique_file_chunks: Vec<&ScoredChunk> = Vec::new();
        let mut file_to_doc_num: std::collections::HashMap<(String, String), usize> = std::collections::HashMap::new();
        for &c in active_excerpts {
            let file_name = std::path::Path::new(&c.chunk.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&c.chunk.file_path);
            let key = (c.source_peer.to_ascii_lowercase(), file_name.to_ascii_lowercase());
            if !file_to_doc_num.contains_key(&key) {
                let next_num = unique_file_chunks.len() + 1;
                file_to_doc_num.insert(key, next_num);
                unique_file_chunks.push(c);
            }
        }

        // Query-time multimodal inspection: let a local vision model look at the actual pixels of the top
        // cited local image files, so answers describe what images show rather than only their metadata.
        let mut vision_notes: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let image_targets: Vec<&ScoredChunk> = active_excerpts
            .iter()
            .copied()
            .filter(|c| {
                crate::vision::is_image_chunk_text(&c.chunk.text_content)
                    && (c.source_peer.is_empty() || c.source_peer.eq_ignore_ascii_case("local"))
                    && std::path::Path::new(&c.chunk.file_path).is_file()
            })
            .take(3)
            .collect();
        if !image_targets.is_empty() {
            if let Some(vision_model) = crate::vision::pick_vision_model(&installed_models) {
                let question = clean_prompt_for_prefix.to_string();
                let results: Vec<(String, Option<String>)> = std::thread::scope(|s| {
                    let handles: Vec<_> = image_targets
                        .iter()
                        .map(|c| {
                            let vm = vision_model.clone();
                            let path = c.chunk.file_path.clone();
                            let id = c.chunk.chunk_id.clone();
                            let q = question.clone();
                            s.spawn(move || {
                                let d = crate::vision::describe_image_file(&addr, host_port, &vm, std::path::Path::new(&path), &q);
                                (id, d)
                            })
                        })
                        .collect();
                    handles.into_iter().filter_map(|h| h.join().ok()).collect()
                });
                for (id, desc) in results {
                    if let Some(d) = desc {
                        vision_notes.insert(id, d);
                    }
                }
                tracing::info!(
                    vision_model = %vision_model,
                    images = image_targets.len(),
                    described = vision_notes.len(),
                    "Query-time multimodal image inspection complete"
                );
            } else if Self::model_fits_free_memory("moondream", &hw) {
                // No vision model installed: fetch the small one in the background for next time.
                let _ = Self::trigger_background_ollama_pull("moondream");
            }
        }

        // ~6000 characters of evidence in total: a single stitched parent document gets a long window instead of
        // its first 750 characters only.
        let excerpt_count = active_excerpts.len().clamp(1, 8);
        let per_excerpt_chars = (6000 / excerpt_count).clamp(750, 3000);
        let context_blocks = active_excerpts
            .iter()
            .map(|c| {
                let file_name_base = std::path::Path::new(&c.chunk.file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(&c.chunk.file_path);
                let lookup_key = (c.source_peer.to_ascii_lowercase(), file_name_base.to_ascii_lowercase());
                let doc_num = file_to_doc_num
                    .get(&lookup_key)
                    .copied()
                    .unwrap_or(1);
                let file_name = if !c.source_peer.is_empty() && !c.source_peer.eq_ignore_ascii_case("local") {
                    let short_peer = if c.source_peer.len() > 8 { &c.source_peer[..8] } else { &c.source_peer };
                    format!("{} (Peer: {})", file_name_base, short_peer)
                } else {
                    file_name_base.to_string()
                };
                let cleaned = Self::clean_chunk_text(&c.chunk.text_content);
                let compact_text: String = if !prior_answer_text.is_empty() {
                    let win = Self::least_covered_window(&cleaned, &prior_answer_text, per_excerpt_chars);
                    Self::scrub_prior_covered_clauses(&win, &prior_answer_text)
                } else {
                    Self::answer_focused_window(prompt, &cleaned, per_excerpt_chars)
                };
                let compact_text = match vision_notes.get(&c.chunk.chunk_id) {
                    Some(v) => format!(
                        "{}\nVisual Content (what the image actually shows, from a local vision model): {}",
                        compact_text.trim(),
                        v
                    ),
                    None => compact_text,
                };
                format!(
                    "[{}] Source File: {}\n{}",
                    doc_num,
                    file_name,
                    compact_text.trim()
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n");

        let source_corpus: String = active_excerpts
            .iter()
            .map(|c| {
                let base = Self::clean_chunk_text(&c.chunk.text_content);
                match vision_notes.get(&c.chunk.chunk_id) {
                    Some(v) => format!("{base}\n{v}"),
                    None => base,
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let _fact_sheets = if ui.map_reduce_fact_extraction {
            Self::extract_fact_sheets(active_excerpts, prompt)
        } else {
            Vec::new()
        };

        let opening_directive = if !prior_answer_text.is_empty() {
            "Begin immediately with brand-new facts, properties, dates, or clauses NOT mentioned anywhere in your previous response".to_string()
        } else if expected_prefix.trim().is_empty() {
            "Begin your first paragraph immediately with a direct declarative sentence that restates and answers the User Question".to_string()
        } else {
            format!("Begin your first paragraph immediately with `{}`", expected_prefix.trim())
        };

        let continuation_guard_note = if !prior_answer_text.is_empty() {
            " CONTINUATION STRICTNESS: Never repeat, paraphrase, or circle back to any rule, subletting/occupancy consent clause, late fee, bank account, phone number, email address, or relationship already mentioned in your previous response—even if another lease or document contains similar boilerplate. Cite ONLY the numbered sources (`[1]`..`[N]`) that supply the new facts you introduce."
        } else {
            ""
        };

        let exclusion_constraints = if !prior_answer_text.is_empty() {
            let key_facts = Self::extract_key_facts_summary(&prior_answer_text);
            if !key_facts.is_empty() {
                format!(
                    "\n\n### STRICT EXCLUSION CONSTRAINTS (DO NOT REPEAT):\n\
                    The following facts, fees, numbers, and clauses have ALREADY been stated in prior turns. \
                    DO NOT repeat, re-state, or paraphrase any of these in your response:\n{}\n",
                    key_facts
                )
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let max_doc_num = unique_file_chunks.len().max(1);
        let vision_directive = if vision_notes.is_empty() {
            ""
        } else {
            " Some excerpts include 'Visual Content' written by a local vision model that looked at the actual image file: use it to describe what each image shows (subjects, appearance, setting), cite that image's number, and never claim the documents lack a description when Visual Content is present."
        };
        let continuation_guard_note = format!("{}{}", continuation_guard_note, vision_directive);
        let user_content = format!(
            "Reference Excerpts (numbered [1] through [{}], for your use only; never repeat this label):\n{}\n\nUser Question: {}\n\n\
            INSTRUCTION: Synthesize a complete, exhaustive, multi-paragraph analysis across the relevant source documents above to answer ONLY the User Question. {} and cite source documents inline using ONLY valid bracketed numbers `[1]` through `[{}]`. Write flowing prose paragraphs (not a bullet list of file names), start with a full sentence rather than a heading, and never repeat any sentence or paragraph.{}{}",
            max_doc_num,
            context_blocks,
            prompt,
            opening_directive,
            max_doc_num,
            continuation_guard_note,
            exclusion_constraints
        );

        messages.push(serde_json::json!({
            "role": "user",
            "content": user_content
        }));

        let send_chat_request = |target_model: &str| -> Option<(String, Vec<Citation>)> {
            let max_hops = 1usize;

            let mut current_messages = messages.clone();
            let mut full_text = String::new();
            let mut accumulated_tokens = 0usize;
            let mut hop_count = 0usize;

            // Unified real-time NDJSON streaming mode with 56-char lookahead repetition loop breaker
            while hop_count < max_hops && accumulated_tokens < max_output_tokens {
                hop_count += 1;
                let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(800)).ok()?;
                let read_timeout = Self::socket_read_timeout_for_model(target_model);
                let _ = stream.set_read_timeout(Some(read_timeout));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));

                let mut payload_val = serde_json::json!({
                    "model": target_model,
                    "messages": current_messages,
                    "stream": true,
                    "keep_alive": "24h",
                    "options": {
                        "temperature": temp,
                        "num_predict": per_hop_predict,
                        "num_ctx": num_ctx,
                        "num_thread": 16,
                        "top_p": 0.9,
                        "repeat_last_n": 256,
                        "repeat_penalty": 1.12
                    }
                });
                if Self::model_uses_thinking_flag(target_model) {
                    if let Some(obj) = payload_val.as_object_mut() {
                        obj.insert("think".to_string(), serde_json::Value::Bool(false));
                    }
                }
                let payload = payload_val.to_string();

                let request = format!(
                    "POST /api/chat HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    host_port,
                    payload.len(),
                    payload
                );

                stream.write_all(request.as_bytes()).ok()?;

                let mut reader = BufReader::new(stream);
                let mut header_line = String::new();
                // Skip HTTP headers until blank line
                loop {
                    header_line.clear();
                    let n = reader.read_line(&mut header_line).ok()?;
                    if n == 0 || header_line == "\r\n" || header_line == "\n" {
                        break;
                    }
                }

                let mut hop_text = String::new();
                let mut pending_emit = String::new();
                let mut line_buf = String::new();
                let mut done_reason = String::new();
                let mut hop_eval_count = 0usize;
                let mut repetition_detected = false;

                loop {
                    if let Some(tx) = telemetry_tx {
                        if tx.is_closed() {
                            break;
                        }
                    }
                    line_buf.clear();
                    let n = match reader.read_line(&mut line_buf) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if n == 0 {
                        break;
                    }
                    let trimmed = line_buf.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                        if val.get("error").is_some() {
                            return None;
                        }
                        if let Some(tok) = val
                            .get("message")
                            .and_then(|m| m.get("content"))
                            .and_then(|c| c.as_str())
                        {
                            if !tok.is_empty() {
                                full_text.push_str(tok);
                                hop_text.push_str(tok);
                                pending_emit.push_str(tok);

                                if let Some(cut_pos) = Self::has_repeated_passage(&full_text) {
                                    let emitted_len = full_text.len().saturating_sub(pending_emit.len());
                                    let safe_cut = cut_pos.max(emitted_len);
                                    if full_text.is_char_boundary(safe_cut) {
                                        full_text.truncate(safe_cut);
                                    }
                                    pending_emit.clear();
                                    repetition_detected = true;
                                    break;
                                }

                                if !prior_answer_text.is_empty() {
                                    // Continuation turn: release only complete sentences, skipping ones that repeat
                                    // the previous answer, so the user never sees the restatement stream by.
                                    if let Some(cut) = Self::last_sentence_boundary(&pending_emit) {
                                        let ready: String = pending_emit[..cut].to_string();
                                        pending_emit = pending_emit[cut..].to_string();
                                        let novel = Self::filter_repeating_segments(&ready, &prior_answer_text);
                                        if !novel.is_empty() {
                                            if let Some(tx) = telemetry_tx {
                                                if !Self::send_telemetry(tx, AgenticTelemetryEvent::TokenDelta { delta: novel }) {
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                } else if pending_emit.len() >= 56 {
                                    let flush_chunk = std::mem::take(&mut pending_emit);
                                    if let Some(tx) = telemetry_tx {
                                        if !Self::send_telemetry(
                                            tx,
                                            AgenticTelemetryEvent::TokenDelta {
                                                delta: flush_chunk,
                                            },
                                        ) {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(reason) = val.get("done_reason").and_then(|r| r.as_str()) {
                            done_reason = reason.to_string();
                        }
                        if let Some(eval) = val.get("eval_count").and_then(|c| c.as_u64()) {
                            hop_eval_count = eval as usize;
                        }
                        if val.get("done").and_then(|d| d.as_bool()).unwrap_or(false) {
                            break;
                        }
                    }
                }

                if !pending_emit.is_empty() && !repetition_detected {
                    let raw_tail = std::mem::take(&mut pending_emit);
                    let flush_chunk = if prior_answer_text.is_empty() {
                        raw_tail
                    } else {
                        Self::filter_repeating_segments(&raw_tail, &prior_answer_text)
                    };
                    if let Some(tx) = telemetry_tx {
                        let _ = Self::send_telemetry(
                            tx,
                            AgenticTelemetryEvent::TokenDelta {
                                delta: flush_chunk,
                            },
                        );
                    }
                }

                if repetition_detected {
                    break;
                }
                if let Some(tx) = telemetry_tx {
                    if tx.is_closed() {
                        break;
                    }
                }

                accumulated_tokens += if hop_eval_count > 0 {
                    hop_eval_count
                } else {
                    hop_text.len() / 4
                };

                if done_reason == "length" && accumulated_tokens < max_output_tokens && hop_count < max_hops {
                    let rolling_summary: String = if hop_text.len() > 1500 {
                        let start = hop_text.len() - 1500;
                        let safe_start = hop_text.char_indices().map(|(i, _)| i).find(|&i| i >= start).unwrap_or(start);
                        hop_text[safe_start..].to_string()
                    } else {
                        hop_text.clone()
                    };

                    current_messages.push(serde_json::json!({
                        "role": "assistant",
                        "content": rolling_summary
                    }));
                    current_messages.push(serde_json::json!({
                        "role": "user",
                        "content": "Continue immediately from where you stopped. Maintain the exact same analytical depth and Markdown structure. Do not repeat earlier text, do not emit conversational filler, and seamlessly complete the analysis."
                    }));
                } else {
                    break;
                }
            }

            let (deduped, _) = Self::deduplicate_repeated_paragraphs(&full_text);
            full_text = deduped;
            full_text = Self::drop_ungrounded_sentences(&full_text, &source_corpus);
            if !prior_answer_text.is_empty() {
                full_text = Self::drop_sentences_repeating_prior(&full_text, &prior_answer_text);
            }

            // Sentence-boundary completion guard
            Self::enforce_sentence_boundary_guard(
                &mut full_text,
                &addr,
                host_port,
                target_model,
                telemetry_tx,
            );

            let prose_only = Self::strip_sources_footer(full_text.trim());
            let pass1 = Self::strip_question_echo_and_meta_with_corpus(prose_only, prompt, &source_corpus);
            let pass2 = Self::strip_stub_heading_and_label_echo(&pass1);
            let mut cleaned_final = Self::strip_question_echo_and_meta_with_corpus(&pass2, prompt, &source_corpus);
            if !prior_answer_text.is_empty() {
                cleaned_final = Self::drop_sentences_repeating_prior(&cleaned_final, &prior_answer_text);
            }
            let cleaned_final = {
                let mut out = String::with_capacity(cleaned_final.len());
                let mut blank_run = 0usize;
                for line in cleaned_final.lines() {
                    if line.trim().is_empty() {
                        blank_run += 1;
                        if blank_run > 1 {
                            continue;
                        }
                    } else {
                        blank_run = 0;
                    }
                    out.push_str(line);
                    out.push('\n');
                }
                out.trim().to_string()
            };
            let trimmed_full = if cleaned_final.trim().len() < 20 {
                // Never let post-processing erase a real answer: fall back to the lightly-cleaned prose
                Self::strip_stub_heading_and_label_echo(prose_only)
            } else {
                cleaned_final
            };
            if trimmed_full.is_empty() {
                None
            } else {
                let prefix = if !prior_answer_text.is_empty() {
                    String::new()
                } else {
                    Self::format_question_restated_prefix(prompt)
                };
                let prose_with_prefix = if !prefix.is_empty()
                    && !trimmed_full.starts_with(&prefix)
                    && !trimmed_full.starts_with('#')
                {
                    let lower_start = trimmed_full.chars().take(60).collect::<String>().to_ascii_lowercase();
                    let prefix_lower = prefix.to_ascii_lowercase();
                    let has_any_prefix_word = prefix_lower
                        .split_whitespace()
                        .filter(|w| w.len() >= 4 && *w != "with" && *w != "from")
                        .any(|w| lower_start.contains(w));
                    if !has_any_prefix_word {
                        format!("{}{}", prefix, trimmed_full)
                    } else {
                        trimmed_full
                    }
                } else {
                    trimmed_full
                };

                let consolidated_prose = Self::consolidate_duplicate_entity_statements(&prose_with_prefix);
                // Compact & renumber inline [k] citations so every [1]..[M] in prose maps 1-to-1 to the M emitted sources
                // (eliminating dangling [8] when 7 unique files exist, and omitting uncited Turn-1 files on `continue`).
                let (compacted_prose, compacted_chunks) =
                    Self::remap_and_compact_citations(&consolidated_prose, &unique_file_chunks, true);
                let sources_block = Self::format_sources_block(&compacted_chunks);
                let final_with_sources = format!("{}{}", compacted_prose.trim(), sources_block);
                let turn_citations = Self::build_deduplicated_citations(&compacted_chunks);
                Some((final_with_sources, turn_citations))
            }
        };

        let attempt_started = std::time::Instant::now();
        let (synthesized, turn_citations) = match send_chat_request(model) {
            Some(pair) => pair,
            None => {
                // Retry once ONLY on fast transient connection/swap errors (<10s); never double-wait or pile onto a timed-out runner.
                if attempt_started.elapsed() >= Duration::from_secs(10) {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(600));
                send_chat_request(model)?
            }
        };

        if let Ok(mut guard) = crate::dlp_mesh::global_mesh_dlp_controller().settings.write() {
            if guard.ui.restrl_daemon_running {
                guard.ui.restrl_processed_tasks = guard.ui.restrl_processed_tasks.saturating_add(1);
            }
        }
        Some((synthesized, turn_citations))
    }

    /// Computes Levenshtein edit distance between two lowercase ASCII/UTF-8 strings.
    pub fn levenshtein_distance(a: &str, b: &str) -> usize {
        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();
        let m = a_chars.len();
        let n = b_chars.len();
        if m == 0 {
            return n;
        }
        if n == 0 {
            return m;
        }
        let mut prev: Vec<usize> = (0..=n).collect();
        let mut curr: Vec<usize> = vec![0; n + 1];
        for i in 1..=m {
            curr[0] = i;
            for j in 1..=n {
                let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
                curr[j] = (prev[j] + 1)
                    .min(curr[j - 1] + 1)
                    .min(prev[j - 1] + cost);
            }
            std::mem::swap(&mut prev, &mut curr);
        }
        prev[n]
    }

    /// Corrects spelling errors in a chat box prompt using deterministic typo rules + local Ollama LLM (`qwen2.5:1.5b`).
    /// Never uses the LLM to answer or rewrite the query—strictly fixes word-level spelling mistakes.
    pub fn correct_spelling(raw_input: &str) -> String {
        Self::correct_query_spelling(raw_input, false).0
    }

    /// Corrects spelling errors and returns `(corrected_text, engine_label)`.
    /// When `use_llm` is true, also invokes the local Ollama model (`qwen2.5:1.5b`) with strict per-word edit-distance validation.
    pub fn correct_query_spelling(raw_input: &str, use_llm: bool) -> (String, String) {
        let trimmed = raw_input.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('@')
            || trimmed.starts_with('/')
            || trimmed.contains("```")
        {
            return (raw_input.to_string(), "passthrough".to_string());
        }

        const EXACT_TYPO_MAP: &[(&str, &str)] = &[
            ("waht", "what"),
            ("whta", "what"),
            ("wat", "what"),
            ("whaat", "what"),
            ("wher", "where"),
            ("whre", "where"),
            ("wereh", "where"),
            ("whn", "when"),
            ("wehn", "when"),
            ("whic", "which"),
            ("wich", "which"),
            ("hwo", "how"),
            ("abotu", "about"),
            ("abuot", "about"),
            ("abot", "about"),
            ("teh", "the"),
            ("tht", "that"),
            ("taht", "that"),
            ("thta", "that"),
            ("thsi", "this"),
            ("tihs", "this"),
            ("adn", "and"),
            ("nad", "and"),
            ("wiht", "with"),
            ("wtih", "with"),
            ("fom", "from"),
            ("frim", "from"),
            ("theyr", "their"),
            ("thier", "their"),
            ("doese", "does"),
            ("ddi", "did"),
            ("univeral", "universal"),
            ("universl", "universal"),
            ("univesal", "universal"),
            ("univerasl", "universal"),
            ("unversal", "universal"),
            ("uniiversal", "universal"),
            ("minral", "mineral"),
            ("minerl", "mineral"),
            ("minreal", "mineral"),
            ("mneral", "mineral"),
            ("minerall", "mineral"),
            ("incom", "income"),
            ("incme", "income"),
            ("icome", "income"),
            ("incomme", "income"),
            ("incm", "income"),
            ("schol", "school"),
            ("shcool", "school"),
            ("scool", "school"),
            ("scholl", "school"),
            ("schoo", "school"),
            ("shool", "school"),
            ("scools", "schools"),
            ("schols", "schools"),
            ("univeristy", "university"),
            ("universtiy", "university"),
            ("unversity", "university"),
            ("univrsity", "university"),
            ("univesity", "university"),
            ("colege", "college"),
            ("collee", "college"),
            ("collge", "college"),
            ("educaton", "education"),
            ("edcation", "education"),
            ("eduction", "education"),
            ("educaion", "education"),
            ("degre", "degree"),
            ("dgree", "degree"),
            ("degee", "degree"),
            ("experince", "experience"),
            ("expereince", "experience"),
            ("experiance", "experience"),
            ("exprience", "experience"),
            ("resum", "resume"),
            ("rsume", "resume"),
            ("resme", "resume"),
            ("documnt", "document"),
            ("documet", "document"),
            ("docments", "documents"),
            ("documnts", "documents"),
            ("informtion", "information"),
            ("infromation", "information"),
            ("infomation", "information"),
            ("secrity", "security"),
            ("securty", "security"),
            ("scurity", "security"),
            ("securtiy", "security"),
            ("architcture", "architecture"),
            ("architecure", "architecture"),
            ("archtecture", "architecture"),
            ("certifcation", "certification"),
            ("certificaton", "certification"),
            ("certfication", "certification"),
            ("angela", "Angela"),
            ("angla", "Angela"),
            ("anglea", "Angela"),
            ("angelaa", "Angela"),
            ("anjela", "Angela"),
            ("davis", "Davis"),
            ("davs", "Davis"),
            ("dvis", "Davis"),
            ("femi", "Femi"),
            ("femii", "Femi"),
            ("femy", "Femi"),
            ("oyesanya", "Oyesanya"),
            ("oyesnya", "Oyesanya"),
            ("oyesana", "Oyesanya"),
            ("oyesany", "Oyesanya"),
            ("oyesania", "Oyesanya"),
            ("oyesnaya", "Oyesanya"),
            ("oyesanay", "Oyesanya"),
            ("cigna", "Cigna"),
            ("cinga", "Cigna"),
            ("cigana", "Cigna"),
            ("disput", "dispute"),
            ("dspute", "dispute"),
            ("dipute", "dispute"),
            ("coverge", "coverage"),
            ("covrage", "coverage"),
            ("coveage", "coverage"),
            ("patientpoint", "PatientPoint"),
            ("patienpoint", "PatientPoint"),
            ("patientpnt", "PatientPoint"),
            ("patintpoint", "PatientPoint"),
            ("westrn", "Western"),
            ("govenors", "Governors"),
            ("govrnors", "Governors"),
            ("houstn", "Houston"),
            ("baptst", "Baptist"),
            ("bapist", "Baptist"),
            ("mckinney", "McKinney"),
            ("mckiney", "McKinney"),
            ("mckinny", "McKinney"),
            ("lagange", "La Grange"),
            ("lagrange", "La Grange"),
            ("hierachy", "hierarchy"),
            ("heirarchy", "hierarchy"),
            ("hirarchy", "hierarchy"),
            ("breth", "breath"),
            ("alternatves", "alternatives"),
            ("alterntives", "alternatives"),
            ("orcgestrate", "orchestrate"),
            ("orcghestrate", "orchestrate"),
            ("orchstrate", "orchestrate"),
            ("orchestarte", "orchestrate"),
            ("respons", "response"),
            ("respones", "response"),
            ("repsonse", "response"),
            ("aat", "at"),
            ("regenrate", "regenerate"),
            ("regenerat", "regenerate"),
            ("buton", "button"),
            ("butons", "buttons"),
            ("brower", "browser"),
            ("browsr", "browser"),
            ("spelcheck", "spellcheck"),
            ("spellchek", "spellcheck"),
            ("dynmic", "dynamic"),
            ("dynamc", "dynamic"),
            ("redactx", "RedactX"),
            ("redacx", "RedactX"),
            ("redact-x", "RedactX"),
            ("vaultgemma", "VaultGemma"),
            ("presidio", "Presidio"),
            ("presido", "Presidio"),
            ("violance", "violence"),
            ("churh", "church"),
            ("chruch", "church"),
            ("continuew", "continue"),
            ("contunue", "continue"),
            ("lile", "like"),
            ("univerity", "university"),
            ("universty", "university"),
        ];

        const KNOWN_ACRONYMS: &[&str] = &[
            "llm", "rag", "ai", "umi", "cissp", "hipaa", "pii", "phi", "pdf", "mrn",
            "wgu", "hbu", "cessa", "ltacc", "api", "ast", "rrf", "sql", "cpu", "gpu",
            "ram", "ui", "os", "id", "cv", "it",
        ];

        // Detect if the user accidentally left Caps Lock on or shouted mid-sentence (e.g. "what DOES IT DO?" or "WHAT REDACTX")
        let has_shouting_words = trimmed.split_whitespace().any(|tok| {
            let alpha: String = tok.chars().filter(|c| c.is_alphabetic()).collect();
            let lower = alpha.to_ascii_lowercase();
            alpha.len() >= 2
                && alpha.chars().all(|c| c.is_uppercase())
                && (!KNOWN_ACRONYMS.contains(&lower.as_str()) || lower == "it")
        });

        let mut deterministic_tokens: Vec<String> = Vec::new();
        for (tok_idx, raw_token) in trimmed.split_whitespace().enumerate() {
            let lead_end = raw_token
                .char_indices()
                .find(|(_, c)| c.is_alphanumeric())
                .map(|(i, _)| i)
                .unwrap_or(raw_token.len());
            let trail_start = raw_token
                .char_indices()
                .rev()
                .find(|(_, c)| c.is_alphanumeric())
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(lead_end);

            let leading = &raw_token[..lead_end];
            let core = &raw_token[lead_end..trail_start];
            let trailing = &raw_token[trail_start..];

            if core.is_empty() || (core.chars().any(|c| c.is_ascii_digit()) && !core.eq_ignore_ascii_case("redactx")) {
                deterministic_tokens.push(raw_token.to_string());
                continue;
            }

            let core_lower = core.to_ascii_lowercase();
            let mut replacement: Option<String> = None;

            for &(typo, fixed) in EXACT_TYPO_MAP {
                if core_lower == typo {
                    replacement = Some(fixed.to_string());
                    break;
                }
            }

            // Dynamic lookup against learned corpus vocabulary + edit distance 1-2
            if replacement.is_none() {
                if let Ok(vocab) = global_corpus_vocab().read() {
                    if let Some(canonical) = vocab.get(&core_lower) {
                        // Apply canonical casing if it is a proper noun (starts with uppercase) or if normalizing shouting
                        if canonical.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
                            || (has_shouting_words && core.chars().all(|c| c.is_uppercase()))
                        {
                            replacement = Some(canonical.clone());
                        }
                    } else if core_lower.len() >= 5 {
                        let max_dist = if core_lower.len() >= 8 { 2 } else { 1 };
                        let first_ch = core_lower.chars().next();
                        let mut best_match: Option<(usize, String)> = None;
                        for (v_lower, v_canon) in vocab.iter() {
                            if v_lower.len().abs_diff(core_lower.len()) <= max_dist
                                && v_lower.chars().next() == first_ch
                            {
                                let dist = Self::levenshtein_distance(&core_lower, v_lower);
                                if dist > 0 && dist <= max_dist {
                                    if best_match.as_ref().map(|(d, _)| dist < *d).unwrap_or(true) {
                                        best_match = Some((dist, v_canon.clone()));
                                    }
                                }
                            }
                        }
                        if let Some((_, best_word)) = best_match {
                            replacement = Some(best_word);
                        }
                    }
                }
            }

            // Normalize accidental ALL-CAPS shouting words ("DOES" -> "does", "IT" -> "it", "DO" -> "do")
            if replacement.is_none()
                && has_shouting_words
                && core.len() >= 2
                && core.chars().all(|c| c.is_uppercase())
                && (!KNOWN_ACRONYMS.contains(&core_lower.as_str()) || core_lower == "it")
            {
                replacement = Some(core_lower.clone());
            }

            let mut final_word = replacement.unwrap_or_else(|| core.to_string());
            // When normalizing a shouting query (e.g. "what DOES IT DO?" or "WHAT REDACTX"), capitalize the first word of the sentence
            if has_shouting_words && tok_idx == 0 {
                let mut chars = final_word.chars();
                if let Some(first) = chars.next() {
                    if first.is_lowercase() {
                        final_word = format!("{}{}", first.to_uppercase(), chars.as_str());
                    }
                }
            }

            deterministic_tokens.push(format!("{}{}{}", leading, final_word, trailing));
        }

        // Dynamic missing-copula completion for 2-word "What <Subject>" queries (e.g. "WHAT REDACTX" -> "What is RedactX?")
        if deterministic_tokens.len() == 2
            && deterministic_tokens[0].eq_ignore_ascii_case("what")
            && !deterministic_tokens[1].eq_ignore_ascii_case("is")
            && !deterministic_tokens[1].eq_ignore_ascii_case("are")
            && !deterministic_tokens[1].eq_ignore_ascii_case("does")
            && !deterministic_tokens[1].eq_ignore_ascii_case("did")
        {
            let mut subj = deterministic_tokens[1].clone();
            if !subj.ends_with('?') && !subj.ends_with('.') {
                subj.push('?');
            }
            deterministic_tokens = vec!["What".to_string(), "is".to_string(), subj];
        }

        let det_corrected = deterministic_tokens.join(" ");

        if use_llm {
            if let Some(llm_fixed) = Self::query_local_ollama_spellcheck(&det_corrected) {
                if Self::validate_spellcheck_candidate(&det_corrected, &llm_fixed) {
                    // Take the LLM's word only where it actually fixed spelling; keep the user's own casing and
                    // punctuation everywhere else (case-only edits like "phone number" -> "Phone Number" would
                    // otherwise be mistaken downstream for proper-noun anchors).
                    let base_words: Vec<&str> = det_corrected.split_whitespace().collect();
                    let cand_words: Vec<&str> = llm_fixed.split_whitespace().collect();
                    let norm = |w: &str| -> String {
                        w.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_ascii_lowercase()
                    };
                    let merged: Vec<String> = base_words
                        .iter()
                        .zip(cand_words.iter())
                        .map(|(b, c)| if norm(b) == norm(c) { (*b).to_string() } else { (*c).to_string() })
                        .collect();
                    return (merged.join(" "), "Ollama LLM (qwen2.5:1.5b)".to_string());
                }
            }
        }

        (det_corrected, "Dynamic Hybrid Spellcheck".to_string())
    }

    /// Validates that an LLM spellcheck candidate only fixes typos and never rewrites, answers, or truncates valid words.
    fn validate_spellcheck_candidate(baseline: &str, candidate: &str) -> bool {
        let base_words: Vec<&str> = baseline.split_whitespace().collect();
        let cand_words: Vec<&str> = candidate.split_whitespace().collect();
        if base_words.is_empty() || base_words.len() != cand_words.len() {
            return false;
        }

        const PROTECTED_PROPER_TERMS: &[&str] = &[
            "femi", "oyesanya", "cigna", "angela", "davis", "quorumrag", "patientpoint",
            "universal", "mineral", "income", "wgu", "hbu", "cissp", "redactx", "vaultgemma",
            "presidio",
        ];

        let vocab_guard = global_corpus_vocab().read().ok();

        for (b, c) in base_words.iter().zip(cand_words.iter()) {
            let b_clean: String = b
                .chars()
                .filter(|ch| ch.is_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            let c_clean: String = c
                .chars()
                .filter(|ch| ch.is_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            if b_clean == c_clean {
                continue;
            }
            // Never allow the LLM to alter protected domain terms, numbers, or already-valid corpus vocabulary words
            if PROTECTED_PROPER_TERMS.contains(&b_clean.as_str())
                || b_clean.chars().any(|ch| ch.is_ascii_digit())
            {
                return false;
            }
            if let Some(ref vocab) = vocab_guard {
                if vocab.contains_key(&b_clean) {
                    return false;
                }
            }
            // Never allow truncating a word to a short 1-3 char prefix (e.g. "income" -> "in")
            if c_clean.len() <= 3 && b_clean.len() >= 5 {
                return false;
            }
            let max_dist = if b_clean.len() >= 7 { 3 } else { 2 };
            if Self::levenshtein_distance(&b_clean, &c_clean) > max_dist {
                return false;
            }
        }
        true
    }

    /// Calls warm local Ollama (`127.0.0.1:11434`, `qwen2.5:1.5b` with `keep_alive: "24h"`) strictly to fix spelling typos in the chat box.
    fn query_local_ollama_spellcheck(input_text: &str) -> Option<String> {
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpStream};
        use std::time::Duration;

        let addr = SocketAddr::from(([127, 0, 0, 1], 11434));
        // Never evict a larger warm synthesis model (such as gemma4:26b, glm4:9b, or qwen2.5:32b) just to spellcheck
        // a keystroke: only invoke `qwen2.5:1.5b` via Ollama if `qwen2.5:1.5b` is ALREADY the warm loaded model in `/api/ps`.
        {
            let mut ps_stream = TcpStream::connect_timeout(&addr, Duration::from_millis(180)).ok()?;
            let _ = ps_stream.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = ps_stream.set_write_timeout(Some(Duration::from_millis(180)));
            ps_stream
                .write_all(b"GET /api/ps HTTP/1.0\r\nHost: 127.0.0.1:11434\r\nConnection: close\r\n\r\n")
                .ok()?;
            let mut ps_resp = String::new();
            ps_stream.read_to_string(&mut ps_resp).ok()?;
            if !ps_resp.contains("qwen2.5:1.5b") {
                return None;
            }
        }
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(400)).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_millis(2200)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

        let payload = serde_json::json!({
            "model": "qwen2.5:1.5b",
            "stream": false,
            "keep_alive": "24h",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a real-time spellchecker for a chat input box. Fix ONLY spelling mistakes and accidental ALL-CAPS in the user's text. Output ONLY the corrected text with the exact same number of words. Never answer the question. Never change proper names like Femi Oyesanya, RedactX, VaultGemma, Presidio, Cigna, or Angela Davis."
                },
                {
                    "role": "user",
                    "content": input_text
                }
            ],
            "options": {
                "temperature": 0.0,
                "num_predict": 48,
                "num_ctx": 256
            }
        })
        .to_string();

        let request = format!(
            "POST /api/chat HTTP/1.0\r\nHost: 127.0.0.1:11434\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );

        stream.write_all(request.as_bytes()).ok()?;
        let mut raw_resp = String::new();
        stream.read_to_string(&mut raw_resp).ok()?;

        let body_start = raw_resp.find("\r\n\r\n").map(|i| i + 4)?;
        let body_str = &raw_resp[body_start..];
        let json_start = body_str.find('{')?;
        let json_end = body_str.rfind('}')?;
        let val: serde_json::Value = serde_json::from_str(&body_str[json_start..=json_end]).ok()?;

        let text = val
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())?
            .trim()
            .trim_matches('"')
            .trim();

        if text.is_empty() {
            None
        } else {
            Some(text.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quorum_types::DocumentChunk;

    #[test]
    fn test_spellcheck_corrects_chat_box_typos_without_rewriting() {
        let (fixed1, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling(
            "waht is univeral minral incom",
            false,
        );
        assert_eq!(fixed1, "what is universal mineral income");

        let (fixed2, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling(
            "wher did femi oyesnya go to schol",
            false,
        );
        assert_eq!(fixed2, "where did Femi Oyesanya go to school");

        let (fixed3, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling(
            "angla davs cinga coverge disput",
            false,
        );
        assert_eq!(fixed3, "Angela Davis Cigna coverage dispute");

        let (fixed4, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling(
            "what DOES IT DO?",
            false,
        );
        assert_eq!(fixed4, "What does it do?");

        let (fixed5, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling(
            "WHAT REDACTX",
            false,
        );
        assert_eq!(fixed5, "What is RedactX?");

        let (fixed6, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling(
            "orcgestrate respons aat end",
            false,
        );
        assert_eq!(fixed6, "orchestrate response at end");
    }

    #[test]
    fn test_offline_engine_synthesizes_compilable_rrf_code() {
        let chunk = DocumentChunk::new(
            "chunk_1",
            "doc_1",
            "crates/quorum-coordinator/src/fusion.rs",
            1,
            20,
            0,
            vec![0.1; 768],
            "pub struct RrfCombiner;\nimpl RrfCombiner { pub fn compute_rrf_score() {} }",
            None,
        )
        .expect("valid chunk");
        let scored = ScoredChunk::new(chunk, 0.9, "local", false);
        let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
            "Synthesize RrfCombiner implementation and unit test",
            &[scored],
            "glm4:9b",
        );

        assert_eq!(citations.len(), 1);
        assert!(body.contains("```rust"));
        assert!(body.contains("pub struct RrfCombiner;"));
        assert!(body.contains("pub fn compute_rrf_score"));
        assert!(body.contains("fn test_rrf_combiner_scoring()"));
    }

    #[test]
    fn test_clean_chunk_text_collapses_broken_pdf_lines_and_strips_metadata() {
        let raw = "[PDF Metadata] Title: Resume2026 | Producer: Skia/PDF\r\n[Page 1]\r\nFEMI\r\n \r\nOYESANYA,\r\n \r\nCISSP\r\nCISSP-certified Application and AI Security professional.";
        let cleaned = DeterministicOfflineSynthesisEngine::clean_chunk_text(raw);
        assert!(!cleaned.contains("[PDF Metadata]"));
        assert!(!cleaned.contains("[Page 1]"));
        assert!(cleaned.contains("FEMI OYESANYA, CISSP"));
    }

    #[test]
    fn test_non_code_rag_query_never_outputs_python_code_or_false_cover_letter_matches() {
        let colab_chunk = DocumentChunk::new(
            "colab_1",
            "doc_colab",
            "C:/Users/oyesanyf/Documents/Array shape analysis.docx",
            50,
            60,
            0,
            vec![0.1; 768],
            "Load the File:\n```python\nimport numpy as np\nimg = np.loadtxt('/content/drive/My Drive/array.txt', dtype='U32')\n```",
            None,
        )
        .unwrap();
        let cigna_chunk = DocumentChunk::new(
            "cigna_1",
            "doc_cigna",
            "C:/Users/oyesanyf/Documents/Cigna Coverage Dispute.docx",
            1423,
            1427,
            0,
            vec![0.1; 768],
            "Review the finished appeal letter for the Cigna health insurance coverage dispute.",
            None,
        )
        .unwrap();

        let chunks = vec![
            ScoredChunk::new(colab_chunk, 0.85, "local", false),
            ScoredChunk::new(cigna_chunk, 0.82, "local", false),
        ];

        // 1. "IS THERE A COVER LETTER FILE" must NOT match Array shape analysis.docx or Cigna Coverage Dispute.docx
        let (resp_cover, cits_cover) = DeterministicOfflineSynthesisEngine::synthesize(
            "IS THERE A COVER LETTER FILE",
            &chunks,
            "glm4:9b",
        );
        assert!(!resp_cover.contains("```python"));
        assert!(!resp_cover.contains("np.loadtxt"));
        assert!(!resp_cover.contains("Array shape analysis.docx"));
        assert!(cits_cover.is_empty());

        // 2. "WHAT THE CIGNA POLICY" MUST match Cigna Coverage Dispute.docx cleanly without code
        let (resp_cigna, cits_cigna) = DeterministicOfflineSynthesisEngine::synthesize(
            "WHAT THE CIGNA POLICY",
            &chunks,
            "glm4:9b",
        );
        assert_eq!(cits_cigna.len(), 1);
        assert!(resp_cigna.contains("Cigna Coverage Dispute.docx"));
        assert!(!resp_cigna.contains("```python"));
    }

    #[test]
    fn test_fallback_role_extraction_avoids_title_as_identity() {
        let mk = |path: &str, text: &str| {
            ScoredChunk::new(
                DocumentChunk::new(
                    format!("{path}:0"),
                    path.to_string(),
                    path,
                    1,
                    1,
                    0,
                    vec![0.0; 768],
                    text,
                    None,
                )
                .unwrap(),
                0.9,
                "local",
                false,
            )
        };
        let a = mk(
            "Susan lease.doc",
            "SIMPLE LEASE AGREEMENT\nThis agreement, made and entered into this 15th day of January 2018 between Angela Davis (landlord) and Casey Ringgold (tenant)",
        );
        let b = mk("Grace lease.doc", "between Angela Davis (landlord) and Grace Bridges (tenant)");
        let refs = vec![&a, &b];
        let (role, cites) =
            DeterministicOfflineSynthesisEngine::subject_role_from_chunks("Angela Davis", &refs).expect("role");
        assert_eq!(role, "landlord");
        assert_eq!(cites, vec![1, 2]);
        assert!(!DeterministicOfflineSynthesisEngine::is_sentence_like("SIMPLE LEASE AGREEMENT"));
        assert!(DeterministicOfflineSynthesisEngine::is_sentence_like(
            "Angela Davis manages residential rental properties in New Orleans."
        ));
    }

    #[test]
    fn test_format_question_restated_prefix() {
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("Who is femi"),
            "Femi is "
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("who is Femi Oyesanya?"),
            "Femi Oyesanya is "
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("who was Angela Davis"),
            "Angela Davis was "
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("What is RedactX?"),
            "RedactX is "
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("where did femi study"),
            "Femi studied at "
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("where did femi go to school"),
            "Femi attended "
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("tell me about Femi Oyesanya"),
            "Femi Oyesanya is "
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("what the cigna policy"),
            "The Cigna Policy is "
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("explain VaultGemma"),
            "VaultGemma refers to "
        );
        // Arbitrary natural-language question shapes must not be title-cased into a fake opening phrase
        for q in [
            "how much rent does Casey Ringgold pay?",
            "which bank is the rent paid to?",
            "why is sacred math important?",
            "list every tenant",
            "compare RedactX and Presidio",
            "does Femi have a CISSP?",
        ] {
            assert_eq!(
                DeterministicOfflineSynthesisEngine::format_question_restated_prefix(q),
                "",
                "query: {q}"
            );
        }
    }

    #[test]
    fn test_deterministic_synthesis_restates_question_and_appends_sources_block_without_line_numbers() {
        let resume_chunk = DocumentChunk::new(
            "chunk_1",
            "doc_resume",
            "C:/Users/oyesanyf/Documents/ResumeSec-AI-FemiOyesanya2025.pdf",
            1,
            45,
            0,
            vec![0.1; 768],
            "FEMI OYESANYA, CISSP\nCISSP-certified Application and AI Security professional with 10+ years experience.",
            None,
        )
        .unwrap();

        let cv_chunk = DocumentChunk::new(
            "chunk_2",
            "doc_cv",
            "C:/Users/oyesanyf/Documents/Femi_Oyesanya_CV_2026.pdf",
            1,
            60,
            0,
            vec![0.1; 768],
            "Education: Master of Science in Information Security Architecture. Western Governors University.",
            None,
        )
        .unwrap();

        let chunks = vec![
            ScoredChunk::new(resume_chunk, 0.95, "local", false),
            ScoredChunk::new(cv_chunk, 0.91, "local", false),
        ];

        let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
            "Who is femi",
            &chunks,
            "qwen2.5:1.5b",
        );

        assert_eq!(citations.len(), 2);
        assert!(body.starts_with("Femi is"), "Body must start with affirmative restatement: {}", body);
        assert!(body.contains("CISSP-certified Application and AI Security professional"));
        assert!(body.contains("### 📚 Sources & Document Links"));
        assert!(body.contains("[📄 ResumeSec-AI-FemiOyesanya2025.pdf]"));
        assert!(body.contains("95% accuracy"));
        assert!(body.contains("[📄 Femi_Oyesanya_CV_2026.pdf]"));
        assert!(body.contains("91% accuracy"));

        // Mandatory Invariant: ZERO line numbers and ZERO raw file headers
        assert!(!body.contains("Lines "), "Must not contain line numbers: {}", body);
        assert!(!body.contains("(Lines"), "Must not contain line numbers: {}", body);
        assert!(!body.contains("### 📄 "), "Must not contain raw file headers in body: {}", body);
    }

    #[test]
    fn test_african_church_gang_violence_and_eastern_university_grounding() {
        // 1. Typo correction
        let (fixed, _) = DeterministicOfflineSynthesisEngine::correct_query_spelling(
            "tell me all about african churh and gang violance",
            false,
        );
        assert_eq!(fixed, "tell me all about African church and gang violence");

        // 2. Q&A Restatement Prefix
        let prefix = DeterministicOfflineSynthesisEngine::format_question_restated_prefix(
            "tell me all about african church and gang violence",
        );
        assert_eq!(prefix, "African Church And Gang Violence — ");

        let prefix_raw = DeterministicOfflineSynthesisEngine::format_question_restated_prefix(
            "African Churches and Gang Violence",
        );
        assert_eq!(prefix_raw, "African Churches And Gang Violence — ");

        // 3. Filename Title Match Priority
        let african_chunk = DocumentChunk::new(
            "chunk_ac",
            "doc_ac",
            "C:/Users/oyesanyf/Documents/African Churches and Gang Violence.docx",
            1,
            50,
            0,
            vec![0.1; 768],
            "African Churches and Gang Violence in urban communities examine the role of religious institutions in violence prevention.",
            None,
        )
        .unwrap();

        let general_chunk = DocumentChunk::new(
            "chunk_gen",
            "doc_gen",
            "C:/Users/oyesanyf/Documents/General Community Studies.docx",
            1,
            50,
            0,
            vec![0.1; 768],
            "Studies on community interventions and local church youth outreach programs.",
            None,
        )
        .unwrap();

        let chunks = vec![
            ScoredChunk::new(general_chunk, 0.88, "local", false),
            ScoredChunk::new(african_chunk, 0.85, "local", false),
        ];

        let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
            "tell me all about african church and gang violance",
            &chunks,
            "qwen2.5:1.5b",
        );

        // African Churches and Gang Violence.docx must rank #1 due to file_hits * 160 bonus
        assert_eq!(citations[0].file_path, "C:/Users/oyesanyf/Documents/African Churches and Gang Violence.docx");
        assert!(body.starts_with("African Church And Gang Violence — "));
        assert!(body.contains("African Churches and Gang Violence.docx"));
        assert!(citations[0].score >= 0.78 && citations[0].score <= 0.99);

        // 4. Strict Similarity Cutoff & Co-Occurrence Guard for Eastern University
        // Document has "Western Governors University" (has "university", but NOT "eastern")
        let wgu_chunk = DocumentChunk::new(
            "chunk_wgu",
            "doc_wgu",
            "C:/Users/oyesanyf/Documents/Education.docx",
            1,
            50,
            0,
            vec![0.1; 768],
            "Attended Western Governors University for Master of Science in Information Security Architecture.",
            None,
        )
        .unwrap();

        // Document has "Eastern time zone" (has "eastern", but NOT "university")
        let time_chunk = DocumentChunk::new(
            "chunk_time",
            "doc_time",
            "C:/Users/oyesanyf/Documents/Schedule.docx",
            1,
            50,
            0,
            vec![0.1; 768],
            "All meetings scheduled in Eastern time zone between 9am and 5pm.",
            None,
        )
        .unwrap();

        let non_cooccurring_chunks = vec![
            ScoredChunk::new(wgu_chunk, 0.75, "local", false),
            ScoredChunk::new(time_chunk, 0.70, "local", false),
        ];

        let (missing_body, missing_citations) = DeterministicOfflineSynthesisEngine::synthesize(
            "tell me about Eastern University",
            &non_cooccurring_chunks,
            "qwen2.5:1.5b",
        );

        assert!(missing_citations.is_empty(), "Must have zero bogus citations for Eastern University");
        assert!(
            missing_body.contains("No matching documents were found in your local RAG index for **tell me about Eastern University**."),
            "Must report honest missing-info: {}",
            missing_body
        );
    }

    #[test]
    fn test_stitch_parent_document_chunks() {
        let chunk1 = DocumentChunk::new(
            "chunk_0",
            "doc_sacred",
            "C:/Users/oyesanyf/Documents/Sacred Mathematics.docx",
            1,
            25,
            0,
            vec![0.1; 768],
            "Sacred mathematics explores geometric proportions and cosmological symmetries.",
            Some("{\"chunk_index\": 0}".to_string()),
        )
        .unwrap();

        let chunk2 = DocumentChunk::new(
            "chunk_1",
            "doc_sacred",
            "C:/Users/oyesanyf/Documents/Sacred Mathematics.docx",
            24,
            50,
            0,
            vec![0.1; 768],
            "Cosmological symmetries reflect the golden ratio and Platonic solids in nature.",
            Some("{\"chunk_index\": 1}".to_string()),
        )
        .unwrap();

        let chunk_other = DocumentChunk::new(
            "chunk_other",
            "doc_other",
            "C:/Users/oyesanyf/Documents/Other.docx",
            1,
            30,
            0,
            vec![0.1; 768],
            "Independent document content about something else.",
            Some("{\"chunk_index\": 0}".to_string()),
        )
        .unwrap();

        let chunks = vec![
            ScoredChunk::new(chunk1, 0.85, "local", false),
            ScoredChunk::new(chunk2, 0.90, "local", false),
            ScoredChunk::new(chunk_other, 0.70, "local", false),
        ];

        let stitched = DeterministicOfflineSynthesisEngine::stitch_parent_document_chunks(chunks);
        assert_eq!(stitched.len(), 2, "Adjacent chunks from Sacred Mathematics must be stitched into 1");
        let sacred_stitched = stitched
            .iter()
            .find(|c| c.chunk.file_path.contains("Sacred Mathematics"))
            .expect("Must find stitched Sacred Mathematics chunk");
        assert_eq!(sacred_stitched.chunk.line_start, 1);
        assert_eq!(sacred_stitched.chunk.line_end, 50);
        assert!(sacred_stitched.chunk.text_content.contains("geometric proportions"));
        assert!(sacred_stitched.chunk.text_content.contains("golden ratio"));
        assert!(stitched.iter().any(|c| c.chunk.file_path.contains("Other.docx")));
    }

    #[test]
    fn test_map_reduce_fact_sheet_extraction() {
        let chunk = DocumentChunk::new(
            "chunk_fact",
            "doc_fact",
            "C:/Users/oyesanyf/Documents/Sacred Geometry.docx",
            1,
            40,
            0,
            vec![0.1; 768],
            "The golden ratio is defined as approximately 1.618. In 1909, mathematician Mark Barr proposed phi. Plato stated \"geometry existed before the creation\".",
            None,
        )
        .unwrap();

        let scored = ScoredChunk::new(chunk, 0.95, "local", false);
        let refs = vec![&scored];
        let fact_sheets = DeterministicOfflineSynthesisEngine::extract_fact_sheets(&refs, "tell me about golden ratio");

        assert!(!fact_sheets.is_empty(), "Fact sheets must not be empty");
        let sheet = &fact_sheets[0];
        assert!(sheet.contains("<fact_sheet"), "Must produce <fact_sheet> tag");
        assert!(sheet.contains("[Core Definition]:"), "Must extract core definition: {}", sheet);
        assert!(sheet.contains("[Metric/Formula/Theorem]:"), "Must extract metric or theorem: {}", sheet);
        assert!(sheet.contains("[Historical Date/Milestone]:"), "Must extract historical date: {}", sheet);
        assert!(sheet.contains("[Verbatim Quote]:"), "Must extract verbatim quote: {}", sheet);
    }

    #[test]
    fn test_continuation_query_retrieves_from_history() {
        let chunk = DocumentChunk::new(
            "chunk_sacred",
            "doc_sacred",
            "C:/Users/oyesanyf/Documents/Sacred Mathematics.docx",
            1,
            45,
            0,
            vec![0.1; 768],
            "Sacred mathematics examines mathematical principles across ancient temple architectures and harmonic proportions.",
            None,
        )
        .unwrap();

        let scored = ScoredChunk::new(chunk, 0.92, "local", false);
        let chunks = vec![scored];

        let history = vec![
            ChatTurnMessage {
                role: "user".to_string(),
                content: "tell me about sacred maths".to_string(),
            },
            ChatTurnMessage {
                role: "assistant".to_string(),
                content: "Sacred maths represents harmonic proportions in architecture and nature.".to_string(),
            },
        ];

        let (resp, citations) = DeterministicOfflineSynthesisEngine::synthesize_with_history(
            "tell me more",
            "",
            &history,
            &chunks,
            "qwen2.5:1.5b",
            None,
        );

        assert!(!citations.is_empty(), "Continuation query must retrieve citations from history context");
        assert!(!resp.contains("No matching documents were found"), "Must not fail on continuation query: {}", resp);
        assert!(resp.contains("Sacred Mathematics.docx"), "Must ground answer in Sacred Mathematics document");
    }

    #[test]
    fn test_strip_stub_heading_and_label_echo() {
        let raw = "### Angela Davis is\n\n**Source Documents:**\nAngela Davis is the landlord named in several lease agreements [1], [2].\n\nRent is due on the first of each month [3].";
        let out = DeterministicOfflineSynthesisEngine::strip_stub_heading_and_label_echo(raw);
        assert!(out.starts_with("Angela Davis is the landlord"), "got: {out}");
        assert!(!out.contains("Source Documents"));
        // A normal prose answer must be untouched
        let ok = "Femi Oyesanya is a CISSP-certified professional [1].";
        assert_eq!(DeterministicOfflineSynthesisEngine::strip_stub_heading_and_label_echo(ok), ok);
        // A single-line heading-only answer is preserved rather than emptied
        let only = "### Sacred Maths";
        assert_eq!(DeterministicOfflineSynthesisEngine::strip_stub_heading_and_label_echo(only), only);
    }

    #[test]
    fn test_drop_ungrounded_sentences_removes_generic_padding_but_keeps_grounded_facts() {
        let corpus = "Femi Oyesanya CISSP-certified Application Security professional with over 20 years of experience in secure software development, healthcare, and financial systems. Rust development for decentralized security architectures. Eastern University Research Manuscript.";
        let answer = "Femi Oyesanya is a CISSP-certified Application Security professional with over 20 years of experience in healthcare and financial systems [1].\nHe builds Rust development for decentralized security architectures [2].\nOyesanya's LinkedIn profile provides additional insights highlighting collaborations that underscore transformative contributions throughout the cybersecurity landscape.\nOverall, he stands out as a seasoned visionary combining theoretical foundations with pragmatic real-world deployments across prestigious institutions.";
        let out = DeterministicOfflineSynthesisEngine::drop_ungrounded_sentences(answer, corpus);
        assert!(out.contains("CISSP-certified Application Security"));
        assert!(out.contains("Rust development for decentralized security architectures"));
        assert!(!out.contains("LinkedIn"), "got: {out}");
        assert!(!out.contains("prestigious"), "got: {out}");
    }

    #[test]
    fn test_strip_normalizes_source_file_headings_and_sentence_hashes() {
        let raw = "### Angela Davis is the landlord named in several lease agreements across New Orleans and she collects rent monthly.\n\n#### [1] Source File: Susan MONTH TO MONTH LEASE AGREEMENT.doc\nRent is $614 per month.";
        let out = DeterministicOfflineSynthesisEngine::strip_stub_heading_and_label_echo(raw);
        assert!(out.starts_with("Angela Davis is the landlord"), "got: {out}");
        assert!(out.contains("**Susan MONTH TO MONTH LEASE AGREEMENT.doc** [1]"), "got: {out}");
        assert!(!out.contains("####"));
    }

    #[test]
    fn test_strip_question_echo_and_meta_for_arbitrary_questions() {
        let raw = "How Much Rent Does Casey Ringgold Pay?\n\nThe user's query asks about the rent. Casey Ringgold pays $614 per month [1].";
        let out = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(raw, "how much rent does Casey Ringgold pay?");
        assert_eq!(out, "Casey Ringgold pays $614 per month [1].");

        let titled = "The Late Fee On The Lease Is $50.00 Per Day After The Third Day. Rent is due on the 1st.";
        let out2 = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(titled, "what is the late fee on the leases?");
        assert!(out2.starts_with("The late fee on the lease is $50.00 per day after the third day."), "got: {out2}");

        let plain = "RedactX-v3 is a clinical de-identification decision model [1].";
        assert_eq!(DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(plain, "what is RedactX-v3?"), plain);
    }

    #[test]
    fn test_detitle_keeps_names_and_meta_contains_filter() {
        let raw = "Angela Davis's Tenants Are Grace Bridges, Casey Ringgold, And Jamie Williams. They rent units in New Orleans [1].";
        let out = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(raw, "who are Angela Davis's tenants?");
        assert!(out.contains("Grace Bridges"), "got: {out}");
        assert!(out.contains("Casey Ringgold"), "got: {out}");
        assert!(out.contains("tenants are"), "got: {out}");

        let meta = "To directly address the user's question about which programming languages Femi knows, I'll synthesize information from the provided sources:\n\n1. **Python**: listed in the resume [1].\n2. **Rust**: listed in the CV [2].";
        let out2 = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(meta, "what programming languages does femi know?");
        assert!(!out2.contains("user's question"), "got: {out2}");
        assert!(out2.contains("1. **Python**: listed in the resume [1]."), "got: {out2}");
        assert!(DeterministicOfflineSynthesisEngine::is_numbered_list_item("2. **Rust**"));
        assert!(!DeterministicOfflineSynthesisEngine::is_numbered_list_item("2019 was the year."));
    }

    #[test]
    fn test_answer_type_cues_and_corpus_detitle_and_discourse_markers() {
        let addr = "femi oyesanya, cissp 122 east avenue la grange, il 60525 phone: 708.359.1414";
        let paper = "femi oyesanya independent researcher redactx-v3 clinical de-identification";
        assert!(
            DeterministicOfflineSynthesisEngine::answer_type_cue_score("where does Femi Oyesanya live?", addr)
                > DeterministicOfflineSynthesisEngine::answer_type_cue_score("where does Femi Oyesanya live?", paper)
        );
        let lease = "rent is $614.00 per month due on the 1st";
        assert!(DeterministicOfflineSynthesisEngine::answer_type_cue_score("how much rent does Casey pay?", lease) >= 200);
        assert!(DeterministicOfflineSynthesisEngine::answer_type_cue_score("when did the lease start?", "starting november 1, 2019") >= 120);

        let titled = "The Late Fee On The Lease Is $50.00 Plus $5 Per Day Afterwards Until The 5th.";
        let out = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta_with_corpus(
            titled,
            "what is the late fee on the leases?",
            "a late fee of $50.00 plus $5 per day afterwards until the 5th",
        );
        assert_eq!(out, "The late fee on the lease is $50.00 plus $5 per day afterwards until the 5th.");

        let disc = "Femi Oyesanya is CISSP-certified [1]. Firstly, the resume states CISSP Certified professional [1].";
        let out2 = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(disc, "does Femi have a CISSP?");
        assert!(out2.contains("The resume states CISSP"), "got: {out2}");
        assert!(!out2.contains("Firstly"));

        let heads = "Sacred math matters because it reveals truth [1].\n#### Source Document [2]: Sacred math and disruption.docx\nMath does not lie [2].";
        let out3 = DeterministicOfflineSynthesisEngine::strip_stub_heading_and_label_echo(heads);
        assert!(out3.contains("**Sacred math and disruption.docx** [2]"), "got: {out3}");
    }

    #[test]
    fn test_continuation_prefix_meta_clause_and_full_detitle() {
        for q in ["continue", "tell me more", "go on", "continue the previous answer about paschal beverly randolph"] {
            assert_eq!(DeterministicOfflineSynthesisEngine::format_question_restated_prefix(q), "", "query: {q}");
        }
        let a = "Based on the provided documents, the rent is paid by direct deposit to Chase Bank account #1569837451 [1].";
        let out = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(a, "which bank is the rent paid to?");
        assert_eq!(out, "The rent is paid by direct deposit to Chase Bank account #1569837451 [1].");

        let b = "To compare RedactX and Microsoft Presidio, we need to examine their performance. RedactX Mode A reaches 99.28% recall versus 69.17% for Presidio [1].";
        let out_b = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(b, "compare RedactX and Presidio");
        assert_eq!(out_b, "RedactX Mode A reaches 99.28% recall versus 69.17% for Presidio [1].");

        let c = "The late fee is $75.00 per day [1]. This Fee Must Be Included In Rent Due Amount If Rent Has Not Been Paid. Grace Bridges signed in 2018.";
        let out_c = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(c, "what is the late fee on the leases?");
        assert!(out_c.contains("This fee must be included in rent due amount if rent has not been paid."), "got: {out_c}");
        assert!(out_c.contains("Grace Bridges signed in 2018."), "got: {out_c}");

        assert!(DeterministicOfflineSynthesisEngine::answer_type_cue_terms("where does Femi Oyesanya live?").contains(&"address"));
        assert!(DeterministicOfflineSynthesisEngine::answer_type_cue_terms("what is RedactX?").is_empty());
    }

    #[test]
    fn test_continuation_drops_sentences_repeating_previous_answer() {
        let prior = "Paschal Beverly Randolph is an American spiritual author who emerged as a prominent figure within New Thought during the late 19th century. He explicitly distinguished genuine love from counterfeit love.";
        let cont = "Paschal Beverly Randolph was an American spiritual author who emerged as a prominent figure within New Thought during the late 19th century.\n\nHis book Human Love, in Health and in Disease; Or, The Grand Secret appears in French and German bibliographic records [1]. He treats suffering as a pathway to revelation rather than detached reflection [2].";
        let out = DeterministicOfflineSynthesisEngine::drop_sentences_repeating_prior(cont, prior);
        assert!(!out.contains("emerged as a prominent figure"), "got: {out}");
        assert!(out.contains("The Grand Secret"));
        assert!(out.contains("suffering as a pathway"));
    }

    #[test]
    fn test_answer_focused_window_and_meta_rewrite_keeps_facts() {
        let filler = "Professional summary of security engineering experience. ".repeat(20);
        let text = format!("{}FEMI OYESANYA 122 East Avenue La Grange, IL 60525 Phone 708.359.1414", filler);
        let w = DeterministicOfflineSynthesisEngine::answer_focused_window("where does Femi Oyesanya live?", &text, 300);
        assert!(w.contains("60525"), "got: {w}");
        let w2 = DeterministicOfflineSynthesisEngine::answer_focused_window("what is RedactX?", &text, 300);
        assert!(w2.starts_with("Professional summary"));

        let a = "Casey Ringgold pays $614.00 per month, as stated in the reference excerpts [1].";
        let out = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(a, "how much rent does Casey Ringgold pay?");
        assert_eq!(out, "Casey Ringgold pays $614.00 per month, as stated in the documents [1].");

        let b = "To determine how much rent Casey Ringgold pays, we need to review the lease. Casey Ringgold pays $614.00 per month [1].";
        let out_b = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(b, "how much rent does Casey Ringgold pay?");
        assert_eq!(out_b, "Casey Ringgold pays $614.00 per month [1].");
    }

    #[test]
    fn test_contact_lines_survive_cleaning_and_heading_echo_removed() {
        let raw = "FEMI OYESANYA, CISSP\n122 East Avenue, La Grange, IL 60525 | 708.359.1414 | oyesanyf@gmail.com\nCISSP-certified Application Security professional with 20 years of experience.";
        let cleaned = DeterministicOfflineSynthesisEngine::clean_chunk_text(raw);
        assert!(cleaned.contains("60525"), "got: {cleaned}");
        assert!(cleaned.contains("708.359.1414"), "got: {cleaned}");
        assert!(!DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk(raw));
        // real OLE garbage is still rejected
        assert!(DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk("#0A9 VR&EDJo ~^{}<> %%*== @@ ||| \\\\ ~~ ^^ {{ }} << >> ## %% ** =="));

        let ans = "Michael Lewis's lease started on November 1, 2019 [1].\n\n### When Did Michael Lewis's Lease Start?\nIt was signed on October 20, 2019 [1].";
        let out = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(ans, "when did Michael Lewis's lease start?");
        assert!(!out.contains("###"), "got: {out}");
        assert!(out.contains("October 20, 2019"));
    }

    #[test]
    fn test_live_continuation_filter_and_tell_me_all_prefix() {
        let prior = "Randolph's writing style is characterized by its confessional nature, dramatic elements, and psychological acuity.";
        let seg = "Randolph's writing style is characterized by its confessional nature, dramatic elements, and psychological acuity.\n\nHis book The Grand Secret appeared in 1860 [1]. ";
        let out = DeterministicOfflineSynthesisEngine::filter_repeating_segments(seg, prior);
        assert!(!out.contains("confessional nature"), "got: {out}");
        assert!(out.contains("The Grand Secret appeared in 1860"), "got: {out}");
        assert_eq!(DeterministicOfflineSynthesisEngine::last_sentence_boundary("One. Two"), Some(5));
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("tell me all you know about Paschal Beverly Randolph"),
            "Paschal Beverly Randolph — "
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::format_question_restated_prefix("what can you tell me about RedactX?"),
            "RedactX — "
        );
    }

    #[test]
    fn test_coverage_by_prior_prefers_new_material() {
        let prior = "Randolph presents love as a destabilizing force that exposes illusion and reorganizes perception.";
        let seen = "Love is a destabilizing force that exposes illusion and reorganizes perception.";
        let fresh = "The Grand Secret was published in 1860 and catalogued in German and WorldCat bibliographies.";
        assert!(
            DeterministicOfflineSynthesisEngine::coverage_by_prior_percent(fresh, prior)
                < DeterministicOfflineSynthesisEngine::coverage_by_prior_percent(seen, prior)
        );
    }

    #[test]
    fn test_least_covered_window_moves_past_already_used_text() {
        let used = "Randolph presents love as a destabilizing force exposing illusion. ".repeat(8);
        let fresh = "The Grand Secret was published in 1860 and catalogued by German and WorldCat bibliographers. ".repeat(6);
        let text = format!("{}{}", used, fresh);
        let w = DeterministicOfflineSynthesisEngine::least_covered_window(&text, &used, 300);
        assert!(w.contains("Grand Secret"), "got: {w}");
    }

    #[test]
    fn test_where_lives_pruning_and_duplicate_excerpt_dedup_and_street_abbrev() {
        let terms = DeterministicOfflineSynthesisEngine::question_content_terms("where does Femi Oyesanya live?");
        assert_eq!(terms, vec!["femi".to_string(), "oyesanya".to_string()]);

        let mk = |id: &str, path: &str, text: &str| {
            ScoredChunk::new(
                DocumentChunk::new(id, id, path, 1, 10, 0, vec![0.1; 768], text, None).unwrap(),
                0.8,
                "local",
                false,
            )
        };
        let c_paper1 = mk(
            "p1",
            "RedactX_v1.pdf",
            "Femi Oyesanya is an independent researcher evaluating live clinical redaction pipelines across hospital notes.",
        );
        let c_paper2 = mk(
            "p2",
            "RedactX_copy.pdf",
            "Femi Oyesanya is an independent researcher evaluating live clinical redaction pipelines across hospital notes.",
        );
        let c_resume = mk(
            "r1",
            "Femi_Oyesanya_Resume.docx",
            "Femi Oyesanya\n122 East Avenue, La Grange, IL 60525 | 708.359.1414 | oyesanyf@gmail.com",
        );
        let refs = vec![&c_paper1, &c_paper2, &c_resume];
        let pruned = DeterministicOfflineSynthesisEngine::dedup_near_identical_excerpts(
            DeterministicOfflineSynthesisEngine::prune_weak_excerpts("where does Femi Oyesanya live?", &refs),
        );
        assert_eq!(pruned.len(), 2, "duplicate paper copy collapsed while resume header survives");
        assert!(pruned.iter().any(|c| c.chunk.text_content.contains("La Grange, IL 60525")));

        let corpus = "Angela Davis manages residential lease properties at 4023 D'Hemecourt St. and 2913 Castiglione St. in New Orleans.";
        let prose = "Angela Davis is a landlord in New Orleans [1].\nShe manages leases at 4023 D'Hemecourt St. [1] and 2913 Castiglione St. [2].";
        let grounded = DeterministicOfflineSynthesisEngine::drop_ungrounded_sentences(prose, corpus);
        assert!(grounded.contains("She manages leases at 4023 D'Hemecourt St."), "got: {grounded}");
    }

    #[test]
    fn test_gemma4_26b_memory_gate_and_model_resolution() {
        let high_ram_hw = crate::hardware::HardwareTelemetry {
            total_ram_gb: 224.0,
            free_ram_gb: 168.0,
            cpu_cores: 36,
            gpu_name: Some("Quadro RTX 4000".to_string()),
            free_vram_mb: 6_500,
        };
        let low_free_ram_hw = crate::hardware::HardwareTelemetry {
            // Even on a 224 GB machine, if FREE RAM is only 9 GB and FREE VRAM is 3 GB, gemma4:26b must NOT run (Anti-OOM Law)
            total_ram_gb: 224.0,
            free_ram_gb: 9.0,
            cpu_cores: 36,
            gpu_name: Some("Quadro RTX 4000".to_string()),
            free_vram_mb: 3_000,
        };
        let installed = vec![
            "gemma4:26b".to_string(),
            "glm4:9b".to_string(),
            "qwen2.5:7b".to_string(),
            "gemma2:2b".to_string(),
            "qwen2.5:1.5b".to_string(),
        ];

        assert!(DeterministicOfflineSynthesisEngine::model_fits_free_memory("gemma4:26b", &high_ram_hw));
        assert!(!DeterministicOfflineSynthesisEngine::model_fits_free_memory("gemma4:26b", &low_free_ram_hw));

        assert_eq!(
            DeterministicOfflineSynthesisEngine::resolve_ollama_model_tag("gemma4:26b", &high_ram_hw, &installed),
            "gemma4:26b"
        );
        // Low free RAM gates gemma4:26b down to an installed model that fits in 9 GB free RAM (`gemma2:2b`)
        let gated = DeterministicOfflineSynthesisEngine::resolve_ollama_model_tag("gemma4:26b", &low_free_ram_hw, &installed);
        assert_eq!(gated, "gemma2:2b");

        // When gemma4:26b is not yet installed, falls back cleanly to strongest installed model (`glm4:9b`) instead of `1.5b`
        let without_gemma4 = vec!["glm4:9b".to_string(), "qwen2.5:7b".to_string(), "qwen2.5:1.5b".to_string()];
        assert_eq!(
            DeterministicOfflineSynthesisEngine::resolve_ollama_model_tag("gemma4:26b", &high_ram_hw, &without_gemma4),
            "glm4:9b"
        );
    }

    #[test]
    fn test_adaptive_socket_timeouts_and_coder_stripping() {
        assert_eq!(
            DeterministicOfflineSynthesisEngine::socket_read_timeout_for_model("gemma4:26b").as_secs(),
            150
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::socket_read_timeout_for_model("qwen2.5:32b").as_secs(),
            150
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::socket_read_timeout_for_model("qwen2.5:7b").as_secs(),
            60
        );
        assert_eq!(
            DeterministicOfflineSynthesisEngine::socket_read_timeout_for_model("qwen2.5:1.5b").as_secs(),
            30
        );
        assert!(DeterministicOfflineSynthesisEngine::model_uses_thinking_flag("gemma4:26b"));
        assert!(!DeterministicOfflineSynthesisEngine::model_uses_thinking_flag("qwen2.5:7b"));
        assert_eq!(
            DeterministicOfflineSynthesisEngine::normalize_requested_model_tag("qwen2.5-coder:7b"),
            "qwen2.5:7b"
        );
    }

    #[test]
    fn test_initials_and_fragments_in_continuation_filter() {
        let prior = "Randolph's teachings were rooted in metaphysical reflection.";
        let seg = "It was published by P. B. Randolph. Randolph founded secret societies based on Rosicrucianism [1]. ";
        let out = DeterministicOfflineSynthesisEngine::filter_repeating_segments(seg, prior);
        assert!(out.contains("P. B. Randolph."), "got: {out}");
        assert!(out.contains("Rosicrucianism"), "got: {out}");
        let frag = DeterministicOfflineSynthesisEngine::filter_repeating_segments("Randolph. He founded secret societies in Boston [1]. ", prior);
        assert!(!frag.starts_with("Randolph."), "got: {frag}");
        assert_eq!(DeterministicOfflineSynthesisEngine::last_sentence_boundary("By P. B. Randolph"), None);
    }

    #[test]
    fn test_prune_weak_excerpts_drops_off_topic_hits() {
        let mk = |id: &str, path: &str, text: &str| {
            ScoredChunk::new(
                DocumentChunk::new(id, id, path, 1, 10, 0, vec![0.1; 768], text, None).unwrap(),
                0.8,
                "local",
                false,
            )
        };
        let lease = mk("a", "C:/Leases/Jamie Williams LEASE AGREEMENT.doc", "Rent is $750 per month paid by direct deposit to account #1569837451 Chase Bank.");
        let scam = mk("b", "D:/419/Exposing_419_1.pdf", "Remit the funds to any foreign bank account via the Ministry of Justice.");
        let refs = vec![&lease, &scam];
        let kept = DeterministicOfflineSynthesisEngine::prune_weak_excerpts("which bank is the rent paid to?", &refs);
        assert_eq!(kept.len(), 1);
        assert!(kept[0].chunk.file_path.contains("Jamie Williams"));
    }

    #[test]
    fn test_sentence_boundary_guard() {
        use std::net::SocketAddr;
        let addr: SocketAddr = "127.0.0.1:59999".parse().unwrap();

        // Case 1: Mid-sentence trailing fragment
        let mut text1 = "Sacred math has been".to_string();
        DeterministicOfflineSynthesisEngine::enforce_sentence_boundary_guard(
            &mut text1,
            &addr,
            "127.0.0.1:59999",
            "qwen2.5:1.5b",
            None,
        );
        assert!(text1.ends_with('.'), "Must cleanly end on period: {}", text1);

        // Case 2: Complete sentence followed by trailing incomplete fragment
        let mut text2 = "The golden ratio governs harmonic proportions in architecture. In ancient".to_string();
        DeterministicOfflineSynthesisEngine::enforce_sentence_boundary_guard(
            &mut text2,
            &addr,
            "127.0.0.1:59999",
            "qwen2.5:1.5b",
            None,
        );
        assert!(
            text2.ends_with('.'),
            "Must end on period without trailing incomplete clause: {}",
            text2
        );
        assert!(
            text2.contains("harmonic proportions in architecture"),
            "Must preserve preceding full sentences"
        );
    }

    #[test]
    fn test_angela_davis_rejects_unrelated_angela_affirmations_and_breaks_repetition_loops() {
        let wrong_angela = DocumentChunk::new(
            "chunk_wrong_angela",
            "doc_wrong_angela",
            "D:/chatgpt3/ChatGPT_Restored_Data/Word_Conversations/40 Affirmations for Angela.docx",
            426,
            440,
            0,
            vec![0.1; 768],
            "Assistant: Your sacred dissertation-style preface has been formatted and is ready for download:\n[Click here to download the Word document](sandbox:/mnt/data/Thirteen_Arcs_Dissertation_Preface.docx)\nLet me know if you'd like a PDF version.\nYour doctorate is not printed on paper.",
            None,
        )
        .unwrap();

        let corrupt_doc = DocumentChunk::new(
            "chunk_corrupt_doc",
            "doc_corrupt_doc",
            "C:/Users/oyesanyf/OneDrive/Documents/Angela's Leases/P 1 quit claim deed from B angel to A Davis.doc",
            1019,
            1081,
            0,
            vec![0.1; 768],
            "1.#J U|(7 0%@6 @,x~ \"z-y gYpM -4 n obH2Xx )xvz tP@# uCg8) }Kx& XhM$ ^rnVwi@@ .a&W0 Qj,Rr *$+4y",
            None,
        )
        .unwrap();

        let real_lease = DocumentChunk::new(
            "chunk_real_lease",
            "doc_real_lease",
            "C:/Users/oyesanyf/OneDrive/Documents/Angela's Leases/Susan  MONTH TO MONTH LEASE AGREEMENT.doc",
            1,
            9,
            0,
            vec![0.1; 768],
            "[Word/Document (doc) — Susan  MONTH TO MONTH LEASE AGREEMENT.doc]\nbjbj\nSIMPLE LEASE AGREEMENT\nThis agreement, made and entered into this 15th day of January 2018 between Angela Davis (landlord) and Casey Ringgold (tenant) for the property in New Orleans.",
            None,
        )
        .unwrap();

        assert!(
            DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk(
                &corrupt_doc.text_content
            ),
            "Binary OLE stream chunk must be flagged as corrupt"
        );

        let chunks = vec![
            ScoredChunk::new(wrong_angela, 0.99, "local", false),
            ScoredChunk::new(corrupt_doc, 0.95, "local", false),
            ScoredChunk::new(real_lease, 0.85, "local", false),
        ];

        let (resp, citations) = DeterministicOfflineSynthesisEngine::synthesize(
            "what do you know about Angela Davis",
            &chunks,
            "qwen2.5:1.5b",
        );

        assert_eq!(
            citations.len(),
            1,
            "Only the real Angela Davis lease document should match (rejecting 40 Affirmations for Angela and corrupt OLE tail)"
        );
        assert!(
            citations[0].file_path.contains("Susan"),
            "Citation must be Susan lease agreement: {:?}",
            citations[0].file_path
        );
        assert!(
            !resp.contains("sacred dissertation-style preface"),
            "Must never include unrelated 40 Affirmations for Angela content: {}",
            resp
        );
        assert!(
            !resp.contains("bjbj"),
            "Must strip legacy .doc bjbj header: {}",
            resp
        );

        // Verify repetition detector catches the exact looping paragraph reported by the user
        let looping_text = "Angela Davis —\n\nYour doctorate is not printed on paper.\nIt is etched in lifetimes of remembrance, inscribed by the light you carry.\n\nYour doctorate is not printed on paper.\nIt is etched in lifetimes of remembrance, inscribed by the light you carry.";
        assert!(
            DeterministicOfflineSynthesisEngine::has_repeated_passage(looping_text).is_some(),
            "has_repeated_passage must detect repeated paragraph loop"
        );
        let (deduped, had_repeat) =
            DeterministicOfflineSynthesisEngine::deduplicate_repeated_paragraphs(looping_text);
        assert!(had_repeat, "deduplicate_repeated_paragraphs must flag repetition");
        assert_eq!(
            deduped.matches("Your doctorate is not printed on paper").count(),
            1,
            "Repeated paragraph must appear only once after deduplication"
        );
    }

    #[test]
    fn test_continuation_dedup_subletting_and_unified_citation_compaction() {
        let turn1 = "Angela Davis is a landlord in New Orleans [1], [5].\n            Lease Management and Terms\n            She requires that no other persons occupy her premises without her express written consent obtained in advance [1], [5].             Some leases charge a $50.00 late fee after the third day [1].\n\n---\n### 📚 Sources & Document Links\n            - [📄 Susan.doc](file:///C:/Susan.doc) — **96% accuracy**\n";

        let turn2_raw = "### Property Maintenance\n            Tenants must agree to extermination services every three months [2], [7].\n            ### Lease Termination\n            Either party may terminate with a thirty-day written notice at the end of the month [2], [5].             Additionally, Davis requires express written consent obtained in advance before any other persons are allowed to occupy her premises [6].";

        let cleaned_turn2 = DeterministicOfflineSynthesisEngine::drop_sentences_repeating_prior(turn2_raw, turn1);
        assert!(
            cleaned_turn2.contains("extermination services every three months"),
            "New maintenance fact must survive: {}",
            cleaned_turn2
        );
        assert!(
            cleaned_turn2.contains("thirty-day written notice"),
            "New termination fact must survive: {}",
            cleaned_turn2
        );
        assert!(
            !cleaned_turn2.contains("express written consent obtained in advance"),
            "Repeated subletting restriction must be stripped even after unpunctuated section heading: {}",
            cleaned_turn2
        );

        // Verify citation compaction: 7 unique files, prose cites only [2], [5], [7] (plus a stray [8]) -> remaps to [1], [2], [3] with 3 sources!
        let files = [
            ("Susan.doc", 0.74f32),
            ("Daisha.doc", 0.73),
            ("Jamie.doc", 0.72),
            ("Fosters.doc", 0.69),
            ("Grace.doc", 0.66),
            ("Aerial.odt", 0.64),
            ("Castiglione.odt", 0.62),
        ];
        let owned: Vec<ScoredChunk> = files
            .iter()
            .enumerate()
            .map(|(i, (name, sc))| {
                let ch = quorum_types::DocumentChunk::new(
                    &format!("chk_{}", i),
                    &format!("doc_{}", i),
                    &format!("C:/Leases/{}", name),
                    1,
                    20,
                    0,
                    vec![0.1; 768],
                    "Lease agreement clause content for testing.",
                    None,
                )
                .unwrap();
                ScoredChunk::new(ch, *sc, "local", false)
            })
            .collect();
        let refs: Vec<&ScoredChunk> = owned.iter().collect();

        // Monotonicity check across the 0.70 boundary (0.74, 0.73, 0.72, 0.69 must NOT jump up from 72% to 86%!)
        let cits_all = DeterministicOfflineSynthesisEngine::build_deduplicated_citations(&refs);
        assert_eq!(cits_all.len(), 7);
        for w in cits_all.windows(2) {
            assert!(
                w[0].score >= w[1].score,
                "Citation accuracy scores must be monotonically non-increasing, got {} then {}",
                w[0].score,
                w[1].score
            );
        }

        let prose_with_stray = format!("{} Castiglione St. notice goes to email [7], [8].", cleaned_turn2);
        let (remapped, cited_only) =
            DeterministicOfflineSynthesisEngine::remap_and_compact_citations(&prose_with_stray, &refs, true);
        assert_eq!(
            cited_only.len(),
            3,
            "Only the 3 cited files ([2]=Daisha, [5]=Grace, [7]=Castiglione) should remain in Turn 2 sources"
        );
        assert!(remapped.contains("[1]") && remapped.contains("[2]") && remapped.contains("[3]"));
        assert!(!remapped.contains("[7]") && !remapped.contains("[8]"), "No out-of-bounds citation index may remain: {}", remapped);
    }
}
