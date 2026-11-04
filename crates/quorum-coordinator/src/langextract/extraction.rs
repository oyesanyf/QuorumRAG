use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Source-grounded entity extraction with strict character interval offsets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extraction {
    pub extraction_class: String,
    pub extraction_text: String,
    pub char_interval: Option<(usize, usize)>,
    pub attributes: BTreeMap<String, String>,
    pub source_chunk_id: Option<String>,
    pub source_file_path: Option<String>,
}

impl Extraction {
    pub fn new(
        extraction_class: impl Into<String>,
        extraction_text: impl Into<String>,
    ) -> Self {
        Self {
            extraction_class: extraction_class.into(),
            extraction_text: extraction_text.into(),
            char_interval: None,
            attributes: BTreeMap::new(),
            source_chunk_id: None,
            source_file_path: None,
        }
    }

    pub fn with_source(
        mut self,
        chunk_id: impl Into<String>,
        file_path: impl Into<String>,
    ) -> Self {
        self.source_chunk_id = Some(chunk_id.into());
        self.source_file_path = Some(file_path.into());
        self
    }

    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    pub fn with_interval(mut self, start: usize, end: usize) -> Self {
        self.char_interval = Some((start, end));
        self
    }
}

/// Verbatim text grounding function:
/// Searches `source_text` for verbatim substring match of `extraction.extraction_text`.
/// If found at byte index `start`, sets `extraction.char_interval = Some((start, start + len))` and returns true.
/// If not found via exact match, attempts case-insensitive fallback:
/// if found and boundaries align, sets `char_interval` and returns true.
/// Otherwise, sets `extraction.char_interval = None` and returns false.
pub fn ground_extraction(extraction: &mut Extraction, source_text: &str) -> bool {
    if extraction.extraction_text.is_empty() {
        extraction.char_interval = None;
        return false;
    }

    // 1. Verbatim exact byte match
    if let Some(start) = source_text.find(&extraction.extraction_text) {
        let end = start + extraction.extraction_text.len();
        extraction.char_interval = Some((start, end));
        return true;
    }

    // 2. Case-insensitive substring fallback
    let source_lower = source_text.to_lowercase();
    let target_lower = extraction.extraction_text.to_lowercase();
    if let Some(start) = source_lower.find(&target_lower) {
        let end = start + target_lower.len();
        if source_text.is_char_boundary(start) && source_text.is_char_boundary(end) {
            extraction.char_interval = Some((start, end));
            return true;
        }
    }

    extraction.char_interval = None;
    false
}

/// Hallucination filter: strictly retains only items where `extraction.char_interval.is_some()`.
pub fn filter_grounded(extractions: Vec<Extraction>) -> Vec<Extraction> {
    extractions
        .into_iter()
        .filter(|e| e.char_interval.is_some())
        .collect()
}

// ============================================================================
// Google LangExtract Chat Box Candidate Extraction & Invariant Constants
// ============================================================================

const DOC_EXTENSIONS: &[&str] = &[
    ".pdf", ".docx", ".doc", ".txt", ".rs", ".md", ".csv", ".json", ".toml",
];

const KNOWN_ENTITIES: &[&str] = &[
    "femi",
    "oyesanya",
    "redactx",
    "vaultgemma",
    "presidio",
    "patientpoint",
    "cigna",
    "angela",
    "davis",
    "rrfcombiner",
    "lancedb",
    "tantivy",
    "blake3",
    "ed25519",
];

const ENTITY_STOPWORDS: &[&str] = &[
    "who", "what", "where", "when", "why", "how", "which",
    "is", "are", "was", "were", "be", "been", "being",
    "do", "does", "did", "have", "has", "had",
    "the", "this", "that", "these", "those",
    "and", "but", "or", "nor", "for", "yet", "so",
    "with", "from", "into", "about", "using", "under", "over",
    "tell", "show", "explain", "describe", "list", "find", "check",
    "can", "could", "would", "will", "shall", "should", "may", "might", "must",
    "you", "your", "yours", "his", "her", "hers", "their", "theirs", "its", "our", "ours",
    "file", "files", "document", "documents", "doc", "docs", "docx", "pdf", "txt",
    "school", "university", "college", "degree", "education", "resume", "experience",
];

const INTERROGATIVE_PREFIXES: &[&str] = &[
    "who ", "what ", "where ", "when ", "why ", "how ",
    "tell me ", "explain ", "describe ", "show me ", "list ",
    "can you ", "could you ", "would you ", "which ",
    "is ", "are ", "was ", "were ", "does ", "did ", "do ",
];

/// Splits prompt text into sentence and interrogative clauses without breaking file extensions or decimals.
fn split_prompt_clauses(prompt: &str) -> Vec<&str> {
    let mut clauses = Vec::new();
    let mut current_start = 0;
    let bytes = prompt.as_bytes();
    let len = bytes.len();

    let mut i = 0;
    while i < len {
        let b = bytes[i];
        let is_boundary = if b == b'?' || b == b'\n' || b == b';' {
            true
        } else if b == b'.' || b == b'!' {
            // Only split on '.' or '!' if followed by whitespace or at the very end of prompt
            i + 1 == len || bytes[i + 1].is_ascii_whitespace()
        } else {
            false
        };

        if is_boundary {
            let slice = &prompt[current_start..i];
            let trimmed = slice.trim();
            if !trimmed.is_empty() {
                clauses.push(trimmed);
            }
            current_start = i + 1;
        }
        i += 1;
    }

    if current_start < len {
        let slice = &prompt[current_start..];
        let trimmed = slice.trim();
        if !trimmed.is_empty() {
            clauses.push(trimmed);
        }
    }

    clauses
}

/// Extracts candidate questions, document references, and named entities/technical terms
/// from a user chat box query.
///
/// Guaranteed Invariant: Every candidate extraction_text is an exact verbatim substring
/// of `prompt`, guaranteeing 100% pass rate in `ground_extraction` (Arm 1) and
/// `CounterfactualJudge` (Arm 3) under `LlmFusionConsensus`.
pub fn extract_chat_candidates(prompt: &str) -> Vec<Extraction> {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut all_candidates = Vec::new();

    // ------------------------------------------------------------------------
    // 1. Extract Questions
    // ------------------------------------------------------------------------
    let clauses = split_prompt_clauses(trimmed);
    let mut found_question = false;

    for clause in &clauses {
        let lower = clause.to_ascii_lowercase();
        let is_interrogative = INTERROGATIVE_PREFIXES.iter().any(|prefix| lower.starts_with(prefix));
        let ends_with_qmark = prompt.contains(&format!("{}?", clause));

        if is_interrogative || ends_with_qmark {
            if prompt.contains(clause) {
                all_candidates.push(
                    Extraction::new("question", *clause)
                        .with_attribute("type", "interrogative_clause"),
                );
                found_question = true;
            }
        }
    }

    if !found_question {
        if prompt.contains(trimmed) {
            all_candidates.push(
                Extraction::new("question", trimmed)
                    .with_attribute("type", "full_prompt_question"),
            );
        }
    }

    // ------------------------------------------------------------------------
    // 2. Extract Document References (e.g. .pdf, .docx, .doc, .txt, .rs, .md)
    // ------------------------------------------------------------------------
    for token in trimmed.split_whitespace() {
        if token.contains(':') {
            continue; // Skip metadata query filters (e.g. filetype:pdf)
        }
        let clean_tok = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '_' && c != '-');
        let lower_tok = clean_tok.to_ascii_lowercase();

        for ext in DOC_EXTENSIONS {
            if lower_tok.ends_with(ext) && clean_tok.len() > ext.len() && !clean_tok.starts_with('.') {
                if prompt.contains(clean_tok) {
                    let ext_name = ext.trim_start_matches('.');
                    all_candidates.push(
                        Extraction::new("document_reference", clean_tok)
                            .with_attribute("file_name", clean_tok)
                            .with_attribute("extension", ext_name)
                            .with_attribute("canonical", &lower_tok),
                    );
                }
                break;
            }
        }
    }

    // ------------------------------------------------------------------------
    // 3. Extract Named Entities & Technical Terms
    // ------------------------------------------------------------------------
    let mut detected_entity_words = Vec::new();

    for token in trimmed.split_whitespace() {
        if token.contains(':') {
            continue;
        }
        let is_doc = DOC_EXTENSIONS.iter().any(|ext| token.to_ascii_lowercase().ends_with(ext));
        if is_doc {
            continue;
        }

        let raw_clean = token
            .trim_matches(|c: char| !c.is_alphanumeric() && c != '-')
            .trim_matches('-');
        if raw_clean.len() < 2 {
            continue;
        }

        // Strip possessive 's or trailing apostrophe ('s / ')
        let clean = raw_clean
            .strip_suffix("'s")
            .or_else(|| raw_clean.strip_suffix('\''))
            .unwrap_or(raw_clean);
        if clean.len() < 2 {
            continue;
        }

        let lower = clean.to_ascii_lowercase();
        if ENTITY_STOPWORDS.contains(&lower.as_str()) {
            continue;
        }

        let is_capitalized = clean.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
        let is_known = KNOWN_ENTITIES.contains(&lower.as_str());

        if is_capitalized || is_known {
            if prompt.contains(clean) {
                let is_tech = lower == "redactx"
                    || lower == "vaultgemma"
                    || lower == "presidio"
                    || lower == "rrfcombiner"
                    || lower == "lancedb"
                    || lower == "tantivy"
                    || lower == "blake3"
                    || lower == "ed25519";

                let kind = if is_tech {
                    "technical_term"
                } else if lower == "cigna" || lower == "patientpoint" {
                    "organization"
                } else {
                    "named_entity"
                };

                all_candidates.push(
                    Extraction::new("named_entity", clean)
                        .with_attribute("canonical", &lower)
                        .with_attribute("kind", kind),
                );
                detected_entity_words.push(clean);
            }
        }
    }

    // ------------------------------------------------------------------------
    // 4. Extract Multi-Word Proper Nouns (e.g. "Femi Oyesanya", "Angela Davis")
    // ------------------------------------------------------------------------
    if detected_entity_words.len() >= 2 {
        for window in detected_entity_words.windows(2) {
            let phrase = format!("{} {}", window[0], window[1]);
            if prompt.contains(&phrase) {
                let lower_phrase = phrase.to_ascii_lowercase();
                all_candidates.push(
                    Extraction::new("named_entity", phrase)
                        .with_attribute("canonical", lower_phrase)
                        .with_attribute("kind", "full_name"),
                );
            }
        }
    }

    // ------------------------------------------------------------------------
    // 5. Deduplicate Candidates by (class, text)
    // ------------------------------------------------------------------------
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    for cand in all_candidates {
        let key = (cand.extraction_class.clone(), cand.extraction_text.clone());
        if seen.insert(key) {
            result.push(cand);
        }
    }

    result
}

