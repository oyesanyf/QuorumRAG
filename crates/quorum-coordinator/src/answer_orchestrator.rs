//! Answer orchestration for when LLM synthesis is unavailable.
//!
//! The primary path is the local LLM writing a grounded answer (see
//! `DeterministicOfflineSynthesisEngine::query_local_ollama_chat`). This module covers what happens
//! when that path fails:
//!
//! 1. **Fast-model retry.** `fast_fallback_models` picks a smaller installed model (7-9B or
//!    smaller) to retry after the primary model (often a 26B+ model on CPU) times out.
//! 2. **LangExtract-style grounded composition.** If no model answers, facts are extracted from
//!    the retrieved excerpts with regex/structural rules. Every fact is grounded to an exact
//!    character span with `langextract::extraction::ground_extraction` and kept only if grounded
//!    (`filter_grounded`), so nothing is invented. Facts that repeat across documents are merged
//!    with all their citations, then rendered as a structured Markdown answer instead of raw
//!    excerpt dumps.

use std::collections::BTreeMap;

use quorum_types::ScoredChunk;
use regex::Regex;

use crate::langextract::extraction::{filter_grounded, ground_extraction, Extraction};

/// Smaller models to try after the primary model fails, in preference order.
const FAST_MODELS: &[&str] = &[
    "qwen2.5:7b",
    "glm4:9b",
    "gemma2:9b",
    "llama3.1:8b",
    "mistral:latest",
    "qwen2.5:3b",
    "gemma3:4b",
    "gemma2:2b",
    "qwen2.5:1.5b",
];

/// Installed fast models (excluding the model that just failed), in preference order.
pub fn fast_fallback_models(installed: &[String], failed_model: &str) -> Vec<String> {
    let failed = failed_model.trim().to_ascii_lowercase();
    let mut out = Vec::new();
    for cand in FAST_MODELS {
        let c = cand.to_ascii_lowercase();
        if failed == c || failed == format!("{c}:latest") {
            continue;
        }
        if let Some(m) = installed.iter().find(|m| {
            let ml = m.to_ascii_lowercase();
            ml == c || ml == format!("{c}:latest")
        }) {
            if !out.contains(m) {
                out.push(m.clone());
            }
        }
    }
    out
}

/// A grounded fact with every citation (1-based excerpt numbers) that supports it.
#[derive(Debug, Clone, PartialEq)]
pub struct GroundedFact {
    pub class: &'static str,
    pub value: String,
    pub cites: Vec<usize>,
}

fn norm_key(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase()
}

fn push_fact(facts: &mut Vec<GroundedFact>, class: &'static str, value: &str, cite: usize) {
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let value = value.trim_matches(|c: char| c == ',' || c == ';' || c == ' ').to_string();
    if value.len() < 3 {
        return;
    }
    let key = norm_key(&value);
    if let Some(f) = facts.iter_mut().find(|f| f.class == class && norm_key(&f.value) == key) {
        if !f.cites.contains(&cite) {
            f.cites.push(cite);
        }
        return;
    }
    facts.push(GroundedFact { class, value, cites: vec![cite] });
}

struct Rules {
    phone: Regex,
    email: Regex,
    money: Regex,
    date_day_of: Regex,
    date_month: Regex,
    address: Regex,
    counterpart: Regex,
}

fn rules() -> &'static Rules {
    static R: std::sync::OnceLock<Rules> = std::sync::OnceLock::new();
    R.get_or_init(|| Rules {
        phone: Regex::new(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s][0-9]{4}\b").unwrap(),
        email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
        money: Regex::new(r"\$\s?[0-9][0-9,]*(?:\.[0-9]{2})?").unwrap(),
        date_day_of: Regex::new(r"(?i)\b[0-9]{1,2}(?:st|nd|rd|th)\s+day\s+of\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s*,?\s*[0-9]{4}\b").unwrap(),
        date_month: Regex::new(r"\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+[0-9]{1,2},?\s+[0-9]{4}\b").unwrap(),
        address: Regex::new(r"\b[0-9]{2,6}(?:\s+\x{00BD})?\s+(?:[A-Z][A-Za-z]+\s+){1,3}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|Ct|Court|Way|Pl|Place|Pkwy)\b\.?(?:,?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*,?\s+[A-Z]{2}\s+[0-9]{5})?").unwrap(),
        counterpart: Regex::new(r"\b([A-Z][a-z]+\s+[A-Z][a-z']+)\s*\((tenant|tenants|landlord|owner|lessee|lessor|buyer|seller|employee|employer|client|patient|borrower|lender|contractor)\)").unwrap(),
    })
}

/// Short normalized context before a money amount, e.g. "rate of" or "late fee of", so the same
/// clause in different documents merges into one fact.
fn money_label(text: &str, start: usize) -> String {
    let before = &text[..start];
    // Only the clause the amount belongs to: cut at the last sentence/clause break that is followed by
    // whitespace, so decimal points inside earlier amounts ("$50.00 and $5.00") are not treated as breaks.
    let bytes = before.as_bytes();
    let mut cut = 0;
    for i in 0..bytes.len() {
        let next_ws = bytes.get(i + 1).map_or(false, |n| n.is_ascii_whitespace());
        if (matches!(bytes[i], b'.' | b';' | b':') && next_ws) || bytes[i] == b'\n' {
            cut = i + 1;
        }
    }
    let clause = &before[cut..];
    let mut words: Vec<&str> = clause.split_whitespace().collect();
    if words.len() > 3 {
        words = words[words.len() - 3..].to_vec();
    }
    while let Some(first) = words.first() {
        if matches!(first.to_ascii_lowercase().as_str(), "a" | "an" | "the" | "and" | "for" | "of" | "at") {
            words.remove(0);
        } else {
            break;
        }
    }
    words.join(" ").to_ascii_lowercase()
}

fn content_terms(prompt: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "tell", "me", "about", "what", "who", "is", "are", "was", "the", "a", "an", "of", "in", "on",
        "for", "to", "and", "does", "do", "did", "how", "why", "when", "where", "please", "can", "you",
        "show", "file", "files", "that", "contains", "know", "all",
    ];
    prompt
        .split(|c: char| !c.is_alphanumeric())
        .map(|w| w.to_ascii_lowercase())
        .filter(|w| w.len() > 2 && !STOP.contains(&w.as_str()))
        .collect()
}

fn strip_leading_title(s: &str) -> String {
    // Drop a leading run of ALL-CAPS words ("SIMPLE LEASE AGREEMENT This agreement ..." -> "This agreement ...").
    let words: Vec<&str> = s.split_whitespace().collect();
    let mut i = 0;
    while i < words.len() {
        let letters: Vec<char> = words[i].chars().filter(|c| c.is_alphabetic()).collect();
        if letters.len() >= 2 && letters.iter().all(|c| c.is_uppercase()) {
            i += 1;
        } else {
            break;
        }
    }
    if i >= 2 && i < words.len() { words[i..].join(" ") } else { s.to_string() }
}

fn sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let flat: Vec<char> = text.replace(['\r', '\n'], " ").chars().collect();
    let mut cur = String::new();
    for (i, &ch) in flat.iter().enumerate() {
        cur.push(ch);
        // A sentence ends at . ! ? followed by whitespace or end of text, never inside "$50.00".
        let ends = matches!(ch, '.' | '!' | '?') && flat.get(i + 1).map_or(true, |n| n.is_whitespace());
        if ends && cur.trim().len() > 30 {
            out.push(strip_leading_title(&cur.split_whitespace().collect::<Vec<_>>().join(" ")));
            cur.clear();
        }
    }
    if cur.trim().len() > 30 {
        out.push(strip_leading_title(&cur.split_whitespace().collect::<Vec<_>>().join(" ")));
    }
    out
}

fn is_mostly_upper(s: &str) -> bool {
    let letters: Vec<char> = s.chars().filter(|c| c.is_alphabetic()).collect();
    !letters.is_empty() && letters.iter().filter(|c| c.is_uppercase()).count() * 3 > letters.len() * 2
}

/// Extract grounded facts from the retrieved excerpts. `texts[i]` is cited as `[i + 1]`.
pub fn extract_grounded_facts(subject: Option<&str>, texts: &[(String, String, String)]) -> Vec<GroundedFact> {
    let r = rules();
    let subj_l = subject.map(|s| s.trim().to_ascii_lowercase()).filter(|s| s.len() >= 3);
    let mut facts: Vec<GroundedFact> = Vec::new();

    for (idx, (chunk_id, file_path, text)) in texts.iter().enumerate() {
        let cite = idx + 1;
        let mut candidates: Vec<(&'static str, String)> = Vec::new();

        if let Some(subj) = &subj_l {
            let role_re = Regex::new(&format!(r"(?i){}\s*\(([A-Za-z][A-Za-z \-]{{1,28}})\)", regex::escape(subj))).unwrap();
            for cap in role_re.captures_iter(text) {
                candidates.push(("Role", cap[1].trim().to_ascii_lowercase()));
            }
        }
        for cap in r.counterpart.captures_iter(text) {
            let name = cap[1].trim();
            if subj_l.as_deref().map_or(false, |s| name.to_ascii_lowercase().contains(s)) {
                continue;
            }
            candidates.push(("Other parties", format!("{} ({})", name, &cap[2])));
        }
        for m in r.address.find_iter(text) {
            candidates.push(("Addresses", m.as_str().to_string()));
        }
        for m in r.phone.find_iter(text) {
            candidates.push(("Phone", m.as_str().to_string()));
        }
        for m in r.email.find_iter(text) {
            candidates.push(("Email", m.as_str().to_string()));
        }
        for m in r.date_day_of.find_iter(text).chain(r.date_month.find_iter(text)) {
            candidates.push(("Dates", m.as_str().to_string()));
        }
        for m in r.money.find_iter(text) {
            let label = money_label(text, m.start());
            let v = if label.is_empty() { m.as_str().to_string() } else { format!("{} {}", label, m.as_str()) };
            candidates.push(("Amounts", v));
        }

        // LangExtract grounding: every candidate must map back to an exact span of its excerpt.
        let mut extractions: Vec<(&'static str, Extraction)> = Vec::new();
        for (class, value) in candidates {
            // Ground on the distinctive part (the amount itself for labelled money values).
            let anchor = if class == "Amounts" {
                value.rsplit(' ').next().unwrap_or(&value).to_string()
            } else if class == "Role" {
                value.clone()
            } else {
                value.split(" (").next().unwrap_or(&value).to_string()
            };
            let mut e = Extraction::new(class, anchor)
                .with_source(chunk_id.clone(), file_path.clone())
                .with_attribute("display", value);
            if ground_extraction(&mut e, text) {
                extractions.push((class, e));
            }
        }
        let grounded = filter_grounded(extractions.iter().map(|(_, e)| e.clone()).collect());
        for e in grounded {
            let class = extractions
                .iter()
                .find(|(_, x)| x.extraction_text == e.extraction_text && x.attributes == e.attributes)
                .map(|(c, _)| *c)
                .unwrap_or("Facts");
            let display = e.attributes.get("display").cloned().unwrap_or(e.extraction_text.clone());
            push_fact(&mut facts, class, &display, cite);
        }
    }
    facts
}

/// Most relevant verbatim sentences (prose only), each with its citation.
pub fn key_passages(prompt: &str, subject: Option<&str>, texts: &[(String, String, String)], max: usize) -> Vec<(String, usize)> {
    let mut terms = content_terms(prompt);
    if let Some(s) = subject {
        terms.extend(content_terms(s));
    }
    terms.sort();
    terms.dedup();
    let mut scored: Vec<(usize, String, usize)> = Vec::new();
    for (idx, (_, _, text)) in texts.iter().enumerate() {
        for s in sentences(text) {
            if s.len() > 320 || is_mostly_upper(&s) {
                continue;
            }
            let low = s.to_ascii_lowercase();
            let score = terms.iter().filter(|t| low.contains(t.as_str())).count();
            if score > 0 {
                scored.push((score, s, idx + 1));
            }
        }
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.2.cmp(&b.2)));
    let mut out: Vec<(String, usize)> = Vec::new();
    for (_, s, c) in scored {
        let k = norm_key(&s);
        if out.iter().any(|(o, _)| norm_key(o) == k) {
            continue;
        }
        out.push((s, c));
        if out.len() >= max {
            break;
        }
    }
    out
}

fn cite_list(cites: &[usize]) -> String {
    cites.iter().map(|c| format!("[{c}]")).collect::<Vec<_>>().join(", ")
}

/// Render grounded facts and key passages as Markdown sections (no opening, no sources block).
/// Returns `None` when nothing could be grounded, so callers keep their previous behaviour.
pub fn render_grounded_sections(prompt: &str, subject: Option<&str>, chunks: &[&ScoredChunk]) -> Option<String> {
    let texts: Vec<(String, String, String)> = chunks
        .iter()
        .take(8)
        .filter(|c| !crate::offline_engine::DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk(&c.chunk.text_content))
        .map(|c| {
            (
                c.chunk.chunk_id.clone(),
                c.chunk.file_path.clone(),
                crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(&c.chunk.text_content),
            )
        })
        .collect();
    let facts = extract_grounded_facts(subject, &texts);
    let passages = key_passages(prompt, subject, &texts, 3);
    if facts.is_empty() && passages.is_empty() {
        return None;
    }

    const ORDER: &[&str] = &["Role", "Other parties", "Addresses", "Phone", "Email", "Amounts", "Dates"];
    let mut grouped: BTreeMap<usize, (&str, Vec<&GroundedFact>)> = BTreeMap::new();
    for f in &facts {
        let pos = ORDER.iter().position(|o| *o == f.class).unwrap_or(ORDER.len());
        grouped.entry(pos).or_insert((f.class, Vec::new())).1.push(f);
    }

    let mut md = String::new();
    if !grouped.is_empty() {
        md.push_str("### Key facts from the documents\n");
        for (_, (class, mut items)) in grouped {
            // Facts supported by more documents first; cap list length per class.
            items.sort_by(|a, b| b.cites.len().cmp(&a.cites.len()));
            let limit = if class == "Amounts" { 6 } else { 5 };
            let rendered: Vec<String> = items
                .iter()
                .take(limit)
                .map(|f| format!("{} {}", f.value, cite_list(&f.cites)))
                .collect();
            md.push_str(&format!("- **{}:** {}\n", class, rendered.join("; ")));
        }
    }
    if !passages.is_empty() {
        md.push_str("\n### Relevant passages\n");
        for (s, c) in passages {
            md.push_str(&format!("- \"{}\" [{}]\n", s.trim(), c));
        }
    }
    Some(md.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease_texts() -> Vec<(String, String, String)> {
        vec![
            (
                "c1".into(),
                "Susan lease.doc".into(),
                "SIMPLE LEASE AGREEMENT This agreement, made and entered into this 15th day of January 2018 between Angela Davis (landlord) and Casey Ringgold (tenant) for the dwelling unit located at 2913 Castiglione St. New Orleans, LA 70119 and shall have a one year lease starting on the 1st day of February for the rate of $614.00 due and payable on the 1st of each month. After the third day of the month if rent has not been received a late fee of $50.00 must be included.".into(),
            ),
            (
                "c2".into(),
                "Grace lease.doc".into(),
                "between Angela Davis (landlord) and Grace Bridges (tenant). Tenant agrees to report any necessary repairs to Angela Davis, by email and telephone 504 427-5625 immediately. A late fee of $50.00 applies.".into(),
            ),
        ]
    }

    #[test]
    fn extracts_and_merges_grounded_lease_facts() {
        let facts = extract_grounded_facts(Some("Angela Davis"), &lease_texts());
        let get = |class: &str| facts.iter().filter(|f| f.class == class).collect::<Vec<_>>();
        let role = get("Role");
        assert_eq!(role.len(), 1);
        assert_eq!(role[0].value, "landlord");
        assert_eq!(role[0].cites, vec![1, 2]);
        let parties: Vec<&str> = get("Other parties").iter().map(|f| f.value.as_str()).collect();
        assert!(parties.contains(&"Casey Ringgold (tenant)"));
        assert!(parties.contains(&"Grace Bridges (tenant)"));
        assert!(get("Addresses").iter().any(|f| f.value.starts_with("2913 Castiglione St")));
        assert!(get("Phone").iter().any(|f| f.value == "504 427-5625"));
        assert!(get("Dates").iter().any(|f| f.value == "15th day of January 2018"));
        let amounts: Vec<&GroundedFact> = get("Amounts");
        assert!(amounts.iter().any(|f| f.value.ends_with("rate of $614.00")));
        // "late fee of $50.00" appears in both excerpts and must be merged with both citations.
        let late = amounts.iter().find(|f| f.value.contains("late fee of $50.00")).expect("late fee");
        assert_eq!(late.cites, vec![1, 2]);
    }

    #[test]
    fn renders_structured_answer_without_title_dump() {
        let texts = lease_texts();
        let chunks: Vec<ScoredChunk> = texts
            .iter()
            .map(|(id, path, text)| {
                ScoredChunk::new(
                    quorum_types::DocumentChunk::new(id.clone(), id.clone(), path.as_str(), 1, 1, 0, vec![0.0; 768], text.as_str(), None).unwrap(),
                    0.9,
                    "local",
                    false,
                )
            })
            .collect();
        let refs: Vec<&ScoredChunk> = chunks.iter().collect();
        let md = render_grounded_sections("tell me about Angela Davis", Some("Angela Davis"), &refs).expect("md");
        println!("{md}");
        assert!(md.contains("- **Role:** landlord [1], [2]"), "{md}");
        assert!(md.contains("### Relevant passages"), "{md}");
        assert!(!md.contains("SIMPLE LEASE AGREEMENT This agreement"), "raw title dump leaked: {md}");
    }

    #[test]
    fn live_defects_amount_labels_names_and_sentences() {
        let texts = vec![(
            "c".to_string(),
            "x.doc".to_string(),
            "Firldeal Breure Michael Lewis (tenant) signed. A late fee of $50.00 and $5.00 per day applies. Rent may be paid to Angela Davis after the third day if a late fee of $50.00 is included.".to_string(),
        )];
        let facts = extract_grounded_facts(Some("Angela Davis"), &texts);
        assert!(facts.iter().any(|f| f.class == "Other parties" && f.value == "Michael Lewis (tenant)"), "{facts:?}");
        assert!(!facts.iter().any(|f| f.value.starts_with("00 ")), "decimal split leaked: {facts:?}");
        let s = sentences(&texts[0].2);
        assert!(s.iter().any(|x| x.ends_with("late fee of $50.00 is included.")), "{s:?}");
    }

    #[test]
    fn nothing_grounded_returns_none() {
        let chunks: Vec<ScoredChunk> = vec![];
        assert!(render_grounded_sections("x", None, &chunks.iter().collect::<Vec<_>>()).is_none());
    }

    #[test]
    fn fast_models_skip_failed_and_respect_installed() {
        let installed = vec!["gemma4:26b".to_string(), "glm4:9b".to_string(), "qwen2.5:7b".to_string(), "moondream:latest".to_string()];
        assert_eq!(fast_fallback_models(&installed, "gemma4:26b"), vec!["qwen2.5:7b".to_string(), "glm4:9b".to_string()]);
        assert_eq!(fast_fallback_models(&installed, "qwen2.5:7b"), vec!["glm4:9b".to_string()]);
    }
}
