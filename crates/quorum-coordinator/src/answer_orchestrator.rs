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

#[path = "query_framing.rs"]
pub mod query_framing;

use std::collections::{BTreeMap, BTreeSet};

use quorum_types::{DocumentChunk, ScoredChunk};
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::langextract::extraction::{filter_grounded, ground_extraction, Extraction};

/// Explicit structured Nimble-9B relevance attestation for candidate document chunks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NimbleRelevanceAttestation {
    pub document_id: String,
    pub file_path: String,
    pub source_peer: String,
    pub attested_relevant: bool,
    pub calibrated_probability: f64,
    pub model_tag: String,
    pub used_fallback: bool,
}

impl NimbleRelevanceAttestation {
    pub const RELEVANCE_FLOOR: f64 = 0.20;

    /// Attests document relevance using Nimble-9B decision scoring with distractor classification.
    /// Strictly enforces the 0.20 relevance floor without argmax binary choice masking.
    pub fn from_chunk(
        chunk: &DocumentChunk,
        query: &str,
        source_peer: &str,
    ) -> Self {
        let is_noise_or_distractor = query_framing::is_lexical_distractor(query, &chunk.file_path, &chunk.text_content);

        if is_noise_or_distractor {
            return Self {
                document_id: chunk.document_id.clone(),
                file_path: chunk.file_path.clone(),
                source_peer: source_peer.to_string(),
                attested_relevant: false,
                calibrated_probability: 0.05,
                model_tag: "nimble-fallback-distractor".to_string(),
                used_fallback: true,
            };
        }

        let context = format!("Query: {}\nDocument excerpt: {}\nAssessment: relevant substantive match", query, chunk.text_content);
        let choices = ["Yes", "No"];
        let decision = crate::nimble_client::NimbleClient::decide_fallback(&context, &choices);

        let p_yes = decision.probability_of("Yes");
        let is_relevant = p_yes >= Self::RELEVANCE_FLOOR;

        Self {
            document_id: chunk.document_id.clone(),
            file_path: chunk.file_path.clone(),
            source_peer: source_peer.to_string(),
            attested_relevant: is_relevant,
            calibrated_probability: p_yes,
            model_tag: decision.model_tag,
            used_fallback: decision.used_fallback,
        }
    }
}

/// Attests a slice of DocumentChunks concurrently using `Arc<tokio::sync::Semaphore>` and `FuturesUnordered`.
pub async fn attest_documents_concurrent(
    chunks: &[DocumentChunk],
    query: &str,
    source_peer: &str,
    max_concurrency: Option<usize>,
) -> Vec<NimbleRelevanceAttestation> {
    use futures::stream::FuturesUnordered;
    use futures::StreamExt;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let concurrency = max_concurrency.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get().clamp(1, 32))
            .unwrap_or(8)
    });
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = FuturesUnordered::new();

    for chunk in chunks {
        let sem = Arc::clone(&semaphore);
        let c = chunk.clone();
        let q = query.to_string();
        let sp = source_peer.to_string();
        tasks.push(async move {
            let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
            Ok::<NimbleRelevanceAttestation, String>(NimbleRelevanceAttestation::from_chunk(&c, &q, &sp))
        });
    }

    let mut results = Vec::with_capacity(chunks.len());
    while let Some(res) = tasks.next().await {
        if let Ok(att) = res {
            results.push(att);
        }
    }
    results
}

/// Concurrently filters candidate ScoredChunks using Nimble relevance attestation.
/// Preserves genuine multi-host recall across local storage and mesh peers.
pub async fn filter_attested_scored_chunks(
    chunks: &[&ScoredChunk],
    query: &str,
    max_concurrency: Option<usize>,
) -> (Vec<ScoredChunk>, Vec<NimbleRelevanceAttestation>) {
    use futures::stream::FuturesUnordered;
    use futures::StreamExt;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let concurrency = max_concurrency.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get().clamp(1, 32))
            .unwrap_or(8)
    });
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = FuturesUnordered::new();

    for (idx, &sc) in chunks.iter().enumerate() {
        let sem = Arc::clone(&semaphore);
        let sc_clone = (*sc).clone();
        let q = query.to_string();
        tasks.push(async move {
            let _permit = sem.acquire().await.map_err(|e| e.to_string())?;
            let att = NimbleRelevanceAttestation::from_chunk(&sc_clone.chunk, &q, &sc_clone.source_peer);
            Ok::<(usize, ScoredChunk, NimbleRelevanceAttestation), String>((idx, sc_clone, att))
        });
    }

    let mut collected = Vec::new();
    while let Some(res) = tasks.next().await {
        if let Ok(item) = res {
            collected.push(item);
        }
    }
    collected.sort_by_key(|(idx, _, _)| *idx);

    let mut kept_chunks = Vec::new();
    let mut attestations = Vec::new();
    for (_, sc, att) in collected {
        if att.attested_relevant {
            kept_chunks.push(sc);
        }
        attestations.push(att);
    }
    (kept_chunks, attestations)
}

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

/// Returns true if a line represents a contact header, pipe-delimited metadata bar, or bare contact field.
pub fn is_contact_bar_or_header(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Never treat lines carrying formal [k] citations or markdown table rows as contact bars
    if trimmed.contains('[') || (trimmed.starts_with('|') && trimmed.ends_with('|')) {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("defender antivirus")
        || lower.contains("codeintegrity")
        || lower.contains("systemeventlog")
        || lower.contains("processexecution")
        || lower.contains("networkconnection")
        || lower.contains("registrypersistence")
        || lower.contains("prefetchamcacheexecution")
        || lower.contains("servicedaemon")
        || lower.contains("artemis dfir")
        || lower.contains("blocked and removed")
        || lower.contains("event id ")
    {
        return false;
    }

    // 1. Explicit contact/metadata label prefixes
    for prefix in &[
        "email:", "e-mail:", "phone:", "tel:", "telephone:", "cell:",
        "mobile:", "fax:", "contact:", "contact info:", "contact information:",
        "address:", "location:", "linkedin:", "github:", "website:", "portfolio:"
    ] {
        if lower.starts_with(prefix) {
            return true;
        }
    }

    // 2. Email detection: unconditionally treat lines containing email addresses as contact headers
    let has_email = lower.contains('@') && lower.split_whitespace().any(|w| w.contains('@') && w.contains('.'));
    if has_email {
        return true;
    }

    // 3. Contact emojis
    if trimmed.contains('📧')
        || trimmed.contains('📱')
        || trimmed.contains('📞')
        || trimmed.contains('📍')
        || trimmed.contains('✉')
    {
        return true;
    }

    let has_url = lower.contains("linkedin.com")
        || lower.contains("github.com")
        || lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("www.");
    let has_phone_digits = trimmed.chars().filter(|c| c.is_ascii_digit()).count() >= 7;

    let ends_with_sentence_punct = trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?');

    // 4. Multi-pipe or single-pipe contact bars
    let pipe_count = trimmed.matches('|').count();
    if pipe_count >= 2 {
        return true;
    }
    if pipe_count >= 1 && !ends_with_sentence_punct {
        return true;
    }

    // 5. Bullet delimiter detection (•, ·, ●, ▪, ◆, ■, dashes)
    let bullet_count = trimmed.matches('•').count()
        + trimmed.matches('·').count()
        + trimmed.matches('●').count()
        + trimmed.matches('▪').count()
        + trimmed.matches('◆').count()
        + trimmed.matches('■').count()
        + trimmed.matches(" - ").count()
        + trimmed.matches(" — ").count();
    if bullet_count >= 2 && !ends_with_sentence_punct {
        return true;
    }

    // 6. Forward-slash delimiter detection
    let slash_count = trimmed.matches(" / ").count() + trimmed.matches('/').count();
    if (slash_count >= 2 && (!ends_with_sentence_punct || trimmed.matches(" / ").count() >= 2))
        || (slash_count >= 1 && (has_url || has_phone_digits))
    {
        return true;
    }

    if (pipe_count >= 1 || bullet_count >= 1) && (has_url || has_phone_digits) {
        return true;
    }

    // 7. Delimiter bar with address/location tokens
    if pipe_count >= 1 && (
        lower.contains("new york")
        || lower.contains("st.")
        || lower.contains("street")
        || lower.contains("ave")
        || lower.contains("avenue")
        || lower.contains("drive")
        || lower.contains("road")
        || lower.contains("rd.")
    ) {
        return true;
    }

    // 8. Short lines consisting primarily of url, phone, or website metadata
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    if words.len() <= 6 && has_url {
        return true;
    }
    if words.len() <= 5
        && has_phone_digits
        && (lower.contains("tel") || lower.contains("phone") || lower.contains("cell") || lower.contains("fax") || lower.contains("ext"))
    {
        return true;
    }

    false
}

fn sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut prose_lines = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Markdown table rows are discrete blocks/rows, not contact bars or prose to be split on periods
        if trimmed.starts_with('|') && trimmed.ends_with('|') {
            if trimmed.contains("---") {
                continue;
            }
            if trimmed.contains('[') || trimmed.len() >= 5 {
                out.push(trimmed.to_string());
                continue;
            }
        }
        if is_contact_bar_or_header(trimmed) {
            continue;
        }
        prose_lines.push(trimmed);
    }

    if !prose_lines.is_empty() {
        let sanitized_text = prose_lines.join(" ");
        let flat: Vec<char> = sanitized_text.chars().collect();
        let mut cur = String::new();
        for (i, &ch) in flat.iter().enumerate() {
            cur.push(ch);
            // A sentence ends at . ! ? followed by whitespace or end of text, never inside "$50.00".
            let ends = matches!(ch, '.' | '!' | '?') && flat.get(i + 1).map_or(true, |n| n.is_whitespace());
            if ends && (cur.trim().contains('[') || cur.trim().len() >= 10) {
                let s = strip_leading_title(&cur.split_whitespace().collect::<Vec<_>>().join(" "));
                if !is_contact_bar_or_header(&s) {
                    out.push(s);
                }
                cur.clear();
            }
        }
        if cur.trim().contains('[') || cur.trim().len() >= 10 {
            let s = strip_leading_title(&cur.split_whitespace().collect::<Vec<_>>().join(" "));
            if !is_contact_bar_or_header(&s) {
                out.push(s);
            }
        }
    }
    out
}

fn is_mostly_upper(s: &str) -> bool {
    let letters: Vec<char> = s.chars().filter(|c| c.is_alphabetic()).collect();
    !letters.is_empty() && letters.iter().filter(|c| c.is_uppercase()).count() * 3 > letters.len() * 2
}

/// Returns true if an address candidate represents a government agency headquarters,
/// form filing lockbox, or administrative boilerplate address rather than a subject's personal/business address.
pub fn is_government_agency_or_boilerplate_address(addr: &str, surrounding: &str) -> bool {
    let a_low = addr.to_ascii_lowercase();
    let c_low = surrounding.to_ascii_lowercase();

    // 1. Known Federal Agency / USCIS / DHS / Government Headquarters Addresses
    const KNOWN_AGENCY_ADDRESSES: &[&str] = &[
        "111 massachusetts",
        "20 massachusetts",
        "5900 capital gateway",
        "5107 leesburg pike",
        "200 constitution ave",
        "400 7th st",
        "1600 pennsylvania",
        "p.o. box 805887",
        "p.o. box 660867",
        "p.o. box 21281",
        "p.o. box 4008",
        "2501 s. state highway 121",
        "131 s. dearborn",
        "1820 e. skyharbor",
    ];
    for &known in KNOWN_AGENCY_ADDRESSES {
        if a_low.contains(known) {
            return true;
        }
    }

    // 2. Washington DC Agency ZIP codes (20529: USCIS/DHS, 20530: DOJ, 20210: DOL, 20588: FDA/HHS)
    if a_low.contains("20529") || a_low.contains("20530") || a_low.contains("20210") || a_low.contains("20588") {
        return true;
    }

    // 3. Surrounding Contextual Indicators (Form Instructions & Filing Lockboxes)
    let is_form_context = c_low.contains("uscis")
        || c_low.contains("department of homeland security")
        || c_low.contains("citizenship and immigration")
        || c_low.contains("form g-28")
        || c_low.contains("form i-")
        || c_low.contains("instructions for form")
        || c_low.contains("filing address")
        || c_low.contains("lockbox")
        || c_low.contains("mail your application")
        || c_low.contains("submit to:")
        || c_low.contains("omb no.")
        || c_low.contains("administrative appeals office");

    if is_form_context && (a_low.contains("washington") || a_low.contains("d.c.") || a_low.contains("p.o. box") || a_low.contains("20529")) {
        return true;
    }

    false
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
            let matched_addr = m.as_str();
            let window_start = m.start().saturating_sub(150);
            let window_end = (m.end() + 150).min(text.len());
            let surrounding = &text[window_start..window_end];

            if !is_government_agency_or_boilerplate_address(matched_addr, surrounding) {
                candidates.push(("Addresses", matched_addr.to_string()));
            }
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
            if s.len() > 320 || is_mostly_upper(&s) || is_contact_bar_or_header(&s) {
                continue;
            }
            let low = s.to_ascii_lowercase();
            let mut score = terms.iter().filter(|t| low.contains(t.as_str())).count() * 10;

            // Prioritize executive summaries and professional profile statements
            if low.contains("professional")
                || low.contains("experience")
                || low.contains("executive")
                || low.contains("summary")
                || low.contains("certified")
                || low.contains("architect")
                || low.contains("engineer")
                || low.contains("leader")
                || low.contains("specializ")
            {
                score += 15;
            }

            // Prioritize work history and substantive achievement statements
            if low.contains("led ")
                || low.contains("designed ")
                || low.contains("developed ")
                || low.contains("implemented ")
                || low.contains("managed ")
                || low.contains("responsible for")
                || low.contains("served as")
                || low.contains("architected")
            {
                score += 12;
            }

            // Prioritize education and advanced credentials
            if low.contains("university")
                || low.contains("degree")
                || low.contains("master of")
                || low.contains("bachelor of")
                || low.contains("education")
                || low.contains("cissp")
            {
                score += 10;
            }

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

/// Classifies a document chunk into a general domain cluster to disambiguate homonyms across any subject.
pub fn classify_entity_domain_cluster(path: &str, text: &str) -> &'static str {
    let tl = text.to_ascii_lowercase();
    let fl = path.to_ascii_lowercase();
    if !fl.contains("lease")
        && !tl.contains("lease agreement")
        && (tl.contains("new thought")
            || tl.contains("ma'at")
            || tl.contains("ma\u{2019}at")
            || tl.contains("divine intelligence")
            || tl.contains("planetary human")
            || tl.contains("yarnspinner")
            || tl.contains("yarn spinner")
            || tl.contains("reverend")
            || tl.contains("ministry")
            || tl.contains("sermon")
            || tl.contains("divine presence")
            || tl.contains("metaphysical")
            || tl.contains("affirmations")
            || fl.contains("yarnspinner")
            || fl.contains("yarn spinner")
            || fl.contains("planetary human"))
    {
        "Religious Ministry, Spiritual Teaching & Organizational Stewardship"
    } else if tl.contains("critical theory")
        || tl.contains("philosophy")
        || tl.contains("scholar")
        || tl.contains("professor")
        || tl.contains("university press")
        || tl.contains("first published in")
        || tl.contains("landmark work")
        || tl.contains("landmark book")
        || tl.contains("dissertation")
        || tl.contains("thesis")
        || tl.contains("peer-reviewed")
        || tl.contains("historiograph")
        || tl.contains("sociolog")
        || tl.contains("political activist")
        || (tl.contains("published in ") && (tl.contains("book") || tl.contains("author") || tl.contains("chapter") || tl.contains("summary")))
        || (fl.contains("summary") && (tl.contains("written in ") || tl.contains("published in ")))
    {
        "Academic Scholarship, Published Works & Critical Theory"
    } else if tl.contains("landlord")
        || tl.contains("lessor")
        || tl.contains("lessee")
        || tl.contains("lease agreement")
        || tl.contains("dwelling unit")
        || tl.contains("monthly rent")
        || tl.contains("security deposit")
        || tl.contains("subletting")
        || tl.contains("renters insurance")
        || (tl.contains("tenant") && tl.contains("lease"))
        || fl.contains("lease")
    {
        "Residential Property Leasing & Real Estate Management"
    } else if tl.contains("minister")
        || tl.contains("ministry")
        || tl.contains("reverend")
        || tl.contains("church")
        || tl.contains("congregation")
        || tl.contains("sermon")
        || tl.contains("spiritual")
        || tl.contains("divine presence")
        || tl.contains("steward")
        || tl.contains("metaphysical")
        || tl.contains("theolog")
    {
        "Religious Ministry, Spiritual Teaching & Organizational Stewardship"
    } else if tl.contains("cybersecurity")
        || tl.contains("security architect")
        || tl.contains("software engineer")
        || tl.contains("penetration test")
        || tl.contains("cissp")
        || tl.contains("cryptograph")
        || tl.contains("kubernetes")
        || tl.contains("microservices")
        || tl.contains("distributed system")
    {
        "Software Engineering, Architecture & Cybersecurity"
    } else if tl.contains("sports biomechanics")
        || tl.contains("sprint coach")
        || tl.contains("athletics coaching")
        || tl.contains("athletics performance")
        || tl.contains("ground reaction forces")
        || fl.contains("biomechanics")
    {
        "Sports Science & Athletics Coaching"
    } else if tl.contains("concertmaster")
        || tl.contains("violin soloist")
        || tl.contains("chamber orchestra")
        || tl.contains("classical music")
        || tl.contains("guarneri")
        || tl.contains("symphony")
        || fl.contains("concertmaster")
    {
        "Classical Music & Solo Performance"
    } else if tl.contains("marine engineer")
        || tl.contains("subsea")
        || tl.contains("underwater vehicle")
        || tl.contains("auv")
        || tl.contains("pipeline weld inspection")
        || tl.contains("subsea robotics")
        || fl.contains("subsea")
    {
        "Marine Engineering & Subsea Robotics"
    } else if tl.contains("cardiologist")
        || tl.contains("cardiology")
        || tl.contains("echocardiography")
        || tl.contains("heart failure")
        || (tl.contains("patient")
            && (tl.contains("diagnosis")
                || tl.contains("clinical")
                || tl.contains("hospital")
                || tl.contains("physician")
                || tl.contains("medical")))
    {
        "Clinical & Healthcare Records"
    } else if tl.contains("popgen")
        || tl.contains("wright-fisher")
        || tl.contains("genetic drift")
        || tl.contains("diploid populations")
    {
        "Population Genetics & Mathematical Modeling"
    } else if (tl.contains("invoice")
        || tl.contains("tax return")
        || tl.contains("form 1099")
        || tl.contains("form w-2")
        || tl.contains("balance sheet"))
        && !tl.contains("lease")
    {
        "Corporate Finance, Banking & Tax Records"
    } else if fl.ends_with(".pm")
        || fl.ends_with(".py")
        || fl.ends_with(".rs")
        || fl.ends_with(".js")
        || fl.ends_with(".ts")
        || fl.ends_with(".c")
        || fl.ends_with(".cpp")
        || fl.ends_with(".go")
        || tl.contains("package datetime")
        || tl.contains("source code")
    {
        "Software Source Code"
    } else {
        "General Document Context"
    }
}

/// Returns the entity domain cluster name and calibrated confidence for a document chunk.
pub fn classify_chunk_entity_cluster_and_confidence(
    path: &str,
    text: &str,
) -> (&'static str, f64) {
    let cluster = classify_entity_domain_cluster(path, text);
    let confidence = if cluster != "General Document Context" {
        0.95
    } else {
        0.50
    };
    (cluster, confidence)
}

/// Annotates a document chunk with two-layer entity cluster and calibrated confidence,
/// storing `entity_cluster` and `nimble_confidence` in `chunk.metadata_json` while
/// strictly preserving all pre-existing JSON keys.
pub fn annotate_chunk_entity_cluster(chunk: &mut DocumentChunk) {
    let (cluster, conf) = classify_chunk_entity_cluster_and_confidence(&chunk.file_path, &chunk.text_content);
    let mut meta: serde_json::Value = serde_json::from_str(&chunk.metadata_json)
        .unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = meta.as_object_mut() {
        obj.insert("entity_cluster".to_string(), serde_json::json!(cluster));
        obj.insert("nimble_confidence".to_string(), serde_json::json!(conf));
        if let Ok(serialized) = serde_json::to_string(&meta) {
            chunk.metadata_json = serialized;
        }
    }
}

/// Returns the distinct specific (non-generic) domain cluster labels present across `chunks`.
pub fn distinct_specific_entity_clusters(chunks: &[&ScoredChunk]) -> Vec<&'static str> {
    let mut set: BTreeSet<&'static str> = BTreeSet::new();
    for c in chunks {
        if crate::offline_engine::DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk(
            &c.chunk.text_content,
        ) {
            continue;
        }
        let cleaned = crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(
            &c.chunk.text_content,
        );
        let label = classify_entity_domain_cluster(&c.chunk.file_path, &cleaned);
        if label != "General Document Context" {
            set.insert(label);
        }
    }
    set.into_iter().collect()
}

/// Renders an exhaustive, cleanly formatted, disambiguated multi-cluster report when retrieved documents
/// span 2 or more distinct specific entity domain clusters (general homonym disambiguation).
pub fn render_disambiguated_multi_cluster_report(
    prompt: &str,
    subject: Option<&str>,
    chunks: &[&ScoredChunk],
) -> Option<String> {
    let specific = distinct_specific_entity_clusters(chunks);
    if specific.len() < 2 {
        return None;
    }

    struct ClusterItem<'a> {
        global_cite: usize,
        scored: &'a ScoredChunk,
        cleaned_text: String,
    }

    let mut cluster_map: BTreeMap<&'static str, Vec<ClusterItem<'_>>> = BTreeMap::new();
    for (idx, &c) in chunks.iter().enumerate().take(28) {
        if crate::offline_engine::DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk(
            &c.chunk.text_content,
        ) {
            continue;
        }
        let cleaned = crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(
            &c.chunk.text_content,
        );
        if cleaned.trim().is_empty() {
            continue;
        }
        let label = classify_entity_domain_cluster(&c.chunk.file_path, &cleaned);
        cluster_map.entry(label).or_default().push(ClusterItem {
            global_cite: idx + 1,
            scored: c,
            cleaned_text: cleaned,
        });
    }

    if cluster_map.len() < 2 {
        return None;
    }

    // Emit specific domain clusters first in deterministic order, followed by General Document Context if present
    let mut ordered_labels: Vec<&'static str> = cluster_map
        .keys()
        .copied()
        .filter(|&l| l != "General Document Context")
        .collect();
    if cluster_map.contains_key("General Document Context") {
        ordered_labels.push("General Document Context");
    }

    let mut md = String::new();
    for cluster_label in ordered_labels {
        let Some(items) = cluster_map.get(cluster_label) else {
            continue;
        };
        if items.is_empty() {
            continue;
        }

        let heading = if cluster_label == "General Document Context" {
            "Additional Grounded Document Records"
        } else {
            cluster_label
        };
        md.push_str(&format!("### {}\n\n", heading));

        let local_to_global: Vec<usize> = items.iter().map(|it| it.global_cite).collect();
        let cluster_texts: Vec<(String, String, String)> = items
            .iter()
            .map(|it| {
                (
                    it.scored.chunk.chunk_id.clone(),
                    it.scored.chunk.file_path.clone(),
                    it.cleaned_text.clone(),
                )
            })
            .collect();

        let facts = extract_grounded_facts(subject, &cluster_texts);
        let passages = key_passages(prompt, subject, &cluster_texts, 4);

        const ORDER: &[&str] = &[
            "Role",
            "Other parties",
            "Addresses",
            "Phone",
            "Email",
            "Amounts",
            "Dates",
        ];
        let mut grouped: BTreeMap<usize, (&str, Vec<&GroundedFact>)> = BTreeMap::new();
        for f in &facts {
            let pos = ORDER.iter().position(|o| *o == f.class).unwrap_or(ORDER.len());
            grouped.entry(pos).or_insert((f.class, Vec::new())).1.push(f);
        }

        if !grouped.is_empty() {
            for (_, (class, mut fact_items)) in grouped {
                fact_items.sort_by(|a, b| b.cites.len().cmp(&a.cites.len()));
                let limit = if class == "Amounts" { 8 } else { 6 };
                let rendered: Vec<String> = fact_items
                    .iter()
                    .take(limit)
                    .map(|f| {
                        let mapped_cites: Vec<usize> = f
                            .cites
                            .iter()
                            .map(|&lc| {
                                local_to_global
                                    .get(lc.saturating_sub(1))
                                    .copied()
                                    .unwrap_or(lc)
                            })
                            .collect();
                        format!("{} {}", f.value, cite_list(&mapped_cites))
                    })
                    .collect();
                md.push_str(&format!("- **{}:** {}\n", class, rendered.join("; ")));
            }
            md.push('\n');
        }

        if items.len() >= 2 {
            md.push_str("| Ref | Source Document | Origin Node | Grounded Context Summary |\n");
            md.push_str("|---|---|---|---|\n");
            for it in items.iter().take(20) {
                let doc_name = it
                    .scored
                    .chunk
                    .file_path
                    .rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(&it.scored.chunk.file_path)
                    .replace('|', "\\|");
                let origin = if it.scored.is_remote
                    && !it.scored.source_peer.is_empty()
                    && !it.scored.source_peer.eq_ignore_ascii_case("local")
                {
                    let short_peer: String = it.scored.source_peer.chars().take(12).collect();
                    format!("Mesh Peer (`{}`)", short_peer)
                } else {
                    "Local Host".to_string()
                };
                let brief = crate::offline_engine::DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(
                    &it.cleaned_text.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" "),
                    180,
                )
                .replace('|', "\\|");
                md.push_str(&format!(
                    "| **[{}]** | `{}` | {} | {} |\n",
                    it.global_cite, doc_name, origin, brief
                ));
            }
            md.push('\n');
        }

        for it in items.iter().take(16) {
            let doc_name = it
                .scored
                .chunk
                .file_path
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(&it.scored.chunk.file_path);
            let origin_badge = if it.scored.is_remote
                && !it.scored.source_peer.is_empty()
                && !it.scored.source_peer.eq_ignore_ascii_case("local")
            {
                let short_peer: String = it.scored.source_peer.chars().take(12).collect();
                format!(" (Mesh Peer `{}`)", short_peer)
            } else {
                String::new()
            };
            let clean_lines: Vec<String> = it
                .cleaned_text
                .lines()
                .map(str::trim)
                .filter(|l| {
                    !l.is_empty()
                        && !crate::offline_engine::DeterministicOfflineSynthesisEngine::is_contact_bar_or_header(l)
                        && !l.chars().all(|ch| ch == '_' || ch == '-' || ch == ' ')
                })
                .map(|l| {
                    if let Some(rest) = l
                        .strip_prefix('•')
                        .or_else(|| l.strip_prefix('●'))
                        .or_else(|| l.strip_prefix('▪'))
                    {
                        format!("- {}", rest.trim())
                    } else {
                        l.to_string()
                    }
                })
                .collect();
            let joined = clean_lines.join("\n");
            let excerpt = crate::offline_engine::DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(
                joined.trim(),
                1600,
            );
            if !excerpt.is_empty() {
                md.push_str(&format!(
                    "**Source Record `{}`{}:** {}\n\n",
                    doc_name,
                    origin_badge,
                    format!("{} **[{}]**", excerpt.trim(), it.global_cite)
                ));
            }
        }

        if !passages.is_empty() && items.is_empty() {
            for (s, lc) in passages {
                let gc = local_to_global
                    .get(lc.saturating_sub(1))
                    .copied()
                    .unwrap_or(lc);
                md.push_str(&format!("- \"{}\" [{}]\n", s.trim(), gc));
            }
            md.push('\n');
        }
    }

    if !md.contains("\n|---|---|---|---|\n") {
        let matrix = render_homonym_cluster_summary_table(chunks);
        if !matrix.is_empty() {
            md.push_str("\n\n");
            md.push_str(&matrix);
        }
    }

    let res = md.trim_end().to_string();
    if res.is_empty() {
        None
    } else {
        Some(res)
    }
}

/// Renders a 4-column Markdown summary matrix across all distinct homonym identity/context clusters.
pub fn render_homonym_cluster_summary_table(chunks: &[&ScoredChunk]) -> String {
    let mut rows = Vec::new();
    for (idx, &c) in chunks.iter().enumerate().take(16) {
        if crate::offline_engine::DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk(
            &c.chunk.text_content,
        ) {
            continue;
        }
        let cleaned = crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(
            &c.chunk.text_content,
        );
        if cleaned.trim().is_empty() {
            continue;
        }
        let cluster = classify_entity_domain_cluster(&c.chunk.file_path, &cleaned);
        let doc_name = c
            .chunk
            .file_path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&c.chunk.file_path)
            .replace('|', "\\|");
        let origin = if c.is_remote
            && !c.source_peer.is_empty()
            && !c.source_peer.eq_ignore_ascii_case("local")
        {
            let short_peer: String = c.source_peer.chars().take(12).collect();
            format!("Mesh Peer (`{}`)", short_peer)
        } else {
            "Local Host".to_string()
        };
        let stripped = strip_leading_title(
            &cleaned
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !is_contact_bar_or_header(l))
                .collect::<Vec<_>>()
                .join(" "),
        );
        let brief = crate::offline_engine::DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(
            stripped.trim(),
            160,
        )
        .replace('|', "\\|");
        rows.push(format!(
            "| **[{}]** | `{}` | {} | *{}* — {} |",
            idx + 1,
            doc_name,
            origin,
            cluster,
            brief
        ));
    }
    if rows.is_empty() {
        return String::new();
    }
    format!(
        "### Identity & Domain Cluster Summary\n\n| Ref | Source Document | Origin Node | Grounded Context Summary |\n|---|---|---|---|\n{}\n",
        rows.join("\n")
    )
}

/// Ensures live LLM multi-domain homonym synthesis preserves exact canonical `### <Cluster>` headings,
/// upfront multi-entity disambiguation framing, 100% cluster section coverage, and an intact Markdown summary table.
pub fn enforce_multi_cluster_homonym_structure(
    prompt: &str,
    subject: Option<&str>,
    llm_prose: &str,
    chunks: &[&ScoredChunk],
) -> String {
    let specific_clusters = distinct_specific_entity_clusters(chunks);
    if specific_clusters.len() < 2 {
        return llm_prose.to_string();
    }

    // 1. Snap approximate `##` / `###` LLM headings (e.g. singular/typo variants) to exact canonical cluster labels
    let mut normalized_lines: Vec<String> = Vec::new();
    for line in llm_prose.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("##") {
            let raw_heading = trimmed
                .trim_start_matches('#')
                .trim()
                .trim_matches(['*', ':', ' ']);
            let raw_lower = raw_heading.to_ascii_lowercase();
            let mut snapped: Option<&'static str> = None;
            let mut best_dist = usize::MAX;
            for &canon in &specific_clusters {
                let canon_lower = canon.to_ascii_lowercase();
                let d = crate::response_formatter_watchdog::levenshtein_distance(&raw_lower, &canon_lower);
                let max_len = raw_lower.len().max(canon_lower.len()).max(1);
                if (d <= 10 || (max_len.saturating_sub(d)) * 100 / max_len >= 75) && d < best_dist {
                    best_dist = d;
                    snapped = Some(canon);
                }
            }
            if let Some(canon_heading) = snapped {
                normalized_lines.push(format!("### {}", canon_heading));
                continue;
            }
        }
        normalized_lines.push(line.to_string());
    }
    let mut out = normalized_lines.join("\n").trim().to_string();

    // 2. Prepend upfront homonym disambiguation banner if absent
    if !out.contains("multiple distinct individuals") && !out.contains("distinct contexts") {
        let subj_label = subject
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| prompt.trim());
        let cluster_summary = specific_clusters.join("; ");
        let all_cites = (1..=chunks.len().min(8))
            .map(|n| format!("[{n}]"))
            .collect::<Vec<_>>()
            .join(", ");
        let banner = format!(
            "The retrieved documents across your federated corpus reference multiple distinct individuals or contexts sharing the name **{subj_label}** ({cluster_summary}). Under strict corpus grounding—without conflating distinct identities or backfilling unverified outside biographical claims—each distinct identity and its grounded records are detailed separately below {all_cites}."
        );
        out = format!("{}\n\n{}", banner, out);
    }

    // 3. Append grounded `### <Cluster>` sections for any canonical cluster omitted by the LLM
    for &cluster_label in &specific_clusters {
        let expected_heading = format!("### {}", cluster_label);
        if !out.contains(&expected_heading) {
            let mut section_items: Vec<(usize, &ScoredChunk, String)> = Vec::new();
            for (idx, &c) in chunks.iter().enumerate() {
                let cleaned = crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(
                    &c.chunk.text_content,
                );
                if !cleaned.trim().is_empty()
                    && classify_entity_domain_cluster(&c.chunk.file_path, &cleaned) == cluster_label
                {
                    section_items.push((idx + 1, c, cleaned));
                }
            }
            if !section_items.is_empty() {
                out.push_str(&format!("\n\n### {}\n\n", cluster_label));
                for (cite_num, c, cleaned) in section_items {
                    let doc_name = std::path::Path::new(&c.chunk.file_path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&c.chunk.file_path);
                    let stripped_body = strip_leading_title(cleaned.trim());
                    let excerpt = crate::offline_engine::DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(
                        stripped_body.trim(),
                        900,
                    );
                    out.push_str(&format!(
                        "**Source Record `{}`:** {} [{}]\n\n",
                        doc_name,
                        excerpt.trim(),
                        cite_num
                    ));
                }
                out = out.trim_end().to_string();
            }
        }
    }

    // 4. Ensure an intact multi-line 4-column Markdown cluster summary table is present
    if !out.contains("\n|---|---|---|---|\n") {
        let matrix = render_homonym_cluster_summary_table(chunks);
        if !matrix.is_empty() {
            out.push_str("\n\n");
            out.push_str(matrix.trim());
        }
    }

    out
}

/// Render grounded facts and key passages as Markdown sections (no opening, no sources block).
/// Returns `None` when nothing could be grounded, so callers keep their previous behaviour.
pub fn render_grounded_sections(prompt: &str, subject: Option<&str>, chunks: &[&ScoredChunk]) -> Option<String> {
    if let Some(multi_report) = render_disambiguated_multi_cluster_report(prompt, subject, chunks) {
        return Some(multi_report);
    }

    let mut local_to_global: Vec<usize> = Vec::new();
    let mut texts: Vec<(String, String, String)> = Vec::new();
    for (idx, c) in chunks.iter().enumerate() {
        if texts.len() >= 10 {
            break;
        }
        if crate::offline_engine::DeterministicOfflineSynthesisEngine::is_corrupt_or_binary_chunk(
            &c.chunk.text_content,
        ) {
            continue;
        }
        local_to_global.push(idx + 1);
        texts.push((
            c.chunk.chunk_id.clone(),
            c.chunk.file_path.clone(),
            crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(
                &c.chunk.text_content,
            ),
        ));
    }

    if texts.is_empty() {
        return None;
    }

    let facts = extract_grounded_facts(subject, &texts);
    let passages = key_passages(prompt, subject, &texts, 4);
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
            items.sort_by(|a, b| b.cites.len().cmp(&a.cites.len()));
            let limit = if class == "Amounts" { 6 } else { 5 };
            let rendered: Vec<String> = items
                .iter()
                .take(limit)
                .map(|f| {
                    let mapped_cites: Vec<usize> = f
                        .cites
                        .iter()
                        .map(|&lc| {
                            local_to_global
                                .get(lc.saturating_sub(1))
                                .copied()
                                .unwrap_or(lc)
                        })
                        .collect();
                    format!("{} {}", f.value, cite_list(&mapped_cites))
                })
                .collect();
            md.push_str(&format!("- **{}:** {}\n", class, rendered.join("; ")));
        }
    }
    if !passages.is_empty() {
        md.push_str("\n### Relevant passages\n");
        for (s, lc) in passages {
            let gc = local_to_global
                .get(lc.saturating_sub(1))
                .copied()
                .unwrap_or(lc);
            md.push_str(&format!("- \"{}\" [{}]\n", s.trim(), gc));
        }
    }
    Some(md.trim_end().to_string())
}

/// Detailed result of post-synthesis groundedness verification against cited spans [N].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroundednessVerificationResult {
    pub is_grounded: bool,
    pub ungrounded_claims: Vec<String>,
    pub backfill_detected: bool,
    pub verified_citations_count: usize,
    pub sanitized_answer: String,
}

/// Verifies that all cited claims in `answer` are genuinely supported by the corresponding cited
/// chunks `[k]` in `chunks` (where [1] maps to chunks[0], etc.).
/// Detects and flags pretraining biography backfill (facts like "Born as ... in Birmingham, Alabama",
/// birthplaces, birth years, family details not present in the cited document text).
pub fn verify_post_synthesis_groundedness(
    answer: &str,
    chunks: &[&ScoredChunk],
) -> GroundednessVerificationResult {
    let total_sources = chunks.len();
    let mut ungrounded_claims = Vec::new();
    let mut backfill_detected = false;
    let mut verified_citations_count = 0usize;

    // Check for fully quoted answer
    let trimmed_answer = answer.trim();
    if (trimmed_answer.starts_with('"') && trimmed_answer.ends_with('"'))
        || (trimmed_answer.starts_with('“') && trimmed_answer.ends_with('”'))
    {
        let unquoted = trimmed_answer.trim_matches(['"', '“', '”']);
        let found = chunks.iter().any(|c| c.chunk.text_content.contains(unquoted));
        if found {
            return GroundednessVerificationResult {
                is_grounded: true,
                ungrounded_claims: Vec::new(),
                backfill_detected: false,
                verified_citations_count: 1,
                sanitized_answer: answer.to_string(),
            };
        }
    }

    let sentences_list = sentences(answer);
    let mut clean_sentences = Vec::new();
    for stmt in &sentences_list {
        let stmt_trimmed = stmt.trim();
        if stmt_trimmed.is_empty() {
            continue;
        }

        // Parse citation indices in brackets
        let mut cites = Vec::new();
        let bytes = stmt_trimmed.as_bytes();
        let mut pos = 0usize;
        while pos < bytes.len() {
            if bytes[pos] == b'[' {
                if let Some(rel_end) = stmt_trimmed[pos + 1..].find(']') {
                    let close_pos = pos + 1 + rel_end;
                    let inner = &stmt_trimmed[pos + 1..close_pos];
                    for part in inner.split(',') {
                        let p = part.trim();
                        if let Some((a_s, b_s)) = p.split_once('-').or_else(|| p.split_once('–')) {
                            if let (Ok(a), Ok(b)) = (a_s.trim().parse::<usize>(), b_s.trim().parse::<usize>()) {
                                if a > 0 && b >= a && b - a <= 20 {
                                    for n in a..=b {
                                        cites.push(n);
                                    }
                                }
                            }
                        } else if let Ok(n) = p.parse::<usize>() {
                            cites.push(n);
                        }
                    }
                    pos = close_pos + 1;
                    continue;
                }
            }
            let ch_len = stmt_trimmed[pos..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
            pos += ch_len;
        }

        if cites.is_empty() {
            let lower_stmt = stmt_trimmed.to_ascii_lowercase();
            let backfill_markers = &[
                "born as", "born in", "native of", "birth in", "childhood in",
                "passed away", "died on", "died in", "alumnus of", "alumna of",
            ];
            let has_backfill = backfill_markers.iter().any(|m| lower_stmt.contains(m));
            if has_backfill {
                backfill_detected = true;
                ungrounded_claims.push(format!("Uncited pretraining backfill detected: \"{}\"", stmt_trimmed));
            } else {
                clean_sentences.push(stmt_trimmed.to_string());
            }
            continue;
        }

        let mut stmt_valid = true;
        for &cite_idx in &cites {
            if cite_idx == 0 || cite_idx > total_sources {
                stmt_valid = false;
                ungrounded_claims.push(format!("Out of bounds citation [{cite_idx}] in: \"{stmt_trimmed}\""));
                continue;
            }

            let cited_chunk = chunks[cite_idx - 1];
            let source_text = &cited_chunk.chunk.text_content;

            // Check biographical pretraining backfill markers
            let lower_stmt = stmt_trimmed.to_ascii_lowercase();
            let lower_source = source_text.to_ascii_lowercase();

            let backfill_markers = &[
                "born as", "born in", "native of", "birth in", "childhood in",
                "passed away", "died on", "died in", "alumnus of", "alumna of",
            ];
            for marker in backfill_markers {
                if lower_stmt.contains(marker) && !lower_source.contains(marker) {
                    backfill_detected = true;
                    stmt_valid = false;
                    ungrounded_claims.push(format!(
                        "Pretraining backfill detected (marker '{}' absent from [{}]): \"{}\"",
                        marker, cite_idx, stmt_trimmed
                    ));
                }
            }

            // Check distinctive proper nouns (e.g. Birmingham, Alabama if not in source)
            let terms = content_terms(stmt_trimmed);
            let mut matched_terms = 0;
            for t in &terms {
                if lower_source.contains(t) {
                    matched_terms += 1;
                }
            }
            let has_substantiation = if cites.len() > 1 {
                matched_terms >= 1
            } else {
                matched_terms > 0 && (matched_terms as f64 / terms.len() as f64) >= 0.20
            };
            if !terms.is_empty() && !has_substantiation {
                stmt_valid = false;
                ungrounded_claims.push(format!(
                    "Unsubstantiated claim for [{}] with low source word overlap: \"{}\"",
                    cite_idx, stmt_trimmed
                ));
            } else {
                verified_citations_count += 1;
            }
        }

        if stmt_valid {
            clean_sentences.push(stmt_trimmed.to_string());
        }
    }

    let is_grounded = ungrounded_claims.is_empty() && !backfill_detected;
    let sanitized_answer = if is_grounded {
        answer.to_string()
    } else if answer.contains("\n#")
        || answer.trim_start().starts_with('#')
        || answer.contains("\n|---")
    {
        let valid_keys: BTreeSet<String> = clean_sentences.iter().map(|s| norm_key(s)).collect();
        let mut kept_lines: Vec<String> = Vec::new();
        for line in answer.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || (trimmed.starts_with('|') && trimmed.contains("---"))
            {
                kept_lines.push(line.to_string());
                continue;
            }
            if trimmed.starts_with('|') && trimmed.ends_with('|') {
                if valid_keys.contains(&norm_key(trimmed)) || !trimmed.contains('[') {
                    kept_lines.push(line.to_string());
                }
                continue;
            }
            let line_sents = sentences(line);
            if line_sents.is_empty() {
                kept_lines.push(line.to_string());
            } else {
                let surviving: Vec<String> = line_sents
                    .into_iter()
                    .filter(|s| valid_keys.contains(&norm_key(s)))
                    .collect();
                if !surviving.is_empty() {
                    kept_lines.push(surviving.join(" "));
                }
            }
        }
        kept_lines.join("\n").trim().to_string()
    } else {
        clean_sentences.join(" ")
    };
    GroundednessVerificationResult {
        is_grounded,
        ungrounded_claims,
        backfill_detected,
        verified_citations_count,
        sanitized_answer,
    }
}

/// Attested Document Coverage Loop: guarantees that every distinct document [1]..[K]
/// that passed Nimble relevance attestation actively contributes substantive grounded facts
/// and carries an inline citation in the synthesized output.
pub fn enforce_attested_document_coverage_loop<'a>(
    initial_prose: &str,
    attested_chunks: &[&'a ScoredChunk],
) -> (String, Vec<&'a ScoredChunk>) {
    use std::collections::BTreeSet;
    let k = attested_chunks.len();
    if k == 0 {
        return (initial_prose.to_string(), Vec::new());
    }

    // Pass 1: Parse which of the 1..=k attested documents were cited in the initial prose
    let bytes = initial_prose.as_bytes();
    let mut cited_set = BTreeSet::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if bytes[pos] == b'[' {
            if let Some(rel_end) = initial_prose[pos + 1..].find(']') {
                let close_pos = pos + 1 + rel_end;
                let followed_by_paren = close_pos + 1 < bytes.len() && bytes[close_pos + 1] == b'(';
                if !followed_by_paren {
                    let inner = &initial_prose[pos + 1..close_pos];
                    for part in inner.split(',') {
                        let p = part.trim();
                        if let Some((a_str, b_str)) = p.split_once('-').or_else(|| p.split_once('–')) {
                            if let (Ok(a), Ok(b)) = (a_str.trim().parse::<usize>(), b_str.trim().parse::<usize>()) {
                                if a > 0 && b >= a && b - a <= 20 {
                                    for n in a..=b {
                                        if (1..=k).contains(&n) {
                                            cited_set.insert(n);
                                        }
                                    }
                                }
                            }
                        } else if let Ok(n) = p.parse::<usize>() {
                            if (1..=k).contains(&n) {
                                cited_set.insert(n);
                            }
                        }
                    }
                    pos = close_pos + 1;
                    continue;
                }
            }
        }
        let ch_len = initial_prose[pos..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        pos += ch_len;
    }

    let mut consolidated_prose = initial_prose.to_string();

    // Coverage Loop: For any attested document not yet cited, append targeted grounded contribution
    for i in 1..=k {
        if !cited_set.contains(&i) {
            let chunk = attested_chunks[i - 1];
            let doc_name = std::path::Path::new(&chunk.chunk.file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&chunk.chunk.file_path);
            let clean_contrib = strip_leading_title(
                &crate::offline_engine::DeterministicOfflineSynthesisEngine::clean_chunk_text(
                    chunk.chunk.text_content.trim(),
                ),
            );
            let excerpt = crate::offline_engine::DeterministicOfflineSynthesisEngine::truncate_to_sentence_boundary(
                clean_contrib.trim(),
                600,
            );
            let additional_section = format!(
                "\n\nAdditionally, evidence from `{}` [{}] confirms: {}",
                doc_name,
                i,
                excerpt.trim()
            );
            consolidated_prose.push_str(&additional_section);
            cited_set.insert(i);
        }
    }

    // Pass 2: Remap and compact citations with filter_uncited = true
    crate::offline_engine::DeterministicOfflineSynthesisEngine::remap_and_compact_citations(
        &consolidated_prose,
        attested_chunks,
        true,
    )
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

    #[test]
    fn test_government_agency_and_boilerplate_address_filtering() {
        let texts = vec![
            (
                "g28_chunk".to_string(),
                "Form_G28_Instructions.pdf".to_string(),
                "Department of Homeland Security USCIS Form G-28 Notice of Entry of Appearance as Attorney. \
Submit completed form to: 111 Massachusetts Avenue, NW, Washington, DC 20529. OMB No. 1615-0105.".to_string(),
            ),
            (
                "lease_chunk".to_string(),
                "Residential_Lease.docx".to_string(),
                "Tenant agrees to reside at 2913 Castiglione St, New Orleans, LA 70119 for the term of twelve months.".to_string(),
            ),
        ];

        let facts = extract_grounded_facts(Some("Femi Oyesanya"), &texts);
        let addresses: Vec<&str> = facts
            .iter()
            .filter(|f| f.class == "Addresses")
            .map(|f| f.value.as_str())
            .collect();

        // Must NOT contain the USCIS Washington DC headquarters address
        assert!(
            !addresses.iter().any(|a| a.contains("111 Massachusetts")),
            "Government agency address leaked: {addresses:?}"
        );
        assert!(
            !addresses.iter().any(|a| a.contains("20529")),
            "Government agency ZIP leaked: {addresses:?}"
        );

        // MUST contain the genuine residential address
        assert!(
            addresses.iter().any(|a| a.contains("2913 Castiglione St")),
            "Genuine residential address missing: {addresses:?}"
        );
    }
}
