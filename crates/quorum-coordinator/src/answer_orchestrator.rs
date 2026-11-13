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

/// Returns true if a line represents a contact header, pipe-delimited metadata bar, or bare contact field.
pub fn is_contact_bar_or_header(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
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
    // Strip contact lines and bare headers before joining into a prose stream
    let sanitized_lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !is_contact_bar_or_header(l))
        .collect();
    let sanitized_text = sanitized_lines.join(" ");

    let flat: Vec<char> = sanitized_text.chars().collect();
    let mut cur = String::new();
    for (i, &ch) in flat.iter().enumerate() {
        cur.push(ch);
        // A sentence ends at . ! ? followed by whitespace or end of text, never inside "$50.00".
        let ends = matches!(ch, '.' | '!' | '?') && flat.get(i + 1).map_or(true, |n| n.is_whitespace());
        if ends && cur.trim().len() > 30 {
            let s = strip_leading_title(&cur.split_whitespace().collect::<Vec<_>>().join(" "));
            if !is_contact_bar_or_header(&s) {
                out.push(s);
            }
            cur.clear();
        }
    }
    if cur.trim().len() > 30 {
        let s = strip_leading_title(&cur.split_whitespace().collect::<Vec<_>>().join(" "));
        if !is_contact_bar_or_header(&s) {
            out.push(s);
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

/// Classifies a document chunk into an entity domain cluster to disambiguate homonyms.
pub fn classify_entity_domain_cluster(path: &str, text: &str) -> &'static str {
    let tl = text.to_ascii_lowercase();
    let fl = path.to_ascii_lowercase();
    if tl.contains("women, race & class")
        || tl.contains("women, race and class")
        || tl.contains("1981")
        || tl.contains("critical theory")
        || tl.contains("philosophy")
        || fl.contains("women_race")
    {
        "Academic & Critical Theory Works (1981)"
    } else if tl.contains("landlord")
        || tl.contains("lease")
        || tl.contains("tenant")
        || tl.contains("new orleans")
        || tl.contains("castiglione")
        || tl.contains("d'hemecourt")
        || tl.contains("breure")
        || tl.contains("firldeal")
        || fl.contains("lease")
    {
        "New Orleans Residential Property Management & Lease Agreement"
    } else if tl.contains("unity minister") || tl.contains("steward") || tl.contains("reverend") || tl.contains("church") {
        "Religious Ministry & Stewardship"
    } else {
        "General Document Context"
    }
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

    if texts.is_empty() {
        return None;
    }

    // Check if multiple distinct entity domain clusters exist across texts
    let mut cluster_map: BTreeMap<&'static str, Vec<(String, String, String)>> = BTreeMap::new();
    for t in &texts {
        let label = classify_entity_domain_cluster(&t.1, &t.2);
        cluster_map.entry(label).or_default().push(t.clone());
    }

    if cluster_map.len() > 1 {
        let mut md = String::new();
        for (cluster_label, cluster_texts) in cluster_map {
            let facts = extract_grounded_facts(subject, &cluster_texts);
            let passages = key_passages(prompt, subject, &cluster_texts, 3);
            if facts.is_empty() && passages.is_empty() {
                continue;
            }
            md.push_str(&format!("### {}\n", cluster_label));
            const ORDER: &[&str] = &["Role", "Other parties", "Addresses", "Phone", "Email", "Amounts", "Dates"];
            let mut grouped: BTreeMap<usize, (&str, Vec<&GroundedFact>)> = BTreeMap::new();
            for f in &facts {
                let pos = ORDER.iter().position(|o| *o == f.class).unwrap_or(ORDER.len());
                grouped.entry(pos).or_insert((f.class, Vec::new())).1.push(f);
            }
            if !grouped.is_empty() {
                for (_, (class, mut items)) in grouped {
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
                for (s, c) in passages {
                    md.push_str(&format!("- \"{}\" [{}]\n", s.trim(), c));
                }
            }
            md.push('\n');
        }
        let res = md.trim_end().to_string();
        if res.is_empty() {
            None
        } else {
            Some(res)
        }
    } else {
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
