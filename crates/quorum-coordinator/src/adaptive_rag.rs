//! Adaptive RAG Complexity Routing (#18), Compound Query Decomposition (#8),
//! Multi-Query Retrieval Expansion (#6), and Adaptive Conceptual HyDE (#7).
//!
//! All analysis runs deterministically in <1ms with zero external API dependencies,
//! ensuring compound questions (e.g. `"who is angela davis what is her research"`) are
//! decomposed into focused sub-questions with pronoun coreference resolved (`"her"` ->
//! `"Angela Davis's"`) before parallel hybrid retrieval, while HyDE is strictly gated to
//! abstract conceptual queries (never exact entity or host forensic queries).

use std::collections::BTreeSet;
use std::sync::OnceLock;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Adaptive retrieval depth selected by query complexity classification (#18 Adaptive RAG).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetrievalDepth {
    /// Direct single-pass hybrid search (simple factual/single-clause lookup).
    SingleHop,
    /// Compound multi-part question decomposed into parallel sub-queries + RRF merge.
    DecomposedMultiQuery,
    /// Abstract conceptual question eligible for Adaptive HyDE + Multi-Query expansion.
    ConceptualHyde,
    /// Deep entity/cross-document comparative query engaging GraphRAG (AtlasKV) + multi-hop.
    DeepGraph,
}

/// Output of the Adaptive RAG query planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdaptiveQueryPlan {
    pub depth: RetrievalDepth,
    /// Primary subject/entity extracted cleanly without compound tail echo (e.g. `"Angela Davis"`).
    pub primary_subject: Option<String>,
    /// Decomposed sub-questions (1 item for simple queries; 2–4 items for compound queries).
    pub sub_questions: Vec<String>,
    /// Deduplicated search query variants for parallel Multi-Query Retrieval (#6).
    pub query_variants: Vec<String>,
    /// Optional conceptual HyDE seed passage (#7) — strictly `None` on entity & forensic queries.
    pub hyde_passage: Option<String>,
}

/// Classifies query complexity and produces an `AdaptiveQueryPlan` combining:
/// - #18 Adaptive RAG depth routing
/// - #8 Query Decomposition (with pronoun coreference resolution)
/// - #6 Multi-Query Retrieval variants (capped at 3)
/// - #7 Adaptive HyDE (strictly conceptual-only)
pub fn plan_adaptive_query(raw_query: &str, is_forensic: bool) -> AdaptiveQueryPlan {
    let trimmed = raw_query.trim();
    if trimmed.is_empty() {
        return AdaptiveQueryPlan {
            depth: RetrievalDepth::SingleHop,
            primary_subject: None,
            sub_questions: Vec::new(),
            query_variants: Vec::new(),
            hyde_passage: None,
        };
    }

    if is_forensic {
        return AdaptiveQueryPlan {
            depth: RetrievalDepth::SingleHop,
            primary_subject: None,
            sub_questions: vec![trimmed.to_string()],
            query_variants: vec![trimmed.to_string()],
            hyde_passage: None,
        };
    }

    let primary_subject = extract_clean_primary_subject(trimmed);
    let sub_questions = decompose_compound_query(trimmed, primary_subject.as_deref());
    let lower = trimmed.to_ascii_lowercase();

    let is_comparative_or_graph = lower.contains("compare ")
        || lower.contains("relationship between ")
        || lower.contains("how do ")
        || lower.contains("connected to ")
        || lower.contains("across all ")
        || sub_questions.len() >= 3;

    let is_conceptual = primary_subject.is_none()
        && (lower.starts_with("explain ")
            || lower.starts_with("describe ")
            || lower.starts_with("how does ")
            || lower.starts_with("why does ")
            || lower.starts_with("what is the concept of ")
            || lower.contains("theory of ")
            || lower.contains("architecture of ")
            || lower.contains("principles of "));

    let depth = if is_comparative_or_graph {
        RetrievalDepth::DeepGraph
    } else if sub_questions.len() >= 2 {
        RetrievalDepth::DecomposedMultiQuery
    } else if is_conceptual {
        RetrievalDepth::ConceptualHyde
    } else {
        RetrievalDepth::SingleHop
    };

    let query_variants = generate_query_variants(trimmed, primary_subject.as_deref(), &sub_questions);
    let hyde_passage = if depth == RetrievalDepth::ConceptualHyde {
        build_adaptive_hyde_passage(trimmed)
    } else {
        None
    };

    AdaptiveQueryPlan {
        depth,
        primary_subject,
        sub_questions,
        query_variants,
        hyde_passage,
    }
}

/// Extracts the clean primary subject/entity from entity-oriented queries, stripping any
/// secondary question tail (e.g. `"who is angela davis what is her research"` -> `Some("Angela Davis")`).
pub fn extract_clean_primary_subject(query: &str) -> Option<String> {
    let clean = query
        .trim()
        .trim_end_matches(|c: char| matches!(c, '?' | '!' | '.'))
        .trim();
    let lower = clean.to_ascii_lowercase();

    let after_lead = [
        "who is ",
        "who was ",
        "who are ",
        "who were ",
        "who's ",
        "tell me about ",
        "what do you know about ",
        "biography of ",
    ]
    .iter()
    .find_map(|prefix| {
        if lower.starts_with(prefix) {
            Some(clean[prefix.len()..].trim())
        } else {
            None
        }
    })?;

    let after_low = after_lead.to_ascii_lowercase();
    let mut cut = after_lead.len();
    for sep in [
        "?",
        ",",
        ";",
        " and what ",
        " and where ",
        " and when ",
        " and how ",
        " and why ",
        " what is ",
        " what are ",
        " what was ",
        " what were ",
        " what does ",
        " what did ",
        " where is ",
        " where did ",
        " when did ",
        " how did ",
        " how does ",
        " why did ",
        " tell me ",
    ] {
        if let Some(pos) = after_low.find(sep) {
            if pos >= 2 && pos < cut {
                cut = pos;
            }
        }
    }

    let raw_subj = after_lead[..cut].trim();
    let words: Vec<&str> = raw_subj.split_whitespace().collect();
    if words.is_empty() || words.len() > 5 {
        return None;
    }
    let titled = words
        .into_iter()
        .map(|w| {
            let mut cs = w.chars();
            match cs.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), cs.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(titled)
}

/// Decomposes a multi-part / compound user question into crisp, standalone sub-questions (#8).
/// Resolves possessive/personal pronouns (`her`, `his`, `their`, `she`, `he`) against `primary_subject`.
pub fn decompose_compound_query(query: &str, primary_subject: Option<&str>) -> Vec<String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let raw_parts: Vec<String> = split_compound_clauses(trimmed)
        .into_iter()
        .map(|p| p.trim().trim_matches(|c: char| matches!(c, '?' | ',' | ';')).trim().to_string())
        .filter(|p| p.split_whitespace().count() >= 2)
        .collect();

    let mut raw_parts = raw_parts;
    if raw_parts.len() <= 1 {
        return vec![trimmed.to_string()];
    }

    raw_parts.truncate(4);
    let mut resolved: Vec<String> = Vec::with_capacity(raw_parts.len());
    for (idx, part) in raw_parts.into_iter().enumerate() {
        let mut q = part;
        if idx > 0 {
            if let Some(subj) = primary_subject {
                q = resolve_subject_pronouns(&q, subj);
            }
        }
        if !q.ends_with('?') {
            q.push('?');
        }
        if !resolved.iter().any(|existing| existing.eq_ignore_ascii_case(&q)) {
            resolved.push(q);
        }
    }
    if resolved.is_empty() {
        vec![trimmed.to_string()]
    } else {
        resolved
    }
}

/// Pure-Rust clause boundary splitter (zero regex look-around, O(n)) that preserves the
/// interrogative starter (`what`, `who`, `where`, `when`, `how`, `why`) on each split clause.
fn split_compound_clauses(query: &str) -> Vec<&str> {
    const KEEP_STARTERS: &[&str] = &[
        " what is ",
        " what are ",
        " what was ",
        " what were ",
        " what did ",
        " what does ",
        " where is ",
        " where did ",
        " where was ",
        " when did ",
        " when was ",
        " how did ",
        " how does ",
        " why did ",
        " why does ",
    ];
    const AND_STARTERS: &[&str] = &[
        " and what ",
        " and who ",
        " and where ",
        " and when ",
        " and how ",
        " and why ",
    ];

    let lower = query.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut parts: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        // Explicit punctuation delimiter: `? ` or `; `
        if (bytes[i] == b'?' || bytes[i] == b';') && i + 1 < bytes.len() && bytes[i + 1].is_ascii_whitespace() {
            parts.push(&query[start..i]);
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            start = i;
            continue;
        }
        // Only inspect interrogative clause transitions once the current clause has >= 6 bytes
        if i >= start + 6 && bytes[i] == b' ' {
            let rest = &lower[i..];
            if AND_STARTERS.iter().any(|pat| rest.starts_with(pat)) {
                parts.push(&query[start..i]);
                // Skip ` and ` (5 bytes) so the next clause starts cleanly at `what`/`where`/...
                start = i + 5;
                i = start;
                continue;
            }
            if KEEP_STARTERS.iter().any(|pat| rest.starts_with(pat)) {
                parts.push(&query[start..i]);
                // Skip leading space (1 byte) so the next clause keeps `what is ...`
                start = i + 1;
                i = start;
                continue;
            }
        }
        i += 1;
    }

    if start < query.len() {
        parts.push(&query[start..]);
    }
    parts
}

fn resolve_subject_pronouns(clause: &str, subject: &str) -> String {
    static POSS_RE: OnceLock<Regex> = OnceLock::new();
    static SUBJ_RE: OnceLock<Regex> = OnceLock::new();
    let poss_re = POSS_RE.get_or_init(|| Regex::new(r"(?i)\b(?:her|his|their)\b").expect("poss regex"));
    let subj_re = SUBJ_RE.get_or_init(|| Regex::new(r"(?i)\b(?:she|he)\b").expect("subj regex"));

    let possessive = if subject.ends_with('s') || subject.ends_with('S') {
        format!("{subject}'")
    } else {
        format!("{subject}'s")
    };
    let s1 = poss_re.replace_all(clause, possessive.as_str());
    let s2 = subj_re.replace_all(&s1, subject);
    s2.into_owned()
}

/// Generates 1–3 focused, deduplicated search variants for parallel Multi-Query Retrieval (#6).
pub fn generate_query_variants(
    raw_query: &str,
    primary_subject: Option<&str>,
    sub_questions: &[String],
) -> Vec<String> {
    let mut variants: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    let mut push_unique = |cand: String| {
        let clean = cand.trim().trim_end_matches('?').trim().to_string();
        if clean.len() < 3 {
            return;
        }
        let key = clean.to_ascii_lowercase();
        if seen.insert(key) {
            variants.push(clean);
        }
    };

    for sq in sub_questions {
        push_unique(sq.clone());
    }
    if let Some(subj) = primary_subject {
        push_unique(subj.to_string());
    }
    push_unique(raw_query.to_string());

    variants.truncate(3);
    variants
}

/// Builds a lightweight, strictly grounded conceptual HyDE expansion passage (#7) for abstract
/// conceptual queries (never called for entity lookups or host forensic telemetry queries).
pub fn build_adaptive_hyde_passage(query: &str) -> Option<String> {
    let clean = query.trim().trim_end_matches(['?', '.', '!']).trim();
    if clean.split_whitespace().count() < 3 {
        return None;
    }
    Some(format!(
        "Conceptual overview and technical analysis regarding {clean}: key mechanisms, definitions, historical context, architecture, evidence, and primary themes."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compound_query_decomposition_and_pronoun_coreference() {
        let plan = plan_adaptive_query("who is angela davis what is her research", false);
        assert_eq!(plan.depth, RetrievalDepth::DecomposedMultiQuery);
        assert_eq!(plan.primary_subject.as_deref(), Some("Angela Davis"));
        assert_eq!(plan.sub_questions.len(), 2);
        assert_eq!(plan.sub_questions[0].to_ascii_lowercase(), "who is angela davis?");
        assert!(
            plan.sub_questions[1].contains("Angela Davis'"),
            "Possessive pronoun 'her' must resolve to Angela Davis': {:?}",
            plan.sub_questions
        );
        assert!(plan.sub_questions[1].to_ascii_lowercase().contains("research"));
        assert!(
            plan.hyde_passage.is_none(),
            "Entity lookups must never trigger HyDE hallucination drift"
        );
        assert!(plan.query_variants.len() >= 2 && plan.query_variants.len() <= 3);
    }

    #[test]
    fn test_adaptive_rag_routes_conceptual_and_forensic_queries_distinctly() {
        let conceptual = plan_adaptive_query("explain the theory of intersectional labor economics", false);
        assert_eq!(conceptual.depth, RetrievalDepth::ConceptualHyde);
        assert!(conceptual.hyde_passage.is_some());

        let forensic = plan_adaptive_query("what was the last dns domain my computer queried?", true);
        assert_eq!(forensic.depth, RetrievalDepth::SingleHop);
        assert!(forensic.hyde_passage.is_none());

        let deep = plan_adaptive_query("compare the lease terms across all New Orleans properties", false);
        assert_eq!(deep.depth, RetrievalDepth::DeepGraph);
    }
}
