//! Local RAGAS-Style Evaluation & Markdown Hygiene Harness (#20 RAG Evaluation).
//!
//! Scores any `(query, retrieved_chunks, synthesized_answer)` tuple offline with zero external
//! network calls across four orthogonal dimensions:
//! 1. **Faithfulness** (`0.0..=1.0`): share of declarative answer sentences lexically grounded in
//!    the retrieved chunks (catching unsupported hallucinations).
//! 2. **Answer Relevance** (`0.0..=1.0`): coverage of all decomposed sub-questions (#8).
//! 3. **Context Precision** (`0.0..=1.0`): share of retrieved chunks containing meaningful overlap
//!    with the query / primary subject (catching distractor pollution).
//! 4. **Markdown Hygiene** (`0.0..=1.0`): deterministic check for zero unbalanced `*`/`**`, zero
//!    raw `---` inside table cells, zero mid-word `...` truncations, zero `[1] .` spacing bugs,
//!    zero raw `HYPERLINK` field codes, and zero false conversational `###`/`####` headings.

use std::collections::BTreeSet;
use std::sync::OnceLock;
use quorum_types::ScoredChunk;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Comprehensive offline RAG quality scorecard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RagEvalReport {
    pub faithfulness: f32,
    pub answer_relevance: f32,
    pub context_precision: f32,
    pub markdown_hygiene: f32,
    pub composite_score: f32,
    pub hygiene_violations: Vec<String>,
}

/// Deterministic local RAGAS-style evaluation harness (#20).
pub struct RagEvalHarness;

impl RagEvalHarness {
    pub fn evaluate(
        query: &str,
        retrieved_chunks: &[&ScoredChunk],
        synthesized_answer: &str,
    ) -> RagEvalReport {
        let plan = crate::adaptive_rag::plan_adaptive_query(query, false);

        // 1. Context Precision
        let context_precision = score_context_precision(
            query,
            plan.primary_subject.as_deref(),
            retrieved_chunks,
        );

        // 2. Answer Relevance across all decomposed sub-questions
        let answer_relevance = score_answer_relevance(&plan.sub_questions, synthesized_answer);

        // 3. Faithfulness (grounded sentence ratio against corpus token set)
        let faithfulness = score_faithfulness(retrieved_chunks, synthesized_answer);

        // 4. Markdown Hygiene (catches all 11 browser-observed visual defects deterministically)
        let (markdown_hygiene, hygiene_violations) = score_markdown_hygiene(synthesized_answer);

        let composite_score =
            (faithfulness * 0.30 + answer_relevance * 0.25 + context_precision * 0.20 + markdown_hygiene * 0.25)
                .clamp(0.0, 1.0);

        RagEvalReport {
            faithfulness,
            answer_relevance,
            context_precision,
            markdown_hygiene,
            composite_score,
            hygiene_violations,
        }
    }
}

fn tokenize_content(s: &str) -> BTreeSet<String> {
    const STOP: &[&str] = &[
        "the", "and", "for", "with", "from", "that", "this", "into", "about", "what", "who",
        "where", "when", "how", "why", "are", "was", "were", "have", "has", "had", "not", "but",
        "her", "his", "their", "she", "they", "your", "document", "documents", "source", "sources",
    ];
    s.to_ascii_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 4 && !STOP.contains(w))
        .map(|w| w.to_string())
        .collect()
}

fn score_context_precision(
    query: &str,
    primary_subject: Option<&str>,
    chunks: &[&ScoredChunk],
) -> f32 {
    if chunks.is_empty() {
        return 0.0;
    }
    let q_toks = tokenize_content(query);
    let subj_low = primary_subject.map(|s| s.to_ascii_lowercase());
    let mut relevant = 0usize;
    for sc in chunks {
        let hay = format!(
            "{} {}",
            sc.chunk.file_path.to_ascii_lowercase(),
            sc.chunk.text_content.to_ascii_lowercase()
        );
        let has_subj = subj_low.as_deref().map_or(false, |s| hay.contains(s));
        let overlap = q_toks.iter().filter(|t| hay.contains(t.as_str())).count();
        if has_subj || overlap >= 2 || (q_toks.len() <= 2 && overlap >= 1) {
            relevant += 1;
        }
    }
    relevant as f32 / chunks.len() as f32
}

fn score_answer_relevance(sub_questions: &[String], answer: &str) -> f32 {
    if sub_questions.is_empty() || answer.trim().is_empty() {
        return 0.0;
    }
    let ans_low = answer.to_ascii_lowercase();
    let mut covered = 0usize;
    for sq in sub_questions {
        let toks = tokenize_content(sq);
        if toks.is_empty() {
            covered += 1;
            continue;
        }
        let hits = toks.iter().filter(|t| ans_low.contains(t.as_str())).count();
        if hits * 2 >= toks.len() {
            covered += 1;
        }
    }
    covered as f32 / sub_questions.len() as f32
}

fn score_faithfulness(chunks: &[&ScoredChunk], answer: &str) -> f32 {
    if chunks.is_empty() || answer.trim().is_empty() {
        return 0.0;
    }
    let mut corpus_tokens: BTreeSet<String> = BTreeSet::new();
    for sc in chunks {
        corpus_tokens.extend(tokenize_content(&sc.chunk.text_content));
        corpus_tokens.extend(tokenize_content(&sc.chunk.file_path));
    }
    // Strip collapsible <details> raw excerpts and tables so we score synthesized prose claims
    let prose_part = answer.split("<details>").next().unwrap_or(answer);
    let mut total_sents = 0usize;
    let mut grounded_sents = 0usize;
    for line in prose_part.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with('|') || t == "---" {
            continue;
        }
        for sent in t.split(['.', '!', '?']) {
            let toks = tokenize_content(sent);
            if toks.len() < 4 {
                continue;
            }
            total_sents += 1;
            let supported = toks.iter().filter(|w| corpus_tokens.contains(*w)).count();
            if supported * 3 >= toks.len() {
                grounded_sents += 1;
            }
        }
    }
    if total_sents == 0 {
        1.0
    } else {
        grounded_sents as f32 / total_sents as f32
    }
}

pub fn score_markdown_hygiene(answer: &str) -> (f32, Vec<String>) {
    static RE_MIDWORD: OnceLock<Regex> = OnceLock::new();
    static RE_CITE_GAP: OnceLock<Regex> = OnceLock::new();
    let mut violations: Vec<String> = Vec::new();
    let re_midword = RE_MIDWORD.get_or_init(|| Regex::new(r"(?m)\s+\b[A-Za-z]{1,8}\.{3}\s*$").expect("midword regex"));
    let re_cite_gap = RE_CITE_GAP.get_or_init(|| Regex::new(r"\[\d+\] +[.,;:]").expect("cite gap regex"));

    let mut in_fence = false;
    for (idx, line) in answer.lines().enumerate() {
        let t = line.trim();
        if t.starts_with("```") || t.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if t.to_ascii_uppercase().contains("HYPERLINK \"") {
            violations.push(format!("line {}: raw HYPERLINK field code", idx + 1));
        }
        if t.matches("**").count() % 2 != 0 {
            violations.push(format!("line {}: unbalanced ** bold marker", idx + 1));
        }
        if t.starts_with('|') && !t.starts_with("|---") && t.contains(" --- ") {
            violations.push(format!("line {}: raw horizontal rule --- inside table cell", idx + 1));
        }
        if re_cite_gap.is_match(t) {
            violations.push(format!("line {}: space before punctuation after citation badge", idx + 1));
        }
        if !t.starts_with('|') && re_midword.is_match(t) {
            violations.push(format!("line {}: mid-word truncation ellipsis", idx + 1));
        }
        if (t.starts_with("### ") || t.starts_with("#### ")) && t.contains('?') && !t.contains('`') {
            violations.push(format!("line {}: conversational question promoted to heading", idx + 1));
        }
    }

    // Real CommonMark + GFM AST validation via pulldown-cmark
    let ast = crate::structured_output::validate_gfm_ast(answer);
    if ast.mismatched_table_rows > 0 {
        violations.push(format!(
            "pulldown-cmark AST: {} GFM table row(s) with mismatched column count",
            ast.mismatched_table_rows
        ));
    }
    if ast.unbalanced_details_tags {
        violations.push("pulldown-cmark AST: unbalanced <details>/<summary> drawer tags".to_string());
    }
    for raw_tag in &ast.unsafe_raw_html_tags {
        violations.push(format!("pulldown-cmark AST: unescaped raw HTML/angle tag `{}`", raw_tag));
    }

    let score = (1.0f32 - (violations.len() as f32 * 0.15)).clamp(0.0, 1.0);
    (score, violations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quorum_types::DocumentChunk;

    #[test]
    fn test_rag_eval_harness_distinguishes_clean_grounded_from_noisy_output() {
        let c1 = ScoredChunk {
            chunk: DocumentChunk::new(
                "c1",
                "c1",
                "D:/Docs/Women Race Class Summary.docx",
                1,
                10,
                0,
                vec![0.0; 8],
                "Women, Race & Class (1981) by Angela Davis analyzes race, gender, slavery, abolition, suffrage, and class struggle in American history.",
                None,
            )
            .unwrap(),
            score: 0.95,
            source_peer: "local".to_string(),
            is_remote: false,
        };

        let clean_answer = "### Academic Scholarship, Published Works & Critical Theory\n\nAngela Davis authored Women, Race & Class (1981), analyzing race, gender, slavery, abolition, suffrage, and class struggle in American history [1].\n\n| Ref | Source Document | Origin Node | Grounded Context Summary |\n|---|---|---|---|\n| **[1]** | `Women Race Class Summary.docx` | Local Host | Summarizes Angela Davis's 1981 research on race, gender, and class. |\n";
        let good = RagEvalHarness::evaluate("who is angela davis what is her research", &[&c1], clean_answer);
        assert!(good.hygiene_violations.is_empty(), "Expected 0 violations: {:?}", good.hygiene_violations);
        assert!(good.markdown_hygiene >= 0.99);
        assert!(good.faithfulness >= 0.90);
        assert!(good.composite_score >= 0.85, "Good answer composite={}", good.composite_score);

        let noisy_answer = "#### And your big sister instinct?\nAngela Davis at HYPERLINK \"mailto:a@b.com\" a@b.com [1] .\n| **[1]** | `doc` | Local | foo --- bar** |\nFragment will n...";
        let bad = RagEvalHarness::evaluate("who is angela davis what is her research", &[&c1], noisy_answer);
        assert!(
            bad.hygiene_violations.len() >= 4,
            "Noisy answer must trigger >= 4 hygiene violations, got: {:?}",
            bad.hygiene_violations
        );
        assert!(bad.markdown_hygiene < 0.50);
    }
}
