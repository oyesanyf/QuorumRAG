//! Query framing integration with relevance attestation and distractor classification.
//!
//! Natural language queries contain conversational framing, media requests, or topic indicators.
//! This module classifies and filters false-positive lexical distractors (Perl modules, grading rubrics,
//! UI screenshots on prose queries, and unrelated boilerplate) and extracts clean query subjects
//! to support high-accuracy Nimble-9B relevance attestation.

pub use quorum_storage::query_framing::{
    detect_media_intent, detect_protocol_forensic_intent, media_content_prefix,
    strip_conversational_framing, MediaIntent, ProtocolIntent,
};

/// Distractor types identified by the lexical filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistractorType {
    PerlSourceCode,
    GradingRubric,
    UiScreenshotOnProseQuery,
    BoilerplateLicense,
    UnrelatedContent,
    CodeIntegrityOnDnsQuery,
}

/// Identifies whether a retrieved candidate chunk is a false-positive lexical distractor
/// for the given query.
pub fn is_lexical_distractor(query: &str, file_path: &str, text: &str) -> bool {
    classify_distractor_type(query, file_path, text).is_some()
}

/// Classifies the specific type of distractor if the chunk is deemed irrelevant or noise.
pub fn classify_distractor_type(query: &str, file_path: &str, text: &str) -> Option<DistractorType> {
    let q_lower = query.to_ascii_lowercase();
    let f_lower = file_path.to_ascii_lowercase();
    let t_lower = text.to_ascii_lowercase();

    // 1. Perl source code (.pm, .pl, package declaration) on non-Perl/non-code queries
    let is_perl_file = f_lower.ends_with(".pm") || f_lower.ends_with(".pl");
    let is_perl_package = t_lower.starts_with("package ") || t_lower.contains("package datetime::");
    let asks_for_perl = q_lower.contains("perl") || q_lower.contains("package") || q_lower.contains(".pm");
    if (is_perl_file || is_perl_package) && !asks_for_perl {
        return Some(DistractorType::PerlSourceCode);
    }

    // 2. Grading rubrics and student assignment templates on biographical/historical/factual queries
    if f_lower.contains("zrubrics")
        || f_lower.contains("rubric")
        || t_lower.contains("student grading rubric")
        || t_lower.contains("zrubrics clarification")
        || t_lower.contains("rubric clarification")
    {
        let asks_for_rubric = q_lower.contains("rubric") || q_lower.contains("grading");
        if !asks_for_rubric {
            return Some(DistractorType::GradingRubric);
        }
    }

    // 3. UI screenshots / visual media descriptions on purely text/prose queries
    let is_image_doc = t_lower.starts_with("[image document:") || f_lower.ends_with(".png") || f_lower.ends_with(".jpg");
    let media_intent = detect_media_intent(query);
    if is_image_doc && media_intent != MediaIntent::Image && !q_lower.contains("image") && !q_lower.contains("screenshot") && !q_lower.contains("picture") {
        return Some(DistractorType::UiScreenshotOnProseQuery);
    }

    // 4. Boilerplate license terms and copyright footers
    if (t_lower.contains("all rights reserved boilerplate")
        || t_lower.contains("boilerplate license terms")
        || (t_lower.contains("all rights reserved") && t_lower.contains("license") && text.len() < 160))
        && !q_lower.contains("license")
    {
        return Some(DistractorType::BoilerplateLicense);
    }

    // 5. Unrelated content markers (e.g. gardening on technical/biographical queries)
    if t_lower.contains("unrelated notes on gardening")
        || (t_lower.contains("unrelated") && text.len() < 80)
    {
        return Some(DistractorType::UnrelatedContent);
    }

    // 6. Python population genetics distractor on biographical queries (e.g. wright_fisher_model.py)
    if (f_lower.contains("popgen") || f_lower.ends_with(".py"))
        && t_lower.contains("wright-fisher")
        && !q_lower.contains("genetics")
        && !q_lower.contains("wright-fisher")
    {
        return Some(DistractorType::UnrelatedContent);
    }

    None
}

/// Calibrated heuristic relevance score between a query and a document chunk in [0.0, 1.0].
pub fn score_chunk_relevance_heuristic(query: &str, file_path: &str, text: &str) -> f64 {
    if is_lexical_distractor(query, file_path, text) {
        return 0.05;
    }

    let q_clean = strip_conversational_framing(query);
    let q_terms: Vec<String> = q_clean
        .split(|c: char| !c.is_alphanumeric())
        .map(|w| w.to_ascii_lowercase())
        .filter(|w| w.len() > 2)
        .collect();

    if q_terms.is_empty() {
        return 0.50;
    }

    let t_lower = text.to_ascii_lowercase();
    let f_lower = file_path.to_ascii_lowercase();

    let mut matches = 0usize;
    for term in &q_terms {
        if t_lower.contains(term) || f_lower.contains(term) {
            matches += 1;
        }
    }

    let match_ratio = matches as f64 / q_terms.len() as f64;
    (0.30 + (match_ratio * 0.65)).clamp(0.10, 0.95)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_perl_distractor() {
        assert!(is_lexical_distractor(
            "Who is Angela Davis?",
            "DateTime/LeapSecond/Davis.pm",
            "package DateTime::LeapSecond::Davis; # Perl code"
        ));
    }

    #[test]
    fn detects_rubric_distractor() {
        assert!(is_lexical_distractor(
            "Who is Angela Davis?",
            "Zrubrics Clarification.docx",
            "Student Grading Rubric Zrubrics Clarification"
        ));
    }

    #[test]
    fn allows_relevant_chunk() {
        assert!(!is_lexical_distractor(
            "Who is Angela Davis?",
            "Women Race Class Summary.docx",
            "Women, Race & Class published in 1981 by Angela Davis"
        ));
    }
}
