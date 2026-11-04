//! Adversarial Empirical Stress Suite for Milestone M11: LangExtract Chat Candidate Extraction & 4-Arm Consensus
//! Challenger: Challenger M11 1 (critic, specialist)
//!
//! Evaluates the following adversarial dimensions:
//! 1. Complex Interrogative Queries: Multi-question clauses with varied punctuation (?, ;, \n, !, .)
//! 2. Document Reference Boundary Extraction: .pdf, .docx, .doc, .txt, .rs, .md, .csv, .json, .toml
//!    wrapped in parens, brackets, quotes, with uppercase extensions, and avoiding scalar metadata filters (e.g. filetype:pdf).
//! 3. Possessive & Apostrophe Stripping: 's and trailing apostrophes without altering verbatim substring integrity.
//! 4. Stopword Guard: Sentence-starting question words never extracted as entities.
//! 5. Multi-Word Proper Nouns & Technical Term Classification: Automatic classification as technical_term / organization / named_entity.
//! 6. 4-Arm Consensus Invariant: 100% pass across all 4 arms for genuine extracted candidates; fused confidence >= 8500 bp.
//! 7. Adversarial Ungrounded Injection Rejection: Fabricated entities, tampered intervals, and unbalanced syntax fail Arm 1, 2, or 3 and fail consensus.
//! 8. AgenticGraphState Propagation: ClassifyIntentNode populates state graph with verified consensus questions and entities.

use quorum_coordinator::agentic::classify::ClassifyIntentNode;
use quorum_coordinator::hardware::HardwareTelemetry;
use quorum_coordinator::langextract::{
    extract_chat_candidates, filter_grounded, ground_extraction, Extraction, LlmFusionConsensus,
};
use quorum_coordinator::types::{AgenticGraphState, SynthesisModelFamily};

#[test]
fn test_m11_1_complex_multi_question_clauses() {
    let prompt = "Who is Femi? Where did he study; what did he do at PatientPoint? Tell me about RedactX! How does it work?";
    let candidates = extract_chat_candidates(prompt);

    let questions: Vec<&str> = candidates
        .iter()
        .filter(|e| e.extraction_class == "question")
        .map(|e| e.extraction_text.as_str())
        .collect();

    assert!(questions.len() >= 4, "Expected at least 4 question clauses, found {}", questions.len());
    assert!(questions.iter().any(|q| *q == "Who is Femi"));
    assert!(questions.iter().any(|q| *q == "Where did he study"));
    assert!(questions.iter().any(|q| *q == "what did he do at PatientPoint"));
    assert!(questions.iter().any(|q| *q == "How does it work"));

    // Invariant: every single question candidate must be a verbatim substring of prompt
    for q in &questions {
        assert!(prompt.contains(q), "Question '{}' is not verbatim in prompt", q);
    }

    let consensus = LlmFusionConsensus::evaluate_extractions(prompt, candidates, None);
    assert!(consensus.consensus_passed, "4-arm consensus must pass on multi-clause questions");
    assert_eq!(consensus.arm_reports[0].score_pct, 100.0, "Arm 1 must be 100%");
    assert_eq!(consensus.arm_reports[2].score_pct, 100.0, "Arm 3 must be 100%");
    assert!(consensus.fused_confidence_bp >= 8500);
}

#[test]
fn test_m11_1_document_reference_boundaries_and_extensions() {
    let prompt = "Review [ResumeSec-AI-FemiOyesanya2025.pdf], 'Femi_Oyesanya_Enhanced_Resume_v3.docx', (Femi_Oyesanya_CV_2026.pdf)! Also check Resume2026.PDF; notes.txt, logic.rs, summary.md, metrics.csv, and config.toml. Skip filetype:pdf and tier:2.";
    let candidates = extract_chat_candidates(prompt);

    let doc_refs: Vec<&str> = candidates
        .iter()
        .filter(|e| e.extraction_class == "document_reference")
        .map(|e| e.extraction_text.as_str())
        .collect();

    assert!(doc_refs.contains(&"ResumeSec-AI-FemiOyesanya2025.pdf"));
    assert!(doc_refs.contains(&"Femi_Oyesanya_Enhanced_Resume_v3.docx"));
    assert!(doc_refs.contains(&"Femi_Oyesanya_CV_2026.pdf"));
    assert!(doc_refs.contains(&"Resume2026.PDF"));
    assert!(doc_refs.contains(&"notes.txt"));
    assert!(doc_refs.contains(&"logic.rs"));
    assert!(doc_refs.contains(&"summary.md"));
    assert!(doc_refs.contains(&"metrics.csv"));
    assert!(doc_refs.contains(&"config.toml"));

    // Invariant: Metadata filter tokens must NOT be extracted as document references
    assert!(!doc_refs.contains(&"filetype:pdf"));
    assert!(!doc_refs.contains(&"tier:2"));
    assert!(!doc_refs.contains(&"pdf"));

    for d in &doc_refs {
        assert!(prompt.contains(d), "Doc ref '{}' must be verbatim in prompt", d);
    }

    let consensus = LlmFusionConsensus::evaluate_extractions(prompt, candidates, None);
    assert!(consensus.consensus_passed);
    assert_eq!(consensus.arm_reports[0].score_pct, 100.0);
}

#[test]
fn test_m11_1_possessive_stripping_and_apostrophe_handling() {
    let prompt = "Where is Angela Davis's school and James' experience documented in ResumeSec-AI-FemiOyesanya2025.pdf?";
    let candidates = extract_chat_candidates(prompt);

    let entities: Vec<&str> = candidates
        .iter()
        .filter(|e| e.extraction_class == "named_entity")
        .map(|e| e.extraction_text.as_str())
        .collect();

    assert!(entities.contains(&"Angela"));
    assert!(entities.contains(&"Davis"));
    assert!(entities.contains(&"Angela Davis"));
    assert!(entities.contains(&"James"));

    // Invariant: Possessive 's or trailing apostrophe must be stripped
    assert!(!entities.contains(&"Davis's"));
    assert!(!entities.contains(&"James'"));

    // Invariant: Stopwords at start of sentence must NOT be extracted
    assert!(!entities.contains(&"Where"));
    assert!(!entities.contains(&"is"));

    for e in &entities {
        assert!(prompt.contains(e), "Entity '{}' must be verbatim in prompt", e);
    }

    let consensus = LlmFusionConsensus::evaluate_extractions(prompt, candidates, None);
    assert!(consensus.consensus_passed);
}

#[test]
fn test_m11_1_case_variations_and_technical_terms() {
    let prompt = "what did femi oyesanya implement with REDACTX, vaultgemma, presidio, and RRFCOMBINER?";
    let candidates = extract_chat_candidates(prompt);

    let entities: Vec<(&str, Option<&str>)> = candidates
        .iter()
        .filter(|e| e.extraction_class == "named_entity")
        .map(|e| (e.extraction_text.as_str(), e.attributes.get("kind").map(String::as_str)))
        .collect();

    let texts: Vec<&str> = entities.iter().map(|(t, _)| *t).collect();
    assert!(texts.contains(&"femi"));
    assert!(texts.contains(&"oyesanya"));
    assert!(texts.contains(&"femi oyesanya"));
    assert!(texts.contains(&"REDACTX"));
    assert!(texts.contains(&"vaultgemma"));
    assert!(texts.contains(&"presidio"));
    assert!(texts.contains(&"RRFCOMBINER"));

    let redactx_kind = entities.iter().find(|(t, _)| *t == "REDACTX").and_then(|(_, k)| *k);
    assert_eq!(redactx_kind, Some("technical_term"));

    let consensus = LlmFusionConsensus::evaluate_extractions(prompt, candidates, None);
    assert!(consensus.consensus_passed);
}

#[test]
fn test_m11_1_empty_and_whitespace_prompts() {
    assert!(extract_chat_candidates("").is_empty());
    assert!(extract_chat_candidates("   ").is_empty());
    assert!(extract_chat_candidates("\t\n\r  ").is_empty());
}

#[test]
fn test_m11_1_adversarial_injection_failure_modes() {
    let prompt = "Who is Femi Oyesanya from ResumeSec-AI-FemiOyesanya2025.pdf?";

    // 1. Ungrounded entity injection: must fail Arm 1 & Arm 3, failing consensus
    {
        let mut candidates = extract_chat_candidates(prompt);
        candidates.push(Extraction::new("named_entity", "QuantumBreakoutSuperweapon99"));
        let result = LlmFusionConsensus::evaluate_extractions(prompt, candidates, None);
        assert!(!result.consensus_passed, "Ungrounded entity must fail consensus");
        assert!(!result.arm_reports[0].passed, "Arm 1 must fail on ungrounded entity");
        assert!(!result.arm_reports[2].passed, "Arm 3 must fail on ungrounded entity");
        assert!(!result.verified_extractions.iter().any(|e| e.extraction_text == "QuantumBreakoutSuperweapon99"));
    }

    // 2. Syntactically unbalanced entity injection: must fail Arm 2
    {
        let mut candidates = extract_chat_candidates(prompt);
        candidates.push(Extraction::new("syntax_test", "Unbalanced(Bracket[Payload"));
        let result = LlmFusionConsensus::evaluate_extractions(prompt, candidates, None);
        assert!(!result.consensus_passed, "Unbalanced syntax must fail consensus");
        assert!(!result.arm_reports[1].passed, "Arm 2 must fail on unbalanced syntax");
    }

    // 3. Counterfactual boundary check: filter_grounded drops ungrounded items
    {
        let mut ungrounded = Extraction::new("named_entity", "FakeEntityNotPresent");
        assert!(!ground_extraction(&mut ungrounded, prompt));
        assert!(ungrounded.char_interval.is_none());

        let filtered = filter_grounded(vec![ungrounded]);
        assert!(filtered.is_empty(), "filter_grounded must purge ungrounded items");
    }
}

#[test]
fn test_m11_1_state_graph_propagation_and_metadata_filters() {
    let mut state = AgenticGraphState::new(
        "Who is Femi Oyesanya from ResumeSec-AI-FemiOyesanya2025.pdf? filetype:pdf tier:2",
        SynthesisModelFamily::AutoFusion,
        3,
    );
    let hw = HardwareTelemetry::probe();

    ClassifyIntentNode::execute(&mut state, &hw);

    assert!(state.langextract_result.is_some(), "langextract_result must be populated");
    let result = state.langextract_result.as_ref().unwrap();
    assert!(result.consensus_passed, "Consensus must pass in state graph execution");

    assert!(!state.extracted_questions.is_empty(), "extracted_questions must be populated");
    assert!(state.extracted_questions.iter().any(|q| q.contains("Who is Femi Oyesanya")));

    assert!(!state.extracted_entities.is_empty(), "extracted_entities must be populated");
    assert!(state.extracted_entities.iter().any(|e| e.extraction_class == "document_reference"));

    assert!(state.query_metadata_filters.is_some(), "query_metadata_filters must be populated");
    let filters = state.query_metadata_filters.as_ref().unwrap();
    assert_eq!(filters.get("filetype"), Some(&"pdf".to_string()));
    assert_eq!(filters.get("tier"), Some(&"2".to_string()));
}
