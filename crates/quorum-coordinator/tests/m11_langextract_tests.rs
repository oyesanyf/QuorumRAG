use quorum_coordinator::agentic::classify::ClassifyIntentNode;
use quorum_coordinator::hardware::HardwareTelemetry;
use quorum_coordinator::langextract::{
    extract_chat_candidates, Extraction, LlmFusionConsensus,
};
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_coordinator::types::{AgenticGraphState, SynthesisModelFamily};
use quorum_types::{DocumentChunk, ScoredChunk};

#[test]
fn test_extract_chat_candidates_questions_interrogative() {
    let prompt = "Who is femi? Where did he study?";
    let candidates = extract_chat_candidates(prompt);

    let questions: Vec<&str> = candidates
        .iter()
        .filter(|e| e.extraction_class == "question")
        .map(|e| e.extraction_text.as_str())
        .collect();

    assert_eq!(questions.len(), 2);
    assert_eq!(questions[0], "Who is femi");
    assert_eq!(questions[1], "Where did he study");

    for q in &questions {
        assert!(prompt.contains(q), "Question must be verbatim in prompt: {}", q);
    }
}

#[test]
fn test_extract_chat_candidates_document_references() {
    let prompt = "Tell me about Femi from ResumeSec-AI-FemiOyesanya2025.pdf and (Femi_Oyesanya_Enhanced_Resume_v3.docx). Also check Femi_Oyesanya_CV_2026.pdf and Resume2026.pdf.";
    let candidates = extract_chat_candidates(prompt);

    let doc_refs: Vec<&str> = candidates
        .iter()
        .filter(|e| e.extraction_class == "document_reference")
        .map(|e| e.extraction_text.as_str())
        .collect();

    assert_eq!(doc_refs.len(), 4);
    assert!(doc_refs.contains(&"ResumeSec-AI-FemiOyesanya2025.pdf"));
    assert!(doc_refs.contains(&"Femi_Oyesanya_Enhanced_Resume_v3.docx"));
    assert!(doc_refs.contains(&"Femi_Oyesanya_CV_2026.pdf"));
    assert!(doc_refs.contains(&"Resume2026.pdf"));

    for d in &doc_refs {
        assert!(prompt.contains(d), "Document reference must be verbatim in prompt: {}", d);
    }
}

#[test]
fn test_extract_chat_candidates_named_entities_and_technical_terms() {
    let prompt = "What did Femi do at PatientPoint and Cigna with RedactX, VaultGemma, and Presidio?";
    let candidates = extract_chat_candidates(prompt);

    let entities: Vec<(&str, Option<&str>)> = candidates
        .iter()
        .filter(|e| e.extraction_class == "named_entity")
        .map(|e| (e.extraction_text.as_str(), e.attributes.get("kind").map(String::as_str)))
        .collect();

    let texts: Vec<&str> = entities.iter().map(|(t, _)| *t).collect();
    assert!(texts.contains(&"Femi"));
    assert!(texts.contains(&"PatientPoint"));
    assert!(texts.contains(&"Cigna"));
    assert!(texts.contains(&"RedactX"));
    assert!(texts.contains(&"VaultGemma"));
    assert!(texts.contains(&"Presidio"));

    let redactx_ext = candidates.iter().find(|e| e.extraction_text == "RedactX").unwrap();
    assert_eq!(redactx_ext.attributes.get("kind").map(String::as_str), Some("technical_term"));

    let cigna_ext = candidates.iter().find(|e| e.extraction_text == "Cigna").unwrap();
    assert_eq!(cigna_ext.attributes.get("kind").map(String::as_str), Some("organization"));
}

#[test]
fn test_extract_chat_candidates_stopwords_never_extracted_as_entities() {
    let prompt = "Who is Femi and What does he do? Where did he study?";
    let candidates = extract_chat_candidates(prompt);

    let entity_texts: Vec<&str> = candidates
        .iter()
        .filter(|e| e.extraction_class == "named_entity")
        .map(|e| e.extraction_text.as_str())
        .collect();

    // Invariant: Sentence-starting question words must NEVER be extracted as named entities
    assert!(!entity_texts.contains(&"Who"));
    assert!(!entity_texts.contains(&"What"));
    assert!(!entity_texts.contains(&"Where"));
    assert!(entity_texts.contains(&"Femi"));
}

#[test]
fn test_extract_chat_candidates_possessive_stripping() {
    let prompt = "Tell me about Angela Davis's school from ResumeSec-AI-FemiOyesanya2025.pdf";
    let candidates = extract_chat_candidates(prompt);

    let entity_texts: Vec<&str> = candidates
        .iter()
        .filter(|e| e.extraction_class == "named_entity")
        .map(|e| e.extraction_text.as_str())
        .collect();

    assert!(entity_texts.contains(&"Angela"));
    assert!(entity_texts.contains(&"Davis")); // Stripped from "Davis's"
    assert!(entity_texts.contains(&"Angela Davis")); // Multi-word phrase
    assert!(!entity_texts.contains(&"Davis's"));
}

#[test]
fn test_extract_chat_candidates_4arm_consensus_100_percent() {
    let prompt = "Who is Femi Oyesanya from ResumeSec-AI-FemiOyesanya2025.pdf? What did he do at PatientPoint?";
    let candidates = extract_chat_candidates(prompt);
    assert!(!candidates.is_empty());

    let result = LlmFusionConsensus::evaluate_extractions(prompt, candidates, None);

    assert!(result.consensus_passed, "Consensus must pass for genuine chat candidates");
    assert!(
        result.fused_confidence_bp >= 8500,
        "Confidence must exceed 8500 bp, got {}",
        result.fused_confidence_bp
    );
    assert_eq!(result.arm_reports.len(), 4);

    for arm in &result.arm_reports {
        assert!(arm.passed, "Arm '{}' failed: {}", arm.arm_name, arm.details);
        assert_eq!(arm.score_pct, 100.0, "Arm '{}' score must be 100%", arm.arm_name);
    }
}

#[test]
fn test_extract_chat_candidates_empty_and_whitespace() {
    assert!(extract_chat_candidates("").is_empty());
    assert!(extract_chat_candidates("   \n\t  ").is_empty());
}

#[test]
fn test_adversarial_hallucination_injection_rejected() {
    let prompt = "Who is Femi from ResumeSec-AI-FemiOyesanya2025.pdf?";
    let mut candidates = extract_chat_candidates(prompt);

    // Inject hallucinated ungrounded candidate
    candidates.push(Extraction::new("FakeEntity", "QuantumBreakoutSuperweapon99"));

    let result = LlmFusionConsensus::evaluate_extractions(prompt, candidates, None);

    assert!(!result.consensus_passed, "Hallucinated extraction must cause consensus to fail");
    assert!(!result.arm_reports[0].passed, "Arm 1 (SemanticSpanExtractor) must fail on hallucination");
    assert!(!result.arm_reports[2].passed, "Arm 3 (CounterfactualJudge) must fail on hallucination");

    // Only genuine grounded items must survive in verified_extractions
    assert!(!result.verified_extractions.iter().any(|e| e.extraction_text == "QuantumBreakoutSuperweapon99"));
}

#[test]
fn test_agentic_graph_state_langextract_propagation() {
    let mut state = AgenticGraphState::new(
        "Who is Femi Oyesanya from ResumeSec-AI-FemiOyesanya2025.pdf?",
        SynthesisModelFamily::AutoFusion,
        3,
    );
    let hw = HardwareTelemetry::probe();

    ClassifyIntentNode::execute(&mut state, &hw);

    assert!(state.langextract_result.is_some(), "langextract_result must be populated");
    let result = state.langextract_result.as_ref().unwrap();
    assert!(result.consensus_passed);

    assert!(!state.extracted_questions.is_empty(), "extracted_questions must have verified questions");
    assert!(state.extracted_questions.iter().any(|q| q.contains("Who is Femi Oyesanya")));

    assert!(!state.extracted_entities.is_empty(), "extracted_entities must have verified entities");
    assert!(state.extracted_entities.iter().any(|e| e.extraction_class == "document_reference"));
    assert!(state.extracted_entities.iter().any(|e| e.extraction_text == "Femi" || e.extraction_text == "Femi Oyesanya"));
}

#[test]
fn test_question_restating_synthesis_no_line_numbers_and_clean_sources() {
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
        ScoredChunk::new(resume_chunk, 0.96, "local", false),
        ScoredChunk::new(cv_chunk, 0.92, "local", false),
    ];

    let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "Who is femi",
        &chunks,
        "qwen2.5:1.5b",
    );

    assert_eq!(citations.len(), 2);
    // Must begin with affirmative question restatement
    assert!(body.starts_with("Femi is"), "Body must start with affirmative restatement: {}", body);
    assert!(body.contains("CISSP-certified Application and AI Security professional"));
    // Must contain sources block at end
    assert!(body.contains("### 📚 Sources & Document Links"));
    assert!(body.contains("[📄 ResumeSec-AI-FemiOyesanya2025.pdf]"));
    assert!(body.contains("96% accuracy"));
    assert!(body.contains("[📄 Femi_Oyesanya_CV_2026.pdf]"));
    assert!(body.contains("92% accuracy"));

    // Invariant: ZERO line numbers anywhere!
    assert!(!body.contains("Lines "), "Must not contain line numbers: {}", body);
    assert!(!body.contains("(Lines"), "Must not contain line numbers: {}", body);
    assert!(!body.contains(":1-45"), "Must not contain line ranges: {}", body);
    // Invariant: ZERO raw file headers in body
    assert!(!body.contains("### 📄 "), "Must not contain raw file headers in body: {}", body);
}
