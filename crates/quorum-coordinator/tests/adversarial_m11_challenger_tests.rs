//! Adversarial Empirical Stress Suite for Milestone M11: Question-Restating Synthesis & Clean Sources.
//! Challenger: Challenger M11 2 (critic, specialist)
//!
//! Evaluates 6 adversarial dimensions:
//! 1. Affirmative Question-Restating Prefix: Stress-tests 25+ interrogative structures, casing, and punctuation variants.
//! 2. Zero Line Numbers Oracle: Verifies that line numbers `(Lines X–Y)` and `:line_start-line_end` are 100% eliminated from synthesized bodies and citations.
//! 3. Zero Raw Headers Oracle: Verifies that raw file headers `### 📄 filename` never appear in the prose body.
//! 4. Clean Deduplicated Sources Block: Verifies case-insensitive file deduplication, URL/path linking, and accuracy percentage formatting strictly at the end.
//! 5. Profile Query CV/Resume Prioritization: Verifies that profile queries prioritize CV/Resume files and heavily penalize ChatGPT artifacts (`fileciteturn0file0`, `sandbox:/mnt/data/`).
//! 6. Target Document Extraction & 4-Arm Consensus: Verifies verbatim grounding and 4-arm consensus pass rate for user-specified document targets.

use quorum_coordinator::langextract::{
    extract_chat_candidates, LlmFusionConsensus,
};
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_types::{DocumentChunk, ScoredChunk};

#[test]
fn test_adversarial_interrogative_restatements_matrix() {
    let test_cases = vec![
        // (Input query, Expected restated prefix)
        // Core dispatch cases
        ("Who is femi", "Femi is "),
        ("what is RedactX", "RedactX is "),
        ("where did Femi study", "Femi studied at "),
        ("where did Femi go to school", "Femi attended "),
        ("what the Cigna policy", "The Cigna Policy is "),
        ("tell me about Femi", "Femi is "),
        // Additional interrogative patterns
        ("Who is Femi Oyesanya?", "Femi Oyesanya is "),
        ("who was Angela Davis", "Angela Davis was "),
        ("who are the candidates", "The Candidates are "),
        ("who were the authors", "The Authors were "),
        ("what is VaultGemma?", "VaultGemma is "),
        ("what was the decision", "The Decision was "),
        ("what are the requirements", "The Requirements are "),
        ("what were the findings", "The Findings were "),
        ("what the patientpoint dispute", "The Patientpoint Dispute is "),
        ("where did Femi attend", "Femi attended "),
        ("where did Femi graduate", "Femi studied at "),
        ("what did Femi do at Cigna", "At Cigna, Femi "),
        ("what did Femi do at PatientPoint", "At Patientpoint, Femi "),
        ("what does redactx do", "Redactx "),
        ("what does VaultGemma mean", "Vaultgemma "),
        ("where is Western Governors University", "Western Governors University is located at "),
        ("where was PatientPoint", "PatientPoint was located at "),
        ("tell me about Angela Davis", "Angela Davis is "),
        ("describe RedactX", "RedactX is "),
        ("explain VaultGemma", "VaultGemma refers to "),
        ("can you explain Presidio", "Presidio refers to "),
        ("can you tell me about Cigna", "Cigna is "),
        ("femi oyesanya", "Femi Oyesanya is "),
        ("redactx", "Redactx is "),
        // Edge cases with excess punctuation, quotes, and whitespace
        ("  Who is femi???  ", "Femi is "),
        ("\"what is RedactX\"", "RedactX is "),
        ("'where did Femi study.'", "Femi studied at "),
        ("where did Femi go to school?!", "Femi attended "),
        ("tell me about Femi!!!", "Femi is "),
    ];

    for (query, expected) in test_cases {
        let actual = DeterministicOfflineSynthesisEngine::format_question_restated_prefix(query);
        assert_eq!(
            actual, expected,
            "Failed prefix restatement for query: '{}'. Expected '{}', got '{}'",
            query, expected, actual
        );
    }

    // Boundary edge cases
    assert_eq!(DeterministicOfflineSynthesisEngine::format_question_restated_prefix(""), "");
    assert_eq!(DeterministicOfflineSynthesisEngine::format_question_restated_prefix("   \n\t  "), "");
    assert_eq!(DeterministicOfflineSynthesisEngine::format_question_restated_prefix("???"), "");
    assert_eq!(DeterministicOfflineSynthesisEngine::format_question_restated_prefix("..."), "");
}

#[test]
fn test_adversarial_zero_line_numbers_and_zero_raw_headers_oracle() {
    let queries = [
        "Who is femi",
        "what is RedactX",
        "where did Femi study",
        "where did Femi go to school",
        "what the Cigna policy",
        "tell me about Femi",
        "explain RedactX",
        "what did Femi do at PatientPoint",
    ];

    let chunk1 = DocumentChunk::new(
        "chk_1",
        "doc_assignments",
        "C:/Users/oyesanyf/Documents/Complete Assignments__.docx",
        35,
        39,
        0,
        vec![0.1; 768],
        "Femi Oyesanya, CISSP. Information Security Architecture and Privacy Engineering at PatientPoint.",
        None,
    )
    .unwrap();

    let chunk2 = DocumentChunk::new(
        "chk_2",
        "doc_discrepancies",
        "C:/Users/oyesanyf/Documents/Case Discrepancies Review.docx",
        105,
        142,
        0,
        vec![0.1; 768],
        "Cigna policy dispute review and resolution framework. Clinical de-identification with RedactX.",
        None,
    )
    .unwrap();

    let chunk3 = DocumentChunk::new(
        "chk_3",
        "doc_cv",
        "C:/Users/oyesanyf/Documents/Femi_Oyesanya_CV_2026.pdf",
        1,
        60,
        0,
        vec![0.1; 768],
        "Western Governors University - Master of Science in Information Security Architecture.",
        None,
    )
    .unwrap();

    let chunks = vec![
        ScoredChunk::new(chunk1, 0.95, "local", false),
        ScoredChunk::new(chunk2, 0.88, "local", false),
        ScoredChunk::new(chunk3, 0.91, "local", false),
    ];

    for q in &queries {
        let (synthesized_body, citations) =
            DeterministicOfflineSynthesisEngine::synthesize(q, &chunks, "qwen2.5:1.5b");

        // 1. Assert ZERO occurrences of line number patterns anywhere
        assert!(
            !synthesized_body.contains("Lines "),
            "Query '{}' leaked 'Lines ': {}",
            q,
            synthesized_body
        );
        assert!(
            !synthesized_body.contains("(Lines"),
            "Query '{}' leaked '(Lines': {}",
            q,
            synthesized_body
        );
        assert!(
            !synthesized_body.contains(":35-39"),
            "Query '{}' leaked ':35-39': {}",
            q,
            synthesized_body
        );
        assert!(
            !synthesized_body.contains(":105-142"),
            "Query '{}' leaked ':105-142': {}",
            q,
            synthesized_body
        );
        assert!(
            !synthesized_body.contains(":1-60"),
            "Query '{}' leaked ':1-60': {}",
            q,
            synthesized_body
        );

        // 2. Assert ZERO raw file headers
        assert!(
            !synthesized_body.contains("### 📄 "),
            "Query '{}' contained raw file header '### 📄 ': {}",
            q,
            synthesized_body
        );

        // 3. Assert citations vector is clean
        assert!(
            !citations.is_empty(),
            "Query '{}' must produce at least one citation",
            q
        );
        for cit in &citations {
            assert!(
                !cit.snippet.contains("fileciteturn0file0"),
                "Citation snippet contained ChatGPT artifact"
            );
        }

        // 4. Assert sources block is strictly at the bottom
        let sources_header = "### 📚 Sources & Document Links";
        assert!(
            synthesized_body.contains(sources_header),
            "Query '{}' missing sources header: {}",
            q,
            synthesized_body
        );
        let header_pos = synthesized_body.find(sources_header).unwrap();
        let prose_before = &synthesized_body[..header_pos];
        assert!(
            prose_before.len() > 30,
            "Query '{}' had insufficient prose before sources block",
            q
        );
    }
}

#[test]
fn test_adversarial_clean_sources_block_deduplication_and_accuracy_scores() {
    // Chunks from the SAME document but different line numbers
    let chunk_doc1_a = DocumentChunk::new(
        "chk_1a",
        "doc_assign",
        "C:/Data/Complete Assignments__.docx",
        1,
        20,
        0,
        vec![0.1; 768],
        "Section 1: Initial requirements and background.",
        None,
    )
    .unwrap();

    let chunk_doc1_b = DocumentChunk::new(
        "chk_1b",
        "doc_assign",
        "C:/Data/Complete Assignments__.docx",
        35,
        50,
        0,
        vec![0.1; 768],
        "Section 2: Security architecture specifications.",
        None,
    )
    .unwrap();

    let chunk_doc1_c = DocumentChunk::new(
        "chk_1c",
        "doc_assign",
        "C:/Data/Complete Assignments__.docx",
        80,
        100,
        0,
        vec![0.1; 768],
        "Section 3: Audit review notes and deliverables.",
        None,
    )
    .unwrap();

    let chunk_doc2 = DocumentChunk::new(
        "chk_2",
        "doc_resume",
        "C:/Data/Resume2026.pdf",
        1,
        45,
        0,
        vec![0.1; 768],
        "Femi Oyesanya, CISSP resume document.",
        None,
    )
    .unwrap();

    let scored_chunks = vec![
        ScoredChunk::new(chunk_doc1_a, 0.942, "local", false),
        ScoredChunk::new(chunk_doc1_b, 0.915, "local", false),
        ScoredChunk::new(chunk_doc1_c, 0.880, "local", false),
        ScoredChunk::new(chunk_doc2, 0.978, "local", false),
    ];

    let refs: Vec<&ScoredChunk> = scored_chunks.iter().collect();
    let sources_block = DeterministicOfflineSynthesisEngine::format_sources_block(&refs);

    // 1. Verify header
    assert!(sources_block.contains("### 📚 Sources & Document Links"));

    // 2. Count bullet item occurrences of "Complete Assignments__.docx"
    let doc1_bullets = sources_block
        .lines()
        .filter(|l| l.contains("- [📄 Complete Assignments__.docx]"))
        .count();
    assert_eq!(
        doc1_bullets,
        1,
        "Complete Assignments__.docx must appear in EXACTLY one bullet in Sources block, but appeared {} times:\n{}",
        doc1_bullets,
        sources_block
    );

    // 3. Count bullet item occurrences of "Resume2026.pdf"
    let doc2_bullets = sources_block
        .lines()
        .filter(|l| l.contains("- [📄 Resume2026.pdf]"))
        .count();
    assert_eq!(
        doc2_bullets,
        1,
        "Resume2026.pdf must appear in EXACTLY one bullet in Sources block, but appeared {} times:\n{}",
        doc2_bullets,
        sources_block
    );

    // 4. Verify total number of bullet items is exactly 2
    let bullet_count = sources_block.lines().filter(|l| l.trim().starts_with("- [📄")).count();
    assert_eq!(
        bullet_count, 2,
        "Sources block must have exactly 2 deduplicated bullets, found {}:\n{}",
        bullet_count, sources_block
    );

    // 5. Verify accuracy scores formatted as percentages
    assert!(sources_block.contains("94% accuracy"));
    assert!(sources_block.contains("98% accuracy"));

    // 6. Verify ZERO line numbers in sources block
    assert!(!sources_block.contains("Lines "));
    assert!(!sources_block.contains(":1-20"));
    assert!(!sources_block.contains(":35-50"));
    assert!(!sources_block.contains(":80-100"));
}

#[test]
fn test_adversarial_profile_query_cv_resume_prioritization_and_artifact_penalties() {
    let resume_chunk = DocumentChunk::new(
        "chk_res",
        "doc_res",
        "C:/Docs/Femi_Oyesanya_CV_2026.pdf",
        1,
        45,
        0,
        vec![0.1; 768],
        "Femi Oyesanya, CISSP. Professional Summary: Application and AI Security Architect.",
        None,
    )
    .unwrap();

    let chatgpt_export_chunk = DocumentChunk::new(
        "chk_chatgpt",
        "doc_export",
        "C:/Docs/chat_history.txt",
        1,
        50,
        0,
        vec![0.1; 768],
        "fileciteturn0file0 sandbox:/mnt/data/Femi Oyesanya random chat transcript conversation.",
        None,
    )
    .unwrap();

    let general_doc_chunk = DocumentChunk::new(
        "chk_general",
        "doc_gen",
        "C:/Docs/RandomNotes.docx",
        1,
        30,
        0,
        vec![0.1; 768],
        "Femi Oyesanya attended the general all-hands sync call yesterday.",
        None,
    )
    .unwrap();

    let scored = vec![
        ScoredChunk::new(general_doc_chunk, 0.70, "local", false),
        ScoredChunk::new(chatgpt_export_chunk, 0.75, "local", false),
        ScoredChunk::new(resume_chunk, 0.85, "local", false),
    ];

    let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "Who is Femi Oyesanya",
        &scored,
        "qwen2.5:1.5b",
    );

    // 1. Assert synthesis begins affirmatively grounded in the CV/Resume
    assert!(
        body.starts_with("Femi Oyesanya is"),
        "Body must start with affirmative restatement: {}",
        body
    );
    assert!(
        body.contains("Application and AI Security Architect"),
        "Body must prioritize CV professional summary"
    );

    // 2. Assert ChatGPT artifacts are 100% stripped and never leaked
    assert!(
        !body.contains("fileciteturn0file0"),
        "Body must not contain fileciteturn0file0"
    );
    assert!(
        !body.contains("sandbox:/mnt/data"),
        "Body must not contain sandbox:/mnt/data"
    );

    // 3. Top citation must be the CV/Resume
    assert_eq!(citations[0].file_path, "C:/Docs/Femi_Oyesanya_CV_2026.pdf");
}

#[test]
fn test_adversarial_target_document_extraction_and_4arm_consensus() {
    let prompt = "Extract details about Femi Oyesanya from ResumeSec-AI-FemiOyesanya2025.pdf, Femi_Oyesanya_CV_2026.pdf, and Resume2026.pdf.";
    let candidates = extract_chat_candidates(prompt);

    let doc_refs: Vec<&str> = candidates
        .iter()
        .filter(|e| e.extraction_class == "document_reference")
        .map(|e| e.extraction_text.as_str())
        .collect();

    assert_eq!(doc_refs.len(), 3);
    assert!(doc_refs.contains(&"ResumeSec-AI-FemiOyesanya2025.pdf"));
    assert!(doc_refs.contains(&"Femi_Oyesanya_CV_2026.pdf"));
    assert!(doc_refs.contains(&"Resume2026.pdf"));

    // Verify 4-arm consensus passes with 100% score on each arm
    let result = LlmFusionConsensus::evaluate_extractions(prompt, candidates, None);
    assert!(result.consensus_passed);
    assert_eq!(result.arm_reports.len(), 4);
    for arm in &result.arm_reports {
        assert!(arm.passed, "Arm '{}' failed", arm.arm_name);
        assert_eq!(arm.score_pct, 100.0, "Arm '{}' score was {}", arm.arm_name, arm.score_pct);
    }
}
