//! Adversarial Stress-Test Harness for Milestone M34:
//! 1. Document Family Key Derivation and Canonical Document Picker (`derive_document_family_key`, `pick_canonical_document_for_family`).
//! 2. Preservation of Multimodal Assets and Distinct Document Types.
//! 3. Form G-28 / Agency Address Suppression vs Genuine Residential Address Preservation.
//! 4. Title Spellcheck Normalization and Echoed Heading Stripping.

use quorum_coordinator::answer_orchestrator::{
    extract_grounded_facts, is_government_agency_or_boilerplate_address,
};
use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_types::{DocumentChunk, ScoredChunk};

fn make_scored_chunk(
    chunk_id: &str,
    file_path: &str,
    text: &str,
    source_peer: &str,
    score: f32,
) -> ScoredChunk {
    let doc_chunk = DocumentChunk::new(
        chunk_id,
        "doc_candidate",
        file_path,
        1,
        50,
        0,
        vec![0.1f32; 768],
        text,
        None,
    )
    .expect("DocumentChunk creation must succeed");

    ScoredChunk::new(doc_chunk, score, source_peer, source_peer != "local")
}

#[test]
fn test_stress_derive_document_family_key_redactx() {
    let stems = [
        "RedactX_v3_evaluation_report.pdf",
        "RedactX_v3_technical_specification.docx",
        "RedactX_v3_final.pdf",
        "RedactX_v3_draft.pdf",
        "RedactX_v3_2026-04-17.pdf",
        "RedactX_v3_benchmarks.pdf",
        "RedactX_v3_arxiv.pdf",
        "RedactX_v3_typesetting.pdf",
        "RedactX_v3_annotated.pdf",
        "RedactX_v3_corrected.pdf",
        "RedactX_v3_rewritten.pdf",
        "RedactX_v3 (1).docx",
        "RedactX_v3 (2).pdf",
        "RedactX_v3.docx.pdf",
        "RedactX-v3-final.pdf",
        "RedactX_v3.final.pdf",
        "RedactX_v3_2026_final.pdf",
        "RedactX_v3_2026-04-17_final.pdf",
        "redactx_v3_update.pdf",
        "redactx_v3_revised.pdf",
        "RedactX_v3_technical_report.pdf",
    ];

    for path in &stems {
        let key = DeterministicOfflineSynthesisEngine::derive_document_family_key(path);
        assert_eq!(
            key, "redactx",
            "Stem '{}' must derive canonical family key 'redactx', but got '{}'",
            path, key
        );
    }
}

#[test]
fn test_stress_derive_document_family_key_femi_resume() {
    let stems = [
        "Femi_Oyesanya_Enhanced_Resume_2026.docx",
        "Femi_Oyesanya_Enhanced_Resume_v2.docx",
        "Femi_Oyesanya_Enhanced_Resume_v3.docx",
        "Femi_Oyesanya_Enhanced_Resume_Final.pdf",
        "Femi_Oyesanya_Enhanced_Resume (1).pdf",
        "Femi_Oyesanya_Enhanced_Resume (2).docx",
        "Femi_Oyesanya_Enhanced_Resume (99).pdf",
        "Femi_Oyesanya_Enhanced_Resume_2026-04-17.docx",
        "Femi_Oyesanya_Enhanced_Resume_draft.txt",
        "Femi_Oyesanya_Enhanced_Resume_copy.pdf",
        "Femi_Oyesanya_Enhanced_Resume-copy.pdf",
        "Femi_Oyesanya_Enhanced_Resume_update.pdf",
        "Femi_Oyesanya_Enhanced_Resume_revised.docx",
        "Femi_Oyesanya_Enhanced_Resume.docx",
        "Femi_Oyesanya_Enhanced_Resume_2025-11-08_draft.pdf",
        "Femi_Oyesanya_Enhanced_Resume-2026.docx",
    ];

    for path in &stems {
        let key = DeterministicOfflineSynthesisEngine::derive_document_family_key(path);
        assert_eq!(
            key, "femi_oyesanya_enhanced_resume",
            "Stem '{}' must derive canonical family key 'femi_oyesanya_enhanced_resume', but got '{}'",
            path, key
        );
    }
}

#[test]
fn test_stress_multimodal_and_distinct_documents_never_merged() {
    // Media files must preserve extension and never collapse into text documents
    let png_key = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Checkmarx Social Media Assets - Femi Oyesanya.png",
    );
    let jpg_key = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Checkmarx Social Media Assets - Femi Oyesanya.jpg",
    );
    let jpeg_key = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Checkmarx Social Media Assets - Femi Oyesanya.jpeg",
    );
    let gif_key = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Checkmarx Social Media Assets - Femi Oyesanya.gif",
    );
    let webp_key = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Checkmarx Social Media Assets - Femi Oyesanya.webp",
    );
    let mp3_key = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Checkmarx Social Media Assets - Femi Oyesanya.mp3",
    );
    let wav_key = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Checkmarx Social Media Assets - Femi Oyesanya.wav",
    );
    let text_pdf_key = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Checkmarx Social Media Assets - Femi Oyesanya.pdf",
    );

    assert_eq!(
        png_key,
        "media_png_checkmarx_social_media_assets_femi_oyesanya"
    );
    assert_eq!(
        jpg_key,
        "media_jpg_checkmarx_social_media_assets_femi_oyesanya"
    );
    assert_eq!(
        jpeg_key,
        "media_jpeg_checkmarx_social_media_assets_femi_oyesanya"
    );
    assert_eq!(
        gif_key,
        "media_gif_checkmarx_social_media_assets_femi_oyesanya"
    );
    assert_eq!(
        webp_key,
        "media_webp_checkmarx_social_media_assets_femi_oyesanya"
    );
    assert_eq!(
        mp3_key,
        "media_mp3_checkmarx_social_media_assets_femi_oyesanya"
    );
    assert_eq!(
        wav_key,
        "media_wav_checkmarx_social_media_assets_femi_oyesanya"
    );
    assert_eq!(
        text_pdf_key,
        "checkmarx_social_media_assets_femi_oyesanya"
    );

    // Media must not match text PDF
    assert_ne!(png_key, text_pdf_key);
    assert_ne!(jpg_key, text_pdf_key);
    assert_ne!(mp3_key, text_pdf_key);

    // Different media formats must not collapse into each other
    assert_ne!(png_key, jpg_key);
    assert_ne!(png_key, mp3_key);

    // Distinct document types must never be merged
    let offer_letter = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Oyesanya_Femi_0754749_Offer_Letter.pdf",
    );
    let w2_doc = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "Oyesanya_Femi_0754749_2024_W2.pdf",
    );
    let patent_doc = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "RedactX_v3_patent_filing.pdf",
    );
    let eval_doc = DeterministicOfflineSynthesisEngine::derive_document_family_key(
        "RedactX_v3_evaluation_report.pdf",
    );

    assert_eq!(offer_letter, "oyesanya_femi_0754749_offer_letter");
    assert_eq!(w2_doc, "oyesanya_femi_0754749_w2");
    assert_ne!(offer_letter, w2_doc);

    assert_eq!(patent_doc, "redactx_patent_filing");
    assert_eq!(eval_doc, "redactx");
    assert_ne!(patent_doc, eval_doc);
}

#[test]
fn test_stress_pick_canonical_document_for_family_hierarchy() {
    let c_copy = make_scored_chunk(
        "c_copy",
        "Femi_Oyesanya_Enhanced_Resume (1).pdf",
        "text",
        "local",
        0.90,
    );
    let c_draft = make_scored_chunk(
        "c_draft",
        "Femi_Oyesanya_Enhanced_Resume_draft.txt",
        "text",
        "local",
        0.85,
    );
    let c_2024 = make_scored_chunk(
        "c_2024",
        "Femi_Oyesanya_Enhanced_Resume_2024.doc",
        "text",
        "local",
        0.88,
    );
    let c_v2 = make_scored_chunk(
        "c_v2",
        "Femi_Oyesanya_Enhanced_Resume_v2.docx",
        "text",
        "local",
        0.89,
    );
    let c_final = make_scored_chunk(
        "c_final",
        "Femi_Oyesanya_Enhanced_Resume_Final.pdf",
        "text",
        "local",
        0.91,
    );
    let c_2026 = make_scored_chunk(
        "c_2026",
        "Femi_Oyesanya_Enhanced_Resume_2026.docx",
        "text",
        "local",
        0.92,
    );

    let candidates = vec![&c_copy, &c_draft, &c_2024, &c_v2, &c_final, &c_2026];
    let picked =
        DeterministicOfflineSynthesisEngine::pick_canonical_document_for_family(&candidates)
            .expect("Must pick canonical candidate");

    assert_eq!(
        picked.chunk.file_path,
        "Femi_Oyesanya_Enhanced_Resume_2026.docx",
        "2026 .docx revision must win over older revisions and drafts"
    );

    // Test copy penalty: original vs copy
    let c_orig = make_scored_chunk(
        "orig",
        "Femi_Oyesanya_Resume.pdf",
        "text",
        "local",
        0.80,
    );
    let c_copy_higher_score = make_scored_chunk(
        "copy",
        "Femi_Oyesanya_Resume (1).pdf",
        "text",
        "local",
        0.95,
    );
    let pair = vec![&c_orig, &c_copy_higher_score];
    let picked_pair =
        DeterministicOfflineSynthesisEngine::pick_canonical_document_for_family(&pair).unwrap();
    assert_eq!(
        picked_pair.chunk.file_path,
        "Femi_Oyesanya_Resume.pdf",
        "Original document must win over (1) copy despite lower raw score"
    );

    // Test Final over Draft
    let c_d = make_scored_chunk("d", "Paper_draft.pdf", "text", "local", 0.90);
    let c_f = make_scored_chunk("f", "Paper_final.pdf", "text", "local", 0.85);
    let status_pair = vec![&c_d, &c_f];
    let picked_status =
        DeterministicOfflineSynthesisEngine::pick_canonical_document_for_family(&status_pair).unwrap();
    assert_eq!(
        picked_status.chunk.file_path,
        "Paper_final.pdf",
        "_final must win over _draft"
    );

    // Test Format preference: docx > pdf > doc > txt
    let c_txt = make_scored_chunk("txt", "Spec.txt", "text", "local", 0.90);
    let c_doc = make_scored_chunk("doc", "Spec.doc", "text", "local", 0.90);
    let c_pdf = make_scored_chunk("pdf", "Spec.pdf", "text", "local", 0.90);
    let c_docx = make_scored_chunk("docx", "Spec.docx", "text", "local", 0.90);
    let format_candidates = vec![&c_txt, &c_doc, &c_pdf, &c_docx];
    let picked_format =
        DeterministicOfflineSynthesisEngine::pick_canonical_document_for_family(&format_candidates)
            .unwrap();
    assert_eq!(
        picked_format.chunk.file_path,
        "Spec.docx",
        ".docx format must win when scores and versions are identical"
    );

    // Test deduplication in format_sources_block: produces exactly 1 entry per family
    let sources = DeterministicOfflineSynthesisEngine::format_sources_block(&candidates);
    assert!(sources.contains("Femi_Oyesanya_Enhanced_Resume_2026.docx"));
    assert!(!sources.contains("Femi_Oyesanya_Enhanced_Resume (1).pdf"));
    assert!(!sources.contains("Femi_Oyesanya_Enhanced_Resume_draft.txt"));
    assert!(!sources.contains("Femi_Oyesanya_Enhanced_Resume_2024.doc"));
    assert!(!sources.contains("Femi_Oyesanya_Enhanced_Resume_v2.docx"));
    assert!(!sources.contains("Femi_Oyesanya_Enhanced_Resume_Final.pdf"));
}

#[test]
fn test_stress_form_g28_address_suppression_and_residential_preservation() {
    // 1. USCIS HQ and government addresses must be identified as agency boilerplate
    assert!(is_government_agency_or_boilerplate_address(
        "111 Massachusetts Avenue, NW, Washington, DC 20529",
        "Form G-28 Notice of Entry of Appearance. Mail to: 111 Massachusetts Avenue, NW, Washington, DC 20529"
    ));
    assert!(is_government_agency_or_boilerplate_address(
        "111 Massachusetts Ave NW, Washington, DC",
        "USCIS instructions"
    ));
    assert!(is_government_agency_or_boilerplate_address(
        "20 Massachusetts Ave NW, Washington, DC 20529",
        "Department of Homeland Security"
    ));
    assert!(is_government_agency_or_boilerplate_address(
        "5900 Capital Gateway Dr, Camp Springs, MD 20588",
        "USCIS Headquarters"
    ));
    assert!(is_government_agency_or_boilerplate_address(
        "950 Pennsylvania Avenue, NW, Washington, DC 20530",
        "Department of Justice"
    ));
    assert!(is_government_agency_or_boilerplate_address(
        "200 Constitution Ave NW, Washington, DC 20210",
        "Department of Labor"
    ));
    assert!(is_government_agency_or_boilerplate_address(
        "P.O. Box 4008, Washington, DC 20529",
        "filing address lockbox"
    ));
    assert!(is_government_agency_or_boilerplate_address(
        "P.O. Box 660867, Dallas, TX 75266",
        "USCIS Lockbox"
    ));

    // 2. Genuine residential and commercial addresses must be preserved
    assert!(!is_government_agency_or_boilerplate_address(
        "2913 Castiglione St, New Orleans, LA 70119",
        "Candidate Femi Oyesanya residence 2913 Castiglione St, New Orleans, LA 70119"
    ));
    assert!(!is_government_agency_or_boilerplate_address(
        "123 Main St, Austin, TX 78701",
        "Employee home address 123 Main St, Austin, TX 78701"
    ));
    assert!(!is_government_agency_or_boilerplate_address(
        "450 Serra Mall, Stanford, CA 94305",
        "Stanford University campus"
    ));
    assert!(!is_government_agency_or_boilerplate_address(
        "742 Evergreen Terrace, Springfield, OR 97477",
        "Residential domicile"
    ));

    // 3. Fact extraction grounding: Form G-28 filtered, residential retained
    let doc_g28 = (
        "chunk_g28".to_string(),
        "Form_G28.pdf".to_string(),
        "Department of Homeland Security USCIS Form G-28 Notice of Entry of Appearance. \
         Please mail your application to 111 Massachusetts Avenue, NW, Washington, DC 20529. \
         Phone: (800) 375-5283. Date: 01/15/2026."
            .to_string(),
    );
    let doc_resume = (
        "chunk_resume".to_string(),
        "Resume.pdf".to_string(),
        "Femi Oyesanya (Lead Architect) resides at 2913 Castiglione St, New Orleans, LA 70119. \
         Phone: (504) 555-0199. Email: femi@example.com."
            .to_string(),
    );

    let texts = vec![doc_g28, doc_resume];
    let facts = extract_grounded_facts(Some("Femi Oyesanya"), &texts);

    let address_facts: Vec<&str> = facts
        .iter()
        .filter(|f| f.class == "Addresses")
        .map(|f| f.value.as_str())
        .collect();

    assert!(
        address_facts.contains(&"2913 Castiglione St, New Orleans, LA 70119"),
        "Residential address must be extracted: {:?}",
        address_facts
    );
    assert!(
        !address_facts.iter().any(|a| a.contains("Massachusetts") || a.contains("20529")),
        "USCIS Form G-28 address must NOT be extracted: {:?}",
        address_facts
    );

    // 4. Cue score suppression for location questions
    let location_query = "where does Femi live?";
    let g28_text = "Form G-28 filing address: 111 Massachusetts Avenue, NW, Washington, DC 20529".to_ascii_lowercase();
    let resume_text = "Femi lives at 2913 Castiglione St, New Orleans, LA 70119".to_ascii_lowercase();
    let g28_cue_score = DeterministicOfflineSynthesisEngine::answer_type_cue_score(
        location_query,
        &g28_text,
    );
    let resume_cue_score = DeterministicOfflineSynthesisEngine::answer_type_cue_score(
        location_query,
        &resume_text,
    );

    assert_eq!(
        g28_cue_score, 0,
        "Form G-28 with USCIS agency address and ZIP 20529 must receive 0 location boost, got {}",
        g28_cue_score
    );
    assert!(
        resume_cue_score >= 220,
        "Residential address with ZIP 70119 must receive at least +220 boost, got {}",
        resume_cue_score
    );
}

#[test]
fn test_stress_title_spellcheck_and_heading_normalization() {
    // 1. Direct query spellcheck
    let (fixed1, _) =
        DeterministicOfflineSynthesisEngine::correct_query_spelling("whi is Femi Oyesanya", false);
    assert_eq!(fixed1, "who is Femi Oyesanya");

    let (fixed2, _) =
        DeterministicOfflineSynthesisEngine::correct_query_spelling("Whi is Femi Oyesanya", false);
    assert_eq!(fixed2, "Who is Femi Oyesanya");

    let (fixed3, _) =
        DeterministicOfflineSynthesisEngine::correct_query_spelling("whos Femi Oyesanya", false);
    assert_eq!(fixed3, "who's Femi Oyesanya");

    let (fixed4, _) =
        DeterministicOfflineSynthesisEngine::correct_query_spelling("whoo is Femi Oyesanya", false);
    assert_eq!(fixed4, "who is Femi Oyesanya");

    let (fixed5, _) =
        DeterministicOfflineSynthesisEngine::correct_query_spelling("waht is redactx", false);
    assert_eq!(fixed5, "what is RedactX");

    let (fixed6, _) =
        DeterministicOfflineSynthesisEngine::correct_query_spelling("wher does femi reside", false);
    assert_eq!(fixed6, "where does Femi reside");

    // 2. Question restated prefix
    let prefix =
        DeterministicOfflineSynthesisEngine::format_question_restated_prefix("whi is Femi Oyesanya");
    assert_eq!(prefix, "Femi Oyesanya is ");

    let prefix_was =
        DeterministicOfflineSynthesisEngine::format_question_restated_prefix("whi was Femi Oyesanya");
    assert_eq!(prefix_was, "Femi Oyesanya was ");

    // 3. Question echo heading stripping
    let echo_input = "### Whi Is Femi Oyesanya\n\nFemi Oyesanya is an enterprise security architect [1].";
    let stripped = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(
        echo_input,
        "whi is Femi Oyesanya",
    );
    assert!(
        !stripped.contains("###"),
        "Echoed question heading must be completely removed: got '{}'",
        stripped
    );
    assert!(stripped.contains("Femi Oyesanya is an enterprise security architect [1]."));

    // 4. Non-matching heading normalization
    let other_heading_input =
        "### Whi Is Femi Oyesanya\n\nFemi Oyesanya completed advanced degrees in cybersecurity [1].";
    let normalized = DeterministicOfflineSynthesisEngine::strip_question_echo_and_meta(
        other_heading_input,
        "tell me about Femi's educational background",
    );
    assert!(
        normalized.contains("### Who Is Femi Oyesanya"),
        "Typo heading must be corrected to 'Who': got '{}'",
        normalized
    );
    assert!(
        !normalized.contains("### Whi Is"),
        "Typo heading must not echo 'Whi'"
    );
}

#[test]
fn test_stress_form_g28_case_insensitivity_leak() {
    // Stress test: answer_type_cue_score must be resilient to raw mixed-case excerpts
    // without requiring the caller to manually pre-lowercase text_l.
    let location_query = "where does Femi live?";
    let raw_mixed_case_g28 =
        "Form G-28 Notice of Entry of Appearance. Mailing address is 111 Massachusetts Avenue, NW, Washington, DC 20529";
    let score =
        DeterministicOfflineSynthesisEngine::answer_type_cue_score(location_query, raw_mixed_case_g28);

    assert_eq!(
        score, 0,
        "Form G-28 with mixed-case 'Form G-28' and '111 Massachusetts' MUST receive 0 location boost, but received {}",
        score
    );
}
