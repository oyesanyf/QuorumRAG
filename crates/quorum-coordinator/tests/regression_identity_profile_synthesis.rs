//! Deterministic Regression Test Suite for Milestone M28 / M30:
//! Identity Profile Synthesis, Contact Header Elimination & Verbatim Substring Grounding.
//!
//! Enforces:
//! 1. "who is Femi Oyesanya" synthesizes a complete multi-paragraph professional profile
//!    rather than collapsing into `<Name> is a <Contact Bar>` templates.
//! 2. The opening sentence does NOT match regex `r"is a .*[|@].*"`.
//! 3. Deep parent-document window expansion (`0..10000` bytes) provides executive summaries,
//!    work histories, and research bodies alongside Chunk 0 blocks.
//! 4. Verbatim substring citation grounding strictly satisfies `slice_text.contains(&quote)`
//!    and `&slice_text[start..end] == quote` across the expanded window.
//! 5. Sources blocks contain zero line numbers and clean provenance links.

use quorum_coordinator::{
    offline_engine::DeterministicOfflineSynthesisEngine,
    rlm_orchestrator::RlmOrchestrator,
};
use quorum_types::{DocumentChunk, ScoredChunk};
use regex::Regex;

// Realistic, multi-thousand-byte resume corpus modeling real-world document ingestion
const REALISTIC_RESUME_TEXT: &str = r#"FEMI OYESANYA, CISSP | Atlanta, GA | femi.oyesanya@cybersecurity-research.org | (404) 555-0199 | linkedin.com/in/femi-oyesanya

EXECUTIVE SUMMARY
Distinguished Enterprise Information Security Architect and Cyber Defense Leader with over 15 years of experience engineering zero-trust architectures, sovereign cryptographic enclaves, and autonomous threat mitigation systems. Proven track record leading large-scale cybersecurity transformations across financial services, healthcare, and distributed cloud infrastructure. Recognized for authoring novel decentralized quorum consensus protocols, Byzantine-fault-tolerant telemetry networks, and post-quantum cryptographic migration frameworks.

CORE COMPETENCIES & TECHNICAL PROFICIENCIES
- Architecture: Zero-Trust Architecture (ZTA), NIST SP 800-207, SABSA Enterprise Architecture, Cloud Security (AWS, Azure, GCP).
- Cryptography: Post-Quantum Cryptography (ML-KEM / Kyber, ML-DSA / Dilithium), Ed25519 PKI, Zero-Knowledge Proofs, Volatile Memory Scrubbing.
- Governance & Policy: Cedar Policy Language, RBAC / ABAC, SOC 2 Type II, HIPAA Security Rule, PCI-DSS 4.0, ISO 27001.
- Systems & Engineering: Distributed Consensus (Raft, Paxos, Quorum Byzantine), Rust, Python, High-Throughput Stream Processing.

PROFESSIONAL EXPERIENCE

Principal Security Architect | CyberDefense Solutions LLC (2020 – Present)
- Directed global enterprise zero-trust security architecture across multi-cloud hybrid environments, achieving 99.99% threat containment uptime.
- Engineered automated continuous-compliance validation engines integrating Cedar policy evaluation and decentralized cryptographic logging.
- Spearheaded post-quantum cryptography readiness initiatives, implementing hybrid Kyber and Dilithium key exchange primitives across corporate communications.
- Orchestrated red-team adversarial simulation gauntlets evaluating container isolation, namespace confinement, and side-channel leakage.

Lead Cyber Risk Engineer | SecureHealth Network (2015 – 2020)
- Designed and operationalized enterprise data loss prevention (DLP) frameworks safeguarding sensitive medical records and HIPAA-governed workflows.
- Mentored cross-functional incident response and penetration testing teams conducting adversarial security gauntlets across Linux, Windows, and macOS endpoints.
- Deployed distributed event streaming telemetry for real-time anomaly detection and zero-day intrusion mitigation.

EDUCATION & CREDENTIALS
- Master of Science in Information Security Architecture, Western Governors University (2014)
- Bachelor of Science in Computer Engineering, University of Lagos (2008)
- Certified Information Systems Security Professional (CISSP #492810, (ISC)²)
- Certified Information Security Manager (CISM, ISACA)
- GIAC Certified Enterprise Defender (GCED, SANS Institute)
"#;

/// Helper: constructs a test chunk with optional parent-window metadata
fn make_test_chunk(
    chunk_id: &str,
    file_path: &str,
    text: &str,
    parent_win_start: Option<usize>,
    parent_win_end: Option<usize>,
) -> ScoredChunk {
    let metadata_json = if let (Some(s), Some(e)) = (parent_win_start, parent_win_end) {
        format!(
            r#"{{"parent_window_start_byte":{},"parent_window_end_byte":{},"rlm_parent_enriched":true}}"#,
            s, e
        )
    } else {
        r#"{}"#.to_string()
    };

    let doc_chunk = DocumentChunk::new(
        chunk_id,
        "doc_femi_resume",
        file_path,
        1,
        65,
        0,
        vec![0.1f32; 768],
        text,
        Some(metadata_json),
    )
    .expect("DocumentChunk construction must succeed");

    ScoredChunk::new(doc_chunk, 0.98, "local", false)
}

#[test]
fn test_who_is_femi_oyesanya_no_contact_template_collapse() {
    let file_path = "C:/Users/oyesanyf/Documents/Femi_Oyesanya_Resume_2026.docx";

    // Simulate primary search hit on Chunk 0 expanded into deep 0..10000 byte parent window
    let parent_window_len = REALISTIC_RESUME_TEXT.len().min(10000);
    let slice_text = &REALISTIC_RESUME_TEXT[..parent_window_len];

    let scored = make_test_chunk(
        "chunk_resume_0",
        file_path,
        slice_text,
        Some(0),
        Some(parent_window_len),
    );

    let chunks = vec![scored];

    // Execute synthesis via deterministic offline engine
    let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "who is Femi Oyesanya",
        &chunks,
        "offline",
    );

    println!("=== Synthesized Profile Body ===\n{}\n================================", body);

    // 1. Invariant: Opening MUST NOT collapse into pipe-delimited contact template "<Name> is a <Contact Bar>"
    let contact_template_regex = Regex::new(r"(?i)is a .*[|@].*").expect("valid regex");
    assert!(
        !contact_template_regex.is_match(&body),
        "CRITICAL REGRESSION: Synthesized body collapsed into contact bar template '<Name> is a <Contact Bar>'. Body:\n{}",
        body
    );

    // 2. Invariant: Affirmative opening must restate subject and introduce substantive professional role
    let first_paragraph = body.split("\n\n").next().unwrap_or(&body);
    assert!(
        first_paragraph.starts_with("Femi Oyesanya is") || first_paragraph.starts_with("Femi Oyesanya appears"),
        "Opening paragraph must affirm subject identity, got: '{}'",
        first_paragraph
    );
    assert!(
        !first_paragraph.contains("| Atlanta") && !first_paragraph.contains("@cybersecurity"),
        "Opening paragraph must not leak raw contact bar tokens: '{}'",
        first_paragraph
    );

    // 3. Invariant: Synthesis must produce a multi-paragraph, substantive professional profile
    let body_paragraphs: Vec<&str> = body
        .split("\n\n")
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.starts_with("---") && !p.starts_with("### 📚"))
        .collect();

    assert!(
        body_paragraphs.len() >= 2,
        "Response must synthesize a complete multi-paragraph profile (expected >= 2 paragraphs, got {}). Body:\n{}",
        body_paragraphs.len(),
        body
    );

    // Substantive professional content assertions
    assert!(
        body.contains("Security Architect") || body.contains("Cyber Defense Leader"),
        "Synthesized profile must include primary professional title/role"
    );
    assert!(
        body.contains("zero-trust") || body.contains("Zero-Trust"),
        "Synthesized profile must include technical core competencies"
    );

    // 4. Invariant: Sources block formatting & zero line numbers
    assert!(
        body.contains("### 📚 Sources & Document Links"),
        "Response must conclude with standard sources block"
    );
    assert!(
        body.contains("[📄 Femi_Oyesanya_Resume_2026.docx]"),
        "Sources block must link source document"
    );
    assert!(
        !body.contains("Lines ") && !body.contains("(Lines") && !body.contains(":1-"),
        "Body and sources block must contain zero line numbers"
    );

    // 5. Invariant: Citations must be populated and pass verbatim substring check
    assert!(!citations.is_empty(), "Citations must not be empty");
    for (idx, cit) in citations.iter().enumerate() {
        let quote = cit.verbatim_quote.as_deref().unwrap_or_else(|| {
            panic!("Citation [{}] must have verbatim_quote populated", idx + 1);
        });
        assert!(
            !quote.trim().is_empty(),
            "Citation [{}] verbatim_quote must not be empty",
            idx + 1
        );
        assert!(
            slice_text.contains(quote),
            "Citation [{}] verbatim_quote must be an exact substring of slice_text. Quote: '{}'",
            idx + 1,
            quote
        );
        if let Some((b_start, b_end)) = cit.byte_range {
            assert!(
                b_end > b_start,
                "Citation [{}] byte_range end ({}) must exceed start ({})",
                idx + 1,
                b_end,
                b_start
            );
            assert!(
                b_end <= slice_text.len(),
                "Citation [{}] byte_range end ({}) exceeds slice_text length ({})",
                idx + 1,
                b_end,
                slice_text.len()
            );
            assert_eq!(
                &slice_text[b_start..b_end],
                quote,
                "Citation [{}] byte_range does not slice verbatim_quote exactly",
                idx + 1
            );
        }
    }
}

#[test]
fn test_expanded_parent_window_verbatim_citation_grounding() {
    let file_path = "D:/papers/Quorum_Consensus_Architecture.pdf";
    let full_doc = REALISTIC_RESUME_TEXT;
    let window_start = 0usize;
    let window_end = full_doc.len().min(10000);
    let slice_text = &full_doc[window_start..window_end];

    let scored = make_test_chunk(
        "paper:0",
        file_path,
        slice_text,
        Some(window_start),
        Some(window_end),
    );

    let answer = "Femi Oyesanya is a Distinguished Enterprise Information Security Architect with deep experience in zero-trust architectures and post-quantum cryptographic migration frameworks [1].";

    let mut citations = vec![scored.to_citation()];
    let refs = vec![&scored];

    RlmOrchestrator::verify_and_attach_verbatim_grounding(
        "Who is Femi Oyesanya and what are his architectural specializations?",
        answer,
        &refs,
        &mut citations,
    );

    assert_eq!(citations.len(), 1);
    let cit = &citations[0];
    let quote = cit.verbatim_quote.as_deref().expect("verbatim_quote must be attached");

    // Mathematical substring guarantee
    assert!(
        slice_text.contains(quote),
        "Emitted quote must be an exact substring of slice_text"
    );
    assert!(
        quote.len() >= 12,
        "Quote must be substantive (>= 12 chars), got: '{}'",
        quote
    );

    // Byte span verification
    let (b_start, b_end) = cit.byte_range.expect("byte_range must be attached");
    assert_eq!(b_start, window_start + slice_text.find(quote).unwrap());
    assert_eq!(b_end, b_start + quote.len());
    assert_eq!(&slice_text[b_start..b_end], quote);

    // Provenance rationale verification
    assert!(
        cit.grounding_rationale.is_some(),
        "Grounding rationale must be populated"
    );
}

#[test]
fn test_contact_bar_filter_predicate_unit_isolation() {
    // Contact bar samples that must be rejected
    let bad_contact_bars = [
        "FEMI OYESANYA, CISSP | Atlanta, GA | femi.oyesanya@cybersecurity-research.org | (404) 555-0199",
        "John Doe | 123 Main St, New York, NY | john@example.com | 555-0199",
        "femi.oyesanya@cybersecurity-research.org",
        "Phone: (404) 555-0199 | Email: test@domain.com",
        "City, State | email@host.com | linkedin.com/in/profile",
    ];

    // Substantive prose sentences that must NOT be rejected
    let good_prose_sentences = [
        "Distinguished Enterprise Information Security Architect and Cyber Defense Leader with over 15 years of experience.",
        "Directed global enterprise zero-trust security architecture across multi-cloud hybrid environments.",
        "Engineered automated continuous-compliance validation engines integrating Cedar policy evaluation.",
        "Education: Master of Science in Information Security Architecture from Western Governors University.",
    ];

    for bad in &bad_contact_bars {
        assert!(
            DeterministicOfflineSynthesisEngine::is_contact_bar_or_header(bad),
            "Line should be recognized as contact header: '{}'",
            bad
        );
        assert!(
            !DeterministicOfflineSynthesisEngine::is_sentence_like(bad),
            "Contact header must NOT be treated as sentence-like: '{}'",
            bad
        );
    }

    for good in &good_prose_sentences {
        assert!(
            !DeterministicOfflineSynthesisEngine::is_contact_bar_or_header(good),
            "Prose sentence must NOT be recognized as contact header: '{}'",
            good
        );
        assert!(
            DeterministicOfflineSynthesisEngine::is_sentence_like(good),
            "Substantive prose must be treated as sentence-like: '{}'",
            good
        );
    }
}

#[test]
fn test_rlm_verbatim_grounding_with_synthetic_headers() {
    let raw_parent = REALISTIC_RESUME_TEXT;
    let synthetic_header = "[Document: Title: \"Executive Curriculum Vitae\" | Author: Femi Oyesanya]\n";
    let enriched_source = format!("{}{}", synthetic_header, raw_parent);

    let doc_chunk = DocumentChunk::new(
        "chunk_synth_0",
        "doc_synth",
        "D:/docs/Femi_CV.docx",
        1,
        50,
        0,
        vec![0.1f32; 768],
        &enriched_source,
        Some(r#"{"parent_window_start_byte":0,"rlm_parent_enriched":true}"#.to_string()),
    )
    .unwrap();

    let sc = ScoredChunk::new(doc_chunk, 0.95, "local", false);
    let mut citations = vec![sc.to_citation()];
    let refs = vec![&sc];

    let answer = "He has over 15 years of experience engineering zero-trust architectures and sovereign cryptographic enclaves [1].";

    RlmOrchestrator::verify_and_attach_verbatim_grounding(
        "What is his experience in zero-trust architectures?",
        answer,
        &refs,
        &mut citations,
    );

    let cit = &citations[0];
    let quote = cit.verbatim_quote.as_deref().expect("verbatim_quote must exist");

    // Invariant: quote must NEVER be the synthetic header line
    assert!(
        !quote.starts_with("[Document:"),
        "Verbatim quote must not extract synthetic document header: '{}'",
        quote
    );

    // Invariant: quote must be a substring of raw_parent (without synthetic header)
    assert!(
        raw_parent.contains(quote),
        "Quote must be an exact substring of raw parent text: '{}'",
        quote
    );

    // Invariant: byte span must compensate for synthetic header length and correctly slice raw_parent
    let (abs_start, abs_end) = cit.byte_range.expect("byte_range must exist");
    assert_eq!(
        &raw_parent[abs_start..abs_end],
        quote,
        "Byte range must slice verbatim quote in raw parent text"
    );
}

#[test]
fn test_identity_profile_query_filters_uscis_form_g28_boilerplate_from_citations() {
    let resume_chunk = make_test_chunk(
        "chunk_resume_0",
        "C:/Users/oyesanyf/Documents/Femi_Oyesanya_Resume_2026.docx",
        REALISTIC_RESUME_TEXT,
        Some(0),
        Some(REALISTIC_RESUME_TEXT.len()),
    );

    let g28_text = "USCIS Form G-28 Notice of Entry of Appearance as Attorney or Accredited Representative. Department of Homeland Security. OMB No. 1615-0105. In re: Femi Oyesanya. Part 1. Information About Attorney.";
    let g28_chunk = make_test_chunk(
        "chunk_g28_0",
        "C:/Users/oyesanyf/Downloads/Form_G-28_USCIS.pdf",
        g28_text,
        None,
        None,
    );

    let chunks = vec![resume_chunk, g28_chunk];
    let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "who is Femi Oyesanya",
        &chunks,
        "offline",
    );

    assert!(
        citations.iter().any(|c| c.file_path.contains("Resume")),
        "Resume document must be cited in citations"
    );
    assert!(
        !citations.iter().any(|c| c.file_path.contains("G-28") || c.file_path.contains("g28") || c.file_path.contains("G28")),
        "Form G-28 must be filtered from citations when resume is present"
    );
    assert!(
        !body.contains("Form_G-28"),
        "Sources block in synthesized body must omit Form G-28"
    );
}
