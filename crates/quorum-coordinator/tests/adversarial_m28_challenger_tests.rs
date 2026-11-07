//! Empirical Challenger Test Suite for Milestone M28:
//! Contact Header Elimination, Substantive Profile Synthesis & Verbatim Substring Grounding.
//! Challenger: teamwork_challenger_m28_1 (critic, specialist)

use quorum_coordinator::offline_engine::DeterministicOfflineSynthesisEngine;
use quorum_types::{DocumentChunk, ScoredChunk};
use regex::Regex;

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
        "doc_candidate",
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

/// Adversarial Challenge 1: Single-Pipe Location Header
/// Stress-tests whether a single-pipe delimiter header (e.g. "Software Consultant | Boston, MA")
/// bypasses `is_contact_bar_or_header` and collapses into `<Name> is a <Title | Location>` template.
#[test]
fn test_challenge_single_pipe_location_collapse() {
    let resume_text = r#"Alice Smith
Software Consultant | Boston, MA
Building fast distributed data pipelines for enterprise organizations.
Proven track record in scaling high-throughput stream processing pipelines.
"#;
    let chunk = make_test_chunk(
        "chunk_single_pipe",
        "C:/Users/test/Alice_Smith_Resume.docx",
        resume_text,
        Some(0),
        Some(resume_text.len()),
    );

    let (body, _citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "who is Alice Smith",
        &[chunk],
        "offline",
    );

    println!("=== Synthesized Body (Single-Pipe Challenge) ===\n{}\n===============================================", body);

    let contact_template_regex = Regex::new(r"(?i)is a .*[|@].*").expect("valid regex");
    assert!(
        !contact_template_regex.is_match(&body),
        "CRITICAL REGRESSION: Output collapsed into contact bar template '<Name> is a <Contact Bar>' with single pipe: Body:\n{}",
        body
    );
}

/// Adversarial Challenge 2: Comma-Delimited Multi-Token Contact Bar with Email
/// Stress-tests whether comma-delimited contact bars with > 6 words bypass word-count heuristic
/// and leak email into opening template `<Name> is a <Role, Address, Email>`.
#[test]
fn test_challenge_comma_delimited_contact_bar_with_email() {
    let resume_text = r#"Jane Doe
Senior Security Consultant, Boston, MA, USA, jane.doe@cloudsec-lab.org
Accomplished cybersecurity leader with over a decade of hands-on expertise in zero-trust architecture.
Recognized for engineering cryptographic defenses and automating compliance workflows.
"#;
    let chunk = make_test_chunk(
        "chunk_comma_bar",
        "C:/Users/test/Jane_Doe_Resume.docx",
        resume_text,
        Some(0),
        Some(resume_text.len()),
    );

    let (body, _citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "who is Jane Doe",
        &[chunk],
        "offline",
    );

    println!("=== Synthesized Body (Comma Delimited Challenge) ===\n{}\n==================================================", body);

    let contact_template_regex = Regex::new(r"(?i)is a .*[|@].*").expect("valid regex");
    assert!(
        !contact_template_regex.is_match(&body),
        "CRITICAL REGRESSION: Output collapsed into contact bar template with email: Body:\n{}",
        body
    );
}

/// Adversarial Challenge 3: Slash-Delimited Contact Bar
/// Stress-tests slash delimiters with contact information.
#[test]
fn test_challenge_slash_delimited_contact_bar() {
    let resume_text = r#"Bob Johnson
Senior Cloud Architect / Austin, TX / bob.johnson@austin-tech.io / (512) 555-0144
Experienced infrastructure architect specializing in Kubernetes, service meshes, and infrastructure as code.
Successfully led migration of critical enterprise workloads to sovereign cloud environments.
"#;
    let chunk = make_test_chunk(
        "chunk_slash_bar",
        "C:/Users/test/Bob_Johnson_Resume.docx",
        resume_text,
        Some(0),
        Some(resume_text.len()),
    );

    let (body, _citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "who is Bob Johnson",
        &[chunk],
        "offline",
    );

    println!("=== Synthesized Body (Slash Delimited Challenge) ===\n{}\n==================================================", body);

    let contact_template_regex = Regex::new(r"(?i)is a .*[|@].*").expect("valid regex");
    assert!(
        !contact_template_regex.is_match(&body),
        "CRITICAL REGRESSION: Output collapsed into contact bar template with slash: Body:\n{}",
        body
    );
}

/// Adversarial Challenge 4: Varied Prompts against Exotic Contact Bars
/// Stress-tests varied prompt restatements ("who is", "tell me about", "background on", "describe")
/// against resumes with multi-pipe, bulleted, and unicode contact bars.
#[test]
fn test_challenge_varied_prompts_against_exotic_headers() {
    let resume_text = r#"Femi Oyesanya, CISSP || Atlanta, GA || femi.oyesanya@cybersecurity-research.org || (404) 555-0199

EXECUTIVE SUMMARY
Distinguished Enterprise Information Security Architect and Cyber Defense Leader with over 15 years of experience engineering zero-trust architectures, sovereign cryptographic enclaves, and autonomous threat mitigation systems. Proven track record leading large-scale cybersecurity transformations across financial services, healthcare, and distributed cloud infrastructure. Recognized for authoring novel decentralized quorum consensus protocols, Byzantine-fault-tolerant telemetry networks, and post-quantum cryptographic migration frameworks.

PROFESSIONAL EXPERIENCE
Principal Security Architect | CyberDefense Solutions LLC (2020 – Present)
- Directed global enterprise zero-trust security architecture across multi-cloud hybrid environments.
"#;
    let chunk = make_test_chunk(
        "chunk_exotic_pipes",
        "C:/Users/test/Femi_Oyesanya_Resume_2026.docx",
        resume_text,
        Some(0),
        Some(resume_text.len()),
    );

    let prompts = vec![
        "who is Femi Oyesanya",
        "tell me about Femi Oyesanya",
        "background on Femi Oyesanya",
        "give me details on Femi Oyesanya",
        "what do you know about Femi Oyesanya",
        "describe Femi Oyesanya",
        "can you tell me about Femi Oyesanya",
        "who was Femi Oyesanya",
    ];

    let contact_regex = Regex::new(r"(?i)is a .*[|@].*").expect("valid regex");

    for prompt in prompts {
        let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
            prompt,
            &[chunk.clone()],
            "offline",
        );

        assert!(
            !contact_regex.is_match(&body),
            "CRITICAL REGRESSION: Prompt '{}' collapsed into contact bar template: Body:\n{}",
            prompt,
            body
        );

        let first_paragraph = body.split("\n\n").next().unwrap_or(&body);
        assert!(
            !first_paragraph.contains("|| Atlanta") && !first_paragraph.contains("@cybersecurity"),
            "Prompt '{}' leaked raw contact tokens into opening: '{}'",
            prompt,
            first_paragraph
        );

        // Substantive profile verification
        assert!(
            body.contains("Security Architect") || body.contains("Cyber Defense Leader"),
            "Prompt '{}' must include primary professional role: Body:\n{}",
            prompt,
            body
        );

        // Verbatim substring grounding verification
        for cit in &citations {
            if let Some(ref quote) = cit.verbatim_quote {
                assert!(
                    resume_text.contains(quote),
                    "Citation verbatim quote must be a literal substring of source resume. Quote: '{}'",
                    quote
                );
            }
        }
    }
}

/// Adversarial Challenge 5: Multi-Bullet and Unicode Contact Bars
/// Stress-tests bullet characters (•, ·, ●, ▪, -) and emojis (📧, 📱, 📍).
#[test]
fn test_challenge_bullet_and_unicode_contact_bars() {
    let formats = vec![
        // Bullet middle dots
        "Femi Oyesanya • Atlanta, GA • femi.oyesanya@cybersecurity-research.org • (404) 555-0199",
        // Small dots
        "Femi Oyesanya · Atlanta, GA · femi.oyesanya@cybersecurity-research.org · (404) 555-0199",
        // Large circles
        "Femi Oyesanya ● Atlanta, GA ● femi.oyesanya@cybersecurity-research.org ● (404) 555-0199",
        // Squares
        "Femi Oyesanya ▪ Atlanta, GA ▪ femi.oyesanya@cybersecurity-research.org ▪ (404) 555-0199",
        // Dashes
        "Femi Oyesanya - Atlanta, GA - femi.oyesanya@cybersecurity-research.org - (404) 555-0199",
        // Unicode emojis
        "Femi Oyesanya 📧 femi.oyesanya@cybersecurity-research.org 📱 (404) 555-0199 📍 Atlanta, GA",
    ];

    let contact_regex = Regex::new(r"(?i)is a .*[|@•·●▪].*").expect("valid regex");

    for (idx, header) in formats.iter().enumerate() {
        let resume_text = format!(
            "{}\n\nEXECUTIVE SUMMARY\nDistinguished Enterprise Information Security Architect and Cyber Defense Leader with over 15 years of experience engineering zero-trust architectures, sovereign cryptographic enclaves, and autonomous threat mitigation systems.\n",
            header
        );
        let chunk = make_test_chunk(
            &format!("chunk_bullet_{}", idx),
            "C:/Users/test/Femi_Oyesanya_Resume_2026.docx",
            &resume_text,
            Some(0),
            Some(resume_text.len()),
        );

        let (body, _citations) = DeterministicOfflineSynthesisEngine::synthesize(
            "who is Femi Oyesanya",
            &[chunk],
            "offline",
        );

        assert!(
            !contact_regex.is_match(&body),
            "CRITICAL REGRESSION: Header format {} collapsed into contact bar template: Body:\n{}",
            idx,
            body
        );

        let first_paragraph = body.split("\n\n").next().unwrap_or(&body);
        assert!(
            !first_paragraph.contains("@cybersecurity-research.org"),
            "Header format {} leaked email into opening: '{}'",
            idx,
            first_paragraph
        );
    }
}

/// Adversarial Challenge 6: Verbatim Substring Grounding Across Expanded Parent Window
/// Verifies that citations strictly satisfy `slice_text.contains(&quote)` and `&slice_text[start..end] == quote`.
#[test]
fn test_challenge_verbatim_grounding_byte_range_integrity() {
    let full_document = r#"FEMI OYESANYA, CISSP | Atlanta, GA | femi.oyesanya@cybersecurity-research.org | (404) 555-0199

EXECUTIVE SUMMARY
Distinguished Enterprise Information Security Architect and Cyber Defense Leader with over 15 years of experience engineering zero-trust architectures, sovereign cryptographic enclaves, and autonomous threat mitigation systems. Proven track record leading large-scale cybersecurity transformations across financial services, healthcare, and distributed cloud infrastructure. Recognized for authoring novel decentralized quorum consensus protocols, Byzantine-fault-tolerant telemetry networks, and post-quantum cryptographic migration frameworks.

PROFESSIONAL EXPERIENCE
Principal Security Architect | CyberDefense Solutions LLC (2020 – Present)
- Directed global enterprise zero-trust security architecture across multi-cloud hybrid environments.
"#;

    let parent_win_len = full_document.len();
    let chunk = make_test_chunk(
        "chunk_grounding_audit",
        "C:/Users/test/Femi_Oyesanya_Resume_2026.docx",
        full_document,
        Some(0),
        Some(parent_win_len),
    );

    let (body, citations) = DeterministicOfflineSynthesisEngine::synthesize(
        "who is Femi Oyesanya",
        &[chunk],
        "offline",
    );

    assert!(!citations.is_empty(), "Citations must not be empty");

    for (idx, cit) in citations.iter().enumerate() {
        println!("Checking citation {}: {:?}", idx, cit);
        let quote = cit.verbatim_quote.as_ref().expect("Verbatim quote must be present");
        assert!(
            full_document.contains(quote),
            "Citation {} verbatim quote is not contained in source document: '{}'",
            idx,
            quote
        );

        if let Some((start, end)) = cit.byte_range {
            assert!(
                end <= full_document.len(),
                "Citation byte_range end {} exceeds document length {}",
                end,
                full_document.len()
            );
            assert_eq!(
                &full_document[start..end],
                quote,
                "Citation byte_range [{}..{}] does not match verbatim quote exactly",
                start,
                end
            );
        }
    }

    assert!(body.contains("### 📚 Sources & Document Links"), "Must contain sources block");
    assert!(!body.contains("Lines ") && !body.contains("(Lines"), "Must contain zero line numbers");
}
