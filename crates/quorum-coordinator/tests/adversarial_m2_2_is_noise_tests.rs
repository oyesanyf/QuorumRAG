//! Adversarial Stress & Boundary Test Suite for `is_noise` Pattern Matching
//! Milestone 2 Iteration 2 (Challenger 2 Empirical Verification).

use quorum_contract::RlmSufficiencyChoice;
use quorum_coordinator::nimble_client::NimbleClient;
use std::time::Instant;

#[test]
fn test_adversarial_is_noise_all_twelve_standard_keywords() {
    let keywords = [
        "license",
        "copyright",
        "all rights reserved",
        "boilerplate",
        "unrelated",
        "privacy policy",
        "cookie policy",
        "terms of service",
        "disclaimer",
        "advertisement",
        "irrelevant",
        "low relevance",
    ];

    let choices = RlmSufficiencyChoice::all_choices();

    for &kw in &keywords {
        let text = format!("This section contains standard {} information for web visitors.", kw);
        let dec = NimbleClient::decide_fallback(&text, choices);
        assert_eq!(
            dec.selected_choice, "DropIrrelevantSpan",
            "Keyword '{}' must trigger DropIrrelevantSpan",
            kw
        );
        // Normalized weight: 0.85 / (0.85 + 0.15 + 0.10 + 0.12) = 0.85 / 1.22 = 0.69672...
        assert!(
            dec.calibrated_probability >= 0.69,
            "Keyword '{}' must yield calibrated probability >= 0.69 (got {})",
            kw,
            dec.calibrated_probability
        );
        let drop_prob = dec.probabilities.get("DropIrrelevantSpan").copied().unwrap_or(0.0);
        assert!(
            drop_prob >= 0.69,
            "Keyword '{}' DropIrrelevantSpan prob must be >= 0.69 (got {})",
            kw,
            drop_prob
        );
        assert!(dec.used_fallback);
    }
}

#[test]
fn test_adversarial_is_noise_case_variations() {
    let case_variants = [
        "PRIVACY POLICY: PLEASE REVIEW OUR TERMS.",
        "CoPyRiGhT 2026. AlL rIgHtS rEsErVeD.",
        "DISCLAIMER: The author assumes no liability.",
        "UnReLaTeD bOiLeRpLaTe TeXt",
        "ADVERTISEMENT: Click here to buy now.",
        "LOW RELEVANCE SPAN IDENTIFIED.",
        "TERMS OF SERVICE AND COOKIE POLICY.",
    ];

    let choices = RlmSufficiencyChoice::all_choices();
    for &variant in &case_variants {
        let dec = NimbleClient::decide_fallback(variant, choices);
        assert_eq!(
            dec.selected_choice, "DropIrrelevantSpan",
            "Case variant '{}' must trigger DropIrrelevantSpan",
            variant
        );
    }
}

#[test]
fn test_adversarial_is_noise_conflicting_triggers_precedence() {
    let choices = RlmSufficiencyChoice::all_choices();

    // 1. Noise + Expansion: Noise (0.85) must take precedence over Expansion (0.80)
    let noise_plus_expansion = "Need more context: privacy policy disclaimer is incomplete and truncated...";
    let dec1 = NimbleClient::decide_fallback(noise_plus_expansion, choices);
    assert_eq!(
        dec1.selected_choice, "DropIrrelevantSpan",
        "Noise must take precedence over Expansion so boilerplate is not expanded"
    );

    // 2. Noise + Subquery: Noise (0.85) must take precedence over Subquery (0.75)
    let noise_plus_subquery = "Further investigation required for unknown entity in advertisement terms of service.";
    let dec2 = NimbleClient::decide_fallback(noise_plus_subquery, choices);
    assert_eq!(
        dec2.selected_choice, "DropIrrelevantSpan",
        "Noise must take precedence over Subquery so noise does not spawn useless queries"
    );

    // 3. Noise + Expansion + Subquery: Noise must strictly win
    let all_three = "Need more context on unknown entity: cookie policy disclaimer is truncated. Further investigation needed.";
    let dec3 = NimbleClient::decide_fallback(all_three, choices);
    assert_eq!(
        dec3.selected_choice, "DropIrrelevantSpan",
        "Noise must win when all three conditions are present"
    );
}

#[test]
fn test_adversarial_is_noise_clean_evidence_never_dropped() {
    let choices = RlmSufficiencyChoice::all_choices();

    let clean_evidence = [
        "Angela Yvonne Davis (born January 26, 1944) is an American political activist, philosopher, academic, and author.",
        "The Artemis forensic engine parsed NTFS $MFT record at cluster 409600 for artifact analysis.",
        "Execution of svchost.exe (PID 1420) spawned abnormal network outbound connection to port 443.",
        "Threat actor deployed cobalt strike beacon to C:\\Windows\\Temp\\beacon.bin using scheduled task.",
        "Memory dump analysis confirmed hash 0x7FFA89B0 matches known benign Windows core DLL.",
    ];

    for &ev in &clean_evidence {
        let dec = NimbleClient::decide_fallback(ev, choices);
        assert_ne!(
            dec.selected_choice, "DropIrrelevantSpan",
            "Clean evidence '{}' must NOT be classified as DropIrrelevantSpan",
            ev
        );
        assert_eq!(
            dec.selected_choice, "SufficientAsIs",
            "Clean evidence '{}' must be classified as SufficientAsIs",
            ev
        );
        assert!(dec.calibrated_probability >= 0.70);
    }
}

#[test]
fn test_adversarial_is_noise_boundary_extremes_and_performance() {
    let choices = RlmSufficiencyChoice::all_choices();

    // 1. Empty string
    let dec_empty = NimbleClient::decide_fallback("", choices);
    assert_eq!(dec_empty.selected_choice, "SufficientAsIs");

    // 2. Whitespace only
    let dec_ws = NimbleClient::decide_fallback("   \t\n\r  ", choices);
    assert_eq!(dec_ws.selected_choice, "SufficientAsIs");

    // 3. 1 MB clean buffer benchmark (under unoptimized debug profile)
    let large_clean = "Evidence chunk containing critical forensic logs without noise. ".repeat(15000); // ~1MB
    let start_clean = Instant::now();
    let dec_large_clean = NimbleClient::decide_fallback(&large_clean, choices);
    let dur_clean = start_clean.elapsed();
    assert_eq!(dec_large_clean.selected_choice, "SufficientAsIs");
    assert!(
        dur_clean.as_millis() < 150,
        "1MB clean buffer fallback evaluation in debug mode must complete in <150ms (took {}ms)",
        dur_clean.as_millis()
    );

    // 4. 1 MB buffer with noise at the very end
    let mut large_noise = "Forensic data chunk repeated many times. ".repeat(15000);
    large_noise.push_str("Privacy policy and terms of service.");
    let start_noise = Instant::now();
    let dec_large_noise = NimbleClient::decide_fallback(&large_noise, choices);
    let dur_noise = start_noise.elapsed();
    assert_eq!(dec_large_noise.selected_choice, "DropIrrelevantSpan");
    assert!(
        dur_noise.as_millis() < 150,
        "1MB noise buffer fallback evaluation in debug mode must complete in <150ms (took {}ms)",
        dur_noise.as_millis()
    );
}

#[test]
fn test_adversarial_is_noise_unicode_and_null_bytes() {
    let choices = RlmSufficiencyChoice::all_choices();

    // 1. Non-ASCII Cyrillic clean
    let cyrillic_clean = "Анализ криминалистических артефактов файловой системы завершен.";
    let dec_cyrillic = NimbleClient::decide_fallback(cyrillic_clean, choices);
    assert_eq!(dec_cyrillic.selected_choice, "SufficientAsIs");

    // 2. Non-ASCII with English noise keyword embedded
    let mixed_noise = "Политика конфиденциальности: privacy policy for users.";
    let dec_mixed = NimbleClient::decide_fallback(mixed_noise, choices);
    assert_eq!(dec_mixed.selected_choice, "DropIrrelevantSpan");

    // 3. Embedded null bytes and control characters
    let null_noise = "Evidence\0with\0embedded\0nulls\0and\0copyright\0notice.";
    let dec_null = NimbleClient::decide_fallback(null_noise, choices);
    assert_eq!(dec_null.selected_choice, "DropIrrelevantSpan");

    // 4. Emoji and symbols
    let emoji_noise = "🚨 ALERT 🚨 Unrelated advertisement boilerplate banner.";
    let dec_emoji = NimbleClient::decide_fallback(emoji_noise, choices);
    assert_eq!(dec_emoji.selected_choice, "DropIrrelevantSpan");
}

#[test]
fn test_adversarial_is_noise_substring_overlap_empirical_characterization() {
    let choices = RlmSufficiencyChoice::all_choices();

    // Characterization: Substring collisions where legitimate forensic terms contain "license"
    // "driver's license"
    let driver_license = "Suspect submitted scanned driver's license ID 98234-A.";
    let dec_dl = NimbleClient::decide_fallback(driver_license, choices);
    // Because .contains("license") is a simple substring match, it triggers DropIrrelevantSpan
    assert_eq!(
        dec_dl.selected_choice, "DropIrrelevantSpan",
        "Empirically verify that simple substring matching on 'license' matches 'driver's license'"
    );

    // "disclaimer" in official forensic report header
    let report_disclaimer = "Official FBI forensic examiner report disclaimer: findings verified by peer review.";
    let dec_disc = NimbleClient::decide_fallback(report_disclaimer, choices);
    assert_eq!(
        dec_disc.selected_choice, "DropIrrelevantSpan",
        "Empirically verify that 'disclaimer' matches official report disclaimers"
    );
}
