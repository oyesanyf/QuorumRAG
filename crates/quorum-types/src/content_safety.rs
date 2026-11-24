//! Zero-tolerance Pornography & Explicit Adult Content Safety Filter (Shared Policy Core).
//!
//! Enforced fail-closed across ingestion (`quorum-ingest`), retrieval & vision
//! (`quorum-coordinator`), P2P Mesh / Marketplace DLP, uploads, and `/api/media` serving
//! (`quorum-daemon`).
//!
//! Uses multi-token boundary matching and domain-context awareness so legitimate medical,
//! clinical, anatomical, legal, academic, and art-history documents are preserved while
//! pornographic and explicit adult media/content is blocked everywhere.

use std::path::Path;

/// Result of evaluating a file path, metadata block, caption, or text payload against
/// the mandatory pornography / explicit adult content filter.
#[derive(Debug, Clone, PartialEq)]
pub enum ContentSafetyDecision {
    Allowed,
    Blocked {
        category: &'static str,
        reason: String,
        confidence: f32,
    },
}

impl ContentSafetyDecision {
    #[inline]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    pub fn block_reason(&self) -> Option<&str> {
        match self {
            Self::Allowed => None,
            Self::Blocked { reason, .. } => Some(reason.as_str()),
        }
    }
}

/// Returns `true` for image and video extensions subject to visual explicit-content filtering.
pub fn is_visual_media_extension(ext: &str) -> bool {
    matches!(
        ext.trim().trim_start_matches('.').to_ascii_lowercase().as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "webp"
            | "gif"
            | "bmp"
            | "tif"
            | "tiff"
            | "heic"
            | "heif"
            | "avif"
            | "jfif"
            | "svg"
            | "ico"
            | "mp4"
            | "mkv"
            | "mov"
            | "avi"
            | "webm"
            | "wmv"
            | "m4v"
            | "flv"
    )
}

/// Returns `true` for raster image extensions that can be pixel-analyzed cross-platform.
pub fn is_raster_image_extension(ext: &str) -> bool {
    matches!(
        ext.trim().trim_start_matches('.').to_ascii_lowercase().as_str(),
        "jpg" | "jpeg" | "png" | "webp" | "gif" | "bmp" | "jfif"
    )
}

/// Unambiguous pornography / adult-site tokens that never represent benign personal images.
const HARD_PORN_TOKENS: &[&str] = &[
    "porn",
    "porno",
    "pornography",
    "pornographic",
    "pornhub",
    "xvideos",
    "xnxx",
    "xhamster",
    "redtube",
    "youporn",
    "spankbang",
    "brazzers",
    "bangbros",
    "realitykings",
    "naughtyamerica",
    "chaturbate",
    "onlyfans",
    "stripchat",
    "bongacams",
    "myfreecams",
    "livejasmin",
    "hentai",
    "rule34",
    "r34",
    "nhentai",
    "hanime",
    "fakku",
    "nsfw",
    "sextape",
    "camgirl",
    "camwhore",
    "pornstar",
    "hardcoreporn",
    "softcore",
    "blowjob",
    "handjob",
    "footjob",
    "rimjob",
    "titfuck",
    "gangbang",
    "creampie",
    "bukkake",
    "cumshot",
    "deepthroat",
    "threesome",
    "orgy",
    "dildo",
    "buttplug",
    "fleshlight",
    "masturbat",
    "cunnilingus",
    "fellatio",
    "fisting",
    "scissoring",
    "ahegao",
    "futanari",
    "ecchi",
    "lewd",
    "erotica",
    "playboy",
    "hustler",
    "fapping",
    "nudes",
    "dickpic",
    "dickpics",
    "upskirt",
    "creepshot",
    "milf",
    "gilf",
    "pawg",
    "bdsm",
    "dominatrix",
    "shemale",
    "ladyboy",
    "boobjob",
];

/// Compound adult substrings checked on normalized alphanumeric runs inside filenames/paths.
const HARD_PORN_COMPOUNDS: &[&str] = &[
    "pornhub",
    "xvideos",
    "xhamster",
    "redtube",
    "youporn",
    "spankbang",
    "brazzers",
    "onlyfans",
    "chaturbate",
    "stripchat",
    "nhentai",
    "rule34",
    "pornstar",
    "pornography",
    "sextape",
    "camgirl",
    "blowjob",
    "handjob",
    "gangbang",
    "creampie",
    "bukkake",
    "cumshot",
    "deepthroat",
    "dickpic",
    "upskirt",
    "creepshot",
];

/// Secondary explicit/nudity tokens that trigger on visual media or when paired with another
/// adult indicator (protected against clinical/medical/art-history false positives).
const CONTEXTUAL_ADULT_TOKENS: &[&str] = &[
    "nude",
    "naked",
    "nudity",
    "topless",
    "bottomless",
    "erotic",
    "explicit",
    "uncensored",
    "hardcore",
    "stripper",
    "striptease",
    "fetish",
    "bondage",
    "lingerie",
    "boudoir",
    "boobs",
    "tits",
    "titties",
    "nipple",
    "nipples",
    "pussy",
    "vagina",
    "vulva",
    "penis",
    "cock",
    "dick",
    "genital",
    "genitalia",
    "genitals",
    "clitoris",
    "scrotum",
    "testicle",
    "buttocks",
    "asshole",
    "intercourse",
    "orgasm",
    "ejaculat",
    "horny",
    "slut",
    "whore",
    "hentai",
    "smut",
];

/// Multi-word explicit phrases that unambiguously indicate pornography in captions/OCR/text.
const EXPLICIT_PHRASES: &[&str] = &[
    "explicit sexual",
    "sexual intercourse",
    "oral sex",
    "anal sex",
    "group sex",
    "pornographic image",
    "pornographic video",
    "pornographic content",
    "adult video",
    "adult film",
    "nude selfie",
    "naked selfie",
    "nude photo",
    "naked photo",
    "nude picture",
    "naked picture",
    "exposed breasts",
    "exposed genitals",
    "exposed genitalia",
    "exposed penis",
    "exposed vagina",
    "naked woman",
    "naked man",
    "nude woman",
    "nude man",
    "having sex",
    "sex act",
    "sexual act",
    "sexually explicit",
    "hardcore sex",
    "xxx video",
    "xxx photo",
    "not safe for work",
    "18+ only",
    "onlyfans leak",
];

/// Legitimate clinical, medical, academic, legal, and art-history context markers that prevent
/// false positives on non-pornographic documents (e.g. dermatology reports, anatomy textbooks).
const BENIGN_CONTEXT_TOKENS: &[&str] = &[
    "medical",
    "clinical",
    "hospital",
    "patient",
    "diagnosis",
    "radiology",
    "mammogram",
    "oncology",
    "dermatology",
    "urology",
    "gynecology",
    "obstetrics",
    "pathology",
    "anatomy",
    "textbook",
    "pubmed",
    "journal",
    "icd10",
    "hipaa",
    "museum",
    "sculpture",
    "statue",
    "renaissance",
    "painting",
    "court",
    "statute",
    "affidavit",
    "legal",
    "forensic",
    "police",
    "policy",
    "curriculum",
    "syllabus",
];

const COSMETIC_OR_APPAREL_BENIGN_TOKENS: &[&str] = &[
    "lipstick",
    "makeup",
    "palette",
    "shade",
    "beige",
    "heels",
    "shoe",
    "shoes",
    "dress",
    "nail",
    "polish",
    "foundation",
];

fn tokenize_normalized(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            // Split camelCase boundaries (`myPornFolder` -> `my`, `porn`, `folder`)
            if ch.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
                tokens.push(cur.to_ascii_lowercase());
                cur.clear();
            }
            prev_lower = ch.is_ascii_lowercase();
            cur.push(ch);
        } else {
            if !cur.is_empty() {
                tokens.push(cur.to_ascii_lowercase());
                cur.clear();
            }
            prev_lower = false;
        }
    }
    if !cur.is_empty() {
        tokens.push(cur.to_ascii_lowercase());
    }
    tokens
}

fn token_matches_hard_porn(tok: &str) -> bool {
    if HARD_PORN_TOKENS.contains(&tok) {
        return true;
    }
    if matches!(
        tok,
        s if s.starts_with("porno")
            || s.starts_with("pornograph")
            || s.starts_with("pornhub")
            || s.starts_with("pornstar")
            || s.starts_with("porntube")
            || s.starts_with("pornsite")
            || s.starts_with("pornvid")
    ) {
        return true;
    }
    if tok.starts_with("masturbat") {
        return true;
    }
    HARD_PORN_COMPOUNDS.iter().any(|c| tok.contains(c))
}

fn token_matches_contextual_adult(tok: &str) -> bool {
    CONTEXTUAL_ADULT_TOKENS.contains(&tok)
        || matches!(tok, "anal" | "fap" | "pegging")
        || tok.starts_with("ejaculat")
}

/// Evaluates a filesystem path (parent directories + filename) for pornography / explicit
/// adult media markers. Fails closed on unambiguous adult/pornography terms across all media.
pub fn check_path_explicit_content(path: &Path) -> ContentSafetyDecision {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    let is_media = is_visual_media_extension(ext);

    let mut all_tokens: Vec<String> = Vec::new();
    for comp in path.components() {
        let seg = comp.as_os_str().to_string_lossy();
        // Skip drive letters and root separators
        if seg.len() <= 3 && seg.ends_with(':') {
            continue;
        }
        all_tokens.extend(tokenize_normalized(&seg));
    }

    if all_tokens.is_empty() {
        return ContentSafetyDecision::Allowed;
    }

    let mut distinct_benign: Vec<&str> = Vec::new();
    for t in &all_tokens {
        if BENIGN_CONTEXT_TOKENS.contains(&t.as_str()) && !distinct_benign.contains(&t.as_str()) {
            distinct_benign.push(t.as_str());
        }
    }
    let has_benign_context = !distinct_benign.is_empty();
    let strong_benign_path = distinct_benign.len() >= 2;
    let has_cosmetic_context = all_tokens
        .iter()
        .any(|t| COSMETIC_OR_APPAREL_BENIGN_TOKENS.contains(&t.as_str()));

    for tok in &all_tokens {
        if token_matches_hard_porn(tok) || (is_media && tok == "xxx") {
            // Avoid blocking purely non-media source/policy files discussing content safety
            // (e.g., `content_safety.rs` itself or legal policy PDFs without porn domains).
            if !is_media && has_benign_context {
                continue;
            }
            if is_media || HARD_PORN_COMPOUNDS.iter().any(|c| tok.contains(c)) || matches!(
                tok.as_str(),
                "porn"
                    | "porno"
                    | "pornography"
                    | "pornographic"
                    | "hentai"
                    | "nsfw"
                    | "nudes"
                    | "sextape"
                    | "camgirl"
                    | "onlyfans"
            ) {
                return ContentSafetyDecision::Blocked {
                    category: "pornography_path",
                    reason: format!(
                        "Blocked by pornography/explicit content filter (explicit path marker '{}')",
                        tok
                    ),
                    confidence: 0.99,
                };
            }
        }
    }

    // Check contextual adult/nudity indicators on visual media files (unless strong clinical/art context)
    if is_media && !strong_benign_path {
        let mut ctx_hits: Vec<&str> = Vec::new();
        for tok in &all_tokens {
            if token_matches_contextual_adult(tok) && !ctx_hits.contains(&tok.as_str()) {
                ctx_hits.push(tok.as_str());
            }
        }
        // Single strong nudity/explicit token in an image filename/folder (e.g. `nude_pic.jpg`,
        // `naked_selfie.png`, `topless.webp`, `explicit_photo.jpg`) blocks visual media outright.
        let has_strong_media_nudity = ctx_hits.iter().any(|t| match *t {
            "nude" => !has_cosmetic_context && !has_benign_context,
            "naked"
            | "nudity"
            | "topless"
            | "bottomless"
            | "erotic"
            | "hardcore"
            | "striptease"
            | "pussy"
            | "cock"
            | "tits"
            | "titties"
            | "boobs"
            | "nipple"
            | "nipples"
            | "genitals"
            | "genitalia"
            | "smut" => true,
            _ => false,
        });
        if has_strong_media_nudity || ctx_hits.len() >= 2 {
            return ContentSafetyDecision::Blocked {
                category: "explicit_media_path",
                reason: format!(
                    "Blocked by pornography/explicit image filter (explicit media indicator '{}')",
                    ctx_hits.join(", ")
                ),
                confidence: 0.95,
            };
        }
    }

    ContentSafetyDecision::Allowed
}

/// Evaluates text (OCR output, vision caption, EXIF/XMP keywords, or chunk content) for
/// pornographic / sexually explicit content, preserving benign medical/academic/legal records.
pub fn check_text_explicit_content(text: &str) -> ContentSafetyDecision {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return ContentSafetyDecision::Allowed;
    }

    let lower = trimmed.to_ascii_lowercase();
    let tokens = tokenize_normalized(trimmed);
    if tokens.is_empty() {
        return ContentSafetyDecision::Allowed;
    }

    let mut distinct_benign: Vec<&str> = Vec::new();
    for t in &tokens {
        if BENIGN_CONTEXT_TOKENS.contains(&t.as_str()) && !distinct_benign.contains(&t.as_str()) {
            distinct_benign.push(t.as_str());
        }
    }
    let strong_benign_context = distinct_benign.len() >= 2;

    // 1. Multi-word explicit phrases
    for phrase in EXPLICIT_PHRASES {
        if lower.contains(phrase) {
            // Allow clinical/medical/legal reports discussing anatomy or legal policy unless
            // overtly pornographic terms appear.
            let overt_porn = phrase.contains("porn")
                || phrase.contains("xxx")
                || phrase.contains("onlyfans")
                || phrase.contains("nude selfie")
                || phrase.contains("naked selfie");
            if overt_porn || !strong_benign_context {
                return ContentSafetyDecision::Blocked {
                    category: "explicit_text_phrase",
                    reason: format!(
                        "Blocked by pornography/explicit content filter (explicit phrase '{}')",
                        phrase
                    ),
                    confidence: 0.96,
                };
            }
        }
    }

    // 2. Hard pornographic tokens & adult domains
    let mut hard_hits: Vec<&str> = Vec::new();
    for tok in &tokens {
        if token_matches_hard_porn(tok) && !hard_hits.contains(&tok.as_str()) {
            hard_hits.push(tok.as_str());
        }
    }
    if !hard_hits.is_empty() {
        let has_unambiguous_domain_or_act = hard_hits.iter().any(|t| {
            HARD_PORN_COMPOUNDS.iter().any(|c| t.contains(c))
                || matches!(
                    *t,
                    "porno"
                        | "hentai"
                        | "blowjob"
                        | "handjob"
                        | "gangbang"
                        | "creampie"
                        | "bukkake"
                        | "cumshot"
                        | "deepthroat"
                        | "onlyfans"
                        | "chaturbate"
                        | "nudes"
                )
        });
        if has_unambiguous_domain_or_act || !strong_benign_context {
            return ContentSafetyDecision::Blocked {
                category: "pornography_text",
                reason: format!(
                    "Blocked by pornography/explicit content filter (explicit term '{}')",
                    hard_hits.join(", ")
                ),
                confidence: 0.97,
            };
        }
    }

    // 3. Multi-token contextual explicit density (requires >= 2 distinct explicit terms
    // without strong clinical/academic/legal context).
    if !strong_benign_context {
        let mut ctx_hits: Vec<&str> = Vec::new();
        for tok in &tokens {
            if token_matches_contextual_adult(tok) && !ctx_hits.contains(&tok.as_str()) {
                ctx_hits.push(tok.as_str());
            }
        }
        if ctx_hits.len() >= 2 {
            return ContentSafetyDecision::Blocked {
                category: "explicit_text_cluster",
                reason: format!(
                    "Blocked by pornography/explicit content filter (explicit terms: {})",
                    ctx_hits.join(", ")
                ),
                confidence: 0.90,
            };
        }
    }

    ContentSafetyDecision::Allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_pornographic_image_paths_and_domains() {
        for bad in [
            r"C:\Users\Alice\Downloads\pornhub_clip_01.jpg",
            r"D:\media\NSFW\photo_001.png",
            r"C:\Users\Alice\Pictures\hentai_gallery\img02.webp",
            r"C:\Users\Alice\Pictures\nude_selfie.jpg",
            r"C:\Users\Alice\Pictures\gallery\nude_selfie.jpg",
            r"C:\Users\Alice\Downloads\onlyfans_leak.png",
            "/home/alice/xxx/clip.mp4",
        ] {
            assert!(
                check_path_explicit_content(Path::new(bad)).is_blocked(),
                "Expected path '{bad}' to be blocked"
            );
        }
    }

    #[test]
    fn allows_benign_photos_documents_and_medical_records() {
        for ok in [
            r"C:\Users\Alice\Pictures\family_vacation_2025.jpg",
            r"C:\Users\Alice\Documents\medical_dermatology_report.pdf",
            r"C:\Users\Alice\Documents\hospital_anatomy_textbook_diagram.png",
            r"C:\Users\Alice\Pictures\museum_renaissance_statue.jpg",
            r"D:\dataset\images\dogs\dog.119.jpg",
            r"C:\Users\Alice\Documents\assignment_analysis.docx",
            r"C:\Users\Alice\Documents\Pornchai_resume.pdf",
            r"C:\Users\Alice\Pictures\Dick_Smith_family.jpg",
            r"C:\Users\Alice\Pictures\nude_lipstick_palette.jpg",
            r"C:\Users\Alice\Pictures\cam4_front_door.jpg",
        ] {
            assert!(
                !check_path_explicit_content(Path::new(ok)).is_blocked(),
                "Expected benign path '{ok}' to be allowed"
            );
        }
    }

    #[test]
    fn blocks_explicit_captions_while_allowing_clinical_notes() {
        assert!(check_text_explicit_content(
            "A naked woman posing in an explicit sexual act for OnlyFans"
        )
        .is_blocked());
        assert!(check_text_explicit_content(
            "Image shows exposed breasts and nude buttocks on a bed"
        )
        .is_blocked());
        assert!(!check_text_explicit_content(
            "Clinical hospital radiology report: patient underwent routine breast mammogram and dermatology diagnosis."
        )
        .is_blocked());
        assert!(!check_text_explicit_content(
            "Redacted SSN: XXX-XX-1234 on Bath & Body Works (BBW) invoice #4421"
        )
        .is_blocked());
        assert!(!check_text_explicit_content(
            "A golden retriever sitting on green grass next to a red ball in a park."
        )
        .is_blocked());
    }
}
