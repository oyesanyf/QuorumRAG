//! Conversational query framing removal and media-intent detection.
//!
//! Natural questions such as "show me the File that contains a cow" or
//! "are there pictures taken in La Grange" carry filler words ("show", "file",
//! "contains", "pictures", "taken") that dilute BM25 scoring and can make the
//! lexical index match unrelated documents (e.g. Perl "COW" = copy-on-write docs).
//! This module isolates the subject ("cow", "La Grange") and separately reports
//! which media modality the user asked for so retrieval can rank that modality first.

/// Which modality a query is explicitly asking about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaIntent {
    Image,
    Audio,
    Video,
    None,
}

/// Leading phrases removed (longest first, case-insensitive, applied repeatedly).
const LEADING_FRAMES: &[&str] = &[
    "can you show me the file that contains a ",
    "can you show me the file that contains ",
    "show me the file that contains an ",
    "show me the file that contains a ",
    "show me the file that contains ",
    "show me the files that contain ",
    "show me a file that contains ",
    "show me files that contain ",
    "show me files containing ",
    "show me files with ",
    "find the file that contains ",
    "find files that contain ",
    "find files containing ",
    "which file contains ",
    "which files contain ",
    "file that contains a ",
    "file that contains ",
    "files containing ",
    "are there any pictures taken in ",
    "are there any photos taken in ",
    "are there pictures taken in ",
    "are there photos taken in ",
    "are there images taken in ",
    "are there any pictures of ",
    "are there any photos of ",
    "are there any images of ",
    "are there pictures of ",
    "are there photos of ",
    "are there images of ",
    "do i have pictures taken in ",
    "do i have photos taken in ",
    "do i have pictures of ",
    "do i have photos of ",
    "do you have pictures of ",
    "do you have photos of ",
    "is there a picture of ",
    "is there a photo of ",
    "is there an image of ",
    "pictures taken in ",
    "photos taken in ",
    "images taken in ",
    "photos from ",
    "pictures from ",
    "show me pictures of ",
    "show me photos of ",
    "show me images of ",
    "show me the image of ",
    "show me an image of ",
    "show me a picture of ",
    "tell me about the images of ",
    "tell me about the image of ",
    "tell me about images of ",
    "tell me about image of ",
    "tell me about pictures of ",
    "tell me about the pictures of ",
    "tell me about the photo of ",
    "tell me about photos of ",
    "tell me about the song ",
    "tell me about the track ",
    "tell me about the audio ",
    "tell me about the video ",
    "tell me about song ",
    "information about the song ",
    "what is the song ",
    "play the song ",
    "play ",
    "describe the image of ",
    "describe image of ",
    "describe the picture of ",
    "describe ",
    "show me ",
    "tell me about ",
];

/// Filler words dropped from the remaining subject when they are not the only content.
const FILLER: &[&str] = &[
    "file", "files", "document", "documents", "contains", "contain", "containing",
    "picture", "pictures", "photo", "photos", "image", "images", "taken", "song", "songs",
    "track", "audio", "video", "videos", "any", "some", "there", "that", "which", "a", "an", "the",
    "of", "in", "please", "me", "show",
];

/// Remove conversational framing, returning the subject in its original casing.
/// Falls back to the trimmed input when stripping would leave nothing.
pub fn strip_conversational_framing(query: &str) -> String {
    let trimmed = query.trim().trim_end_matches(['?', '.', '!']).trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut rest: &str = trimmed;
    loop {
        let lower = rest.to_ascii_lowercase();
        let mut stripped = false;
        for frame in LEADING_FRAMES {
            if lower.starts_with(frame) && rest.len() > frame.len() {
                rest = rest[frame.len()..].trim_start();
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }
    let words: Vec<&str> = rest
        .split_whitespace()
        .filter(|w| {
            let lw = w.trim_matches(|c: char| !c.is_alphanumeric()).to_ascii_lowercase();
            !FILLER.contains(&lw.as_str())
        })
        .collect();
    if words.is_empty() {
        if rest.trim().is_empty() { trimmed.to_string() } else { rest.trim().to_string() }
    } else {
        words.join(" ")
    }
}

fn has_word(lower: &str, words: &[&str]) -> bool {
    lower
        .split(|c: char| !c.is_alphanumeric())
        .any(|w| words.contains(&w))
}

/// Detect an explicit modality request in the user's question.
pub fn detect_media_intent(query: &str) -> MediaIntent {
    let lower = query.to_ascii_lowercase();
    if has_word(&lower, &["picture", "pictures", "photo", "photos", "image", "images", "photograph", "photographs", "jpg", "jpeg", "png", "selfie"]) {
        return MediaIntent::Image;
    }
    if has_word(&lower, &["video", "videos", "movie", "clip", "mp4", "mkv"]) {
        return MediaIntent::Video;
    }
    if has_word(&lower, &["song", "songs", "track", "music", "audio", "mp3", "recording", "album", "lyrics"]) {
        return MediaIntent::Audio;
    }
    MediaIntent::None
}

/// Content prefix written by the corresponding media indexer.
pub fn media_content_prefix(intent: MediaIntent) -> Option<&'static str> {
    match intent {
        MediaIntent::Image => Some("[Image Document:"),
        MediaIntent::Audio => Some("[Audio Document:"),
        MediaIntent::Video => Some("[Video Document:"),
        MediaIntent::None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_four_user_questions() {
        assert_eq!(strip_conversational_framing("show me the File that contains a cow"), "cow");
        assert_eq!(strip_conversational_framing("are there pictures taken in La Grange"), "La Grange");
        assert_eq!(strip_conversational_framing("tell me about the song Savannah Woman"), "Savannah Woman");
        assert_eq!(strip_conversational_framing("tell me about image of dogs"), "dogs");
    }

    #[test]
    fn keeps_plain_queries_and_never_returns_empty() {
        assert_eq!(strip_conversational_framing("Angela Davis lease"), "Angela Davis lease");
        assert_eq!(strip_conversational_framing("show me"), "show me");
        assert_eq!(strip_conversational_framing("   "), "");
    }

    #[test]
    fn detects_media_intent() {
        assert_eq!(detect_media_intent("are there pictures taken in La Grange"), MediaIntent::Image);
        assert_eq!(detect_media_intent("tell me about image of dogs"), MediaIntent::Image);
        assert_eq!(detect_media_intent("tell me about the song Savannah Woman"), MediaIntent::Audio);
        assert_eq!(detect_media_intent("show me the File that contains a cow"), MediaIntent::None);
        assert_eq!(detect_media_intent("lease agreement"), MediaIntent::None);
    }
}
