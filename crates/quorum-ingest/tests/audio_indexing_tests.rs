//! Unit and Integration Tests for Milestone M11 Audio Indexing & Metadata Extraction.
//!
//! Verifies:
//! 1. Candidate routing accepts MP3/WAV/FLAC/OGG as CandidateKind::Audio and never SkipBinary.
//! 2. Real audio file parsing on Savannah_Woman.mp3 at D:\harfile\music\storage\album\savana_woman\Savannah_Woman.mp3.
//! 3. Real audio file parsing on Savannah_Woman_320.mp3 (320 kbps variant).
//! 4. Synthetic MP3 with ID3v2 text frames (TIT2, TPE1, TALB, TYER, TCON, USLT) and ID3v1 trailer.
//! 5. Companion lyrics discovery (.lrc, .txt, .srt) and integration into search text.
//! 6. Pure-Rust WAV header parsing (RIFF/WAVE fmt chunk).
//! 7. Pure-Rust FLAC header parsing (fLaC STREAMINFO).
//! 8. End-to-end DocumentChunk emission into vector and metadata format.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;

use quorum_classifier::{FileCategory, FileIdentity};
use quorum_contract::{EmbeddingContract, EmbeddingGenerator};
use quorum_ingest::audio_indexer::AudioIndexer;
use quorum_ingest::classifier_router::{CandidateKind, ClassifierRouter, FilterDecision};
use quorum_ingest::config::IngestConfig;

/// Deterministic 768-dim L2-normalized embedding generator for unit tests.
#[derive(Debug, Clone)]
struct TestEmbeddingGenerator {
    contract: EmbeddingContract,
}

impl Default for TestEmbeddingGenerator {
    fn default() -> Self {
        Self {
            contract: EmbeddingContract::canonical_gemma_300m(),
        }
    }
}

impl EmbeddingGenerator for TestEmbeddingGenerator {
    fn contract(&self) -> &EmbeddingContract {
        &self.contract
    }

    fn embed_text(&self, text: &str) -> Result<Vec<f32>, quorum_contract::ContractError> {
        let dim = self.contract.dimension;
        let mut vec = Vec::with_capacity(dim);
        let mut hasher = blake3::Hasher::new();
        hasher.update(text.as_bytes());

        for i in 0..dim {
            let mut step_hasher = hasher.clone();
            step_hasher.update(&(i as u32).to_le_bytes());
            let hash = step_hasher.finalize();
            let raw_int = u32::from_le_bytes([
                hash.as_bytes()[0],
                hash.as_bytes()[1],
                hash.as_bytes()[2],
                hash.as_bytes()[3],
            ]);
            let float_val = (raw_int as f32 / u32::MAX as f32) * 2.0 - 1.0;
            vec.push(float_val);
        }

        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for v in &mut vec {
                *v /= norm;
            }
        }
        Ok(vec)
    }
}

/// Helper to build a valid synthetic ID3v2.3 tag buffer.
fn build_id3v2_tag(
    title: &str,
    artist: &str,
    album: &str,
    year: &str,
    genre: &str,
    lyrics: &str,
) -> Vec<u8> {
    let mut frames_data = Vec::new();

    // Helper to append a standard text frame (TIT2, TPE1, TALB, etc.)
    let mut add_text_frame = |frame_id: &[u8; 4], text: &str| {
        frames_data.extend_from_slice(frame_id);
        let text_bytes = text.as_bytes();
        let frame_size = (1 + text_bytes.len()) as u32; // 1 byte encoding + text
        frames_data.extend_from_slice(&frame_size.to_be_bytes());
        frames_data.extend_from_slice(&[0x00, 0x00]); // flags
        frames_data.push(0x03); // UTF-8 encoding
        frames_data.extend_from_slice(text_bytes);
    };

    add_text_frame(b"TIT2", title);
    add_text_frame(b"TPE1", artist);
    add_text_frame(b"TALB", album);
    add_text_frame(b"TYER", year);
    add_text_frame(b"TCON", genre);

    // USLT lyrics frame: 1 byte encoding (0x03) + 3 bytes lang ("eng") + content desc null (0x00) + lyrics
    {
        frames_data.extend_from_slice(b"USLT");
        let lyrics_bytes = lyrics.as_bytes();
        let frame_size = (1 + 3 + 1 + lyrics_bytes.len()) as u32;
        frames_data.extend_from_slice(&frame_size.to_be_bytes());
        frames_data.extend_from_slice(&[0x00, 0x00]);
        frames_data.push(0x03); // UTF-8
        frames_data.extend_from_slice(b"eng");
        frames_data.push(0x00); // descriptor delimiter
        frames_data.extend_from_slice(lyrics_bytes);
    }

    let tag_size = frames_data.len();
    let syncsafe_size = [
        ((tag_size >> 21) & 0x7f) as u8,
        ((tag_size >> 14) & 0x7f) as u8,
        ((tag_size >> 7) & 0x7f) as u8,
        (tag_size & 0x7f) as u8,
    ];

    let mut id3 = Vec::new();
    id3.extend_from_slice(b"ID3");
    id3.push(0x03); // ID3v2.3
    id3.push(0x00); // revision
    id3.push(0x00); // flags
    id3.extend_from_slice(&syncsafe_size);
    id3.extend_from_slice(&frames_data);

    id3
}

/// Helper to build a 128-byte ID3v1 trailer.
fn build_id3v1_tag(title: &str, artist: &str, album: &str, year: &str, track: u8) -> [u8; 128] {
    let mut tag = [0u8; 128];
    tag[0..3].copy_from_slice(b"TAG");

    let t_bytes = title.as_bytes();
    let t_len = t_bytes.len().min(30);
    tag[3..3 + t_len].copy_from_slice(&t_bytes[..t_len]);

    let a_bytes = artist.as_bytes();
    let a_len = a_bytes.len().min(30);
    tag[33..33 + a_len].copy_from_slice(&a_bytes[..a_len]);

    let al_bytes = album.as_bytes();
    let al_len = al_bytes.len().min(30);
    tag[63..63 + al_len].copy_from_slice(&al_bytes[..al_len]);

    let y_bytes = year.as_bytes();
    let y_len = y_bytes.len().min(4);
    tag[93..93 + y_len].copy_from_slice(&y_bytes[..y_len]);

    // ID3v1.1 track number
    tag[125] = 0;
    tag[126] = track;
    tag[127] = 17; // Rock

    tag
}

/// Helper to build a valid synthetic MP3 buffer with ID3v2, MPEG audio frames, and ID3v1.
fn build_synthetic_mp3(
    title: &str,
    artist: &str,
    album: &str,
    year: &str,
    genre: &str,
    lyrics: &str,
) -> Vec<u8> {
    let mut buffer = build_id3v2_tag(title, artist, album, year, genre, lyrics);

    // MPEG-1 Layer III frame header:
    // Byte 0: 0xFF
    // Byte 1: 0xFB (MPEG-1, Layer III, no CRC)
    // Byte 2: 0x90 (128 kbps, 44100 Hz, no padding)
    // Byte 3: 0x44 (Joint Stereo)
    // Frame size = 144 * 128000 / 44100 = 417 bytes.
    const FRAME_SIZE: usize = 417;
    let mut frame = vec![0x55; FRAME_SIZE];
    frame[0] = 0xFF;
    frame[1] = 0xFB;
    frame[2] = 0x90;
    frame[3] = 0x44;

    // Append 100 audio frames (approx 2.6 seconds)
    for _ in 0..100 {
        buffer.extend_from_slice(&frame);
    }

    // Append ID3v1 trailer
    let id3v1 = build_id3v1_tag(title, artist, album, year, 1);
    buffer.extend_from_slice(&id3v1);

    buffer
}

#[test]
fn test_audio_candidate_routing_accepts_and_never_skips_binary() {
    let dir = tempdir().unwrap();
    let config = IngestConfig {
        watch_paths: vec![dir.path().to_path_buf()],
        ..Default::default()
    };
    let router = ClassifierRouter::new(config);

    let audio_files = [
        ("track.mp3", build_synthetic_mp3("Test Title", "Artist", "Album", "2024", "Rock", "")),
        ("recording.wav", vec![
            b'R', b'I', b'F', b'F', 0x24, 0x00, 0x00, 0x00, b'W', b'A', b'V', b'E',
            b'f', b'm', b't', b' ', 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00,
            0x44, 0xAC, 0x00, 0x00, 0x10, 0xB1, 0x02, 0x00, 0x04, 0x00, 0x10, 0x00,
            b'd', b'a', b't', b'a', 0x00, 0x00, 0x00, 0x00,
        ]),
        ("lossless.flac", vec![b'f', b'L', b'a', b'C', 0x00, 0x00, 0x00, 0x22, 0x00]),
    ];

    for (name, content) in &audio_files {
        let file_path = dir.path().join(name);
        let mut file = File::create(&file_path).unwrap();
        file.write_all(content).unwrap();

        let decision = router.evaluate_file(&file_path);
        match decision {
            FilterDecision::Accept { kind, identity, .. } => {
                match kind {
                    CandidateKind::Audio { format_label, mime_type } => {
                        assert!(!format_label.is_empty());
                        assert!(!mime_type.is_empty());
                    }
                    other => panic!("Audio file '{}' routed to wrong kind: {:?}", name, other),
                }
                assert_eq!(
                    identity.category,
                    FileCategory::Audio,
                    "File '{}' category was not Audio: {:?}",
                    name,
                    identity.category
                );
            }
            FilterDecision::SkipBinary { identity } => {
                panic!(
                    "CRITICAL REGRESSION: Audio file '{}' was rejected as SkipBinary: {:?}",
                    name, identity
                );
            }
            other => panic!("Audio file '{}' unexpected decision: {:?}", name, other),
        }
    }
}

#[test]
fn test_synthetic_mp3_parsing_and_chunk_generation() {
    let synthetic_bytes = build_synthetic_mp3(
        "Moonlight Sonata",
        "Ludwig van Beethoven",
        "Piano Sonatas",
        "1801",
        "Classical",
        "Look at the stars\nLook how they shine for you",
    );

    let temp_path = Path::new("D:\\music\\classical\\Moonlight_Sonata.mp3");
    let identity = FileIdentity::new(
        "mp3",
        "audio/mpeg",
        FileCategory::Audio,
        "MP3 audio file",
        false,
        1.0,
        quorum_classifier::ClassifierEngine::ExtensionFallback,
    );

    let metadata = AudioIndexer::extract_metadata(temp_path, &synthetic_bytes, &identity);

    assert_eq!(metadata.title.as_deref(), Some("Moonlight Sonata"));
    assert_eq!(metadata.artist.as_deref(), Some("Ludwig van Beethoven"));
    assert_eq!(metadata.album.as_deref(), Some("Piano Sonatas"));
    assert_eq!(metadata.year, Some(1801));
    assert_eq!(metadata.genre.as_deref(), Some("Classical"));
    assert_eq!(metadata.track_number, Some(1));
    assert_eq!(metadata.bitrate_kbps, 128);
    assert_eq!(metadata.sample_rate_hz, 44100);
    assert_eq!(metadata.channels, 2);
    assert_eq!(metadata.channel_mode, "Joint Stereo");
    assert!(metadata.duration_secs > 2.0 && metadata.duration_secs < 3.5);
    assert!(metadata.has_lyrics);
    assert_eq!(metadata.lyrics_source.as_deref(), Some("ID3v2 USLT"));
    assert!(metadata.lyrics_text.as_ref().unwrap().contains("Look at the stars"));

    let embedder = TestEmbeddingGenerator::default();
    let chunk = AudioIndexer::index_audio(temp_path, &synthetic_bytes, &identity, 1, &embedder).unwrap();

    assert!(chunk.chunk_id.ends_with(":audio:0"));
    assert_eq!(chunk.vector.len(), 768);
    assert!(chunk.text_content.contains("Title: Moonlight Sonata"));
    assert!(chunk.text_content.contains("Artist: Ludwig van Beethoven"));
    assert!(chunk.text_content.contains("128 kbps, 44100 Hz"));
    assert!(chunk.text_content.contains("Lyrics / Transcript (from ID3v2 USLT):"));
    assert!(!chunk.metadata_json.is_empty());
}

#[test]
fn test_companion_lyrics_discovery_and_indexing() {
    let dir = tempdir().unwrap();
    let audio_path = dir.path().join("amazing_grace.mp3");
    let lyrics_path = dir.path().join("amazing_grace.lrc");

    // Write MP3 without embedded lyrics
    let mp3_bytes = build_synthetic_mp3("Amazing Grace", "John Newton", "Hymns", "1779", "Gospel", "");
    File::create(&audio_path).unwrap().write_all(&mp3_bytes).unwrap();

    // Write companion .lrc file
    let lrc_content = "[00:12.00]Amazing grace how sweet the sound\n[00:18.00]That saved a wretch like me";
    File::create(&lyrics_path).unwrap().write_all(lrc_content.as_bytes()).unwrap();

    let identity = FileIdentity::new(
        "mp3",
        "audio/mpeg",
        FileCategory::Audio,
        "MP3 audio file",
        false,
        1.0,
        quorum_classifier::ClassifierEngine::ExtensionFallback,
    );

    let metadata = AudioIndexer::extract_metadata(&audio_path, &mp3_bytes, &identity);
    assert!(metadata.has_lyrics);
    assert_eq!(metadata.lyrics_source.as_deref(), Some("amazing_grace.lrc"));
    assert!(metadata.lyrics_text.as_ref().unwrap().contains("Amazing grace how sweet the sound"));

    let embedder = TestEmbeddingGenerator::default();
    let chunk = AudioIndexer::index_audio(&audio_path, &mp3_bytes, &identity, 1, &embedder).unwrap();
    assert!(chunk.text_content.contains("Lyrics / Transcript (from amazing_grace.lrc):"));
    assert!(chunk.text_content.contains("saved a wretch like me"));
}

#[test]
fn test_real_savannah_woman_audio_file_verification() {
    let audio_file_path = Path::new(r"D:\harfile\music\storage\album\savana_woman\Savannah_Woman.mp3");

    // If the file exists on this system, perform strict real-world parsing verification
    if audio_file_path.is_file() {
        let bytes = std::fs::read(audio_file_path).expect("Failed to read Savannah_Woman.mp3");
        assert_eq!(bytes.len(), 4_358_962, "Savannah_Woman.mp3 file size mismatch");

        let identity = FileIdentity::new(
            "mp3",
            "audio/mpeg",
            FileCategory::Audio,
            "MP3 audio file",
            false,
            1.0,
            quorum_classifier::ClassifierEngine::HeaderInspection,
        );

        let metadata = AudioIndexer::extract_metadata(audio_file_path, &bytes, &identity);

        // Verify title resolved to "Savannah Woman" via stem fallback
        assert_eq!(
            metadata.title.as_deref(),
            Some("Savannah Woman"),
            "Expected title 'Savannah Woman', got {:?}",
            metadata.title
        );

        // Verify format and MPEG audio header properties
        assert_eq!(metadata.format_name, "MP3");
        assert_eq!(metadata.bitrate_kbps, 192, "Expected 192 kbps bitrate");
        assert_eq!(metadata.sample_rate_hz, 44100, "Expected 44100 Hz sample rate");
        assert_eq!(metadata.channels, 2, "Expected 2 channels");
        assert_eq!(metadata.channel_mode, "Joint Stereo");

        // Verify duration is approx 181.4 seconds (~3m 1s)
        assert!(
            metadata.duration_secs >= 180.0 && metadata.duration_secs <= 183.0,
            "Expected duration ~181s, got {:.2}s",
            metadata.duration_secs
        );

        // Verify path tokens
        assert!(metadata.path_tokens.contains(&"Savannah".to_string()));
        assert!(metadata.path_tokens.contains(&"Woman".to_string()));
        assert!(metadata.path_tokens.contains(&"music".to_string()));
        assert!(metadata.path_tokens.contains(&"album".to_string()));

        // Verify DocumentChunk generation
        let embedder = TestEmbeddingGenerator::default();
        let chunk = AudioIndexer::index_audio(audio_file_path, &bytes, &identity, 1, &embedder)
            .expect("Failed to index Savannah_Woman.mp3 into DocumentChunk");

        assert!(chunk.chunk_id.ends_with(":audio:0"));
        assert_eq!(chunk.vector.len(), 768);
        assert!(chunk.text_content.contains("[Audio Document: Savannah_Woman.mp3]"));
        assert!(chunk.text_content.contains("Title: Savannah Woman"));
        assert!(chunk.text_content.contains("192 kbps, 44100 Hz, Joint Stereo (2 channels)"));
        assert!(chunk.text_content.contains("Duration: 3m 1s"));

        // Verify structured metadata JSON
        let parsed_json: serde_json::Value =
            serde_json::from_str(&chunk.metadata_json).unwrap();
        assert_eq!(parsed_json["title"], "Savannah Woman");
        assert_eq!(parsed_json["bitrate_kbps"], 192);
        assert_eq!(parsed_json["sample_rate_hz"], 44100);
        assert_eq!(parsed_json["channels"], 2);
    }
}

#[test]
fn test_real_savannah_woman_320_audio_file_verification() {
    let audio_file_path = Path::new(r"D:\harfile\music\storage\album\savana_woman\Savannah_Woman_320.mp3");

    if audio_file_path.is_file() {
        let bytes = std::fs::read(audio_file_path).expect("Failed to read Savannah_Woman_320.mp3");
        assert_eq!(bytes.len(), 7_256_859, "Savannah_Woman_320.mp3 file size mismatch");

        let identity = FileIdentity::new(
            "mp3",
            "audio/mpeg",
            FileCategory::Audio,
            "MP3 audio file",
            false,
            1.0,
            quorum_classifier::ClassifierEngine::HeaderInspection,
        );

        let metadata = AudioIndexer::extract_metadata(audio_file_path, &bytes, &identity);

        assert_eq!(metadata.format_name, "MP3");
        assert_eq!(metadata.bitrate_kbps, 320, "Expected 320 kbps bitrate");
        assert_eq!(metadata.sample_rate_hz, 44100, "Expected 44100 Hz sample rate");
        assert_eq!(metadata.channels, 2);
        assert_eq!(metadata.channel_mode, "Stereo");
        assert!(
            metadata.duration_secs >= 180.0 && metadata.duration_secs <= 183.0,
            "Expected duration ~181s, got {:.2}s",
            metadata.duration_secs
        );
    }
}
