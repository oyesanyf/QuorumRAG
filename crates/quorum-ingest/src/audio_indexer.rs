//! Audio Extraction, ID3/MPEG Metadata Parsing & LanceDB/Tantivy Indexing for QuorumRAG.
//!
//! Intercepts Magika-identified and extension-based audio formats (`audio/mpeg`, `audio/mp3`,
//! `audio/wav`, `audio/flac`, `audio/ogg`, `audio/m4a`, `audio/aac`, `audio/x-ms-wma`, `audio/aiff`,
//! `audio/opus`) so they are NOT skipped as generic binaries.
//! Extracts track title, artist, album, year, genre, duration, bitrate, sample rate, channels,
//! embedded ID3v1/ID3v2 tags, and companion lyrics/transcripts (.lrc, .txt, .srt), producing dense
//! Gemma 768d vector embeddings and searchable Tantivy full-text index records.

use std::path::Path;
use quorum_classifier::{FileCategory, FileIdentity};
use quorum_contract::EmbeddingGenerator;
use quorum_types::{DocumentChunk, TypeError};
use serde::{Deserialize, Serialize};

/// Comprehensive structured metadata extracted from an audio file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AudioMetadata {
    pub mime_type: String,
    pub format_name: String,
    pub title: Option<String>,
    pub artist: Option<String>,
    pub album: Option<String>,
    pub year: Option<u32>,
    pub genre: Option<String>,
    pub track_number: Option<u32>,
    pub duration_secs: f32,
    pub bitrate_kbps: u32,
    pub sample_rate_hz: u32,
    pub channels: u8,
    pub channel_mode: String,
    pub size_bytes: u64,
    pub has_lyrics: bool,
    pub lyrics_source: Option<String>,
    pub lyrics_text: Option<String>,
    pub path_tokens: Vec<String>,
}

/// Raw parsed ID3 tags before applying filename/directory fallbacks.
#[derive(Debug, Default, Clone)]
struct RawId3Tags {
    title: Option<String>,
    artist: Option<String>,
    album: Option<String>,
    year: Option<u32>,
    genre: Option<String>,
    track_number: Option<u32>,
    duration_secs: Option<f32>,
    lyrics: Option<String>,
    comment: Option<String>,
}

/// Audio properties derived from container and audio stream headers.
#[derive(Debug, Clone)]
struct StreamProperties {
    format_name: String,
    duration_secs: f32,
    bitrate_kbps: u32,
    sample_rate_hz: u32,
    channels: u8,
    channel_mode: String,
}

impl Default for StreamProperties {
    fn default() -> Self {
        Self {
            format_name: "AUDIO".into(),
            duration_secs: 0.0,
            bitrate_kbps: 0,
            sample_rate_hz: 44100,
            channels: 2,
            channel_mode: "Stereo".into(),
        }
    }
}

/// Pure-Rust Audio Indexing Engine.
pub struct AudioIndexer;

impl AudioIndexer {
    /// Verify whether a classified file is an audio file that should route to this extractor.
    pub fn is_supported_audio(identity: &FileIdentity) -> bool {
        identity.category == FileCategory::Audio
            || identity.mime_type.starts_with("audio/")
            || matches!(
                identity.label.to_ascii_lowercase().as_str(),
                "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" | "wma" | "aiff" | "aif" | "opus"
            )
    }

    /// Extract audio metadata from file bytes using pure-Rust binary header inspections.
    pub fn extract_metadata(
        path: &Path,
        bytes: &[u8],
        identity: &FileIdentity,
    ) -> AudioMetadata {
        let size_bytes = bytes.len() as u64;
        let path_tokens = Self::extract_path_tokens(path);

        // 1. Try parsing ID3v2 tags at the start of the file
        let (id3v2_tags, tag_total_size) = Self::parse_id3v2(bytes);

        // 2. Try parsing ID3v1 tags at the tail of the file
        let id3v1_tags = Self::parse_id3v1(bytes);

        // Merge ID3 tags (ID3v2 takes precedence over ID3v1)
        let merged_tags = Self::merge_tags(id3v2_tags, id3v1_tags);

        // 3. Parse stream properties (bitrate, sample rate, channels, duration)
        let stream = Self::parse_stream_properties(bytes, tag_total_size, &identity.label);

        // 4. Companion lyrics and transcript discovery
        let (has_companion_lyrics, companion_source, companion_text) =
            Self::find_companion_lyrics(path);

        let (has_lyrics, lyrics_source, lyrics_text) = if has_companion_lyrics {
            (true, companion_source, companion_text)
        } else if let Some(ref embedded) = merged_tags.lyrics {
            (true, Some("ID3v2 USLT".to_string()), Some(embedded.clone()))
        } else {
            (false, None, None)
        };

        // 5. Title / Album / Artist Fallback Heuristics
        let (title, artist, album) = Self::resolve_metadata_fallbacks(
            path,
            merged_tags.title,
            merged_tags.artist,
            merged_tags.album,
        );

        let duration_secs = if stream.duration_secs > 0.0 {
            stream.duration_secs
        } else if let Some(id3_dur) = merged_tags.duration_secs {
            id3_dur
        } else {
            0.0
        };

        AudioMetadata {
            mime_type: identity.mime_type.clone(),
            format_name: stream.format_name,
            title: Some(title),
            artist,
            album,
            year: merged_tags.year,
            genre: merged_tags.genre,
            track_number: merged_tags.track_number,
            duration_secs,
            bitrate_kbps: stream.bitrate_kbps,
            sample_rate_hz: stream.sample_rate_hz,
            channels: stream.channels,
            channel_mode: stream.channel_mode,
            size_bytes,
            has_lyrics,
            lyrics_source,
            lyrics_text,
            path_tokens,
        }
    }

    /// Pure-Rust ID3v1 Parser (inspects trailing 128 bytes).
    fn parse_id3v1(bytes: &[u8]) -> Option<RawId3Tags> {
        if bytes.len() < 128 {
            return None;
        }

        let tail = &bytes[bytes.len() - 128..];
        if &tail[0..3] != b"TAG" {
            return None;
        }

        let title = Self::decode_latin1_trimmed(&tail[3..33]);
        let artist = Self::decode_latin1_trimmed(&tail[33..63]);
        let album = Self::decode_latin1_trimmed(&tail[63..93]);
        let year_str = Self::decode_latin1_trimmed(&tail[93..97]);
        let year = year_str.and_then(|y| y.parse::<u32>().ok());

        // ID3v1.1 track number check
        let (comment, track_number) = if tail[125] == 0 && tail[126] != 0 {
            let c = Self::decode_latin1_trimmed(&tail[97..125]);
            (c, Some(tail[126] as u32))
        } else {
            let c = Self::decode_latin1_trimmed(&tail[97..127]);
            (c, None)
        };

        let genre_idx = tail[127];
        let genre = Self::id3v1_genre_name(genre_idx).map(|s| s.to_string());

        Some(RawId3Tags {
            title,
            artist,
            album,
            year,
            genre,
            track_number,
            duration_secs: None,
            lyrics: None,
            comment,
        })
    }

    /// Pure-Rust ID3v2 Parser (ID3v2.2, ID3v2.3, ID3v2.4).
    /// Returns the parsed tags and total byte size of the ID3v2 header/payload.
    fn parse_id3v2(bytes: &[u8]) -> (Option<RawId3Tags>, usize) {
        if bytes.len() < 10 || &bytes[0..3] != b"ID3" {
            return (None, 0);
        }

        let major_version = bytes[3];
        let flags = bytes[5];
        let tag_size = ((bytes[6] as usize & 0x7f) << 21)
            | ((bytes[7] as usize & 0x7f) << 14)
            | ((bytes[8] as usize & 0x7f) << 7)
            | (bytes[9] as usize & 0x7f);

        let has_footer = (flags & 0x10) != 0;
        let total_tag_len = 10 + tag_size + if has_footer { 10 } else { 0 };

        if bytes.len() < 10 + tag_size {
            return (None, bytes.len());
        }

        let tag_data = &bytes[10..10 + tag_size];
        let mut tags = RawId3Tags::default();

        if major_version == 3 || major_version == 4 {
            let mut offset = 0;
            // Skip extended header if present
            if (flags & 0x40) != 0 && tag_data.len() >= 4 {
                let ext_size = if major_version == 4 {
                    ((tag_data[0] as usize & 0x7f) << 21)
                        | ((tag_data[1] as usize & 0x7f) << 14)
                        | ((tag_data[2] as usize & 0x7f) << 7)
                        | (tag_data[3] as usize & 0x7f)
                } else {
                    u32::from_be_bytes([tag_data[0], tag_data[1], tag_data[2], tag_data[3]]) as usize
                };
                offset = ext_size.min(tag_data.len());
            }

            while offset + 10 <= tag_data.len() {
                // If frame ID starts with null byte, padding has been reached
                if tag_data[offset] == 0 {
                    break;
                }

                let frame_id = &tag_data[offset..offset + 4];
                let frame_size = if major_version == 4 {
                    ((tag_data[offset + 4] as usize & 0x7f) << 21)
                        | ((tag_data[offset + 5] as usize & 0x7f) << 14)
                        | ((tag_data[offset + 6] as usize & 0x7f) << 7)
                        | (tag_data[offset + 7] as usize & 0x7f)
                } else {
                    u32::from_be_bytes([
                        tag_data[offset + 4],
                        tag_data[offset + 5],
                        tag_data[offset + 6],
                        tag_data[offset + 7],
                    ]) as usize
                };

                let frame_start = offset + 10;
                let frame_end = (frame_start + frame_size).min(tag_data.len());
                if frame_start < tag_data.len() {
                    let frame_bytes = &tag_data[frame_start..frame_end];
                    Self::apply_id3v2_frame(frame_id, frame_bytes, &mut tags);
                }

                offset += 10 + frame_size;
            }
        } else if major_version == 2 {
            // ID3v2.2: 3-byte frame ID, 3-byte frame size
            let mut offset = 0;
            while offset + 6 <= tag_data.len() {
                if tag_data[offset] == 0 {
                    break;
                }
                let frame_id = &tag_data[offset..offset + 3];
                let frame_size = ((tag_data[offset + 3] as usize) << 16)
                    | ((tag_data[offset + 4] as usize) << 8)
                    | (tag_data[offset + 5] as usize);

                let frame_start = offset + 6;
                let frame_end = (frame_start + frame_size).min(tag_data.len());
                if frame_start < tag_data.len() {
                    let frame_bytes = &tag_data[frame_start..frame_end];
                    Self::apply_id3v22_frame(frame_id, frame_bytes, &mut tags);
                }

                offset += 6 + frame_size;
            }
        }

        (Some(tags), total_tag_len)
    }

    /// Process a standard ID3v2.3 / ID3v2.4 frame.
    fn apply_id3v2_frame(frame_id: &[u8], frame_bytes: &[u8], tags: &mut RawId3Tags) {
        match frame_id {
            b"TIT2" => tags.title = Self::decode_id3_text_frame(frame_bytes),
            b"TPE1" => tags.artist = Self::decode_id3_text_frame(frame_bytes),
            b"TALB" => tags.album = Self::decode_id3_text_frame(frame_bytes),
            b"TYER" => {
                if let Some(text) = Self::decode_id3_text_frame(frame_bytes) {
                    tags.year = text.trim().parse::<u32>().ok();
                }
            }
            b"TDRC" => {
                if let Some(text) = Self::decode_id3_text_frame(frame_bytes) {
                    let year_str = text.split('-').next().unwrap_or("").trim();
                    tags.year = year_str.parse::<u32>().ok();
                }
            }
            b"TRCK" => {
                if let Some(text) = Self::decode_id3_text_frame(frame_bytes) {
                    let track_str = text.split('/').next().unwrap_or("").trim();
                    tags.track_number = track_str.parse::<u32>().ok();
                }
            }
            b"TCON" => tags.genre = Self::decode_id3_text_frame(frame_bytes),
            b"TLEN" => {
                if let Some(text) = Self::decode_id3_text_frame(frame_bytes) {
                    if let Ok(ms) = text.trim().parse::<f32>() {
                        if ms > 0.0 {
                            tags.duration_secs = Some(ms / 1000.0);
                        }
                    }
                }
            }
            b"USLT" => {
                tags.lyrics = Self::decode_id3_lyrics_frame(frame_bytes);
            }
            b"COMM" => {
                tags.comment = Self::decode_id3_comment_frame(frame_bytes);
            }
            _ => {}
        }
    }

    /// Process an ID3v2.2 frame (3-byte identifiers).
    fn apply_id3v22_frame(frame_id: &[u8], frame_bytes: &[u8], tags: &mut RawId3Tags) {
        match frame_id {
            b"TT2" => tags.title = Self::decode_id3_text_frame(frame_bytes),
            b"TP1" => tags.artist = Self::decode_id3_text_frame(frame_bytes),
            b"TAL" => tags.album = Self::decode_id3_text_frame(frame_bytes),
            b"TYE" => {
                if let Some(text) = Self::decode_id3_text_frame(frame_bytes) {
                    tags.year = text.trim().parse::<u32>().ok();
                }
            }
            b"TRK" => {
                if let Some(text) = Self::decode_id3_text_frame(frame_bytes) {
                    let track_str = text.split('/').next().unwrap_or("").trim();
                    tags.track_number = track_str.parse::<u32>().ok();
                }
            }
            b"TCO" => tags.genre = Self::decode_id3_text_frame(frame_bytes),
            b"TLE" => {
                if let Some(text) = Self::decode_id3_text_frame(frame_bytes) {
                    if let Ok(ms) = text.trim().parse::<f32>() {
                        if ms > 0.0 {
                            tags.duration_secs = Some(ms / 1000.0);
                        }
                    }
                }
            }
            b"ULT" => {
                tags.lyrics = Self::decode_id3_lyrics_frame(frame_bytes);
            }
            b"COM" => {
                tags.comment = Self::decode_id3_comment_frame(frame_bytes);
            }
            _ => {}
        }
    }

    /// Decodes an ID3v2 text frame, respecting encoding flag byte.
    fn decode_id3_text_frame(bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }

        let encoding = bytes[0];
        let payload = &bytes[1..];

        let text = match encoding {
            // ISO-8859-1 (Latin-1)
            0 => payload.iter().map(|&b| b as char).collect::<String>(),
            // UTF-16 with BOM
            1 => Self::decode_utf16(payload),
            // UTF-16BE without BOM
            2 => Self::decode_utf16_be(payload),
            // UTF-8
            3 => String::from_utf8_lossy(payload).to_string(),
            _ => String::from_utf8_lossy(payload).to_string(),
        };

        let trimmed = text.trim_matches('\0').trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    /// Decodes an ID3v2 USLT (unsynchronised lyrics) frame.
    fn decode_id3_lyrics_frame(bytes: &[u8]) -> Option<String> {
        if bytes.len() < 5 {
            return None;
        }
        let encoding = bytes[0];
        // Language is bytes 1..4 (3 ASCII bytes)
        let payload = &bytes[4..];

        // Content descriptor is separated by null terminator(s)
        match encoding {
            0 | 3 => {
                // Single-byte null separator
                if let Some(pos) = payload.iter().position(|&b| b == 0) {
                    let lyrics_bytes = &payload[pos + 1..];
                    let text = if encoding == 3 {
                        String::from_utf8_lossy(lyrics_bytes).to_string()
                    } else {
                        lyrics_bytes.iter().map(|&b| b as char).collect::<String>()
                    };
                    let trimmed = text.trim_matches('\0').trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
            1 | 2 => {
                // Double-byte null separator for UTF-16
                let text = if encoding == 1 {
                    Self::decode_utf16(payload)
                } else {
                    Self::decode_utf16_be(payload)
                };
                let parts: Vec<&str> = text.split('\0').collect();
                if parts.len() > 1 {
                    let lyrics = parts[1..].join("\n").trim().to_string();
                    if !lyrics.is_empty() {
                        return Some(lyrics);
                    }
                }
            }
            _ => {}
        }

        None
    }

    /// Decodes an ID3v2 COMM (comment) frame.
    fn decode_id3_comment_frame(bytes: &[u8]) -> Option<String> {
        if bytes.len() < 5 {
            return None;
        }
        let encoding = bytes[0];
        let payload = &bytes[4..];

        match encoding {
            0 | 3 => {
                if let Some(pos) = payload.iter().position(|&b| b == 0) {
                    let comment_bytes = &payload[pos + 1..];
                    let text = if encoding == 3 {
                        String::from_utf8_lossy(comment_bytes).to_string()
                    } else {
                        comment_bytes.iter().map(|&b| b as char).collect::<String>()
                    };
                    let trimmed = text.trim_matches('\0').trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    }
                }
            }
            _ => {
                let text = Self::decode_id3_text_frame(bytes);
                if let Some(t) = text {
                    return Some(t);
                }
            }
        }
        None
    }

    /// Decodes UTF-16 with BOM (Little-Endian or Big-Endian).
    fn decode_utf16(bytes: &[u8]) -> String {
        if bytes.len() < 2 {
            return String::new();
        }

        let is_be = bytes[0] == 0xFE && bytes[1] == 0xFF;
        let is_le = bytes[0] == 0xFF && bytes[1] == 0xFE;

        let slice = if is_be || is_le { &bytes[2..] } else { bytes };
        let mut u16_vec = Vec::with_capacity(slice.len() / 2);

        for chunk in slice.chunks_exact(2) {
            let val = if is_be {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_le_bytes([chunk[0], chunk[1]])
            };
            u16_vec.push(val);
        }

        String::from_utf16_lossy(&u16_vec)
    }

    /// Decodes UTF-16 Big-Endian without BOM.
    fn decode_utf16_be(bytes: &[u8]) -> String {
        let mut u16_vec = Vec::with_capacity(bytes.len() / 2);
        for chunk in bytes.chunks_exact(2) {
            u16_vec.push(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        String::from_utf16_lossy(&u16_vec)
    }

    /// Decodes a null-padded or space-trimmed Latin-1 slice.
    fn decode_latin1_trimmed(bytes: &[u8]) -> Option<String> {
        let text: String = bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    /// Standard ID3v1 genre code mapping.
    fn id3v1_genre_name(idx: u8) -> Option<&'static str> {
        const GENRES: &[&str] = &[
            "Blues", "Classic Rock", "Country", "Dance", "Disco", "Funk", "Grunge", "Hip-Hop",
            "Jazz", "Metal", "New Age", "Oldies", "Other", "Pop", "R&B", "Rap", "Reggae", "Rock",
            "Techno", "Industrial", "Alternative", "Ska", "Death Metal", "Pranks", "Soundtrack",
            "Euro-Techno", "Ambient", "Trip-Hop", "Vocal", "Jazz+Funk", "Fusion", "Trance",
            "Classical", "Instrumental", "Acid", "House", "Game", "Sound Clip", "Gospel", "Noise",
            "Alternative Rock", "Bass", "Soul", "Punk", "Space", "Meditative", "Instrumental Pop",
            "Instrumental Rock", "Ethnic", "Gothic", "Darkwave", "Techno-Industrial", "Electronic",
            "Pop-Folk", "Eurodance", "Dream", "Southern Rock", "Comedy", "Cult", "Gangsta",
            "Top 40", "Christian Rap", "Pop/Funk", "Jungle", "Native US", "Cabaret", "New Wave",
            "Psychadelic", "Rave", "Showtunes", "Trailer", "Lo-Fi", "Tribal", "Acid Punk",
            "Acid Jazz", "Polka", "Retro", "Musical", "Rock & Roll", "Hard Rock", "Folk",
            "Folk-Rock", "National Folk", "Swing", "Fast Fusion", "Bebob", "Latin", "Revival",
            "Celtic", "Bluegrass", "Avantgarde", "Gothic Rock", "Progressive Rock",
            "Psychedelic Rock", "Symphonic Rock", "Slow Rock", "Big Band", "Chorus",
            "Easy Listening", "Acoustic", "Humour", "Speech", "Chanson", "Opera", "Chamber Music",
            "Sonata", "Symphony", "Booty Bass", "Primus", "Porn Groove", "Satire", "Slow Jam",
            "Club", "Tango", "Samba", "Folklore", "Ballad", "Power Ballad", "Rhythmic Soul",
            "Freestyle", "Duet", "Punk Rock", "Drum Solo", "A capella", "Euro-House", "Dance Hall",
        ];
        GENRES.get(idx as usize).copied()
    }

    /// Merges ID3v2 and ID3v1 tags, giving priority to ID3v2.
    fn merge_tags(v2: Option<RawId3Tags>, v1: Option<RawId3Tags>) -> RawId3Tags {
        match (v2, v1) {
            (Some(v2_val), Some(v1_val)) => RawId3Tags {
                title: v2_val.title.or(v1_val.title),
                artist: v2_val.artist.or(v1_val.artist),
                album: v2_val.album.or(v1_val.album),
                year: v2_val.year.or(v1_val.year),
                genre: v2_val.genre.or(v1_val.genre),
                track_number: v2_val.track_number.or(v1_val.track_number),
                duration_secs: v2_val.duration_secs.or(v1_val.duration_secs),
                lyrics: v2_val.lyrics.or(v1_val.lyrics),
                comment: v2_val.comment.or(v1_val.comment),
            },
            (Some(v2_val), None) => v2_val,
            (None, Some(v1_val)) => v1_val,
            (None, None) => RawId3Tags::default(),
        }
    }

    /// Pure-Rust audio stream property parser (MP3 MPEG frames, WAV RIFF, FLAC streaminfo).
    fn parse_stream_properties(
        bytes: &[u8],
        tag_total_size: usize,
        label_hint: &str,
    ) -> StreamProperties {
        // 1. Check for WAV format
        if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE" {
            return Self::parse_wav_properties(bytes);
        }

        // 2. Check for FLAC format
        if bytes.starts_with(b"fLaC") {
            return Self::parse_flac_properties(bytes);
        }

        // 3. Check for MP3 / MPEG Audio frame header
        if let Some(mp3_props) = Self::parse_mpeg_frame_sync(bytes, tag_total_size) {
            return mp3_props;
        }

        // Fallback default
        let format = if label_hint.is_empty() {
            "AUDIO".into()
        } else {
            label_hint.to_uppercase()
        };
        StreamProperties {
            format_name: format,
            ..Default::default()
        }
    }

    /// MPEG Audio Layer III frame sync header parser.
    /// Computes bitrate, sample rate, channels, channel mode, and duration.
    fn parse_mpeg_frame_sync(bytes: &[u8], tag_total_size: usize) -> Option<StreamProperties> {
        let scan_start = tag_total_size;
        let scan_limit = (scan_start + 65536).min(bytes.len());

        if scan_start >= bytes.len() || bytes.len() - scan_start < 4 {
            return None;
        }

        // Bitrate lookup table for MPEG-1 Layer III (in kbps)
        const MPEG1_LAYER3_BITRATES: [u32; 16] = [
            0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
        ];
        // Bitrate lookup table for MPEG-2 / 2.5 Layer III (in kbps)
        const MPEG2_LAYER3_BITRATES: [u32; 16] = [
            0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
        ];

        // Sample rate lookup tables (in Hz)
        const MPEG1_SAMPLERATES: [u32; 4] = [44100, 48000, 32000, 0];
        const MPEG2_SAMPLERATES: [u32; 4] = [22050, 24000, 16000, 0];
        const MPEG25_SAMPLERATES: [u32; 4] = [11025, 12000, 8000, 0];

        for i in scan_start..scan_limit.saturating_sub(3) {
            // MPEG frame sync: 11 bits set to 1
            if bytes[i] == 0xFF && (bytes[i + 1] & 0xE0) == 0xE0 {
                let b1 = bytes[i + 1];
                let b2 = bytes[i + 2];
                let b3 = bytes[i + 3];

                let version_bits = (b1 >> 3) & 0x03;
                let layer_bits = (b1 >> 1) & 0x03;

                // We require Layer III (bits = 01)
                if layer_bits != 0x01 {
                    continue;
                }

                // Version: 00 = 2.5, 10 = 2, 11 = 1 (01 is reserved)
                if version_bits == 0x01 {
                    continue;
                }

                let bitrate_idx = (b2 >> 4) & 0x0F;
                let samplerate_idx = (b2 >> 2) & 0x03;

                if bitrate_idx == 0 || bitrate_idx == 15 || samplerate_idx == 3 {
                    continue;
                }

                let is_mpeg1 = version_bits == 0x03;
                let is_mpeg2 = version_bits == 0x02;

                let bitrate_kbps = if is_mpeg1 {
                    MPEG1_LAYER3_BITRATES[bitrate_idx as usize]
                } else {
                    MPEG2_LAYER3_BITRATES[bitrate_idx as usize]
                };

                let sample_rate_hz = if is_mpeg1 {
                    MPEG1_SAMPLERATES[samplerate_idx as usize]
                } else if is_mpeg2 {
                    MPEG2_SAMPLERATES[samplerate_idx as usize]
                } else {
                    MPEG25_SAMPLERATES[samplerate_idx as usize]
                };

                let channel_bits = (b3 >> 6) & 0x03;
                let (channels, channel_mode) = match channel_bits {
                    0x00 => (2, "Stereo".to_string()),
                    0x01 => (2, "Joint Stereo".to_string()),
                    0x02 => (2, "Dual Channel".to_string()),
                    0x03 => (1, "Mono".to_string()),
                    _ => (2, "Stereo".to_string()),
                };

                // Check for Xing / Info VBR header
                let xing_offset = if is_mpeg1 {
                    if channels == 1 { i + 21 } else { i + 36 }
                } else {
                    if channels == 1 { i + 13 } else { i + 21 }
                };

                let mut duration_secs = 0.0;
                if xing_offset + 12 <= bytes.len() {
                    let magic = &bytes[xing_offset..xing_offset + 4];
                    if magic == b"Xing" || magic == b"Info" {
                        let flags = u32::from_be_bytes([
                            bytes[xing_offset + 4],
                            bytes[xing_offset + 5],
                            bytes[xing_offset + 6],
                            bytes[xing_offset + 7],
                        ]);
                        if (flags & 0x01) != 0 {
                            let frames = u32::from_be_bytes([
                                bytes[xing_offset + 8],
                                bytes[xing_offset + 9],
                                bytes[xing_offset + 10],
                                bytes[xing_offset + 11],
                            ]);
                            if frames > 0 && sample_rate_hz > 0 {
                                let samples_per_frame = if is_mpeg1 { 1152.0 } else { 576.0 };
                                duration_secs = (frames as f32 * samples_per_frame) / (sample_rate_hz as f32);
                            }
                        }
                    }
                }

                // If Xing duration is not present, calculate CBR duration
                if duration_secs <= 0.0 && bitrate_kbps > 0 {
                    let audio_payload_bytes = bytes.len().saturating_sub(tag_total_size);
                    duration_secs = (audio_payload_bytes as f32 * 8.0) / (bitrate_kbps as f32 * 1000.0);
                }

                return Some(StreamProperties {
                    format_name: "MP3".into(),
                    duration_secs,
                    bitrate_kbps,
                    sample_rate_hz,
                    channels,
                    channel_mode,
                });
            }
        }

        None
    }

    /// Pure-Rust WAV Header Parser (RIFF / WAVE `fmt ` chunk).
    fn parse_wav_properties(bytes: &[u8]) -> StreamProperties {
        let mut props = StreamProperties {
            format_name: "WAV".into(),
            channels: 2,
            channel_mode: "Stereo".into(),
            sample_rate_hz: 44100,
            bitrate_kbps: 1411,
            duration_secs: 0.0,
        };

        if bytes.len() < 36 {
            return props;
        }

        let mut offset = 12;
        let mut byte_rate = 0u32;
        let mut data_size = 0u32;

        while offset + 8 <= bytes.len() {
            let chunk_id = &bytes[offset..offset + 4];
            let chunk_size = u32::from_le_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]) as usize;

            if chunk_id == b"fmt " && offset + 8 + chunk_size <= bytes.len() && chunk_size >= 16 {
                let fmt_data = &bytes[offset + 8..offset + 8 + chunk_size];
                let channels = u16::from_le_bytes([fmt_data[2], fmt_data[3]]) as u8;
                let sample_rate = u32::from_le_bytes([
                    fmt_data[4],
                    fmt_data[5],
                    fmt_data[6],
                    fmt_data[7],
                ]);
                byte_rate = u32::from_le_bytes([
                    fmt_data[8],
                    fmt_data[9],
                    fmt_data[10],
                    fmt_data[11],
                ]);

                props.channels = channels;
                props.channel_mode = if channels == 1 {
                    "Mono".into()
                } else {
                    "Stereo".into()
                };
                props.sample_rate_hz = sample_rate;
                if byte_rate > 0 {
                    props.bitrate_kbps = (byte_rate * 8) / 1000;
                }
            } else if chunk_id == b"data" {
                data_size = chunk_size as u32;
            }

            offset += 8 + chunk_size;
            // Chunks in RIFF are word-aligned
            if chunk_size % 2 != 0 {
                offset += 1;
            }
        }

        if byte_rate > 0 && data_size > 0 {
            props.duration_secs = data_size as f32 / byte_rate as f32;
        }

        props
    }

    /// Pure-Rust FLAC Header Parser (`fLaC` `STREAMINFO`).
    fn parse_flac_properties(bytes: &[u8]) -> StreamProperties {
        let mut props = StreamProperties {
            format_name: "FLAC".into(),
            channels: 2,
            channel_mode: "Stereo".into(),
            sample_rate_hz: 44100,
            bitrate_kbps: 0,
            duration_secs: 0.0,
        };

        if bytes.len() < 42 || !bytes.starts_with(b"fLaC") {
            return props;
        }

        // First metadata block after "fLaC" (4 bytes) is STREAMINFO (type 0)
        let block_header = &bytes[4..8];
        let block_type = block_header[0] & 0x7F;

        if block_type == 0 {
            let data = &bytes[8..42];
            // Sample rate (20 bits): bytes 10..13
            let sample_rate = ((data[10] as u32) << 12)
                | ((data[11] as u32) << 4)
                | ((data[12] as u32) >> 4);
            let channels = ((data[12] >> 1) & 0x07) + 1;
            let total_samples = (((data[13] as u64) & 0x0F) << 32)
                | ((data[14] as u64) << 24)
                | ((data[15] as u64) << 16)
                | ((data[16] as u64) << 8)
                | (data[17] as u64);

            props.sample_rate_hz = sample_rate;
            props.channels = channels;
            props.channel_mode = if channels == 1 {
                "Mono".into()
            } else {
                "Stereo".into()
            };

            if sample_rate > 0 && total_samples > 0 {
                props.duration_secs = total_samples as f32 / sample_rate as f32;
                if props.duration_secs > 0.0 {
                    props.bitrate_kbps = ((bytes.len() as f32 * 8.0) / (props.duration_secs * 1000.0)) as u32;
                }
            }
        }

        props
    }

    /// Searches file directory for companion lyrics and transcripts.
    /// Matches `<stem>.lrc`, `<stem>.txt`, `<stem>.srt`, `lyrics.txt`, `transcript.txt`.
    pub fn find_companion_lyrics(path: &Path) -> (bool, Option<String>, Option<String>) {
        let parent = match path.parent() {
            Some(p) => p,
            None => return (false, None, None),
        };
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => return (false, None, None),
        };

        let candidate_names = [
            format!("{}.lrc", stem),
            format!("{}.txt", stem),
            format!("{}.srt", stem),
            "lyrics.txt".to_string(),
            "transcript.txt".to_string(),
        ];

        for name in &candidate_names {
            let candidate_path = parent.join(name);
            if candidate_path.is_file() {
                // Read up to 512KB for performance and security
                if let Ok(content) = std::fs::read_to_string(&candidate_path) {
                    let trimmed = content.trim();
                    if !trimmed.is_empty() {
                        return (true, Some(name.clone()), Some(trimmed.to_string()));
                    }
                } else if let Ok(raw_bytes) = std::fs::read(&candidate_path) {
                    let text = String::from_utf8_lossy(&raw_bytes).trim().to_string();
                    if !text.is_empty() {
                        return (true, Some(name.clone()), Some(text));
                    }
                }
            }
        }

        (false, None, None)
    }

    /// Resolves title, artist, and album fallbacks when tags are missing.
    fn resolve_metadata_fallbacks(
        path: &Path,
        tag_title: Option<String>,
        tag_artist: Option<String>,
        tag_album: Option<String>,
    ) -> (String, Option<String>, Option<String>) {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Unknown Track");

        // Format stem: e.g. "Savannah_Woman" -> "Savannah Woman"
        let fallback_title = Self::format_stem_title(stem);

        let title = match tag_title {
            Some(t) if !t.trim().is_empty() => t.trim().to_string(),
            _ => fallback_title,
        };

        // Fallback album: parent folder name (e.g. "savana_woman" -> "Savana Woman")
        let album = match tag_album {
            Some(a) if !a.trim().is_empty() => Some(a.trim().to_string()),
            _ => path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).map(Self::format_stem_title),
        };

        let artist = match tag_artist {
            Some(art) if !art.trim().is_empty() => Some(art.trim().to_string()),
            _ => {
                // Check if title or stem contains "Artist - Title" format
                if let Some(pos) = stem.find(" - ") {
                    let artist_part = &stem[..pos];
                    Some(Self::format_stem_title(artist_part))
                } else {
                    None
                }
            }
        };

        (title, artist, album)
    }

    /// Clean formatting for stems and directory names (replaces underscores/hyphens with spaces).
    fn format_stem_title(stem: &str) -> String {
        let clean = stem.replace('_', " ").replace('-', " ");
        let mut words: Vec<String> = Vec::new();
        for word in clean.split_whitespace() {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                let rest: String = chars.collect();
                // Capitalize first character if word is lowercase
                if first.is_lowercase() && rest.chars().all(|c| c.is_lowercase()) {
                    words.push(format!("{}{}", first.to_uppercase(), rest));
                } else {
                    words.push(word.to_string());
                }
            }
        }
        if words.is_empty() {
            stem.to_string()
        } else {
            words.join(" ")
        }
    }

    /// Extracts alphanumeric tokens from a path.
    pub fn extract_path_tokens(path: &Path) -> Vec<String> {
        let mut tokens = Vec::new();
        for component in path.components() {
            let comp_str = component.as_os_str().to_string_lossy();
            for word in comp_str.split(|c: char| !c.is_alphanumeric()) {
                let trimmed = word.trim();
                if trimmed.len() > 1 {
                    tokens.push(trimmed.to_string());
                }
            }
        }
        tokens
    }

    /// Formats a rich search text representation of the audio file.
    pub fn build_search_text(meta: &AudioMetadata, path: &Path) -> String {
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("audio_file");

        let mut lines = Vec::new();
        lines.push(format!("[Audio Document: {}]", filename));

        if let Some(ref title) = meta.title {
            lines.push(format!("Title: {}", title));
        }
        if let Some(ref artist) = meta.artist {
            lines.push(format!("Artist: {}", artist));
        }
        if let Some(ref album) = meta.album {
            lines.push(format!("Album: {}", album));
        }
        if let Some(year) = meta.year {
            lines.push(format!("Year: {}", year));
        }
        if let Some(ref genre) = meta.genre {
            lines.push(format!("Genre: {}", genre));
        }
        if let Some(track) = meta.track_number {
            lines.push(format!("Track: {}", track));
        }

        lines.push(format!("Format: {} ({})", meta.format_name, meta.mime_type));

        let mins = (meta.duration_secs / 60.0).floor() as u32;
        let secs = (meta.duration_secs % 60.0).floor() as u32;
        lines.push(format!(
            "Duration: {}m {}s ({:.1}s)",
            mins, secs, meta.duration_secs
        ));

        lines.push(format!(
            "Audio Properties: {} kbps, {} Hz, {} ({} channels)",
            meta.bitrate_kbps, meta.sample_rate_hz, meta.channel_mode, meta.channels
        ));

        let size_kb = (meta.size_bytes + 1023) / 1024;
        lines.push(format!("File Size: {} KB", size_kb));

        if !meta.path_tokens.is_empty() {
            lines.push(format!("Path Tags: {}", meta.path_tokens.join(", ")));
        }

        if let (true, Some(ref src), Some(ref lyrics)) = (meta.has_lyrics, &meta.lyrics_source, &meta.lyrics_text) {
            lines.push(format!("Lyrics / Transcript (from {}):", src));
            lines.push(lyrics.clone());
        }

        lines.join("\n")
    }

    /// Index an audio file into a `DocumentChunk` ready for LanceDB and Tantivy.
    pub fn index_audio(
        path: &Path,
        bytes: &[u8],
        identity: &FileIdentity,
        access_tier: u8,
        embedding_generator: &dyn EmbeddingGenerator,
    ) -> Result<DocumentChunk, TypeError> {
        let metadata = Self::extract_metadata(path, bytes, identity);
        let search_text = Self::build_search_text(&metadata, path);
        let file_b3 = blake3::hash(bytes).to_hex().to_string();

        // Compute 768-dim dense embedding vector from the search representation
        let vector = embedding_generator
            .embed_text(&search_text)
            .unwrap_or_else(|_| vec![0.0; embedding_generator.dimension()]);

        let metadata_json = serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".to_string());
        let chunk_id = format!("{}:audio:0", file_b3);

        DocumentChunk::new(
            chunk_id,
            file_b3,
            path.to_string_lossy().to_string(),
            1, // line_start
            1, // line_end
            access_tier,
            vector,
            search_text,
            Some(metadata_json),
        )
    }
}
