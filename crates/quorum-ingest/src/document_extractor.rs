//! Universal Magika-Driven Document & Data Extractor for QuorumRAG (`quorum-ingest`).
//!
//! Extracts all searchable text, tables, pages, slides, sheets, schemas, and metadata
//! from every file discovered and accepted by Google Magika (`FileCategory::Document`,
//! `FileCategory::Text`, `FileCategory::Code`, `FileCategory::Data`):
//! - **PDF (`pdf`, `application/pdf`)**: Multi-page text & metadata via `pypdf`, pure-Rust
//!   `/FlateDecode` stream + `/ToUnicode` CMap text extraction (zero Python dependency under
//!   `LocalSystem` service), Vision/OCR fallback for scanned pages, and literal stream fallback.
//! - **Word & OpenDocument (`docx`, `doc`, `odt`, `rtf`, `epub`)**: Native Rust ZIP/OpenXML
//!   (`word/document.xml` paragraphs, tables, `<w:txbxContent>` timeline boxes, `<w:sdt>` content
//!   controls, `<a:t>` DrawingML shapes, headers, and footers), `content.xml`, OLE2 piece table,
//!   EPUB XHTML, and RTF stripping.
//! - **Excel & Spreadsheets (`xlsx`, `xls`, `ods`, `csv`, `tsv`)**: Native Rust OpenXML sheet
//!   shared strings (`xl/sharedStrings.xml`) and cell rows (`xl/worksheets/*.xml`).
//! - **PowerPoint Presentations (`pptx`, `ppt`, `odp`)**: Native Rust slide text runs (`<a:t>`) and speaker notes.
//! - **Jupyter Notebooks (`ipynb`)**: Markdown cells, code cells, and execution text outputs.
//! - **SQLite Databases (`sqlite`, `application/vnd.sqlite3`)**: Native `rusqlite` read-only schemas and text rows.
//! - **Network Captures & Binary Data (`pcap`, `parquet`, etc.)**: Printable strings & header summaries.
//! - **Source Code, Markdown, Markup & Plain Text**: Full UTF-8, UTF-16LE/BE, and Latin-1/CP-1252 decoding.

use crate::error::IngestError;
use crate::image_indexer::ImageIndexer;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use quorum_classifier::{FileCategory, FileIdentity};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Maximum uncompressed bytes extracted from a single ZIP entry or PDF stream (32 MiB anti-zip-bomb guard).
const MAX_DECOMPRESSED_STREAM_BYTES: u64 = 32 * 1024 * 1024;

/// Universal content extractor for every file discovered by Google Magika.
pub struct DocumentExtractor;

impl DocumentExtractor {
    /// Discovers a usable Python 3 interpreter even when running as a `LocalSystem` Windows Service
    /// where user-installed Python paths are absent from `SYSTEM` `PATH`, while skipping Microsoft Store stubs.
    fn resolve_python_binary() -> Option<PathBuf> {
        static PYTHON_BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
        PYTHON_BIN
            .get_or_init(|| {
                let is_usable = |cand: &Path| -> bool {
                    let s = cand.to_string_lossy().to_ascii_lowercase();
                    if s.contains("windowsapps") {
                        return false;
                    }
                    Command::new(cand)
                        .args(["-c", "import sys; sys.exit(0)"])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                };

                for cmd_name in ["python3", "python"] {
                    let p = PathBuf::from(cmd_name);
                    if is_usable(&p) {
                        return Some(p);
                    }
                }

                #[cfg(target_os = "windows")]
                {
                    let mut candidates: Vec<PathBuf> = vec![
                        PathBuf::from(r"C:\ProgramData\QuorumRAG\dlp_venv\Scripts\python.exe"),
                        PathBuf::from(r"C:\ProgramData\QuorumRAG\python\python.exe"),
                    ];
                    for ver in ["313", "312", "311", "310", "39"] {
                        candidates.push(PathBuf::from(format!(r"C:\Python{}\python.exe", ver)));
                        candidates.push(PathBuf::from(format!(
                            r"C:\Program Files\Python{}\python.exe",
                            ver
                        )));
                    }
                    if let Ok(entries) = std::fs::read_dir(r"C:\Users") {
                        for entry in entries.flatten() {
                            let user_dir = entry.path();
                            if !user_dir.is_dir() {
                                continue;
                            }
                            for ver in ["313", "312", "311", "310"] {
                                candidates.push(user_dir.join(format!(
                                    r"AppData\Local\Programs\Python\Python{}\python.exe",
                                    ver
                                )));
                            }
                            candidates.push(user_dir.join(r"anaconda3\python.exe"));
                            candidates.push(user_dir.join(r"miniconda3\python.exe"));
                        }
                    }
                    for cand in candidates {
                        if cand.exists() && is_usable(&cand) {
                            return Some(cand);
                        }
                    }
                }

                #[cfg(not(target_os = "windows"))]
                {
                    for cand_str in [
                        "/opt/homebrew/bin/python3",
                        "/usr/local/bin/python3",
                        "/usr/bin/python3",
                    ] {
                        let cand = PathBuf::from(cand_str);
                        if cand.exists() && is_usable(&cand) {
                            return Some(cand);
                        }
                    }
                }

                None
            })
            .clone()
    }

    /// Detects whether an existing stored chunk was produced by a degraded pre-native fallback
    /// (e.g., raw ZIP central directory XML filenames `[Content_Types].xml` / `word/document.xml`
    /// or body-less PDF metadata/URI dictionaries) so startup self-healing re-extracts the file.
    pub fn is_degraded_document_chunk(file_path: &str, text_content: &str) -> bool {
        let lower_path = file_path.to_ascii_lowercase();
        let lower_text = text_content.to_ascii_lowercase();

        if lower_text.contains("[word/document (")
            || lower_text.contains("[spreadsheet —")
            || lower_text.contains("[presentation —")
            || lower_text.contains("[content_types].xml")
            || lower_text.contains("word/document.xml")
            || lower_text.contains("_rels/.rels")
            || lower_text.contains("docprops/core.xml")
            || lower_text.contains("docprops/app.xml")
        {
            return true;
        }

        if lower_path.ends_with(".pdf") {
            let body_alnum: usize = text_content
                .lines()
                .filter(|line| {
                    let t = line.trim_start();
                    !t.starts_with("[Document:")
                        && !t.starts_with("[File:")
                        && !t.starts_with("[PDF Metadata]")
                })
                .flat_map(|line| line.chars())
                .filter(|c| c.is_alphanumeric())
                .count();
            let stem_alnum = Path::new(file_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.chars().filter(|c| c.is_alphanumeric()).count())
                .unwrap_or(0);
            // If the PDF chunk contains almost nothing beyond its filename stem + raw URI/trailer markers
            if body_alnum <= stem_alnum.saturating_add(45)
                || (body_alnum < 160
                    && (lower_text.contains("/flatedecode")
                        || lower_text.contains("endobj")
                        || lower_text.contains("/type /page")))
            {
                return true;
            }
        }

        false
    }

    /// Public entry point for PDF extraction with scanned OCR fallback,
    /// matching the interface contract in `SCOPE.md`.
    pub fn extract_pdf_with_ocr_fallback(path: &Path) -> Result<String, IngestError> {
        Self::extract_pdf_text(path).map_err(IngestError::Io)
    }

    /// Determines whether the extracted text represents a scanned or image-only PDF
    /// where genuine document body text is absent or near-zero (< 10 alphanumeric characters).
    pub fn is_scanned_or_insufficient_text(text: &str) -> bool {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return true;
        }

        // Count alphanumeric characters excluding PDF Metadata headers
        let alnum_count = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("[PDF Metadata]"))
            .flat_map(|line| line.chars())
            .filter(|c| c.is_alphanumeric())
            .count();

        alnum_count < 10
    }

    /// Pure-Rust magic-byte & extension guard excluding compiled executables, shared libraries,
    /// object files, debug symbols, and bytecode (PE/MZ, ELF, Mach-O, Fat Mach-O, WASM, DEX)
    /// even when misnamed as `.txt`, `.md`, or `.pdf`.
    pub fn is_excluded_executable_or_library(header: &[u8], path: &Path) -> bool {
        let file_name_lower = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if matches!(
            ext.as_str(),
            "exe" | "dll" | "sys" | "drv" | "ocx" | "scr" | "cpl" | "efi"
                | "so" | "dylib" | "bundle" | "a" | "lib" | "obj" | "o"
                | "pdb" | "ilk" | "exp" | "wasm" | "pyc" | "pyo" | "pyd"
                | "class" | "dex" | "ko"
        ) || file_name_lower.contains(".so.")
        {
            return true;
        }

        if header.len() >= 4 {
            // Linux / BSD / Solaris ELF
            if &header[0..4] == b"\x7FELF" {
                return true;
            }
            // macOS / iOS Mach-O (32-bit, 64-bit, big/little endian, Universal Fat) & Java .class
            if matches!(
                [header[0], header[1], header[2], header[3]],
                [0xFE, 0xED, 0xFA, 0xCE]
                    | [0xFE, 0xED, 0xFA, 0xCF]
                    | [0xCE, 0xFA, 0xED, 0xFE]
                    | [0xCF, 0xFA, 0xED, 0xFE]
                    | [0xCA, 0xFE, 0xBA, 0xBE]
                    | [0xBE, 0xBA, 0xFE, 0xCA]
            ) {
                return true;
            }
            // WebAssembly binary module
            if &header[0..4] == b"\0asm" {
                return true;
            }
            // Android Dalvik Executable
            if &header[0..4] == b"dex\n" {
                return true;
            }
        }

        // Windows PE / COFF / DOS MZ header check (verify PE signature, DOS stub, or binary NULs
        // so an ordinary plain-text note beginning with the letters "MZ" is never falsely rejected)
        if header.len() >= 2 && &header[0..2] == b"MZ" {
            if header.len() >= 0x40 {
                let pe_off = u32::from_le_bytes([
                    header[0x3C],
                    header[0x3D],
                    header[0x3E],
                    header[0x3F],
                ]) as usize;
                if pe_off + 4 <= header.len() && &header[pe_off..pe_off + 4] == b"PE\0\0" {
                    return true;
                }
                if header.windows(18).any(|w| w == b"This program canno" || w == b"This program must ") {
                    return true;
                }
                if (0x40..=4096).contains(&pe_off) && header[2..0x3C].contains(&0) {
                    return true;
                }
            } else if header[2..].contains(&0) {
                return true;
            }
        }

        false
    }

    fn is_lock_or_permission_error(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::PermissionDenied
            || matches!(err.raw_os_error(), Some(32) | Some(33) | Some(5))
    }

    /// Extracts all searchable UTF-8 text from any file discovered by Magika,
    /// falling back to the user-space OS Search index (Windows Search OLE DB / macOS Spotlight)
    /// when a document is exclusively locked by another application.
    pub fn extract_text(path: &Path, identity: &FileIdentity) -> io::Result<String> {
        let res = Self::extract_text_inner(path, identity);
        match res {
            Ok(text) => Ok(text),
            Err(e) if Self::is_lock_or_permission_error(&e) => {
                if let Some((fallback_text, _meta)) = Self::query_os_search_index_fallback(path) {
                    if !fallback_text.trim().is_empty() {
                        return Ok(fallback_text);
                    }
                }
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    fn extract_text_inner(path: &Path, identity: &FileIdentity) -> io::Result<String> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let label = identity.label.to_ascii_lowercase();
        let mime = identity.mime_type.to_ascii_lowercase();

        // 0. Magic-byte sniffing & compiled executable exclusion before extension routing
        let mut probe_buf = [0u8; 512];
        let mut magic_header = [0u8; 16];
        match std::fs::File::open(path) {
            Ok(mut f) => {
                let n = f.read(&mut probe_buf).unwrap_or(0);
                if Self::is_excluded_executable_or_library(&probe_buf[..n], path) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Excluded compiled executable or shared library",
                    ));
                }
                let copy_len = n.min(16);
                magic_header[..copy_len].copy_from_slice(&probe_buf[..copy_len]);
            }
            Err(e) if Self::is_lock_or_permission_error(&e) => {
                return Err(e);
            }
            Err(_) => {}
        }

        // Sniff OLE2 Compound Document: \xD0\xCF\x11\xE0 (e.g. legacy binary .doc misnamed as .pdf)
        if magic_header.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
            if let Ok(text) = Self::extract_ole2_doc_text(path) {
                if !text.trim().is_empty() {
                    return Ok(text);
                }
            }
        }

        // Sniff JPEG: \xFF\xD8\xFF misnamed as other formats (e.g. .pdf)
        if magic_header.starts_with(&[0xFF, 0xD8, 0xFF]) {
            if let Some(ocr_text) = ImageIndexer::run_ocr_on_file(path) {
                if !ocr_text.trim().is_empty() {
                    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("image");
                    return Ok(format!("[Image OCR — {}]\n{}", file_name, ocr_text));
                }
            }
        }

        // 1. PDF Documents (multi-page text + native FlateDecode/CMap + OCR fallback)
        if label == "pdf" || mime == "application/pdf" || ext == "pdf" || magic_header.starts_with(b"%PDF-") {
            return Self::extract_pdf_text(path);
        }

        // 2. HTML Documents (.html, .htm, .xhtml, .mhtml)
        if label == "html"
            || mime == "text/html"
            || matches!(ext.as_str(), "html" | "htm" | "xhtml" | "mhtml")
            || magic_header.starts_with(b"<!DOCTYPE")
            || magic_header.starts_with(b"<!doctype")
            || magic_header.starts_with(b"<html")
            || magic_header.starts_with(b"<HTML")
        {
            return Self::extract_html_prose(path);
        }

        // 3. Word OpenXML & Legacy Word / OpenDocument Text (.docx, .doc, .odt)
        if label == "docx"
            || mime.contains("wordprocessingml")
            || matches!(ext.as_str(), "docx" | "doc" | "odt")
        {
            return Self::extract_word_or_odt_text(path, &ext);
        }

        // 4. Excel Spreadsheets (.xlsx, .xls, .ods)
        if label == "xlsx"
            || mime.contains("spreadsheetml")
            || matches!(ext.as_str(), "xlsx" | "xls" | "ods")
        {
            return Self::extract_spreadsheet_text(path);
        }

        // 5. PowerPoint Presentations (.pptx, .ppt, .odp)
        if label == "pptx"
            || mime.contains("presentationml")
            || matches!(ext.as_str(), "pptx" | "ppt" | "odp")
        {
            return Self::extract_presentation_text(path);
        }

        // 6. Rich Text Format (.rtf)
        if label == "rtf" || mime.contains("rtf") || ext == "rtf" {
            return Self::extract_rtf_text(path);
        }

        // 7. EPUB E-books (.epub)
        if label == "epub" || mime.contains("epub") || ext == "epub" {
            return Self::extract_epub_text(path);
        }

        // 8. Jupyter Notebooks (.ipynb)
        if label == "ipynb" || ext == "ipynb" {
            return Self::extract_ipynb_text(path);
        }

        // 9. SQLite 3 Databases (.sqlite, .db, .sqlite3)
        if label == "sqlite"
            || mime == "application/vnd.sqlite3"
            || matches!(ext.as_str(), "sqlite" | "sqlite3" | "db")
        {
            return Self::extract_sqlite_text(path);
        }

        // 10. Non-UTF8 Binary Data files classified under FileCategory::Data or Document (e.g. pcap, parquet)
        if !identity.is_text
            && matches!(identity.category, FileCategory::Data | FileCategory::Document)
        {
            return Self::extract_binary_data_strings(path, identity);
        }

        // 11. All Text, Source Code, Config, Markup, CSV/TSV/JSON/YAML/TOML/Markdown files
        Self::read_any_text_encoding(path)
    }

    /// Reads text supporting UTF-8, UTF-16LE, UTF-16BE, and Latin-1/lossy fallbacks.
    fn read_any_text_encoding(path: &Path) -> io::Result<String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(text),
            Err(_) => {
                let bytes = std::fs::read(path)?;
                if bytes.starts_with(&[0xFF, 0xFE]) {
                    let u16s: Vec<u16> = bytes[2..]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    return Ok(String::from_utf16_lossy(&u16s));
                }
                if bytes.starts_with(&[0xFE, 0xFF]) {
                    let u16s: Vec<u16> = bytes[2..]
                        .chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    return Ok(String::from_utf16_lossy(&u16s));
                }
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            }
        }
    }

    /// Pure-Rust PKZIP Central Directory reader supporting Stored (0) and Deflate (8) entries.
    /// Reading via the Central Directory (`0x02014b50`) guarantees accurate `compressed_size` even
    /// when streaming data descriptors (bit 3) are used by Word, Google Docs, or LibreOffice.
    pub fn read_zip_entries(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
        let mut entries = BTreeMap::new();
        if bytes.len() < 22 || !bytes.starts_with(b"PK\x03\x04") {
            return entries;
        }

        // Locate End of Central Directory record (0x06054b50) scanning backwards from end
        let min_eocd_offset = bytes.len().saturating_sub(65_557);
        let mut eocd_pos = None;
        for pos in (min_eocd_offset..=bytes.len() - 22).rev() {
            if &bytes[pos..pos + 4] == b"PK\x05\x06" {
                eocd_pos = Some(pos);
                break;
            }
        }
        let Some(eocd) = eocd_pos else {
            return entries;
        };

        let total_entries = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as usize;
        let cd_size = u32::from_le_bytes([
            bytes[eocd + 12],
            bytes[eocd + 13],
            bytes[eocd + 14],
            bytes[eocd + 15],
        ]) as usize;
        let cd_offset = u32::from_le_bytes([
            bytes[eocd + 16],
            bytes[eocd + 17],
            bytes[eocd + 18],
            bytes[eocd + 19],
        ]) as usize;

        if cd_offset >= bytes.len() {
            return entries;
        }
        let cd_end = cd_offset.saturating_add(cd_size).min(bytes.len());
        let mut cursor = cd_offset;
        let mut parsed = 0usize;

        while cursor + 46 <= cd_end && parsed < total_entries.max(512) {
            if &bytes[cursor..cursor + 4] != b"PK\x01\x02" {
                break;
            }
            let method = u16::from_le_bytes([bytes[cursor + 10], bytes[cursor + 11]]);
            let comp_size = u32::from_le_bytes([
                bytes[cursor + 20],
                bytes[cursor + 21],
                bytes[cursor + 22],
                bytes[cursor + 23],
            ]) as usize;
            let uncomp_size = u32::from_le_bytes([
                bytes[cursor + 24],
                bytes[cursor + 25],
                bytes[cursor + 26],
                bytes[cursor + 27],
            ]) as u64;
            let name_len = u16::from_le_bytes([bytes[cursor + 28], bytes[cursor + 29]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[cursor + 30], bytes[cursor + 31]]) as usize;
            let comment_len = u16::from_le_bytes([bytes[cursor + 32], bytes[cursor + 33]]) as usize;
            let local_offset = u32::from_le_bytes([
                bytes[cursor + 42],
                bytes[cursor + 43],
                bytes[cursor + 44],
                bytes[cursor + 45],
            ]) as usize;

            let name_start = cursor + 46;
            let next_cd = name_start
                .saturating_add(name_len)
                .saturating_add(extra_len)
                .saturating_add(comment_len);
            if name_start + name_len > bytes.len() {
                break;
            }
            let name = String::from_utf8_lossy(&bytes[name_start..name_start + name_len]).into_owned();
            parsed += 1;
            cursor = next_cd;

            if uncomp_size > MAX_DECOMPRESSED_STREAM_BYTES || local_offset + 30 > bytes.len() {
                continue;
            }
            if &bytes[local_offset..local_offset + 4] != b"PK\x03\x04" {
                continue;
            }
            let local_name_len =
                u16::from_le_bytes([bytes[local_offset + 26], bytes[local_offset + 27]]) as usize;
            let local_extra_len =
                u16::from_le_bytes([bytes[local_offset + 28], bytes[local_offset + 29]]) as usize;
            let data_start = local_offset + 30 + local_name_len + local_extra_len;
            let data_end = data_start.saturating_add(comp_size);
            if data_end > bytes.len() {
                continue;
            }

            let slice = &bytes[data_start..data_end];
            match method {
                0 => {
                    entries.insert(name, slice.to_vec());
                }
                8 => {
                    let mut out = Vec::with_capacity((uncomp_size as usize).min(4 * 1024 * 1024));
                    let decoder = DeflateDecoder::new(slice);
                    if decoder
                        .take(MAX_DECOMPRESSED_STREAM_BYTES)
                        .read_to_end(&mut out)
                        .is_ok()
                    {
                        entries.insert(name, out);
                    }
                }
                _ => {}
            }
        }

        entries
    }

    /// Extracts clean document prose, tables, `<w:sdt>` content controls, `<w:txbxContent>` timeline boxes,
    /// and `<a:t>` DrawingML shapes from OpenXML Word (`.docx`) or OpenDocument (`.odt`) XML strings.
    fn extract_word_xml_runs(xml: &str, is_odt: bool) -> String {
        let mut out = String::with_capacity(xml.len() / 3);
        let bytes = xml.as_bytes();
        let mut i = 0usize;
        let mut capture_depth = 0usize;
        let mut skip_depth = 0usize;
        let mut table_cell_depth = 0usize;

        while i < bytes.len() {
            if bytes[i] == b'<' {
                if let Some(rel_end) = xml[i..].find('>') {
                    let tag_raw = xml[i + 1..i + rel_end].trim();
                    i += rel_end + 1;

                    if tag_raw.starts_with('!') || tag_raw.starts_with('?') {
                        continue;
                    }
                    let is_closing = tag_raw.starts_with('/');
                    let is_self_closing = tag_raw.ends_with('/');
                    let clean_tag = tag_raw.trim_start_matches('/').trim_end_matches('/').trim();
                    let tag_name = clean_tag
                        .split(|c: char| c.is_ascii_whitespace())
                        .next()
                        .unwrap_or("");

                    // Skip Word AlternateContent VML fallbacks (`mc:Fallback`), deleted revisions (`w:delText`),
                    // and raw field instruction syntax (`w:instrText`) so timeline textboxes are never duplicated
                    // or polluted with raw `HYPERLINK` field codes.
                    let is_skip_tag = matches!(
                        tag_name,
                        "mc:Fallback" | "w:delText" | "w:instrText" | "office:binary-data" | "svg:desc"
                    );
                    if is_skip_tag {
                        if is_closing {
                            skip_depth = skip_depth.saturating_sub(1);
                        } else if !is_self_closing {
                            skip_depth += 1;
                        }
                        continue;
                    }
                    if skip_depth > 0 {
                        continue;
                    }

                    let is_text_run = if is_odt {
                        matches!(tag_name, "text:p" | "text:h" | "text:span" | "text:a")
                    } else {
                        matches!(tag_name, "w:t" | "a:t" | "dgm:t" | "w:sym")
                    };

                    if is_text_run {
                        if is_closing {
                            capture_depth = capture_depth.saturating_sub(1);
                        } else if !is_self_closing {
                            capture_depth += 1;
                        }
                    } else if !is_closing {
                        if matches!(tag_name, "w:tc" | "a:tc" | "table:table-cell") && !is_self_closing {
                            table_cell_depth += 1;
                        } else if matches!(tag_name, "w:tab" | "a:tab" | "text:tab") {
                            out.push('\t');
                        } else if matches!(tag_name, "w:br" | "w:cr" | "a:br" | "text:line-break") {
                            if table_cell_depth > 0 {
                                if !out.ends_with(' ') && !out.ends_with(" | ") && !out.ends_with('\n') {
                                    out.push(' ');
                                }
                            } else {
                                out.push('\n');
                            }
                        }
                    } else {
                        match tag_name {
                            "w:tc" | "a:tc" | "table:table-cell" => {
                                table_cell_depth = table_cell_depth.saturating_sub(1);
                                while out.ends_with(' ') && !out.ends_with(" | ") {
                                    out.pop();
                                }
                                if !out.is_empty() && !out.ends_with(" | ") && !out.ends_with('\n') {
                                    out.push_str(" | ");
                                }
                            }
                            "w:tr" | "a:tr" | "table:table-row" => {
                                if out.ends_with(" | ") {
                                    out.truncate(out.len() - 3);
                                }
                                if !out.ends_with('\n') {
                                    out.push('\n');
                                }
                            }
                            "w:p" | "a:p" | "text:p" | "text:h" => {
                                if table_cell_depth > 0 {
                                    if !out.is_empty()
                                        && !out.ends_with(' ')
                                        && !out.ends_with(" | ")
                                        && !out.ends_with('\n')
                                    {
                                        out.push(' ');
                                    }
                                } else if !out.ends_with('\n') {
                                    out.push('\n');
                                }
                            }
                            _ => {}
                        }
                    }
                    continue;
                }
            }

            let next_tag = xml[i..].find('<').map(|off| i + off).unwrap_or(bytes.len());
            if capture_depth > 0 && skip_depth == 0 && next_tag > i {
                let raw_text = &xml[i..next_tag];
                out.push_str(&Self::decode_html_entities(raw_text));
            }
            i = next_tag;
        }

        let mut cleaned_lines: Vec<String> = Vec::new();
        for line in out.lines() {
            let trimmed = line.trim().trim_matches('|').trim();
            if !trimmed.is_empty() {
                cleaned_lines.push(trimmed.to_string());
            }
        }
        cleaned_lines.join("\n")
    }

    /// Pure-Rust `.docx` and `.odt` extractor reading OpenXML/ODF parts directly from ZIP bytes.
    pub fn extract_ooxml_word_or_odt_native(bytes: &[u8]) -> Option<String> {
        let entries = Self::read_zip_entries(bytes);
        if entries.is_empty() {
            return None;
        }

        let mut sections: Vec<String> = Vec::new();

        // 1. Headers (often hold candidate name, title, certifications, and contact banner on resumes)
        for (name, data) in &entries {
            if name.starts_with("word/header") && name.ends_with(".xml") {
                let xml = String::from_utf8_lossy(data);
                let text = Self::extract_word_xml_runs(&xml, false);
                if !text.is_empty() {
                    sections.push(text);
                }
            }
        }

        // 2. Main body (`word/document.xml` for .docx or `content.xml` for .odt)
        if let Some(doc_bytes) = entries.get("word/document.xml") {
            let xml = String::from_utf8_lossy(doc_bytes);
            let text = Self::extract_word_xml_runs(&xml, false);
            if !text.is_empty() {
                sections.push(text);
            }
        } else if let Some(odt_bytes) = entries.get("content.xml") {
            let xml = String::from_utf8_lossy(odt_bytes);
            let text = Self::extract_word_xml_runs(&xml, true);
            if !text.is_empty() {
                sections.push(text);
            }
        }

        // 3. Footnotes / Endnotes / Diagrams (`word/diagrams/data*.xml` for SmartArt timelines)
        for (name, data) in &entries {
            if (name == "word/footnotes.xml"
                || name == "word/endnotes.xml"
                || (name.starts_with("word/diagrams/data") && name.ends_with(".xml")))
                && !data.is_empty()
            {
                let xml = String::from_utf8_lossy(data);
                let text = Self::extract_word_xml_runs(&xml, false);
                if !text.is_empty() {
                    sections.push(text);
                }
            }
        }

        // 4. Footers
        for (name, data) in &entries {
            if name.starts_with("word/footer") && name.ends_with(".xml") {
                let xml = String::from_utf8_lossy(data);
                let text = Self::extract_word_xml_runs(&xml, false);
                if !text.is_empty() {
                    sections.push(text);
                }
            }
        }

        let joined = sections.join("\n\n");
        if joined.trim().is_empty() {
            None
        } else {
            Some(joined)
        }
    }

    /// Extracts all pages, metadata, and OCR-extracted text from a PDF file.
    fn extract_pdf_text(path: &Path) -> io::Result<String> {
        // Step 1: Attempt standard text and metadata extraction via pypdf when Python + pypdf are available
        let mut metadata_header = String::new();
        let direct_text = match Self::extract_pdf_via_pypdf(path) {
            Ok((meta, body)) => {
                metadata_header = meta;
                body
            }
            Err(_) => String::new(),
        };

        if !Self::is_scanned_or_insufficient_text(&direct_text) {
            if metadata_header.is_empty() {
                return Ok(direct_text);
            } else {
                return Ok(format!("{}\n\n{}", metadata_header, direct_text));
            }
        }

        // Step 2: Pure-Rust `/FlateDecode` stream + `/ToUnicode` CMap + `BT..ET` (`Tj`/`TJ`) extractor
        // Works 100% offline with zero Python dependency (e.g. under `NT AUTHORITY\SYSTEM` Windows Service).
        let bytes = std::fs::read(path)?;
        let native_pdf_text = Self::extract_pdf_native_rust(&bytes);
        if !Self::is_scanned_or_insufficient_text(&native_pdf_text) {
            if metadata_header.is_empty() {
                return Ok(native_pdf_text);
            } else {
                return Ok(format!("{}\n\n{}", metadata_header, native_pdf_text));
            }
        }

        tracing::info!(
            pdf_path = %path.display(),
            "PDF text layer is empty or scanned; triggering page image OCR fallback"
        );

        // Step 3: Run page image extraction + OCR fallback
        if let Ok(ocr_text) = Self::extract_scanned_pdf_ocr(path) {
            if !ocr_text.trim().is_empty() {
                if metadata_header.is_empty() {
                    return Ok(ocr_text);
                } else {
                    return Ok(format!("{}\n\n{}", ocr_text, metadata_header));
                }
            }
        }

        // Step 4: Pure-Rust fallback: scan embedded JPEG byte streams
        if let Ok(jpeg_ocr) = Self::extract_pdf_embedded_jpegs_ocr(&bytes) {
            if !jpeg_ocr.trim().is_empty() {
                if metadata_header.is_empty() {
                    return Ok(jpeg_ocr);
                } else {
                    return Ok(format!("{}\n\n{}", jpeg_ocr, metadata_header));
                }
            }
        }

        // Step 5: Pure-Rust stream literal fallback (filtered against trailer/URI noise)
        let stream_fallback = Self::extract_pdf_streams_fallback(&bytes, path);
        if !stream_fallback.trim().is_empty() {
            if metadata_header.is_empty() {
                return Ok(stream_fallback);
            } else {
                return Ok(format!("{}\n\n{}", metadata_header, stream_fallback));
            }
        }

        if !metadata_header.is_empty() {
            Ok(metadata_header)
        } else {
            Ok(String::new())
        }
    }

    /// Inflates all PDF streams (`/FlateDecode` zlib/raw-deflate or uncompressed), collects `/ToUnicode`
    /// CMap mappings (`beginbfchar` / `beginbfrange`), and decodes PDF text-showing operators (`Tj`, `TJ`, `'`, `"`).
    pub fn extract_pdf_native_rust(bytes: &[u8]) -> String {
        let streams = Self::collect_decompressed_pdf_streams(bytes);
        if streams.is_empty() {
            return String::new();
        }

        // Pass 1: Build global CID/glyph hex -> Unicode map across `/ToUnicode` CMap streams
        let mut cmap: HashMap<u32, String> = HashMap::new();
        let mut cmap_key_bytes: usize = 2;
        for s in &streams {
            let text = String::from_utf8_lossy(s);
            if text.contains("begincmap")
                || text.contains("beginbfchar")
                || text.contains("beginbfrange")
            {
                Self::parse_pdf_tounicode_cmap(&text, &mut cmap, &mut cmap_key_bytes);
            }
        }

        // Pass 2: Extract text objects (`BT ... ET`) from content streams in page/object order
        let mut page_blocks: Vec<String> = Vec::new();
        for s in &streams {
            let text = String::from_utf8_lossy(s);
            if text.contains("begincmap")
                || text.contains("<x:xmpmeta")
                || text.contains("<?xpacket")
                || (!text.contains("BT") && !text.contains("Tj") && !text.contains("TJ"))
            {
                continue;
            }
            let extracted = Self::decode_pdf_content_stream(s, &cmap, cmap_key_bytes);
            if extracted.chars().filter(|c| c.is_alphanumeric()).count() >= 4 {
                page_blocks.push(extracted);
            }
        }

        page_blocks.join("\n\n")
    }

    /// Scans PDF bytes for `stream ... endstream` blocks and inflates `/FlateDecode` payloads.
    fn collect_decompressed_pdf_streams(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0usize;

        while pos + 16 < bytes.len() {
            let Some(rel) = bytes[pos..].windows(6).position(|w| w == b"stream") else {
                break;
            };
            let kw = pos + rel;
            // Ensure `stream` is not the tail of `endstream`
            if kw >= 3 && &bytes[kw - 3..kw] == b"end" {
                pos = kw + 6;
                continue;
            }

            let dict_start = kw.saturating_sub(512);
            let dict_header = String::from_utf8_lossy(&bytes[dict_start..kw]);
            // Skip image XObjects and embedded font binaries so we only inflate text/CMap streams
            let dict_lower = dict_header.to_ascii_lowercase();
            if dict_lower.contains("/subtype /image")
                || dict_lower.contains("/subtype/image")
                || dict_lower.contains("/fontfile")
            {
                pos = kw + 6;
                continue;
            }

            let mut data_start = kw + 6;
            if data_start < bytes.len() && bytes[data_start] == b'\r' {
                data_start += 1;
            }
            if data_start < bytes.len() && bytes[data_start] == b'\n' {
                data_start += 1;
            } else if data_start == kw + 6 {
                // `stream` keyword in PDF must be followed by EOL (`\n` or `\r\n`)
                pos = kw + 6;
                continue;
            }

            let Some(end_rel) = bytes[data_start..]
                .windows(9)
                .position(|w| w == b"endstream")
            else {
                break;
            };
            let mut data_end = data_start + end_rel;
            while data_end > data_start && matches!(bytes[data_end - 1], b'\r' | b'\n' | b' ') {
                data_end -= 1;
            }
            pos = data_start + end_rel + 9;

            if data_end <= data_start {
                continue;
            }
            let raw = &bytes[data_start..data_end];
            let is_flate = dict_lower.contains("flatedecode") || dict_lower.contains("/fl ");

            if is_flate {
                let mut inflated = Vec::new();
                if ZlibDecoder::new(raw)
                    .take(MAX_DECOMPRESSED_STREAM_BYTES)
                    .read_to_end(&mut inflated)
                    .is_ok()
                    && !inflated.is_empty()
                {
                    out.push(inflated);
                    continue;
                }
                inflated.clear();
                if DeflateDecoder::new(raw)
                    .take(MAX_DECOMPRESSED_STREAM_BYTES)
                    .read_to_end(&mut inflated)
                    .is_ok()
                    && !inflated.is_empty()
                {
                    out.push(inflated);
                    continue;
                }
            } else if raw.len() <= MAX_DECOMPRESSED_STREAM_BYTES as usize {
                out.push(raw.to_vec());
            }
        }

        out
    }

    /// Parses `/ToUnicode` CMap `beginbfchar` and `beginbfrange` sections into `cmap`.
    fn parse_pdf_tounicode_cmap(
        cmap_str: &str,
        cmap: &mut HashMap<u32, String>,
        key_bytes: &mut usize,
    ) {
        let extract_hex_tokens = |section: &str| -> Vec<String> {
            let mut tokens = Vec::new();
            let mut cur = String::new();
            let mut inside = false;
            for ch in section.chars() {
                if ch == '<' {
                    inside = true;
                    cur.clear();
                } else if ch == '>' && inside {
                    inside = false;
                    let hex: String = cur.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                    if !hex.is_empty() {
                        tokens.push(hex);
                    }
                } else if inside {
                    cur.push(ch);
                }
            }
            tokens
        };

        let hex_to_unicode = |hex: &str| -> Option<String> {
            let mut padded = hex.to_string();
            if padded.len() % 2 != 0 {
                padded.insert(0, '0');
            }
            let raw_bytes: Vec<u8> = (0..padded.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&padded[i..i + 2], 16).ok())
                .collect();
            if raw_bytes.is_empty() {
                return None;
            }
            if raw_bytes.len() >= 2 && raw_bytes.len() % 2 == 0 {
                let u16s: Vec<u16> = raw_bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&u16s);
                if !s.is_empty() {
                    return Some(s);
                }
            }
            Some(raw_bytes.iter().map(|&b| b as char).collect())
        };

        // 1. `beginbfchar ... endbfchar`
        let mut search_from = 0usize;
        while let Some(b_idx) = cmap_str[search_from..].find("beginbfchar") {
            let start = search_from + b_idx + "beginbfchar".len();
            let Some(e_rel) = cmap_str[start..].find("endbfchar") else {
                break;
            };
            let block = &cmap_str[start..start + e_rel];
            search_from = start + e_rel + "endbfchar".len();
            let hexes = extract_hex_tokens(block);
            for pair in hexes.chunks_exact(2) {
                if pair[0].len() == 2 && *key_bytes == 2 && cmap.is_empty() {
                    *key_bytes = 1;
                } else if pair[0].len() == 4 {
                    *key_bytes = 2;
                }
                if let (Ok(code), Some(uni)) = (u32::from_str_radix(&pair[0], 16), hex_to_unicode(&pair[1])) {
                    cmap.insert(code, uni);
                }
            }
        }

        // 2. `beginbfrange ... endbfrange`
        let mut range_from = 0usize;
        while let Some(b_idx) = cmap_str[range_from..].find("beginbfrange") {
            let start = range_from + b_idx + "beginbfrange".len();
            let Some(e_rel) = cmap_str[start..].find("endbfrange") else {
                break;
            };
            let block = &cmap_str[start..start + e_rel];
            range_from = start + e_rel + "endbfrange".len();
            for line in block.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.contains('[') {
                    continue;
                }
                let hexes = extract_hex_tokens(trimmed);
                if hexes.len() >= 3 {
                    if hexes[0].len() == 4 {
                        *key_bytes = 2;
                    }
                    if let (Ok(lo), Ok(hi), Ok(dst_start)) = (
                        u32::from_str_radix(&hexes[0], 16),
                        u32::from_str_radix(&hexes[1], 16),
                        u32::from_str_radix(&hexes[2], 16),
                    ) {
                        for offset in 0..=(hi.saturating_sub(lo)).min(1024) {
                            if let Some(ch) = char::from_u32(dst_start.saturating_add(offset)) {
                                cmap.insert(lo + offset, ch.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Decodes a decompressed PDF content stream (`Tj`, `TJ`, `'`, `"`, `Td`, `TD`, `T*`, `Tm`, `ET`) into clean UTF-8 text.
    fn decode_pdf_content_stream(
        stream: &[u8],
        cmap: &HashMap<u32, String>,
        cmap_key_bytes: usize,
    ) -> String {
        #[derive(Clone)]
        enum PdfVal {
            Str(String),
            Num(f32),
            Array(Vec<PdfVal>),
        }

        let decode_literal = |raw: &[u8]| -> String {
            let mut bytes_out = Vec::with_capacity(raw.len());
            let mut k = 0usize;
            while k < raw.len() {
                if raw[k] == b'\\' && k + 1 < raw.len() {
                    k += 1;
                    match raw[k] {
                        b'n' => bytes_out.push(b'\n'),
                        b'r' => bytes_out.push(b'\r'),
                        b't' => bytes_out.push(b'\t'),
                        b'b' => bytes_out.push(0x08),
                        b'f' => bytes_out.push(0x0C),
                        b'\r' => {
                            if k + 1 < raw.len() && raw[k + 1] == b'\n' {
                                k += 1;
                            }
                        }
                        b'\n' => {}
                        c if (b'0'..=b'7').contains(&c) => {
                            let mut oct = (c - b'0') as u8;
                            for _ in 0..2 {
                                if k + 1 < raw.len() && (b'0'..=b'7').contains(&raw[k + 1]) {
                                    k += 1;
                                    oct = oct.wrapping_mul(8).wrapping_add(raw[k] - b'0');
                                } else {
                                    break;
                                }
                            }
                            bytes_out.push(oct);
                        }
                        other => bytes_out.push(other),
                    }
                } else {
                    bytes_out.push(raw[k]);
                }
                k += 1;
            }
            if bytes_out.starts_with(&[0xFE, 0xFF]) && bytes_out.len() >= 4 {
                let u16s: Vec<u16> = bytes_out[2..]
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                return String::from_utf16_lossy(&u16s);
            }
            // If a 1-byte CMap exists and characters are low glyph indices, map through CMap
            if !cmap.is_empty() && cmap_key_bytes == 1 && bytes_out.iter().any(|&b| b < 0x20 && b != b'\n' && b != b'\t') {
                let mut mapped = String::new();
                for &b in &bytes_out {
                    if let Some(u) = cmap.get(&(b as u32)) {
                        mapped.push_str(u);
                    } else if b >= 0x20 {
                        mapped.push(b as char);
                    }
                }
                return mapped;
            }
            bytes_out
                .into_iter()
                .map(|b| match b {
                    0x91 | 0x92 => '’',
                    0x93 | 0x94 => '"',
                    0x95 => '•',
                    0x96 => '–',
                    0x97 => '—',
                    _ => b as char,
                })
                .collect()
        };

        let decode_hex = |hex_bytes: &[u8]| -> String {
            let clean: Vec<u8> = hex_bytes
                .iter()
                .copied()
                .filter(|b| b.is_ascii_hexdigit())
                .collect();
            if clean.is_empty() {
                return String::new();
            }
            let mut raw = Vec::with_capacity((clean.len() + 1) / 2);
            let mut idx = 0usize;
            while idx < clean.len() {
                let pair = if idx + 1 < clean.len() {
                    [clean[idx], clean[idx + 1]]
                } else {
                    [clean[idx], b'0']
                };
                if let Ok(s) = std::str::from_utf8(&pair) {
                    if let Ok(v) = u8::from_str_radix(s, 16) {
                        raw.push(v);
                    }
                }
                idx += 2;
            }
            if !cmap.is_empty() {
                let mut out = String::new();
                if cmap_key_bytes >= 2 && raw.len() % 2 == 0 {
                    for pair in raw.chunks_exact(2) {
                        let code = u16::from_be_bytes([pair[0], pair[1]]) as u32;
                        if let Some(s) = cmap.get(&code) {
                            out.push_str(s);
                        } else if let Some(ch) = char::from_u32(code) {
                            if !ch.is_control() {
                                out.push(ch);
                            }
                        }
                    }
                    if !out.is_empty() {
                        return out;
                    }
                }
                for &b in &raw {
                    if let Some(s) = cmap.get(&(b as u32)) {
                        out.push_str(s);
                    } else if (0x20..=0x7E).contains(&b) {
                        out.push(b as char);
                    }
                }
                if !out.is_empty() {
                    return out;
                }
            }
            if raw.starts_with(&[0xFE, 0xFF]) || (raw.len() % 2 == 0 && raw.iter().step_by(2).all(|&b| b == 0)) {
                let slice = if raw.starts_with(&[0xFE, 0xFF]) { &raw[2..] } else { &raw[..] };
                let u16s: Vec<u16> = slice
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                return String::from_utf16_lossy(&u16s);
            }
            raw.into_iter()
                .filter(|&b| (0x20..=0x7E).contains(&b) || b >= 0xA0)
                .map(|b| b as char)
                .collect()
        };

        let parse_next_token = |buf: &[u8], pos: &mut usize| -> Option<Result<PdfVal, String>> {
            while *pos < buf.len() {
                let b = buf[*pos];
                if b.is_ascii_whitespace() {
                    *pos += 1;
                } else if b == b'%' {
                    while *pos < buf.len() && buf[*pos] != b'\n' && buf[*pos] != b'\r' {
                        *pos += 1;
                    }
                } else {
                    break;
                }
            }
            if *pos >= buf.len() {
                return None;
            }
            match buf[*pos] {
                b'(' => {
                    *pos += 1;
                    let start = *pos;
                    let mut depth = 1i32;
                    while *pos < buf.len() && depth > 0 {
                        if buf[*pos] == b'\\' {
                            *pos = (*pos + 2).min(buf.len());
                            continue;
                        }
                        if buf[*pos] == b'(' {
                            depth += 1;
                        } else if buf[*pos] == b')' {
                            depth -= 1;
                            if depth == 0 {
                                let s = decode_literal(&buf[start..*pos]);
                                *pos += 1;
                                return Some(Ok(PdfVal::Str(s)));
                            }
                        }
                        *pos += 1;
                    }
                    Some(Ok(PdfVal::Str(decode_literal(&buf[start..*pos]))))
                }
                b'<' => {
                    if *pos + 1 < buf.len() && buf[*pos + 1] == b'<' {
                        *pos += 2;
                        return Some(Err("<<".to_string()));
                    }
                    *pos += 1;
                    let start = *pos;
                    while *pos < buf.len() && buf[*pos] != b'>' {
                        *pos += 1;
                    }
                    let s = decode_hex(&buf[start..*pos]);
                    if *pos < buf.len() {
                        *pos += 1;
                    }
                    Some(Ok(PdfVal::Str(s)))
                }
                b'>' => {
                    if *pos + 1 < buf.len() && buf[*pos + 1] == b'>' {
                        *pos += 2;
                        Some(Err(">>".to_string()))
                    } else {
                        *pos += 1;
                        Some(Err(">".to_string()))
                    }
                }
                b'[' => {
                    *pos += 1;
                    Some(Err("[".to_string()))
                }
                b']' => {
                    *pos += 1;
                    Some(Err("]".to_string()))
                }
                b'/' => {
                    *pos += 1;
                    while *pos < buf.len()
                        && !buf[*pos].is_ascii_whitespace()
                        && !matches!(buf[*pos], b'/' | b'(' | b')' | b'<' | b'>' | b'[' | b']')
                    {
                        *pos += 1;
                    }
                    Some(Err("/name".to_string()))
                }
                _ => {
                    let start = *pos;
                    while *pos < buf.len()
                        && !buf[*pos].is_ascii_whitespace()
                        && !matches!(buf[*pos], b'/' | b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'%')
                    {
                        *pos += 1;
                    }
                    let tok = String::from_utf8_lossy(&buf[start..*pos]).into_owned();
                    if let Ok(num) = tok.parse::<f32>() {
                        Some(Ok(PdfVal::Num(num)))
                    } else {
                        Some(Err(tok))
                    }
                }
            }
        };

        let mut out = String::new();
        let mut stack: Vec<PdfVal> = Vec::new();
        let mut array_stack: Option<Vec<PdfVal>> = None;
        let mut pos = 0usize;
        let mut last_tm_y: Option<f32> = None;

        while let Some(tok) = parse_next_token(stream, &mut pos) {
            match tok {
                Ok(val) => {
                    if let Some(ref mut arr) = array_stack {
                        arr.push(val);
                    } else {
                        if stack.len() >= 16 {
                            stack.remove(0);
                        }
                        stack.push(val);
                    }
                }
                Err(op) => match op.as_str() {
                    "[" => {
                        array_stack = Some(Vec::new());
                    }
                    "]" => {
                        if let Some(arr) = array_stack.take() {
                            stack.push(PdfVal::Array(arr));
                        }
                    }
                    "BT" => {
                        stack.clear();
                    }
                    "ET" => {
                        if !out.ends_with('\n') && !out.ends_with(' ') && !out.is_empty() {
                            out.push(' ');
                        }
                        stack.clear();
                    }
                    "T*" => {
                        if !out.ends_with('\n') {
                            out.push('\n');
                        }
                        stack.clear();
                    }
                    "Td" | "TD" => {
                        if stack.len() >= 2 {
                            let ty = match &stack[stack.len() - 1] {
                                PdfVal::Num(n) => *n,
                                _ => 0.0,
                            };
                            let tx = match &stack[stack.len() - 2] {
                                PdfVal::Num(n) => *n,
                                _ => 0.0,
                            };
                            if ty.abs() > 1.5 {
                                if !out.ends_with('\n') {
                                    out.push('\n');
                                }
                            } else if tx > 8.0 && !out.ends_with(' ') && !out.ends_with('\n') {
                                out.push(' ');
                            }
                        }
                        stack.clear();
                    }
                    "Tm" => {
                        if stack.len() >= 6 {
                            if let PdfVal::Num(y) = &stack[stack.len() - 1] {
                                if let Some(prev_y) = last_tm_y {
                                    if (y - prev_y).abs() > 2.0 && !out.ends_with('\n') && !out.is_empty() {
                                        out.push('\n');
                                    } else if !out.ends_with(' ') && !out.ends_with('\n') && !out.is_empty() {
                                        out.push(' ');
                                    }
                                }
                                last_tm_y = Some(*y);
                            }
                        }
                        stack.clear();
                    }
                    "Tj" => {
                        if let Some(PdfVal::Str(s)) = stack.pop() {
                            out.push_str(&s);
                        }
                        stack.clear();
                    }
                    "'" | "\"" => {
                        if !out.ends_with('\n') {
                            out.push('\n');
                        }
                        if let Some(PdfVal::Str(s)) = stack.pop() {
                            out.push_str(&s);
                        }
                        stack.clear();
                    }
                    "TJ" => {
                        if let Some(PdfVal::Array(items)) = stack.pop() {
                            for item in items {
                                match item {
                                    PdfVal::Str(s) => out.push_str(&s),
                                    PdfVal::Num(kern) => {
                                        // Negative PDF TJ adjustment <= -120 thousandths of text space represents a word space
                                        if kern <= -120.0
                                            && !out.ends_with(' ')
                                            && !out.ends_with('\n')
                                        {
                                            out.push(' ');
                                        }
                                    }
                                    PdfVal::Array(_) => {}
                                }
                            }
                        }
                        stack.clear();
                    }
                    _ => {
                        stack.clear();
                    }
                },
            }
        }

        let mut lines = Vec::new();
        for line in out.lines() {
            let collapsed = line.split_whitespace().collect::<Vec<_>>().join(" ");
            if !collapsed.is_empty() {
                lines.push(collapsed);
            }
        }
        lines.join("\n")
    }

    /// Extracts metadata and text layer using pypdf via discovered python subprocess.
    fn extract_pdf_via_pypdf(path: &Path) -> io::Result<(String, String)> {
        let Some(python_bin) = Self::resolve_python_binary() else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No Python 3 interpreter found",
            ));
        };

        let script = [
            "import sys, pypdf",
            "sys.stdout.reconfigure(encoding='utf-8', errors='replace')",
            "try:",
            "    r = pypdf.PdfReader(sys.argv[1])",
            "except Exception:",
            "    sys.exit(1)",
            "meta_parts = []",
            "if r.metadata:",
            "    for k, v in r.metadata.items():",
            "        if v and str(v).strip():",
            "            meta_parts.append(f'{str(k)[1:]}: {v}')",
            "meta_str = ('[PDF Metadata] ' + ' | '.join(meta_parts)) if meta_parts else ''",
            "pages_out = []",
            "for idx, p in enumerate(r.pages):",
            "    try:",
            "        t = (p.extract_text() or '').strip()",
            "        if t:",
            "            pages_out.append(f'[Page {idx+1}]\\n{t}')",
            "    except Exception:",
            "        pass",
            "print('---METADATA_DIVIDER---')",
            "print(meta_str)",
            "print('---PAGES_DIVIDER---')",
            "print('\\n\\n'.join(pages_out))",
        ]
        .join("\n");

        let output = Command::new(python_bin)
            .arg("-c")
            .arg(script)
            .arg(path.as_os_str())
            .output()?;

        if !output.status.success() {
            return Err(io::Error::other(format!(
                "pypdf extraction failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut meta = String::new();
        let mut body = String::new();

        if let Some(m_idx) = stdout.find("---METADATA_DIVIDER---") {
            if let Some(p_idx) = stdout.find("---PAGES_DIVIDER---") {
                let m_slice = stdout[m_idx + "---METADATA_DIVIDER---".len()..p_idx].trim();
                let b_slice = stdout[p_idx + "---PAGES_DIVIDER---".len()..].trim();
                meta = m_slice.to_string();
                body = b_slice.to_string();
            }
        } else {
            body = stdout.trim().to_string();
        }

        Ok((meta, body))
    }

    /// Extracts embedded raster images from each PDF page and executes OCR,
    /// formatting the output as `[Scanned PDF — OCR Extracted Text]\nPage X:\n...`.
    fn extract_scanned_pdf_ocr(path: &Path) -> io::Result<String> {
        let Some(python_bin) = Self::resolve_python_binary() else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No Python 3 interpreter found",
            ));
        };
        let temp_dir = tempfile::tempdir()?;
        let temp_dir_path = temp_dir.path().to_path_buf();

        let script = [
            "import sys, os, pypdf",
            "sys.stdout.reconfigure(encoding='utf-8', errors='replace')",
            "pdf_path = sys.argv[1]",
            "out_dir = sys.argv[2]",
            "try:",
            "    r = pypdf.PdfReader(pdf_path)",
            "except Exception:",
            "    sys.exit(1)",
            "manifest = []",
            "for idx, p in enumerate(r.pages):",
            "    page_num = idx + 1",
            "    try:",
            "        for img_idx, img in enumerate(p.images):",
            "            ext = os.path.splitext(img.name)[1] or '.png'",
            "            fname = f'page_{page_num}_img_{img_idx}{ext}'",
            "            fpath = os.path.join(out_dir, fname)",
            "            with open(fpath, 'wb') as f:",
            "                f.write(img.data)",
            "            manifest.append(f'{page_num}\\t{fpath}')",
            "    except Exception:",
            "        pass",
            "print('\\n'.join(manifest))",
        ]
        .join("\n");

        let output = Command::new(python_bin)
            .arg("-c")
            .arg(script)
            .arg(path.as_os_str())
            .arg(temp_dir_path.as_os_str())
            .output()?;

        if !output.status.success() {
            return Err(io::Error::other(format!(
                "Failed to extract page images: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let manifest = String::from_utf8_lossy(&output.stdout);
        let mut pages_map: BTreeMap<usize, Vec<String>> = BTreeMap::new();

        for line in manifest.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() == 2 {
                if let Ok(page_num) = parts[0].parse::<usize>() {
                    let img_path = Path::new(parts[1]);
                    if img_path.exists() {
                        if let Some(ocr_text) = ImageIndexer::run_ocr_on_file(img_path) {
                            let trimmed = ocr_text.trim();
                            if !trimmed.is_empty() {
                                pages_map.entry(page_num).or_default().push(trimmed.to_string());
                            }
                        }
                    }
                }
            }
        }

        if pages_map.is_empty() {
            return Ok(String::new());
        }

        let mut out = Vec::new();
        out.push("[Scanned PDF — OCR Extracted Text]".to_string());
        for (page_num, texts) in pages_map {
            out.push(format!("Page {}:\n{}", page_num, texts.join("\n")));
        }

        Ok(out.join("\n\n"))
    }

    /// Pure-Rust scanner extracting raw embedded JPEG byte slices from PDF byte streams.
    pub fn extract_embedded_jpegs_from_pdf_bytes(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut jpegs = Vec::new();
        let mut idx = 0;
        while idx + 3 < bytes.len() {
            if bytes[idx] == 0xFF && bytes[idx + 1] == 0xD8 && bytes[idx + 2] == 0xFF {
                let start = idx;
                let mut search = start + 3;
                let mut found_eoi = None;
                while search + 1 < bytes.len() {
                    if bytes[search] == 0xFF && bytes[search + 1] == 0xD9 {
                        found_eoi = Some(search + 2);
                        break;
                    }
                    search += 1;
                }
                if let Some(end) = found_eoi {
                    let slice = &bytes[start..end];
                    if slice.len() >= 100 {
                        jpegs.push(slice.to_vec());
                    }
                    idx = end;
                    continue;
                }
            }
            idx += 1;
        }
        jpegs
    }

    /// Pure-Rust fallback: writes extracted JPEG byte streams to temporary files and executes OCR.
    fn extract_pdf_embedded_jpegs_ocr(bytes: &[u8]) -> io::Result<String> {
        let jpegs = Self::extract_embedded_jpegs_from_pdf_bytes(bytes);
        if jpegs.is_empty() {
            return Ok(String::new());
        }

        let temp_dir = tempfile::tempdir()?;
        let mut out_pages = Vec::new();

        for (idx, jpeg_data) in jpegs.iter().enumerate() {
            let img_path = temp_dir.path().join(format!("embedded_page_{}.jpg", idx + 1));
            std::fs::write(&img_path, jpeg_data)?;
            if let Some(text) = ImageIndexer::run_ocr_on_file(&img_path) {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    out_pages.push(format!("Page {}:\n{}", idx + 1, trimmed));
                }
            }
        }

        if out_pages.is_empty() {
            return Ok(String::new());
        }

        let mut result = Vec::new();
        result.push("[Scanned PDF — OCR Extracted Text]".to_string());
        result.extend(out_pages);
        Ok(result.join("\n\n"))
    }

    /// Extracts all paragraphs, tables, timeline textboxes, content controls, headers, and footers
    /// from `.docx`, `.doc`, or `.odt` using pure-Rust OpenXML/OLE2 parsing first.
    fn extract_word_or_odt_text(path: &Path, ext: &str) -> io::Result<String> {
        if ext == "doc" {
            if let Ok(text) = Self::extract_ole2_doc_text(path) {
                if !text.trim().is_empty() {
                    return Ok(text);
                }
            }
        }

        let bytes = std::fs::read(path)?;

        // Primary path: 100% pure-Rust ZIP + OpenXML/ODF XML extraction (handles paragraphs, tables,
        // `<w:txbxContent>` timeline boxes, `<w:sdt>` content controls, and `<a:t>` DrawingML shapes
        // without requiring external Python or `python-docx`).
        if let Some(native_text) = Self::extract_ooxml_word_or_odt_native(&bytes) {
            return Ok(native_text);
        }

        // Secondary path: Python `docx` / `zipfile` if available
        if let Some(python_bin) = Self::resolve_python_binary() {
            let script = [
                "import sys, zipfile, xml.etree.ElementTree as ET",
                "sys.stdout.reconfigure(encoding='utf-8', errors='replace')",
                "out = []",
                "try:",
                "    import docx",
                "    d = docx.Document(sys.argv[1])",
                "    for p in d.paragraphs:",
                "        if p.text.strip(): out.append(p.text.strip())",
                "    for t in d.tables:",
                "        for row in t.rows:",
                "            cells = [c.text.strip() for c in row.cells if c.text.strip()]",
                "            if cells: out.append(' | '.join(cells))",
                "except Exception:",
                "    pass",
                "if not out:",
                "    try:",
                "        with zipfile.ZipFile(sys.argv[1], 'r') as z:",
                "            for name in z.namelist():",
                "                if name.endswith('.xml') and ('word/' in name or name == 'content.xml'):",
                "                    root = ET.fromstring(z.read(name))",
                "                    texts = [el.text.strip() for el in root.iter() if el.text and el.text.strip()]",
                "                    if texts: out.append(' '.join(texts))",
                "    except Exception:",
                "        pass",
                "print('\\n'.join(out))",
            ]
            .join("\n");

            if let Ok(output) = Command::new(python_bin)
                .arg("-c")
                .arg(script)
                .arg(path.as_os_str())
                .output()
            {
                if output.status.success() {
                    let extracted = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !extracted.is_empty() {
                        return Ok(extracted);
                    }
                }
            }
        }

        // Never dump raw PKZIP central directory XML filenames (`[Content_Types].xml`, `word/document.xml`) into RAG chunks
        if bytes.starts_with(b"PK\x03\x04") {
            return Ok(String::new());
        }

        Ok(Self::extract_printable_strings(
            &bytes,
            path,
            &format!("Word/Document ({})", ext),
        ))
    }

    /// Pure-Rust OLE2 parser using `cfb` for legacy binary `.doc` files (Word 97-2003).
    /// Extracts text from the `WordDocument` stream without 256KB truncation.
    pub fn extract_ole2_doc_text(path: &Path) -> io::Result<String> {
        let file = std::fs::File::open(path)?;
        let mut comp = cfb::CompoundFile::open(file)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        if !comp.is_stream("/WordDocument") {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No WordDocument stream found in OLE2 container",
            ));
        }

        let word_bytes = {
            let mut word_doc_stream = comp
                .open_stream("/WordDocument")
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let mut bytes = Vec::new();
            word_doc_stream.read_to_end(&mut bytes)?;
            bytes
        };

        // Try piece table extraction from 1Table or 0Table if present
        let table_stream_name = if word_bytes.len() > 11 && (word_bytes[11] & 0x02) != 0 {
            "/1Table"
        } else {
            "/0Table"
        };

        if comp.is_stream(table_stream_name) {
            if let Ok(mut table_stream) = comp.open_stream(table_stream_name) {
                let mut table_bytes = Vec::new();
                if table_stream.read_to_end(&mut table_bytes).is_ok() {
                    if let Some(text) = Self::parse_word_piece_table(&word_bytes, &table_bytes) {
                        let trimmed = text.trim();
                        if !trimmed.is_empty() {
                            return Ok(trimmed.to_string());
                        }
                    }
                }
            }
        }

        // Lossless text run scan fallback across word_bytes without truncation
        let extracted = Self::extract_word_bytes_lossless(&word_bytes, path);
        if !extracted.trim().is_empty() {
            return Ok(extracted);
        }

        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "No extractable text in WordDocument stream",
        ))
    }

    /// Parses the Word 97-2003 FIB piece table (`Plcfpcd`) from the Table stream.
    fn parse_word_piece_table(word_bytes: &[u8], table_bytes: &[u8]) -> Option<String> {
        if word_bytes.len() < 426 {
            return None;
        }
        let fc_clx = u32::from_le_bytes(word_bytes[418..422].try_into().ok()?) as usize;
        let lcb_clx = u32::from_le_bytes(word_bytes[422..426].try_into().ok()?) as usize;

        if fc_clx + lcb_clx > table_bytes.len() || lcb_clx == 0 {
            return None;
        }

        let clx_data = &table_bytes[fc_clx..fc_clx + lcb_clx];
        let mut pos = 0;

        // Skip any Prc (0x01) records
        while pos < clx_data.len() && clx_data[pos] == 0x01 {
            pos += 1;
            if pos + 2 > clx_data.len() {
                return None;
            }
            let cb = u16::from_le_bytes(clx_data[pos..pos + 2].try_into().ok()?) as usize;
            pos += 2 + cb;
        }

        // Pcdt record (0x02)
        if pos >= clx_data.len() || clx_data[pos] != 0x02 {
            return None;
        }
        pos += 1;
        if pos + 4 > clx_data.len() {
            return None;
        }
        let lcb_pcd = u32::from_le_bytes(clx_data[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;

        if pos + lcb_pcd > clx_data.len() || lcb_pcd < 4 {
            return None;
        }

        let n_pieces = (lcb_pcd - 4) / 12;
        if n_pieces == 0 {
            return None;
        }

        let pcd_data = &clx_data[pos..pos + lcb_pcd];
        let cp_array_len = (n_pieces + 1) * 4;
        let pcd_start = cp_array_len;

        let mut extracted_text = String::new();

        for i in 0..n_pieces {
            let cp_curr = u32::from_le_bytes(pcd_data[i * 4..i * 4 + 4].try_into().ok()?) as usize;
            let cp_next = u32::from_le_bytes(pcd_data[(i + 1) * 4..(i + 1) * 4 + 4].try_into().ok()?) as usize;
            if cp_next <= cp_curr {
                continue;
            }
            let char_count = cp_next - cp_curr;

            let pcd_offset = pcd_start + i * 8;
            if pcd_offset + 8 > pcd_data.len() {
                break;
            }
            let fc = u32::from_le_bytes(pcd_data[pcd_offset + 2..pcd_offset + 6].try_into().ok()?);
            let f_compressed = (fc & 0x4000_0000) != 0;

            if f_compressed {
                let actual_offset = ((fc & !0x4000_0000) / 2) as usize;
                if actual_offset + char_count <= word_bytes.len() {
                    let slice = &word_bytes[actual_offset..actual_offset + char_count];
                    for &b in slice {
                        if b == 0x0D || b == 0x07 || b == 0x0B {
                            extracted_text.push('\n');
                        } else if b == 0x09 {
                            extracted_text.push('\t');
                        } else if (0x20..=0x7E).contains(&b) || b >= 0xA0 {
                            extracted_text.push(b as char);
                        }
                    }
                }
            } else {
                let actual_offset = fc as usize;
                let byte_count = char_count * 2;
                if actual_offset + byte_count <= word_bytes.len() {
                    let slice = &word_bytes[actual_offset..actual_offset + byte_count];
                    let u16_chars: Vec<u16> = slice
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    for ch in char::decode_utf16(u16_chars) {
                        if let Ok(c) = ch {
                            if c == '\r' || c == '\x07' || c == '\x0b' {
                                extracted_text.push('\n');
                            } else if c == '\t' || !c.is_control() {
                                extracted_text.push(c);
                            }
                        }
                    }
                }
            }
        }

        if extracted_text.trim().is_empty() {
            None
        } else {
            Some(extracted_text)
        }
    }

    /// Scans the entire WordDocument stream for UTF-16LE and CP1252 text runs without any 256KB cap.
    fn extract_word_bytes_lossless(bytes: &[u8], path: &Path) -> String {
        let mut out = format!(
            "[WordDocument — {}]\n",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("document.doc")
        );
        let mut run_16 = Vec::new();
        let mut i = 0;
        let mut u16_runs = Vec::new();

        while i + 1 < bytes.len() {
            let code = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            if code == 0x0D || code == 0x0A || (code >= 0x20 && code <= 0x024F) {
                run_16.push(code);
                i += 2;
            } else {
                if run_16.len() >= 4 {
                    let decoded: String = char::decode_utf16(run_16.iter().copied())
                        .map(|r| r.unwrap_or(' '))
                        .collect();
                    if decoded.trim().len() >= 4 {
                        u16_runs.push(decoded.trim().to_string());
                    }
                }
                run_16.clear();
                i += 1;
            }
        }
        if run_16.len() >= 4 {
            let decoded: String = char::decode_utf16(run_16.iter().copied())
                .map(|r| r.unwrap_or(' '))
                .collect();
            if decoded.trim().len() >= 4 {
                u16_runs.push(decoded.trim().to_string());
            }
        }

        if !u16_runs.is_empty() {
            out.push_str(&u16_runs.join("\n"));
            return out;
        }

        let mut run = String::new();
        for &b in bytes {
            if (0x20..=0x7E).contains(&b) || b == 0x09 || b == 0x0A || b == 0x0D || b >= 0xA0 {
                run.push(b as char);
            } else {
                if run.trim().len() >= 4 {
                    out.push_str(run.trim());
                    out.push('\n');
                }
                run.clear();
            }
        }
        if run.trim().len() >= 4 {
            out.push_str(run.trim());
        }
        out
    }

    /// Extracts clean prose from HTML files, stripping `<script>` and `<style>` blocks and decoding entities.
    pub fn extract_html_prose(path: &Path) -> io::Result<String> {
        let raw = Self::read_any_text_encoding(path)?;
        Ok(Self::clean_html_prose(&raw))
    }

    /// Strips `<script>` and `<style>` blocks, removes HTML tags, and decodes HTML entities into clean prose.
    pub fn clean_html_prose(html: &str) -> String {
        let without_script = if let Ok(re) = regex::RegexBuilder::new(r"(?is)<script\b[^>]*>.*?</script>")
            .build()
        {
            re.replace_all(html, " ").to_string()
        } else {
            html.to_string()
        };

        let without_style = if let Ok(re) = regex::RegexBuilder::new(r"(?is)<style\b[^>]*>.*?</style>")
            .build()
        {
            re.replace_all(&without_script, " ").to_string()
        } else {
            without_script
        };

        let block_spaced = if let Ok(re) = regex::RegexBuilder::new(r"(?i)</(?:p|div|h[1-6]|li|tr|blockquote|section|article)>")
            .build()
        {
            re.replace_all(&without_style, "\n").to_string()
        } else {
            without_style
        };

        let tag_regex = regex::Regex::new(r"<[^>]+>").unwrap();
        let stripped = tag_regex.replace_all(&block_spaced, " ");

        let decoded = Self::decode_html_entities(&stripped);

        let mut lines = Vec::new();
        for line in decoded.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                lines.push(trimmed);
            }
        }
        lines.join("\n\n")
    }

    /// Decodes common named, decimal, and hex HTML entities.
    fn decode_html_entities(text: &str) -> String {
        let mut s = text
            .replace("&nbsp;", " ")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&#39;", "'")
            .replace("&ndash;", "–")
            .replace("&mdash;", "—")
            .replace("&hellip;", "…")
            .replace("&lsquo;", "‘")
            .replace("&rsquo;", "’")
            .replace("&ldquo;", "“")
            .replace("&rdquo;", "”");

        if let Ok(re_dec) = regex::Regex::new(r"&#(\d+);") {
            s = re_dec
                .replace_all(&s, |caps: &regex::Captures| {
                    if let Ok(num) = caps[1].parse::<u32>() {
                        if let Some(ch) = char::from_u32(num) {
                            return ch.to_string();
                        }
                    }
                    caps[0].to_string()
                })
                .to_string();
        }

        if let Ok(re_hex) = regex::Regex::new(r"(?i)&#x([0-9a-f]+);") {
            s = re_hex
                .replace_all(&s, |caps: &regex::Captures| {
                    if let Ok(num) = u32::from_str_radix(&caps[1], 16) {
                        if let Some(ch) = char::from_u32(num) {
                            return ch.to_string();
                        }
                    }
                    caps[0].to_string()
                })
                .to_string();
        }

        s
    }

    /// Pure-Rust OpenXML (`docProps/core.xml`, `docProps/app.xml`) & OpenDocument (`meta.xml`)
    /// internal document metadata harvester (`doc_title`, `doc_author`, `doc_revision`, etc.).
    pub fn extract_openxml_core_props(bytes: &[u8]) -> HashMap<String, String> {
        let mut meta = HashMap::new();
        let entries = Self::read_zip_entries(bytes);
        if entries.is_empty() {
            return meta;
        }

        let extract_tag = |xml: &str, tag_names: &[&str]| -> Option<String> {
            for tag in tag_names {
                let open_pat = format!("<{}", tag);
                let close_pat = format!("</{}>", tag);
                let mut search_from = 0usize;
                while let Some(rel_start) = xml[search_from..].find(&open_pat) {
                    let abs_start = search_from + rel_start;
                    let after_tag = abs_start + open_pat.len();
                    if let Some(ch) = xml[after_tag..].chars().next() {
                        if ch != '>' && !ch.is_ascii_whitespace() && ch != '/' {
                            search_from = after_tag;
                            continue;
                        }
                    }
                    let Some(gt_rel) = xml[after_tag..].find('>') else {
                        break;
                    };
                    let gt_abs = after_tag + gt_rel;
                    if xml[after_tag..gt_abs].ends_with('/') {
                        search_from = gt_abs + 1;
                        continue;
                    }
                    let content_start = gt_abs + 1;
                    if let Some(end_rel) = xml[content_start..].find(&close_pat) {
                        let raw_inner = &xml[content_start..content_start + end_rel];
                        let cleaned = Self::decode_html_entities(raw_inner).trim().to_string();
                        if !cleaned.is_empty() {
                            return Some(cleaned);
                        }
                        search_from = content_start + end_rel + close_pat.len();
                    } else {
                        break;
                    }
                }
            }
            None
        };

        if let Some(core_bytes) = entries.get("docProps/core.xml").or_else(|| entries.get("meta.xml")) {
            let xml = String::from_utf8_lossy(core_bytes);
            if let Some(v) = extract_tag(&xml, &["dc:title", "title"]) {
                meta.insert("doc_title".to_string(), v);
            }
            if let Some(v) = extract_tag(&xml, &["dc:creator", "meta:initial-creator", "creator"]) {
                meta.insert("doc_author".to_string(), v);
            }
            if let Some(v) = extract_tag(&xml, &["dc:subject", "subject"]) {
                meta.insert("doc_subject".to_string(), v);
            }
            if let Some(v) = extract_tag(&xml, &["dc:description", "description"]) {
                meta.insert("doc_description".to_string(), v);
            }
            if let Some(v) = extract_tag(&xml, &["cp:keywords", "meta:keyword", "keywords"]) {
                meta.insert("doc_keywords".to_string(), v);
            }
            if let Some(v) = extract_tag(&xml, &["cp:lastModifiedBy", "dc:creator"]) {
                meta.entry("doc_last_modified_by".to_string()).or_insert(v);
            }
            if let Some(v) = extract_tag(&xml, &["cp:revision", "meta:editing-cycles"]) {
                meta.insert("doc_revision".to_string(), v);
            }
            if let Some(v) = extract_tag(&xml, &["dcterms:created", "meta:creation-date"]) {
                meta.insert("doc_created".to_string(), v);
            }
            if let Some(v) = extract_tag(&xml, &["dcterms:modified", "dc:date"]) {
                meta.insert("doc_modified".to_string(), v);
            }
        }

        if let Some(app_bytes) = entries.get("docProps/app.xml") {
            let xml = String::from_utf8_lossy(app_bytes);
            if let Some(v) = extract_tag(&xml, &["Application"]) {
                meta.insert("doc_application".to_string(), v);
            }
            if let Some(v) = extract_tag(&xml, &["Company"]) {
                meta.insert("doc_company".to_string(), v);
            }
        }

        meta
    }

    /// Pure-Rust multi-sheet OpenXML (`.xlsx`) & OpenDocument (`.ods`) workbook parser.
    /// Resolves `xl/sharedStrings.xml` indices, maps `xl/workbook.xml` sheet names, and emits
    /// structured `=== Sheet: <name> ===` tab-delimited rows so RLM `peek_slice` and `regex_grep`
    /// preserve complete multi-column financial and engineering tables.
    pub fn extract_ooxml_spreadsheet_native(bytes: &[u8]) -> Option<String> {
        let entries = Self::read_zip_entries(bytes);
        if entries.is_empty() {
            return None;
        }

        let extract_attr = |tag_header: &str, attr_name: &str| -> Option<String> {
            for quote in ['"', '\''] {
                let pat = format!("{}={}", attr_name, quote);
                if let Some(pos) = tag_header.find(&pat) {
                    let start = pos + pat.len();
                    if let Some(end) = tag_header[start..].find(quote) {
                        return Some(Self::decode_html_entities(&tag_header[start..start + end]));
                    }
                }
            }
            None
        };

        let extract_t_runs = |fragment: &str| -> String {
            let mut buf = String::new();
            let mut cursor = 0usize;
            while let Some(rel) = fragment[cursor..].find('<') {
                let lt = cursor + rel;
                let Some(gt_rel) = fragment[lt..].find('>') else {
                    break;
                };
                let gt = lt + gt_rel;
                let header = &fragment[lt + 1..gt];
                let tag_token = header.split_whitespace().next().unwrap_or("");
                // Skip phonetic pronunciation runs `<rPh>...</rPh>`
                if tag_token == "rPh" || tag_token.ends_with(":rPh") {
                    if let Some(end_rph) = fragment[gt + 1..].find("</rPh>") {
                        cursor = gt + 1 + end_rph + 6;
                        continue;
                    }
                }
                let is_t = (tag_token == "t" || tag_token.ends_with(":t")) && !header.ends_with('/');
                if is_t {
                    let val_start = gt + 1;
                    let close_rel = fragment[val_start..]
                        .find("</t>")
                        .or_else(|| fragment[val_start..].find(":t>").and_then(|p| fragment[val_start..val_start + p].rfind("</")));
                    if let Some(c_rel) = close_rel {
                        buf.push_str(&Self::decode_html_entities(&fragment[val_start..val_start + c_rel]));
                        cursor = val_start + c_rel + 4;
                        continue;
                    }
                }
                cursor = gt + 1;
            }
            buf
        };

        // 1. Parse xl/sharedStrings.xml into 0-based lookup table
        let mut shared_strings: Vec<String> = Vec::new();
        if let Some(ss_bytes) = entries.get("xl/sharedStrings.xml") {
            let ss_xml = String::from_utf8_lossy(ss_bytes);
            let mut cursor = 0usize;
            while let Some(si_rel) = ss_xml[cursor..].find("<si") {
                let si_start = cursor + si_rel;
                let after = si_start + 3;
                if let Some(ch) = ss_xml[after..].chars().next() {
                    if ch != '>' && !ch.is_ascii_whitespace() && ch != '/' {
                        cursor = after;
                        continue;
                    }
                }
                let Some(gt_rel) = ss_xml[after..].find('>') else { break; };
                let gt = after + gt_rel;
                if ss_xml[after..gt].ends_with('/') {
                    shared_strings.push(String::new());
                    cursor = gt + 1;
                    continue;
                }
                if let Some(end_rel) = ss_xml[gt + 1..].find("</si>") {
                    let inner = &ss_xml[gt + 1..gt + 1 + end_rel];
                    shared_strings.push(extract_t_runs(inner));
                    cursor = gt + 1 + end_rel + 5;
                } else {
                    break;
                }
            }
        }

        // 2. Map sheet tab names via xl/workbook.xml + xl/_rels/workbook.xml.rels
        let mut rel_id_to_target: HashMap<String, String> = HashMap::new();
        if let Some(rels_bytes) = entries.get("xl/_rels/workbook.xml.rels") {
            let rels_xml = String::from_utf8_lossy(rels_bytes);
            let mut cursor = 0usize;
            while let Some(rel) = rels_xml[cursor..].find("<Relationship") {
                let st = cursor + rel;
                let Some(gt) = rels_xml[st..].find('>') else { break; };
                let hdr = &rels_xml[st..st + gt];
                if let (Some(id), Some(target)) = (extract_attr(hdr, "Id"), extract_attr(hdr, "Target")) {
                    let norm = target.trim_start_matches('/');
                    let full = if norm.starts_with("xl/") {
                        norm.to_string()
                    } else {
                        format!("xl/{}", norm)
                    };
                    rel_id_to_target.insert(id, full);
                }
                cursor = st + gt + 1;
            }
        }

        let mut ordered_sheets: Vec<(String, String)> = Vec::new();
        if let Some(wb_bytes) = entries.get("xl/workbook.xml") {
            let wb_xml = String::from_utf8_lossy(wb_bytes);
            let mut cursor = 0usize;
            let mut idx = 1usize;
            while let Some(rel) = wb_xml[cursor..].find("<sheet") {
                let st = cursor + rel;
                let after = st + 6;
                if let Some(ch) = wb_xml[after..].chars().next() {
                    if !ch.is_ascii_whitespace() {
                        cursor = after;
                        continue;
                    }
                }
                let Some(gt) = wb_xml[st..].find('>') else { break; };
                let hdr = &wb_xml[st..st + gt];
                if let Some(name) = extract_attr(hdr, "name") {
                    let rid = extract_attr(hdr, "r:id").unwrap_or_default();
                    let target = rel_id_to_target
                        .get(&rid)
                        .cloned()
                        .unwrap_or_else(|| format!("xl/worksheets/sheet{}.xml", idx));
                    ordered_sheets.push((name, target));
                    idx += 1;
                }
                cursor = st + gt + 1;
            }
        }

        for entry_name in entries.keys() {
            if entry_name.starts_with("xl/worksheets/") && entry_name.ends_with(".xml") {
                if !ordered_sheets.iter().any(|(_, t)| t == entry_name) {
                    let fallback_name = Path::new(entry_name)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("Sheet")
                        .to_string();
                    ordered_sheets.push((fallback_name, entry_name.clone()));
                }
            }
        }

        // 3. Parse each worksheet's <row> and <c> cells
        let mut sheet_outputs: Vec<String> = Vec::new();
        for (sheet_name, entry_path) in &ordered_sheets {
            let Some(ws_bytes) = entries.get(entry_path) else { continue; };
            let ws_xml = String::from_utf8_lossy(ws_bytes);
            let mut sheet_lines = vec![format!("=== Sheet: {} ===", sheet_name)];
            let mut row_cursor = 0usize;
            while let Some(r_rel) = ws_xml[row_cursor..].find("<row") {
                let r_st = row_cursor + r_rel;
                let r_after = r_st + 4;
                if let Some(ch) = ws_xml[r_after..].chars().next() {
                    if ch != '>' && !ch.is_ascii_whitespace() && ch != '/' {
                        row_cursor = r_after;
                        continue;
                    }
                }
                let Some(r_gt_rel) = ws_xml[r_after..].find('>') else { break; };
                let r_gt = r_after + r_gt_rel;
                if ws_xml[r_after..r_gt].ends_with('/') {
                    row_cursor = r_gt + 1;
                    continue;
                }
                let Some(r_end_rel) = ws_xml[r_gt + 1..].find("</row>") else { break; };
                let row_inner = &ws_xml[r_gt + 1..r_gt + 1 + r_end_rel];
                row_cursor = r_gt + 1 + r_end_rel + 6;

                let mut cells: Vec<String> = Vec::new();
                let mut c_cursor = 0usize;
                while let Some(c_rel) = row_inner[c_cursor..].find("<c") {
                    let c_st = c_cursor + c_rel;
                    let c_after = c_st + 2;
                    if let Some(ch) = row_inner[c_after..].chars().next() {
                        if ch != '>' && !ch.is_ascii_whitespace() && ch != '/' {
                            c_cursor = c_after;
                            continue;
                        }
                    }
                    let Some(c_gt_rel) = row_inner[c_after..].find('>') else { break; };
                    let c_gt = c_after + c_gt_rel;
                    let c_hdr = &row_inner[c_st..c_gt];
                    if c_hdr.ends_with('/') {
                        c_cursor = c_gt + 1;
                        continue;
                    }
                    let Some(c_end_rel) = row_inner[c_gt + 1..].find("</c>") else { break; };
                    let cell_inner = &row_inner[c_gt + 1..c_gt + 1 + c_end_rel];
                    c_cursor = c_gt + 1 + c_end_rel + 4;

                    let cell_type = extract_attr(c_hdr, "t").unwrap_or_default();
                    let raw_v = if let Some(v_st) = cell_inner.find("<v>") {
                        cell_inner[v_st + 3..]
                            .find("</v>")
                            .map(|v_end| Self::decode_html_entities(&cell_inner[v_st + 3..v_st + 3 + v_end]))
                            .unwrap_or_default()
                    } else if let Some(v_st) = cell_inner.find("<v ") {
                        cell_inner[v_st..]
                            .find('>')
                            .and_then(|gt| {
                                let st = v_st + gt + 1;
                                cell_inner[st..].find("</v>").map(|en| Self::decode_html_entities(&cell_inner[st..st + en]))
                            })
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };

                    let resolved = match cell_type.as_str() {
                        "s" => raw_v
                            .trim()
                            .parse::<usize>()
                            .ok()
                            .and_then(|i| shared_strings.get(i).cloned())
                            .unwrap_or(raw_v),
                        "inlineStr" => extract_t_runs(cell_inner),
                        "b" => {
                            if raw_v.trim() == "1" {
                                "TRUE".to_string()
                            } else if raw_v.trim() == "0" {
                                "FALSE".to_string()
                            } else {
                                raw_v
                            }
                        }
                        _ => {
                            if !raw_v.is_empty() {
                                raw_v
                            } else {
                                extract_t_runs(cell_inner)
                            }
                        }
                    };
                    let trimmed = resolved.trim();
                    if !trimmed.is_empty() {
                        cells.push(trimmed.replace('\t', " "));
                    }
                }

                if !cells.is_empty() {
                    sheet_lines.push(cells.join("\t"));
                }
            }

            if sheet_lines.len() > 1 {
                sheet_outputs.push(sheet_lines.join("\n"));
            }
        }

        if !sheet_outputs.is_empty() {
            return Some(sheet_outputs.join("\n\n"));
        }

        // OpenDocument Spreadsheet (.ods) fallback (`content.xml`)
        if let Some(ods_bytes) = entries.get("content.xml") {
            let xml = String::from_utf8_lossy(ods_bytes);
            let clean = Self::clean_html_prose(&xml);
            if !clean.trim().is_empty() {
                return Some(clean);
            }
        }

        None
    }

    /// Extracts all worksheets, shared strings, and cell values from `.xlsx`, `.xls`, or `.ods`.
    fn extract_spreadsheet_text(path: &Path) -> io::Result<String> {
        let bytes = std::fs::read(path)?;
        if let Some(structured) = Self::extract_ooxml_spreadsheet_native(&bytes) {
            return Ok(structured);
        }
        if bytes.starts_with(b"PK\x03\x04") {
            return Ok(String::new());
        }
        Ok(Self::extract_printable_strings(&bytes, path, "Spreadsheet"))
    }

    /// User-space OS Search index fallback for files exclusively locked by another process.
    /// Queries Windows Search (`Search.CollatorDSO` OLE DB) on Windows or Spotlight (`mdls`) on macOS
    /// strictly in standard user space — zero Admin privileges, zero raw `$MFT` or `Windows.edb` access.
    pub fn query_os_search_index_fallback(path: &Path) -> Option<(String, HashMap<String, String>)> {
        #[cfg(windows)]
        {
            let abs = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
            let clean_path = abs.to_string_lossy().trim_start_matches(r"\\?\").to_string();
            let ps_script = r#"
$ErrorActionPreference = 'Stop'
$targetPath = $args[0]
if (-not $targetPath) { exit 1 }
$escaped = $targetPath.Replace("'", "''")
$conn = New-Object System.Data.OleDb.OleDbConnection("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")
$conn.Open()
try {
    $sql = "SELECT TOP 1 System.Title, System.Author, System.Subject, System.Keywords, System.Search.AutoSummary FROM SystemIndex WHERE System.ItemPathDisplay = '$escaped'"
    $cmd = New-Object System.Data.OleDb.OleDbCommand($sql, $conn)
    $reader = $cmd.ExecuteReader()
    if ($reader.Read()) {
        $obj = @{
            title = [string]$reader.GetValue(0)
            author = [string]$reader.GetValue(1)
            subject = [string]$reader.GetValue(2)
            keywords = [string]$reader.GetValue(3)
            summary = [string]$reader.GetValue(4)
        }
        $obj | ConvertTo-Json -Compress
    }
    $reader.Close()
} finally {
    $conn.Close()
}
"#;
            let output = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    ps_script,
                ])
                .arg(&clean_path)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            let trimmed = stdout.trim();
            if trimmed.is_empty() {
                return None;
            }
            let val: serde_json::Value = serde_json::from_str(trimmed).ok()?;
            let mut meta = HashMap::new();
            let mut parts = Vec::new();
            for (json_key, meta_key, label) in [
                ("title", "doc_title", "Title"),
                ("author", "doc_author", "Author"),
                ("subject", "doc_subject", "Subject"),
                ("keywords", "doc_keywords", "Keywords"),
                ("summary", "os_search_summary", "Indexed Summary"),
            ] {
                if let Some(s) = val.get(json_key).and_then(|v| v.as_str()) {
                    let s = s.trim();
                    if !s.is_empty() {
                        meta.insert(meta_key.to_string(), s.to_string());
                        parts.push(format!("{}: {}", label, s));
                    }
                }
            }
            if parts.is_empty() {
                return None;
            }
            meta.insert("extraction_source".to_string(), "windows_search_oledb".to_string());
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("document");
            let text = format!(
                "[OS Search Cached Summary — {}]\n{}",
                file_name,
                parts.join("\n")
            );
            return Some((text, meta));
        }

        #[cfg(target_os = "macos")]
        {
            let output = Command::new("mdls")
                .arg("-name")
                .arg("kMDItemTitle")
                .arg("-name")
                .arg("kMDItemAuthors")
                .arg("-name")
                .arg("kMDItemSubject")
                .arg("-name")
                .arg("kMDItemTextContent")
                .arg(path.as_os_str())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .output()
                .ok()?;
            if !output.status.success() {
                return None;
            }
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if text.is_empty() || text.lines().all(|l| l.ends_with("(null)")) {
                return None;
            }
            let mut meta = HashMap::new();
            meta.insert("extraction_source".to_string(), "macos_spotlight_mdls".to_string());
            return Some((text, meta));
        }

        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = path;
            None
        }
    }

    /// Builds a canonical `IngestedParentDocument` record containing the unchunked full text
    /// and internal OpenXML / PDF / OS Search metadata (`doc_title`, `doc_author`, `doc_revision`).
    pub fn build_ingested_parent_document(
        path: &Path,
        doc_id: &str,
        blake3_hash: &str,
        full_text: &str,
        mtime_secs: i64,
        size_bytes: u64,
        override_format: Option<quorum_types::DocumentFormat>,
    ) -> quorum_types::IngestedParentDocument {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let format = if full_text.starts_with("[OS Search Cached Summary") {
            quorum_types::DocumentFormat::OsSearchSnippetFallback
        } else {
            override_format.unwrap_or_else(|| quorum_types::DocumentFormat::from_extension(&ext))
        };

        let created_unix_secs = std::fs::metadata(path)
            .and_then(|m| m.created())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(mtime_secs);

        let mut metadata: HashMap<String, String> = HashMap::new();
        metadata.insert("file_size_bytes".to_string(), size_bytes.to_string());

        if matches!(ext.as_str(), "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp") {
            if let Ok(bytes) = std::fs::read(path) {
                for (k, v) in Self::extract_openxml_core_props(&bytes) {
                    metadata.insert(k, v);
                }
            }
        }

        // Parse PDF Metadata header line if present (`[PDF Metadata] Title: ... | Author: ...`)
        for line in full_text.lines().take(5) {
            if let Some(rest) = line.trim().strip_prefix("[PDF Metadata]") {
                for seg in rest.split('|') {
                    if let Some((k, v)) = seg.split_once(':') {
                        let key_l = k.trim().to_ascii_lowercase();
                        let val = v.trim();
                        if val.is_empty() {
                            continue;
                        }
                        match key_l.as_str() {
                            "title" => {
                                metadata.entry("doc_title".to_string()).or_insert_with(|| val.to_string());
                            }
                            "author" => {
                                metadata.entry("doc_author".to_string()).or_insert_with(|| val.to_string());
                            }
                            "subject" => {
                                metadata.entry("doc_subject".to_string()).or_insert_with(|| val.to_string());
                            }
                            "creator" | "producer" => {
                                metadata.entry(format!("pdf_{}", key_l)).or_insert_with(|| val.to_string());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let title = metadata
            .get("doc_title")
            .cloned()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.replace(['_', '-'], " "))
            });
        let author = metadata
            .get("doc_author")
            .cloned()
            .filter(|s| !s.trim().is_empty());

        quorum_types::IngestedParentDocument {
            doc_id: doc_id.to_string(),
            blake3_hash: blake3_hash.to_string(),
            source_path: path.to_string_lossy().to_string(),
            os_platform: std::env::consts::OS.to_string(),
            format,
            title,
            author,
            created_unix_secs,
            modified_unix_secs: mtime_secs,
            byte_len: full_text.len() as u64,
            full_text: full_text.to_string(),
            metadata,
        }
    }

    /// Extracts all slide text runs and speaker notes from `.pptx`, `.ppt`, or `.odp`.
    fn extract_presentation_text(path: &Path) -> io::Result<String> {
        let bytes = std::fs::read(path)?;
        let entries = Self::read_zip_entries(&bytes);
        if !entries.is_empty() {
            let mut out = Vec::new();
            for (name, data) in &entries {
                if name.ends_with(".xml")
                    && (name.contains("slides/slide")
                        || name.contains("notesSlides/")
                        || name == "content.xml")
                {
                    let xml = String::from_utf8_lossy(data);
                    let text = Self::extract_word_xml_runs(&xml, name == "content.xml");
                    if !text.is_empty() {
                        out.push(text);
                    }
                }
            }
            if !out.is_empty() {
                return Ok(out.join("\n\n"));
            }
            return Ok(String::new());
        }

        Ok(Self::extract_printable_strings(&bytes, path, "Presentation"))
    }

    /// Strips RTF control words and hex sequences to extract clean text.
    fn extract_rtf_text(path: &Path) -> io::Result<String> {
        let raw = Self::read_any_text_encoding(path)?;
        let mut out = String::with_capacity(raw.len());
        let mut chars = raw.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(&next) = chars.peek() {
                    if next == '\'' {
                        let _ = chars.next();
                        let _ = chars.next();
                        let _ = chars.next();
                        out.push(' ');
                        continue;
                    }
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_alphanumeric() || c == '-' {
                            let _ = chars.next();
                        } else {
                            if c == ' ' {
                                let _ = chars.next();
                            }
                            break;
                        }
                    }
                }
            } else if ch == '{' || ch == '}' {
                out.push(' ');
            } else {
                out.push(ch);
            }
        }
        Ok(out.split_whitespace().collect::<Vec<_>>().join(" "))
    }

    /// Extracts all XHTML/HTML chapters from an `.epub` archive natively in Rust.
    fn extract_epub_text(path: &Path) -> io::Result<String> {
        let bytes = std::fs::read(path)?;
        let entries = Self::read_zip_entries(&bytes);
        if !entries.is_empty() {
            let mut out = Vec::new();
            for (name, data) in &entries {
                if name.ends_with(".xhtml")
                    || name.ends_with(".html")
                    || name.ends_with(".htm")
                    || name.ends_with(".opf")
                {
                    let raw = String::from_utf8_lossy(data);
                    let clean = Self::clean_html_prose(&raw);
                    if !clean.is_empty() {
                        out.push(clean);
                    }
                }
            }
            if !out.is_empty() {
                return Ok(out.join("\n\n"));
            }
            return Ok(String::new());
        }

        Ok(Self::extract_printable_strings(&bytes, path, "EPUB"))
    }

    /// Extracts all Markdown cells, code cells, and text outputs from a Jupyter Notebook (`.ipynb`).
    fn extract_ipynb_text(path: &Path) -> io::Result<String> {
        let raw = Self::read_any_text_encoding(path)?;
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(cells) = json.get("cells").and_then(|c| c.as_array()) {
                let mut out = Vec::new();
                for (idx, cell) in cells.iter().enumerate() {
                    let cell_type = cell
                        .get("cell_type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("cell");
                    if let Some(source) = cell.get("source") {
                        let text = if let Some(arr) = source.as_array() {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join("")
                        } else {
                            source.as_str().unwrap_or("").to_string()
                        };
                        if !text.trim().is_empty() {
                            out.push(format!("[Notebook Cell {} ({})]\n{}", idx + 1, cell_type, text.trim()));
                        }
                    }
                }
                if !out.is_empty() {
                    return Ok(out.join("\n\n"));
                }
            }
        }
        Ok(raw)
    }

    /// Extracts schema (`sqlite_master`) and sample rows from a SQLite 3 database natively via `rusqlite`.
    fn extract_sqlite_text(path: &Path) -> io::Result<String> {
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if let Ok(conn) = rusqlite::Connection::open_with_flags(path, flags) {
            let mut out = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL",
            ) {
                let rows: Vec<(String, String, String)> = stmt
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                    .map(|it| it.flatten().collect())
                    .unwrap_or_default();
                for (t_type, name, sql) in rows {
                    out.push(format!("[{}: {}] {}", t_type.to_ascii_uppercase(), name, sql));
                    if t_type == "table" && !name.starts_with("sqlite_") {
                        let safe_ident = name.replace('"', "\"\"");
                        if let Ok(mut q) =
                            conn.prepare(&format!("SELECT * FROM \"{}\" LIMIT 25", safe_ident))
                        {
                            let col_cnt = q.column_count();
                            if let Ok(mut data_rows) = q.query([]) {
                                while let Ok(Some(row)) = data_rows.next() {
                                    let mut vals = Vec::new();
                                    for idx in 0..col_cnt {
                                        if let Ok(v_ref) = row.get_ref(idx) {
                                            let s = match v_ref {
                                                rusqlite::types::ValueRef::Null => continue,
                                                rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                                                rusqlite::types::ValueRef::Real(f) => f.to_string(),
                                                rusqlite::types::ValueRef::Text(b) => {
                                                    String::from_utf8_lossy(b).into_owned()
                                                }
                                                rusqlite::types::ValueRef::Blob(_) => continue,
                                            };
                                            if !s.trim().is_empty() {
                                                vals.push(s);
                                            }
                                        }
                                    }
                                    if !vals.is_empty() {
                                        out.push(vals.join(" | "));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if !out.is_empty() {
                return Ok(out.join("\n"));
            }
        }

        let bytes = std::fs::read(path)?;
        Ok(Self::extract_printable_strings(&bytes, path, "SQLite Database"))
    }

    /// Extracts printable ASCII/UTF-8 strings from structured binary data files (`pcap`, `parquet`, etc.).
    fn extract_binary_data_strings(path: &Path, identity: &FileIdentity) -> io::Result<String> {
        let bytes = std::fs::read(path)?;
        Ok(Self::extract_printable_strings(
            &bytes,
            path,
            &format!("{} ({})", identity.description, identity.mime_type),
        ))
    }

    /// Pure-Rust fallback extractor for PDF parenthesized text literals `( ... )`, filtering out
    /// XMP XML metadata packets and raw PDF dictionary/trailer keys.
    fn extract_pdf_streams_fallback(bytes: &[u8], path: &Path) -> String {
        let mut out = String::new();
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            out.push_str(&stem.replace('_', " "));
            out.push('\n');
        }
        let lossy = String::from_utf8_lossy(bytes);
        let mut in_parens = false;
        let mut current = String::new();
        for ch in lossy.chars() {
            if ch == '(' && !in_parens {
                in_parens = true;
                current.clear();
            } else if ch == ')' && in_parens {
                in_parens = false;
                let trimmed = current.trim();
                let tl = trimmed.to_ascii_lowercase();
                if trimmed.len() >= 2
                    && !tl.starts_with("d:20")
                    && !tl.starts_with("d:19")
                    && !tl.contains("adobe ")
                    && !tl.contains("reportlab")
                    && !tl.contains("skia/pdf")
                    && trimmed
                        .chars()
                        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                {
                    out.push_str(trimmed);
                    out.push(' ');
                }
            } else if in_parens {
                current.push(ch);
            }
        }
        out.trim().to_string()
    }

    /// Extracts contiguous printable ASCII sequences (>= 4 chars) from binary containers.
    fn extract_printable_strings(bytes: &[u8], path: &Path, header_label: &str) -> String {
        let mut out = format!(
            "[{} — {}]\n",
            header_label,
            path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
        );
        let mut run = String::new();
        for &b in bytes.iter().take(256 * 1024) {
            if (0x20..=0x7E).contains(&b) {
                run.push(b as char);
            } else {
                if run.trim().len() >= 4 {
                    out.push_str(run.trim());
                    out.push('\n');
                }
                run.clear();
            }
        }
        if run.trim().len() >= 4 {
            out.push_str(run.trim());
        }
        out
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::{DeflateEncoder, ZlibEncoder};
    use flate2::Compression;
    use quorum_classifier::FileTypeClassifier;
    use std::io::Write;

    /// Builds a valid PKZIP archive in memory (with Deflate method 8) for testing native `.docx` extraction.
    fn build_test_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut central = Vec::new();
        for &(name, raw) in files {
            let local_offset = buf.len() as u32;
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
            enc.write_all(raw).unwrap();
            let comp = enc.finish().unwrap();
            let name_b = name.as_bytes();

            // Local file header (0x04034b50)
            buf.extend_from_slice(b"PK\x03\x04");
            buf.extend_from_slice(&20u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&8u16.to_le_bytes()); // Deflate
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            buf.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes());
            buf.extend_from_slice(name_b);
            buf.extend_from_slice(&comp);

            // Central directory header (0x02014b50)
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&8u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&(comp.len() as u32).to_le_bytes());
            central.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(name_b);
        }
        let cd_offset = buf.len() as u32;
        let cd_size = central.len() as u32;
        buf.extend_from_slice(&central);

        // End of Central Directory (0x06054b50)
        buf.extend_from_slice(b"PK\x05\x06");
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&(files.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(files.len() as u16).to_le_bytes());
        buf.extend_from_slice(&cd_size.to_le_bytes());
        buf.extend_from_slice(&cd_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf
    }

    #[test]
    fn test_native_docx_extracts_tables_timeline_textboxes_and_skips_fallback_duplicates() {
        let doc_xml = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
                    xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
                    xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
          <w:body>
            <w:p><w:r><w:t>Femi Oyesanya — AI &amp; Application Security Resume Timeline</w:t></w:r></w:p>
            <w:tbl>
              <w:tr>
                <w:tc><w:p><w:r><w:t>2022 – Present</w:t></w:r></w:p></w:tc>
                <w:tc><w:p><w:r><w:t>Principal AI Security Architect</w:t></w:r></w:p></w:tc>
              </w:tr>
              <w:tr>
                <w:tc><w:p><w:r><w:t>2018 – 2022</w:t></w:r></w:p></w:tc>
                <w:tc><w:p><w:r><w:t>Lead Application Security Engineer</w:t></w:r></w:p></w:tc>
              </w:tr>
            </w:tbl>
            <w:p>
              <mc:AlternateContent>
                <mc:Choice Requires="wps">
                  <w:txbxContent><w:p><w:r><w:t>Senior Security Consultant (2014 – 2018)</w:t></w:r></w:p></w:txbxContent>
                </mc:Choice>
                <mc:Fallback>
                  <w:txbxContent><w:p><w:r><w:t>Senior Security Consultant (2014 – 2018)</w:t></w:r></w:p></w:txbxContent>
                </mc:Fallback>
              </mc:AlternateContent>
            </w:p>
          </w:body>
        </w:document>"#.as_bytes();

        let zip_bytes = build_test_zip(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", doc_xml),
        ]);
        let extracted = DocumentExtractor::extract_ooxml_word_or_odt_native(&zip_bytes)
            .expect("native docx extraction");

        assert!(extracted.contains("Femi Oyesanya — AI & Application Security Resume Timeline"));
        assert!(extracted.contains("2022 – Present | Principal AI Security Architect"));
        assert!(extracted.contains("2018 – 2022 | Lead Application Security Engineer"));
        assert_eq!(
            extracted.matches("Senior Security Consultant (2014 – 2018)").count(),
            1,
            "mc:Fallback duplicate textbox must be skipped"
        );
        assert!(!extracted.contains("[Content_Types].xml"));
    }

    #[test]
    fn test_native_pdf_flatedecode_and_tj_array_extraction() {
        let content_stream = b"BT /F1 12 Tf 72 720 Td [(Femi) -200 (Oyesanya) -180 (- ) (Principal) -160 (AI) -150 (Security) -170 (Architect)] TJ 0 -18 Td (Lead Application Security Engineer 2018 - 2022) Tj ET";
        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(content_stream).unwrap();
        let compressed = zlib.finish().unwrap();

        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.7\n1 0 obj\n<< /Length ");
        pdf.extend_from_slice(compressed.len().to_string().as_bytes());
        pdf.extend_from_slice(b" /Filter /FlateDecode >>\nstream\r\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\r\nendstream\nendobj\n%%EOF");

        let extracted = DocumentExtractor::extract_pdf_native_rust(&pdf);
        assert!(
            extracted.contains("Femi Oyesanya - Principal AI Security Architect"),
            "Got: {}",
            extracted
        );
        assert!(
            extracted.contains("Lead Application Security Engineer 2018 - 2022"),
            "Got: {}",
            extracted
        );
    }

    #[test]
    fn test_is_degraded_document_chunk_detects_zip_xml_fallback() {
        let poisoned = "[Document: \"Resume\" | File: Resume.docx]\n[Word/Document (docx) — Resume.docx]\n[Content_Types].xml\n_rels/.rels\nword/document.xml";
        assert!(DocumentExtractor::is_degraded_document_chunk(
            "D:\\docs\\Resume.docx",
            poisoned
        ));
        let healthy = "[Document: \"Resume\" | File: Resume.docx]\nFemi Oyesanya — Principal AI Security Architect (2022–Present), Lead Application Security Engineer (2018–2022), CISSP Certified.";
        assert!(!DocumentExtractor::is_degraded_document_chunk(
            "D:\\docs\\Resume.docx",
            healthy
        ));
    }

    #[test]
    fn test_extract_pdf_femi_oyesanya_transcript() {
        let pdf_path = Path::new(
            r"D:\harfile\Mechanistic_Interpretability\probe_and_tools\Oyesanya_Femi_0754749_5_15_2026.pdf",
        );
        if pdf_path.exists() {
            let classifier = FileTypeClassifier::new();
            let identity = classifier.classify_file(pdf_path).expect("classify pdf");
            let text = DocumentExtractor::extract_text(pdf_path, &identity).expect("extract pdf");
            assert!(
                text.contains("Eastern University"),
                "Expected PDF extraction to contain 'Eastern University', got: {}",
                text
            );
            assert!(
                text.contains("Femi Oyesanya"),
                "Expected PDF extraction to contain 'Femi Oyesanya'"
            );
        }
    }

    #[test]
    fn test_extract_docx_fixture() {
        let docx_path = Path::new(r"D:\harfile\ModelFusion\tests\fixtures\sample_resume.docx");
        if docx_path.exists() {
            let classifier = FileTypeClassifier::new();
            let identity = classifier.classify_file(docx_path).expect("classify docx");
            let text = DocumentExtractor::extract_text(docx_path, &identity).expect("extract docx");
            assert!(!text.is_empty(), "Expected non-empty DOCX extraction");
        }
    }

    #[test]
    fn test_extract_html_prose_strips_scripts_and_decodes_entities() {
        let html_content = r#"
            <!DOCTYPE html>
            <html>
            <head>
                <style>body { color: red; } p { font-size: 14px; }</style>
                <script type="text/javascript">
                    console.log("alert('secret tracking code');");
                </script>
            </head>
            <body>
                <h1>Research &amp; Analysis on Quorum Systems</h1>
                <p>QuorumRAG introduces a &ldquo;recursive language model&rdquo; architecture &mdash; arXiv:2512.24601.</p>
                <p>Numeric entities: &#65;&#66;&#67; and hex: &#x44;&#x45;&#x46;.</p>
            </body>
            </html>
        "#;

        let temp_dir = tempfile::tempdir().unwrap();
        let html_file = temp_dir.path().join("paper.html");
        std::fs::write(&html_file, html_content).unwrap();

        let extracted = DocumentExtractor::extract_html_prose(&html_file).unwrap();

        assert!(!extracted.contains("color: red"), "Styles should be stripped");
        assert!(!extracted.contains("secret tracking code"), "Scripts should be stripped");
        assert!(extracted.contains("Research & Analysis on Quorum Systems"), "Entities decoded");
        assert!(extracted.contains("“recursive language model” architecture — arXiv:2512.24601"), "Quotes and dashes decoded");
        assert!(extracted.contains("ABC and hex: DEF"), "Numeric entities decoded");
    }

    #[test]
    fn test_magic_byte_sniffing_misnamed_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let fake_pdf = temp_dir.path().join("fake_scan.pdf");
        let mut jpeg_bytes = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F'];
        jpeg_bytes.extend(vec![0u8; 100]);
        std::fs::write(&fake_pdf, &jpeg_bytes).unwrap();

        let classifier = FileTypeClassifier::new();
        let identity = classifier.classify_file(&fake_pdf).expect("classify");
        let _ = DocumentExtractor::extract_text(&fake_pdf, &identity);
    }
}
