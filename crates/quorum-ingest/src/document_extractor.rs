//! Universal Magika-Driven Document & Data Extractor for QuorumRAG (`quorum-ingest`).
//!
//! Extracts all searchable text, tables, pages, slides, sheets, schemas, and metadata
//! from every file discovered and accepted by Google Magika (`FileCategory::Document`,
//! `FileCategory::Text`, `FileCategory::Code`, `FileCategory::Data`):
//! - **PDF (`pdf`, `application/pdf`)**: Multi-page text & metadata via `pypdf`, Vision/OCR
//!   fallback for scanned pages, and native Rust PDF stream literal extraction fallback.
//! - **Word & OpenDocument (`docx`, `doc`, `odt`, `rtf`, `epub`)**: Paragraphs, tables, headers,
//!   and footers via `python-docx` / OpenXML (`word/document.xml`), `content.xml`, EPUB XHTML, and RTF stripping.
//! - **Excel & Spreadsheets (`xlsx`, `xls`, `ods`, `csv`, `tsv`)**: Sheet names, shared strings,
//!   and cell rows via `openpyxl` / OpenXML (`xl/sharedStrings.xml`, `xl/worksheets/*.xml`).
//! - **PowerPoint Presentations (`pptx`, `ppt`, `odp`)**: All slide text runs (`<a:t>`) and speaker notes.
//! - **Jupyter Notebooks (`ipynb`)**: Markdown cells, code cells, and execution text outputs.
//! - **SQLite Databases (`sqlite`, `application/vnd.sqlite3`)**: Table schemas (`sqlite_master`) and text rows.
//! - **Network Captures & Binary Data (`pcap`, `parquet`, etc.)**: Printable strings & header summaries.
//! - **Source Code, Markdown, Markup & Plain Text**: Full UTF-8, UTF-16LE/BE, and Latin-1/CP-1252 decoding.

use crate::error::IngestError;
use crate::image_indexer::ImageIndexer;
use quorum_classifier::{FileCategory, FileIdentity};
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::Path;
use std::process::Command;

/// Universal content extractor for every file discovered by Google Magika.
pub struct DocumentExtractor;

impl DocumentExtractor {
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

    /// Extracts all searchable UTF-8 text from any file discovered by Magika.
    pub fn extract_text(path: &Path, identity: &FileIdentity) -> io::Result<String> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let label = identity.label.to_ascii_lowercase();
        let mime = identity.mime_type.to_ascii_lowercase();

        // 0. Magic-byte sniffing before extension routing
        let mut magic_header = [0u8; 16];
        if let Ok(mut f) = std::fs::File::open(path) {
            let _ = f.read_exact(&mut magic_header);
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

        // 1. PDF Documents (multi-page text + metadata + OCR fallback + native stream fallback)
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

        // 3. Excel Spreadsheets (.xlsx, .xls, .ods)
        if label == "xlsx"
            || mime.contains("spreadsheetml")
            || matches!(ext.as_str(), "xlsx" | "xls" | "ods")
        {
            return Self::extract_spreadsheet_text(path);
        }

        // 4. PowerPoint Presentations (.pptx, .ppt, .odp)
        if label == "pptx"
            || mime.contains("presentationml")
            || matches!(ext.as_str(), "pptx" | "ppt" | "odp")
        {
            return Self::extract_presentation_text(path);
        }

        // 5. Rich Text Format (.rtf)
        if label == "rtf" || mime.contains("rtf") || ext == "rtf" {
            return Self::extract_rtf_text(path);
        }

        // 6. EPUB E-books (.epub)
        if label == "epub" || mime.contains("epub") || ext == "epub" {
            return Self::extract_epub_text(path);
        }

        // 7. Jupyter Notebooks (.ipynb)
        if label == "ipynb" || ext == "ipynb" {
            return Self::extract_ipynb_text(path);
        }

        // 8. SQLite 3 Databases (.sqlite, .db, .sqlite3)
        if label == "sqlite"
            || mime == "application/vnd.sqlite3"
            || matches!(ext.as_str(), "sqlite" | "sqlite3" | "db")
        {
            return Self::extract_sqlite_text(path);
        }

        // 9. Non-UTF8 Binary Data files classified under FileCategory::Data or Document (e.g. pcap, parquet)
        if !identity.is_text
            && matches!(identity.category, FileCategory::Data | FileCategory::Document)
        {
            return Self::extract_binary_data_strings(path, identity);
        }

        // 10. All Text, Source Code, Config, Markup, CSV/TSV/JSON/YAML/TOML/Markdown files
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

    /// Extracts all pages, metadata, and OCR-extracted text from a PDF file.
    fn extract_pdf_text(path: &Path) -> io::Result<String> {
        // Step 1: Attempt standard text and metadata extraction via pypdf
        let mut metadata_header = String::new();
        let direct_text = match Self::extract_pdf_via_pypdf(path) {
            Ok((meta, body)) => {
                metadata_header = meta;
                body
            }
            Err(_) => String::new(),
        };

        // Step 2: If direct text has genuine document content (>= 10 alphanumeric chars), return it directly
        if !Self::is_scanned_or_insufficient_text(&direct_text) {
            if metadata_header.is_empty() {
                return Ok(direct_text);
            } else {
                return Ok(format!("{}\n\n{}", metadata_header, direct_text));
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
        let bytes = std::fs::read(path)?;
        if let Ok(jpeg_ocr) = Self::extract_pdf_embedded_jpegs_ocr(&bytes) {
            if !jpeg_ocr.trim().is_empty() {
                if metadata_header.is_empty() {
                    return Ok(jpeg_ocr);
                } else {
                    return Ok(format!("{}\n\n{}", jpeg_ocr, metadata_header));
                }
            }
        }

        // Step 5: Pure-Rust stream literal fallback
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

    /// Extracts metadata and text layer using pypdf via python subprocess.
    fn extract_pdf_via_pypdf(path: &Path) -> io::Result<(String, String)> {
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

        let output = Command::new("python")
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

        let output = Command::new("python")
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


    /// Extracts all paragraphs, tables, headers, and footers from `.docx`, `.doc`, or `.odt`.
    fn extract_word_or_odt_text(path: &Path, ext: &str) -> io::Result<String> {
        if ext == "doc" {
            if let Ok(text) = Self::extract_ole2_doc_text(path) {
                if !text.trim().is_empty() {
                    return Ok(text);
                }
            }
        }

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

        if let Ok(output) = Command::new("python")
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

        let bytes = std::fs::read(path)?;
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

    /// Extracts all worksheets, shared strings, and cell values from `.xlsx`, `.xls`, or `.ods`.
    fn extract_spreadsheet_text(path: &Path) -> io::Result<String> {
        let script = [
            "import sys, zipfile, xml.etree.ElementTree as ET",
            "sys.stdout.reconfigure(encoding='utf-8', errors='replace')",
            "out = []",
            "try:",
            "    with zipfile.ZipFile(sys.argv[1], 'r') as z:",
            "        for name in sorted(z.namelist()):",
            "            if name.endswith('.xml') and ('sharedStrings' in name or 'worksheets/' in name or name == 'content.xml'):",
            "                root = ET.fromstring(z.read(name))",
            "                vals = [el.text.strip() for el in root.iter() if el.text and el.text.strip()]",
            "                if vals: out.append(f'[{name}] ' + ' | '.join(vals))",
            "except Exception:",
            "    pass",
            "print('\\n'.join(out))",
        ]
        .join("\n");

        if let Ok(output) = Command::new("python")
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

        let bytes = std::fs::read(path)?;
        Ok(Self::extract_printable_strings(&bytes, path, "Spreadsheet"))
    }

    /// Extracts all slide text runs and speaker notes from `.pptx`, `.ppt`, or `.odp`.
    fn extract_presentation_text(path: &Path) -> io::Result<String> {
        let script = [
            "import sys, zipfile, xml.etree.ElementTree as ET",
            "sys.stdout.reconfigure(encoding='utf-8', errors='replace')",
            "out = []",
            "try:",
            "    with zipfile.ZipFile(sys.argv[1], 'r') as z:",
            "        for name in sorted(z.namelist()):",
            "            if name.endswith('.xml') and ('slides/slide' in name or 'notesSlides/' in name or name == 'content.xml'):",
            "                root = ET.fromstring(z.read(name))",
            "                vals = [el.text.strip() for el in root.iter() if el.text and el.text.strip()]",
            "                if vals: out.append(f'[{name}] ' + ' '.join(vals))",
            "except Exception:",
            "    pass",
            "print('\\n'.join(out))",
        ]
        .join("\n");

        if let Ok(output) = Command::new("python")
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

        let bytes = std::fs::read(path)?;
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

    /// Extracts all XHTML/HTML chapters from an `.epub` archive.
    fn extract_epub_text(path: &Path) -> io::Result<String> {
        let script = [
            "import sys, zipfile, re",
            "sys.stdout.reconfigure(encoding='utf-8', errors='replace')",
            "out = []",
            "try:",
            "    with zipfile.ZipFile(sys.argv[1], 'r') as z:",
            "        for name in sorted(z.namelist()):",
            "            if name.endswith(('.xhtml', '.html', '.htm', '.opf')):",
            "                raw = z.read(name).decode('utf-8', errors='replace')",
            "                clean = re.sub(r'<[^>]+>', ' ', raw)",
            "                clean = ' '.join(clean.split())",
            "                if clean: out.append(clean)",
            "except Exception:",
            "    pass",
            "print('\\n'.join(out))",
        ]
        .join("\n");

        if let Ok(output) = Command::new("python")
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

        let bytes = std::fs::read(path)?;
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

    /// Extracts schema (`sqlite_master`) and sample rows from a SQLite 3 database.
    fn extract_sqlite_text(path: &Path) -> io::Result<String> {
        let script = [
            "import sys, sqlite3",
            "sys.stdout.reconfigure(encoding='utf-8', errors='replace')",
            "conn = sqlite3.connect(f'file:{sys.argv[1]}?mode=ro', uri=True)",
            "cur = conn.cursor()",
            "out = []",
            "for t_type, name, sql in cur.execute('SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL'):",
            "    out.append(f'[{t_type.upper()}: {name}] {sql}')",
            "    if t_type == 'table' and not name.startswith('sqlite_'):",
            "        try:",
            "            rows = cur.execute(f'SELECT * FROM \"{name}\" LIMIT 25').fetchall()",
            "            for r in rows:",
            "                out.append(' | '.join(str(v) for v in r if v is not None))",
            "        except Exception:",
            "            pass",
            "print('\\n'.join(out))",
        ]
        .join("\n");

        if let Ok(output) = Command::new("python")
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

    /// Pure-Rust fallback extractor for PDF parenthesized text literals `( ... )`.
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
                if trimmed.len() >= 2
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
    use quorum_classifier::FileTypeClassifier;

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
