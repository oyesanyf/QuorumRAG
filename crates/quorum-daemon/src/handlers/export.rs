//! `POST /api/export`: genuine PDF (`%PDF-1.4`) and Word (`.docx` OpenXML) export of an answer.
//!
//! Both formats are generated in pure Rust with no external tools:
//! - DOCX: an OPC/ZIP package (stored entries + CRC-32) containing `[Content_Types].xml`,
//!   relationships, `word/styles.xml`, `word/document.xml` with real heading styles, bold runs,
//!   bullet/numbered paragraphs, a Sources section, and embedded JPEG/PNG pictures.
//! - PDF: Catalog/Pages/Page objects, Helvetica + Helvetica-Bold (WinAnsiEncoding) with
//!   metric-based word wrap and automatic pagination, embedded JPEG images (`/DCTDecode`),
//!   a byte-accurate `xref` table and trailer.
//!
//! Images listed in `attached_media` are only embedded if they pass the same index gate as
//! `/api/media`, so export cannot be used to read arbitrary files.

use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;

use crate::state::DaemonState;

#[derive(Debug, Clone, Deserialize)]
pub struct ExportSource {
    #[serde(default)]
    pub cite_num: Option<usize>,
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub score_pct: Option<f32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExportRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    pub markdown_content: String,
    #[serde(default)]
    pub sources: Vec<ExportSource>,
    /// Absolute paths of cited image files to embed (gated to indexed files).
    #[serde(default)]
    pub attached_media: Vec<String>,
    /// "pdf" | "docx" | "md"
    pub format: String,
}

/// A decoded image ready to embed.
#[derive(Debug, Clone)]
pub struct EmbedImage {
    pub name: String,
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub is_jpeg: bool,
    /// JPEG component count (1 gray, 3 RGB, 4 CMYK).
    pub components: u8,
}

/// Read pixel dimensions from JPEG (SOF0/1/2) or PNG (IHDR) bytes.
pub fn image_dims(bytes: &[u8]) -> Option<(u32, u32, bool, u8)> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") && bytes.len() >= 24 {
        let w = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let h = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        return (w > 0 && h > 0).then_some((w, h, false, 3));
    }
    if bytes.starts_with(&[0xFF, 0xD8]) {
        let mut off = 2;
        while off + 9 < bytes.len() {
            if bytes[off] != 0xFF {
                off += 1;
                continue;
            }
            let marker = bytes[off + 1];
            if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) || marker == 0xFF {
                off += if marker == 0xFF { 1 } else { 2 };
                continue;
            }
            let len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
            if matches!(marker, 0xC0 | 0xC1 | 0xC2) && off + 9 < bytes.len() {
                let h = u16::from_be_bytes([bytes[off + 5], bytes[off + 6]]) as u32;
                let w = u16::from_be_bytes([bytes[off + 7], bytes[off + 8]]) as u32;
                let comps = bytes[off + 9];
                return (w > 0 && h > 0).then_some((w, h, true, comps));
            }
            if marker == 0xDA || len < 2 {
                return None;
            }
            off += 2 + len;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Markdown -> simple block model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Block {
    Heading(u8, String),
    Paragraph(String),
    Bullet(String),
    Numbered(usize, String),
}

/// Parse the subset of Markdown the chat renderer emits.
pub fn parse_markdown(md: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut para: Vec<String> = Vec::new();
    let flush = |para: &mut Vec<String>, blocks: &mut Vec<Block>| {
        if !para.is_empty() {
            blocks.push(Block::Paragraph(para.join(" ")));
            para.clear();
        }
    };
    for raw in md.lines() {
        let line = raw.trim_end();
        let t = line.trim_start();
        if t.is_empty() {
            flush(&mut para, &mut blocks);
            continue;
        }
        if t.starts_with("```") || t == "---" || t == "***" {
            flush(&mut para, &mut blocks);
            continue;
        }
        let hashes = t.chars().take_while(|&c| c == '#').count();
        if (1..=6).contains(&hashes) && t[hashes..].starts_with(' ') {
            flush(&mut para, &mut blocks);
            blocks.push(Block::Heading(hashes.min(3) as u8, t[hashes..].trim().to_string()));
            continue;
        }
        if let Some(rest) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")).or_else(|| t.strip_prefix("\u{2022} ")) {
            flush(&mut para, &mut blocks);
            blocks.push(Block::Bullet(rest.trim().to_string()));
            continue;
        }
        let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 && digits < 4 && t[digits..].starts_with(". ") {
            flush(&mut para, &mut blocks);
            let n = t[..digits].parse().unwrap_or(1);
            blocks.push(Block::Numbered(n, t[digits + 2..].trim().to_string()));
            continue;
        }
        para.push(t.to_string());
    }
    flush(&mut para, &mut blocks);
    blocks
}

/// Split `**bold**` markers into (text, bold) runs; strips `*`/`_`/backtick emphasis markers.
pub fn inline_runs(text: &str) -> Vec<(String, bool)> {
    let mut runs = Vec::new();
    let mut bold = false;
    for (i, part) in text.split("**").enumerate() {
        if i > 0 {
            bold = !bold;
        }
        let cleaned: String = part.replace('`', "");
        if !cleaned.is_empty() {
            runs.push((cleaned, bold));
        }
    }
    runs
}

fn plain(text: &str) -> String {
    inline_runs(text).into_iter().map(|(t, _)| t).collect()
}

// ---------------------------------------------------------------------------
// ZIP (stored) writer for OPC packages
// ---------------------------------------------------------------------------

fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// Build a ZIP archive with stored (uncompressed) entries.
pub fn zip_store(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    // 1980-01-01 00:00 DOS timestamp.
    let (dos_time, dos_date) = (0u16, 0x0021u16);
    for (name, data) in entries {
        let crc = crc32(data);
        let offset = out.len() as u32;
        let n = name.as_bytes();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&dos_time.to_le_bytes());
        out.extend_from_slice(&dos_date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(n.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(n);
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&dos_time.to_le_bytes());
        central.extend_from_slice(&dos_date.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(n.len() as u16).to_le_bytes());
        // extra len (2), comment len (2), disk start (2), internal attrs (2), external attrs (4)
        central.extend_from_slice(&[0u8; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(n);
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// DOCX
// ---------------------------------------------------------------------------

fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            // XML 1.0 forbids most C0 controls.
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {}
            c => o.push(c),
        }
    }
    o
}

fn docx_runs(text: &str, force_bold: bool) -> String {
    inline_runs(text)
        .into_iter()
        .map(|(t, b)| {
            let rpr = if b || force_bold { "<w:rPr><w:b/></w:rPr>" } else { "" };
            format!("<w:r>{rpr}<w:t xml:space=\"preserve\">{}</w:t></w:r>", xml_escape(&t))
        })
        .collect()
}

fn docx_para(style: Option<&str>, indent: bool, body: &str) -> String {
    let mut ppr = String::new();
    if style.is_some() || indent {
        ppr.push_str("<w:pPr>");
        if let Some(s) = style {
            ppr.push_str(&format!("<w:pStyle w:val=\"{s}\"/>"));
        }
        if indent {
            ppr.push_str("<w:ind w:left=\"720\" w:hanging=\"360\"/>");
        }
        ppr.push_str("</w:pPr>");
    }
    format!("<w:p>{ppr}{body}</w:p>")
}

pub fn generate_docx(req: &ExportRequest, images: &[EmbedImage]) -> Vec<u8> {
    let title = req.title.clone().unwrap_or_else(|| "QuorumRAG Answer".to_string());
    let mut body = String::new();
    body.push_str(&docx_para(Some("Title"), false, &docx_runs(&title, false)));
    if let Some(p) = req.prompt.as_deref().filter(|p| !p.trim().is_empty()) {
        body.push_str(&docx_para(None, false, &format!(
            "<w:r><w:rPr><w:i/></w:rPr><w:t xml:space=\"preserve\">Question: {}</w:t></w:r>",
            xml_escape(p)
        )));
    }
    for block in parse_markdown(&req.markdown_content) {
        match block {
            Block::Heading(l, t) => body.push_str(&docx_para(Some(&format!("Heading{l}")), false, &docx_runs(&t, false))),
            Block::Paragraph(t) => body.push_str(&docx_para(None, false, &docx_runs(&t, false))),
            Block::Bullet(t) => body.push_str(&docx_para(None, true, &format!(
                "<w:r><w:t xml:space=\"preserve\">\u{2022}\t</w:t></w:r>{}",
                docx_runs(&t, false)
            ))),
            Block::Numbered(n, t) => body.push_str(&docx_para(None, true, &format!(
                "<w:r><w:t xml:space=\"preserve\">{n}.\t</w:t></w:r>{}",
                docx_runs(&t, false)
            ))),
        }
    }

    let mut rels_extra = String::new();
    let mut media_entries: Vec<(String, Vec<u8>)> = Vec::new();
    if !images.is_empty() {
        body.push_str(&docx_para(Some("Heading2"), false, &docx_runs("Attached Images", false)));
    }
    for (i, img) in images.iter().enumerate() {
        let id = i + 1;
        let ext = if img.is_jpeg { "jpeg" } else { "png" };
        let part = format!("media/image{id}.{ext}");
        rels_extra.push_str(&format!(
            "<Relationship Id=\"rIdImg{id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"{part}\"/>"
        ));
        media_entries.push((format!("word/{part}"), img.bytes.clone()));
        // Fit within 6in x 6in at 96 dpi (9525 EMU per pixel).
        let max_emu = 5_486_400f64;
        let (mut cx, mut cy) = (img.width as f64 * 9525.0, img.height as f64 * 9525.0);
        let scale = (max_emu / cx).min(max_emu / cy).min(1.0);
        cx *= scale;
        cy *= scale;
        let (cx, cy) = (cx as u64, cy as u64);
        let name = xml_escape(&img.name);
        body.push_str(&format!(
            "<w:p><w:r><w:drawing><wp:inline distT=\"0\" distB=\"0\" distL=\"0\" distR=\"0\"><wp:extent cx=\"{cx}\" cy=\"{cy}\"/><wp:docPr id=\"{id}\" name=\"{name}\"/><a:graphic xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\"><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\"><pic:pic xmlns:pic=\"http://schemas.openxmlformats.org/drawingml/2006/picture\"><pic:nvPicPr><pic:cNvPr id=\"{id}\" name=\"{name}\"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed=\"rIdImg{id}\"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>"
        ));
        body.push_str(&docx_para(None, false, &format!(
            "<w:r><w:rPr><w:i/></w:rPr><w:t xml:space=\"preserve\">{name}</w:t></w:r>"
        )));
    }

    if !req.sources.is_empty() {
        body.push_str(&docx_para(Some("Heading2"), false, &docx_runs("Sources", false)));
        for (i, s) in req.sources.iter().enumerate() {
            let n = s.cite_num.unwrap_or(i + 1);
            let score = s.score_pct.map(|p| format!(" ({p:.0}%)")).unwrap_or_default();
            body.push_str(&docx_para(None, true, &format!(
                "<w:r><w:rPr><w:b/></w:rPr><w:t xml:space=\"preserve\">[{n}] {}{score}</w:t></w:r><w:r><w:br/><w:t xml:space=\"preserve\">{}</w:t></w:r>",
                xml_escape(&s.file_name),
                xml_escape(&s.file_path)
            )));
        }
    }

    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\" \
xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" \
xmlns:wp=\"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing\">\
<w:body>{body}<w:sectPr><w:pgSz w:w=\"12240\" w:h=\"15840\"/><w:pgMar w:top=\"1080\" w:right=\"1080\" w:bottom=\"1080\" w:left=\"1080\" w:header=\"720\" w:footer=\"720\" w:gutter=\"0\"/></w:sectPr></w:body></w:document>"
    );

    let styles = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<w:styles xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii=\"Calibri\" w:hAnsi=\"Calibri\" w:cs=\"Calibri\"/><w:sz w:val=\"22\"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after=\"120\" w:line=\"276\" w:lineRule=\"auto\"/></w:pPr></w:pPrDefault></w:docDefaults>\
<w:style w:type=\"paragraph\" w:default=\"1\" w:styleId=\"Normal\"><w:name w:val=\"Normal\"/><w:qFormat/></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Title\"><w:name w:val=\"Title\"/><w:basedOn w:val=\"Normal\"/><w:qFormat/><w:pPr><w:spacing w:after=\"240\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"40\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Heading1\"><w:name w:val=\"heading 1\"/><w:basedOn w:val=\"Normal\"/><w:next w:val=\"Normal\"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before=\"240\" w:after=\"120\"/><w:outlineLvl w:val=\"0\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"32\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Heading2\"><w:name w:val=\"heading 2\"/><w:basedOn w:val=\"Normal\"/><w:next w:val=\"Normal\"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before=\"200\" w:after=\"100\"/><w:outlineLvl w:val=\"1\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"28\"/></w:rPr></w:style>\
<w:style w:type=\"paragraph\" w:styleId=\"Heading3\"><w:name w:val=\"heading 3\"/><w:basedOn w:val=\"Normal\"/><w:next w:val=\"Normal\"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before=\"160\" w:after=\"80\"/><w:outlineLvl w:val=\"2\"/></w:pPr><w:rPr><w:b/><w:sz w:val=\"24\"/></w:rPr></w:style>\
</w:styles>";

    let content_types = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">\
<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>\
<Default Extension=\"xml\" ContentType=\"application/xml\"/>\
<Default Extension=\"jpeg\" ContentType=\"image/jpeg\"/>\
<Default Extension=\"png\" ContentType=\"image/png\"/>\
<Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/>\
<Override PartName=\"/word/styles.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml\"/>\
<Override PartName=\"/docProps/core.xml\" ContentType=\"application/vnd.openxmlformats-package.core-properties+xml\"/>\
</Types>";

    let root_rels = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/>\
<Relationship Id=\"rId2\" Type=\"http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties\" Target=\"docProps/core.xml\"/>\
</Relationships>";

    let doc_rels = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\
<Relationship Id=\"rIdStyles\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles\" Target=\"styles.xml\"/>{rels_extra}</Relationships>"
    );

    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let core = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\
<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\
<dc:title>{}</dc:title><dc:creator>QuorumRAG</dc:creator>\
<dcterms:created xsi:type=\"dcterms:W3CDTF\">{now}</dcterms:created><dcterms:modified xsi:type=\"dcterms:W3CDTF\">{now}</dcterms:modified></cp:coreProperties>",
        xml_escape(&title)
    );

    let mut entries: Vec<(String, Vec<u8>)> = vec![
        ("[Content_Types].xml".into(), content_types.as_bytes().to_vec()),
        ("_rels/.rels".into(), root_rels.as_bytes().to_vec()),
        ("docProps/core.xml".into(), core.into_bytes()),
        ("word/document.xml".into(), document.into_bytes()),
        ("word/styles.xml".into(), styles.as_bytes().to_vec()),
        ("word/_rels/document.xml.rels".into(), doc_rels.into_bytes()),
    ];
    entries.extend(media_entries);
    let refs: Vec<(&str, &[u8])> = entries.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    zip_store(&refs)
}

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

/// Helvetica advance widths (1/1000 em) for ASCII 32..=126 (Adobe standard metrics).
const HELV: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556,
    556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778,
    722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278,
    278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
];

/// Map a char to a single WinAnsiEncoding byte (lossy for characters outside the code page).
fn winansi(c: char) -> u8 {
    match c {
        ' '..='~' => c as u8,
        '\u{2013}' => 0x96,
        '\u{2014}' => 0x97,
        '\u{2018}' => 0x91,
        '\u{2019}' => 0x92,
        '\u{201C}' => 0x93,
        '\u{201D}' => 0x94,
        '\u{2022}' => 0x95,
        '\u{2026}' => 0x85,
        '\u{20AC}' => 0x80,
        '\u{2122}' => 0x99,
        '\t' => b' ',
        c if (0xA0..=0xFF).contains(&(c as u32)) => c as u32 as u8,
        _ => b'?',
    }
}

fn char_width(b: u8, bold: bool) -> f64 {
    let w = if (32..=126).contains(&b) { HELV[(b - 32) as usize] as f64 } else { 556.0 };
    if bold { w * 1.08 } else { w }
}

fn text_width(bytes: &[u8], size: f64, bold: bool) -> f64 {
    bytes.iter().map(|&b| char_width(b, bold)).sum::<f64>() * size / 1000.0
}

fn wrap(text: &str, size: f64, bold: bool, max_w: f64) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for word in text.split_whitespace() {
        let wb: Vec<u8> = word.chars().map(winansi).collect();
        let candidate_w = if cur.is_empty() {
            text_width(&wb, size, bold)
        } else {
            text_width(&cur, size, bold) + text_width(b" ", size, bold) + text_width(&wb, size, bold)
        };
        if candidate_w <= max_w || cur.is_empty() {
            if !cur.is_empty() {
                cur.push(b' ');
            }
            // Hard-break a single word longer than the line (e.g. long file paths).
            if cur.is_empty() && text_width(&wb, size, bold) > max_w {
                let mut piece = Vec::new();
                for b in wb {
                    if text_width(&piece, size, bold) + char_width(b, bold) * size / 1000.0 > max_w {
                        lines.push(std::mem::take(&mut piece));
                    }
                    piece.push(b);
                }
                cur = piece;
            } else {
                cur.extend_from_slice(&wb);
            }
        } else {
            lines.push(std::mem::take(&mut cur));
            cur = wb;
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn pdf_str(bytes: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(bytes.len() + 2);
    o.push(b'(');
    for &b in bytes {
        if matches!(b, b'(' | b')' | b'\\') {
            o.push(b'\\');
        }
        o.push(b);
    }
    o.push(b')');
    o
}

struct PdfLayout {
    pages: Vec<Vec<u8>>,
    cur: Vec<u8>,
    y: f64,
    /// (page index, image index, x, y, w, h)
    placements: Vec<(usize, usize, f64, f64, f64, f64)>,
}

const PAGE_W: f64 = 612.0;
const PAGE_H: f64 = 792.0;
const MARGIN: f64 = 54.0;

impl PdfLayout {
    fn new() -> Self {
        Self { pages: Vec::new(), cur: Vec::new(), y: PAGE_H - MARGIN, placements: Vec::new() }
    }
    fn new_page(&mut self) {
        self.pages.push(std::mem::take(&mut self.cur));
        self.y = PAGE_H - MARGIN;
    }
    fn ensure(&mut self, h: f64) {
        if self.y - h < MARGIN {
            self.new_page();
        }
    }
    fn line(&mut self, bytes: &[u8], size: f64, bold: bool, indent: f64) {
        let lead = size * 1.35;
        self.ensure(lead);
        self.y -= lead;
        let font = if bold { "F2" } else { "F1" };
        self.cur.extend_from_slice(format!("BT /{font} {size} Tf {:.2} {:.2} Td ", MARGIN + indent, self.y).as_bytes());
        self.cur.extend_from_slice(&pdf_str(bytes));
        self.cur.extend_from_slice(b" Tj ET\n");
    }
    fn para(&mut self, text: &str, size: f64, bold: bool, indent: f64, prefix: Option<&str>) {
        let max_w = PAGE_W - 2.0 * MARGIN - indent;
        let lines = wrap(text, size, bold, max_w);
        for (i, l) in lines.iter().enumerate() {
            if i == 0 {
                if let Some(p) = prefix {
                    let pb: Vec<u8> = p.chars().map(winansi).collect();
                    let lead = size * 1.35;
                    self.ensure(lead);
                    let font = if bold { "F2" } else { "F1" };
                    // Prefix is drawn in the hanging-indent gutter on the same baseline as line 1.
                    self.cur.extend_from_slice(
                        format!("BT /{font} {size} Tf {:.2} {:.2} Td ", MARGIN + indent - 14.0, self.y - lead).as_bytes(),
                    );
                    self.cur.extend_from_slice(&pdf_str(&pb));
                    self.cur.extend_from_slice(b" Tj ET\n");
                }
            }
            self.line(l, size, bold, indent);
        }
        self.y -= size * 0.45;
    }
    fn image(&mut self, idx: usize, w_px: u32, h_px: u32) {
        let max_w = PAGE_W - 2.0 * MARGIN;
        let max_h = 320.0;
        let (mut w, mut h) = (w_px as f64 * 0.75, h_px as f64 * 0.75);
        let s = (max_w / w).min(max_h / h).min(1.0);
        w *= s;
        h *= s;
        self.ensure(h + 8.0);
        self.y -= h + 4.0;
        let page = self.pages.len();
        self.placements.push((page, idx, MARGIN, self.y, w, h));
        self.cur.extend_from_slice(format!("q {w:.2} 0 0 {h:.2} {MARGIN:.2} {:.2} cm /Im{idx} Do Q\n", self.y).as_bytes());
        self.y -= 6.0;
    }
    fn finish(mut self) -> (Vec<Vec<u8>>, Vec<(usize, usize, f64, f64, f64, f64)>) {
        if !self.cur.is_empty() || self.pages.is_empty() {
            self.pages.push(std::mem::take(&mut self.cur));
        }
        (self.pages, self.placements)
    }
}

pub fn generate_pdf(req: &ExportRequest, images: &[EmbedImage]) -> Vec<u8> {
    let title = req.title.clone().unwrap_or_else(|| "QuorumRAG Answer".to_string());
    let mut lay = PdfLayout::new();
    lay.para(&plain(&title), 18.0, true, 0.0, None);
    if let Some(p) = req.prompt.as_deref().filter(|p| !p.trim().is_empty()) {
        lay.para(&format!("Question: {p}"), 10.0, false, 0.0, None);
    }
    for block in parse_markdown(&req.markdown_content) {
        match block {
            Block::Heading(1, t) => lay.para(&plain(&t), 15.0, true, 0.0, None),
            Block::Heading(2, t) => lay.para(&plain(&t), 13.0, true, 0.0, None),
            Block::Heading(_, t) => lay.para(&plain(&t), 11.5, true, 0.0, None),
            Block::Paragraph(t) => lay.para(&plain(&t), 11.0, false, 0.0, None),
            Block::Bullet(t) => lay.para(&plain(&t), 11.0, false, 18.0, Some("\u{2022}")),
            Block::Numbered(n, t) => lay.para(&plain(&t), 11.0, false, 18.0, Some(&format!("{n}."))),
        }
    }
    let jpegs: Vec<(usize, &EmbedImage)> = images
        .iter()
        .filter(|i| i.is_jpeg && (i.components == 1 || i.components == 3))
        .enumerate()
        .collect();
    if !jpegs.is_empty() {
        lay.para("Attached Images", 13.0, true, 0.0, None);
        for (i, img) in &jpegs {
            lay.image(*i, img.width, img.height);
            lay.para(&img.name, 9.0, false, 0.0, None);
        }
    }
    if !req.sources.is_empty() {
        lay.para("Sources", 13.0, true, 0.0, None);
        for (i, s) in req.sources.iter().enumerate() {
            let n = s.cite_num.unwrap_or(i + 1);
            let score = s.score_pct.map(|p| format!(" ({p:.0}%)")).unwrap_or_default();
            lay.para(&format!("[{n}] {}{score}", s.file_name), 10.0, true, 0.0, None);
            lay.para(&s.file_path, 9.0, false, 12.0, None);
        }
    }
    let (pages, _placements) = lay.finish();

    // Object numbering: 1 Catalog, 2 Pages, 3 F1, 4 F2, then images, then (content, page) pairs.
    let mut objs: Vec<Vec<u8>> = Vec::new();
    let img_base = 5;
    let page_base = img_base + jpegs.len();
    let kids: Vec<String> = (0..pages.len()).map(|i| format!("{} 0 R", page_base + i * 2 + 1)).collect();
    objs.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
    objs.push(format!("<< /Type /Pages /Kids [{}] /Count {} >>", kids.join(" "), pages.len()).into_bytes());
    objs.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>".to_vec());
    objs.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>".to_vec());
    let mut xobjects = String::new();
    for (i, img) in &jpegs {
        let cs = if img.components == 1 { "/DeviceGray" } else { "/DeviceRGB" };
        let mut o = format!(
            "<< /Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace {cs} /BitsPerComponent 8 /Filter /DCTDecode /Length {} >>\nstream\n",
            img.width, img.height, img.bytes.len()
        )
        .into_bytes();
        o.extend_from_slice(&img.bytes);
        o.extend_from_slice(b"\nendstream");
        objs.push(o);
        xobjects.push_str(&format!("/Im{i} {} 0 R ", img_base + i));
    }
    let resources = format!(
        "<< /Font << /F1 3 0 R /F2 4 0 R >> /XObject << {xobjects}>> /ProcSet [/PDF /Text /ImageB /ImageC] >>"
    );
    for (i, content) in pages.iter().enumerate() {
        let mut c = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
        c.extend_from_slice(content);
        c.extend_from_slice(b"\nendstream");
        objs.push(c);
        let content_id = page_base + i * 2;
        objs.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Resources {resources} /Contents {content_id} 0 R >>"
            )
            .into_bytes(),
        );
    }

    let mut out: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objs.len());
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(o);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref_at = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n", objs.len() + 1).as_bytes(),
    );
    out
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

fn safe_file_stem(title: &str) -> String {
    let s: String = title
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' { c } else { '_' })
        .collect();
    let s = s.split_whitespace().collect::<Vec<_>>().join("_");
    let s: String = s.chars().take(80).collect();
    if s.is_empty() { "quorumrag-answer".to_string() } else { s }
}

fn load_images(state: &DaemonState, paths: &[String]) -> Vec<EmbedImage> {
    let mut out = Vec::new();
    for p in paths.iter().take(12) {
        let Ok(path) = crate::handlers::media::authorize_media_path(state, p) else { continue };
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if meta.len() > 15 * 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let Some((w, h, is_jpeg, comps)) = image_dims(&bytes) else { continue };
        out.push(EmbedImage {
            name: path.file_name().and_then(|n| n.to_str()).unwrap_or("image").to_string(),
            bytes,
            width: w,
            height: h,
            is_jpeg,
            components: comps,
        });
    }
    out
}

pub async fn export_handler(State(state): State<Arc<DaemonState>>, Json(req): Json<ExportRequest>) -> Response {
    if req.markdown_content.len() > 4 * 1024 * 1024 {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Export content too large").into_response();
    }
    let stem = safe_file_stem(req.title.as_deref().unwrap_or("quorumrag-answer"));
    let fmt = req.format.to_ascii_lowercase();
    let (bytes, mime, ext) = match fmt.as_str() {
        "pdf" => {
            let imgs = load_images(&state, &req.attached_media);
            (generate_pdf(&req, &imgs), "application/pdf", "pdf")
        }
        "docx" | "word" => {
            let imgs = load_images(&state, &req.attached_media);
            (
                generate_docx(&req, &imgs),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "docx",
            )
        }
        "md" | "markdown" => (req.markdown_content.clone().into_bytes(), "text/markdown; charset=utf-8", "md"),
        _ => return (StatusCode::BAD_REQUEST, "Unsupported format: use pdf, docx, or md").into_response(),
    };
    let disp = format!("attachment; filename=\"{stem}.{ext}\"");
    let mut resp = (StatusCode::OK, bytes).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
    if let Ok(v) = HeaderValue::from_str(&disp) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ExportRequest {
        ExportRequest {
            title: Some("Dogs in the dataset".into()),
            prompt: Some("tell me about image of dogs".into()),
            markdown_content: "# Summary\nA small **brown and white** dog sits on grass [1].\n\n## Details\n- Tongue out\n- Bushes behind\n1. First\n2. Second (with parentheses) and a backslash \\ and \u{2014} dash".into(),
            sources: vec![ExportSource {
                cite_num: Some(1),
                file_name: "dog.119.jpg".into(),
                file_path: r"D:\dataset\images\data\dogs\dog.119.jpg".into(),
                score_pct: Some(96.0),
            }],
            attached_media: vec![],
            format: "pdf".into(),
        }
    }

    #[test]
    fn markdown_blocks_parse() {
        let b = parse_markdown(&sample().markdown_content);
        assert_eq!(b[0], Block::Heading(1, "Summary".into()));
        assert!(matches!(b[2], Block::Heading(2, _)));
        assert!(matches!(b[3], Block::Bullet(_)));
        assert!(matches!(b[5], Block::Numbered(1, _)));
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn pdf_has_valid_structure_and_xref_offsets() {
        let pdf = generate_pdf(&sample(), &[]);
        assert!(pdf.starts_with(b"%PDF-1.4"));
        assert!(pdf.ends_with(b"%%EOF\n"));
        // Byte-exact checks: offsets in the xref table are byte offsets into the raw file.
        let sx = pdf.windows(10).rposition(|w| w == b"startxref\n").unwrap();
        let tail = std::str::from_utf8(&pdf[sx + 10..]).unwrap();
        let xref_at: usize = tail.lines().next().unwrap().trim().parse().unwrap();
        assert!(pdf[xref_at..].starts_with(b"xref\n"));
        let xref_text = std::str::from_utf8(&pdf[xref_at..]).unwrap();
        // Every xref entry must point at "N 0 obj".
        let entries: Vec<&str> = xref_text.lines().skip(3).take_while(|l| l.ends_with(" n ")).collect();
        assert!(!entries.is_empty());
        for (i, e) in entries.iter().enumerate() {
            let off: usize = e[..10].parse().unwrap();
            assert!(pdf[off..].starts_with(format!("{} 0 obj", i + 1).as_bytes()), "obj {} at {}", i + 1, off);
        }
        assert!(find(&pdf, b"(Summary) Tj").is_some());
        assert!(find(&pdf, b"\\(with parentheses\\)").is_some());
        // Em dash is encoded as the single WinAnsi byte 0x97.
        assert!(find(&pdf, &[b' ', 0x97, b' ']).is_some());
    }

    #[test]
    fn pdf_paginates_long_content() {
        let mut r = sample();
        r.markdown_content = (0..400).map(|i| format!("Paragraph {i} with enough words to wrap across the line width of the page.\n\n")).collect();
        let pdf = generate_pdf(&r, &[]);
        let s = String::from_utf8_lossy(&pdf);
        let count: usize = s.matches("/Type /Page ").count();
        assert!(count > 5, "pages: {count}");
    }

    #[test]
    fn docx_is_valid_zip_with_required_parts() {
        let docx = generate_docx(&sample(), &[]);
        assert!(docx.starts_with(b"PK\x03\x04"));
        let s = String::from_utf8_lossy(&docx);
        for part in ["[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/styles.xml", "word/_rels/document.xml.rels"] {
            assert!(s.contains(part), "missing {part}");
        }
        assert!(s.contains("<w:pStyle w:val=\"Heading1\"/>"));
        assert!(s.contains("<w:b/></w:rPr><w:t xml:space=\"preserve\">brown and white</w:t>"));
        assert!(s.contains("dog.119.jpg"));
        // EOCD present
        assert!(docx.windows(4).any(|w| w == [0x50, 0x4b, 0x05, 0x06]));
    }

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn jpeg_dims_parse() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x01, 0x90, 0x01, 0x18, 0x03, 0x01, 0x11, 0x00, 0xFF, 0xD9];
        assert_eq!(image_dims(&jpeg), Some((280, 400, true, 3)));
    }
}
