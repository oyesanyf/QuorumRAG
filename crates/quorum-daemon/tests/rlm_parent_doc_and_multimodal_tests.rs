//! End-to-end integration tests for QuorumRAG v0.6.3 Parent-Document Store,
//! Live RLM Environment (`peek_slice`, `regex_grep`, `expand_parent_window`),
//! Verbatim Substring Citation Grounding, Magic-Byte Binary Filtering,
//! Multi-Sheet OpenXML `.xlsx` + `docProps/core.xml` Extraction, and
//! Multimodal Ollama Vision Image Indexing.

use std::sync::{Arc, Mutex};

use quorum_classifier::FileTypeClassifier;
use quorum_contract::rlm::{GroundedCitation, RlmConfig};
use quorum_contract::{DeterministicOfflineEngine, EmbeddingGenerator};
use quorum_coordinator::rlm_orchestrator::{rhai, RlmOrchestrator, RlmWorkspaceState};
use quorum_coordinator::scatter_gather::StorageSearcher;
use quorum_ingest::{
    ClassifierRouter, DocumentExtractor, FilterDecision, ImageIndexer, IngestConfig, IngestEngine,
};
use quorum_storage::{StorageConfig, StorageEngine};
use quorum_types::{Citation, DocumentChunk, DocumentFormat, ScoredChunk};

/// Builds a valid Stored (method 0) PKZIP archive in memory with zero external dependencies.
fn build_stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    fn crc32_ieee(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc ^= b as u32;
            for _ in 0..8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    let mut buf = Vec::new();
    let mut central = Vec::new();
    for &(name, raw) in entries {
        let local_offset = buf.len() as u32;
        let crc = crc32_ieee(raw);
        let size = raw.len() as u32;
        let name_b = name.as_bytes();

        // Local file header (PK\x03\x04)
        buf.extend_from_slice(b"PK\x03\x04");
        buf.extend_from_slice(&20u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // Method 0: Stored
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(name_b);
        buf.extend_from_slice(raw);

        // Central directory header (PK\x01\x02)
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // Method 0: Stored
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
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

    // End of Central Directory (PK\x05\x06)
    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_offset.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf
}

/// Encodes a valid 64x64 24-bit RGB PNG image using uncompressed zlib blocks.
fn build_valid_rgb_png_64x64() -> Vec<u8> {
    fn crc32_png(chunk_type: &[u8; 4], data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &b in chunk_type.iter().chain(data.iter()) {
            crc ^= b as u32;
            for _ in 0..8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ 0xEDB8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    fn adler32(data: &[u8]) -> u32 {
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &byte in data {
            a = (a + byte as u32) % 65_521;
            b = (b + a) % 65_521;
        }
        (b << 16) | a
    }

    let width = 64u32;
    let height = 64u32;
    let mut raw_scanlines = Vec::with_capacity((height * (1 + width * 3)) as usize);
    for y in 0..height {
        raw_scanlines.push(0u8); // Filter type 0 (None)
        for x in 0..width {
            let (r, g, b) = if y < 28 {
                (95u8, 170u8, 245u8) // Blue sky
            } else if (20..44).contains(&x) && (26..48).contains(&y) {
                if (x + y) % 5 == 0 {
                    (30u8, 30u8, 30u8)
                } else {
                    (245u8, 245u8, 240u8)
                }
            } else {
                (55u8, 155u8, 60u8) // Green pasture
            };
            raw_scanlines.extend_from_slice(&[r, g, b]);
        }
    }

    // Zlib stream with single Stored (BTYPE=00, BFINAL=1) DEFLATE block (len = 12,352 <= 65,535)
    let mut zlib = Vec::new();
    zlib.extend_from_slice(&[0x78, 0x01]);
    zlib.push(0x01); // BFINAL=1, BTYPE=00
    let len = raw_scanlines.len() as u16;
    let nlen = !len;
    zlib.extend_from_slice(&len.to_le_bytes());
    zlib.extend_from_slice(&nlen.to_le_bytes());
    zlib.extend_from_slice(&raw_scanlines);
    zlib.extend_from_slice(&adler32(&raw_scanlines).to_be_bytes());

    let mut png = Vec::from(&b"\x89PNG\r\n\x1a\n"[..]);
    let write_chunk = |out: &mut Vec<u8>, ctype: &[u8; 4], data: &[u8]| {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(ctype);
        out.extend_from_slice(data);
        out.extend_from_slice(&crc32_png(ctype, data).to_be_bytes());
    };

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit truecolor RGB
    write_chunk(&mut png, b"IHDR", &ihdr);
    write_chunk(&mut png, b"IDAT", &zlib);
    write_chunk(&mut png, b"IEND", &[]);
    png
}

#[tokio::test]
async fn parent_document_store_xlsx_docx_rlm_enrichment_and_mesh_preservation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let storage_dir = temp.path().join("storage");
    let docs_dir = temp.path().join("docs");
    std::fs::create_dir_all(&docs_dir).unwrap();

    let storage = Arc::new(
        StorageEngine::open(StorageConfig::new(&storage_dir))
            .await
            .expect("open storage"),
    );
    let classifier = Arc::new(FileTypeClassifier::new());
    let embedder: Arc<dyn EmbeddingGenerator> = Arc::new(DeterministicOfflineEngine::default());
    let mut ingest_cfg = IngestConfig::default();
    ingest_cfg.watch_paths = vec![docs_dir.clone()];
    let ingest = IngestEngine::new(
        ingest_cfg,
        Arc::clone(&storage),
        Arc::clone(&classifier),
        Arc::clone(&embedder),
    )
    .expect("create ingest engine");

    // 1. Multi-sheet .xlsx with OpenXML docProps/core.xml + sharedStrings + 2 worksheets
    let core_xml = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                       xmlns:dc="http://purl.org/dc/elements/1.1/"
                       xmlns:dcterms="http://purl.org/dc/terms/">
      <dc:title>Q4 2026 Cloud Security Budget</dc:title>
      <dc:creator>Femi Oyesanya</dc:creator>
      <cp:revision>7</cp:revision>
    </cp:coreProperties>"#;

    let workbook_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
    <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
              xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
      <sheets>
        <sheet name="Executive Summary" sheetId="1" r:id="rId1"/>
        <sheet name="Vendor Contracts" sheetId="2" r:id="rId2"/>
      </sheets>
    </workbook>"#;

    let workbook_rels = br#"<?xml version="1.0" encoding="UTF-8"?>
    <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
      <Relationship Id="rId1" Target="worksheets/sheet1.xml"/>
      <Relationship Id="rId2" Target="worksheets/sheet2.xml"/>
    </Relationships>"#;

    let shared_strings = br#"<?xml version="1.0" encoding="UTF-8"?>
    <sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
      <si><t>Department</t></si>
      <si><t>AI Security Architecture</t></si>
      <si><t>PQC HSM Appliance</t></si>
      <si><t>2026-11-15</t></si>
    </sst>"#;

    let sheet1 = br#"<?xml version="1.0" encoding="UTF-8"?>
    <worksheet><sheetData>
      <row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>
    </sheetData></worksheet>"#;

    let sheet2 = br#"<?xml version="1.0" encoding="UTF-8"?>
    <worksheet><sheetData>
      <row r="1"><c r="A1" t="s"><v>2</v></c><c r="B1"><v>148500</v></c><c r="C1" t="s"><v>3</v></c></row>
    </sheetData></worksheet>"#;

    let xlsx_path = docs_dir.join("budget_2026.xlsx");
    let xlsx_bytes = build_stored_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("docProps/core.xml", core_xml),
        ("xl/workbook.xml", workbook_xml),
        ("xl/_rels/workbook.xml.rels", workbook_rels),
        ("xl/sharedStrings.xml", shared_strings),
        ("xl/worksheets/sheet1.xml", sheet1),
        ("xl/worksheets/sheet2.xml", sheet2),
    ]);
    std::fs::write(&xlsx_path, &xlsx_bytes).unwrap();

    let xlsx_chunks = ingest
        .ingest_file(&xlsx_path)
        .await
        .expect("ingest xlsx")
        .expect("accepted xlsx");
    assert!(!xlsx_chunks.is_empty());

    let parent_xlsx = storage
        .load_parent_document(&xlsx_path.to_string_lossy(), 2)
        .expect("parent xlsx stored");
    assert_eq!(parent_xlsx.format, DocumentFormat::Spreadsheet);
    assert_eq!(parent_xlsx.title.as_deref(), Some("Q4 2026 Cloud Security Budget"));
    assert_eq!(parent_xlsx.author.as_deref(), Some("Femi Oyesanya"));
    assert_eq!(parent_xlsx.metadata.get("doc_revision").map(String::as_str), Some("7"));
    assert!(parent_xlsx.full_text.contains("=== Sheet: Executive Summary ==="));
    assert!(parent_xlsx.full_text.contains("=== Sheet: Vendor Contracts ==="));
    assert!(parent_xlsx.full_text.contains("PQC HSM Appliance\t148500\t2026-11-15"));

    // 2. Multi-chunk .docx where critical credential table sits > 4,500 bytes past chunk 0
    let mut filler_paragraphs = String::new();
    for idx in 1..=35 {
        filler_paragraphs.push_str(&format!(
            "<w:p><w:r><w:t>Section {} details distributed consensus validation, Byzantine quorum stability, and post-quantum lattice key rotation across enterprise enclaves.</w:t></w:r></w:p>",
            idx
        ));
    }
    let docx_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
          <w:body>
            <w:p><w:r><w:t>Femi Oyesanya — Principal AI Security Executive Dossier</w:t></w:r></w:p>
            {}
            <w:tbl>
              <w:tr>
                <w:tc><w:p><w:r><w:t>CISSP-ISSAP Renewal</w:t></w:r></w:p></w:tc>
                <w:tc><w:p><w:r><w:t>Certificate #884920</w:t></w:r></w:p></w:tc>
                <w:tc><w:p><w:r><w:t>2026-09-30</w:t></w:r></w:p></w:tc>
              </w:tr>
            </w:tbl>
          </w:body>
        </w:document>"#,
        filler_paragraphs
    );
    let docx_path = docs_dir.join("executive_dossier.docx");
    let docx_bytes = build_stored_zip(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("docProps/core.xml", core_xml),
        ("word/document.xml", docx_xml.as_bytes()),
    ]);
    std::fs::write(&docx_path, &docx_bytes).unwrap();

    let docx_chunks = ingest
        .ingest_file(&docx_path)
        .await
        .expect("ingest docx")
        .expect("accepted docx");
    assert!(
        docx_chunks.len() >= 2,
        "Expected multi-chunk .docx, got {} chunk(s)",
        docx_chunks.len()
    );
    assert!(
        !docx_chunks[0].text_content.contains("884920"),
        "Chunk 0 should not initially contain the distant table row"
    );

    // 3. Test Rhai sandboxed RLM `peek_slice` and `regex_grep` against live StorageEngine
    let ws = Arc::new(Mutex::new(RlmWorkspaceState::default()));
    let searcher: Arc<dyn StorageSearcher> = Arc::clone(&storage) as Arc<dyn StorageSearcher>;
    let rhai_engine = RlmOrchestrator::create_sandboxed_engine_with_storage(
        &RlmConfig::default(),
        ws,
        "qwen2.5:3b".to_string(),
        Arc::clone(&searcher),
        2,
    );
    let escaped_path = docx_path.to_string_lossy().replace('\\', "\\\\");
    let grep_script = format!(r#"regex_grep("{}", "884920")"#, escaped_path);
    let grep_arr: rhai::Array = rhai_engine.eval(&grep_script).expect("rhai regex_grep");
    assert_eq!(grep_arr.len(), 1);
    assert!(grep_arr[0].to_string().contains("CISSP-ISSAP Renewal | Certificate #884920 | 2026-09-30"));

    let peek_script = format!(r#"peek_slice("{}", 0, 120)"#, escaped_path);
    let peek_out: String = rhai_engine.eval(&peek_script).expect("rhai peek_slice");
    assert!(peek_out.contains("Femi Oyesanya"));

    // 4. Test Live RLM Enrichment (`enrich_retrieved_chunks_with_parent_rlm`) + Mesh Peer Preservation
    let local_scored = ScoredChunk::new(docx_chunks[0].clone(), 0.95, "local", false);
    let mesh_chunk = DocumentChunk::new(
        "mesh_doc:0",
        "mesh_doc",
        "/remote/peer/Femi_Oyesanya_AI_Security_Resume.docx",
        1,
        15,
        0,
        vec![0.0; 768],
        "Remote mesh peer evidence: Master of Science in Data Science (2024-2026).",
        None,
    )
    .unwrap();
    let remote_scored = ScoredChunk::new(mesh_chunk, 0.91, "12D3KooWDRDLPeerTestNode", true);

    let mut retrieved = vec![local_scored, remote_scored];
    RlmOrchestrator::enrich_retrieved_chunks_with_parent_rlm(
        "What is the CISSP-ISSAP Certificate 884920 renewal date?",
        &mut retrieved,
        searcher.as_ref(),
        2,
    );

    assert!(
        retrieved[0].chunk.text_content.contains("Certificate #884920 | 2026-09-30"),
        "RLM parent enrichment must pull distant matching table row into chunk 0; got: {}",
        retrieved[0].chunk.text_content
    );
    assert_eq!(retrieved[1].source_peer, "12D3KooWDRDLPeerTestNode");
    assert!(retrieved[1].is_remote);
    assert!(retrieved[1]
        .chunk
        .text_content
        .contains("Remote mesh peer evidence: Master of Science in Data Science"));
}

#[tokio::test]
async fn retroactive_tantivy_parent_reconstruction_heals_legacy_chunks_without_recrawl() {
    let temp = tempfile::tempdir().expect("tempdir");
    let storage = StorageEngine::open(StorageConfig::new(temp.path().join("storage")))
        .await
        .expect("open storage");

    let legacy_path = "D:/legacy_docs/Retroactive_Audit_Report.pdf";
    let c0 = DocumentChunk::new(
        "legacyb3:0",
        "legacyb3",
        legacy_path,
        1,
        20,
        0,
        vec![0.0; 768],
        "[Document: \"Retroactive Audit Report\" | File: Retroactive_Audit_Report.pdf]\nExecutive Overview: QuorumRAG cluster achieved 99.98% uptime in Q3.",
        Some(r#"{"chunk_index":0,"char_start":0,"char_end":70}"#.to_string()),
    )
    .unwrap();
    let c1 = DocumentChunk::new(
        "legacyb3:1",
        "legacyb3",
        legacy_path,
        21,
        45,
        0,
        vec![0.0; 768],
        "[Document: \"Retroactive Audit Report\" | File: Retroactive_Audit_Report.pdf]\nAppendix Table B: Zero-Trust Latency P95 = 14.2 ms across 4 LAN peers.",
        Some(r#"{"chunk_index":1,"char_start":71,"char_end":142}"#.to_string()),
    )
    .unwrap();

    // Insert ONLY chunks (no upsert_parent_document call) to simulate pre-v0.6.3 indexed corpus
    storage.insert_chunks(&[c1, c0]).await.expect("insert legacy chunks");
    assert_eq!(storage.catalog().count_parent_documents().unwrap(), 0);

    let reconstructed = storage
        .load_parent_document(legacy_path, 2)
        .expect("reconstruct")
        .expect("parent reconstructed from Tantivy");
    assert!(reconstructed.full_text.contains("99.98% uptime in Q3"));
    assert!(reconstructed.full_text.contains("Zero-Trust Latency P95 = 14.2 ms"));
    let pos_q3 = reconstructed.full_text.find("99.98%").unwrap();
    let pos_p95 = reconstructed.full_text.find("14.2 ms").unwrap();
    assert!(pos_q3 < pos_p95, "Chunks must be ordered by chunk_index");
    assert_eq!(
        storage.catalog().count_parent_documents().unwrap(),
        1,
        "Reconstructed parent document must be cached in SQLite parent_documents"
    );
}

#[test]
fn magic_byte_filter_blocks_pe_elf_macho_wasm_even_when_disguised_as_documents() {
    let temp = tempfile::tempdir().expect("tempdir");
    let router = ClassifierRouter::new(IngestConfig::default());

    // 1. Disguised Windows PE executable (`disguised_pe.txt`)
    let mut pe_bytes = vec![0u8; 256];
    pe_bytes[0..2].copy_from_slice(b"MZ");
    pe_bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe_bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let pe_file = temp.path().join("disguised_pe.txt");
    std::fs::write(&pe_file, &pe_bytes).unwrap();
    assert!(matches!(
        router.evaluate_file(&pe_file),
        FilterDecision::SkipBinary { .. }
    ));

    // 2. Disguised Linux ELF shared object (`disguised_elf.pdf`)
    let mut elf_bytes = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0];
    elf_bytes.extend_from_slice(&[0u8; 120]);
    let elf_file = temp.path().join("disguised_elf.pdf");
    std::fs::write(&elf_file, &elf_bytes).unwrap();
    assert!(matches!(
        router.evaluate_file(&elf_file),
        FilterDecision::SkipBinary { .. }
    ));

    // 3. Disguised macOS 64-bit Mach-O binary (`disguised_macho.md`)
    let mut macho_bytes = vec![0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01];
    macho_bytes.extend_from_slice(&[0u8; 120]);
    let macho_file = temp.path().join("disguised_macho.md");
    std::fs::write(&macho_file, &macho_bytes).unwrap();
    assert!(matches!(
        router.evaluate_file(&macho_file),
        FilterDecision::SkipBinary { .. }
    ));

    // 4. Legitimate plain-text note starting with ASCII letters "MZ" must NOT be falsely blocked
    let note_file = temp.path().join("mz_architecture_notes.txt");
    std::fs::write(
        &note_file,
        "MZ-2026 Security Architecture Notes: All peer frames require Ed25519 signatures and BLAKE3 hashes.\n",
    )
    .unwrap();
    assert!(
        matches!(router.evaluate_file(&note_file), FilterDecision::Accept { .. }),
        "Legitimate plain-text note starting with 'MZ-' must be accepted"
    );
}

#[test]
fn verbatim_citation_grounding_enforces_exact_substring_and_byte_spans() {
    let source = "[Document: Title: \"Academic Record\" | Author: Femi Oyesanya]\nMaster of Management Information Systems from University of Illinois Springfield (1992).\nCurrently pursuing Master of Science in Data Science (2024 - 2026).";

    let valid_and_fabricated = vec![
        GroundedCitation {
            document_id: "doc1".to_string(),
            file_path: "D:/docs/Resume.docx".to_string(),
            start_char: 0,
            end_char: 0,
            cited_text: "Master of Management Information Systems from University of Illinois Springfield (1992).".to_string(),
            confidence: 0.96,
            node_id: "local".to_string(),
            is_external: false,
            node_alias: None,
            rationale: None,
        },
        GroundedCitation {
            document_id: "doc1".to_string(),
            file_path: "D:/docs/Resume.docx".to_string(),
            start_char: 0,
            end_char: 0,
            cited_text: "PhD in Quantum Astrophysics from Mars University (1999).".to_string(),
            confidence: 0.50,
            node_id: "local".to_string(),
            is_external: false,
            node_alias: None,
            rationale: None,
        },
    ];

    let verified = RlmOrchestrator::verify_rlm_action_citations(source, valid_and_fabricated);
    assert_eq!(verified.len(), 1, "Fabricated quote must be rejected");
    assert_eq!(
        &source[verified[0].start_char..verified[0].end_char],
        verified[0].cited_text
    );

    let chunk = DocumentChunk::new(
        "doc1:0",
        "doc1",
        "D:/docs/Resume.docx",
        1,
        10,
        0,
        vec![0.0; 768],
        source,
        Some(r#"{"parent_window_start_byte":100}"#.to_string()),
    )
    .unwrap();
    let sc = ScoredChunk::new(chunk, 0.96, "local", false);
    let mut cits = vec![sc.to_citation()];
    let refs = vec![&sc];
    RlmOrchestrator::verify_and_attach_verbatim_grounding(
        "Where did he earn his Master of Management Information Systems?",
        "He earned a Master of Management Information Systems from University of Illinois Springfield (1992) [1].",
        &refs,
        &mut cits,
    );

    let quote = cits[0].verbatim_quote.as_deref().expect("verbatim_quote populated");
    assert!(source.contains(quote), "Emitted verbatim_quote must be an exact substring of source");
    assert!(quote.contains("University of Illinois Springfield (1992)"));
    let (b_start, b_end) = cits[0].byte_range.expect("byte_range populated");
    assert!(b_start >= 100 && b_end > b_start);
    assert!(cits[0].grounding_rationale.is_some());

    // Ensure backward-compatible JSON serialization roundtrip on Citation
    let json = serde_json::to_string(&cits[0]).unwrap();
    let roundtrip: Citation = serde_json::from_str(&json).unwrap();
    assert_eq!(roundtrip.verbatim_quote.as_deref(), Some(quote));
    assert_eq!(roundtrip.byte_range, Some((b_start, b_end)));
}

#[test]
fn multimodal_ollama_vision_image_captioning_and_indexing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let png_path = temp.path().join("pasture_scene.png");
    let png_bytes = build_valid_rgb_png_64x64();
    std::fs::write(&png_path, &png_bytes).unwrap();

    let classifier = FileTypeClassifier::new();
    let identity = classifier.classify_file(&png_path).expect("classify png");
    let embedder = DeterministicOfflineEngine::default();

    let chunk = ImageIndexer::index_image(&png_path, &png_bytes, &identity, 0, &embedder)
        .expect("index_image succeeds");
    assert!(chunk.text_content.contains("[Image Document: pasture_scene.png]"));
    assert!(chunk.text_content.contains("64x64"));

    // Verify SSRF guard blocks non-loopback endpoints cleanly
    let ssrf_err = ImageIndexer::caption_image_with_ollama(
        &png_path,
        "http://10.0.0.5:11434",
        "moondream:latest",
    );
    assert!(ssrf_err.is_err(), "Non-loopback vision URL must be rejected");

    // When local Ollama is running with an installed vision model (e.g. moondream:latest),
    // verify real end-to-end multimodal captioning produces searchable scene descriptions!
    if let Ok(stream) = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:11434".parse().unwrap(),
        std::time::Duration::from_millis(300),
    ) {
        drop(stream);
        if let Ok(caption) = ImageIndexer::caption_image_with_ollama(
            &png_path,
            "http://127.0.0.1:11434",
            "moondream:latest",
        ) {
            assert!(
                caption.len() >= 8,
                "Expected non-empty vision description from local Ollama, got: {}",
                caption
            );
            assert!(
                chunk.text_content.contains("[Visual Description]"),
                "ImageIndexer::index_image must embed [Visual Description] into searchable chunk text: {}",
                chunk.text_content
            );
        }
    }

    let _ = DocumentExtractor::is_excluded_executable_or_library(&png_bytes, &png_path);
}
