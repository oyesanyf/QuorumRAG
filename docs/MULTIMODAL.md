# Multimodal RAG in QuorumRAG

QuorumRAG indexes and answers questions over documents, images, and audio on this computer.
Everything runs locally: the daemon uses only loopback Ollama models and never calls a
cloud API.

## What gets indexed

| Kind | Formats | What is extracted |
|------|---------|-------------------|
| Documents | pdf, docx, doc, odt, rtf, txt, md, xlsx, pptx, ... | Text, split into chunks |
| Images | jpg/jpeg, png, webp, gif, bmp, tiff, svg | Dimensions, format, EXIF camera fields, **EXIF GPS (IFD `0x8825`)**, XMP/IPTC location and keywords, Windows XPKeywords, folder/file name tags, and an offline place name resolved from GPS |
| Audio | mp3, wav, flac (ogg, m4a, aac, wma, aiff, opus by extension) | ID3v1/ID3v2 title, artist, album, year, genre, track, embedded `USLT` lyrics; MPEG frame bitrate, sample rate, channels, duration; WAV/FLAC stream info; companion lyrics files (`<name>.lrc`, `<name>.txt`, `<name>.srt`, `lyrics.txt`, `transcript.txt`) |

### What is never indexed

Only compiled executables and shared libraries are skipped
(`quorum_classifier::is_binary_executable_extension`):

- Windows: `.exe .dll .sys .drv .ocx .scr .cpl .efi .obj .lib .pdb`
- Linux: ELF binaries, `.so .ko .o .a`
- macOS: Mach-O binaries, `.dylib .bundle .kext`
- Bytecode: `.wasm .dex .class .pyc`

Audio and images are no longer treated as "binary" and skipped (video still is; see Known limitations).

## Image location (GPS) and the offline reverse geocoder

`crates/quorum-ingest/src/exif.rs` parses the TIFF IFD structure found in JPEG APP1, PNG `eXIf`,
WebP `EXIF`, and bare TIFF files. GPS latitude/longitude (three RATIONALs each) are converted to
signed decimal degrees using the N/S and E/W reference tags. Malformed data never panics; it just
yields no coordinates.

`crates/quorum-ingest/src/reverse_geocoder.rs` maps coordinates to a place with the haversine
distance against an embedded gazetteer. A photo is labelled as taken *in* a place only if it falls
inside that place's radius. Otherwise it is labelled "near <place> (N km away)", or left without a
place when nothing is within 60 km.

**Coverage limits.** The gazetteer has about 160 places: the La Grange towns (TX, IL, KY, GA, NC, TN,
WY, IN), US state capitals and large metros, Washington DC suburbs, and major world cities. It is not
a full world gazetteer, so a photo from a small town that isn't listed is attributed to the nearest
listed place ("near ...") or not at all.

The resolved place goes into the image's search text, for example
`Location (taken in (from GPS)): Beltsville, Maryland, United States`, along with `Location Tags`.
Images that were indexed before this change need a reindex to pick it up (see below).

## Query handling

`crates/quorum-storage/src/query_framing.rs`:

- **Removes conversational framing** before BM25 search. For example, "show me the File that contains a cow"
  becomes `cow`, "are there pictures taken in La Grange" becomes `La Grange`, and
  "tell me about the song Savannah Woman" becomes `Savannah Woman`.
- **Detects which media the question asks for** ("pictures/photos/images", "song/music/audio/lyrics",
  "video"). Hits from the matching media indexer are ranked first. Other hits are kept, never dropped.

## Query-time vision ("what is in this picture?")

Image chunks only contain metadata. For questions about what an image *shows*,
`crates/quorum-coordinator/src/vision.rs` reads up to 3 of the top cited **local** image files,
base64-encodes them, and sends them to an installed Ollama vision model through `/api/generate`
with `images: [...]`. The model is picked in this order: `moondream`, `llava-phi3`, `llava:7b`,
`llava`, `qwen2.5vl`, `llama3.2-vision`, `minicpm-v`, `bakllava`, `gemma3`. The description is added
to that excerpt as `Visual Content (...)` and to the grounding corpus, so the answer can describe
the picture and cite it.

- Results are cached in memory by BLAKE3 hash of the image bytes, so asking again is instant.
- If no vision model is installed, a background `ollama pull moondream` starts (when free memory
  allows), and the answer falls back to metadata only.
- Each image costs about 8 to 10 seconds with `moondream` on this machine.

## Answer orchestration when the LLM is slow or unavailable

`crates/quorum-coordinator/src/answer_orchestrator.rs` keeps answers meaningful in three stages:

1. **Primary synthesis.** The configured local model writes the grounded answer (unchanged).
2. **Fast-model retry.** If the primary model fails or times out (for example `gemma4:26b` on CPU while
   the machine is busy), up to two smaller installed models (`qwen2.5:7b`, `glm4:9b`, `gemma2:9b`, ...)
   retry over the 5 strongest excerpts.
3. **LangExtract-style grounded composition.** If no model answers, facts are extracted from the cleaned
   excerpts: the subject's role ("Angela Davis (landlord)"), other parties, addresses, phone numbers,
   emails, labelled amounts ("late fee of $50.00"), and dates. Each candidate is grounded to an exact
   character span with `langextract::extraction::ground_extraction`, and ungrounded candidates are dropped
   by `filter_grounded`. The same fact found in several documents is merged with all its citations. The
   answer opens with the documented role, followed by **Key facts from the documents** and
   **Relevant passages** (verbatim sentences). Raw excerpt dumps and ALL-CAPS document titles are no longer
   used as the answer.

## Web UI: clickable attachments

In `crates/quorum-ui/assets/app.js`:

- **Inline media gallery** above the Sources list:
  - Cited local images show as thumbnails. Clicking one opens a lightbox.
  - Audio shows an `<audio controls>` player and video a `<video controls>` player.
  - A card is removed instead of shown broken if the file can't be served.
  - If the answer says nothing matched, no media cards are shown.
- **Source cards are clickable.** The `[n] filename` header and the full file path open a preview.
  The inspector has **Preview, Open, Download, Open in App, Copy Path**.
- **Inline `[1]`, `[2]` markers** in the answer are buttons. Clicking one scrolls to and highlights
  the source, then opens its inspector.
- **Save File** is a menu: **Save as PDF**, **Save as Word (.docx)**, **Save Both**, **Save as Markdown**.
  It uses the native save dialog when the browser supports it and a normal download otherwise.

## HTTP endpoints

| Endpoint | Purpose | Security |
|----------|---------|----------|
| `GET /api/media?path=<file>[&download=1]` | Streams a cited file with the correct MIME type and HTTP `Range` (206) support, which audio/video seeking needs | The exact path must be an indexed `file_path` at access tier 0. Relative paths, `..`, `%2e`/`%2f`/`%5c`/`%00`, NUL, NTFS alternate data streams, and executable/library extensions are rejected. Responses carry `nosniff` and a sandboxing CSP. |
| `POST /api/open-file` `{"path": ...}` | Opens an indexed file in the OS default app | Loopback callers only (the daemon is served with connect info), plus the same index gate |
| `POST /api/export` | Exports an answer as a real `%PDF-1.4` (Helvetica metrics, word wrap, pagination, embedded JPEG, byte-exact xref) or `.docx` (OPC zip with CRC-32, heading styles, bold runs, lists, Sources, embedded images) | Images listed in `attached_media` are embedded only if they pass the `/api/media` gate |

## Reindexing media after upgrading

Files that were indexed before this release (or skipped as "binary") need a reindex:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:3031/api/reindex -ContentType application/json `
  -Body '{"target_paths":["D:\\dataset\\images","D:\\harfile\\music"],"full_rebuild":false}'
Invoke-RestMethod -Method Post http://127.0.0.1:3031/api/cache/recache -ContentType application/json -Body '{"clear":true}'
```

The reindex now replaces a file's old chunks instead of adding duplicates. On startup the vector store
detects an existing IVF_PQ index, so the first write after a restart no longer retrains the whole index.

## Known limitations

- The gazetteer is limited (see above); there is no HEIC GPS parsing yet.
- Speech-to-text transcription of audio isn't implemented. Audio answers rely on tags, embedded lyrics,
  and companion lyric files.
- Video files are not indexed yet: there is no video metadata extractor, so the ingest router still
  skips them. The UI and `/api/media` can already play video if a video file is cited.
- The chat composer doesn't accept uploaded attachments yet. Multimodal input currently means the
  indexed files and query-time vision over retrieved images.
- Query-time vision only covers local files, not files from mesh peers.
- Small vision models can invent details (for example `moondream` once gave a dog a name). Treat
  visual descriptions as approximate.
- Open retrieval issue: "tell me about the song Savannah Woman" cites the `Savannah Woman.doc` lyrics
  but not `Savannah_Woman.mp3`, even though the MP3 is indexed and streams via `/api/media`.
- Acronym collisions: "show me the File that contains a cow" can match "COW" (copy-on-write) in
  technical documents when no cow image is indexed.
