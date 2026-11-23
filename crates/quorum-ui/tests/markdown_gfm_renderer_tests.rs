use quorum_ui::get_asset;

#[test]
fn test_gfm_markdown_renderer_supports_tables_quotes_fences_and_details() {
    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);

    // 1. GFM Table parsing & accessible responsive wrapper
    assert!(
        js.contains("function parseGfmTableRow(") && js.contains("function parseGfmSeparatorAlignments("),
        "app.js must implement GFM pipe table parsing"
    );
    assert!(
        js.contains("class=\"qr-md-table-wrap\"") && js.contains("class=\"qr-md-table\"") && js.contains("tabindex=\"0\" role=\"region\""),
        "GFM tables must render inside an accessible scrollable .qr-md-table-wrap region"
    );
    assert!(
        js.contains("<th scope=\"col\""),
        "GFM table headers must emit semantic <th scope=\"col\"> elements"
    );

    // 2. Blockquotes & fenced code blocks
    assert!(
        js.contains("class=\"qr-md-quote\""),
        "renderMarkdownHtml must render Markdown blockquotes with .qr-md-quote"
    );
    assert!(
        js.contains("class=\"qr-md-pre\""),
        "renderMarkdownHtml must render fenced code blocks with .qr-md-pre"
    );

    // 3. Safe allowlisted <details>/<summary> collapsible drawers (no headings inside summary, all text escaped)
    assert!(
        js.contains("class=\"qr-md-details\"") && js.contains("class=\"qr-md-summary\"") && js.contains("class=\"qr-md-details-body\""),
        "renderMarkdownHtml must parse QuorumRAG <details>/<summary> evidence drawers cleanly"
    );
    assert!(
        js.contains("renderInlineMarkdown(escapeHtml(summaryMatch[1].trim()))"),
        "Summary drawer labels must be HTML-escaped before inline rendering"
    );

    // 4. Inline code protection before bold/italic transforms & citation walker skips summary/pre/code
    assert!(
        js.contains("QRCODE"),
        "renderInlineMarkdown must protect inline code spans before bold/italic regexes"
    );
    assert!(
        js.contains("closest('code, pre, summary, .inline-cite-badge')"),
        "linkInlineCitations must skip code, pre, and summary elements when linking [N] badges"
    );

    // 5. Stale spellcheck auto-corrected footer must reset upon chat submit
    let submit_idx = js
        .find("async function submitPrompt()")
        .expect("submitPrompt must exist in app.js");
    let submit_slice = &js[submit_idx..(submit_idx + 2200).min(js.len())];
    assert!(
        submit_slice.contains("lastSpellcheckedText = ''")
            && submit_slice.contains("Dynamic LLM Spellcheck Active"),
        "submitPrompt must clear stale Auto-corrected spellcheck footer text after submitting"
    );
}

#[test]
fn test_gfm_markdown_css_rules_present_for_all_themes() {
    let (css_bytes, _) = get_asset("styles.css").expect("styles.css must be embedded");
    let css = String::from_utf8_lossy(&css_bytes);

    for selector in [
        ".qr-md-table-wrap",
        ".qr-md-table",
        ".qr-md-table thead",
        ".qr-md-table td:first-child",
        ".qr-md-table td:nth-child(3)",
        ".qr-md-quote",
        ".qr-md-pre",
        ".qr-md-details",
        ".qr-md-summary",
        ".qr-md-details-body",
        "body.theme-white .qr-md-table th",
        "@media (prefers-reduced-motion: no-preference)",
    ] {
        assert!(
            css.contains(selector),
            "styles.css must define {selector} for GFM markdown elements"
        );
    }

    // Top nav must flex-wrap with min-height instead of rigid 56px height so dropdowns never overlap telemetry-bar
    let top_nav_idx = css.find(".top-nav {").expect(".top-nav rule must exist");
    let top_nav_block = &css[top_nav_idx..(top_nav_idx + 400).min(css.len())];
    assert!(
        top_nav_block.contains("min-height: 56px;") && top_nav_block.contains("flex-wrap: wrap;"),
        ".top-nav must use min-height: 56px and flex-wrap: wrap to prevent header overlap"
    );

    let (js_bytes, _) = get_asset("app.js").expect("app.js must be embedded");
    let js = String::from_utf8_lossy(&js_bytes);
    assert!(
        js.contains("✓ Complete — "),
        "markTelemetryComplete must clear stale Synthesizing status to Complete"
    );
    assert!(
        js.contains(r"\bHYPERLINK\s+"),
        "renderMarkdownHtml must clean legacy saved HYPERLINK field codes on display"
    );
}
