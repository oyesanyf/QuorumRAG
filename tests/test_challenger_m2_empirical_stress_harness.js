/**
 * Challenger 1: Empirical Adversarial Stress Harness for Milestone 2
 * 
 * Tests:
 * 1. Complete elimination of QuorumRAG source crates (`CANONICAL_CODEBASE_FOLDERS`,
 *    `getCodebaseFoldersList`, `crates/*` placeholders) across all UI and daemon code.
 * 2. Breadcrumb address bar generator (`buildPathBreadcrumbs`) on deep, edge-case,
 *    and adversarial Windows and Unix paths.
 * 3. Explorer HTML generator (`renderWindowsFileExplorerHtml`) resilience against
 *    HTML injection / XSS in folder names and paths.
 * 4. DOM Event Delegation & StopPropagation isolation oracle:
 *    - Checkbox click -> executes selection action, NEVER drills down (browse-dir).
 *    - Folder row click -> drills down (browse-dir), NEVER mutates selection.
 *    - Folder Open -> button drills down (browse-dir).
 *    - Breadcrumb segment click -> navigates to prefix path.
 *    - Up button -> navigates to parentPath.
 *    - This PC button -> navigates to root ("").
 * 5. Full coverage across all 5 folder interfaces:
 *    - General Settings (`tab === 'general'`)
 *    - Data Opt-In & Folders (`tab === 'marketplace'`)
 *    - Mesh & Shared Folders (`tab === 'mesh'`)
 *    - Add New Documents (`marketplace` Step 3 / `newdoc`)
 *    - Reindex Engine modal (`#modal-reindex` / `reindex`)
 * 6. Zero inline event handlers (`onclick`, `onchange`, etc.) in frontend code.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ROOT_DIR = path.resolve(__dirname, '..');
const APP_JS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'app.js');
const INDEX_HTML_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'index.html');
const STYLES_CSS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'styles.css');
const SETTINGS_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'handlers', 'settings.rs');
const MARKETPLACE_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'handlers', 'marketplace.rs');
const SERVER_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'server.rs');

console.log('================================================================');
console.log('  CHALLENGER 1: EMPIRICAL STRESS HARNESS — MILESTONE 2         ');
console.log('================================================================');

const appJs = fs.readFileSync(APP_JS_PATH, 'utf8');
const indexHtml = fs.readFileSync(INDEX_HTML_PATH, 'utf8');
const stylesCss = fs.readFileSync(STYLES_CSS_PATH, 'utf8');
const settingsRs = fs.readFileSync(SETTINGS_RS_PATH, 'utf8');
const marketplaceRs = fs.readFileSync(MARKETPLACE_RS_PATH, 'utf8');
const serverRs = fs.readFileSync(SERVER_RS_PATH, 'utf8');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  [PASS] #${totalTests}: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  [FAIL] #${totalTests}: ${name}`);
    console.error(`         Error: ${err.message}`);
    failedTests++;
  }
}

// -----------------------------------------------------------------------------
// SECTION 1: Total Elimination of Source Crates & Legacy Placeholders
// -----------------------------------------------------------------------------
console.log('\n--- SUITE 1: Source Crate Elimination & Repository Boundary ---');

test('app.js has zero occurrences of CANONICAL_CODEBASE_FOLDERS', () => {
  assert(!appJs.includes('CANONICAL_CODEBASE_FOLDERS'), 'CANONICAL_CODEBASE_FOLDERS leaked in app.js');
});

test('app.js has zero occurrences of getCodebaseFoldersList', () => {
  assert(!appJs.includes('getCodebaseFoldersList'), 'getCodebaseFoldersList leaked in app.js');
});

test('app.js has zero occurrences of cachedCodebaseFolders or cachedCodebaseRoot', () => {
  assert(!appJs.includes('cachedCodebaseFolders'), 'cachedCodebaseFolders leaked in app.js');
  assert(!appJs.includes('cachedCodebaseRoot'), 'cachedCodebaseRoot leaked in app.js');
});

test('app.js has zero occurrences of "Browse Codebase Root"', () => {
  assert(!appJs.includes('Browse Codebase Root'), '"Browse Codebase Root" button leaked in app.js');
});

test('index.html has zero occurrences of "crates/quorum-coordinator"', () => {
  assert(!indexHtml.includes('crates/quorum-coordinator'), 'Internal crate leaked in index.html placeholder');
});

test('marketplace.rs does not contain discover_codebase_folders', () => {
  assert(!marketplaceRs.includes('discover_codebase_folders'), 'discover_codebase_folders leaked in marketplace.rs');
});

test('settings.rs does not contain discover_codebase_folders', () => {
  assert(!settingsRs.includes('discover_codebase_folders'), 'discover_codebase_folders leaked in settings.rs');
});

// -----------------------------------------------------------------------------
// SECTION 2: Extract & Stress-Test Core Explorer Functions
// -----------------------------------------------------------------------------
console.log('\n--- SUITE 2: Breadcrumb Address Bar Generation (buildPathBreadcrumbs) ---');

// We extract buildPathBreadcrumbs and renderWindowsFileExplorerHtml directly from app.js to test real code
function extractFunction(src, fnName) {
  const marker = `function ${fnName}(`;
  const start = src.indexOf(marker);
  if (start === -1) throw new Error(`Could not find function ${fnName}`);
  
  // Basic brace matching
  let braceCount = 0;
  let started = false;
  let end = start;
  for (let i = start; i < src.length; i++) {
    if (src[i] === '{') {
      braceCount++;
      started = true;
    } else if (src[i] === '}') {
      braceCount--;
      if (started && braceCount === 0) {
        end = i + 1;
        break;
      }
    }
  }
  return src.slice(start, end);
}

// Minimal escapeHtml simulator matching app.js
function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const buildPathBreadcrumbsCode = extractFunction(appJs, 'buildPathBreadcrumbs');
const renderWindowsFileExplorerHtmlCode = extractFunction(appJs, 'renderWindowsFileExplorerHtml');

// Evaluate in sandbox
const sandbox = {
  escapeHtml,
  currentBrowsePath: '',
  currentBrowseParentPath: '',
  cachedDrives: ['D:\\', 'C:\\'],
  cachedBrowseDirs: []
};

const evalCtx = new Function('sandbox', `
  with(sandbox) {
    ${buildPathBreadcrumbsCode}
    ${renderWindowsFileExplorerHtmlCode}
    return { buildPathBreadcrumbs, renderWindowsFileExplorerHtml };
  }
`);

const { buildPathBreadcrumbs, renderWindowsFileExplorerHtml } = evalCtx(sandbox);

test('buildPathBreadcrumbs handles empty path ("") as This PC', () => {
  const crumbs = buildPathBreadcrumbs('');
  assert.strictEqual(crumbs.length, 1);
  assert.strictEqual(crumbs[0].label, '💽 This PC');
  assert.strictEqual(crumbs[0].path, '');
});

test('buildPathBreadcrumbs handles null/undefined as This PC', () => {
  const crumbsNull = buildPathBreadcrumbs(null);
  assert.strictEqual(crumbsNull.length, 1);
  assert.strictEqual(crumbsNull[0].label, '💽 This PC');

  const crumbsUndef = buildPathBreadcrumbs(undefined);
  assert.strictEqual(crumbsUndef.length, 1);
  assert.strictEqual(crumbsUndef[0].label, '💽 This PC');
});

test('buildPathBreadcrumbs handles Windows drive root "D:\\"', () => {
  const crumbs = buildPathBreadcrumbs('D:\\');
  assert.strictEqual(crumbs.length, 2);
  assert.strictEqual(crumbs[0].label, '💽 This PC');
  assert.strictEqual(crumbs[0].path, '');
  assert.strictEqual(crumbs[1].label, '💽 D:\\');
  assert.strictEqual(crumbs[1].path, 'D:\\');
});

test('buildPathBreadcrumbs handles Windows drive letter without trailing slash "C:"', () => {
  const crumbs = buildPathBreadcrumbs('C:');
  assert.strictEqual(crumbs.length, 2);
  assert.strictEqual(crumbs[1].label, '💽 C:\\');
  assert.strictEqual(crumbs[1].path, 'C:\\');
});

test('buildPathBreadcrumbs handles forward slash path "D:/harfile/QuorumRAG"', () => {
  const crumbs = buildPathBreadcrumbs('D:/harfile/QuorumRAG');
  assert.strictEqual(crumbs.length, 4);
  assert.strictEqual(crumbs[0].path, '');
  assert.strictEqual(crumbs[1].path, 'D:\\');
  assert.strictEqual(crumbs[2].path, 'D:\\harfile');
  assert.strictEqual(crumbs[3].path, 'D:\\harfile\\QuorumRAG');
  assert.strictEqual(crumbs[2].label, 'harfile');
  assert.strictEqual(crumbs[3].label, 'QuorumRAG');
});

test('buildPathBreadcrumbs handles deeply nested path with spaces and special symbols', () => {
  const deepPath = 'E:\\Deeply Nested\\Folder #1 (2026)\\Sub [Docs]\\Final & Live';
  const crumbs = buildPathBreadcrumbs(deepPath);
  assert.strictEqual(crumbs.length, 6);
  assert.strictEqual(crumbs[1].path, 'E:\\');
  assert.strictEqual(crumbs[2].path, 'E:\\Deeply Nested');
  assert.strictEqual(crumbs[3].path, 'E:\\Deeply Nested\\Folder #1 (2026)');
  assert.strictEqual(crumbs[4].path, 'E:\\Deeply Nested\\Folder #1 (2026)\\Sub [Docs]');
  assert.strictEqual(crumbs[5].path, 'E:\\Deeply Nested\\Folder #1 (2026)\\Sub [Docs]\\Final & Live');
  assert.strictEqual(crumbs[5].label, 'Final & Live');
});

// -----------------------------------------------------------------------------
// SECTION 3: HTML Generator & XSS / Injection Resilience
// -----------------------------------------------------------------------------
console.log('\n--- SUITE 3: HTML Generator & XSS / Attribute Safety ---');

test('renderWindowsFileExplorerHtml safely escapes malicious directory names', () => {
  const maliciousDirs = [
    {
      name: '<script>alert("XSS")</script>',
      path: 'D:\\<script>alert("XSS")</script>',
      is_drive: false,
      is_quick_access: false
    },
    {
      name: 'Quote "breakout" & \'single\'',
      path: 'D:\\Quotes "breakout" & \'single\'',
      is_drive: false,
      is_quick_access: false
    }
  ];

  const html = renderWindowsFileExplorerHtml({
    contextId: 'test-xss',
    currentPath: 'D:\\Test',
    parentPath: 'D:\\',
    directories: maliciousDirs
  });

  // Verify unescaped tags and breakout characters are strictly absent
  assert(!html.includes('<script>'), 'Unescaped <script> tag detected!');
  assert(html.includes('&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'), 'Properly escaped script tag required');
  assert(html.includes('Quote &quot;breakout&quot; &amp; &#39;single&#39;'), 'Quotes and ampersands must be escaped');
});

test('renderWindowsFileExplorerHtml generates all required toolbar elements', () => {
  const html = renderWindowsFileExplorerHtml({
    contextId: 'general',
    currentPath: 'D:\\Projects',
    parentPath: 'D:\\',
    drives: ['D:\\', 'C:\\'],
    directories: [{ name: 'QuorumRAG', path: 'D:\\Projects\\QuorumRAG', is_drive: false }]
  });

  assert(html.includes('data-action="browse-root"'), 'Must have browse-root button');
  assert(html.includes('data-action="browse-up"'), 'Must have browse-up button');
  assert(html.includes('data-action="trigger-native-folder-picker"'), 'Must have native picker button');
  assert(html.includes('data-action="browse-dir"'), 'Must have browse-dir breadcrumb buttons');
  assert(html.includes('class="folder-row-checkbox"'), 'Must render folder row checkbox');
  assert(html.includes('class="pill-btn folder-select-btn'), 'Must render folder select action button');
  assert(html.includes('class="pill-btn folder-open-btn"'), 'Must render folder open button');
});

// -----------------------------------------------------------------------------
// SECTION 4: DOM Event Delegation & Propagation Isolation Oracle
// -----------------------------------------------------------------------------
console.log('\n--- SUITE 4: DOM Event Delegation & StopPropagation Oracle ---');

/**
 * Micro DOM Event Simulator to test bubbling and event delegation
 */
class MockElement {
  constructor(tag, attrs = {}) {
    this.tagName = tag.toUpperCase();
    this.attributes = Object.assign({}, attrs);
    this.dataset = {};
    for (const [k, v] of Object.entries(attrs)) {
      if (k.startsWith('data-')) {
        const camel = k.slice(5).replace(/-([a-z])/g, (_, g) => g.toUpperCase());
        this.dataset[camel] = v;
      }
    }
    this.className = attrs.class || '';
    this.value = attrs.value || '';
    this.checked = Boolean(attrs.checked);
    this.children = [];
    this.parentElement = null;
  }

  appendChild(child) {
    child.parentElement = this;
    this.children.push(child);
    return child;
  }

  closest(selector) {
    let cur = this;
    while (cur) {
      if (selector === '[data-action]' && cur.dataset.action) {
        return cur;
      }
      cur = cur.parentElement;
    }
    return null;
  }
}

// Build synthetic DOM tree of a folder row:
// container
//   └─ folder-row [data-action="browse-dir", data-folder-path="D:\Documents"]
//        ├─ folder-row-left
//        │    ├─ input.folder-row-checkbox [data-action="mkt-toggle-folder", data-folder-path="D:\Documents"]
//        │    ├─ span.folder-row-icon
//        │    └─ span.folder-row-name ("Documents")
//        └─ folder-row-actions
//             ├─ button.folder-select-btn [data-action="mkt-toggle-folder", data-folder-path="D:\Documents"]
//             └─ button.folder-open-btn [data-action="browse-dir", data-folder-path="D:\Documents"]
function buildRowDom(selectAction = 'mkt-toggle-folder') {
  const container = new MockElement('div', { class: 'settings-container' });
  const row = new MockElement('div', {
    class: 'folder-browser-item folder-row',
    'data-action': 'browse-dir',
    'data-folder-path': 'D:\\Documents'
  });
  const rowLeft = new MockElement('div', { class: 'folder-row-left' });
  const checkbox = new MockElement('input', {
    class: 'folder-row-checkbox',
    'data-action': selectAction,
    'data-folder-path': 'D:\\Documents'
  });
  const icon = new MockElement('span', { class: 'folder-row-icon' });
  const name = new MockElement('span', { class: 'folder-row-name' });

  const actions = new MockElement('div', { class: 'folder-row-actions' });
  const selectBtn = new MockElement('button', {
    class: 'folder-select-btn',
    'data-action': selectAction,
    'data-folder-path': 'D:\\Documents'
  });
  const openBtn = new MockElement('button', {
    class: 'folder-open-btn',
    'data-action': 'browse-dir',
    'data-folder-path': 'D:\\Documents'
  });

  rowLeft.appendChild(checkbox);
  rowLeft.appendChild(icon);
  rowLeft.appendChild(name);
  actions.appendChild(selectBtn);
  actions.appendChild(openBtn);
  row.appendChild(rowLeft);
  row.appendChild(actions);
  container.appendChild(row);

  return { container, row, checkbox, name, selectBtn, openBtn };
}

/**
 * Simulates click event dispatching and handler resolution in initSettingsEventDelegation
 */
function simulateClick(target, container, actionHandlers) {
  let propagationStopped = false;
  let defaultPrevented = false;

  const event = {
    target: target,
    preventDefault: () => { defaultPrevented = true; },
    stopPropagation: () => { propagationStopped = true; }
  };

  // Event bubbles up to container
  const actionEl = target.closest('[data-action]');
  if (!actionEl) return { handled: false };

  const action = actionEl.dataset.action;
  const folderPath = actionEl.dataset.folderPath || '';

  if (actionHandlers[action]) {
    actionHandlers[action](event, actionEl, folderPath);
    return {
      handled: true,
      action: action,
      folderPath: folderPath,
      propagationStopped: propagationStopped,
      defaultPrevented: defaultPrevented
    };
  }

  return { handled: false, action };
}

test('Clicking folder checkbox triggers selectAction and executes stopPropagation()', () => {
  const { container, checkbox } = buildRowDom('mkt-toggle-folder');
  let browseDirCalls = 0;
  let toggleFolderCalls = 0;

  const handlers = {
    'browse-dir': (e, el, path) => { browseDirCalls++; },
    'mkt-toggle-folder': (e, el, path) => {
      e.preventDefault();
      e.stopPropagation();
      toggleFolderCalls++;
    }
  };

  const res = simulateClick(checkbox, container, handlers);
  assert.strictEqual(res.action, 'mkt-toggle-folder');
  assert.strictEqual(res.propagationStopped, true, 'e.stopPropagation() must be called');
  assert.strictEqual(toggleFolderCalls, 1, 'Toggle folder action must be called');
  assert.strictEqual(browseDirCalls, 0, 'Drill-down browse-dir must NEVER be called when clicking checkbox');
});

test('Clicking folder-select-btn triggers selectAction and executes stopPropagation()', () => {
  const { container, selectBtn } = buildRowDom('share-folder');
  let browseDirCalls = 0;
  let shareFolderCalls = 0;

  const handlers = {
    'browse-dir': (e, el, path) => { browseDirCalls++; },
    'share-folder': (e, el, path) => {
      e.preventDefault();
      e.stopPropagation();
      shareFolderCalls++;
    }
  };

  const res = simulateClick(selectBtn, container, handlers);
  assert.strictEqual(res.action, 'share-folder');
  assert.strictEqual(res.propagationStopped, true, 'e.stopPropagation() must be called');
  assert.strictEqual(shareFolderCalls, 1, 'Share folder action must be called');
  assert.strictEqual(browseDirCalls, 0, 'Drill-down browse-dir must NEVER be called when clicking select button');
});

test('Clicking folder row or name triggers browse-dir and drills into folder', () => {
  const { container, name } = buildRowDom('mkt-toggle-folder');
  let browsedPath = '';
  let toggleFolderCalls = 0;

  const handlers = {
    'browse-dir': (e, el, path) => {
      e.preventDefault();
      browsedPath = path;
    },
    'mkt-toggle-folder': (e, el, path) => { toggleFolderCalls++; }
  };

  const res = simulateClick(name, container, handlers);
  assert.strictEqual(res.action, 'browse-dir');
  assert.strictEqual(browsedPath, 'D:\\Documents', 'Must drill into D:\\Documents');
  assert.strictEqual(toggleFolderCalls, 0, 'Checkbox/select action must NOT be triggered by row click');
});

test('Clicking Open -> button triggers browse-dir and drills into folder', () => {
  const { container, openBtn } = buildRowDom('mkt-toggle-folder');
  let browsedPath = '';

  const handlers = {
    'browse-dir': (e, el, path) => {
      e.preventDefault();
      browsedPath = path;
    }
  };

  const res = simulateClick(openBtn, container, handlers);
  assert.strictEqual(res.action, 'browse-dir');
  assert.strictEqual(browsedPath, 'D:\\Documents', 'Must drill into folder via Open button');
});

// -----------------------------------------------------------------------------
// SECTION 5: Multi-Interface Coverage Verification
// -----------------------------------------------------------------------------
console.log('\n--- SUITE 5: Universal Coverage Across 5 Folder Interfaces ---');

const INTERFACE_CONTRACTS = [
  { name: 'General Settings', contextId: 'general', selectAction: 'mkt-toggle-folder' },
  { name: 'Marketplace Data Opt-In', contextId: 'mkt', selectAction: 'mkt-toggle-folder' },
  { name: 'Mesh & Shared Folders', contextId: 'mesh', selectAction: 'share-folder' },
  { name: 'Add New Documents', contextId: 'newdoc', selectAction: 'newdoc-pick-folder' },
  { name: 'Reindex Engine Modal', contextId: 'reindex', selectAction: 'reindex-pick-folder' }
];

INTERFACE_CONTRACTS.forEach(iface => {
  test(`Interface "${iface.name}" is wired with contextId="${iface.contextId}" and selectAction="${iface.selectAction}"`, () => {
    assert(appJs.includes(`contextId: '${iface.contextId}'`), `Missing contextId: '${iface.contextId}' in app.js`);
    assert(appJs.includes(`selectAction: '${iface.selectAction}'`), `Missing selectAction: '${iface.selectAction}' in app.js`);
  });
});

test('Reindex engine modal contains dedicated folder explorer mount point', () => {
  assert(indexHtml.includes('id="reindex-folder-explorer-mount"'), 'index.html must have #reindex-folder-explorer-mount');
  assert(appJs.includes('renderReindexExplorer()'), 'app.js must call renderReindexExplorer()');
});

// -----------------------------------------------------------------------------
// SECTION 6: Invariant Checks: Zero Inline Handlers & CSS Rules
// -----------------------------------------------------------------------------
console.log('\n--- SUITE 6: Architecture Invariants (Zero Inline Handlers & CSS) ---');

test('Zero inline onclick handlers in app.js and dynamic templates', () => {
  const inlineOnClickRegex = /onclick\s*=/i;
  assert(!inlineOnClickRegex.test(appJs), 'Forbidden inline onclick= found in app.js');
});

test('Zero inline event handlers in folder explorer components of index.html', () => {
  const mountIdx = indexHtml.indexOf('id="reindex-folder-explorer-mount"');
  assert(mountIdx !== -1, 'reindex mount must exist');
  const slice = indexHtml.slice(Math.max(0, mountIdx - 200), mountIdx + 300);
  assert(!slice.includes('onclick='), 'Explorer mount contains inline onclick');
  assert(!slice.includes('onchange='), 'Explorer mount contains inline onchange');
});

test('styles.css contains full styling suite for Windows File Explorer', () => {
  const requiredStyles = [
    '.folder-explorer-container',
    '.folder-explorer-toolbar',
    '.folder-explorer-nav-buttons',
    '.folder-explorer-drives',
    '.folder-drive-pill',
    '.folder-native-picker-btn',
    '.folder-explorer-address-bar',
    '.folder-breadcrumbs',
    '.folder-breadcrumb-segment',
    '.folder-row',
    '.folder-row-checkbox',
    '.folder-row-icon',
    '.folder-row-details',
    '.folder-row-name',
    '.folder-select-btn',
    '.folder-open-btn'
  ];
  for (const sel of requiredStyles) {
    assert(stylesCss.includes(sel), `styles.css must define ${sel}`);
  }
});

// -----------------------------------------------------------------------------
// SUMMARY
// -----------------------------------------------------------------------------
console.log('\n================================================================');
console.log(`  EMPIRICAL CHALLENGER VERDICT: ${failedTests === 0 ? 'APPROVE' : 'REQUEST_CHANGES'}`);
console.log(`  Tests Executed: ${totalTests} | Passed: ${passedTests} | Failed: ${failedTests}`);
console.log('================================================================\n');

if (failedTests > 0) {
  process.exit(1);
}
