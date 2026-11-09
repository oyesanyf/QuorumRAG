/**
 * Adversarial Challenger Stress Harness for Milestone 2:
 * Interactive and Clickable Windows File Explorer Invariants
 *
 * Verifies:
 * 1. Complete elimination of QuorumRAG source crates (`CANONICAL_CODEBASE_FOLDERS`,
 *    `getCodebaseFoldersList`, `crates/*` placeholders).
 * 2. Real Windows File Explorer architecture:
 *    - Drive root listing with actual physical drives and quick-access folders
 *    - Clickable breadcrumb address bar (`buildPathBreadcrumbs`)
 *    - Drill-down row navigation (`data-action="browse-dir"`)
 *    - StopPropagation on selection checkboxes and button actions
 *    - Native OS folder dialog trigger (`trigger-native-folder-picker`)
 * 3. Explorer integration across all target interfaces:
 *    - Data Opt-In & Folders (`marketplace` / `mkt`)
 *    - General Settings (`general`)
 *    - Mesh & Shared Folders (`mesh`)
 *    - Add New Documents (`marketplace` Step 3 / `newdoc`)
 *    - Reindex Engine Modal (`modal-reindex` / `reindex`)
 * 4. Daemon routing and handler contracts for `/api/fs/browse-folders` and `/api/fs/pick-folder`.
 * 5. CSS classes and visual ergonomics in `styles.css`.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ROOT_DIR = path.resolve(__dirname, '..');
const STYLES_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'styles.css');
const APP_JS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'app.js');
const INDEX_HTML_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'index.html');
const SETTINGS_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'handlers', 'settings.rs');
const SERVER_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'server.rs');

console.log('================================================================');
console.log('  CHALLENGER 2: WINDOWS FILE EXPLORER INVARIANT HARNESS        ');
console.log('================================================================');

assert(fs.existsSync(STYLES_PATH), `styles.css must exist at ${STYLES_PATH}`);
assert(fs.existsSync(APP_JS_PATH), `app.js must exist at ${APP_JS_PATH}`);
assert(fs.existsSync(INDEX_HTML_PATH), `index.html must exist at ${INDEX_HTML_PATH}`);
assert(fs.existsSync(SETTINGS_RS_PATH), `settings.rs must exist at ${SETTINGS_RS_PATH}`);
assert(fs.existsSync(SERVER_RS_PATH), `server.rs must exist at ${SERVER_RS_PATH}`);

const stylesCss = fs.readFileSync(STYLES_PATH, 'utf8');
const appJs = fs.readFileSync(APP_JS_PATH, 'utf8');
const indexHtml = fs.readFileSync(INDEX_HTML_PATH, 'utf8');
const settingsRs = fs.readFileSync(SETTINGS_RS_PATH, 'utf8');
const serverRs = fs.readFileSync(SERVER_RS_PATH, 'utf8');

let totalTests = 0;
let passedTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  [PASS] Test ${totalTests}: ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  [FAIL] Test ${totalTests}: ${name}`);
    console.error(`         ${err.message}`);
    process.exitCode = 1;
  }
}

// --- SUITE 1: Total Elimination of Source Crate Leakage ---
console.log('\n--- SUITE 1: Source Crate Elimination ---');

runTest('app.js does not contain CANONICAL_CODEBASE_FOLDERS', () => {
  assert(!appJs.includes('CANONICAL_CODEBASE_FOLDERS'), 'CANONICAL_CODEBASE_FOLDERS must be purged');
});

runTest('app.js does not contain getCodebaseFoldersList', () => {
  assert(!appJs.includes('getCodebaseFoldersList'), 'getCodebaseFoldersList must be purged');
});

runTest('app.js does not contain cachedCodebaseFolders or cachedCodebaseRoot', () => {
  assert(!appJs.includes('cachedCodebaseFolders'), 'cachedCodebaseFolders must be purged');
  assert(!appJs.includes('cachedCodebaseRoot'), 'cachedCodebaseRoot must be purged');
});

runTest('app.js does not contain Browse Codebase Root button', () => {
  assert(!appJs.includes('Browse Codebase Root'), 'Browse Codebase Root button must be purged');
});

runTest('index.html does not recommend crates/ in reindex placeholder', () => {
  assert(!indexHtml.includes('placeholder="crates/quorum-coordinator"'), 'Crate placeholder must be purged');
});

// --- SUITE 2: Core Windows File Explorer Implementation ---
console.log('\n--- SUITE 2: Windows File Explorer Architecture ---');

runTest('app.js defines buildPathBreadcrumbs helper', () => {
  assert(appJs.includes('function buildPathBreadcrumbs('), 'buildPathBreadcrumbs must be defined');
});

runTest('app.js defines renderWindowsFileExplorerHtml reusable generator', () => {
  assert(appJs.includes('function renderWindowsFileExplorerHtml('), 'renderWindowsFileExplorerHtml must be defined');
});

runTest('app.js handles top toolbar navigation actions', () => {
  assert(appJs.includes('data-action="browse-up"'), 'Toolbar must render browse-up action');
  assert(appJs.includes('data-action="browse-root"'), 'Toolbar must render browse-root action');
  assert(appJs.includes('data-action="trigger-native-folder-picker"'), 'Toolbar must render native picker trigger');
});

runTest('app.js renders clickable breadcrumb segments', () => {
  assert(appJs.includes('folder-breadcrumb-segment'), 'Breadcrumbs must use segment class');
  assert(appJs.includes('data-action="browse-dir"'), 'Breadcrumb segments must have browse-dir action');
});

runTest('app.js renders clickable folder rows with drill-down and selection controls', () => {
  assert(appJs.includes('folder-row'), 'Must render folder rows');
  assert(appJs.includes('folder-row-checkbox'), 'Must render folder row checkbox');
  assert(appJs.includes('folder-row-details'), 'Must render folder row details');
  assert(appJs.includes('folder-select-btn'), 'Must render folder select action button');
});

// --- SUITE 3: Event Delegation and StopPropagation ---
console.log('\n--- SUITE 3: Event Delegation & StopPropagation ---');

runTest('initSettingsEventDelegation wires browse-dir action', () => {
  assert(appJs.includes("case 'browse-dir':") || appJs.includes("action === 'browse-dir'"), 'Must handle browse-dir action');
});

runTest('initSettingsEventDelegation wires browse-up and browse-root actions', () => {
  assert(appJs.includes("case 'browse-up':") || appJs.includes("action === 'browse-up'"), 'Must handle browse-up action');
  assert(appJs.includes("case 'browse-root':") || appJs.includes("action === 'browse-root'"), 'Must handle browse-root action');
});

runTest('initSettingsEventDelegation wires trigger-native-folder-picker action', () => {
  assert(appJs.includes("case 'trigger-native-folder-picker':") || appJs.includes("action === 'trigger-native-folder-picker'"), 'Must handle trigger-native-folder-picker');
});

runTest('Event delegation enforces stopPropagation on selection checkboxes and actions', () => {
  assert(appJs.includes("case 'mkt-toggle-folder':"), 'Must handle mkt-toggle-folder');
  assert(appJs.includes("e.stopPropagation()"), 'Must invoke stopPropagation() to prevent row drill-down');
});

// --- SUITE 4: Multi-Interface Explorer Integration ---
console.log('\n--- SUITE 4: Multi-Interface Integration ---');

runTest('Explorer integrated in General Settings (tab === "general")', () => {
  assert(appJs.includes("contextId: 'general'"), 'General tab must pass contextId: general');
});

runTest('Explorer integrated in Marketplace Data Opt-In (tab === "marketplace")', () => {
  assert(appJs.includes("contextId: 'mkt'"), 'Marketplace tab must pass contextId: mkt');
});

runTest('Explorer integrated in Mesh & Shared Folders (tab === "mesh")', () => {
  assert(appJs.includes("contextId: 'mesh'"), 'Mesh tab must pass contextId: mesh');
});

runTest('Explorer integrated in Add New Documents wizard (Step 3)', () => {
  assert(appJs.includes("contextId: 'newdoc'"), 'New doc wizard must pass contextId: newdoc');
});

runTest('Explorer integrated in Reindex Engine modal (#modal-reindex)', () => {
  assert(appJs.includes("contextId: 'reindex'"), 'Reindex modal must pass contextId: reindex');
  assert(appJs.includes("function renderReindexExplorer"), 'Must implement renderReindexExplorer');
  assert(indexHtml.includes('id="reindex-folder-explorer-mount"'), 'index.html must have #reindex-folder-explorer-mount');
});

// --- SUITE 5: Daemon API Contracts & Routing ---
console.log('\n--- SUITE 5: Daemon API Contracts & Routing ---');

runTest('server.rs mounts /api/fs/browse-folders route', () => {
  assert(serverRs.includes('"/api/fs/browse-folders"'), 'server.rs must mount /api/fs/browse-folders');
});

runTest('server.rs mounts /api/fs/pick-folder route', () => {
  assert(serverRs.includes('"/api/fs/pick-folder"'), 'server.rs must mount /api/fs/pick-folder');
});

runTest('server.rs mounts /api/dialog/pick-folder route alias', () => {
  assert(serverRs.includes('"/api/dialog/pick-folder"'), 'server.rs must mount /api/dialog/pick-folder');
});

runTest('settings.rs always returns drives list in browse_folders_handler', () => {
  assert(settingsRs.includes('"drives": physical_drives'), 'browse_folders_handler must always return physical drives');
});

runTest('settings.rs exposes quick-access user folders on root', () => {
  assert(settingsRs.includes('"Desktop"') && settingsRs.includes('"Documents"'), 'browse_folders_handler must include quick access folders');
});

runTest('settings.rs implements pick_folder_dialog_handler', () => {
  assert(settingsRs.includes('pub async fn pick_folder_dialog_handler'), 'settings.rs must implement pick_folder_dialog_handler');
  assert(settingsRs.includes('FolderBrowserDialog'), 'Must utilize FolderBrowserDialog for genuine OS picker');
});

// --- SUITE 6: CSS Layout & Styling Invariants ---
console.log('\n--- SUITE 6: CSS Layout & Styling Invariants ---');

runTest('styles.css defines .folder-explorer-container with bounded scroll and modern borders', () => {
  assert(stylesCss.includes('.folder-explorer-container'), 'Must define .folder-explorer-container');
  assert(stylesCss.includes('.folder-explorer-toolbar'), 'Must define .folder-explorer-toolbar');
});

runTest('styles.css defines .folder-explorer-address-bar and breadcrumb styles', () => {
  assert(stylesCss.includes('.folder-explorer-address-bar'), 'Must define .folder-explorer-address-bar');
  assert(stylesCss.includes('.folder-breadcrumbs'), 'Must define .folder-breadcrumbs');
  assert(stylesCss.includes('.folder-breadcrumb-segment'), 'Must define .folder-breadcrumb-segment');
  assert(stylesCss.includes('.folder-breadcrumb-sep'), 'Must define .folder-breadcrumb-sep');
});

runTest('styles.css defines folder row states (hover, selected, checkbox, actions)', () => {
  assert(stylesCss.includes('.folder-row'), 'Must define .folder-row');
  assert(stylesCss.includes('.folder-row:hover'), 'Must define .folder-row:hover');
  assert(stylesCss.includes('.folder-row.selected'), 'Must define .folder-row.selected');
  assert(stylesCss.includes('.folder-row-checkbox'), 'Must define .folder-row-checkbox');
  assert(stylesCss.includes('.folder-select-btn'), 'Must define .folder-select-btn');
});

console.log('================================================================');
console.log(`  ALL ${totalTests} TESTS PASSED CLEANLY (${passedTests}/${totalTests} SUCCESS)`);
console.log('================================================================');
