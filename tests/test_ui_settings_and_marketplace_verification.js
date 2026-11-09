/**
 * Automated UI Settings Alignment, Folder Explorer & Localhost Marketplace Verification Test
 * (Feature F21 / E2E Track)
 *
 * Verifies:
 * 1. Settings layout and text alignment (.settings-centered-container, .settings-subtab-nav,
 *    .settings-row-controls, .settings-header-action-row in styles.css & app.js).
 * 2. Clickable Windows File Explorer component (renderWindowsFileExplorerHtml) integration across
 *    all target interfaces: General, Marketplace Opt-In, Mesh Folders, Add Documents, and Reindex Engine.
 * 3. Complete elimination of QuorumRAG source code crates from user folder selection.
 * 4. Localhost Marketplace Issuer & Buyer Test panel wiring and action delegators.
 * 5. Daemon routing contracts for filesystem browsing/picking and marketplace test endpoints.
 * 6. CLI command structure for marketplace-issue-cert and marketplace-buyer-pull.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ROOT_DIR = path.resolve(__dirname, '..');
const STYLES_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'styles.css');
const APP_JS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'app.js');
const INDEX_HTML_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'index.html');
const SERVER_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'server.rs');
const MKT_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'handlers', 'marketplace.rs');
const CLI_MAIN_PATH = path.join(ROOT_DIR, 'crates', 'quorum-cli', 'src', 'main.rs');

console.log('================================================================');
console.log('  E2E HARNESS: UI SETTINGS, FOLDER EXPLORER & MARKETPLACE TEST  ');
console.log('================================================================');

// Verify file existence
[STYLES_PATH, APP_JS_PATH, INDEX_HTML_PATH, SERVER_RS_PATH, MKT_RS_PATH, CLI_MAIN_PATH].forEach(p => {
  assert(fs.existsSync(p), `Required file missing: ${p}`);
});

const stylesCss = fs.readFileSync(STYLES_PATH, 'utf8');
const appJs = fs.readFileSync(APP_JS_PATH, 'utf8');
const indexHtml = fs.readFileSync(INDEX_HTML_PATH, 'utf8');
const serverRs = fs.readFileSync(SERVER_RS_PATH, 'utf8');
const mktRs = fs.readFileSync(MKT_RS_PATH, 'utf8');
const cliMain = fs.readFileSync(CLI_MAIN_PATH, 'utf8');

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
    throw err;
  }
}

// ---------------------------------------------------------------------------
// SUITE 1: Settings CSS Centering and Controls Alignment
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 1: Settings CSS Centering and Controls Alignment ---');

runTest('styles.css enforces .settings-centered-container max-width 860px and margin-inline auto', () => {
  assert(stylesCss.includes('.settings-centered-container'), 'Missing .settings-centered-container');
  assert(stylesCss.includes('max-width: 860px'), 'Must define max-width: 860px');
  assert(stylesCss.includes('margin-inline: auto'), 'Must define margin-inline: auto');
});

runTest('styles.css defines .settings-subtab-nav with centered layout', () => {
  assert(stylesCss.includes('.settings-subtab-nav'), 'Missing .settings-subtab-nav');
  assert(stylesCss.includes('display: flex'), 'Subtab nav must use flexbox');
  assert(stylesCss.includes('justify-content: center'), 'Subtab nav must center items');
});

runTest('styles.css defines .settings-row-controls with flex alignment', () => {
  assert(stylesCss.includes('.settings-row-controls'), 'Missing .settings-row-controls');
  assert(stylesCss.includes('align-items: center'), 'Row controls must align center');
});

runTest('styles.css defines .settings-header-action-row', () => {
  assert(stylesCss.includes('.settings-header-action-row'), 'Missing .settings-header-action-row');
});

// ---------------------------------------------------------------------------
// SUITE 2: Settings Templates in app.js
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 2: Settings Templates in app.js ---');

runTest('app.js wraps settings tabs with settings-centered-container', () => {
  const matches = appJs.match(/<div class="settings-centered-container">/g);
  assert(matches && matches.length >= 22, `Expected at least 22 centered container wraps, found ${matches ? matches.length : 0}`);
});

runTest('Zero left-margin jump overrides on settings headings', () => {
  assert(!appJs.includes('<h2 class="settings-page-title" style="margin-left:0'), 'Found illegal margin-left:0 on page title');
  assert(!appJs.includes('<h2 class="settings-page-title" style="margin:0'), 'Found illegal margin:0 on page title');
});

// ---------------------------------------------------------------------------
// SUITE 3: Windows File Explorer Architecture & Source Crate Elimination
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 3: Windows File Explorer Component & Crate Elimination ---');

runTest('QuorumRAG source code crates completely eliminated from user folder selection', () => {
  assert(!appJs.includes('CANONICAL_CODEBASE_FOLDERS'), 'Forbidden CANONICAL_CODEBASE_FOLDERS found in app.js');
  assert(!appJs.includes('getCodebaseFoldersList'), 'Forbidden getCodebaseFoldersList found in app.js');
  assert(!appJs.includes('cachedCodebaseFolders'), 'Forbidden cachedCodebaseFolders found in app.js');
  assert(!appJs.includes('Browse Codebase Root'), 'Forbidden Browse Codebase Root button found in app.js');
});

runTest('renderWindowsFileExplorerHtml supports breadcrumbs, drives, drill-down, and native picker', () => {
  assert(appJs.includes('function renderWindowsFileExplorerHtml'), 'Missing renderWindowsFileExplorerHtml function');
  assert(appJs.includes('buildPathBreadcrumbs'), 'Missing buildPathBreadcrumbs helper');
  assert(appJs.includes('data-action="browse-dir"'), 'Missing browse-dir drill down action');
  assert(appJs.includes('data-action="browse-root"'), 'Missing browse-root action');
  assert(appJs.includes('data-action="browse-up"'), 'Missing browse-up action');
  assert(appJs.includes('data-action="trigger-native-folder-picker"'), 'Missing trigger-native-folder-picker action');
});

runTest('Folder explorer integrated in General, Marketplace, Mesh, Add Documents, and Reindex', () => {
  assert(appJs.includes("contextId: 'general'"), 'Explorer not integrated in General settings');
  assert(appJs.includes("contextId: 'mkt'"), 'Explorer not integrated in Marketplace');
  assert(appJs.includes("contextId: 'mesh'"), 'Explorer not integrated in Mesh settings');
  assert(appJs.includes("contextId: 'newdoc'"), 'Explorer not integrated in Add New Documents');
  assert(appJs.includes("contextId: 'reindex'"), 'Explorer not integrated in Reindex Engine');
});

// ---------------------------------------------------------------------------
// SUITE 4: Localhost Marketplace Issuer & Buyer Test Panel
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 4: Localhost Marketplace Issuer & Buyer Test Panel ---');

runTest('app.js defines action handler for mkt-issue-test-cert targeting /api/v1/marketplace/test/issue-cert', () => {
  assert(appJs.includes("case 'mkt-issue-test-cert':"), 'Missing mkt-issue-test-cert handler');
  assert(appJs.includes('/api/v1/marketplace/test/issue-cert'), 'Missing call to /api/v1/marketplace/test/issue-cert');
  assert(appJs.includes('127.0.0.1/32'), 'Must specify 127.0.0.1/32 egress CIDR');
});

runTest('app.js defines action handler for mkt-exec-test-transaction targeting /api/v1/marketplace/test/execute-transaction', () => {
  assert(appJs.includes("case 'mkt-exec-test-transaction':"), 'Missing mkt-exec-test-transaction handler');
  assert(appJs.includes('/api/v1/marketplace/test/execute-transaction'), 'Missing call to /api/v1/marketplace/test/execute-transaction');
});

runTest('Marketplace settings tab renders Localhost Marketplace Issuer & Buyer Test Panel', () => {
  assert(appJs.includes('Localhost Marketplace Issuer &amp; Buyer Test Panel'), 'Missing test panel heading');
  assert(appJs.includes('data-action="mkt-issue-test-cert"'), 'Missing issue test cert button in UI template');
  assert(appJs.includes('data-action="mkt-exec-test-transaction"'), 'Missing execute test transaction button in UI template');
  assert(appJs.includes('id="marketplace-test-output-box"'), 'Missing marketplace-test-output-box pre element');
});

// ---------------------------------------------------------------------------
// SUITE 5: Backend Daemon Routing & Endpoints
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 5: Backend Daemon Routing & Endpoints ---');

runTest('server.rs routes filesystem browsing and picking', () => {
  assert(serverRs.includes('"/api/fs/browse-folders"'), 'Missing /api/fs/browse-folders route');
  assert(serverRs.includes('"/api/fs/pick-folder"'), 'Missing /api/fs/pick-folder route');
});

runTest('server.rs routes localhost marketplace test endpoints', () => {
  assert(serverRs.includes('"/api/v1/marketplace/test/issue-cert"'), 'Missing /api/v1/marketplace/test/issue-cert route');
  assert(serverRs.includes('"/api/v1/marketplace/test/execute-transaction"'), 'Missing /api/v1/marketplace/test/execute-transaction route');
});

runTest('marketplace.rs implements marketplace_test_issue_cert_handler and marketplace_test_execute_transaction_handler', () => {
  assert(mktRs.includes('pub async fn marketplace_test_issue_cert_handler'), 'Missing test issue cert handler');
  assert(mktRs.includes('pub async fn marketplace_test_execute_transaction_handler'), 'Missing test execute transaction handler');
});

// ---------------------------------------------------------------------------
// SUITE 6: CLI Subcommands Verification
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 6: CLI Subcommands Verification ---');

runTest('quorum-cli main.rs registers marketplace-issue-cert and marketplace-buyer-pull subcommands', () => {
  assert(cliMain.includes('MarketplaceIssueCert'), 'Missing MarketplaceIssueCert CLI command enum');
  assert(cliMain.includes('MarketplaceBuyerPull'), 'Missing MarketplaceBuyerPull CLI command enum');
});

console.log('================================================================');
console.log(`  ALL ${passedTests}/${totalTests} TESTS PASSED CLEANLY (100% SUCCESS)`);
console.log('================================================================\n');
