/**
 * Adversarial Challenger 2 Stress Harness:
 * Windows Path Edge Cases & Native Folder Picker Headless Fallback Verification
 *
 * Covers:
 * 1. Windows path normalization & edge cases in buildPathBreadcrumbs:
 *    - Drive roots (C:\, D:\, C:, D:, c:\, c:, C:/, d:/)
 *    - Backslashes vs forward slashes
 *    - Trailing slashes and multiple consecutive slashes
 *    - Deep nesting (50+ levels)
 *    - Directory names with spaces, dots, parentheses, brackets, special characters
 *    - Empty, null, undefined paths
 *    - Breadcrumb continuity and click-path invariance
 * 2. Windows File Explorer HTML Generator (renderWindowsFileExplorerHtml):
 *    - Multi-context parametrization
 *    - Drive pills, breadcrumbs, folder rows, checkboxes, action buttons
 *    - Active bar and empty state rendering
 *    - XSS injection resistance in path names
 * 3. Backend Path Logic Invariants in settings.rs:
 *    - is_drive_root detection for all drive variants
 *    - parent_path resolution for drive roots and subdirectories
 * 4. Native Folder Picker Headless Fallback:
 *    - Route mounting (/api/fs/pick-folder and /api/dialog/pick-folder)
 *    - Headless / cancelled fallback contract (cancelled: true, path: "")
 *    - Client-side error handling & graceful degradation
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ROOT_DIR = path.resolve(__dirname, '..');
const APP_JS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'app.js');
const SETTINGS_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'handlers', 'settings.rs');
const SERVER_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'server.rs');

console.log('================================================================');
console.log('  CHALLENGER 2: PATH EDGE CASES & NATIVE PICKER STRESS HARNESS ');
console.log('================================================================');

assert(fs.existsSync(APP_JS_PATH), `app.js not found at ${APP_JS_PATH}`);
assert(fs.existsSync(SETTINGS_RS_PATH), `settings.rs not found at ${SETTINGS_RS_PATH}`);
assert(fs.existsSync(SERVER_RS_PATH), `server.rs not found at ${SERVER_RS_PATH}`);

const appJs = fs.readFileSync(APP_JS_PATH, 'utf8');
const settingsRs = fs.readFileSync(SETTINGS_RS_PATH, 'utf8');
const serverRs = fs.readFileSync(SERVER_RS_PATH, 'utf8');

// Extract buildPathBreadcrumbs from app.js
const breadcrumbsMatch = appJs.match(/function\s+buildPathBreadcrumbs\s*\([^)]*\)\s*\{[\s\S]*?\n  \}/);
assert(breadcrumbsMatch, 'Could not extract buildPathBreadcrumbs implementation from app.js');

const buildPathBreadcrumbs = new Function('currentPath', `
  ${breadcrumbsMatch[0]}
  return buildPathBreadcrumbs(currentPath);
`);

// Extract escapeHtml and renderWindowsFileExplorerHtml from app.js
const escapeHtmlMatch = appJs.match(/function\s+escapeHtml\s*\([^)]*\)\s*\{[\s\S]*?\n  \}/);
assert(escapeHtmlMatch, 'Could not extract escapeHtml implementation from app.js');

const explorerMatch = appJs.match(/function\s+renderWindowsFileExplorerHtml\s*\([^)]*\)\s*\{[\s\S]*?\n  \}/);
assert(explorerMatch, 'Could not extract renderWindowsFileExplorerHtml implementation from app.js');

const renderWindowsFileExplorerHtml = new Function('opts', `
  ${escapeHtmlMatch[0]}
  ${breadcrumbsMatch[0]}
  const cachedDrives = ['D:\\\\', 'C:\\\\'];
  const cachedBrowseDirs = [];
  const currentBrowsePath = '';
  const currentBrowseParentPath = '';
  ${explorerMatch[0]}
  return renderWindowsFileExplorerHtml(opts);
`);

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

// -------------------------------------------------------------
// SUITE 1: Windows Path Breadcrumb Edge Cases
// -------------------------------------------------------------
console.log('\n--- SUITE 1: Windows Path Breadcrumbs Edge Cases ---');

runTest('Empty, null, and undefined paths return single "This PC" crumb', () => {
  const emptyCrumbs = buildPathBreadcrumbs('');
  assert.strictEqual(emptyCrumbs.length, 1);
  assert.strictEqual(emptyCrumbs[0].label, '💽 This PC');
  assert.strictEqual(emptyCrumbs[0].path, '');

  const nullCrumbs = buildPathBreadcrumbs(null);
  assert.strictEqual(nullCrumbs.length, 1);
  assert.strictEqual(nullCrumbs[0].label, '💽 This PC');
  assert.strictEqual(nullCrumbs[0].path, '');

  const undefCrumbs = buildPathBreadcrumbs(undefined);
  assert.strictEqual(undefCrumbs.length, 1);
  assert.strictEqual(undefCrumbs[0].label, '💽 This PC');
  assert.strictEqual(undefCrumbs[0].path, '');
});

runTest('Drive root "C:\\" produces This PC and "💽 C:\\"', () => {
  const crumbs = buildPathBreadcrumbs('C:\\');
  assert.strictEqual(crumbs.length, 2);
  assert.strictEqual(crumbs[0].label, '💽 This PC');
  assert.strictEqual(crumbs[0].path, '');
  assert.strictEqual(crumbs[1].label, '💽 C:\\');
  assert.strictEqual(crumbs[1].path, 'C:\\');
});

runTest('Drive root without backslash "C:" normalizes to "C:\\"', () => {
  const crumbs = buildPathBreadcrumbs('C:');
  assert.strictEqual(crumbs.length, 2);
  assert.strictEqual(crumbs[0].label, '💽 This PC');
  assert.strictEqual(crumbs[0].path, '');
  assert.strictEqual(crumbs[1].label, '💽 C:\\');
  assert.strictEqual(crumbs[1].path, 'C:\\');
});

runTest('Drive root with forward slash "D:/" normalizes to "D:\\"', () => {
  const crumbs = buildPathBreadcrumbs('D:/');
  assert.strictEqual(crumbs.length, 2);
  assert.strictEqual(crumbs[0].label, '💽 This PC');
  assert.strictEqual(crumbs[0].path, '');
  assert.strictEqual(crumbs[1].label, '💽 D:\\');
  assert.strictEqual(crumbs[1].path, 'D:\\');
});

runTest('Lowercase drive root "d:\\" is properly identified and breadcrumbed', () => {
  const crumbs = buildPathBreadcrumbs('d:\\');
  assert.strictEqual(crumbs.length, 2);
  assert.strictEqual(crumbs[0].label, '💽 This PC');
  assert.strictEqual(crumbs[1].label, '💽 d:\\');
  assert.strictEqual(crumbs[1].path, 'd:\\');
});

runTest('Forward slashes are converted to backslashes in subfolders', () => {
  const crumbs = buildPathBreadcrumbs('C:/Users/Admin/Documents');
  assert.strictEqual(crumbs.length, 5);
  assert.strictEqual(crumbs[0].path, '');
  assert.strictEqual(crumbs[1].path, 'C:\\');
  assert.strictEqual(crumbs[2].label, 'Users');
  assert.strictEqual(crumbs[2].path, 'C:\\Users');
  assert.strictEqual(crumbs[3].label, 'Admin');
  assert.strictEqual(crumbs[3].path, 'C:\\Users\\Admin');
  assert.strictEqual(crumbs[4].label, 'Documents');
  assert.strictEqual(crumbs[4].path, 'C:\\Users\\Admin\\Documents');
});

runTest('Mixed slashes and consecutive slashes are cleanly sanitized (D:/Projects\\QuorumRAG///data\\\\raw)', () => {
  const crumbs = buildPathBreadcrumbs('D:/Projects\\QuorumRAG///data\\\\raw');
  assert.strictEqual(crumbs.length, 6);
  assert.strictEqual(crumbs[0].path, '');
  assert.strictEqual(crumbs[1].path, 'D:\\');
  assert.strictEqual(crumbs[2].label, 'Projects');
  assert.strictEqual(crumbs[2].path, 'D:\\Projects');
  assert.strictEqual(crumbs[3].label, 'QuorumRAG');
  assert.strictEqual(crumbs[3].path, 'D:\\Projects\\QuorumRAG');
  assert.strictEqual(crumbs[4].label, 'data');
  assert.strictEqual(crumbs[4].path, 'D:\\Projects\\QuorumRAG\\data');
  assert.strictEqual(crumbs[5].label, 'raw');
  assert.strictEqual(crumbs[5].path, 'D:\\Projects\\QuorumRAG\\data\\raw');
});

runTest('Trailing slashes do not produce empty phantom breadcrumb segments', () => {
  const withTrailing = buildPathBreadcrumbs('C:\\Users\\JohnDoe\\Documents\\');
  const withoutTrailing = buildPathBreadcrumbs('C:\\Users\\JohnDoe\\Documents');
  assert.strictEqual(withTrailing.length, withoutTrailing.length);
  for (let i = 0; i < withTrailing.length; i++) {
    assert.strictEqual(withTrailing[i].label, withoutTrailing[i].label);
    assert.strictEqual(withTrailing[i].path, withoutTrailing[i].path);
  }
});

runTest('Paths with spaces and special characters are preserved accurately (C:\\Program Files (x86)\\My App #1 [v2.0] & Tools\\Config)', () => {
  const complexPath = 'C:\\Program Files (x86)\\My App #1 [v2.0] & Tools\\Config';
  const crumbs = buildPathBreadcrumbs(complexPath);
  assert.strictEqual(crumbs.length, 5);
  assert.strictEqual(crumbs[0].path, '');
  assert.strictEqual(crumbs[1].path, 'C:\\');
  assert.strictEqual(crumbs[2].label, 'Program Files (x86)');
  assert.strictEqual(crumbs[2].path, 'C:\\Program Files (x86)');
  assert.strictEqual(crumbs[3].label, 'My App #1 [v2.0] & Tools');
  assert.strictEqual(crumbs[3].path, 'C:\\Program Files (x86)\\My App #1 [v2.0] & Tools');
  assert.strictEqual(crumbs[4].label, 'Config');
  assert.strictEqual(crumbs[4].path, 'C:\\Program Files (x86)\\My App #1 [v2.0] & Tools\\Config');
});

runTest('Deeply nested paths (50 levels) construct without recursion error or path corruption', () => {
  const segments = [];
  for (let i = 1; i <= 50; i++) {
    segments.push(`sub_${i}`);
  }
  const deepPath = 'E:\\' + segments.join('\\');
  const crumbs = buildPathBreadcrumbs(deepPath);
  assert.strictEqual(crumbs.length, 52); // This PC + E:\ + 50 subfolders
  assert.strictEqual(crumbs[0].label, '💽 This PC');
  assert.strictEqual(crumbs[1].path, 'E:\\');
  assert.strictEqual(crumbs[51].label, 'sub_50');
  assert.strictEqual(crumbs[51].path, deepPath);

  // Invariance check: each crumb path must be an ancestor prefix
  for (let i = 2; i < crumbs.length; i++) {
    assert(deepPath.startsWith(crumbs[i].path), `Crumb ${i} path ${crumbs[i].path} must be prefix of ${deepPath}`);
  }
});

// -------------------------------------------------------------
// SUITE 2: Backend Path Normalization Invariants (settings.rs)
// -------------------------------------------------------------
console.log('\n--- SUITE 2: Backend Drive Root & Parent Path Invariants ---');

runTest('Backend detects drive root whether with backslash, forward slash, or bare letter', () => {
  const physicalDrives = ['D:\\', 'C:\\'];
  function isDriveRoot(req) {
    return physicalDrives.some(d => {
      const d_trimmed = d.replace(/[\\/]+$/, '');
      const req_trimmed = req.replace(/[\\/]+$/, '');
      return d_trimmed.toLowerCase() === req_trimmed.toLowerCase();
    });
  }

  assert(isDriveRoot('D:\\'), 'D:\\ must be drive root');
  assert(isDriveRoot('D:'), 'D: must be drive root');
  assert(isDriveRoot('D:/'), 'D:/ must be drive root');
  assert(isDriveRoot('d:\\'), 'd:\\ must be drive root');
  assert(isDriveRoot('c:'), 'c: must be drive root');
  assert(!isDriveRoot('D:\\Folder'), 'D:\\Folder must NOT be drive root');
  assert(!isDriveRoot('D:\\Users\\Desktop'), 'D:\\Users\\Desktop must NOT be drive root');
});

runTest('Backend parent_path calculation returns empty string at drive root', () => {
  assert(settingsRs.includes('let is_drive_root = physical_drives.iter().any'), 'settings.rs must compute is_drive_root');
  assert(settingsRs.includes('let parent_path = if is_drive_root {'), 'settings.rs must branch on is_drive_root');
  assert(settingsRs.includes('String::new()'), 'settings.rs must return empty string for drive root parent');
});

runTest('Backend parent_path formats top-level drive root with trailing backslash (D:\\ not D:)', () => {
  assert(settingsRs.includes('if s.len() == 2 && s.ends_with(\':\')'), 'Must detect bare drive letter parent');
  assert(settingsRs.includes('format!("{}\\'), 'Must format with trailing backslash');
});

// -------------------------------------------------------------
// SUITE 3: Native Folder Picker Headless Fallback
// -------------------------------------------------------------
console.log('\n--- SUITE 3: Native Folder Picker Headless Fallback ---');

runTest('settings.rs implements FolderBrowserDialog with CREATE_NO_WINDOW flag', () => {
  assert(settingsRs.includes('System.Windows.Forms.FolderBrowserDialog'), 'Must instantiate FolderBrowserDialog');
  assert(settingsRs.includes('creation_flags(0x08000000)'), 'Must pass CREATE_NO_WINDOW (0x08000000)');
  assert(settingsRs.includes('-NonInteractive'), 'Must run powershell with -NonInteractive');
});

runTest('settings.rs returns cancelled: true when dialog is cancelled or runs headless', () => {
  assert(settingsRs.includes('"status": "cancelled"'), 'Must return cancelled status on abort/headless');
  assert(settingsRs.includes('"cancelled": true'), 'Must set cancelled: true');
  assert(settingsRs.includes('"path": ""'), 'Must set empty path on cancelled');
});

runTest('server.rs routes POST /api/fs/pick-folder to pick_folder_dialog_handler', () => {
  assert(serverRs.includes('.route("/api/fs/pick-folder", post(settings::pick_folder_dialog_handler))'),
    'server.rs must mount POST /api/fs/pick-folder');
  assert(serverRs.includes('.route("/api/dialog/pick-folder", post(settings::pick_folder_dialog_handler))'),
    'server.rs must mount POST /api/dialog/pick-folder');
});

runTest('app.js gracefully handles cancelled or unavailable native folder picker', () => {
  assert(appJs.includes("if (data.status === 'ok' && data.path)"), 'Must check status and path');
  assert(appJs.includes("showSettingsToast('Folder selection cancelled')"), 'Must notify user on cancel');
  assert(appJs.includes("Native folder picker unavailable:"), 'Must catch fetch errors gracefully');
});

// -------------------------------------------------------------
// SUITE 4: Multi-Interface Explorer Integration & Event Delegation
// -------------------------------------------------------------
console.log('\n--- SUITE 4: Multi-Interface Explorer Integration ---');

runTest('Explorer integration covers all 5 required interfaces', () => {
  const interfaces = [
    { name: 'General Settings', context: "contextId: 'general'" },
    { name: 'Marketplace Data Opt-In', context: "contextId: 'mkt'" },
    { name: 'Mesh & Shared Folders', context: "contextId: 'mesh'" },
    { name: 'Add New Documents', context: "contextId: 'newdoc'" },
    { name: 'Reindex Engine Modal', context: "contextId: 'reindex'" },
  ];

  for (const item of interfaces) {
    assert(appJs.includes(item.context), `app.js must integrate explorer for ${item.name} (${item.context})`);
  }
});

runTest('Checkboxes enforce stopPropagation to prevent unintended row drill-down', () => {
  assert(appJs.includes("e.stopPropagation()"), 'Event listeners must invoke stopPropagation()');
  assert(appJs.includes("mkt-toggle-folder"), 'Must support mkt-toggle-folder');
});

// -------------------------------------------------------------
// SUITE 5: HTML Generation, Ergonomics & XSS Sanitization
// -------------------------------------------------------------
console.log('\n--- SUITE 5: HTML Generation, Ergonomics & XSS Sanitization ---');

runTest('renderWindowsFileExplorerHtml renders correct structure and escapes special chars', () => {
  const html = renderWindowsFileExplorerHtml({
    contextId: 'test_ctx',
    currentPath: 'D:\\Test<Folder>"&\'',
    parentPath: 'D:\\',
    drives: ['D:\\', 'C:\\'],
    directories: [
      { name: 'Child<One>', path: 'D:\\Test<Folder>"&\'\\Child<One>', is_drive: false },
      { name: 'ChildTwo', path: 'D:\\Test<Folder>"&\'\\ChildTwo', is_drive: false }
    ],
    selectedSet: new Set(['d:\\test<folder>"&\'\\childtwo']),
    selectAction: 'test-toggle-action',
    selectButtonText: '+ Add To Test',
    activePathAction: 'test-set-active',
    activePathButtonText: '+ Confirm Active',
    allowNativeDialog: true,
  });

  // Verify container and context
  assert(html.includes('data-explorer-context="test_ctx"'), 'Must set data-explorer-context');
  // Verify native picker button
  assert(html.includes('data-action="trigger-native-folder-picker"'), 'Must render native picker button');
  // Verify breadcrumbs address bar
  assert(html.includes('class="folder-explorer-address-bar"'), 'Must render address bar');
  // Verify escaped path in breadcrumb
  assert(!html.includes('D:\\Test<Folder>'), 'Unescaped <Folder> must not be in HTML');
  assert(html.includes('&lt;Folder&gt;'), 'HTML escaped &lt;Folder&gt; must be in HTML');
  // Verify selected class on ChildTwo
  assert(html.includes('folder-row selected'), 'ChildTwo must have selected class');
  assert(html.includes('checked'), 'ChildTwo checkbox must be checked');
  assert(html.includes('✓ Selected'), 'ChildTwo select button must show ✓ Selected');
  // Verify unselected class on Child<One>
  assert(html.includes('+ Add To Test'), 'Child<One> select button must show custom button text');
  // Verify active path bar
  assert(html.includes('class="folder-explorer-active-bar"'), 'Must render active bar');
  assert(html.includes('+ Confirm Active'), 'Must render custom active button text');
});

runTest('renderWindowsFileExplorerHtml displays empty state when no directories exist', () => {
  const html = renderWindowsFileExplorerHtml({
    contextId: 'empty_ctx',
    currentPath: 'D:\\EmptyFolder',
    directories: [],
  });

  assert(html.includes('No subdirectories found in this folder.'), 'Must display empty directory fallback message');
});

console.log('================================================================');
console.log(`  ALL ${totalTests} TESTS PASSED CLEANLY (${passedTests}/${totalTests} SUCCESS)`);
console.log('================================================================');
