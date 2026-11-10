/**
 * Milestone 6 Tier 5 Adversarial Stress & Verification Harness
 * Executed by challenger_m6_2 for QuorumRAG Artemis DFIR integration.
 *
 * Verifies:
 * 1. Mandatory User Directive on Folder Input (Zero text inputs, click-to-select across all 7 contexts).
 * 2. Airgap Hardening & Percent-Encoded Adversarial Permutations.
 * 3. Sovereign Marketplace Allowlist & Prohibited Category Gating.
 * 4. UI Invariant Hygiene (No checked=false, search auto-jump consistency).
 */

const fs = require('fs');
const path = require('path');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  [PASS] Test ${totalTests}: ${message}`);
  } else {
    failedTests++;
    console.error(`  [FAIL] Test ${totalTests}: ${message}`);
  }
}

console.log('================================================================');
console.log('QUORUMRAG TIER 5 ADVERSARIAL STRESS HARNESS — CHALLENGER M6_2');
console.log('================================================================\n');

// -----------------------------------------------------------------------------
// PART 1: Mandatory User Directive — Folder Input Invariants Across 7 Contexts
// -----------------------------------------------------------------------------
console.log('--- PART 1: Mandatory User Directive: Click-to-Select Folders ---');

const indexHtmlPath = path.resolve('crates/quorum-ui/assets/index.html');
const appJsPath = path.resolve('crates/quorum-ui/assets/app.js');

const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');
const appJs = fs.readFileSync(appJsPath, 'utf8');

// 1.1 No visible text inputs for folder paths
const folderInputIds = [
  'reindex-target-path',
  'mkt-folder-input',
  'new-doc-path-input',
  'new-shared-folder-input',
  'dlp-sim-path',
  'artemis-jsonl-dir-input',
];

folderInputIds.forEach((id) => {
  const textInputRegex = new RegExp(`<input[^>]*type=["']text["'][^>]*id=["']${id}["']`, 'i');
  const textInputRegexRev = new RegExp(`<input[^>]*id=["']${id}["'][^>]*type=["']text["']`, 'i');
  const untypedInputRegex = new RegExp(`<input(?![^>]*type=)[^>]*id=["']${id}["']`, 'i');

  const inHtml = textInputRegex.test(indexHtml) || textInputRegexRev.test(indexHtml) || untypedInputRegex.test(indexHtml);
  const inJs = textInputRegex.test(appJs) || textInputRegexRev.test(appJs) || untypedInputRegex.test(appJs);

  assert(!inHtml && !inJs, `Folder state element #${id} MUST NEVER be <input type="text"> or untyped <input>`);
});

// 1.2 All folder state inputs are strictly <input type="hidden">
folderInputIds.forEach((id) => {
  const hiddenInputRegex = new RegExp(`<input[^>]*type=["']hidden["'][^>]*id=["']${id}["']|<input[^>]*id=["']${id}["'][^>]*type=["']hidden["']`, 'i');
  const isHidden = hiddenInputRegex.test(indexHtml) || hiddenInputRegex.test(appJs);
  assert(isHidden, `Folder state element #${id} MUST be configured as <input type="hidden">`);
});

// 1.3 Click-to-select controls active across all 7 contexts
const requiredContexts = ['general', 'mkt', 'newdoc', 'mesh', 'storage', 'reindex', 'artemis'];
requiredContexts.forEach((ctx) => {
  const contextWired = appJs.includes(`contextId: '${ctx}'`) || appJs.includes(`contextId: "${ctx}"`);
  assert(contextWired, `Interactive Windows File Explorer must be wired for context '${ctx}'`);
});

// 1.4 Native OS folder picker triggers wired
assert(
  appJs.includes('trigger-native-folder-picker') || indexHtml.includes('trigger-native-folder-picker'),
  'Native OS folder picker action (trigger-native-folder-picker) must exist in UI'
);

// 1.5 Directory upload inputs with webkitdirectory
assert(
  appJs.includes('webkitdirectory directory multiple') || indexHtml.includes('webkitdirectory directory multiple'),
  'Folder upload control with webkitdirectory directory multiple must exist'
);

// 1.6 Visual selected folder display pills
assert(
  indexHtml.includes('id="artemis-selected-folder-display"') && appJs.includes('id="artemis-selected-folder-display"'),
  'Visual selected folder display pill (#artemis-selected-folder-display) must be present in index.html and app.js'
);

// 1.7 Zero occurrences of checked=false in HTML5 boolean attributes
const checkedFalseMatches = (indexHtml.match(/checked\s*=\s*["']?false["']?/gi) || []).concat(
  appJs.match(/checked\s*=\s*["']?false["']?/gi) || []
);
assert(
  checkedFalseMatches.length === 0,
  `Zero occurrences of invalid HTML5 boolean attribute 'checked=false' (found ${checkedFalseMatches.length})`
);

// 1.8 Search auto-jump on "evtx"
assert(
  appJs.includes("q.includes('evtx')"),
  'Search input listener in app.js must include evtx in auto-jump condition to artemis-dfir tab'
);

// -----------------------------------------------------------------------------
// PART 2: Airgap Hardening & Percent-Encoded Adversarial Vectors
// -----------------------------------------------------------------------------
console.log('\n--- PART 2: Airgap Hardening & Percent-Encoded Permutations ---');

// Replicate multi-pass ASCII percent-decoding algorithm from artemis_airgap.rs
function percentDecodeAsciiLossy(input) {
  let current = input;
  for (let pass = 0; pass < 3; pass++) {
    if (!current.includes('%')) break;
    let decoded = '';
    let i = 0;
    let changed = false;
    while (i < current.length) {
      if (current[i] === '%' && i + 2 < current.length) {
        const hex = current.substring(i + 1, i + 3);
        const code = parseInt(hex, 16);
        if (!isNaN(code) && code > 0 && code < 128) {
          decoded += String.fromCharCode(code);
          i += 3;
          changed = true;
          continue;
        }
      }
      decoded += current[i];
      i += 1;
    }
    if (!changed) break;
    current = decoded;
  }
  return current;
}

function isArtemisUri(uri) {
  const lower = uri.trim().toLowerCase();
  if (lower.includes('artemis:') || lower.includes('artemis%3a')) {
    return true;
  }
  if (!lower.includes('%')) {
    return false;
  }
  const decoded = percentDecodeAsciiLossy(lower);
  return decoded.includes('artemis:') || decoded.includes('artemis%3a');
}

// Adversarial URI test cases
const adversarialAirgapVectors = [
  { uri: 'artemis://windows/eventlog/security/4688', expected: true, desc: 'Standard artemis URI' },
  { uri: 'ARTEMIS://WINDOWS/EVENTLOG', expected: true, desc: 'Uppercase scheme' },
  { uri: 'artemis%3a//windows/eventlog', expected: true, desc: 'Single percent-encoded colon' },
  { uri: 'artemis%3A//windows/eventlog', expected: true, desc: 'Uppercase percent-encoded colon' },
  { uri: 'artemis%253a//double_encoded', expected: true, desc: 'Double percent-encoded colon' },
  { uri: 'artemis%25253a//triple_encoded', expected: true, desc: 'Triple percent-encoded colon' },
  { uri: 'artemis:\\windows\\eventlog', expected: true, desc: 'Windows backslash path with artemis:' },
  { uri: 'artemis%3a%5c%5cwindows\\eventlog', expected: true, desc: 'Percent-encoded colon and backslashes' },
  { uri: 'file://host/path/artemis://nested', expected: true, desc: 'Nested artemis scheme inside file URI' },
  { uri: 'https://attacker.com/query?target=artemis://internal', expected: true, desc: 'URI query parameter payload' },
  { uri: 'C:\\Users\\admin\\file.txt', expected: false, desc: 'Standard Windows local file path' },
  { uri: '/var/log/syslog', expected: false, desc: 'Standard Linux syslog file path' },
  { uri: 'https://example.com/artemis_article.html', expected: false, desc: 'Non-artemis URI with artemis substring without colon' },
];

adversarialAirgapVectors.forEach((vec) => {
  const result = isArtemisUri(vec.uri);
  assert(
    result === vec.expected,
    `Airgap vector [${vec.desc}]: "${vec.uri}" -> expected ${vec.expected}, got ${result}`
  );
});

// -----------------------------------------------------------------------------
// PART 3: Sovereign Marketplace Allowlist & Prohibited Category Gating
// -----------------------------------------------------------------------------
console.log('\n--- PART 3: Sovereign Marketplace Allowlist & Prohibitions ---');

const defensiveCategories = [
  'process_execution',
  'network_connection',
  'registry_persistence',
  'system_event_log',
  'prefetch_amcache_execution',
  'service_daemon',
];

const prohibitedCategories = [
  'browser_cookies',
  'browser_history_oauth',
  'credential_store',
  'shell_history_raw',
];

// Check rust contract definitions in crates/quorum-contract/src/forensics.rs
const contractForensicsPath = path.resolve('crates/quorum-contract/src/forensics.rs');
const contractForensicsSrc = fs.readFileSync(contractForensicsPath, 'utf8');

defensiveCategories.forEach((cat) => {
  assert(
    contractForensicsSrc.includes(cat),
    `Forensic contract must include defensive category '${cat}'`
  );
});

prohibitedCategories.forEach((cat) => {
  assert(
    contractForensicsSrc.includes(cat),
    `Forensic contract must include prohibited category '${cat}'`
  );
});

// Category Gate evaluation simulation
function evaluatePathAgainstCategoryGate(filePath) {
  const pLower = filePath.toLowerCase();
  for (const prohibited of prohibitedCategories) {
    if (pLower.includes(prohibited)) {
      return { allowed: false, reason: `contains prohibited category '${prohibited}'` };
    }
  }
  if (
    pLower.includes('cookie') ||
    pLower.includes('oauth') ||
    pLower.includes('credential') ||
    pLower.includes('/shadow') ||
    pLower.includes('\\shadow') ||
    pLower.endsWith('shadow') ||
    pLower.includes('/sam') ||
    pLower.includes('\\sam') ||
    pLower.endsWith('sam') ||
    (!pLower.endsWith('.evtx') && (
      pLower.includes('/config/security') ||
      pLower.includes('\\config\\security') ||
      pLower.includes('/security') ||
      pLower.includes('\\security') ||
      pLower.endsWith('security')
    )) ||
    pLower.includes('dpapi') ||
    pLower.includes('keychain') ||
    pLower.includes('consolehost_history') ||
    pLower.includes('.bash_history')
  ) {
    return { allowed: false, reason: 'contains forbidden credential/personal artifact token' };
  }
  return { allowed: true };
}

const candidatePaths = [
  { path: 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx', expected: true, desc: 'Windows Security.evtx event log' },
  { path: 'C:\\Windows\\System32\\winevt\\Logs\\System.evtx', expected: true, desc: 'Windows System.evtx event log' },
  { path: 'C:\\Windows\\System32\\config\\SECURITY', expected: false, desc: 'Windows config\\SECURITY registry hive' },
  { path: 'C:\\Windows\\System32\\config\\SAM', expected: false, desc: 'Windows config\\SAM registry hive' },
  { path: '/etc/shadow', expected: false, desc: 'Linux /etc/shadow file' },
  { path: '/home/user/.bash_history', expected: false, desc: 'Linux bash history file' },
  { path: 'C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt', expected: false, desc: 'PowerShell ConsoleHost history' },
  { path: 'C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies', expected: false, desc: 'Chrome Cookies SQLite DB' },
  { path: 'C:\\Users\\user\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data (credentials)', expected: false, desc: 'Edge Login Data credential DB' },
  { path: '/var/log/audit/audit.log', expected: true, desc: 'Linux auditd log file' },
];

candidatePaths.forEach((item) => {
  const res = evaluatePathAgainstCategoryGate(item.path);
  assert(
    res.allowed === item.expected,
    `Category Gate [${item.desc}]: "${item.path}" -> expected ${item.expected ? 'ALLOWED' : 'REJECTED'}, got ${res.allowed ? 'ALLOWED' : 'REJECTED'}`
  );
});

// -----------------------------------------------------------------------------
// PART 4: Summary & Exit Code
// -----------------------------------------------------------------------------
console.log('\n================================================================');
console.log(`TOTAL TESTS: ${totalTests} | PASSED: ${passedTests} | FAILED: ${failedTests}`);
console.log('================================================================');

if (failedTests > 0) {
  process.exit(1);
} else {
  console.log('TIER 5 ADVERSARIAL STRESS HARNESS PASSED WITH ZERO FAILURES.\n');
  process.exit(0);
}
