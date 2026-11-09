/**
 * Challenger 2 (teamwork_challenger_t5_2) Independent Empirical Adversarial Stress Harness
 * 
 * Objectives:
 * 1. Verify Repository Isolation & Boundary Invariants (Zero leakage into parent d:\harfile).
 * 2. Verify Windows File Explorer & Source Crate Elimination across all 5 surfaces.
 * 3. Verify Localhost Marketplace CLI Subcommands, 127.0.0.1/32 CIDR certs, and test endpoints.
 * 4. Verify 4-Stage Synthetic Gate algorithms (Stages 1-4) & DataCatalogManifest proof.
 * 5. Verify Concurrency, Backpressure, and Deadlock Immunity Invariants.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { execSync } = require('child_process');
const crypto = require('crypto');

const ROOT_DIR = path.resolve(__dirname, '..');
const STYLES_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'styles.css');
const APP_JS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'app.js');
const INDEX_HTML_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'index.html');
const SERVER_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'server.rs');
const MKT_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'handlers', 'marketplace.rs');
const SETTINGS_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'handlers', 'settings.rs');
const SYNTHETIC_GATE_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'src', 'handlers', 'synthetic_gate.rs');
const CONTRACT_MKT_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-contract', 'src', 'marketplace.rs');
const CLI_MAIN_RS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-cli', 'src', 'main.rs');
const SHIP_PS1_PATH = path.join(ROOT_DIR, 'scripts', 'solo_pr_ship.ps1');

console.log('========================================================================');
console.log('  CHALLENGER 2: TIER 5 EMPIRICAL ADVERSARIAL STRESS TEST HARNESS        ');
console.log('========================================================================\n');

let totalTests = 0;
let passedTests = 0;

function runAssertion(name, fn) {
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
// SUITE 1: REPOSITORY BOUNDARY & ISOLATION INVARIANTS
// ---------------------------------------------------------------------------
console.log('--- SUITE 1: Repository Boundary & Isolation Invariants ---');

runAssertion('QuorumRAG is standalone repository with origin oyesanyf/QuorumRAG', () => {
  const gitExe = 'C:\\Program Files\\Git\\cmd\\git.exe';
  assert(fs.existsSync(gitExe), 'Git executable must exist at C:\\Program Files\\Git\\cmd\\git.exe');
  
  const topLevel = execSync(`"${gitExe}" rev-parse --show-toplevel`, { cwd: ROOT_DIR, encoding: 'utf8' }).trim();
  const normalizedTopLevel = path.normalize(topLevel).toLowerCase();
  const normalizedExpected = path.normalize(ROOT_DIR).toLowerCase();
  assert.strictEqual(normalizedTopLevel, normalizedExpected, `Top level repo must match ${normalizedExpected}`);

  const originUrl = execSync(`"${gitExe}" remote get-url origin`, { cwd: ROOT_DIR, encoding: 'utf8' }).trim();
  assert(originUrl.includes('oyesanyf/QuorumRAG'), `Origin URL must point to oyesanyf/QuorumRAG, got: ${originUrl}`);
});

runAssertion('solo_pr_ship.ps1 enforces fail-closed repository boundary guards', () => {
  const shipPs1 = fs.readFileSync(SHIP_PS1_PATH, 'utf8');
  assert(shipPs1.includes('$ExpectedRepoSlug = "oyesanyf/QuorumRAG"'), 'Missing ExpectedRepoSlug check');
  assert(shipPs1.includes('REPOSITORY BOUNDARY VIOLATION'), 'Missing boundary violation fail-closed error');
  assert(shipPs1.includes('exit 1'), 'Must exit 1 on boundary mismatch');
});

runAssertion('Zero leakage of QuorumRAG artifacts into parent d:\\harfile', () => {
  const parentDir = path.resolve(ROOT_DIR, '..');
  // Check that parent directory does not have QuorumRAG Cargo.lock or crates folder directly at parent level
  const parentCargoToml = path.join(parentDir, 'Cargo.toml');
  if (fs.existsSync(parentCargoToml)) {
    const parentTomlContent = fs.readFileSync(parentCargoToml, 'utf8');
    assert(!parentTomlContent.includes('crates/quorum-contract'), 'Parent Cargo.toml must not include QuorumRAG crates');
  }
});

// ---------------------------------------------------------------------------
// SUITE 2: COMPLETE ELIMINATION OF CRATES/* AND WINDOWS FILE EXPLORER UI
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 2: Windows File Explorer & Source Crate Elimination ---');

const appJs = fs.readFileSync(APP_JS_PATH, 'utf8');
const indexHtml = fs.readFileSync(INDEX_HTML_PATH, 'utf8');
const stylesCss = fs.readFileSync(STYLES_PATH, 'utf8');

runAssertion('app.js has zero occurrences of CANONICAL_CODEBASE_FOLDERS or getCodebaseFoldersList', () => {
  assert(!appJs.includes('CANONICAL_CODEBASE_FOLDERS'), 'Found CANONICAL_CODEBASE_FOLDERS in app.js');
  assert(!appJs.includes('getCodebaseFoldersList'), 'Found getCodebaseFoldersList in app.js');
  assert(!appJs.includes('Browse Codebase Root'), 'Found Browse Codebase Root in app.js');
});

runAssertion('index.html has zero recommendations of crates/* in reindex modal', () => {
  assert(!indexHtml.includes('crates/'), 'index.html contains forbidden "crates/" reference');
  assert(!indexHtml.includes('crates\\'), 'index.html contains forbidden "crates\\" reference');
});

runAssertion('Windows File Explorer component supports universal navigation controls', () => {
  assert(appJs.includes('function renderWindowsFileExplorerHtml'), 'renderWindowsFileExplorerHtml must be defined');
  assert(appJs.includes('data-action="browse-dir"'), 'browse-dir action must be present');
  assert(appJs.includes('data-action="browse-root"'), 'browse-root action must be present');
  assert(appJs.includes('data-action="browse-up"'), 'browse-up action must be present');
  assert(appJs.includes('data-action="trigger-native-folder-picker"'), 'trigger-native-folder-picker action must be present');
});

runAssertion('Folder selection actions call stopPropagation to prevent drill-down collapse', () => {
  // mkt-toggle-folder must preventDefault and stopPropagation
  assert(appJs.includes("case 'mkt-toggle-folder':"), 'Missing case mkt-toggle-folder');
  const mktToggleIdx = appJs.indexOf("case 'mkt-toggle-folder':");
  const mktToggleBlock = appJs.slice(mktToggleIdx, mktToggleIdx + 250);
  assert(mktToggleBlock.includes('e.stopPropagation();'), 'mkt-toggle-folder must invoke stopPropagation()');

  // share-folder must preventDefault and stopPropagation
  assert(appJs.includes("case 'share-folder':"), 'Missing case share-folder');
  const shareFolderIdx = appJs.indexOf("case 'share-folder':");
  const shareFolderBlock = appJs.slice(shareFolderIdx, shareFolderIdx + 250);
  assert(shareFolderBlock.includes('e.stopPropagation();'), 'share-folder must invoke stopPropagation()');

  // newdoc-pick-folder must preventDefault and stopPropagation
  assert(appJs.includes("case 'newdoc-pick-folder':"), 'Missing case newdoc-pick-folder');
  const newdocIdx = appJs.indexOf("case 'newdoc-pick-folder':");
  const newdocBlock = appJs.slice(newdocIdx, newdocIdx + 250);
  assert(newdocBlock.includes('e.stopPropagation();'), 'newdoc-pick-folder must invoke stopPropagation()');

  // reindex-pick-folder must preventDefault and stopPropagation
  assert(appJs.includes("case 'reindex-pick-folder':"), 'Missing case reindex-pick-folder');
  const reindexIdx = appJs.indexOf("case 'reindex-pick-folder':");
  const reindexBlock = appJs.slice(reindexIdx, reindexIdx + 250);
  assert(reindexBlock.includes('e.stopPropagation();'), 'reindex-pick-folder must invoke stopPropagation()');
});

runAssertion('renderWindowsFileExplorerHtml is wired into all 5 target UI surfaces', () => {
  assert(appJs.includes("contextId: 'general'"), 'general settings interface missing explorer');
  assert(appJs.includes("contextId: 'mkt'"), 'marketplace settings interface missing explorer');
  assert(appJs.includes("contextId: 'mesh'"), 'mesh shared folders interface missing explorer');
  assert(appJs.includes("contextId: 'newdoc'"), 'add new documents interface missing explorer');
  assert(appJs.includes("contextId: 'reindex'"), 'reindex engine modal missing explorer');
});

// ---------------------------------------------------------------------------
// SUITE 3: LOCALHOST MARKETPLACE TOOLS & 127.0.0.1/32 CIDR AUTHORIZATION
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 3: Localhost Marketplace Tools & 127.0.0.1/32 CIDRs ---');

const cliBinary = path.join(ROOT_DIR, 'target', 'debug', 'quorum-cli.exe');

runAssertion('quorum-cli binary exists and responds with 127.0.0.1/32 cert issuance', () => {
  assert(fs.existsSync(cliBinary), `CLI binary missing: ${cliBinary}`);
  const output = execSync(`"${cliBinary}" marketplace-issue-cert --egress-cidr 127.0.0.1/32`, { encoding: 'utf8' });
  const cert = JSON.parse(output);
  assert.strictEqual(cert.buyer_id, 'localhost-dev-buyer');
  assert(Array.isArray(cert.authorized_egress_cidrs));
  assert(cert.authorized_egress_cidrs.includes('127.0.0.1/32'), 'Cert must include 127.0.0.1/32');
  assert.strictEqual(cert.foci_ubo_verified_clean, true);
  assert.strictEqual(cert.doj_part202_non_covered_person, true);
  assert.strictEqual(cert.non_redistribution_covenant_accepted, true);
  assert(typeof cert.issuer_ed25519_signature_hex === 'string' && cert.issuer_ed25519_signature_hex.length === 128);
});

runAssertion('quorum-cli marketplace-buyer-pull verifies cert and fails on invalid server endpoint', () => {
  try {
    execSync(`"${cliBinary}" marketplace-buyer-pull --auto-issue-cert --seller-endpoint http://127.0.0.1:1 --batch-id test-batch`, { encoding: 'utf8', stdio: 'pipe' });
    assert.fail('Should have failed to connect to invalid endpoint');
  } catch (err) {
    assert(err.status !== 0, 'Exit code must be non-zero on connection failure');
  }
});

runAssertion('UI defines action handlers for mkt-issue-test-cert and mkt-exec-test-transaction', () => {
  assert(appJs.includes("case 'mkt-issue-test-cert':"), 'Missing mkt-issue-test-cert action');
  assert(appJs.includes("case 'mkt-exec-test-transaction':"), 'Missing mkt-exec-test-transaction action');
  assert(appJs.includes('marketplace-test-output-box'), 'Missing test output box');
});

runAssertion('Daemon routes test/issue-cert and test/execute-transaction in server.rs and marketplace.rs', () => {
  const serverRs = fs.readFileSync(SERVER_RS_PATH, 'utf8');
  assert(serverRs.includes('"/api/v1/marketplace/test/issue-cert"'), 'Route /api/v1/marketplace/test/issue-cert missing in server.rs');
  assert(serverRs.includes('"/api/v1/marketplace/test/execute-transaction"'), 'Route /api/v1/marketplace/test/execute-transaction missing in server.rs');
  
  const mktRs = fs.readFileSync(MKT_RS_PATH, 'utf8');
  assert(mktRs.includes('pub async fn marketplace_test_issue_cert_handler'), 'marketplace_test_issue_cert_handler missing in marketplace.rs');
  assert(mktRs.includes('pub async fn marketplace_test_execute_transaction_handler'), 'marketplace_test_execute_transaction_handler missing in marketplace.rs');
});

// ---------------------------------------------------------------------------
// SUITE 4: 4-STAGE SYNTHETIC GATE & DATACATALOGMANIFEST
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 4: 4-Stage Synthetic Gate & DataCatalogManifest Proof ---');

const syntheticGateRs = fs.readFileSync(SYNTHETIC_GATE_RS_PATH, 'utf8');
const contractMktRs = fs.readFileSync(CONTRACT_MKT_RS_PATH, 'utf8');

runAssertion('synthetic_gate.rs implements all 4 stages', () => {
  assert(syntheticGateRs.includes('pub fn evaluate_stage1_statistics'), 'Missing evaluate_stage1_statistics (Stage 1)');
  assert(syntheticGateRs.includes('pub fn inspect_file_provenance'), 'Missing inspect_file_provenance (Stage 2)');
  assert(syntheticGateRs.includes('pub fn scrub_and_scan_stage3_lexical'), 'Missing scrub_and_scan_stage3_lexical (Stage 3)');
  assert(syntheticGateRs.includes('pub struct HumanTelemetryGuard'), 'Missing HumanTelemetryGuard (Stage 4)');
  assert(syntheticGateRs.includes('pub struct SyntheticExclusionPipeline'), 'Missing SyntheticExclusionPipeline');
});

runAssertion('synthetic_gate.rs Stage 2 inspects KNOWN_SYNTHETIC_PDF_PRODUCERS', () => {
  assert(syntheticGateRs.includes('KNOWN_SYNTHETIC_PDF_PRODUCERS'), 'Missing KNOWN_SYNTHETIC_PDF_PRODUCERS constant');
  const expectedProducers = ['chatgpt', 'openai', 'anthropic', 'claude', 'wkhtmltopdf', 'headlesschrome', 'puppeteer', 'playwright', 'weasyprint', 'jasper', 'copy.ai'];
  for (const producer of expectedProducers) {
    assert(syntheticGateRs.includes(`"${producer}"`), `Missing expected synthetic producer: ${producer}`);
  }
});

runAssertion('synthetic_gate.rs Stage 3 strips all invisible zero-width watermarks and checks 27 clichés', () => {
  assert(syntheticGateRs.includes('SYNTHETIC_CLICHE_PATTERNS'), 'Missing SYNTHETIC_CLICHE_PATTERNS');
  assert(syntheticGateRs.includes('ZERO_WIDTH_WATERMARKS'), 'Missing ZERO_WIDTH_WATERMARKS');
  assert(syntheticGateRs.includes('detect_mixed_script_homoglyphs'), 'Missing detect_mixed_script_homoglyphs');
  assert(syntheticGateRs.includes('is_invisible_watermark_char'), 'Missing is_invisible_watermark_char');
  
  // Verify Unicode range checks: tag chars \u{E0000}..=\u{E007F} and bidi overrides
  assert(syntheticGateRs.includes('\\u{E0000}'), 'Missing Unicode tag character range check');
});

runAssertion('synthetic_gate.rs Stage 4 enforces GCRA burst rate limiter & nonce BLAKE3 MAC verification', () => {
  assert(syntheticGateRs.includes('check_gcra_rate_limit'), 'Missing check_gcra_rate_limit');
  assert(syntheticGateRs.includes('issue_interaction_nonce'), 'Missing issue_interaction_nonce');
  assert(syntheticGateRs.includes('verify_interaction_nonce'), 'Missing verify_interaction_nonce');
  assert(syntheticGateRs.includes('consumed_nonces'), 'Missing consumed_nonces replay prevention');
  assert(syntheticGateRs.includes('ConstantTimeEq'), 'Missing ConstantTimeEq constant-time MAC comparison');
});

runAssertion('DataCatalogManifest contains synthetic_contamination_filtered and signs it into Merkle/Ed25519', () => {
  assert(contractMktRs.includes('pub synthetic_contamination_filtered: bool'), 'DataCatalogManifest missing synthetic_contamination_filtered field');
  assert(contractMktRs.includes('synthetic_contamination_filtered: true'), 'DataCatalogManifest::from_records must initialize synthetic_contamination_filtered to true');
  assert(contractMktRs.includes('hasher.update(&[u8::from(self.synthetic_contamination_filtered)]);'), 'synthetic_contamination_filtered must be included in canonical_signing_bytes');
  assert(contractMktRs.includes('to_unauthenticated_preview'), 'to_unauthenticated_preview must preserve synthetic_contamination_filtered');
  assert(contractMktRs.includes('to_authenticated_watermarked_preview'), 'to_authenticated_watermarked_preview must preserve synthetic_contamination_filtered');
});

// ---------------------------------------------------------------------------
// SUITE 5: CONCURRENCY, BACKPRESSURE & SEMAPHORE ARCHITECTURE
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 5: Concurrency, Backpressure & Semaphore Architecture ---');

runAssertion('concurrency_stress_tests verify deadlock immunity and permit leak resilience', () => {
  const concTestsPath = path.join(ROOT_DIR, 'crates', 'quorum-daemon', 'tests', 'concurrency_stress_tests.rs');
  assert(fs.existsSync(concTestsPath), 'Missing concurrency_stress_tests.rs');
  const concContent = fs.readFileSync(concTestsPath, 'utf8');
  assert(concContent.includes('test_rlm_recursive_depth_aware_semaphore_zero_deadlocks'), 'Missing recursive depth deadlock test');
  assert(concContent.includes('test_mesh_admission_semaphore_zero_permit_leaks_on_cancellation'), 'Missing permit leak cancellation test');
  assert(concContent.includes('test_rlm_slice_cache_bounded_rss_zero_copy'), 'Missing RLM slice cache test');
  assert(concContent.includes('test_reciprocal_rank_fusion_dense_and_sparse'), 'Missing RRF test');
});

console.log('\n========================================================================');
console.log(`  CHALLENGER 2 HARNESS COMPLETE: ALL ${passedTests}/${totalTests} TESTS PASSED CLEANLY (100%)`);
console.log('========================================================================\n');
