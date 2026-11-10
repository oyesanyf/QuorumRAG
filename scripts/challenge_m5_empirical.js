// Empirical Challenger Verification Script for Milestone 5 Iteration 2
// Tests HTML5 boolean attribute semantics, artemis-upload-folder tab refresh,
// evtx search auto-jump, and strict click-to-select folder invariants.

const fs = require('fs');
const path = require('path');
const assert = require('assert');

function runChallengeSuite() {
  console.log('=== RUNNING EMPIRICAL CHALLENGER VERIFICATION SUITE ===\n');
  const appJsPath = path.resolve('crates/quorum-ui/assets/app.js');
  const indexHtmlPath = path.resolve('crates/quorum-ui/assets/index.html');

  assert(fs.existsSync(appJsPath), 'app.js must exist at ' + appJsPath);
  assert(fs.existsSync(indexHtmlPath), 'index.html must exist at ' + indexHtmlPath);

  const appJs = fs.readFileSync(appJsPath, 'utf8');
  const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');

  let passedTests = 0;
  let totalTests = 0;

  function test(name, fn) {
    totalTests++;
    try {
      fn();
      console.log(`[PASS] ${name}`);
      passedTests++;
    } catch (err) {
      console.error(`[FAIL] ${name}: ${err.message}`);
      throw err;
    }
  }

  // TEST 1: Absolute absence of checked=false across all static assets
  test('1.1: Verify checked=false, checked="false", checked=\'false\' absent from app.js and index.html', () => {
    assert(!appJs.includes('checked=false'), 'Found checked=false in app.js');
    assert(!appJs.includes('checked="false"'), 'Found checked="false" in app.js');
    assert(!appJs.includes("checked='false'"), "Found checked='false' in app.js");
    assert(!indexHtml.includes('checked=false'), 'Found checked=false in index.html');
    assert(!indexHtml.includes('checked="false"'), 'Found checked="false" in index.html');
    assert(!indexHtml.includes("checked='false'"), "Found checked='false' in index.html");
  });

  // TEST 2: HTML5 Boolean Attribute Parsing Simulation
  test('1.2: HTML5 Boolean Attribute Semantics for prohibited category switches', () => {
    // Under W3C HTML5 §2.4.2:
    // A boolean attribute on an element represents true value if the attribute is present,
    // and false if the attribute is absent.
    // If an element has checked="false" or checked=false, the attribute IS present, so checked === true!
    // The only way to represent false is total absence of the attribute.
    
    // Check prohibited rows generation in app.js
    const prohibitedSnippet = appJs.slice(appJs.indexOf('const prohibitedRowsHtml'), appJs.indexOf('const curSelectedDir'));
    assert(prohibitedSnippet.length > 0, 'prohibitedRowsHtml section must exist in app.js');
    
    // Check that switch input in prohibited rows has disabled, but NO checked attribute
    assert(prohibitedSnippet.includes('disabled'), 'Prohibited switch must be disabled');
    assert(!prohibitedSnippet.includes('checked'), 'Prohibited switch must NOT have any checked attribute');
    assert(prohibitedSnippet.includes('title="Prohibited category cannot be enabled"'), 'Prohibited switch must have descriptive title');
  });

  // TEST 3: Artemis Upload Folder Event Handling
  test('2.1: case "artemis-upload-folder" re-renders tab and synchronizes UI controls', () => {
    const uploadCaseStart = appJs.indexOf("case 'artemis-upload-folder':");
    assert(uploadCaseStart !== -1, "case 'artemis-upload-folder' must exist in app.js");
    const uploadCaseEnd = uploadCaseStart + 1500;
    const uploadCaseBody = appJs.slice(uploadCaseStart, uploadCaseEnd);

    // Verify it extracts folderName
    assert(uploadCaseBody.includes('artemisSelectedDir = folderName;'), 'artemisSelectedDir must be set');
    // Verify it updates hidden input and pill
    assert(uploadCaseBody.includes("document.getElementById('artemis-jsonl-dir-input')"), 'Updates hidden input');
    assert(uploadCaseBody.includes("document.getElementById('artemis-selected-folder-display')"), 'Updates visual pill');
    // Verify it re-renders tab content
    assert(uploadCaseBody.includes("renderSettingsTabContent('artemis-dfir', '');"), 'Must call renderSettingsTabContent');
    // Verify showSettingsToast is called
    assert(uploadCaseBody.includes('showSettingsToast('), 'Must show feedback toast');
  });

  test('2.2: Verify collect button and clear button conditional rendering logic', () => {
    // When curSelectedDir is set, button text is "Ingest Selected Folder (.jsonl)"
    // and clear button "#btn-artemis-clear-folder" is rendered.
    // When curSelectedDir is empty, button text is "Collect Live OS Telemetry" and clear button is omitted.
    const artemisBranchStart = appJs.indexOf("tab === 'artemis-dfir'");
    assert(artemisBranchStart !== -1, "tab === 'artemis-dfir' branch must exist");
    const artemisBranchEnd = appJs.indexOf("tab === 'notifications'", artemisBranchStart);
    assert(artemisBranchEnd !== -1, "tab === 'notifications' branch must exist after artemis-dfir");
    const artemisBranch = appJs.slice(artemisBranchStart, artemisBranchEnd);
    
    assert(artemisBranch.includes("${curSelectedDir ? 'Ingest Selected Folder (.jsonl)' : 'Collect Live OS Telemetry'}"),
      'Collect button label must toggle based on curSelectedDir');
    
    assert(artemisBranch.includes('data-action="artemis-clear-selected-folder" id="btn-artemis-clear-folder"'),
      'Clear folder button must be defined in template');
    assert(artemisBranch.includes('${curSelectedDir ? `'),
      'Clear folder button must be conditionally rendered when curSelectedDir is set');
  });

  // TEST 4: Search auto-jump on "evtx"
  test('3.1: Search auto-jump condition includes "evtx" and triggers artemis-dfir tab activation', () => {
    const searchListenerStart = appJs.indexOf("settingsSearchInput.addEventListener('input'");
    assert(searchListenerStart !== -1, 'Search listener must exist');
    const searchListenerEnd = appJs.indexOf('async function saveUiSettingsPatch', searchListenerStart);
    const searchBody = appJs.slice(searchListenerStart, searchListenerEnd);

    // Filter test
    assert(searchBody.includes("q.includes('evtx')"), 'Search filter must check evtx');
    
    // Auto-jump branch test
    const autoJumpIndex = searchBody.indexOf("activeSettingsTab = 'artemis-dfir';");
    assert(autoJumpIndex !== -1, 'Must activate artemis-dfir');
    
    // Check preceding condition for artemis-dfir auto-jump
    const precedingCondition = searchBody.slice(searchBody.lastIndexOf('else if', autoJumpIndex), autoJumpIndex);
    assert(precedingCondition.includes("q.includes('evtx')"), 'Auto-jump condition must include evtx: ' + precedingCondition);
    assert(precedingCondition.includes("q.includes('artemis')"), 'Auto-jump condition must include artemis');
    assert(precedingCondition.includes("q.includes('dfir')"), 'Auto-jump condition must include dfir');
    assert(precedingCondition.includes("q.includes('forensic')"), 'Auto-jump condition must include forensic');
    assert(precedingCondition.includes("q.includes('telemetry')"), 'Auto-jump condition must include telemetry');

    // Simulate search query evaluation
    const queryEvaluator = (rawQ) => {
      const q = rawQ.trim().toLowerCase();
      let activeTab = null;
      let tabVisible = false;

      // Nav item visibility simulation for artemis-dfir
      const tab = 'artemis-dfir';
      const label = '🛡️ artemis dfir & forensics (local-only)';
      const match = !q || label.includes(q) || tab.includes(q)
        || (q.includes('folder') && (tab === 'artemis-dfir'))
        || ((q.includes('artemis') || q.includes('dfir') || q.includes('forensic') || q.includes('telemetry') || q.includes('evtx')) && tab === 'artemis-dfir');
      tabVisible = match;

      if (q.includes('opt') || q.includes('sell') || q.includes('consent') || q.includes('personal') || q.includes('market')) {
        activeTab = 'marketplace';
      } else if (q.includes('ledger') || q.includes('bounty') || q.includes('revenue')) {
        activeTab = 'marketplace-ledger';
      } else if (q.includes('stream') || q.includes('reindex') || q.includes('drift') || q.includes('diag')) {
        activeTab = 'diagnostics';
      } else if (q.includes('phi') || q.includes('dlp') || q.includes('redact') || q.includes('hipaa')) {
        activeTab = 'dlp';
      } else if (q.includes('artemis') || q.includes('dfir') || q.includes('forensic') || q.includes('telemetry') || q.includes('evtx')) {
        activeTab = 'artemis-dfir';
      } else if (q.includes('mesh') || q.includes('share') || q.includes('peer')) {
        activeTab = 'mesh';
      }
      return { q, activeTab, tabVisible };
    };

    const evtxCases = ['evtx', 'EVTX', '  evtx  ', 'Windows EVTX', 'artemis evtx logs'];
    for (const testCase of evtxCases) {
      const res = queryEvaluator(testCase);
      assert.strictEqual(res.activeTab, 'artemis-dfir', `Query "${testCase}" must auto-jump to artemis-dfir`);
      assert.strictEqual(res.tabVisible, true, `Query "${testCase}" must keep artemis-dfir nav button visible`);
    }
  });

  // TEST 5: Mandatory User Directive — Click-to-Select Folder Invariants
  test('4.1: Verify all 6 folder path inputs are strictly <input type="hidden">', () => {
    const requiredFolderIds = [
      'artemis-jsonl-dir-input',
      'reindex-target-path',
      'mkt-folder-input',
      'new-doc-path-input',
      'new-shared-folder-input',
      'dlp-sim-path'
    ];

    for (const id of requiredFolderIds) {
      // Must NEVER be type="text"
      assert(!indexHtml.includes(`type="text" id="${id}"`), `index.html contains type="text" for #${id}`);
      assert(!indexHtml.includes(`id="${id}" type="text"`), `index.html contains type="text" for #${id}`);
      assert(!appJs.includes(`type="text" id="${id}"`), `app.js contains type="text" for #${id}`);
      assert(!appJs.includes(`id="${id}" type="text"`), `app.js contains type="text" for #${id}`);
      assert(!indexHtml.includes(`<input id="${id}">`), `index.html contains untyped input for #${id}`);

      // Must be type="hidden"
      const hiddenInHtml = indexHtml.includes(`type="hidden" id="${id}"`) || indexHtml.includes(`id="${id}" type="hidden"`);
      const hiddenInJs = appJs.includes(`type="hidden" id="${id}"`) || appJs.includes(`id="${id}" type="hidden"`);
      assert(hiddenInHtml || hiddenInJs, `#${id} must be <input type="hidden"> in either index.html or app.js`);
    }
  });

  test('4.2: Verify all click-to-select folder controls exist and are properly configured', () => {
    // 1. Native OS picker
    assert(indexHtml.includes('data-action="trigger-native-folder-picker" data-context="artemis"'),
      'index.html must have native folder picker for artemis');
    assert(appJs.includes('data-action="trigger-native-folder-picker" data-context="artemis"'),
      'appJs must have native folder picker for artemis');

    // 2. Folder upload input
    assert(indexHtml.includes('id="artemis-folder-upload-input"') && indexHtml.includes('webkitdirectory'),
      'index.html must have folder upload with webkitdirectory');
    assert(appJs.includes('id="artemis-folder-upload-input" webkitdirectory directory multiple'),
      'app.js must have folder upload with webkitdirectory directory multiple');

    // 3. Visual selected folder pill
    assert(indexHtml.includes('id="artemis-selected-folder-display"'),
      'index.html must have #artemis-selected-folder-display');
    assert(appJs.includes('id="artemis-selected-folder-display"'),
      'app.js must have #artemis-selected-folder-display');

    // 4. Interactive folder browser
    assert(indexHtml.includes('id="artemis-folder-browser-list"'),
      'index.html must have #artemis-folder-browser-list');
    assert(appJs.includes('id="artemis-folder-browser-list"'),
      'app.js must have #artemis-folder-browser-list');
    assert(appJs.includes("contextId: 'artemis'"),
      "app.js must invoke renderWindowsFileExplorerHtml with contextId: 'artemis'");
  });

  console.log(`\n=== SUITE COMPLETE: ${passedTests}/${totalTests} TESTS PASSED ===\n`);
}

runChallengeSuite();
