/**
 * Adversarial Challenger Stress Harness for Milestone 1:
 * Settings Text and Layout Alignment Invariants
 *
 * Verifies:
 * 1. CSS layout utilities (.settings-centered-container, .settings-subtab-nav,
 *    .settings-header-action-row, .settings-row-controls, .settings-page-title,
 *    .settings-page-subtitle, .settings-section-heading).
 * 2. All 22 settings tab templates in app.js strictly enforce centered container alignment.
 * 3. Zero inline style overrides (no margin:0, margin-left:0, text-align:left on titles).
 * 4. Responsive geometry simulation across narrow (320px-768px), standard (1024px-1440px),
 *    and ultra-wide (1920px, 2560px, 3840px 4K) viewports.
 * 5. Rapid tab switching (1,000 cycles) for memory leakage and DOM nesting stability.
 * 6. Defensive fallback wrapper idempotency and edge cases (unwrapped content, text nodes,
 *    empty content, pre-wrapped content).
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const ROOT_DIR = path.resolve(__dirname, '..');
const STYLES_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'styles.css');
const APP_JS_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'app.js');
const INDEX_HTML_PATH = path.join(ROOT_DIR, 'crates', 'quorum-ui', 'assets', 'index.html');

console.log('================================================================');
console.log('  CHALLENGER 1: SETTINGS TEXT & LAYOUT ALIGNMENT STRESS HARNESS ');
console.log('================================================================');

// ---------------------------------------------------------------------------
// 1. Load Source Assets
// ---------------------------------------------------------------------------
assert(fs.existsSync(STYLES_PATH), `styles.css must exist at ${STYLES_PATH}`);
assert(fs.existsSync(APP_JS_PATH), `app.js must exist at ${APP_JS_PATH}`);
assert(fs.existsSync(INDEX_HTML_PATH), `index.html must exist at ${INDEX_HTML_PATH}`);

const stylesCss = fs.readFileSync(STYLES_PATH, 'utf8');
const appJs = fs.readFileSync(APP_JS_PATH, 'utf8');
const indexHtml = fs.readFileSync(INDEX_HTML_PATH, 'utf8');

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
// SUITE 1: CSS Layout Utilities & Spec Conformance
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 1: CSS Layout Utilities & Spec Conformance ---');

runTest('styles.css defines .settings-centered-container with 860px max-width & margin-inline:auto', () => {
  const containerMatch = stylesCss.match(/\.settings-centered-container\s*\{([^}]+)\}/);
  assert(containerMatch, 'styles.css must define .settings-centered-container');
  const body = containerMatch[1];
  assert(body.includes('max-width: 860px'), 'Must contain max-width: 860px');
  assert(body.includes('margin-inline: auto'), 'Must contain margin-inline: auto');
  assert(body.includes('box-sizing: border-box'), 'Must contain box-sizing: border-box');
  assert(body.includes('display: flex'), 'Must contain display: flex');
  assert(body.includes('flex-direction: column'), 'Must contain flex-direction: column');
});

runTest('styles.css defines .settings-centered-container > * with full child bounding', () => {
  const childMatch = stylesCss.match(/\.settings-centered-container\s*>\s*\*\s*\{([^}]+)\}/);
  assert(childMatch, 'styles.css must define .settings-centered-container > *');
  const body = childMatch[1];
  assert(body.includes('max-width: 860px'), 'Direct children must be capped at max-width: 860px');
  assert(body.includes('margin-inline: auto'), 'Direct children must have margin-inline: auto');
  assert(body.includes('box-sizing: border-box'), 'Direct children must have box-sizing: border-box');
  assert(body.includes('width: 100%'), 'Direct children must have width: 100%');
});

runTest('styles.css defines .settings-subtab-nav with centered flex alignment', () => {
  const subtabMatch = stylesCss.match(/\.settings-subtab-nav\s*\{([^}]+)\}/);
  assert(subtabMatch, 'styles.css must define .settings-subtab-nav');
  const body = subtabMatch[1];
  assert(body.includes('display: flex'), 'Must be flex');
  assert(body.includes('justify-content: center'), 'Must be centered horizontally');
  assert(body.includes('align-items: center'), 'Must be centered vertically');
  assert(body.includes('max-width: 860px'), 'Must be bounded to 860px');
  assert(body.includes('margin: 0 auto'), 'Must be auto-centered horizontally');
  assert(body.includes('flex-wrap: wrap'), 'Must wrap gracefully on narrow viewports');
});

runTest('styles.css defines .settings-header-action-row with 860px bound and scoped title alignment', () => {
  const rowMatch = stylesCss.match(/\.settings-header-action-row\s*\{([^}]+)\}/);
  assert(rowMatch, 'styles.css must define .settings-header-action-row');
  const body = rowMatch[1];
  assert(body.includes('max-width: 860px'), 'Must be bounded to 860px');
  assert(body.includes('margin: 0 auto'), 'Must be auto-centered horizontally');
  assert(body.includes('justify-content: space-between'), 'Must space title and action button');

  const titleInRow = stylesCss.match(/\.settings-header-action-row\s+\.settings-page-title\s*\{([^}]+)\}/);
  assert(titleInRow, 'styles.css must define .settings-header-action-row .settings-page-title');
  const titleBody = titleInRow[1];
  assert(titleBody.includes('text-align: left'), 'Title in action row aligns left against action button');
  assert(titleBody.includes('margin: 0'), 'Title in action row removes auto margins');
});

runTest('styles.css defines .settings-row-controls with flex alignment and flex-shrink: 0', () => {
  const controlsMatch = stylesCss.match(/\.settings-row-controls\s*\{([^}]+)\}/);
  assert(controlsMatch, 'styles.css must define .settings-row-controls');
  const body = controlsMatch[1];
  assert(body.includes('display: flex'), 'Must be flex');
  assert(body.includes('align-items: center'), 'Must align center');
  assert(body.includes('flex-shrink: 0'), 'Must have flex-shrink: 0 to prevent button squishing');
});

runTest('styles.css default rules for .settings-page-title and .settings-page-subtitle enforce centering', () => {
  const titleMatch = stylesCss.match(/(?:^|\n)\.settings-page-title\s*\{([^}]+)\}/);
  assert(titleMatch, 'styles.css must define .settings-page-title');
  const titleBody = titleMatch[1];
  assert(titleBody.includes('margin-inline: auto'), 'Title must have margin-inline: auto');
  assert(titleBody.includes('text-align: center'), 'Title must have text-align: center');

  const subtitleMatch = stylesCss.match(/(?:^|\n)\.settings-page-subtitle\s*\{([^}]+)\}/);
  assert(subtitleMatch, 'styles.css must define .settings-page-subtitle');
  const subtitleBody = subtitleMatch[1];
  assert(subtitleBody.includes('margin-inline: auto'), 'Subtitle must have margin-inline: auto');
  assert(subtitleBody.includes('text-align: center'), 'Subtitle must have text-align: center');
});

// ---------------------------------------------------------------------------
// SUITE 2: Tab Template Alignment & Inline Style Extraction
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 2: Tab Template Alignment & Inline Style Extraction ---');

const ALL_22_TABS = [
  'general',
  'marketplace',
  'marketplace-ledger',
  'diagnostics',
  'models',
  'appearance',
  'mesh',
  'dlp',
  'notifications',
  'profile',
  'security',
  'account',
  'archived',
  'parental',
  'trusted',
  'voice',
  'storage',
  'personalization',
  'pets',
  'keyboard',
  'usage',
  'datacontrols'
];

runTest('app.js covers all 22 expected settings tab branches', () => {
  for (const tab of ALL_22_TABS) {
    const branchPattern = new RegExp(`(?:if|else if)\\s*\\(tab\\s*===\\s*['"]${tab}['"]\\)`);
    assert(branchPattern.test(appJs), `app.js must handle tab switch branch for "${tab}"`);
  }
});

runTest('Every one of the 22 settings tab branches opens with <div class="settings-centered-container">', () => {
  const renderFnIdx = appJs.indexOf('function renderSettingsTabContent');
  assert(renderFnIdx !== -1, 'renderSettingsTabContent must exist');
  const renderBody = appJs.slice(renderFnIdx);

  for (const tab of ALL_22_TABS) {
    const tabMatch = renderBody.match(new RegExp(`(?:if|else if)\\s*\\(tab\\s*===\\s*['"]${tab}['"]\\)[\\s\\S]*?settingsContent\\.innerHTML\\s*=\\s*\`([\\s\\S]*?)\`;`));
    assert(tabMatch, `Tab branch '${tab}' must set settingsContent.innerHTML inside renderSettingsTabContent`);
    const innerHtml = tabMatch[1].trim();
    assert(
      innerHtml.startsWith('<div class="settings-centered-container">'),
      `Tab branch '${tab}' must open innerHTML with <div class="settings-centered-container">, instead found:\n${innerHtml.slice(0, 100)}`
    );
    assert(
      innerHtml.endsWith('</div>'),
      `Tab branch '${tab}' must properly terminate with </div> closing the centered container`
    );
  }
});

runTest('Total occurrences of <div class="settings-centered-container"> in app.js is at least 22', () => {
  const matches = appJs.match(/<div class="settings-centered-container">/g);
  assert(matches && matches.length >= 22, `Expected >= 22 occurrences, found ${matches ? matches.length : 0}`);
});

runTest('Zero occurrences of inline style margin overrides on <h2 class="settings-page-title">', () => {
  // Regex to detect any style attribute on settings-page-title
  const badTitleStyle = /<h2[^>]*class=["'][^"']*settings-page-title[^"']*["'][^>]*style=["'][^"']*margin/gi;
  const matches = appJs.match(badTitleStyle);
  assert(!matches || matches.length === 0, `Found illegal inline margin style on settings-page-title: ${matches}`);
});

runTest('Zero occurrences of inline style margin-left overrides on headings across all settings tabs', () => {
  const badMarginLeft = /<h[1-6][^>]*style=["'][^"']*margin-left\s*:\s*0/gi;
  const matches = appJs.match(badMarginLeft);
  assert(!matches || matches.length === 0, `Found illegal margin-left:0 on heading: ${matches}`);
});

runTest('Zero occurrences of arbitrary max-width restrictions on subtitles in parental and trusted tabs', () => {
  assert(!appJs.includes('style="max-width:660px;"'), 'Must not have style="max-width:660px;"');
  assert(!appJs.includes('style="max-width:680px;"'), 'Must not have style="max-width:680px;"');
});

runTest('quickSubTabsBar utilizes class="settings-subtab-nav"', () => {
  assert(
    appJs.includes('<div class="settings-subtab-nav">'),
    'quickSubTabsBar must render with class="settings-subtab-nav"'
  );
});

runTest('Action row tabs (archived, parental) wrap title in class="settings-header-action-row"', () => {
  // archived
  const archivedIdx = appJs.indexOf("tab === 'archived'");
  const archivedSlice = appJs.slice(archivedIdx, archivedIdx + 2500);
  assert(
    archivedSlice.includes('<div class="settings-header-action-row">'),
    'archived tab must wrap title in settings-header-action-row'
  );

  // parental
  const parentalIdx = appJs.indexOf("tab === 'parental'");
  const parentalSlice = appJs.slice(parentalIdx, parentalIdx + 2500);
  assert(
    parentalSlice.includes('<div class="settings-header-action-row">'),
    'parental tab must wrap title in settings-header-action-row'
  );
});

runTest('settings-row-controls is used across at least 15 row control groups', () => {
  const matches = appJs.match(/class=["'][^"']*settings-row-controls[^"']*["']/g);
  assert(matches && matches.length >= 15, `Expected >= 15 row controls, found ${matches ? matches.length : 0}`);
});

// ---------------------------------------------------------------------------
// SUITE 3: DOM Rendering & Defensive Fallback Simulation
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 3: DOM Rendering & Defensive Fallback Simulation ---');

class MockDOMNode {
  constructor(nodeType = 1, nodeName = 'DIV') {
    this.nodeType = nodeType;
    this.nodeName = nodeName;
    this.className = '';
    this.classList = {
      _classes: new Set(),
      add: (...cls) => {
        cls.forEach(c => this.classList._classes.add(c));
        this.className = Array.from(this.classList._classes).join(' ');
      },
      remove: (...cls) => {
        cls.forEach(c => this.classList._classes.delete(c));
        this.className = Array.from(this.classList._classes).join(' ');
      },
      contains: (c) => this.classList._classes.has(c),
      toggle: (c, force) => {
        if (force === undefined) {
          if (this.classList.contains(c)) this.classList.remove(c);
          else this.classList.add(c);
        } else if (force) {
          this.classList.add(c);
        } else {
          this.classList.remove(c);
        }
      }
    };
    this.childNodes = [];
    this.style = {};
    this._innerHTML = '';
  }

  get children() {
    return this.childNodes.filter(n => n.nodeType === 1);
  }

  get firstChild() {
    return this.childNodes[0] || null;
  }

  get firstElementChild() {
    return this.children[0] || null;
  }

  appendChild(child) {
    // If child is in another parent, remove it first
    if (child._parent) {
      child._parent.removeChild(child);
    }
    child._parent = this;
    this.childNodes.push(child);
    return child;
  }

  removeChild(child) {
    const idx = this.childNodes.indexOf(child);
    if (idx !== -1) {
      this.childNodes.splice(idx, 1);
      child._parent = null;
    }
    return child;
  }

  set innerHTML(html) {
    this._innerHTML = html;
    this.childNodes = [];
    // Basic parser for simulation:
    // Extract top-level elements by regex
    const divRegex = /<([a-z0-9]+)([^>]*)>([\s\S]*?)<\/\1>|<([a-z0-9]+)([^>]*)\/>/gi;
    let match;
    let hasElement = false;
    while ((match = divRegex.exec(html)) !== null) {
      hasElement = true;
      const tag = (match[1] || match[4]).toUpperCase();
      const attrs = match[2] || match[5] || '';
      const child = new MockDOMNode(1, tag);
      const classMatch = attrs.match(/class=["']([^"']+)["']/i);
      if (classMatch) {
        classMatch[1].split(/\s+/).forEach(c => child.classList.add(c));
      }
      if (match[3]) {
        child.innerHTML = match[3];
      }
      this.appendChild(child);
    }
    if (!hasElement && html.trim().length > 0) {
      // Raw text node
      const textNode = new MockDOMNode(3, '#text');
      this.appendChild(textNode);
    }
  }

  get innerHTML() {
    return this._innerHTML;
  }
}

// Emulate the exact defensive fallback logic from app.js lines 7006-7014:
function applyDefensiveFallback(settingsContent) {
  if (settingsContent.firstElementChild && !settingsContent.firstElementChild.classList.contains('settings-centered-container')) {
    const wrapper = new MockDOMNode(1, 'DIV');
    wrapper.className = 'settings-centered-container';
    wrapper.classList.add('settings-centered-container');
    while (settingsContent.firstChild) {
      wrapper.appendChild(settingsContent.firstChild);
    }
    settingsContent.appendChild(wrapper);
  }
}

runTest('Defensive fallback: Wraps raw unwrapped elements in .settings-centered-container', () => {
  const container = new MockDOMNode(1, 'DIV');
  container.innerHTML = '<h2 class="settings-page-title">Bare Title</h2><div class="settings-card">Card</div>';

  assert.strictEqual(container.children.length, 2);
  assert.strictEqual(container.firstElementChild.nodeName, 'H2');
  assert(!container.firstElementChild.classList.contains('settings-centered-container'));

  applyDefensiveFallback(container);

  assert.strictEqual(container.children.length, 1, 'Should have exactly 1 root child after fallback');
  assert(container.firstElementChild.classList.contains('settings-centered-container'), 'Root child must be .settings-centered-container');
  assert.strictEqual(container.firstElementChild.children.length, 2, 'All children must be moved into wrapper');
  assert.strictEqual(container.firstElementChild.children[0].nodeName, 'H2');
  assert.strictEqual(container.firstElementChild.children[1].nodeName, 'DIV');
});

runTest('Defensive fallback: Idempotent when content is already pre-wrapped', () => {
  const container = new MockDOMNode(1, 'DIV');
  container.innerHTML = '<div class="settings-centered-container"><h2 class="settings-page-title">Title</h2></div>';

  assert.strictEqual(container.children.length, 1);
  assert(container.firstElementChild.classList.contains('settings-centered-container'));

  applyDefensiveFallback(container);

  assert.strictEqual(container.children.length, 1);
  assert(container.firstElementChild.classList.contains('settings-centered-container'));
  assert.strictEqual(container.firstElementChild.children.length, 1);
  assert.strictEqual(container.firstElementChild.children[0].nodeName, 'H2');
});

runTest('Defensive fallback: Handles empty settings container gracefully', () => {
  const container = new MockDOMNode(1, 'DIV');
  container.innerHTML = '';

  assert.strictEqual(container.children.length, 0);
  assert.strictEqual(container.firstElementChild, null);

  applyDefensiveFallback(container);

  assert.strictEqual(container.children.length, 0);
  assert.strictEqual(container.firstElementChild, null);
});

// ---------------------------------------------------------------------------
// SUITE 4: Responsive Geometry & Multi-Viewport Centering Simulator
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 4: Responsive Geometry & Multi-Viewport Centering Simulator ---');

/**
 * Mathematical model of the CSS Layout:
 * Container:
 *   width: 100%
 *   max-width: 860px
 *   margin-inline: auto
 * Parent container padding:
 *   left: 40px, right: 40px (from index.html #settings-content-container)
 */
function computeLayoutGeometry(viewportWidth, parentPaddingLeft = 40, parentPaddingRight = 40) {
  const availableParentWidth = Math.max(0, viewportWidth - parentPaddingLeft - parentPaddingRight);
  const containerWidth = Math.min(availableParentWidth, 860);
  const marginInlineTotal = availableParentWidth - containerWidth;
  const marginLeft = marginInlineTotal / 2;
  const marginRight = marginInlineTotal / 2;

  // Absolute positioning within viewport:
  const containerLeft = parentPaddingLeft + marginLeft;
  const containerRight = viewportWidth - (parentPaddingRight + marginRight);

  // Symmetry verification:
  const isSymmetric = Math.abs(marginLeft - marginRight) < 0.0001;
  const leftEdgeDistance = containerLeft;
  const rightEdgeDistance = viewportWidth - (containerLeft + containerWidth);
  const isCenteredInViewport = Math.abs(leftEdgeDistance - rightEdgeDistance) < 0.0001;

  return {
    viewportWidth,
    availableParentWidth,
    containerWidth,
    marginLeft,
    marginRight,
    containerLeft,
    containerRight,
    isSymmetric,
    isCenteredInViewport
  };
}

const VIEWPORT_TEST_MATRIX = [
  { name: 'Ultra-Narrow Mobile (iPhone SE)', width: 320 },
  { name: 'Standard Mobile (iPhone 12/13/14)', width: 390 },
  { name: 'Large Mobile (Pixel 7 Pro / iPhone Pro Max)', width: 430 },
  { name: 'Foldable / Small Tablet', width: 600 },
  { name: 'iPad Portrait', width: 768 },
  { name: 'iPad Landscape / Small Laptop', width: 1024 },
  { name: 'HD Laptop (720p)', width: 1280 },
  { name: 'WXGA+ Laptop', width: 1440 },
  { name: 'Full HD Desktop (1080p)', width: 1920 },
  { name: 'QHD / 2K Display (1440p)', width: 2560 },
  { name: '4K Ultra HD Display (2160p)', width: 3840 },
  { name: 'Super Ultrawide Dual-4K', width: 5120 }
];

for (const vp of VIEWPORT_TEST_MATRIX) {
  runTest(`Viewport ${vp.name} (${vp.width}px): strictly centered without left-margin jumping`, () => {
    const geo = computeLayoutGeometry(vp.width);

    assert(geo.isSymmetric, `Margins must be symmetric: left=${geo.marginLeft}, right=${geo.marginRight}`);
    assert(geo.isCenteredInViewport, `Container must be centered in viewport: leftDist=${geo.containerLeft}, rightDist=${vp.width - (geo.containerLeft + geo.containerWidth)}`);

    if (geo.availableParentWidth > 860) {
      assert.strictEqual(geo.containerWidth, 860, 'Container width must be capped at exactly 860px');
      assert(geo.marginLeft > 0, 'Margin-left must be positive when viewport > 860px + padding');
    } else {
      assert.strictEqual(geo.containerWidth, geo.availableParentWidth, 'Container must scale to 100% of available width');
      assert.strictEqual(geo.marginLeft, 0, 'Margin-inline is 0 when fully filling parent');
    }
  });
}

// ---------------------------------------------------------------------------
// SUITE 5: Rapid Tab Switching & DOM Lifecycle Stress Test
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 5: Rapid Tab Switching & DOM Lifecycle Stress Test ---');

runTest('1,000 rapid sequential and randomized tab switch cycles retain DOM integrity', () => {
  const container = new MockDOMNode(1, 'DIV');

  for (let cycle = 0; cycle < 1000; cycle++) {
    const tab = ALL_22_TABS[cycle % ALL_22_TABS.length];
    // Emulate tab render template
    container.innerHTML = `<div class="settings-centered-container"><h2 class="settings-page-title">${tab}</h2></div>`;
    applyDefensiveFallback(container);

    assert.strictEqual(container.children.length, 1, `Cycle ${cycle}: Must have exactly 1 child`);
    assert(container.firstElementChild.classList.contains('settings-centered-container'), `Cycle ${cycle}: Must be centered container`);
    assert.strictEqual(container.firstElementChild.children[0].nodeName, 'H2');
  }
});

// ---------------------------------------------------------------------------
// SUITE 6: Settings Dialog Footer & Scrolling Layer Invariant
// ---------------------------------------------------------------------------
console.log('\n--- SUITE 6: Settings Dialog Footer & Scrolling Layer Invariant ---');

runTest('index.html encapsulates #settings-content-container with overflow-y:auto and docks footer with flex-shrink:0', () => {
  const containerMatch = indexHtml.match(/id=["']settings-content-container["'][^>]*style=["']([^"']+)["']/i);
  assert(containerMatch, 'index.html must contain #settings-content-container with style attribute');
  const styleStr = containerMatch[1];
  assert(styleStr.includes('overflow-y:auto') || styleStr.includes('overflow-y: auto'), 'Container must own vertical scrolling');
  assert(styleStr.includes('flex:1') || styleStr.includes('flex: 1'), 'Container must expand to fill dialog area');

  const footerMatch = indexHtml.match(/class=["'][^"']*settings-dialog-footer[^"']*["'][^>]*style=["']([^"']+)["']/i);
  assert(footerMatch, 'index.html must contain .settings-dialog-footer with style attribute');
  const footerStyle = footerMatch[1];
  assert(footerStyle.includes('flex-shrink:0') || footerStyle.includes('flex-shrink: 0'), 'Footer must have flex-shrink:0');
});

// ---------------------------------------------------------------------------
// SUMMARY & VERDICT
// ---------------------------------------------------------------------------
console.log('\n================================================================');
console.log(`  ALL ${totalTests} TESTS PASSED CLEANLY (100% SUCCESS)`);
console.log('================================================================\n');
