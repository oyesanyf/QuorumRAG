/**
 * Adversarial Challenger Stress Harness for Milestone 37 UI Telemetry Guard:
 * 1. In-flight telemetry banner suppression under all permutation states
 * 2. Contributing peer badge rendering before inline citations
 * 3. Prevention of "0 peers connected" fallback when connected_peers_count > 0
 */

const assert = require('assert');

// Minimal mock DOM for headless testing of refreshSourcesNodeIdRow
class MockElement {
  constructor(tagName = 'div') {
    this.tagName = tagName;
    this.className = '';
    this.classList = {
      add: (c) => { this.className += ' ' + c; },
      remove: (c) => { this.className = this.className.replace(c, '').trim(); },
      contains: (c) => this.className.includes(c),
    };
    this.innerHTML = '';
    this.children = [];
    this.nextSibling = null;
    this.style = {};
  }

  querySelector(selector) {
    if (selector.startsWith('.')) {
      const cls = selector.slice(1);
      return this._find(el => el.className && el.className.includes(cls));
    }
    return null;
  }

  _find(predicate) {
    for (const child of this.children) {
      if (predicate(child)) return child;
      const found = child._find(predicate);
      if (found) return found;
    }
    return null;
  }

  appendChild(el) {
    this.children.push(el);
    return el;
  }

  insertBefore(newEl, refEl) {
    const idx = this.children.indexOf(refEl);
    if (idx !== -1) {
      this.children.splice(idx, 0, newEl);
    } else {
      this.children.push(newEl);
    }
    return newEl;
  }
}

// Global mocks
global.document = {
  createElement: (tag) => new MockElement(tag),
};

function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatNodeIdChip(id) {
  if (!id) return 'local';
  if (id.length <= 16) return id;
  return id.slice(0, 8) + '…' + id.slice(-6);
}

// Emulate the exact refreshSourcesNodeIdRow from crates/quorum-ui/assets/app.js
function refreshSourcesNodeIdRow(citationsEl, cachedSettingsData, isGenerating) {
  if (!citationsEl) return;
  const localNodeId = (cachedSettingsData && cachedSettingsData.runtime && cachedSettingsData.runtime.local_peer_id)
    ? String(cachedSettingsData.runtime.local_peer_id).trim()
    : 'local-sovereign-node';

  const responderId = (citationsEl._responderPeerId && citationsEl._responderPeerId !== 'local')
    ? citationsEl._responderPeerId
    : localNodeId;

  const pendingList = Array.isArray(citationsEl._pendingCitations) ? citationsEl._pendingCitations : [];
  const records = Array.isArray(citationsEl._records) ? citationsEl._records : [];
  const distinctPeers = new Set();

  if (citationsEl._contributingPeerIds && typeof citationsEl._contributingPeerIds.forEach === 'function') {
    citationsEl._contributingPeerIds.forEach(pid => {
      const s = String(pid || '').trim();
      if (s && s.toLowerCase() !== 'local') {
        distinctPeers.add(s);
      }
    });
  }

  for (const item of pendingList) {
    const isExt = Boolean(item && item.is_external_node);
    const pid = String((item && (item.node_id || item.peer_id || item.source_peer)) || '').trim();
    if (isExt && pid && pid.toLowerCase() !== 'local') {
      distinctPeers.add(pid);
    } else {
      distinctPeers.add(localNodeId);
    }
  }
  for (const rec of records) {
    const pid = String(rec.nodeId || '').trim();
    if (pid && pid.toLowerCase() !== 'local') {
      distinctPeers.add(pid);
    } else {
      distinctPeers.add(responderId);
    }
  }
  if (distinctPeers.size === 0) distinctPeers.add(responderId);

  let nodeRow = citationsEl.querySelector('.sources-node-id-row');
  if (!nodeRow) {
    nodeRow = document.createElement('div');
    nodeRow.className = 'sources-node-id-row';
    const heading = citationsEl.querySelector('.sources-heading');
    if (heading && heading.nextSibling) {
      citationsEl.insertBefore(nodeRow, heading.nextSibling);
    } else {
      citationsEl.appendChild(nodeRow);
    }
  }

  const isExternalResponder = responderId !== localNodeId && responderId !== 'local-sovereign-node';
  const meshPeerIds = Array.from(distinctPeers).filter(pid =>
    pid && pid.toLowerCase() !== 'local' && pid !== localNodeId && pid !== 'local-sovereign-node'
  );
  const meshContributorsCount = meshPeerIds.length;
  const retrievedRemoteCount = Number(citationsEl._retrievedRemoteCount || citationsEl._remoteCount || 0);
  const hasRemoteChunks = (meshContributorsCount > 0) || (retrievedRemoteCount > 0);
  const queryInFlight = Boolean(citationsEl._queryInFlight || isGenerating);

  let peerDiagHtml = '';
  // Never render "No data from remote peers" banner while query is in flight OR when remote chunks match or contributors exist!
  if (!queryInFlight && !hasRemoteChunks && meshContributorsCount === 0) {
    const diag = citationsEl._peerDiagnostics;
    const meshPort = (cachedSettingsData && cachedSettingsData.mesh && cachedSettingsData.mesh.mesh_port) || 3032;
    const connectedCount = (diag && typeof diag.connected_peers_count === 'number') ? diag.connected_peers_count : 0;
    let reason = (diag && diag.summary_reason) ? diag.summary_reason : null;
    if (!reason) {
      if (connectedCount > 0) {
        reason = `${connectedCount} peer${connectedCount > 1 ? 's' : ''} connected on P2P port ${meshPort}, but no matching chunks returned`;
      } else {
        reason = `0 peers connected on P2P port ${meshPort} (no mDNS or bootstrap peers online)`;
      }
    } else if (connectedCount > 0 && reason.startsWith('0 peers connected')) {
      reason = `${connectedCount} peer${connectedCount > 1 ? 's' : ''} connected on P2P port ${meshPort}, but no matching chunks returned`;
    }
    peerDiagHtml = `
      <div class="sources-peer-diagnostic-row" style="margin-top:4px; font-size:12px; color:var(--text-muted, #9ca3af);">
        <span>📡 Remote Peers:</span>
        <span style="font-style:italic;">No data from remote peers — Reason: ${escapeHtml(reason)}</span>
      </div>
    `;
  }

  const meshPeersLabel = meshPeerIds.length > 0
    ? ` (+ ${meshContributorsCount} Mesh Peer${meshContributorsCount > 1 ? 's' : ''}: ${meshPeerIds.map(p => escapeHtml(p.length > 12 ? p.slice(0, 10) + '…' : p)).join(', ')})`
    : (meshContributorsCount > 0 ? ` (+ ${meshContributorsCount} Mesh Peer${meshContributorsCount > 1 ? 's' : ''})` : '');

  nodeRow.innerHTML = `
    <div style="display:flex; align-items:center; gap:6px; flex-wrap:wrap;">
      <span style="font-weight:600; color:var(--text-secondary, #d1d5db);">Responding Node ID:</span>
      <button type="button" class="sources-node-id-chip" title="Click to copy full node ID: ${escapeHtml(responderId)}">
        ${escapeHtml(formatNodeIdChip(responderId))}
      </button>
      ${meshContributorsCount > 0 ? `
        <span class="sources-federated-tag" style="font-size:11px; opacity:0.85; color:var(--text-muted); background:rgba(255,255,255,0.06); padding:2px 6px; border-radius:4px;">
          ${meshPeersLabel}
        </span>
      ` : ''}
    </div>
    ${peerDiagHtml}
  `;
}

// -----------------------------------------------------------------------------
// ADVERSARIAL SUITE
// -----------------------------------------------------------------------------

function runAdversarialTests() {
  console.log('--- Starting Adversarial UI Telemetry Stress Tests ---');

  const settings = {
    runtime: { local_peer_id: '12D3KooWLocal' },
    mesh: { mesh_port: 3032 },
  };

  // Test 1: In-Flight Telemetry Guard Invariant
  // While query is in flight (_queryInFlight = true), under NO circumstances should "No data from remote peers" render.
  {
    const inFlightPermutations = [
      { diag: null, desc: 'null diagnostics' },
      { diag: { connected_peers_count: 0, summary_reason: '0 peers connected on P2P port 3032' }, desc: '0 peers online' },
      { diag: { connected_peers_count: 2, summary_reason: null }, desc: 'connected peers but no summary' },
      { diag: { connected_peers_count: 1, summary_reason: 'Peer timed out after 5000ms' }, desc: 'timeout' },
    ];

    for (const perm of inFlightPermutations) {
      const citationsEl = new MockElement();
      citationsEl._queryInFlight = true;
      citationsEl._peerDiagnostics = perm.diag;
      citationsEl._retrievedRemoteCount = 0;
      citationsEl._contributingPeerIds = new Set();
      citationsEl._records = [];
      citationsEl._pendingCitations = [];

      refreshSourcesNodeIdRow(citationsEl, settings, false);

      const nodeRow = citationsEl.querySelector('.sources-node-id-row');
      assert(nodeRow, 'Node row must be created');
      assert(
        !nodeRow.innerHTML.includes('No data from remote peers'),
        `INVARIANT VIOLATION: In-flight query rendered 'No data from remote peers' banner under state: ${perm.desc}`
      );
      assert(
        !nodeRow.innerHTML.includes('sources-peer-diagnostic-row'),
        `INVARIANT VIOLATION: sources-peer-diagnostic-row rendered while in-flight: ${perm.desc}`
      );
    }
    console.log('✓ PASS: In-flight telemetry banner strictly suppressed across all permutations.');
  }

  // Test 2: In-Flight Guard with isGenerating = true
  {
    const citationsEl = new MockElement();
    citationsEl._queryInFlight = false; // even if flag wasn't set, isGenerating acts as secondary safety guard
    citationsEl._peerDiagnostics = { connected_peers_count: 0, summary_reason: '0 peers connected' };
    refreshSourcesNodeIdRow(citationsEl, settings, true);

    const nodeRow = citationsEl.querySelector('.sources-node-id-row');
    assert(
      !nodeRow.innerHTML.includes('No data from remote peers'),
      `INVARIANT VIOLATION: isGenerating=true must suppress diagnostic banner!`
    );
    console.log('✓ PASS: isGenerating flag correctly suppresses banner.');
  }

  // Test 3: Contributing Peer Badge Before Inline Citations
  // When RetrievalCompleted arrives, inline citations are NOT yet parsed or linked, but badge MUST render.
  {
    const citationsEl = new MockElement();
    citationsEl._queryInFlight = true; // still streaming tokens!
    citationsEl._retrievedRemoteCount = 2;
    citationsEl._contributingPeerIds = new Set(['12D3KooWPeerRemote1', '12D3KooWPeerRemote2']);
    citationsEl._pendingCitations = []; // NO citations yet!
    citationsEl._records = []; // NO records yet!

    refreshSourcesNodeIdRow(citationsEl, settings, true);

    const nodeRow = citationsEl.querySelector('.sources-node-id-row');
    assert(nodeRow.innerHTML.includes('sources-federated-tag'), 'Mesh federated tag badge must render');
    assert(nodeRow.innerHTML.includes('+ 2 Mesh Peers'), 'Must indicate 2 mesh peers');
    assert(nodeRow.innerHTML.includes('12D3KooWPe…'), 'Must format contributing peer chip');
    assert(!nodeRow.innerHTML.includes('No data from remote peers'), 'Must NOT render no-data banner');
    console.log('✓ PASS: Contributing peer badge renders immediately before inline citations.');
  }

  // Test 4: False "0 peers connected" Suppression
  // When query completes, if connected_peers_count > 0 and 0 chunks match, NEVER say "0 peers connected".
  {
    const citationsEl = new MockElement();
    citationsEl._queryInFlight = false;
    citationsEl._retrievedRemoteCount = 0;
    citationsEl._contributingPeerIds = new Set();
    citationsEl._peerDiagnostics = {
      connected_peers_count: 2,
      summary_reason: null, // missing summary reason
    };

    refreshSourcesNodeIdRow(citationsEl, settings, false);

    const nodeRow = citationsEl.querySelector('.sources-node-id-row');
    assert(
      nodeRow.innerHTML.includes('2 peers connected on P2P port 3032, but no matching chunks returned'),
      `Expected connected peers explanation, got: ${nodeRow.innerHTML}`
    );
    assert(
      !nodeRow.innerHTML.includes('0 peers connected'),
      'VIOLATION: Falsely reported 0 peers connected when 2 peers are connected!'
    );
    console.log('✓ PASS: Spurious "0 peers connected" fallback successfully prevented.');
  }

  // Test 5: False "0 peers connected" in summary_reason override
  // If summary_reason erroneously begins with "0 peers connected" while connected_peers_count == 3, UI overrides it.
  {
    const citationsEl = new MockElement();
    citationsEl._queryInFlight = false;
    citationsEl._retrievedRemoteCount = 0;
    citationsEl._peerDiagnostics = {
      connected_peers_count: 3,
      summary_reason: '0 peers connected on P2P port 3032 (no mDNS or bootstrap peers online)',
    };

    refreshSourcesNodeIdRow(citationsEl, settings, false);

    const nodeRow = citationsEl.querySelector('.sources-node-id-row');
    assert(
      nodeRow.innerHTML.includes('3 peers connected on P2P port 3032, but no matching chunks returned'),
      'Must override contradictory summary_reason'
    );
    assert(!nodeRow.innerHTML.includes('0 peers connected'), 'Must strip 0 peers');
    console.log('✓ PASS: Contradictory summary_reason overridden cleanly.');
  }

  // Test 6: Answer Finished with Remote Chunks
  // When query finished and retrieved remote chunks exist, banner MUST NOT render even with 0 inline citations.
  {
    const citationsEl = new MockElement();
    citationsEl._queryInFlight = false;
    citationsEl._retrievedRemoteCount = 1;
    citationsEl._contributingPeerIds = new Set(['12D3KooWPeerRemote1']);
    citationsEl._records = [];
    citationsEl._pendingCitations = [];

    refreshSourcesNodeIdRow(citationsEl, settings, false);

    const nodeRow = citationsEl.querySelector('.sources-node-id-row');
    assert(
      !nodeRow.innerHTML.includes('No data from remote peers'),
      'Must not render no data banner when remote chunks matched'
    );
    assert(nodeRow.innerHTML.includes('+ 1 Mesh Peer'), 'Must show 1 mesh peer badge');
    console.log('✓ PASS: Remote chunks prevent no-data banner after query completion.');
  }

  console.log('--- ALL ADVERSARIAL UI TELEMETRY TESTS PASSED ---');
}

runAdversarialTests();
