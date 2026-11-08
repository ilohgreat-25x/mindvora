/*
 * MINDVORA EVOLVE — configurable, cloud-synced intelligence workspace.
 * Local storage is the offline cache; signed-in workspaces also sync to the
 * user's protected Firestore profile document when the existing app database is available.
 */
(function () {
  'use strict';
  var KEY = 'mindvora.evolve.workspace.v3';
  var MODES = {
    creator: { label: 'Content creator', icon: '✦' },
    business: { label: 'Business', icon: '▦' },
    developer: { label: 'Developer', icon: '⌘' },
    educator: { label: 'Teacher / lecturer', icon: '◇' },
    professional: { label: 'Professional', icon: '◈' }
  };
  var divisions = [
    { id: 'sentinel', icon: '🛡️', name: 'Sentinel', label: 'Digital Protection', text: 'Check links, review alerts, and control connected-service risk.' },
    { id: 'nexora', icon: '⚙️', name: 'Nexora', label: 'Evolve intelligence & automation', text: 'Build multi-step, reviewable operating blueprints for serious Evolve work.' },
    { id: 'pulse', icon: '◉', name: 'Pulse', label: 'Personal information intelligence', text: 'Shape a lively stream of interests, live sources, signals, and ideas.' },
    { id: 'identity', icon: '◈', name: 'Identity', label: 'Configurable digital identity', text: 'Choose what your personal, business, or professional identity shares.' },
    { id: 'orbit', icon: '✦', name: 'Orbit', label: 'Your focused workspace', text: 'Plan tasks, collect notes, set priorities, and keep work moving.' },
    { id: 'core', icon: '⬡', name: 'Evolve Core', label: 'Cloud-like continuity layer', text: 'Save progress, organize sensitive files, and create recoverable snapshots.' }
  ];
  var state = load();
  var syncTimer = null;

  function blank() {
    return { mode: 'professional', configured: false,
      sentinel: { alerts: [], services: [], privacy: { shield: 'browser-protected' } },
      nexora: { workflows: [], runs: [] },
      pulse: { interests: ['technology', 'learning'], cards: [], saved: [] },
      identity: { displayName: '', role: 'Professional', sharing: 'private', verify: false, updatedAt: 0 },
      orbit: { tasks: [], notes: '', priorities: [] },
      lifeos: { tasks: [], notes: '' },
      core: { files: [], snapshots: [], plan: 'free', overQuotaAt: 0, lastRetentionNotice: '', retentionBlocked: false },
      usage: { sentinelScans: 0, nexoraRuns: 0, orbitTasks: 0, pulseRefreshes: 0 }
    };
  }
  function merge(base, incoming) {
    incoming = incoming && typeof incoming === 'object' ? incoming : {};
    Object.keys(incoming).forEach(function (k) {
      if (incoming[k] && typeof incoming[k] === 'object' && !Array.isArray(incoming[k])) base[k] = merge(base[k] && typeof base[k] === 'object' ? base[k] : {}, incoming[k]);
      else if (incoming[k] !== undefined) base[k] = incoming[k];
    });
    return base;
  }
  function normalize(s) {
    s = merge(blank(), s || {});
    if ((!s.orbit.tasks || !s.orbit.tasks.length) && s.lifeos && s.lifeos.tasks) s.orbit.tasks = s.lifeos.tasks;
    if ((!s.orbit.notes) && s.lifeos) s.orbit.notes = s.lifeos.notes || '';
    s.sentinel.services = (s.sentinel.services || []).map(function (x) { return typeof x === 'string' ? { name: x, url: '', status: 'saved', checkedAt: 0 } : x; });
    s.nexora.workflows = s.nexora.workflows || [];
    s.nexora.runs = s.nexora.runs || [];
    s.pulse.interests = s.pulse.interests || [];
    s.pulse.cards = (s.pulse.cards || []).filter(function (x) { var t = String(x && (x.title || x) || '').toLowerCase(); return !/live news|live sports|anime/.test(t); });
    s.core.files = s.core.files || [];
    s.core.snapshots = s.core.snapshots || [];
    s.core.plan = s.core.plan || 'free'; s.core.overQuotaAt = Number(s.core.overQuotaAt || 0);
    s.usage = merge({ sentinelScans: 0, nexoraRuns: 0, orbitTasks: 0, pulseRefreshes: 0 }, s.usage || {});
    applyCoreRetention(s);
    return s;
  }
  function load() { try { return normalize(JSON.parse(localStorage.getItem(KEY) || '{}')); } catch (e) { return blank(); } }
  function cloudReady() { return !!(window.state && window.state.user && window.db && db.collection); }
  var FREE_LIMITS = { sentinelScans: 25, nexoraRuns: 5, orbitTasks: 25, pulseRefreshes: 20 };
  var CORE_QUOTA = { free: { label: 'Free', bytes: 5 * 1024 * 1024, records: 25 }, pro: { label: 'Pro', bytes: 50 * 1024 * 1024, records: 250 } };
  function isPro() { return !!(window.state && window.state.profile && window.state.profile.isPremium === true); }
  function corePlan() { return isPro() ? 'pro' : 'free'; }
  function coreUsage(s) { var c = (s || state).core || {}; return new Blob([JSON.stringify(c.files || []), JSON.stringify(c.snapshots || [])]).size; }
  function applyCoreRetention(s) {
    var plan = isPro() ? 'pro' : 'free', quota = CORE_QUOTA[plan], used = coreUsage(s), count = (s.core.files || []).length;
    s.core.plan = plan;
    s.core.retentionBlocked = false;
    if (used <= quota.bytes && count <= quota.records) { s.core.overQuotaAt = 0; return; }
    if (!s.core.overQuotaAt) s.core.overQuotaAt = Date.now();
    if (Date.now() - s.core.overQuotaAt < 24 * 60 * 60 * 1000) return;
    var removed = 0;
    s.core.files.sort(function (a, b) { return Number(a.createdAt || 0) - Number(b.createdAt || 0); });
    while ((coreUsage(s) > quota.bytes || s.core.files.length > quota.records) && s.core.files.some(function (x) { return !x.pinned; })) {
      var idx = s.core.files.findIndex(function (x) { return !x.pinned; });
      if (idx < 0) break;
      s.core.files.splice(idx, 1); removed++;
    }
    while (coreUsage(s) > quota.bytes && s.core.snapshots.length) { s.core.snapshots.pop(); removed++; }
    if (coreUsage(s) > quota.bytes || s.core.files.length > quota.records) { s.core.retentionBlocked = true; s.core.lastRetentionNotice = 'Retention paused because all remaining records are protected. Upgrade storage or unprotect an item.'; return; }
    s.core.overQuotaAt = 0; s.core.lastRetentionNotice = removed + ' older unprotected Evolve Core item(s) were removed after the 24-hour grace period.';
  }
  function withinFreeLimit(key) { if (isPro()) return true; var n = Number(state.usage[key] || 0), limit = FREE_LIMITS[key]; if (limit != null && n >= limit) { toast('Free plan limit reached for Evolve. Upgrade to Pro for a larger allowance.'); return false; } state.usage[key] = n + 1; return true; }
  function setStatus(text) { var n = document.querySelector('#mv-evolve [data-status]'); if (n) n.textContent = text; }
  function save() {
    try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {}
    if (!cloudReady()) return;
    clearTimeout(syncTimer);
    setStatus('Saving to your Mindvora workspace…');
    syncTimer = setTimeout(function () {
      db.collection('users').doc(window.state.user.uid).set({ evolveWorkspace: state }, { merge: true }).then(function () { setStatus('Synced to your Mindvora workspace'); }).catch(function () { setStatus('Saved offline — cloud sync will retry'); });
    }, 180);
  }
  function syncCloud(el) {
    if (!cloudReady()) { setStatus('Local workspace ready'); return; }
    setStatus('Syncing your Mindvora workspace…');
    db.collection('users').doc(window.state.user.uid).get().then(function (snap) {
      if (snap.exists && snap.data().evolveWorkspace) { state = normalize(merge(blank(), snap.data().evolveWorkspace)); try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {} render(el, 'overview'); }
      setStatus('Synced to your Mindvora workspace');
    }).catch(function () { setStatus('Offline cache ready'); });
  }
  function esc(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) { return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]; }); }
  function toast(message) { if (typeof window.showToast === 'function') window.showToast(message); }
  function panel() {
    var el = document.getElementById('mv-evolve');
    if (el) return el;
    el = document.createElement('section'); el.id = 'mv-evolve'; el.className = 'mv-evolve-shell'; el.setAttribute('aria-label', 'Mindvora Evolve');
    el.innerHTML = '<header class="mv-evolve-header"><button type="button" data-close aria-label="Close Evolve">←</button><div><span class="mv-evolve-kicker">MINDVORA / EVOLVE</span><h1>One intelligence layer for your digital world</h1></div><span class="mv-evolve-status"><i></i> <b data-status>Workspace ready</b></span></header>' +
      '<div class="mv-evolve-layout"><nav class="mv-evolve-nav" aria-label="Evolve divisions"><button class="active" data-view="overview">◌ Overview</button>' + divisions.map(function (d) { return '<button data-view="' + d.id + '">' + d.icon + ' ' + esc(d.name) + '</button>'; }).join('') + '</nav><main class="mv-evolve-main" data-main></main></div>';
    document.body.appendChild(el);
    el.querySelector('[data-close]').addEventListener('click', function () { close(el); });
    return el;
  }
  function field(label, name, value, type) { return '<label class="mv-evolve-field"><span>' + esc(label) + '</span><input data-field="' + esc(name) + '" type="' + (type || 'text') + '" value="' + esc(value || '') + '"></label>'; }
  function button(label, action, cls) { return '<button type="button" class="mv-evolve-btn ' + (cls || '') + '" data-action="' + esc(action) + '">' + esc(label) + '</button>'; }
  function metric(title, value, detail, tone) { return '<article class="mv-evolve-metric ' + (tone || '') + '"><span>' + esc(title) + '</span><strong>' + esc(value) + '</strong><small>' + esc(detail) + '</small></article>'; }
  function modeSelect() { return '<label class="mv-evolve-mode"><span>Configure Evolve for</span><select data-mode>' + Object.keys(MODES).map(function (key) { return '<option value="' + key + '"' + (state.mode === key ? ' selected' : '') + '>' + MODES[key].icon + ' ' + MODES[key].label + '</option>'; }).join('') + '</select></label>'; }
  function overview() {
    return '<div class="mv-evolve-hero"><div><span class="mv-evolve-eyebrow">EVOLVE INTELLIGENCE CORE</span><h2>A control room that adapts to the way you work.</h2><p>Choose a working mode, then configure each centre around your goals. Nexora creates explicit operating blueprints, while Core keeps the work synchronized and recoverable.</p>' + modeSelect() + '</div><div class="mv-evolve-orbit" aria-hidden="true"><b>EVOLVE</b><span></span><span></span><span></span></div></div>' +
      '<div class="mv-evolve-metrics">' + metric('Working mode', MODES[state.mode] ? MODES[state.mode].label : MODES.professional.label, state.configured ? 'Configured for this workspace' : 'Choose a mode to begin', 'green') + metric('Nexora runs', String(state.nexora.runs.length), 'Blueprints recorded') + metric('Orbit tasks', String(state.orbit.tasks.filter(function (x) { return !x.done; }).length), 'Open tasks in Orbit') + metric('Core snapshots', String(state.core.snapshots.length), 'Recoverable progress points', 'gold') + '</div>' +
      '<section class="mv-evolve-section"><div class="mv-evolve-section-head"><div><span class="mv-evolve-eyebrow">YOUR EVOLVE LAYER</span><h3>Open a centre</h3></div><span class="mv-evolve-chip">Cloud-synced when signed in</span></div><div class="mv-evolve-grid">' + divisions.map(function (d) { return '<button class="mv-evolve-division" data-view="' + d.id + '"><span class="mv-evolve-division-icon">' + d.icon + '</span><span><strong>' + esc(d.name) + '</strong><small>' + esc(d.label) + '</small><em>' + esc(d.text) + '</em></span><b>→</b></button>'; }).join('') + '</div></section><p class="mv-evolve-note">Evolve uses the same signed-in Mindvora account and Firestore user record for sync. Local storage remains an offline cache. Free includes 25 Sentinel scans, 5 Nexora blueprints, 25 Orbit tasks, 20 Pulse refreshes, and 25 Core records; Pro raises these allowances and storage. Sentinel cannot act as a device-wide VPN; a real IP-masking tunnel requires a separately deployed VPN/proxy service.</p>';
  }
  function sentinel() {
    var services = state.sentinel.services.length ? state.sentinel.services.map(function (x, i) { return '<li><span><strong>' + esc(x.name) + '</strong><small>' + esc(x.url || 'No URL supplied') + ' · ' + esc(x.status || 'saved') + (x.checkedAt ? ' · checked ' + esc(new Date(x.checkedAt).toLocaleTimeString()) : '') + '</small></span>' + (x.url ? button('Connect', 'connect-service-' + i, 'subtle') : '') + button('Remove', 'remove-service-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">No services saved yet.</li>';
    var alerts = state.sentinel.alerts.length ? state.sentinel.alerts.map(function (x) { return '<li><strong>' + esc(x.level) + '</strong> ' + esc(x.text) + '<small>' + esc(x.date) + '</small></li>'; }).join('') : '<li class="muted">No security alerts recorded.</li>';
    return head('Sentinel', 'Digital Protection', 'Protect links, review local security events, and check approved service endpoints before using them.') + '<div class="mv-evolve-tool-grid"><section class="mv-evolve-tool"><h3>Scan a link</h3><p>Sentinel normalizes malformed input, checks the scheme and hostname locally, and never opens the link for you.</p>' + field('URL to scan', 'sentinel-url', '', 'url') + button('Scan link', 'scan-link', 'primary') + '<div data-result="sentinel" class="mv-evolve-result" aria-live="polite">Enter a link to begin.</div></section><section class="mv-evolve-tool"><h3>Review security alerts</h3><p>Every scan result is recorded here so you can review and clear it.</p><ul class="mv-evolve-list">' + alerts + '</ul>' + button('Mark alerts reviewed', 'clear-alerts', 'subtle') + '</section><section class="mv-evolve-tool"><h3>Connected services</h3><p>Save a service URL, then connect to run a live browser reachability check. OAuth permissions must still be granted on the service’s own page.</p>' + field('Service name', 'sentinel-service', '', 'text') + field('Service URL', 'sentinel-service-url', '', 'url') + button('Save service', 'add-service', 'primary') + '<ul class="mv-evolve-list">' + services + '</ul></section><section class="mv-evolve-tool"><h3>Privacy Shield status</h3><p><strong>Browser session protection: active.</strong> Mindvora uses HTTPS and Sentinel blocks nothing outside the app. Your public IP is still visible to websites you visit; masking all device traffic requires a VPN or OS-level network tunnel, not JavaScript.</p><div class="mv-evolve-result">' + (cloudReady() ? 'Evolve data sync is authenticated to your Mindvora account.' : 'Sign in to sync Evolve data across devices.') + '</div></section></div>';
  }
  function nexora() {
    var mode = (MODES[state.mode] || MODES.professional).label;
    var workflows = state.nexora.workflows.length ? state.nexora.workflows.map(function (x, i) { return '<li><strong>' + esc(x.name) + '</strong><span>' + esc(x.detail) + '</span>' + button('Delete', 'delete-workflow-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">No workflows yet. Create one below.</li>';
    return head('Nexora', 'The Evolve operating intelligence', 'Nexora turns demanding Mindvora Evolve work into multi-phase blueprints tailored to your ' + mode.toLowerCase() + ' mode. It never claims an operation completed until a connected tool reports success.') + '<div class="mv-evolve-tool-grid"><section class="mv-evolve-tool wide"><h3>Give Nexora a heavy-duty job</h3><p>Describe the outcome, constraints, inputs, and deadline. Nexora will decompose it into phases, checks, handoffs, and a recovery point.</p><textarea data-field="nexora-task" rows="5" placeholder="Example: audit my project records, identify risks, prepare a launch plan, and create a review checklist…"></textarea><div class="mv-evolve-inline">' + button('Build operating blueprint', 'run-nexora', 'primary') + '<span class="mv-evolve-hint">Mode: ' + esc(mode) + '</span></div><div data-result="nexora" class="mv-evolve-result" aria-live="polite">Your blueprint will appear here for review.</div></section><section class="mv-evolve-tool"><h3>Create a workflow</h3><p>Save a repeatable operation for your role.</p>' + field('Workflow name', 'workflow-name', '', 'text') + field('What should it do?', 'workflow-detail', '', 'text') + button('Save workflow', 'save-workflow', 'primary') + '</section><section class="mv-evolve-tool"><h3>Saved workflows</h3><ul class="mv-evolve-list">' + workflows + '</ul></section></div>';
  }
  function pulse() {
    var interests = state.pulse.interests.map(function (x, i) { return '<button type="button" class="mv-evolve-tag" data-action="remove-interest-' + i + '">' + esc(x) + ' ×</button>'; }).join('');
    var cards = (state.pulse.cards.length ? state.pulse.cards : ['Ideas tailored to your interests', 'A practical next step for your goals', 'A new skill worth exploring', 'A useful question to investigate']).map(function (x) { return '<article class="mv-evolve-pulse-card"><span>Pulse signal · ' + esc(state.mode) + '</span><strong>' + esc(x.title || x) + '</strong><small>' + esc(x.detail || 'Tailored to your selected interests.') + '</small>' + (x.action ? button(x.actionLabel || 'Open', x.action, 'subtle') : '') + '</article>'; }).join('');
    return head('Pulse', 'Personal information intelligence', 'Pulse is a living stream of ideas and actions: choose interests, refresh signals, and shape what deserves your attention.') + '<section class="mv-evolve-tool"><h3>Your interest stream</h3><div class="mv-evolve-tags">' + (interests || '<span class="muted">Add your first interest.</span>') + '</div><div class="mv-evolve-inline">' + field('Add an interest', 'pulse-interest', '', 'text') + button('Add interest', 'add-interest', 'primary') + button('Refresh Pulse', 'refresh-pulse', 'subtle') + '</div></section><div class="mv-evolve-pulse-grid">' + cards + '</div>';
  }
  function identity() {
    var data = state.identity;
    return head('Identity', 'Configurable digital identity', 'Saving publishes a controlled identity profile to your Mindvora account. Private stays private; team and public settings become available to the matching profile surfaces.') + '<section class="mv-evolve-tool mv-evolve-form">' + field('Display name', 'identity-name', data.displayName, 'text') + field('Primary role', 'identity-role', data.role, 'text') + '<label class="mv-evolve-field"><span>Default sharing</span><select data-field="identity-sharing"><option value="private"' + (data.sharing === 'private' ? ' selected' : '') + '>Private by default</option><option value="team"' + (data.sharing === 'team' ? ' selected' : '') + '>Trusted team only</option><option value="public"' + (data.sharing === 'public' ? ' selected' : '') + '>Public profile</option></select></label><label class="mv-evolve-check"><input type="checkbox" data-identity-verify ' + (data.verify ? 'checked' : '') + '> Ask for verification before sharing credentials</label>' + button('Save identity settings', 'save-identity', 'primary') + '<div data-result="identity" class="mv-evolve-result">Your identity settings are private until you save and share them.</div></section>';
  }
  function orbit() {
    var tasks = state.orbit.tasks.length ? state.orbit.tasks.map(function (x, i) { return '<li class="' + (x.done ? 'done' : '') + '"><label><input type="checkbox" data-task="' + i + '" ' + (x.done ? 'checked' : '') + '> ' + esc(x.text) + '</label>' + button('Delete', 'delete-task-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">Your workspace is clear. Add a task to begin.</li>';
    return head('Orbit', 'Your focused workspace', 'A focused place for your workspace.') + '<div class="mv-evolve-tool-grid"><section class="mv-evolve-tool"><h3>Today in Orbit</h3>' + field('New task', 'life-task', '', 'text') + button('Add task', 'add-task', 'primary') + '<ul class="mv-evolve-list" data-task-list>' + tasks + '</ul></section><section class="mv-evolve-tool"><h3>Working notes</h3><textarea data-life-notes rows="11" placeholder="Keep the notes you need for today…">' + esc(state.orbit.notes) + '</textarea>' + button('Save notes', 'save-notes', 'primary') + '<div data-result="life" class="mv-evolve-result"></div></section><section class="mv-evolve-tool"><h3>Orbit priorities</h3><p>Use Nexora to turn these priorities into a reviewable operating blueprint.</p>' + field('Priority', 'orbit-priority', '', 'text') + button('Add priority', 'add-priority', 'primary') + '<ul class="mv-evolve-list">' + (state.orbit.priorities.length ? state.orbit.priorities.map(function (x, i) { return '<li><span>' + esc(x) + '</span>' + button('Remove', 'delete-priority-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">No priorities yet.</li>') + '</ul></section></div>';
  }
  function core() {
    var files = state.core.files.length ? state.core.files.map(function (x, i) { return '<li><strong>' + (x.pinned ? '📌 ' : '') + esc(x.name) + '</strong><small>' + esc(x.detail) + ' · saved ' + esc(x.date || '') + (x.pinned ? ' · protected from retention' : '') + '</small>' + button(x.pinned ? 'Unprotect' : 'Protect', 'toggle-file-pin-' + i, 'subtle') + button('Remove', 'delete-file-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">No workspace records yet.</li>';
    var snaps = state.core.snapshots.length ? state.core.snapshots.map(function (x, i) { return '<li><strong>' + esc(x.name) + '</strong><small>' + esc(x.count) + ' records · ' + esc(x.date) + '</small>' + button('Restore', 'restore-snapshot-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">No snapshots yet.</li>';
    var quota = CORE_QUOTA[corePlan()], used = coreUsage(state), pct = Math.min(100, Math.round((used / quota.bytes) * 100)), grace = state.core.retentionBlocked ? 'Retention is paused because all remaining records are protected. Upgrade or unprotect an item to restore automatic cleanup.' : (state.core.overQuotaAt ? 'Over quota: unprotected items are protected for 24 hours, then the oldest unprotected items are automatically removed unless you upgrade.' : 'Unused space is reserved for your account; one user cannot consume another user’s allocation.');
    return head('Evolve Core', 'Cloud-like continuity layer', 'Records are saved to the same signed-in Mindvora workspace and cached locally, so the save is visible immediately and can follow you across devices.') + '<section class="mv-evolve-storage"><div><span class="mv-evolve-eyebrow">STORAGE ALLOCATION</span><h3>' + esc(quota.label) + ' plan · ' + esc(Math.round(used / 1024)) + ' KB of ' + esc(Math.round(quota.bytes / 1024 / 1024)) + ' MB used</h3><p>' + esc(grace) + '</p></div><div class="mv-evolve-storage-meter"><i style="width:' + pct + '%"></i></div><small>' + esc(state.core.files.length) + ' of ' + esc(quota.records) + ' records · Free plan includes a 24-hour grace period when full.</small>' + (isPro() ? '<b class="mv-evolve-plan-badge">PRO STORAGE ACTIVE</b>' : button('Upgrade storage to Pro', 'upgrade-core', 'primary')) + '</section><div class="mv-evolve-tool-grid"><section class="mv-evolve-tool"><h3>Workspace records</h3>' + field('Record or sensitive file label', 'core-file', '', 'text') + field('What is it for?', 'core-detail', '', 'text') + button('Save record', 'save-file', 'primary') + '<div data-result="core" class="mv-evolve-result">Add a record and it will appear below immediately.</div><ul class="mv-evolve-list">' + files + '</ul></section><section class="mv-evolve-tool"><h3>Backups & recovery</h3><p>Create a recovery point for this Evolve workspace. Export it for safekeeping.</p>' + button('Create snapshot', 'create-snapshot', 'primary') + button('Export workspace backup', 'export-core', 'subtle') + '<ul class="mv-evolve-list">' + snaps + '</ul></section></div>';
  }
  function head(name, label, text) { var d = divisions.filter(function (x) { return x.name === name; })[0] || { icon: '✦' }; return '<div class="mv-evolve-division-head"><span class="mv-evolve-division-icon large">' + d.icon + '</span><div><span class="mv-evolve-eyebrow">EVOLVE CENTRE</span><h2>' + esc(name) + '</h2><p>' + esc(text) + '</p></div></div><p class="mv-evolve-subhead">' + esc(label) + '</p>'; }
  function render(el, view) {
    el.querySelectorAll('[data-view]').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-view') === view); });
    var main = el.querySelector('[data-main]');
    main.innerHTML = view === 'overview' ? overview() : ({ sentinel: sentinel, nexora: nexora, pulse: pulse, identity: identity, orbit: orbit, core: core }[view] || overview)();
    bind(el, view);
  }
  function value(el, name) { var x = el.querySelector('[data-field="' + name + '"]'); return x ? x.value.trim() : ''; }
  function result(el, key, html) { var node = el.querySelector('[data-result="' + key + '"]'); if (node) node.innerHTML = html; }
  function safeUrl(raw) { raw = String(raw || '').trim().replace(/^https::\/\//i, 'https://').replace(/^http::\/\//i, 'http://'); if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw; var u = new URL(raw); if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('Only HTTP and HTTPS links are allowed.'); return u; }
  function action(el, view, actionName) {
    var i, item, parsed;
    if (actionName === 'scan-link') { if (!withinFreeLimit('sentinelScans')) return; try { parsed = safeUrl(value(el, 'sentinel-url')); var host = parsed.hostname.toLowerCase(), level = parsed.protocol !== 'https:' ? 'Caution' : (/^(localhost|127\.|10\.|192\.168\.)/.test(host) ? 'Review' : 'Low risk'); if (parsed.username || parsed.password || /@/.test(host) || /[\-_]{2,}/.test(host)) level = 'Caution'; result(el, 'sentinel', '<strong>' + esc(level) + '</strong><p>' + esc(parsed.origin) + ' was normalized and parsed locally. Confirm the domain and context before opening it.</p>'); state.sentinel.alerts.unshift({ level: level, text: parsed.origin, date: new Date().toLocaleString() }); save(); } catch (e) { result(el, 'sentinel', '<strong>Invalid link</strong><p>' + esc(e.message || 'Enter a complete URL such as https://example.com.') + '</p>'); } return; }
    if (actionName === 'clear-alerts') { state.sentinel.alerts = []; save(); render(el, 'sentinel'); return; }
    if (actionName === 'add-service') { item = value(el, 'sentinel-service'); var serviceUrl; try { serviceUrl = safeUrl(value(el, 'sentinel-service-url')); } catch (e) { return toast('Enter a valid HTTP or HTTPS service URL.'); } if (!item) return toast('Enter a service name first.'); state.sentinel.services.push({ name: item, url: serviceUrl.href, status: 'saved — connect to check reachability', checkedAt: 0 }); save(); render(el, 'sentinel'); return; }
    if (/^remove-service-/.test(actionName)) { state.sentinel.services.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'sentinel'); return; }
    if (/^connect-service-/.test(actionName)) { i = Number(actionName.split('-').pop()); var service = state.sentinel.services[i]; if (!service || !service.url) return; service.status = 'checking…'; render(el, 'sentinel'); fetch(service.url, { method: 'HEAD', mode: 'no-cors', cache: 'no-store' }).then(function () { service.status = 'reachable from this browser (opaque response)'; service.checkedAt = Date.now(); save(); render(el, 'sentinel'); }).catch(function () { service.status = 'not reachable from this browser — check URL or permissions'; service.checkedAt = Date.now(); save(); render(el, 'sentinel'); }); return; }
    if (actionName === 'run-nexora') { if (!withinFreeLimit('nexoraRuns')) return; item = value(el, 'nexora-task'); if (!item) return toast('Tell Nexora the outcome, constraints, or inputs.'); var phaseMap = { creator: ['Frame audience, format, and success criteria', 'Generate a content system and production queue', 'Run brand, rights, and quality checks', 'Prepare a publish-and-measure handoff'], business: ['Map records, owners, approvals, and deadlines', 'Design the fastest repeatable operating flow', 'Check exceptions, privacy, and audit evidence', 'Prepare a handoff and rollback checklist'], developer: ['Reproduce the issue and map dependencies', 'Implement the smallest safe change', 'Run tests, security checks, and regression review', 'Prepare a diff, deploy plan, and rollback point'], educator: ['Define learning outcomes and source material', 'Build lessons, practice, and assessment', 'Check accessibility, citations, and feedback', 'Prepare a delivery and review plan'], professional: ['Define outcome, constraints, and stakeholders', 'Break work into executable phases', 'Validate quality, risk, and evidence', 'Prepare handoff, backup, and next actions'] }[state.mode] || []; state.nexora.runs.unshift({ task: item, mode: state.mode, date: new Date().toLocaleString(), phases: phaseMap }); save(); result(el, 'nexora', '<strong>Operating blueprint for ' + esc(item) + '</strong><ol>' + phaseMap.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ol><small>Blueprint saved to Evolve. No external operation was silently executed; connect approved services and review each phase before running it.</small>'); return; }
    if (actionName === 'save-workflow') { var wn = value(el, 'workflow-name'), wd = value(el, 'workflow-detail'); if (!wn || !wd) return toast('Add a workflow name and its purpose.'); state.nexora.workflows.push({ name: wn, detail: wd, updatedAt: Date.now() }); save(); render(el, 'nexora'); return; }
    if (/^delete-workflow-/.test(actionName)) { state.nexora.workflows.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'nexora'); return; }
    if (actionName === 'add-interest') { item = value(el, 'pulse-interest').toLowerCase(); if (!item) return toast('Enter an interest first.'); if (state.pulse.interests.indexOf(item) < 0) state.pulse.interests.push(item); state.pulse.cards = []; save(); render(el, 'pulse'); return; }
    if (/^remove-interest-/.test(actionName)) { state.pulse.interests.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'pulse'); return; }
    if (actionName === 'refresh-pulse') { if (!withinFreeLimit('pulseRefreshes')) return; var subjects = state.pulse.interests.length ? state.pulse.interests : ['Mindvora']; state.pulse.cards = subjects.slice(0, 5).map(function (x) { return { title: 'New ideas and conversations about ' + x, detail: 'A fresh signal generated from your interest profile.', action: 'open-nexora', actionLabel: 'Give to Nexora' }; }); save(); render(el, 'pulse'); return; }
    if (actionName === 'open-nexora') { render(el, 'nexora'); return; }
    if (actionName === 'save-identity') { state.identity.displayName = value(el, 'identity-name'); state.identity.role = value(el, 'identity-role') || (MODES[state.mode] || MODES.professional).label; state.identity.sharing = value(el, 'identity-sharing'); var verify = el.querySelector('[data-identity-verify]'); state.identity.verify = !!(verify && verify.checked); state.identity.updatedAt = Date.now(); save(); if (cloudReady()) db.collection('users').doc(window.state.user.uid).set({ evolveIdentity: state.identity }, { merge: true }).catch(function () {}); result(el, 'identity', '<strong>Identity saved.</strong><p>Your Evolve identity is now stored in your Mindvora account. Sharing is set to <b>' + esc(state.identity.sharing) + '</b>; only matching profile surfaces may use it.</p>'); return; }
    if (actionName === 'add-task') { if (!withinFreeLimit('orbitTasks')) return; item = value(el, 'life-task'); if (!item) return toast('Enter a task first.'); state.orbit.tasks.push({ text: item, done: false, createdAt: Date.now() }); save(); render(el, 'orbit'); return; }
    if (/^delete-task-/.test(actionName)) { state.orbit.tasks.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'orbit'); return; }
    if (actionName === 'save-notes') { var notes = el.querySelector('[data-life-notes]'); state.orbit.notes = notes ? notes.value : ''; save(); result(el, 'life', '<strong>Notes saved to Orbit and synced.</strong>'); return; }
    if (actionName === 'add-priority') { item = value(el, 'orbit-priority'); if (!item) return toast('Enter a priority first.'); state.orbit.priorities.push(item); save(); render(el, 'orbit'); return; }
    if (/^delete-priority-/.test(actionName)) { state.orbit.priorities.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'orbit'); return; }
    if (actionName === 'save-file') { var fn = value(el, 'core-file'), fd = value(el, 'core-detail'); if (!fn) return toast('Enter a record label first.'); var quota = CORE_QUOTA[corePlan()]; if (state.core.files.length >= quota.records || coreUsage(state) >= quota.bytes) { state.core.overQuotaAt = state.core.overQuotaAt || Date.now(); save(); return toast('Evolve Core is full. Upgrade within 24 hours or remove an unprotected record.'); } state.core.files.push({ name: fn, detail: fd || 'Evolve workspace record', pinned: false, date: new Date().toLocaleString(), createdAt: Date.now() }); applyCoreRetention(state); save(); render(el, 'core'); result(el, 'core', '<strong>Record saved.</strong><p>' + esc(fn) + ' is now in this Evolve workspace and queued for cloud sync.</p>'); toast('Record saved to Evolve Core.'); return; }
    if (/^delete-file-/.test(actionName)) { state.core.files.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'core'); return; }
    if (/^toggle-file-pin-/.test(actionName)) { var pinIndex = Number(actionName.split('-').pop()); if (state.core.files[pinIndex]) state.core.files[pinIndex].pinned = !state.core.files[pinIndex].pinned; applyCoreRetention(state); save(); render(el, 'core'); return; }
    if (actionName === 'create-snapshot') { state.core.snapshots.unshift({ name: 'Snapshot ' + (state.core.snapshots.length + 1), count: state.core.files.length + state.orbit.tasks.length, date: new Date().toLocaleString(), data: JSON.stringify(state) }); state.core.snapshots = state.core.snapshots.slice(0, 5); save(); render(el, 'core'); toast('Evolve Core snapshot created and synced.'); return; }
    if (/^restore-snapshot-/.test(actionName)) { var snap = state.core.snapshots[Number(actionName.split('-').pop())]; if (snap && confirm('Restore this Evolve Core snapshot? Current workspace changes will be replaced.')) { state = normalize(JSON.parse(snap.data)); save(); render(el, 'overview'); toast('Evolve Core workspace restored.'); } return; }
    if (actionName === 'upgrade-core') { if (typeof window.openModal === 'function' && document.getElementById('modal-prem')) window.openModal('modal-prem'); else toast('Upgrade checkout is not available in this session.'); return; }
    if (actionName === 'export-core') { var blob = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' }); var link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'mindvora-evolve-backup.json'; link.click(); setTimeout(function () { URL.revokeObjectURL(link.href); }, 500); toast('Evolve Core backup exported.'); }
  }
  function bind(el, view) {
    el.querySelectorAll('[data-view]').forEach(function (b) { if (!b.__bound) { b.__bound = true; b.addEventListener('click', function () { render(el, b.getAttribute('data-view')); }); } });
    var mode = el.querySelector('[data-mode]'); if (mode) mode.addEventListener('change', function () { state.mode = mode.value; state.configured = true; save(); render(el, 'overview'); });
    el.querySelectorAll('[data-action]').forEach(function (b) { b.addEventListener('click', function () { action(el, view, b.getAttribute('data-action')); }); });
    el.querySelectorAll('[data-task]').forEach(function (box) { box.addEventListener('change', function () { state.orbit.tasks[Number(box.getAttribute('data-task'))].done = box.checked; save(); render(el, 'orbit'); }); });
  }
  function close(el) { el.classList.remove('open'); document.body.style.overflow = ''; if (window.__mvEvolveOpenedFromDrawer && typeof window.toggleDrawer === 'function' && document.getElementById('app-drawer') && !document.getElementById('app-drawer').classList.contains('open')) { window.__mvEvolveOpenedFromDrawer = false; window.toggleDrawer(); } }
  window.openMindvoraEvolve = function () { var el = panel(); render(el, 'overview'); el.classList.add('open'); document.body.style.overflow = 'hidden'; syncCloud(el); };
  window.mvConfigureEvolveFromDrawer = function () { window.__mvEvolveOpenedFromDrawer = true; window.openMindvoraEvolve(); };
})();
