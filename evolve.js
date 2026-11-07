/*
 * MINDVORA EVOLVE — configurable intelligence workspace
 * The feature stays self-contained and stores its local workspace state safely in localStorage.
 * Backend-connected actions can be added later without changing the division contracts.
 */
(function () {
  'use strict';
  var KEY = 'mindvora.evolve.workspace.v2';
  var MODES = {
    creator: { label: 'Content creator', icon: '✦' },
    business: { label: 'Business', icon: '▦' },
    developer: { label: 'Developer', icon: '⌘' },
    educator: { label: 'Teacher / lecturer', icon: '◇' },
    professional: { label: 'Professional', icon: '◈' }
  };
  var divisions = [
    { id: 'sentinel', icon: '🛡️', name: 'Sentinel', label: 'Digital Protection', text: 'Check links, review alerts, and control connected-service risk.' },
    { id: 'nexora', icon: '⚙️', name: 'Nexora', label: 'Evolve intelligence & automation', text: 'The configurable Evolve operator for content, office, code, and professional workflows.' },
    { id: 'pulse', icon: '◉', name: 'Pulse', label: 'Personal information intelligence', text: 'Shape an interest-driven stream of useful topics, trends, and opportunities.' },
    { id: 'identity', icon: '◈', name: 'Identity', label: 'Configurable digital identity', text: 'Choose what your personal, business, or professional identity shares.' },
    { id: 'lifeos', icon: '✦', name: 'LifeOS', label: 'Your working mini workspace', text: 'Plan tasks, keep notes, and move daily work forward in one place.' },
    { id: 'core', icon: '⬡', name: 'Evolve Core', label: 'Cloud-like continuity layer', text: 'Save progress, organize sensitive files, and create recoverable snapshots.' }
  ];
  var state = load();

  function load() {
    var empty = { mode: 'professional', configured: false, sentinel: { alerts: [], services: [] }, nexora: { workflows: [], runs: [] }, pulse: { interests: ['technology', 'learning'], cards: [] }, identity: { displayName: '', role: 'Professional', sharing: 'private' }, lifeos: { tasks: [], notes: '' }, core: { files: [], snapshots: [] } };
    try { return Object.assign(empty, JSON.parse(localStorage.getItem(KEY) || '{}')); } catch (e) { return empty; }
  }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) {} }
  function esc(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function toast(message) { if (typeof window.showToast === 'function') window.showToast(message); }
  function panel() {
    var el = document.getElementById('mv-evolve');
    if (el) return el;
    el = document.createElement('section'); el.id = 'mv-evolve'; el.className = 'mv-evolve-shell'; el.setAttribute('aria-label', 'Mindvora Evolve');
    el.innerHTML = '<header class="mv-evolve-header"><button type="button" data-close aria-label="Close Evolve">←</button><div><span class="mv-evolve-kicker">MINDVORA / EVOLVE</span><h1>One intelligence layer for your digital world</h1></div><span class="mv-evolve-status"><i></i> <b data-status>Workspace ready</b></span></header>' +
      '<div class="mv-evolve-layout"><nav class="mv-evolve-nav" aria-label="Evolve divisions"><button class="active" data-view="overview">◌ Overview</button>' + divisions.map(function (d) { return '<button data-view="' + d.id + '">' + d.icon + ' ' + esc(d.name) + '</button>'; }).join('') + '</nav><main class="mv-evolve-main" data-main></main></div>';
    document.body.appendChild(el);
    el.querySelector('[data-close]').addEventListener('click', function () { close(el); });
    el.querySelectorAll('[data-view]').forEach(function (b) { b.addEventListener('click', function () { render(el, b.getAttribute('data-view')); }); });
    return el;
  }
  function field(label, name, value, type) { return '<label class="mv-evolve-field"><span>' + esc(label) + '</span><input data-field="' + esc(name) + '" type="' + (type || 'text') + '" value="' + esc(value || '') + '"></label>'; }
  function button(label, action, cls) { return '<button type="button" class="mv-evolve-btn ' + (cls || '') + '" data-action="' + esc(action) + '">' + esc(label) + '</button>'; }
  function metric(title, value, detail, tone) { return '<article class="mv-evolve-metric ' + (tone || '') + '"><span>' + esc(title) + '</span><strong>' + esc(value) + '</strong><small>' + esc(detail) + '</small></article>'; }
  function modeSelect() { return '<label class="mv-evolve-mode"><span>Configure Evolve for</span><select data-mode>' + Object.keys(MODES).map(function (key) { return '<option value="' + key + '"' + (state.mode === key ? ' selected' : '') + '>' + MODES[key].icon + ' ' + MODES[key].label + '</option>'; }).join('') + '</select></label>'; }
  function overview() {
    return '<div class="mv-evolve-hero"><div><span class="mv-evolve-eyebrow">EVOLVE INTELLIGENCE CORE</span><h2>A control room that adapts to the way you work.</h2><p>Choose a working mode, then configure each centre around your goals. Evolve keeps actions explicit and gives Nexora the role-aware operating layer that ARIA does not provide.</p>' + modeSelect() + '</div><div class="mv-evolve-orbit" aria-hidden="true"><b>EVOLVE</b><span></span><span></span><span></span></div></div>' +
      '<div class="mv-evolve-metrics">' + metric('Working mode', MODES[state.mode].label, state.configured ? 'Configured for this workspace' : 'Choose a mode to begin', 'green') + metric('Nexora runs', String(state.nexora.runs.length), 'Plans and operations recorded') + metric('LifeOS tasks', String(state.lifeos.tasks.filter(function (x) { return !x.done; }).length), 'Open tasks in your workspace') + metric('Core snapshots', String(state.core.snapshots.length), 'Recoverable progress points', 'gold') + '</div>' +
      '<section class="mv-evolve-section"><div class="mv-evolve-section-head"><div><span class="mv-evolve-eyebrow">YOUR EVOLVE LAYER</span><h3>Open a centre</h3></div><span class="mv-evolve-chip">Permission-aware by design</span></div><div class="mv-evolve-grid">' + divisions.map(function (d) { return '<button class="mv-evolve-division" data-view="' + d.id + '"><span class="mv-evolve-division-icon">' + d.icon + '</span><span><strong>' + esc(d.name) + '</strong><small>' + esc(d.label) + '</small><em>' + esc(d.text) + '</em></span><b>→</b></button>'; }).join('') + '</div></section><p class="mv-evolve-note">Local workspace state is kept on this device for now. Sensitive operations remain confirmation-based, and no external service is connected without your permission.</p>';
  }
  function sentinel() {
    var services = state.sentinel.services.length ? state.sentinel.services.map(function (x, i) { return '<li><span>' + esc(x) + '</span>' + button('Remove', 'remove-service-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">No connected services recorded.</li>';
    var alerts = state.sentinel.alerts.length ? state.sentinel.alerts.map(function (x) { return '<li><strong>' + esc(x.level) + '</strong> ' + esc(x.text) + '<small>' + esc(x.date) + '</small></li>'; }).join('') : '<li class="muted">No security alerts recorded.</li>';
    return head('Sentinel', 'Digital Protection', 'Protect links, review local security events, and keep connected services visible.') + '<div class="mv-evolve-tool-grid"><section class="mv-evolve-tool"><h3>Scan a link</h3><p>Check a URL for unsafe schemes, deceptive hostnames, and common phishing signals before opening it.</p>' + field('URL to scan', 'sentinel-url', '', 'url') + button('Scan link', 'scan-link', 'primary') + '<div data-result="sentinel" class="mv-evolve-result" aria-live="polite">Enter a link to begin.</div></section><section class="mv-evolve-tool"><h3>Review security alerts</h3><p>Sentinel keeps the alerts you create here so you can review and clear them.</p><ul class="mv-evolve-list">' + alerts + '</ul>' + button('Mark alerts reviewed', 'clear-alerts', 'subtle') + '</section><section class="mv-evolve-tool"><h3>Connected services</h3><p>Add a service you want to keep visible in this workspace. Remove it any time.</p>' + field('Service name', 'sentinel-service', '', 'text') + button('Add service', 'add-service', 'primary') + '<ul class="mv-evolve-list">' + services + '</ul></section></div>';
  }
  function nexora() {
    var mode = MODES[state.mode].label;
    var workflows = state.nexora.workflows.length ? state.nexora.workflows.map(function (x, i) { return '<li><strong>' + esc(x.name) + '</strong><span>' + esc(x.detail) + '</span>' + button('Delete', 'delete-workflow-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">No workflows yet. Create one below.</li>';
    return head('Nexora', 'The Evolve operating intelligence', 'Nexora changes its working style to match your configured mode: ' + mode + '.') + '<div class="mv-evolve-tool-grid"><section class="mv-evolve-tool wide"><h3>Give Nexora a job</h3><p>Describe the outcome. Nexora will turn it into an explicit, reviewable plan instead of silently taking action.</p><textarea data-field="nexora-task" rows="4" placeholder="Example: Plan three short videos about sustainable fashion…"></textarea><div class="mv-evolve-inline">' + button('Build a plan', 'run-nexora', 'primary') + '<span class="mv-evolve-hint">Mode: ' + esc(mode) + '</span></div><div data-result="nexora" class="mv-evolve-result" aria-live="polite">Your plan will appear here for review.</div></section><section class="mv-evolve-tool"><h3>Create a workflow</h3><p>Save a repeatable operation for your role.</p>' + field('Workflow name', 'workflow-name', '', 'text') + field('What should it do?', 'workflow-detail', '', 'text') + button('Save workflow', 'save-workflow', 'primary') + '</section><section class="mv-evolve-tool"><h3>Saved workflows</h3><ul class="mv-evolve-list">' + workflows + '</ul></section></div>';
  }
  function pulse() {
    var interests = state.pulse.interests.map(function (x, i) { return '<button type="button" class="mv-evolve-tag" data-action="remove-interest-' + i + '">' + esc(x) + ' ×</button>'; }).join('');
    var cards = (state.pulse.cards.length ? state.pulse.cards : ['A practical guide to ' + MODES[state.mode].label.toLowerCase() + ' workflows', 'New tools and ideas worth exploring', 'A learning path shaped around your interests']).map(function (x) { return '<article class="mv-evolve-pulse-card"><span>Pulse brief</span><strong>' + esc(x) + '</strong><small>Tailored to your selected interests.</small></article>'; }).join('');
    return head('Pulse', 'Personal information intelligence', 'Pulse is social in feel, but configurable: you decide the subjects and signals that shape your stream.') + '<section class="mv-evolve-tool"><h3>Your interest stream</h3><div class="mv-evolve-tags">' + (interests || '<span class="muted">Add your first interest.</span>') + '</div><div class="mv-evolve-inline">' + field('Add an interest', 'pulse-interest', '', 'text') + button('Add interest', 'add-interest', 'primary') + button('Refresh Pulse', 'refresh-pulse', 'subtle') + '</div></section><div class="mv-evolve-pulse-grid">' + cards + '</div>';
  }
  function identity() {
    var data = state.identity;
    return head('Identity', 'Configurable digital identity', 'Control how Evolve represents you in personal, business, teaching, or professional workspaces.') + '<section class="mv-evolve-tool mv-evolve-form">' + field('Display name', 'identity-name', data.displayName, 'text') + field('Primary role', 'identity-role', data.role, 'text') + '<label class="mv-evolve-field"><span>Default sharing</span><select data-field="identity-sharing"><option value="private"' + (data.sharing === 'private' ? ' selected' : '') + '>Private by default</option><option value="team"' + (data.sharing === 'team' ? ' selected' : '') + '>Trusted team only</option><option value="public"' + (data.sharing === 'public' ? ' selected' : '') + '>Public profile</option></select></label><label class="mv-evolve-check"><input type="checkbox" data-identity-verify ' + (data.verify ? 'checked' : '') + '> Ask for verification before sharing credentials</label>' + button('Save identity settings', 'save-identity', 'primary') + '<div data-result="identity" class="mv-evolve-result">Your identity settings are private until you save and share them.</div></section>';
  }
  function lifeos() {
    var tasks = state.lifeos.tasks.length ? state.lifeos.tasks.map(function (x, i) { return '<li class="' + (x.done ? 'done' : '') + '"><label><input type="checkbox" data-task="' + i + '" ' + (x.done ? 'checked' : '') + '> ' + esc(x.text) + '</label>' + button('Delete', 'delete-task-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">Your workspace is clear. Add a task to begin.</li>';
    return head('LifeOS', 'Your working mini workspace', 'A focused workspace for developers, businesses, teachers, lecturers, and every profession in between.') + '<div class="mv-evolve-tool-grid"><section class="mv-evolve-tool"><h3>Today workspace</h3>' + field('New task', 'life-task', '', 'text') + button('Add task', 'add-task', 'primary') + '<ul class="mv-evolve-list" data-task-list>' + tasks + '</ul></section><section class="mv-evolve-tool"><h3>Working notes</h3><textarea data-life-notes rows="11" placeholder="Keep the notes you need for today…">' + esc(state.lifeos.notes) + '</textarea>' + button('Save notes', 'save-notes', 'primary') + '<div data-result="life" class="mv-evolve-result"></div></section></div>';
  }
  function core() {
    var files = state.core.files.length ? state.core.files.map(function (x, i) { return '<li><strong>' + esc(x.name) + '</strong><small>' + esc(x.detail) + '</small>' + button('Remove', 'delete-file-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">No workspace records yet.</li>';
    var snaps = state.core.snapshots.length ? state.core.snapshots.map(function (x, i) { return '<li><strong>' + esc(x.name) + '</strong><small>' + esc(x.count) + ' records · ' + esc(x.date) + '</small>' + button('Restore', 'restore-snapshot-' + i, 'subtle') + '</li>'; }).join('') : '<li class="muted">No snapshots yet.</li>';
    return head('Evolve Core', 'Cloud-like continuity layer', 'Keep Evolve progress organized, create recovery points, and export a copy before moving work between devices.') + '<div class="mv-evolve-tool-grid"><section class="mv-evolve-tool"><h3>Workspace records</h3>' + field('Record or sensitive file label', 'core-file', '', 'text') + field('What is it for?', 'core-detail', '', 'text') + button('Save record', 'save-file', 'primary') + '<ul class="mv-evolve-list">' + files + '</ul></section><section class="mv-evolve-tool"><h3>Backups & recovery</h3><p>Create a local recovery point for this Evolve workspace. Export it for safekeeping.</p>' + button('Create snapshot', 'create-snapshot', 'primary') + button('Export workspace backup', 'export-core', 'subtle') + '<ul class="mv-evolve-list">' + snaps + '</ul></section></div><p class="mv-evolve-note">This first Core layer is device-local and exportable. A connected cloud provider can be added later without changing the workspace model.</p>';
  }
  function head(name, label, text) { return '<div class="mv-evolve-division-head"><span class="mv-evolve-division-icon large">' + (divisions.filter(function (d) { return d.name === name; })[0] || { icon: '✦' }).icon + '</span><div><span class="mv-evolve-eyebrow">EVOLVE CENTRE</span><h2>' + esc(name) + '</h2><p>' + esc(text) + '</p></div></div><p class="mv-evolve-subhead">' + esc(label) + '</p>'; }
  function render(el, view) {
    el.querySelectorAll('[data-view]').forEach(function (b) { b.classList.toggle('active', b.getAttribute('data-view') === view); });
    var main = el.querySelector('[data-main]');
    main.innerHTML = view === 'overview' ? overview() : ({ sentinel: sentinel, nexora: nexora, pulse: pulse, identity: identity, lifeos: lifeos, core: core }[view] || overview)();
    bind(el, view);
  }
  function bind(el, view) {
    el.querySelectorAll('[data-view]').forEach(function (b) { if (!b.__bound) { b.__bound = true; b.addEventListener('click', function () { render(el, b.getAttribute('data-view')); }); } });
    var mode = el.querySelector('[data-mode]'); if (mode) mode.addEventListener('change', function () { state.mode = mode.value; state.configured = true; save(); render(el, 'overview'); });
    el.querySelectorAll('[data-action]').forEach(function (b) { b.addEventListener('click', function () { action(el, view, b.getAttribute('data-action')); }); });
    el.querySelectorAll('[data-task]').forEach(function (box) { box.addEventListener('change', function () { state.lifeos.tasks[Number(box.getAttribute('data-task'))].done = box.checked; save(); render(el, 'lifeos'); }); });
  }
  function value(el, name) { var x = el.querySelector('[data-field="' + name + '"]'); return x ? x.value.trim() : ''; }
  function result(el, key, html) { var node = el.querySelector('[data-result="' + key + '"]'); if (node) node.innerHTML = html; }
  function action(el, view, actionName) {
    var i, item, url, parsed, host, level;
    if (actionName === 'scan-link') { url = value(el, 'sentinel-url'); try { parsed = new URL(url); host = parsed.hostname.toLowerCase(); level = parsed.protocol !== 'https:' ? 'Caution' : (/^(localhost|127\.|10\.|192\.168\.)/.test(host) ? 'Review' : 'Low risk'); if (parsed.username || parsed.password || /@/.test(host) || /[\-_]{2,}/.test(host)) level = 'Caution'; result(el, 'sentinel', '<strong>' + esc(level) + '</strong><p>' + esc(parsed.protocol + '://' + host) + ' was parsed locally. Confirm the domain and context before opening it.</p>' ); state.sentinel.alerts.unshift({ level: level, text: host, date: new Date().toLocaleString() }); save(); } catch (e) { result(el, 'sentinel', '<strong>Invalid link</strong><p>Enter a complete URL such as https://example.com.</p>'); } return; }
    if (actionName === 'clear-alerts') { state.sentinel.alerts = []; save(); render(el, 'sentinel'); return; }
    if (actionName === 'add-service') { item = value(el, 'sentinel-service'); if (!item) return toast('Enter a service name first.'); state.sentinel.services.push(item); save(); render(el, 'sentinel'); return; }
    if (/^remove-service-/.test(actionName)) { state.sentinel.services.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'sentinel'); return; }
    if (actionName === 'run-nexora') { item = value(el, 'nexora-task'); if (!item) return toast('Tell Nexora what outcome you want.'); var plans = { creator: ['Clarify the audience and format', 'Draft a concise content outline', 'Prepare a review checklist before publishing'], business: ['Sort the work into a repeatable process', 'Identify records and approvals needed', 'Prepare a fast handoff checklist'], developer: ['Reproduce the issue or define the change', 'Inspect the smallest safe code path', 'Run tests and review the diff before merging'], educator: ['Define the learning objective', 'Break the topic into practice-sized steps', 'Add a check for understanding'], professional: ['Define the desired outcome', 'Break the work into clear next actions', 'Review the result before sharing'] }[state.mode]; state.nexora.runs.push({ task: item, date: new Date().toLocaleString() }); save(); result(el, 'nexora', '<strong>Nexora plan for ' + esc(item) + '</strong><ol>' + plans.map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ol><small>Nothing was executed. Review and approve each next step yourself.</small>'); return; }
    if (actionName === 'save-workflow') { var wn = value(el, 'workflow-name'), wd = value(el, 'workflow-detail'); if (!wn || !wd) return toast('Add a workflow name and its purpose.'); state.nexora.workflows.push({ name: wn, detail: wd }); save(); render(el, 'nexora'); return; }
    if (/^delete-workflow-/.test(actionName)) { state.nexora.workflows.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'nexora'); return; }
    if (actionName === 'add-interest') { item = value(el, 'pulse-interest').toLowerCase(); if (!item) return toast('Enter an interest first.'); if (state.pulse.interests.indexOf(item) < 0) state.pulse.interests.push(item); state.pulse.cards = []; save(); render(el, 'pulse'); return; }
    if (/^remove-interest-/.test(actionName)) { state.pulse.interests.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'pulse'); return; }
    if (actionName === 'refresh-pulse') { state.pulse.cards = state.pulse.interests.slice(0, 3).map(function (x) { return 'New ideas and conversations about ' + x; }); save(); render(el, 'pulse'); return; }
    if (actionName === 'save-identity') { state.identity.displayName = value(el, 'identity-name'); state.identity.role = value(el, 'identity-role') || MODES[state.mode].label; state.identity.sharing = value(el, 'identity-sharing'); var verify = el.querySelector('[data-identity-verify]'); state.identity.verify = !!(verify && verify.checked); save(); result(el, 'identity', '<strong>Saved privately.</strong><p>Your default sharing is set to ' + esc(state.identity.sharing) + '.</p>'); return; }
    if (actionName === 'add-task') { item = value(el, 'life-task'); if (!item) return toast('Enter a task first.'); state.lifeos.tasks.push({ text: item, done: false }); save(); render(el, 'lifeos'); return; }
    if (/^delete-task-/.test(actionName)) { state.lifeos.tasks.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'lifeos'); return; }
    if (actionName === 'save-notes') { var notes = el.querySelector('[data-life-notes]'); state.lifeos.notes = notes ? notes.value : ''; save(); result(el, 'life', '<strong>Notes saved to this workspace.</strong>'); return; }
    if (actionName === 'save-file') { var fn = value(el, 'core-file'), fd = value(el, 'core-detail'); if (!fn) return toast('Enter a record label first.'); state.core.files.push({ name: fn, detail: fd || 'Evolve workspace record' }); save(); render(el, 'core'); return; }
    if (/^delete-file-/.test(actionName)) { state.core.files.splice(Number(actionName.split('-').pop()), 1); save(); render(el, 'core'); return; }
    if (actionName === 'create-snapshot') { state.core.snapshots.unshift({ name: 'Snapshot ' + (state.core.snapshots.length + 1), count: state.core.files.length + state.lifeos.tasks.length, date: new Date().toLocaleString(), data: JSON.stringify(state) }); save(); render(el, 'core'); toast('Evolve Core snapshot created.'); return; }
    if (/^restore-snapshot-/.test(actionName)) { var snap = state.core.snapshots[Number(actionName.split('-').pop())]; if (snap && confirm('Restore this Evolve Core snapshot? Current workspace changes will be replaced.')) { var restored = JSON.parse(snap.data); state = restored; save(); render(el, 'overview'); toast('Evolve Core workspace restored.'); } return; }
    if (actionName === 'export-core') { var blob = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' }); var link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'mindvora-evolve-backup.json'; link.click(); setTimeout(function () { URL.revokeObjectURL(link.href); }, 500); toast('Evolve Core backup exported.'); }
  }
  function close(el) { el.classList.remove('open'); document.body.style.overflow = ''; if (window.__mvEvolveOpenedFromDrawer && typeof window.toggleDrawer === 'function' && !document.getElementById('app-drawer').classList.contains('open')) { window.__mvEvolveOpenedFromDrawer = false; window.toggleDrawer(); } }
  window.openMindvoraEvolve = function () { var el = panel(); render(el, 'overview'); el.classList.add('open'); document.body.style.overflow = 'hidden'; };
  window.mvConfigureEvolveFromDrawer = function () { window.__mvEvolveOpenedFromDrawer = true; window.openMindvoraEvolve(); };
})();
