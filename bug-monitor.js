(function () {
  'use strict';

  var MAX_TEXT = 1600;
  var MAX_REPORTS = 20;
  var REPORT_PATH = '/api/bugs/report';
  var reportEndpoint = '';
  var seen = Object.create(null);
  var reportCount = 0;
  var bugWatchPoll = null;
  var bugWatchLoaded = false;
  var originalFetch = window.fetch ? window.fetch.bind(window) : null;
  var backendUrl = String(window.BACKEND_URL || '').replace(/\/$/, '');
  var backendOrigin = '';
  try { backendOrigin = backendUrl ? new URL(backendUrl, window.location.href).origin : ''; } catch (e) {}
  var IGNORED = /resizeobserver loop|script error$|network request failed$|the user aborted|aborterror|operation was aborted|play\(\) request was interrupted|request was cancelled|notallowederror|permission denied|quota exceeded/i;
  function serverFailure(status) { return status >= 500 && status <= 599; }

  function cap(value, limit) {
    var text = String(value == null ? '' : value);
    return text.length > (limit || MAX_TEXT) ? text.slice(0, limit || MAX_TEXT) + '…' : text;
  }
  function safeUrl(value) {
    try {
      var url = new URL(String(value), window.location.href);
      ['token', 'access_token', 'id_token', 'api_key', 'apikey', 'key', 'password'].forEach(function (key) { url.searchParams.delete(key); });
      url.hash = '';
      return cap(url.href, 700);
    } catch (e) { return cap(value, 700); }
  }
  function redact(value, key) {
    if (value == null) return value;
    if (key && /token|password|passwd|secret|authorization|cookie|credential|api[_-]?key/i.test(key)) return '[REDACTED]';
    if (typeof value === 'string') return cap(value.replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED]').replace(/(password|passwd|secret|token|id_token|access_token|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]').replace(/[?&](token|access_token|id_token|api_key|apikey|key|password)=[^&]*/gi, '?$1=[REDACTED]'));
    if (Array.isArray(value)) return value.slice(0, 20).map(function (item) { return redact(item, key); });
    if (typeof value === 'object') { var output = {}; Object.keys(value).slice(0, 40).forEach(function (name) { output[name] = redact(value[name], name); }); return output; }
    return value;
  }
  function messageOf(value) { return value && value.message ? String(value.message) : String(value == null ? '' : value); }
  function isNoise(value) { var message = messageOf(value).trim(); return !message || IGNORED.test(message); }
  function isReportRequest(url) { try { return new URL(String(url), window.location.href).pathname === REPORT_PATH; } catch (e) { return String(url).indexOf(REPORT_PATH) !== -1; } }
  function isRelevantUrl(url) { try { var origin = new URL(String(url), window.location.href).origin; return origin === window.location.origin || (!!backendOrigin && origin === backendOrigin); } catch (e) { return false; } }
  function isRelevantStack(stack) { var value = String(stack || ''); return value.indexOf(window.location.origin) !== -1 || (!!backendOrigin && value.indexOf(backendOrigin) !== -1) || /(?:^|[\\/])(script|settings|story-music|live-hub|live-news|bug-monitor)\.js(?:\?|:|\b)/i.test(value); }
  function currentToken() { try { var user = window.firebase && firebase.auth && firebase.auth().currentUser; return user && user.getIdToken ? user.getIdToken().catch(function () { return null; }) : Promise.resolve(null); } catch (e) { return Promise.resolve(null); } }

  function report(kind, details) {
    if (!originalFetch || reportCount >= MAX_REPORTS || !reportEndpoint) return;
    details = details || {};
    if (kind === 'fetch.failure' && !serverFailure(Number(details.status))) return;
    if (isNoise(details.message) && !details.stack && !details.source && kind !== 'fetch.failure' && kind !== 'xhr.failure') return;
    var fingerprintBasis = details.stack || details.message || details.status || details.url || 'unknown';
    var dedupeKey = kind + '|' + cap(fingerprintBasis, 500);
    if (seen[dedupeKey]) return;
    seen[dedupeKey] = true;
    if (details.message && typeof details.message !== 'string') details.message = details.message.message || String(details.message);
    var payload = redact({
      kind: kind,
      fingerprint: cap(kind + ':' + fingerprintBasis, 300),
      message: details.message,
      source: details.source,
      url: details.url && safeUrl(details.url),
      route: cap(details.route || window.location.pathname, 500),
      status: details.status,
      stack: details.stack,
      context: details.context,
      occurredAt: new Date().toISOString(),
      page: safeUrl(window.location.href),
      userAgent: cap(navigator.userAgent, 400)
    });
    reportCount++;
    currentToken().then(function (token) {
      var headers = { 'Content-Type': 'application/json' };
      if (token) headers.Authorization = 'Bearer ' + token;
      return originalFetch(reportEndpoint, { method: 'POST', headers: headers, body: JSON.stringify(payload), keepalive: true });
    }).catch(function () {});
  }

  function init() {
    reportEndpoint = backendUrl + REPORT_PATH;
    window.addEventListener('error', function (event) {
      var source = event.filename || '';
      if (source && !isRelevantUrl(source)) return;
      if (!event.error && (!event.message || /^script error$/i.test(event.message))) return;
      report('window.error', { message: event.message || 'Script error', source: source, stack: event.error && event.error.stack, route: window.location.pathname });
    });
    window.addEventListener('unhandledrejection', function (event) {
      var reason = event.reason;
      if (!reason || !reason.stack || !isRelevantStack(reason.stack)) return;
      report('unhandledrejection', { message: reason && reason.message ? reason.message : reason, stack: reason && reason.stack, route: window.location.pathname });
    });
    if (originalFetch) {
      window.fetch = function (input, initOptions) {
        var requestUrl = typeof input === 'string' ? input : (input && input.url) || '';
        var shouldInspect = isRelevantUrl(requestUrl) && !isReportRequest(requestUrl);
        return originalFetch(input, initOptions).then(function (response) {
          if (shouldInspect && response && serverFailure(response.status)) report('fetch.failure', { url: requestUrl, status: response.status, route: window.location.pathname });
          return response;
        }, function (error) {
          if (shouldInspect && !isNoise(error)) report('fetch.error', { url: requestUrl, message: error && error.message, stack: error && error.stack, route: window.location.pathname });
          throw error;
        });
      };
    }
    if (window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
      var xhrOpen = window.XMLHttpRequest.prototype.open;
      var xhrSend = window.XMLHttpRequest.prototype.send;
      window.XMLHttpRequest.prototype.open = function (method, url) { this.__mvBugWatchUrl = String(url || ''); return xhrOpen.apply(this, arguments); };
      window.XMLHttpRequest.prototype.send = function () {
        var xhr = this;
        var url = xhr.__mvBugWatchUrl || '';
        if (isRelevantUrl(url) && !isReportRequest(url) && !xhr.__mvBugWatchBound) {
          xhr.__mvBugWatchBound = true;
          xhr.addEventListener('loadend', function () {
            var observedUrl = xhr.__mvBugWatchUrl || '';
            if (isRelevantUrl(observedUrl) && !isReportRequest(observedUrl) && xhr.status >= 500 && xhr.status <= 599) report('xhr.failure', { url: observedUrl, status: xhr.status, message: 'HTTP ' + xhr.status + ' response from app/backend request', route: window.location.pathname });
          });
        }
        return xhrSend.apply(this, arguments);
      };
    }
  }

  function adminToken() { try { var user = window.firebase && firebase.auth && firebase.auth().currentUser; return user && user.getIdToken ? user.getIdToken() : Promise.reject(new Error('Not signed in')); } catch (e) { return Promise.reject(e); } }
  function adminRequest(path, options) {
    options = options || {};
    return adminToken().then(function (token) {
      var headers = Object.assign({ 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, options.headers || {});
      return fetch(backendUrl + path, Object.assign({}, options, { headers: headers })).then(function (response) { return response.text().then(function (text) { var data; try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { message: text }; } if (!response.ok) throw new Error(data.message || 'Request failed (' + response.status + ')'); return data; }); });
    });
  }
  function esc(value) { return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
  function renderBugs(items) {
    var list = document.getElementById('bug-watch-list');
    var summary = document.getElementById('bug-watch-summary');
    if (!list) return;
    items = Array.isArray(items) ? items : (items && (items.reports || items.bugs || items.items || items.data)) || [];
    items = items.filter(function (bug) { return !bug.status || bug.status === 'pending'; });
    if (summary) summary.textContent = items.length + ' actionable report' + (items.length === 1 ? '' : 's') + ' awaiting owner review';
    if (!items.length) { list.innerHTML = '<div class="bug-watch-empty">✅ No actionable bug reports waiting for review.</div>'; return; }
    list.innerHTML = items.map(function (bug) {
      var id = bug.id || bug._id;
      var kind = bug.kind || 'observed runtime event';
      var stack = bug.stack || '';
      var observedAt = bug.occurredAt || bug.createdAt || 'Unknown time';
      var httpStatus = bug.httpStatus ? '<br><b>HTTP status</b> ' + esc(bug.httpStatus) : '';
      var source = bug.source ? '<br><b>Source</b> ' + esc(bug.source) : '';
      var evidence = stack ? '<details class="bug-watch-evidence"><summary>View captured stack trace</summary><pre>' + esc(stack) + '</pre></details>' : '';
      return '<article class="bug-watch-card"><div class="bug-watch-card-head"><strong>Observed: ' + esc(kind) + '</strong><span>' + esc(bug.status || 'pending') + '</span></div><div class="bug-watch-card-body"><b>Captured error</b> ' + esc(bug.message || 'No message') + '<br><b>AI hypothesis (unverified)</b> ' + esc(bug.likelyCause || bug.cause || 'No automated hypothesis') + '<br><b>Route</b> ' + esc(bug.route || bug.url || 'Unknown') + httpStatus + source + '<br><b>Observed at</b> ' + esc(observedAt) + '<br><b>Occurrences</b> ' + esc(bug.occurrenceCount || bug.occurrences || bug.count || 1) + '</div>' + evidence + '<div class="bug-watch-actions"><button class="btn-approve" data-bug-decision="accept" data-bug-id="' + esc(id) + '">Accept</button><button class="btn-reject" data-bug-decision="decline" data-bug-id="' + esc(id) + '">Decline</button></div></article>';
    }).join('');
  }
  function loadBugWatch() { var list = document.getElementById('bug-watch-list'); if (!window.isAdmin || !window.isAdmin() || !list) return; if (!bugWatchLoaded) list.innerHTML = '<div class="bug-watch-empty">Loading actionable reports…</div>'; adminRequest('/api/admin/bugs').then(function (items) { bugWatchLoaded = true; renderBugs(items); }).catch(function (error) { list.innerHTML = '<div class="bug-watch-error">Unable to load bug reports: ' + esc(error.message) + '</div>'; }); }
  function startBugWatchPolling() { if (bugWatchPoll) clearInterval(bugWatchPoll); bugWatchPoll = setInterval(function () { var panel = document.getElementById('admin-bug-watch'); if (!document.hidden && panel && panel.style.display !== 'none') loadBugWatch(); }, 15000); }
  function stopBugWatchPolling() { if (bugWatchPoll) clearInterval(bugWatchPoll); bugWatchPoll = null; }
  function decideBug(id, decision, button) { if (!window.isAdmin || !window.isAdmin() || !id) return; button.disabled = true; adminRequest('/api/admin/bugs/' + encodeURIComponent(id) + '/decision', { method: 'POST', body: JSON.stringify({ decision: decision }) }).then(function () { button.parentNode.innerHTML = decision === 'accept' ? '<span class="bug-watch-accepted">✅ Accepted — isolated repair job queued.</span>' : '<span class="bug-watch-declined">Closed — report declined.</span>'; }).catch(function (error) { button.disabled = false; if (typeof window.showToast === 'function') window.showToast('Bug decision failed: ' + error.message); }); }
  function installAdminTab() {
    var tabs = document.querySelector('#modal-admin .admin-tabs'); if (!tabs) return;
    var tab = tabs.querySelector('[data-bug-watch-tab]');
    if (!tab) { tab = document.createElement('button'); tab.className = 'f-pill'; tab.type = 'button'; tab.setAttribute('data-bug-watch-tab', '1'); tab.textContent = '🐞 Bug Watch'; tab.onclick = function () { window.switchAdminTab('bug-watch', tab); }; tabs.appendChild(tab); }
    var panel = document.getElementById('admin-bug-watch'); if (!panel || panel.__bugWatchBound) return;
    panel.__bugWatchBound = true;
    panel.addEventListener('click', function (event) { var button = event.target.closest('[data-bug-decision]'); if (button) decideBug(button.getAttribute('data-bug-id'), button.getAttribute('data-bug-decision'), button); });
  }
  function integrateAdmin() {
    installAdminTab();
    var originalSwitch = window.switchAdminTab;
    if (typeof originalSwitch === 'function' && !originalSwitch.__bugWatchWrapped) {
      var wrappedSwitch = function (tab, btn) {
        if (tab !== 'bug-watch') { stopBugWatchPolling(); return originalSwitch.apply(this, arguments); }
        if (!window.isAdmin || !window.isAdmin()) return;
        document.querySelectorAll('#modal-admin .admin-tabs .f-pill').forEach(function (item) { item.classList.remove('active'); });
        if (btn) btn.classList.add('active');
        ['pending','approved','rejected','overview','security','users','bug-watch'].forEach(function (name) { var panel = document.getElementById('admin-' + name); if (panel) panel.style.display = name === tab ? 'block' : 'none'; });
        loadBugWatch();
        startBugWatchPolling();
      };
      wrappedSwitch.__bugWatchWrapped = true; window.switchAdminTab = wrappedSwitch;
    }
  }
  init();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', integrateAdmin); else integrateAdmin();
  setTimeout(integrateAdmin, 0);
  window.MVBugWatch = { load: loadBugWatch };
}());
