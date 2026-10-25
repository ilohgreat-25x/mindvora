(function () {
  'use strict';

  var MAX_TEXT = 1600;
  var MAX_REPORTS = 40;
  var REPORT_PATH = '/api/bugs/report';
  var reportEndpoint = '';
  var seen = Object.create(null);
  var reportCount = 0;
  var originalFetch = window.fetch ? window.fetch.bind(window) : null;
  var backendUrl = String(window.BACKEND_URL || '').replace(/\/$/, '');
  var backendOrigin = '';
  try { backendOrigin = backendUrl ? new URL(backendUrl, window.location.href).origin : ''; } catch (e) {}

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
    if (typeof value === 'string') {
      return cap(value
        .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED]')
        .replace(/(password|passwd|secret|token|id_token|access_token|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+/gi, '$1=[REDACTED]')
        .replace(/[?&](token|access_token|id_token|api_key|apikey|key|password)=[^&]*/gi, '?$1=[REDACTED]'));
    }
    if (Array.isArray(value)) return value.slice(0, 20).map(function (item) { return redact(item, key); });
    if (typeof value === 'object') {
      var output = {};
      Object.keys(value).slice(0, 40).forEach(function (name) { output[name] = redact(value[name], name); });
      return output;
    }
    return value;
  }

  function isReportRequest(url) {
    try { return new URL(String(url), window.location.href).pathname === REPORT_PATH; } catch (e) { return String(url).indexOf(REPORT_PATH) !== -1; }
  }

  function isRelevantUrl(url) {
    try {
      var origin = new URL(String(url), window.location.href).origin;
      return origin === window.location.origin || (!!backendOrigin && origin === backendOrigin);
    } catch (e) { return false; }
  }

  function currentToken() {
    try {
      var user = window.firebase && firebase.auth && firebase.auth().currentUser;
      return user && user.getIdToken ? user.getIdToken().catch(function () { return null; }) : Promise.resolve(null);
    } catch (e) { return Promise.resolve(null); }
  }

  function report(kind, details) {
    if (!originalFetch || reportCount >= MAX_REPORTS || !reportEndpoint) return;
    var dedupeKey = kind + '|' + cap(details && (details.message || details.status || details.url || 'unknown'), 500);
    if (seen[dedupeKey]) return;
    seen[dedupeKey] = true;
    details = details || {};
    if (details.message && typeof details.message !== 'string') details.message = details.message.message || String(details.message);
    var payload = redact({
      kind: kind,
      fingerprint: cap(kind + ':' + (details && (details.message || details.status || details.url || 'unknown')), 300),
      message: details && details.message,
      source: details && details.source,
      url: details && safeUrl(details.url),
      status: details && details.status,
      stack: details && details.stack,
      response: details && details.response,
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
      report('window.error', { message: event.message || 'Script error', source: event.filename, stack: event.error && event.error.stack });
    });
    window.addEventListener('unhandledrejection', function (event) {
      var reason = event.reason;
      report('unhandledrejection', { message: reason && reason.message ? reason.message : reason, stack: reason && reason.stack });
    });
    if (originalFetch) {
      window.fetch = function (input, initOptions) {
        var requestUrl = typeof input === 'string' ? input : (input && input.url) || '';
        var shouldInspect = isRelevantUrl(requestUrl) && !isReportRequest(requestUrl);
        return originalFetch(input, initOptions).then(function (response) {
          if (shouldInspect && response && response.status >= 400) {
            var copy = response.clone();
            copy.text().then(function (text) {
              report('fetch.failure', { url: requestUrl, status: response.status, response: text });
            }).catch(function () { report('fetch.failure', { url: requestUrl, status: response.status }); });
          }
          return response;
        }, function (error) {
          if (shouldInspect) report('fetch.error', { url: requestUrl, message: error && error.message, stack: error && error.stack });
          throw error;
        });
      };
    }
  }

  function adminToken() {
    try {
      var user = window.firebase && firebase.auth && firebase.auth().currentUser;
      return user && user.getIdToken ? user.getIdToken() : Promise.reject(new Error('Not signed in'));
    } catch (e) { return Promise.reject(e); }
  }

  function adminRequest(path, options) {
    options = options || {};
    return adminToken().then(function (token) {
      var headers = Object.assign({ 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, options.headers || {});
      return fetch(backendUrl + path, Object.assign({}, options, { headers: headers })).then(function (response) {
        return response.text().then(function (text) {
          var data; try { data = text ? JSON.parse(text) : {}; } catch (e) { data = { message: text }; }
          if (!response.ok) throw new Error(data.message || 'Request failed (' + response.status + ')');
          return data;
        });
      });
    });
  }

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; });
  }

  function renderBugs(items) {
    var list = document.getElementById('bug-watch-list');
    var summary = document.getElementById('bug-watch-summary');
    if (!list) return;
    items = Array.isArray(items) ? items : (items && (items.reports || items.bugs || items.items || items.data)) || [];
    items = items.filter(function (bug) { return !bug.status || bug.status === 'pending'; });
    if (summary) summary.textContent = items.length + ' report' + (items.length === 1 ? '' : 's') + ' awaiting owner review';
    if (!items.length) { list.innerHTML = '<div style="text-align:center;padding:30px;color:var(--muted)">✅ No bug reports waiting for review.</div>'; return; }
    list.innerHTML = items.map(function (bug) {
      var id = bug.id || bug._id;
      return '<article style="background:var(--deep);border:1px solid var(--border);border-radius:12px;padding:14px;margin-bottom:10px">' +
        '<div style="display:flex;justify-content:space-between;gap:8px;margin-bottom:8px"><strong style="color:var(--white);font-size:13px">' + esc(bug.summary || bug.message || bug.kind || 'Bug report') + '</strong><span style="font-size:10px;color:var(--muted)">' + esc(bug.status || 'open') + '</span></div>' +
        '<div style="font-size:11px;color:var(--moon);line-height:1.7"><b>Likely cause:</b> ' + esc(bug.likelyCause || bug.cause || 'Not classified') + '<br><b>Source:</b> ' + esc(bug.source || bug.url || 'Unknown') + '<br><b>Occurrences:</b> ' + esc(bug.occurrences || bug.count || 1) + '</div>' +
        '<div style="display:flex;gap:8px;margin-top:12px"><button class="btn-approve" data-bug-decision="accept" data-bug-id="' + esc(id) + '">Accept</button><button class="btn-reject" data-bug-decision="decline" data-bug-id="' + esc(id) + '">Decline</button></div></article>';
    }).join('');
  }

  function loadBugWatch() {
    var list = document.getElementById('bug-watch-list');
    if (!window.isAdmin || !window.isAdmin() || !list) return;
    list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading bug reports…</div>';
    adminRequest('/api/admin/bugs').then(renderBugs).catch(function (error) { list.innerHTML = '<div style="color:#fca5a5;padding:14px">Unable to load bug reports: ' + esc(error.message) + '</div>'; });
  }

  function decideBug(id, decision, button) {
    if (!window.isAdmin || !window.isAdmin() || !id) return;
    button.disabled = true;
    adminRequest('/api/admin/bugs/' + encodeURIComponent(id) + '/decision', { method: 'POST', body: JSON.stringify({ decision: decision }) }).then(function () {
      if (decision === 'accept') {
        button.parentNode.innerHTML = '<span style="color:var(--green3);font-size:11px">✅ Accepted — isolated repair job queued.</span>';
      } else {
        button.parentNode.innerHTML = '<span style="color:var(--muted);font-size:11px">Closed — report declined.</span>';
      }
    }).catch(function (error) { button.disabled = false; if (typeof window.showToast === 'function') window.showToast('Bug decision failed: ' + error.message); });
  }

  function installAdminTab() {
    var tabs = document.querySelector('#modal-admin .admin-tabs');
    if (!tabs) return;
    var tab = tabs.querySelector('[data-bug-watch-tab]');
    if (!tab) {
      tab = document.createElement('button');
      tab.className = 'f-pill'; tab.type = 'button'; tab.setAttribute('data-bug-watch-tab', '1'); tab.textContent = '🐞 Bug Watch';
      tab.onclick = function () { window.switchAdminTab('bug-watch', tab); };
      tabs.appendChild(tab);
    }
    var panel = document.getElementById('admin-bug-watch');
    if (!panel) return;
    panel.addEventListener('click', function (event) {
      var button = event.target.closest('[data-bug-decision]');
      if (button) decideBug(button.getAttribute('data-bug-id'), button.getAttribute('data-bug-decision'), button);
    });
  }

  function integrateAdmin() {
    installAdminTab();
    var originalSwitch = window.switchAdminTab;
    if (typeof originalSwitch === 'function' && !originalSwitch.__bugWatchWrapped) {
      var wrappedSwitch = function (tab, btn) {
        if (tab !== 'bug-watch') return originalSwitch.apply(this, arguments);
        if (!window.isAdmin || !window.isAdmin()) return;
        document.querySelectorAll('#modal-admin .admin-tabs .f-pill').forEach(function (item) { item.classList.remove('active'); });
        if (btn) btn.classList.add('active');
        ['pending','approved','rejected','overview','security','users','bug-watch'].forEach(function (name) { var panel = document.getElementById('admin-' + name); if (panel) panel.style.display = name === tab ? 'block' : 'none'; });
        loadBugWatch();
      };
      wrappedSwitch.__bugWatchWrapped = true;
      window.switchAdminTab = wrappedSwitch;
    }
  }

  init();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', integrateAdmin); else integrateAdmin();
  setTimeout(integrateAdmin, 0);
  window.MVBugWatch = { load: loadBugWatch };
}());
