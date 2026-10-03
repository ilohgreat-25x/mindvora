/**
 * MINDVORA — ADVANCED SEARCH FIX  ·  search-fix.js
 *  • Typed text is white, with a visible caret and placeholder.
 *  • Results match anywhere in a name/handle/post, ignoring upper/lower case.
 *  • Hashtag search works with or without the leading "#".
 */
(function () {
  'use strict';
  var st = document.createElement('style');
  st.textContent =
    '#adv-search-inp{color:#fff!important;-webkit-text-fill-color:#fff!important;caret-color:#22c55e!important;background:#0f1418!important}' +
    '#adv-search-inp::placeholder{color:#9aa0a6!important;-webkit-text-fill-color:#9aa0a6!important;opacity:1}' +
    'body.light #adv-search-inp{color:#fff!important;-webkit-text-fill-color:#fff!important;background:#0f1418!important}';
  document.head.appendChild(st);

  function h(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function jsq(s) { return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); }
  var cache = { users: null, sparks: null, at: 0 };

  function load() {
    if (cache.users && Date.now() - cache.at < 60000) return Promise.resolve(cache);
    var d = window.db;
    return Promise.all([
      d.collection('users').limit(500).get().then(function (s) { return s.docs.map(function (x) { return { id: x.id, data: x.data() }; }); }).catch(function () { return []; }),
      d.collection('sparks').orderBy('createdAt', 'desc').limit(400).get().catch(function () { return d.collection('sparks').limit(400).get(); })
        .then(function (s) { return s.docs.map(function (x) { return { id: x.id, data: x.data() }; }); }).catch(function () { return []; })
    ]).then(function (r) { cache = { users: r[0], sparks: r[1], at: Date.now() }; return cache; });
  }

  window.runAdvancedSearch = function () {
    var inp = document.getElementById('adv-search-inp'), results = document.getElementById('adv-search-results');
    if (!inp || !results || !window.db) return;
    var raw = inp.value.trim(); if (!raw) { results.innerHTML = ''; return; }
    var q = raw.toLowerCase(), tagQ = q.replace(/^#/, '');
    var tab = document.querySelector('#modal-adv-search .search-tab.active');
    var type = tab ? (tab.dataset.type || 'all') : 'all';
    results.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Searching…</div>';
    load().then(function (c) {
      if (inp.value.trim().toLowerCase() !== q) return;          // user kept typing
      var out = [];
      if (type === 'all' || type === 'users') c.users.forEach(function (u) {
        var d = u.data || {}, hay = ((d.name || '') + ' ' + (d.handle || '') + ' ' + (d.bio || '')).toLowerCase();
        if (hay.indexOf(q.replace(/^@/, '')) !== -1) out.push({ t: 'user', id: u.id, d: d });
      });
      if (type === 'all' || type === 'posts') c.sparks.forEach(function (p) {
        var d = p.data || {};
        if (((d.text || '') + ' ' + (d.authorName || '') + ' ' + (d.authorHandle || '')).toLowerCase().indexOf(q) !== -1) out.push({ t: 'post', id: p.id, d: d });
      });
      if (type === 'all' || type === 'hashtags') c.sparks.forEach(function (p) {
        var d = p.data || {}, tags = (d.hashtags || []).map(function (x) { return String(x).toLowerCase().replace(/^#/, ''); });
        var inText = ((d.text || '').toLowerCase().match(/#[\w\u00c0-\uffff]+/g) || []).map(function (x) { return x.slice(1); });
        if (tags.concat(inText).some(function (x) { return x.indexOf(tagQ) === 0; }) && !out.some(function (o) { return o.id === p.id; })) out.push({ t: 'hashtag', id: p.id, d: d });
      });
      if (!out.length) { results.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">No results for "' + h(raw) + '"</div>'; return; }
      results.innerHTML = out.slice(0, 40).map(function (it) {
        var d = it.d;
        if (it.t === 'user') return '<div class="search-result-item" onclick="openProfileModal(\'' + jsq(it.id) + '\')">' +
          '<div style="width:36px;height:36px;border-radius:50%;background:' + h(d.color || 'var(--green)') + ';display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;flex-shrink:0">' + h((d.name || 'M').charAt(0)) + '</div>' +
          '<div><div style="font-size:13px;font-weight:700;color:var(--moon)">' + h(d.name || 'Mindvora user') + '</div><div style="font-size:11px;color:var(--muted)">@' + h(d.handle || 'user') + ' · 👤 User</div></div></div>';
        return '<div class="search-result-item" onclick="openComments(\'' + jsq(it.id) + '\')"><div style="font-size:20px;flex-shrink:0">' + (it.t === 'hashtag' ? '#️⃣' : '✦') + '</div>' +
          '<div><div style="font-size:12px;color:var(--moon)">' + h((d.text || '').slice(0, 100)) + '</div><div style="font-size:10px;color:var(--muted)">by @' + h(d.authorHandle || d.authorName || 'user') + '</div></div></div>';
      }).join('');
    });
  };
  // live results while typing
  document.addEventListener('input', function (e) {
    if (e.target && e.target.id === 'adv-search-inp') { clearTimeout(window.__mvSrchT); window.__mvSrchT = setTimeout(window.runAdvancedSearch, 300); }
  });
})();
