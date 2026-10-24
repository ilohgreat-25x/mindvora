/**
 * MINDVORA — LIVE SPORTS + ANIME MOVIES  ·  live-hub.js
 * Talks ONLY to the Mindvora backend (/api/sports/*, /api/anime/*). No API keys live in the frontend.
 * Sports scores/status refresh every 60 s while the panel is open (server caches, so many viewers = few upstream calls).
 * Video: links to official competition sites / broadcasters and official anime streaming services only.
 */
(function () {
  'use strict';
  var API = function () { return (window.BACKEND_URL || '').replace(/\/$/, ''); };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function safeUrl(u) { return /^https:\/\//i.test(String(u || '')) ? esc(u) : '#'; }
  function getJSON(path) {
    var ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var t = ctl ? setTimeout(function () { ctl.abort(); }, 15000) : null;
    return fetch(API() + path, { signal: ctl ? ctl.signal : undefined }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { if (t) clearTimeout(t); if (!r.ok || !j.status) throw new Error(j.message || ('HTTP ' + r.status)); return j; });
    }, function (e) { if (t) clearTimeout(t); throw e; });
  }

  function panel(id, title) {
    var m = document.getElementById(id); if (m) return m;
    m = document.createElement('div'); m.id = id;
    m.style.cssText = 'position:fixed;inset:0;z-index:99980;background:var(--bg,#0b0b0b);color:var(--text,#fff);display:none;flex-direction:column;font-family:inherit';
    m.innerHTML = '<div style="display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid var(--border,rgba(255,255,255,.1))">' +
      '<button type="button" data-x style="background:none;border:0;color:inherit;font-size:20px;cursor:pointer">←</button>' +
      '<b style="flex:1;font-size:16px">' + esc(title) + '</b><span data-meta style="font-size:11px;opacity:.6"></span></div>' +
      '<div data-tools style="padding:8px 12px"></div><div data-body style="flex:1;overflow-y:auto;padding:0 12px 24px;-webkit-overflow-scrolling:touch"></div>';
    document.body.appendChild(m);
    m.querySelector('[data-x]').onclick = function () { close(m); };
    return m;
  }
  function open(m) { m.style.display = 'flex'; document.body.style.overflow = 'hidden'; }
  function close(m) { m.style.display = 'none'; document.body.style.overflow = ''; if (m._onClose) m._onClose(); }
  function msg(icon, h, p) { return '<div class="feed-empty" style="text-align:center;padding:40px 10px"><div style="font-size:36px">' + icon + '</div><h3>' + esc(h) + '</h3><p style="opacity:.7">' + esc(p || '') + '</p></div>'; }

  // ── ALL SPORTS ───────────────────────────────────────────────────────
  var sportTimer = null, sportDate = null, selectedSport = 'soccer', sportCatalog = [
    { id: 'soccer', name: 'Soccer' }, { id: 'american-football', name: 'American Football' },
    { id: 'basketball', name: 'Basketball' }, { id: 'baseball', name: 'Baseball' },
    { id: 'cricket', name: 'Cricket' }, { id: 'cycling', name: 'Cycling' },
    { id: 'golf', name: 'Golf' }, { id: 'hockey', name: 'Ice Hockey' },
    { id: 'rugby', name: 'Rugby' }, { id: 'tennis', name: 'Tennis' },
    { id: 'combat-sports', name: 'Combat Sports' }, { id: 'motorsport', name: 'Motorsport' }
  ];
  function dstr(off) { var d = new Date(Date.now() + off * 86400000); return d.toISOString().slice(0, 10); }
  function statusLabel(m) { return m.live ? '<span style="color:#ef4444;font-weight:700">● LIVE</span>' : esc(m.statusLabel || new Date(m.date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })); }
  function score(v) { return v == null ? '–' : esc(v); }
  function eventCard(m) {
    var watch = (m.watch || []).map(function (w) { return '<a href="' + safeUrl(w.url) + '" target="_blank" rel="noopener noreferrer" style="font-size:11px;color:var(--green,#22c55e);margin-right:10px">' + esc(w.name) + ' ↗</a>'; }).join('');
    return '<div style="border:1px solid var(--border,rgba(255,255,255,.1));border-radius:12px;padding:10px 12px;margin-top:8px">' +
      '<div style="display:flex;justify-content:space-between;font-size:11px;opacity:.7;margin-bottom:6px"><span>' + esc(m.league) + '</span><span>' + statusLabel(m) + '</span></div>' +
      '<div style="display:flex;align-items:center;gap:8px"><img src="' + safeUrl(m.home && m.home.logo) + '" alt="" style="width:22px;height:22px;object-fit:contain" onerror="this.style.visibility=\'hidden\'"><span style="flex:1">' + esc(m.home && m.home.name) + '</span><b>' + score(m.home && m.home.score) + '</b></div>' +
      '<div style="display:flex;align-items:center;gap:8px;margin-top:4px"><img src="' + safeUrl(m.away && m.away.logo) + '" alt="" style="width:22px;height:22px;object-fit:contain" onerror="this.style.visibility=\'hidden\'"><span style="flex:1">' + esc(m.away && m.away.name) + '</span><b>' + score(m.away && m.away.score) + '</b></div>' +
      '<div style="margin-top:8px">' + watch + '</div></div>';
  }
  function loadSports(m, quiet) {
    var body = m.querySelector('[data-body]'), meta = m.querySelector('[data-meta]');
    if (!quiet) body.innerHTML = msg('🏟️', 'Loading ' + (sportCatalog.filter(function (s) { return s.id === selectedSport; })[0] || {}).name + '…');
    getJSON('/api/sports/events?sport=' + encodeURIComponent(selectedSport) + '&date=' + sportDate).then(function (d) {
      meta.textContent = 'Updated ' + new Date(d.fetchedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + (d.stale ? ' (delayed)' : '');
      if (!d.events.length) { body.innerHTML = msg('📅', 'No events on this day', 'Try another sport or date.'); return; }
      var head = d.live ? '<div style="margin-top:8px;font-size:12px;color:#ef4444;font-weight:700">' + d.live + ' live now</div>' : '';
      body.innerHTML = head + d.events.map(eventCard).join('') + '<p style="font-size:11px;opacity:.55;margin-top:14px">Scores and schedules: ESPN public feeds. Mindvora does not host sports video. Use official broadcaster links where available in your region.</p>';
    }).catch(function (e) { if (!quiet) body.innerHTML = msg('⚠️', 'Sports are unavailable right now', e.message); });
  }
  window.openLiveSports = function () {
    var m = panel('mv-sports', '🏟️ Live Sports');
    sportDate = dstr(0);
    var tools = m.querySelector('[data-tools]');
    tools.innerHTML = '<select data-sport style="padding:7px 10px;border-radius:10px;border:1px solid var(--border,rgba(255,255,255,.15));background:var(--bg2,#111);color:inherit;font-size:13px;margin-bottom:8px;width:100%">' + sportCatalog.map(function (s) { return '<option value="' + esc(s.id) + '"' + (s.id === selectedSport ? ' selected' : '') + '>' + esc(s.name) + '</option>'; }).join('') + '</select>' + [[-1, 'Yesterday'], [0, 'Today'], [1, 'Tomorrow']].map(function (x) {
      return '<button type="button" data-d="' + dstr(x[0]) + '" style="margin-right:6px;padding:6px 12px;border-radius:16px;border:1px solid var(--border,rgba(255,255,255,.15));background:' + (x[0] === 0 ? 'var(--green,#16a34a)' : 'transparent') + ';color:inherit;font-size:12px">' + x[1] + '</button>'; }).join('');
    tools.querySelector('[data-sport]').onchange = function () { selectedSport = this.value; loadSports(m); };
    tools.querySelectorAll('button').forEach(function (b) {
      b.onclick = function () { sportDate = b.getAttribute('data-d'); tools.querySelectorAll('button').forEach(function (o) { o.style.background = o === b ? 'var(--green,#16a34a)' : 'transparent'; }); loadSports(m); };
    });
    open(m); loadSports(m);
    clearInterval(sportTimer);
    sportTimer = setInterval(function () { if (!document.hidden && m.style.display !== 'none') loadSports(m, true); }, 60000);
    m._onClose = function () { clearInterval(sportTimer); sportTimer = null; };
  };
  window.openLiveFootball = window.openLiveSports;

  // ── ANIME MOVIES ────────────────────────────────────────────────────
  var aniSort = 'trending', aniQ = '', aniSeq = 0;
  function aniCard(a) {
    return '<button type="button" data-id="' + esc(a.id) + '" style="text-align:left;background:none;border:0;color:inherit;padding:0;cursor:pointer">' +
      '<img src="' + safeUrl(a.cover) + '" alt="" loading="lazy" style="width:100%;aspect-ratio:2/3;object-fit:cover;border-radius:10px;background:' + esc(a.color || '#222') + '">' +
      '<div style="font-size:12px;font-weight:600;margin-top:4px;line-height:1.25">' + esc(a.title) + '</div>' +
      '<div style="font-size:11px;opacity:.6">' + esc(a.year || '') + (a.score ? ' · ★ ' + esc(a.score) + '%' : '') + (a.watch && a.watch.length ? ' · ▶ ' + a.watch.length : '') + '</div></button>';
  }
  function animeEmbed(url) {
    try {
      var u = new URL(String(url || ''));
      var host = u.hostname.toLowerCase().replace(/^www\./, '');
      if (host === 'youtube.com' || host === 'youtube-nocookie.com' || host === 'youtu.be') {
        var id = host === 'youtu.be' ? u.pathname.slice(1) : u.searchParams.get('v');
        if (id && /^[\w-]{11}$/.test(id)) return 'https://www.youtube.com/embed/' + id + '?autoplay=1&playsinline=1&rel=0';
      }
    } catch (e) {}
    return '';
  }
  function loadAnime(m) {
    var body = m.querySelector('[data-body]'), seq = ++aniSeq;
    body.innerHTML = msg('🎬', 'Loading anime movies…');
    getJSON('/api/anime/movies?sort=' + aniSort + '&q=' + encodeURIComponent(aniQ)).then(function (d) {
      if (seq !== aniSeq) return;
      m.querySelector('[data-meta]').textContent = 'Source: ' + d.source;
      if (!d.items.length) { body.innerHTML = msg('🔍', 'No movies found'); return; }
      body.innerHTML = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:12px;margin-top:8px">' + d.items.map(aniCard).join('') + '</div>';
      var byId = {}; d.items.forEach(function (a) { byId[a.id] = a; });
      body.querySelectorAll('[data-id]').forEach(function (b) { b.onclick = function () { aniDetail(byId[b.getAttribute('data-id')]); }; });
    }).catch(function (e) { if (seq === aniSeq) body.innerHTML = msg('⚠️', 'Anime catalogue unavailable', e.message); });
  }
  function aniDetail(a) {
    var d = panel('mv-anime-detail', '🎬 Anime movie'); open(d);
    var body = d.querySelector('[data-body]'); d.querySelector('[data-tools]').innerHTML = '';
    function render(x) {
      var playable = (x.watch || []).map(function (w) { return { link: w, embed: animeEmbed(w.url) }; }).filter(function (w) { return !!w.embed; })[0];
      var player = playable
        ? '<div style="margin-top:10px;border-radius:12px;overflow:hidden;background:#000;box-shadow:0 4px 18px rgba(0,0,0,.35)">' +
            '<div style="position:relative;padding-top:56.25%"><iframe src="' + safeUrl(playable.embed) + '" title="' + esc(x.title) + ' official player" allow="autoplay; encrypted-media; picture-in-picture" allowfullscreen style="position:absolute;inset:0;width:100%;height:100%;border:0"></iframe></div>' +
            '<div style="padding:8px 10px;font-size:11px;color:#fff;background:#111">▶ Playing from ' + esc(playable.link.site) + ' · <a href="' + safeUrl(playable.link.url) + '" target="_blank" rel="noopener noreferrer" style="color:#86efac">Open official page ↗</a></div></div>'
        : '<div style="margin-top:10px;padding:14px;border-radius:12px;background:var(--deep,#111);border:1px solid var(--border,rgba(255,255,255,.1));font-size:12px;line-height:1.5"><b>In-app playback is not available for this title.</b><br><span style="opacity:.7">The official service does not allow its player to be embedded inside Mindvora. Choose an official service below; it will open in a new tab.</span></div>';
      var links = (x.watch || []).length
        ? x.watch.map(function (w) { return '<a href="' + safeUrl(w.url) + '" target="_blank" rel="noopener noreferrer" style="display:block;padding:12px;margin-top:8px;border-radius:10px;background:var(--green,#16a34a);color:#fff;font-weight:700;text-decoration:none">▶ Watch on ' + esc(w.site) + ' ↗</a>'; }).join('')
        : '<p style="opacity:.7">No official streaming service is listed for this title yet.</p>';
      body.innerHTML = (x.banner ? '<img src="' + safeUrl(x.banner) + '" alt="" style="width:100%;max-height:160px;object-fit:cover;border-radius:10px;margin-top:8px">' : '') +
        '<h2 style="margin:12px 0 4px">' + esc(x.title) + '</h2><div style="font-size:12px;opacity:.7">' + esc([x.year, x.durationMin ? x.durationMin + ' min' : '', (x.genres || []).join(', ')].filter(Boolean).join(' · ')) + '</div>' +
        player + '<p style="font-size:14px;line-height:1.5">' + esc(x.description) + '</p>' + links +
        '<p style="font-size:11px;opacity:.55;margin-top:14px">Links open the official service (subscription and regional availability apply). Info: <a href="' + safeUrl(x.info) + '" target="_blank" rel="noopener noreferrer" style="color:inherit">' + esc(x.source) + '</a></p>';
    }
    render(a);
    getJSON('/api/anime/' + encodeURIComponent(a.id)).then(function (r) { if (d.style.display !== 'none') render(r.item); }).catch(function () {});
  }
  window.openAnimeMovies = function () {
    var m = panel('mv-anime', '🎬 Anime Movies');
    var tools = m.querySelector('[data-tools]');
    if (!tools.firstChild) {
      tools.innerHTML = '<input data-q type="search" placeholder="Search anime movies…" style="width:100%;padding:9px 12px;border-radius:10px;border:1px solid var(--border,rgba(255,255,255,.15));background:transparent;color:inherit;font-size:15px">' +
        '<div style="margin-top:8px">' + [['trending', 'Trending'], ['popular', 'Popular'], ['top', 'Top rated'], ['new', 'Newest']].map(function (s) {
          return '<button type="button" data-s="' + s[0] + '" style="margin-right:6px;padding:6px 12px;border-radius:16px;border:1px solid var(--border,rgba(255,255,255,.15));background:' + (s[0] === aniSort ? 'var(--green,#16a34a)' : 'transparent') + ';color:inherit;font-size:12px">' + s[1] + '</button>';
        }).join('') + '</div>';
      var qt = null;
      tools.querySelector('[data-q]').oninput = function (e) { clearTimeout(qt); qt = setTimeout(function () { aniQ = e.target.value.trim(); loadAnime(m); }, 400); };
      tools.querySelectorAll('[data-s]').forEach(function (b) {
        b.onclick = function () { aniSort = b.getAttribute('data-s'); tools.querySelectorAll('[data-s]').forEach(function (o) { o.style.background = o === b ? 'var(--green,#16a34a)' : 'transparent'; }); loadAnime(m); };
      });
    }
    open(m); loadAnime(m);
  };
})();
