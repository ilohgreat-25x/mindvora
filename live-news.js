/**
 * MINDVORA — STREAM LIVE NEWS + OWNER REFERRAL SWITCH  ·  live-news.js  (loaded from fixes.js)
 *
 * 1) "📰 Stream Live News" in the slide-out menu, directly under "🎬 Stream Live Anime Movies".
 *    10 official 24/7 news channels (8 international, 2 Nigerian), list served by the backend
 *    (/api/news/live) which keeps each channel's current live stream ID fresh. Played with
 *    YouTube's official embed player — the broadcasters' own streams, nothing re-hosted.
 *
 * 2) Owner-only referral ON/OFF now saves through the backend (/api/admin/referral). Firestore rules
 *    block app_settings writes from browsers, so the old toggle could never save. Turning it ON
 *    notifies every Mindvora user (in-app + push) so they can start earning from referrals.
 */
(function () {
  'use strict';
  var API = function () { return (window.BACKEND_URL || '').replace(/\/$/, ''); };
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function safeUrl(u) { return /^https:\/\//i.test(String(u || '')) ? esc(u) : '#'; }
  function toast(t) { try { showToast(t); } catch (e) {} }

  // ── LIVE NEWS ───────────────────────────────────────────────────────
  var FALLBACK = [
    ['aljazeera', 'Al Jazeera English', 'Qatar', 'world', 'UCNye-wNBqNL5ZzHSJj3l8Bg'],
    ['bbc', 'BBC News', 'United Kingdom', 'world', 'UC16niRr50-MSBwiO3YDb3RA'],
    ['sky', 'Sky News', 'United Kingdom', 'world', 'UCoMdktPbSTixAyNGwb-UYkQ'],
    ['dw', 'DW News', 'Germany', 'world', 'UCknLrEdhRCp1aegoMqRaCZg'],
    ['france24', 'FRANCE 24 English', 'France', 'world', 'UCQfwfsi5VrQ8yKZ-UWmAEFg'],
    ['euronews', 'Euronews English', 'Europe', 'world', 'UCSrZ3UV4jOidv8ppoVuvW9Q'],
    ['cna', 'CNA', 'Singapore', 'world', 'UC83jt4dlz1Gjl58fzQrrKZg'],
    ['abcau', 'ABC News Australia', 'Australia', 'world', 'UCVgO39Bk5sMo66-6o6Spn6Q'],
    ['arise', 'Arise News', 'Nigeria', 'nigeria', 'UCyEJX-kSj0kOOCS7Qlq2G7g'],
    ['channels', 'Channels Television', 'Nigeria', 'nigeria', 'UCEXGDNclvmg6RW0vipJYsTQ'],
  ].map(function (c) {
    return { id: c[0], name: c[1], country: c[2], region: c[3], live: true, title: '',
      embed: 'https://www.youtube.com/embed/live_stream?channel=' + c[4] + '&autoplay=1&playsinline=1&rel=0',
      watch: 'https://www.youtube.com/channel/' + c[4] + '/live', thumb: '' };
  });
  var channels = null, region = 'all', current = null;

  function panel() {
    var m = document.getElementById('mv-news-live'); if (m) return m;
    m = document.createElement('div'); m.id = 'mv-news-live';
    m.style.cssText = 'position:fixed;inset:0;z-index:99980;background:var(--bg,#0b0b0b);color:var(--text,#fff);display:none;flex-direction:column;font-family:inherit';
    m.innerHTML = '<div style="display:flex;align-items:center;gap:10px;padding:12px 14px;border-bottom:1px solid var(--border,rgba(255,255,255,.1))">' +
      '<button type="button" data-x style="background:none;border:0;color:inherit;font-size:20px;cursor:pointer">←</button>' +
      '<b style="flex:1;font-size:16px">📰 Live News</b><span style="font-size:11px;color:#ef4444;font-weight:700">● LIVE</span></div>' +
      '<div data-player style="background:#000;display:none"><div style="position:relative;width:100%;max-width:calc(50vh * 16 / 9);margin:0 auto;aspect-ratio:16/9"><iframe data-if title="Live news" allow="autoplay; encrypted-media; picture-in-picture; fullscreen" allowfullscreen referrerpolicy="strict-origin" style="position:absolute;inset:0;width:100%;height:100%;border:0"></iframe></div>' +
      '<div data-now style="padding:8px 12px;font-size:13px;background:var(--bg2,#111)"></div></div>' +
      '<div data-tools style="padding:8px 12px">' + [['all', 'All (10)'], ['world', '🌍 International (8)'], ['nigeria', '🇳🇬 Nigeria (2)']].map(function (r) {
        return '<button type="button" data-r="' + r[0] + '" style="margin-right:6px;padding:6px 12px;border-radius:16px;border:1px solid var(--border,rgba(255,255,255,.15));background:' + (r[0] === 'all' ? 'var(--green,#16a34a)' : 'transparent') + ';color:inherit;font-size:12px">' + r[1] + '</button>';
      }).join('') + '</div>' +
      '<div data-body style="flex:1;overflow-y:auto;padding:0 12px 24px;-webkit-overflow-scrolling:touch"></div>';
    document.body.appendChild(m);
    m.querySelector('[data-x]').onclick = function () {
      m.style.display = 'none'; document.body.style.overflow = '';
      m.querySelector('[data-if]').src = 'about:blank'; m.querySelector('[data-player]').style.display = 'none'; current = null;
    };
    m.querySelectorAll('[data-r]').forEach(function (b) {
      b.onclick = function () { region = b.getAttribute('data-r'); m.querySelectorAll('[data-r]').forEach(function (o) { o.style.background = o === b ? 'var(--green,#16a34a)' : 'transparent'; }); list(m); };
    });
    return m;
  }

  function list(m) {
    var body = m.querySelector('[data-body]');
    var rows = (channels || FALLBACK).filter(function (c) { return region === 'all' || c.region === region; });
    body.innerHTML = rows.map(function (c) {
      var on = current === c.id;
      return '<button type="button" data-c="' + esc(c.id) + '" style="display:flex;width:100%;align-items:center;gap:12px;text-align:left;padding:10px;margin-top:8px;border-radius:12px;border:1px solid ' + (on ? 'var(--green,#16a34a)' : 'var(--border,rgba(255,255,255,.1))') + ';background:var(--bg2,rgba(255,255,255,.03));color:inherit;cursor:pointer">' +
        (c.thumb ? '<img src="' + safeUrl(c.thumb) + '" alt="" loading="lazy" style="width:96px;height:54px;object-fit:cover;border-radius:8px;flex-shrink:0">'
                 : '<div style="width:96px;height:54px;border-radius:8px;background:#222;display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0">📺</div>') +
        '<div style="flex:1;min-width:0"><div style="font-weight:700;font-size:14px">' + esc(c.name) + (on ? ' <span style="color:#22c55e;font-size:11px">▶ Playing</span>' : '') + '</div>' +
        '<div style="font-size:11px;opacity:.65">' + (c.region === 'nigeria' ? '🇳🇬 ' : '🌍 ') + esc(c.country) + (c.live ? ' · <span style="color:#ef4444">● LIVE</span>' : '') + '</div>' +
        (c.title ? '<div style="font-size:12px;opacity:.8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + esc(c.title) + '</div>' : '') + '</div></button>';
    }).join('') + '<p style="font-size:11px;opacity:.55;margin-top:14px">Official 24/7 live streams from each broadcaster, played with YouTube\'s player. Some channels may be unavailable in certain regions.</p>';
    body.querySelectorAll('[data-c]').forEach(function (b) { b.onclick = function () { play(m, b.getAttribute('data-c')); }; });
  }

  function play(m, id) {
    var c = (channels || FALLBACK).filter(function (x) { return x.id === id; })[0]; if (!c) return;
    current = id;
    m.querySelector('[data-player]').style.display = 'block';
    m.querySelector('[data-if]').src = c.embed;
    m.querySelector('[data-now]').innerHTML = '<b>' + esc(c.name) + '</b> · <span style="color:#ef4444">● LIVE</span> &nbsp;<a href="' + safeUrl(c.watch) + '" target="_blank" rel="noopener noreferrer" style="color:inherit;opacity:.7;font-size:12px">Open on YouTube ↗</a>';
    list(m);
    m.querySelector('[data-body]').scrollTop = 0;
  }

  window.openLiveNews = function () {
    var m = panel();
    m.style.display = 'flex'; document.body.style.overflow = 'hidden';
    list(m);
    fetch(API() + '/api/news/live').then(function (r) { return r.json(); }).then(function (j) {
      if (j && j.status && j.channels && j.channels.length) { channels = j.channels; if (m.style.display !== 'none') list(m); }
    }).catch(function () {});
  };

  function addMenu() {
    if (document.getElementById('mv-dr-news')) return true;
    var anime = document.getElementById('mv-dr-anime');
    if (!anime) return false;
    var b = document.createElement('button'); b.type = 'button'; b.className = 'drawer-item'; b.id = 'mv-dr-news'; b.textContent = '📰 Stream Live News';
    b.addEventListener('click', function () { try { if (typeof closeDrawer === 'function') closeDrawer(); } catch (e) {} window.openLiveNews(); });
    anime.parentNode.insertBefore(b, anime.nextSibling);
    return true;
  }
  if (!addMenu()) { var tries = 0, t = setInterval(function () { if (addMenu() || ++tries > 80) clearInterval(t); }, 250); }

  // Notification / deep link: /?action=news
  try { if (new URLSearchParams(location.search).get('action') === 'news') setTimeout(window.openLiveNews, 800); } catch (e) {}

  // ── OWNER REFERRAL SWITCH (server-side save + broadcast to every user) ──
  window.toggleReferralSystem = function () {
    if (typeof isAdmin !== 'function' || !isAdmin()) { toast('⛔ Access denied.'); return; }
    var u = window.firebase && firebase.auth && firebase.auth().currentUser;
    if (!u) { toast('Please log in again.'); return; }
    var on = !(typeof referralEnabled !== 'undefined' ? referralEnabled : true);
    if (on && !confirm('Turn the referral system ON?\n\nEvery Mindvora user will get a notification that they can now earn $1 for each friend they refer.')) return;
    toast(on ? '⏳ Turning referrals ON…' : '⏳ Turning referrals OFF…');
    u.getIdToken().then(function (tok) {
      return fetch(API() + '/api/admin/referral', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + tok }, body: JSON.stringify({ enabled: on }) });
    }).then(function (r) { return r.json().then(function (j) { if (!r.ok || !j.status) throw new Error(j.message || ('HTTP ' + r.status)); return j; }); })
      .then(function (j) {
        try { referralEnabled = j.enabled; } catch (e) {}
        window.referralEnabled = j.enabled;
        try { updateReferralUI(); } catch (e) {}
        toast(j.enabled
          ? ('✅ Referral system is ON' + (j.notifying ? ' — notifying ' + j.notifying + ' users now' : '') + '. Everyone can earn from referrals.')
          : '🔴 Referral system OFF — no new referral bonuses will be paid');
      }).catch(function (e) { toast('Error: ' + e.message); });
  };

  // Every user (not just the owner) sees the right ON/OFF banner on the Earn → Referral tab.
  function syncStatus() {
    fetch(API() + '/api/referral/status').then(function (r) { return r.json(); }).then(function (j) {
      if (!j || !j.status || j.unknown) return;
      try { referralEnabled = j.enabled; } catch (e) {}
      try { updateReferralUI(); } catch (e) {}
    }).catch(function () {});
  }
  setTimeout(syncStatus, 3000);
})();
