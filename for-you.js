/**
 * MINDVORA — FOR YOU (personalised feed)  ·  for-you.js
 *
 * Learns what each user enjoys from what they DO, then ranks the "All" feed for them:
 *   • watch time / dwell time on each post (how long it stays on screen)
 *   • video completion and re-watches (a loop or replay counts as a re-watch)
 *   • likes, comments, saves, shares, reposts
 *   • quick scroll-pasts count as a weak "not interested"
 *
 * What gets learned: affinity scores per creator, category, hashtag and media type,
 * which slowly fade (half-life ~14 days) so the feed follows changing tastes.
 * Stored in the user's own doc  user_interests/{uid}  (only they can read/write it)
 * plus localStorage for instant ranking on reload.
 *
 * Ranking = interest match + engagement quality + freshness − already-seen penalty,
 * with ~20% exploration (new creators/topics) so the feed never collapses into a bubble.
 * window.mvResetInterests() wipes the profile (wire it to a "Reset recommendations" button).
 */
(function () {
  'use strict';
  if (window.__mvForYou) return; window.__mvForYou = true;

  var HALF_LIFE_DAYS = 14, EXPLORE = 0.2, SAVE_EVERY_MS = 20000;
  var W = { view: 0.3, dwell: 0.15 /* per second, capped */, complete: 2, rewatch: 3,
            like: 3, comment: 4, save: 5, share: 6, repost: 5, skip: -0.6 };

  function S() { return window.state || (typeof state !== 'undefined' ? state : null); }
  function uid() { var s = S(); return s && s.user && s.user.uid; }
  function db_() { try { return firebase.firestore(); } catch (e) { return null; } }
  var LS = function () { return 'mv_interests_' + (uid() || 'anon'); };

  // ── Profile ──────────────────────────────────────────────────────────
  var prof = null, dirty = false, seen = {};
  function blank() { return { a: {}, c: {}, h: {}, m: {}, updated: Date.now(), events: 0 }; }
  function load() {
    try { prof = JSON.parse(localStorage.getItem(LS()) || 'null'); } catch (e) {}
    if (!prof || !prof.a) prof = blank();
    try { seen = JSON.parse(localStorage.getItem(LS() + '_seen') || '{}'); } catch (e) { seen = {}; }
    var d = db_(), u = uid();
    if (d && u) d.collection('user_interests').doc(u).get().then(function (doc) {
      if (doc.exists && doc.data().p && (doc.data().p.updated || 0) > (prof.updated || 0)) { prof = doc.data().p; rerank(); }
    }).catch(function () {});
  }
  function decay() {
    var days = (Date.now() - (prof.updated || Date.now())) / 864e5; if (days < 0.04) return;
    var f = Math.pow(0.5, days / HALF_LIFE_DAYS);
    ['a', 'c', 'h', 'm'].forEach(function (k) {
      var o = prof[k]; Object.keys(o).forEach(function (x) { o[x] *= f; if (Math.abs(o[x]) < 0.05) delete o[x]; });
      // keep the profile small
      var keys = Object.keys(o); if (keys.length > 300) keys.sort(function (p, q) { return Math.abs(o[q]) - Math.abs(o[p]); }).slice(300).forEach(function (x) { delete o[x]; });
    });
    prof.updated = Date.now();
  }
  function feats(s) {
    var tags = (s.hashtags || []).slice(0, 8);
    if (!tags.length) (String(s.text || '').match(/#[\w\u00C0-\uFFFF]+/g) || []).slice(0, 8).forEach(function (t) { tags.push(t.slice(1).toLowerCase()); });
    return { a: s.authorId || s.uid || '', c: s.category || 'all', h: tags.map(function (t) { return String(t).toLowerCase(); }), m: s.mediaType || 'text' };
  }
  function find(id) { var s = S(); return s && (s.sparks || []).filter(function (x) { return x.id === id; })[0]; }
  function learn(id, kind, amount) {
    if (!prof || !id) return; var sp = find(id); if (!sp) return;
    if ((sp.authorId || sp.uid) === uid()) return; // own posts teach nothing
    decay();
    var w = (W[kind] || 0) * (amount == null ? 1 : amount), f = feats(sp);
    if (f.a) prof.a[f.a] = (prof.a[f.a] || 0) + w;
    prof.c[f.c] = (prof.c[f.c] || 0) + w * 0.6;
    prof.m[f.m] = (prof.m[f.m] || 0) + w * 0.4;
    f.h.forEach(function (t) { prof.h[t] = (prof.h[t] || 0) + w * 0.5; });
    prof.events = (prof.events || 0) + 1; dirty = true;
  }
  function persist(force) {
    if (!dirty && !force) return; dirty = false;
    try { localStorage.setItem(LS(), JSON.stringify(prof)); localStorage.setItem(LS() + '_seen', JSON.stringify(seen)); } catch (e) {}
    var d = db_(), u = uid();
    if (d && u) d.collection('user_interests').doc(u).set({ p: prof, uid: u, updatedAt: firebase.firestore.FieldValue.serverTimestamp() }).catch(function () {});
  }
  setInterval(persist, SAVE_EVERY_MS);
  document.addEventListener('visibilitychange', function () { if (document.hidden) persist(); });

  // ── Ranking ──────────────────────────────────────────────────────────
  function sq(x) { return x > 0 ? Math.log1p(x) : -Math.log1p(-x); }
  function score(s) {
    var f = feats(s), interest = 0;
    interest += sq(prof.a[f.a] || 0) * 1.6 + sq(prof.c[f.c] || 0) + sq(prof.m[f.m] || 0) * 0.6;
    f.h.forEach(function (t) { interest += sq(prof.h[t] || 0) * 0.7; });
    var eng = Math.log1p((s.likes || []).length + 2 * (s.commentCount || 0) + 3 * (s.reposts || 0) + 3 * (s.shares || 0) + 2 * (s.saved || []).length + (s.viewCount || 0) * 0.05);
    var t = s.createdAt && s.createdAt.toMillis ? s.createdAt.toMillis() : Date.now();
    var ageH = Math.max(0, (Date.now() - t) / 36e5);
    var fresh = 3 / (1 + ageH / 24);
    var seenPen = seen[s.id] ? Math.min(4, seen[s.id]) * 1.2 : 0;
    try { if (typeof isFollowing === 'function' && f.a && isFollowing(f.a)) interest += 1.5; } catch (e) {}
    return interest * 1.4 + eng * 0.8 + fresh - seenPen + (s.pinned ? 0.5 : 0);
  }
  function rank(list) {
    if (!prof || (prof.events || 0) < 3) return list; // brand-new users: keep the normal latest-first feed
    var scored = list.map(function (s, i) { return { s: s, v: score(s) + Math.random() * 0.4, i: i }; });
    scored.sort(function (p, q) { return q.v - p.v; });
    // Exploration: every 5th slot goes to an unseen post from a creator the user hasn't engaged with.
    var out = [], explore = scored.filter(function (x) { var a = feats(x.s).a; return !prof.a[a] && !seen[x.s.id]; });
    var used = {};
    for (var k = 0; out.length < scored.length; k++) {
      var pick = null;
      if (out.length % Math.round(1 / EXPLORE) === Math.round(1 / EXPLORE) - 1) {
        while (explore.length && used[explore[0].s.id]) explore.shift();
        if (explore.length) pick = explore.shift();
      }
      if (!pick) { while (scored.length && used[scored[0].s.id]) scored.shift(); pick = scored.shift(); }
      if (!pick) break; used[pick.s.id] = 1; out.push(pick.s);
    }
    return out;
  }
  var ranking = false;
  function rerank() { try { if (typeof renderFeed === 'function') renderFeed(); } catch (e) {} }

  // ── Hooks into the existing app ──────────────────────────────────────
  function wrap(name, fn) {
    var orig = window[name]; if (typeof orig !== 'function' || orig.__mv) return false;
    var w = function () { try { fn.apply(this, arguments); } catch (e) {} return orig.apply(this, arguments); };
    w.__mv = true; window[name] = w; return true;
  }
  function hook() {
    if (typeof window.renderFeed !== 'function' || !S()) return false;
    if (!window.renderFeed.__mvr) {
      var origRender = window.renderFeed;
      window.renderFeed = function () {
        var s = S();
        if (s && s.filter === 'all' && !ranking && Array.isArray(s.sparks)) {
          // rank once per data change, not on every repaint, so cards don't jump under the user's finger
          var sig = s.sparks.map(function (x) { return x.id; }).sort().join(',');
          if (sig !== window.__mvRankSig) { window.__mvRankSig = sig; s.sparks = rank(s.sparks); }
        }
        var r = origRender.apply(this, arguments);
        setTimeout(observe, 50);
        return r;
      };
      window.renderFeed.__mvr = true;
    }
    // Bigger candidate pool so there is something to choose from (was the latest 50).
    if (typeof window.loadSparks === 'function' && !window.loadSparks.__mv) {
      window.loadSparks = function () {
        var s = S(); if (s.sparksUnsub) s.sparksUnsub();
        s.sparksUnsub = db_().collection('sparks').orderBy('createdAt', 'desc').limit(150).onSnapshot(function (snap) {
          s.sparks = snap.docs.map(function (d) { return Object.assign({ id: d.id }, d.data()); }); window.__mvRankSig = null; renderFeed();
        }, function () { try { showToast('Error loading feed'); } catch (e) {} });
      };
      window.loadSparks.__mv = true;
    }
    wrap('toggleLike', function (id) { var s = find(id); if (s && (s.likes || []).indexOf(uid()) < 0) learn(id, 'like'); else learn(id, 'like', -0.7); });
    wrap('toggleSave', function (id) { var s = find(id); if (s && (s.saved || []).indexOf(uid()) < 0) learn(id, 'save'); });
    wrap('saveSpark', function (id) { learn(id, 'save'); });
    wrap('shareSpark', function (id) { learn(id, 'share'); });
    wrap('shareSparkLink', function (id) { learn(id, 'share'); });
    wrap('shareSparkToDMFromProfile', function (id) { learn(id, 'share'); });
    wrap('repostSpark', function (id) { learn(id, 'repost'); });
    wrap('openComments', function (id) { learn(id, 'view', 2); });
    return true;
  }
  // Posting a comment
  document.addEventListener('click', function (e) {
    var b = e.target && e.target.closest && e.target.closest('#btn-cmt'); if (!b) return;
    var s = S(), inp = document.getElementById('cmt-inp');
    if (s && s.currentSparkId && inp && inp.value.trim()) { learn(s.currentSparkId, 'comment'); persist(); }
  }, true);

  // ── Watch time / dwell / video completion / re-watch ────────────────
  var vis = {}, io = null;
  function cardId(card) {
    if (card.__mvId) return card.__mvId;
    var b = card.querySelector('[onclick*="toggleLike("]'); if (!b) return null;
    var m = /toggleLike\('([^']+)'/.exec(b.getAttribute('onclick') || ''); return (card.__mvId = m && m[1]);
  }
  function leave(id) {
    var v = vis[id]; if (!v) return; delete vis[id];
    var secs = (Date.now() - v.t) / 1000;
    if (secs < 1.2) { learn(id, 'skip'); }
    else { learn(id, 'view'); learn(id, 'dwell', Math.min(secs, 60)); }
    seen[id] = (seen[id] || 0) + 1;
  }
  function observe() {
    var fc = document.getElementById('feed-cont'); if (!fc || !('IntersectionObserver' in window)) return;
    if (!io) io = new IntersectionObserver(function (ents) {
      ents.forEach(function (en) {
        var id = cardId(en.target); if (!id) return;
        if (en.isIntersecting && en.intersectionRatio >= 0.6) { if (!vis[id]) vis[id] = { t: Date.now() }; }
        else leave(id);
      });
    }, { threshold: [0, 0.6] });
    fc.querySelectorAll('.spark-card').forEach(function (card) {
      if (card.__mvObs) return; card.__mvObs = true; io.observe(card);
      var id = cardId(card);
      card.querySelectorAll('video').forEach(function (v) {
        var plays = 0, done = false;
        v.addEventListener('play', function () { plays++; if (plays > 1 || done) learn(id, 'rewatch'); });
        v.addEventListener('ended', function () { done = true; learn(id, 'complete'); });
        v.addEventListener('timeupdate', function () {
          // looping videos never fire "ended": count each wrap-around as a completion + re-watch
          if (v.loop && v.duration && v.__last > v.duration * 0.9 && v.currentTime < 1) { learn(id, 'complete'); learn(id, 'rewatch'); }
          v.__last = v.currentTime;
        });
      });
    });
  }

  window.mvResetInterests = function () {
    prof = blank(); seen = {}; persist(true); window.__mvRankSig = null; rerank();
    try { showToast('Recommendations reset — your feed will relearn from scratch'); } catch (e) {}
  };

  // "Reset recommendations" entry in the slide-out menu (under Stream Live News).
  function addMenu() {
    if (document.getElementById('mv-dr-reset-rec')) return true;
    var anchor = document.getElementById('mv-dr-news'); if (!anchor) return false;
    var b = document.createElement('button'); b.type = 'button'; b.className = 'drawer-item'; b.id = 'mv-dr-reset-rec'; b.textContent = '🔄 Reset recommendations';
    b.addEventListener('click', function () {
      try { if (typeof closeDrawer === 'function') closeDrawer(); } catch (e) {}
      if (confirm('Reset your recommendations? Your feed will start learning your taste from scratch.')) window.mvResetInterests();
    });
    anchor.parentNode.insertBefore(b, anchor.nextSibling); return true;
  }
  var mTries = 0, mT = setInterval(function () { if (addMenu() || ++mTries > 120) clearInterval(mT); }, 500);

  var tries = 0, started = false;
  var t = setInterval(function () {
    if (!started && uid() && hook()) { started = true; load(); window.__mvRankSig = null; rerank(); }
    if (started || ++tries > 240) clearInterval(t);
  }, 500);
})();
