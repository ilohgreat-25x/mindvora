/**
 * MINDVORA — CORE CHAT FEATURES  ·  chat-core.js   (always on, no update needed)
 *  • Message reactions  (tap a message → ❤️ 😂 😮 😢 🙏 👍)
 *  • Reply to a message (quoted above your reply; tap the quote to jump to it)
 *  • Copy a message
 *  • Pin chats to the top of your list (📌 in the chat header)
 *  • Drafts: an unsent message stays in the box when you leave and come back
 *  • Voice-note / audio speed: 1× → 1.5× → 2×
 * Reactions and pins are stored on the conversation document, which both people
 * in the chat can already update — no new database permissions are needed.
 */
(function () {
  'use strict';
  if (window.MVChat) return;

  var EMOJIS = ['❤️', '😂', '😮', '😢', '🙏', '👍'];
  var reply = {};          // dmId -> { id, text, name }
  var dmDocs = {};         // dmId -> latest conversation data
  var unsub = null, watched = null;

  function me() { return window.state && state.user ? state.user.uid : null; }
  function h(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function toast(t) { if (typeof showToast === 'function') showToast(t); }
  function fdb() { return window.db || (window.firebase && firebase.firestore && firebase.firestore()); }

  // ── styles ──
  var st = document.createElement('style');
  st.textContent =
    '.mv-rx{display:flex;gap:4px;flex-wrap:wrap;margin-top:3px}' +
    '.msg.mine .mv-rx{justify-content:flex-end}' +
    '.mv-rx span{background:var(--card,#1c1f24);border:1px solid rgba(255,255,255,.12);border-radius:12px;padding:1px 7px;font-size:12px;cursor:pointer;user-select:none}' +
    '.mv-rx span.on{border-color:var(--green3,#22c55e)}' +
    '.mv-bar{position:fixed;z-index:99999;display:flex;gap:2px;align-items:center;background:#111418;border:1px solid rgba(255,255,255,.15);border-radius:24px;padding:5px 8px;box-shadow:0 6px 24px rgba(0,0,0,.5)}' +
    '.mv-bar button{background:none;border:0;font-size:20px;cursor:pointer;padding:3px 4px;line-height:1;color:#fff}' +
    '.mv-bar button.tx{font-size:12px;font-weight:600;padding:4px 8px;border-left:1px solid rgba(255,255,255,.15)}' +
    '.mv-quote{font-size:11px;border-left:3px solid var(--green3,#22c55e);background:rgba(255,255,255,.06);border-radius:6px;padding:4px 8px;margin-bottom:3px;max-width:260px;cursor:pointer;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted,#9aa0a6)}' +
    '.mv-quote b{color:var(--green3,#22c55e);font-weight:600}' +
    '.mv-replybar{display:flex;align-items:center;gap:8px;padding:6px 12px;border-top:1px solid rgba(255,255,255,.08);font-size:12px;color:var(--muted,#9aa0a6)}' +
    '.mv-replybar div{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;border-left:3px solid var(--green3,#22c55e);padding-left:8px}' +
    '.mv-replybar button{background:none;border:0;color:inherit;font-size:16px;cursor:pointer}' +
    '.mv-flash .msg-bub{outline:2px solid var(--green3,#22c55e);transition:outline .3s}' +
    '.mv-pin{opacity:.55}.mv-pin.on{opacity:1}' +
    '.mv-spd{margin-left:6px;font-size:11px;font-weight:700;border-radius:10px;border:1px solid rgba(255,255,255,.2);background:rgba(0,0,0,.25);color:inherit;padding:2px 7px;cursor:pointer;vertical-align:middle}';
  document.head.appendChild(st);

  // ── watch the open conversation (reactions + pin state) ──
  function watch(dmId) {
    if (watched === dmId || !fdb()) return;
    if (unsub) { try { unsub(); } catch (e) {} }
    watched = dmId;
    unsub = fdb().collection('dms').doc(dmId).onSnapshot(function (doc) {
      dmDocs[dmId] = doc.exists ? doc.data() : {};
      paintAll();
    }, function () {});
  }

  function paintBox(box) {
    var dmId = box.id.slice(3), data = dmDocs[dmId] || {}, rx = data.rx || {}, u = me();
    box.querySelectorAll('.msg[data-mid]').forEach(function (m) {
      var mid = m.getAttribute('data-mid'), r = rx[mid] || {}, counts = {}, mine = null;
      Object.keys(r).forEach(function (k) { if (!r[k]) return; counts[r[k]] = (counts[r[k]] || 0) + 1; if (k === u) mine = r[k]; });
      var sig = JSON.stringify(counts) + '|' + (mine || '');
      var host = m.querySelector('.msg-bub'); if (!host) return;
      var el = m.querySelector('.mv-rx');
      if (el && el.getAttribute('data-sig') === sig) return;
      if (!el) { el = document.createElement('div'); el.className = 'mv-rx'; host.parentNode.insertBefore(el, host.nextSibling); }
      el.setAttribute('data-sig', sig);
      el.innerHTML = Object.keys(counts).map(function (e) {
        return '<span data-mvrx="' + h(e) + '" class="' + (e === mine ? 'on' : '') + '">' + h(e) + (counts[e] > 1 ? ' ' + counts[e] : '') + '</span>';
      }).join('');
    });
    // draft restore + reply bar + pin button
    var inp = document.getElementById('ci-' + dmId);
    if (inp && !inp._mvDraft) {
      inp._mvDraft = true;
      try { var d = localStorage.getItem('mv_draft_' + dmId); if (d && !inp.value) inp.value = d; } catch (e) {}
      inp.addEventListener('input', function () { try { if (inp.value) localStorage.setItem('mv_draft_' + dmId, inp.value); else localStorage.removeItem('mv_draft_' + dmId); } catch (e) {} });
    }
    showReplyBar(dmId);
    var right = box.closest('#dm-right') || document;
    var btns = right.querySelector('.chat-call-btns');
    if (btns) {
      var pin = btns.querySelector('.mv-pin');
      if (!pin) { pin = document.createElement('button'); pin.className = 'chat-call-btn mv-pin'; pin.title = 'Pin chat'; pin.setAttribute('aria-label', 'Pin chat'); pin.textContent = '📌'; pin.setAttribute('data-mvpin', dmId); btns.insertBefore(pin, btns.firstChild); }
      pin.classList.toggle('on', !!(u && data['pin_' + u]));
    }
  }

  function paintAll() {
    document.querySelectorAll('.chat-msgs[id^="cm-"]').forEach(function (box) { watch(box.id.slice(3)); paintBox(box); });
    document.querySelectorAll('audio[controls]').forEach(function (a) {
      if (a._mvSpd) return; a._mvSpd = true;
      var b = document.createElement('button'); b.type = 'button'; b.className = 'mv-spd'; b.textContent = '1×';
      b.addEventListener('click', function (e) { e.stopPropagation(); var r = a.playbackRate >= 2 ? 1 : (a.playbackRate >= 1.5 ? 2 : 1.5); a.playbackRate = r; b.textContent = r + '×'; });
      if (a.parentNode) a.parentNode.insertBefore(b, a.nextSibling);
    });
  }

  var queued = false;
  new MutationObserver(function () { if (queued) return; queued = true; requestAnimationFrame(function () { queued = false; try { paintAll(); } catch (e) {} }); })
    .observe(document.documentElement, { childList: true, subtree: true });
  requestAnimationFrame(function () { try { paintAll(); } catch (e) {} });   // a chat may already be open

  // ── reaction / reply bar ──
  var bar = null;
  function closeBar() { if (bar) { bar.remove(); bar = null; } }
  function openBar(msgEl, x, y) {
    closeBar();
    var box = msgEl.closest('.chat-msgs'), dmId = box.id.slice(3), mid = msgEl.getAttribute('data-mid');
    var bub = msgEl.querySelector('.msg-bub'), text = bub ? bub.textContent : '';
    var mineMsg = msgEl.classList.contains('mine');
    var nameEl = document.querySelector('#dm-right .chat-hd > div:nth-child(3)');
    var name = mineMsg ? 'You' : (nameEl ? nameEl.textContent : 'Them');
    bar = document.createElement('div'); bar.className = 'mv-bar';
    bar.innerHTML = EMOJIS.map(function (e) { return '<button data-e="' + e + '">' + e + '</button>'; }).join('') +
      '<button class="tx" data-a="reply">↩ Reply</button><button class="tx" data-a="copy">Copy</button>';
    document.body.appendChild(bar);
    var w = bar.offsetWidth, hh = bar.offsetHeight;
    bar.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, x - w / 2)) + 'px';
    bar.style.top = Math.max(8, y - hh - 12) + 'px';
    bar.addEventListener('click', function (ev) {
      ev.stopPropagation();
      var t = ev.target.closest('button'); if (!t) return;
      if (t.getAttribute('data-e')) react(dmId, mid, t.getAttribute('data-e'));
      else if (t.getAttribute('data-a') === 'reply') setReply(dmId, { id: mid, text: text.slice(0, 140), name: name });
      else if (t.getAttribute('data-a') === 'copy') { try { navigator.clipboard.writeText(text); toast('Copied'); } catch (e) {} }
      closeBar();
    });
  }

  function react(dmId, mid, emoji) {
    var u = me(); if (!u || !fdb()) return;
    var cur = ((dmDocs[dmId] || {}).rx || {})[mid] || {};
    var upd = {}; upd['rx.' + mid + '.' + u] = cur[u] === emoji ? firebase.firestore.FieldValue.delete() : emoji;
    fdb().collection('dms').doc(dmId).update(upd).catch(function () { toast('Could not react — check your connection'); });
  }

  function setReply(dmId, r) {
    reply[dmId] = r; showReplyBar(dmId);
    var inp = document.getElementById('ci-' + dmId); if (inp) inp.focus();
  }
  function showReplyBar(dmId) {
    var inp = document.getElementById('ci-' + dmId); if (!inp) return;
    var cb = inp.closest('.chat-bar'); if (!cb) return;
    var ex = cb.parentNode.querySelector('.mv-replybar'), r = reply[dmId];
    if (!r) { if (ex) ex.remove(); return; }
    if (ex && ex.getAttribute('data-id') === r.id) return;
    if (ex) ex.remove();
    var el = document.createElement('div'); el.className = 'mv-replybar'; el.setAttribute('data-id', r.id);
    el.innerHTML = '<div>Replying to <b>' + h(r.name) + '</b>: ' + h(r.text) + '</div><button aria-label="Cancel reply">✕</button>';
    el.querySelector('button').addEventListener('click', function () { delete reply[dmId]; el.remove(); });
    cb.parentNode.insertBefore(el, cb);
  }

  document.addEventListener('click', function (e) {
    if (bar && !bar.contains(e.target)) closeBar();
    var chip = e.target.closest('.mv-rx span[data-mvrx]');
    if (chip) { var m = chip.closest('.msg[data-mid]'), bx = chip.closest('.chat-msgs'); if (m && bx) react(bx.id.slice(3), m.getAttribute('data-mid'), chip.getAttribute('data-mvrx')); return; }
    var q = e.target.closest('.mv-quote[data-to]');
    if (q) {
      var target = q.closest('.chat-msgs').querySelector('.msg[data-mid="' + q.getAttribute('data-to') + '"]');
      if (target) { target.scrollIntoView({ block: 'center', behavior: 'smooth' }); target.classList.add('mv-flash'); setTimeout(function () { target.classList.remove('mv-flash'); }, 1200); }
      else toast('That message is no longer in view');
      return;
    }
    var p = e.target.closest('[data-mvpin]');
    if (p) {
      var id = p.getAttribute('data-mvpin'), u = me(); if (!u || !fdb()) return;
      var on = !((dmDocs[id] || {})['pin_' + u]), upd = {}; upd['pin_' + u] = on;
      fdb().collection('dms').doc(id).update(upd).then(function () { toast(on ? '📌 Chat pinned to the top' : 'Chat unpinned'); if (typeof loadConversations === 'function') loadConversations(); }).catch(function () { toast('Could not pin — check your connection'); });
      return;
    }
    var bub = e.target.closest('.chat-msgs .msg[data-mid] .msg-bub');
    if (bub && !e.target.closest('a,button,audio,video,img')) {
      var sel = window.getSelection && String(window.getSelection()); if (sel) return;
      var r = bub.getBoundingClientRect();
      openBar(bub.closest('.msg'), r.left + r.width / 2, r.top);
      e.stopPropagation();
    }
  }, true);
  window.addEventListener('scroll', closeBar, true);

  window.MVChat = {
    takeReply: function (dmId) { var r = reply[dmId] || null; delete reply[dmId]; showReplyBar(dmId); return r; },
    sent: function (dmId) { try { localStorage.removeItem('mv_draft_' + dmId); } catch (e) {} },
    react: react
  };
})();
