// Mindvora — real-time layer on the ONE app socket (the same one calls use).
//  • Messages land on the other person's screen the moment Send is tapped (Firestore still saves them).
//  • "<name> is typing…" in the chat header while the other person types.
//  • Online status in the chat header.
//  • Likes, follows, comments, tips, mentions… pop up instantly as they happen.
(function () {
  'use strict';
  if (window.MVRealtime || !window.MindvoraRT || !MindvoraRT.onMessage) return;
  var RT = window.MindvoraRT;
  function me() { try { return state && state.user ? state.user.uid : null; } catch (e) { return null; } }
  function profile() { try { return state.profile || {}; } catch (e) { return {}; } }
  function send(o) { try { RT.send(o); } catch (e) {} }
  function live() { return !!(RT.isConnected && RT.isConnected()); }
  function other(dmId) { var u = me(); return String(dmId || '').split('_').filter(function (x) { return x && x !== u; })[0] || null; }
  function h(t) { var d = document.createElement('div'); d.textContent = t == null ? '' : String(t); return d.innerHTML; }
  function toastMsg(t) { if (typeof showToast === 'function') showToast(t); }

  // ── instant messages ────────────────────────────────────────────────
  var origSend = window.sendMsg;
  if (typeof origSend === 'function') {
    window.sendMsg = function (dmId, otherId, otherName, otherColor) {
      var inp = document.getElementById('ci-' + dmId), text = inp ? inp.value.trim() : '';
      var r = origSend.apply(this, arguments);
      if (text && me() && otherId) {
        send({ type: 'RT_DM', to: otherId, dmId: dmId, text: text, name: profile().name || 'User', color: profile().color || '' });
        typingStop(dmId);
      }
      return r;
    };
  }
  function showIncomingDm(m) {
    var box = document.getElementById('cm-' + m.dmId);
    hideTyping(m.dmId);
    if (box) {
      // Shown at once; the saved copy replaces it a moment later when the chat refreshes.
      var el = document.createElement('div');
      el.className = 'msg';
      el.innerHTML = '<div class="msg-av" style="background:' + h(m.color || '#555') + '">' + h((m.name || 'U').charAt(0)) + '</div>' +
        '<div><div class="msg-bub">' + h(m.text) + '</div><div class="msg-t">now</div></div>';
      box.appendChild(el); box.scrollTop = box.scrollHeight;
    } else {
      toastMsg('💬 ' + (m.name || 'New message') + ': ' + String(m.text || '').slice(0, 80));
    }
  }

  // ── typing indicator ────────────────────────────────────────────────
  var lastTypingSent = {}, stopTimers = {}, hideTimers = {};
  function typingStop(dmId) {
    clearTimeout(stopTimers[dmId]);
    if (lastTypingSent[dmId]) { lastTypingSent[dmId] = 0; var o = other(dmId); if (o) send({ type: 'RT_TYPING', to: o, dmId: dmId, stop: true }); }
  }
  document.addEventListener('input', function (e) {
    var t = e.target; if (!t || !t.id || t.id.indexOf('ci-') !== 0) return;
    var dmId = t.id.slice(3), o = other(dmId); if (!o || !me()) return;
    if (!t.value.trim()) { typingStop(dmId); return; }
    var now = Date.now();
    if (now - (lastTypingSent[dmId] || 0) > 2500) { lastTypingSent[dmId] = now; send({ type: 'RT_TYPING', to: o, dmId: dmId, name: profile().name || 'User' }); }
    clearTimeout(stopTimers[dmId]); stopTimers[dmId] = setTimeout(function () { typingStop(dmId); }, 4000);
  }, true);
  document.addEventListener('blur', function (e) { var t = e.target; if (t && t.id && t.id.indexOf('ci-') === 0) typingStop(t.id.slice(3)); }, true);

  function headerFor(dmId) {
    var box = document.getElementById('cm-' + dmId); if (!box) return null;
    var right = box.parentNode, hd = right && right.querySelector('.chat-hd'); if (!hd) return null;
    var tag = document.getElementById('rt-sub-' + dmId);
    if (!tag) {
      tag = document.createElement('div'); tag.id = 'rt-sub-' + dmId;
      tag.style.cssText = 'font-size:11px;color:var(--muted,#8a8);margin-left:6px;white-space:nowrap';
      var name = hd.children[2] || hd.lastChild; name.parentNode.insertBefore(tag, name.nextSibling);
    }
    return tag;
  }
  function showTyping(m) {
    var tag = headerFor(m.dmId);
    if (!tag) return;
    tag.dataset.typing = '1'; tag.textContent = (m.name || 'They') + ' is typing…'; tag.style.color = '#2ecc71';
    clearTimeout(hideTimers[m.dmId]); hideTimers[m.dmId] = setTimeout(function () { hideTyping(m.dmId); }, 5000);
  }
  function hideTyping(dmId) {
    clearTimeout(hideTimers[dmId]);
    var tag = document.getElementById('rt-sub-' + dmId); if (!tag || !tag.dataset.typing) return;
    tag.dataset.typing = ''; tag.style.color = ''; tag.textContent = tag.dataset.presence || '';
  }

  // ── online status for the open chat ─────────────────────────────────
  var watched = null;
  function checkOpenChat() {
    var box = document.querySelector('[id^="cm-"]'); var dmId = box ? box.id.slice(3) : null;
    if (dmId && dmId !== watched) { watched = dmId; var o = other(dmId); if (o) send({ type: 'RT_PRESENCE', uids: [o], dmId: dmId }); }
    if (!dmId) watched = null;
  }
  new MutationObserver(function () { checkOpenChat(); }).observe(document.documentElement, { childList: true, subtree: true });
  setInterval(function () { if (watched) { var o = other(watched); if (o) send({ type: 'RT_PRESENCE', uids: [o], dmId: watched }); } }, 30000);
  function showPresence(m) {
    if (!m.dmId) return; var o = other(m.dmId); var tag = headerFor(m.dmId); if (!tag || !o) return;
    tag.dataset.presence = m.online && m.online[o] ? '● Online' : '';
    if (!tag.dataset.typing) { tag.textContent = tag.dataset.presence; tag.style.color = ''; }
  }

  // ── live notifications (likes, follows, comments, tips, mentions…) ──
  var ICON = { like: '❤️', comment: '💬', follow: '➕', tip: '💝', gift: '🎁', repost: '🔁', share: '🔁', save: '🔖', mention: '📣', referral: '🎉', live: '🔴', missed_call: '📵' };
  function showNotif(m) {
    if (m.ntype === 'dm' || m.ntype === 'call') return; // messages/calls have their own live display
    toastMsg((ICON[m.ntype] || '🔔') + ' ' + (m.text || 'New notification'));
    var dot = document.getElementById('nd'); if (dot) dot.style.display = 'block';
  }

  RT.onMessage(function (m) {
    switch (m.type) {
      case 'RT_DM': showIncomingDm(m); break;
      case 'RT_TYPING': if (m.stop) hideTyping(m.dmId); else showTyping(m); break;
      case 'RT_PRESENCE': showPresence(m); break;
      case 'RT_NOTIF': showNotif(m); break;
      case 'RT_EVENT': try { document.dispatchEvent(new CustomEvent('mv:rt', { detail: m })); } catch (e) {} break;
    }
  });
  window.MVRealtime = { live: live, send: send };
})();
