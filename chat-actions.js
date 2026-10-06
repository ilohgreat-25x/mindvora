// Mindvora — chat view + chat actions (loaded from fixes.js; script.js stays untouched).
// • Conversation shows the NEWEST 100 messages (it used to load the OLDEST 50 only, so once a chat passed 50
//   messages nobody saw new ones except the instant socket copy on the receiver's screen) and reuses ONE listener.
// • Chat actions (⋮ in the chat header): pin, mute, mark unread, archive, lock, clear, delete, report, block.
// • Real recordings for Sound Board 'Laugh' and 'Dog Bark'; Advanced Search typed text forced white.
(function () {
  'use strict';
  if (window.MVChatActions || typeof window.openChat !== 'function') return;
  var baseOpen = function(dmId,otherId,otherName,otherColor){ if(state.user) watchDMForScam(dmId, otherId);
// Mark all unread messages from other user as read
  if(state.user) {
    db.collection('dms').doc(dmId).collection('messages')
      .where('fromId','==',otherId)
      .where('read','==',false)
      .get().then(function(snap){
        var batch = db.batch();
        snap.docs.forEach(function(doc){
          batch.update(doc.ref, {read:true, readAt: firebase.firestore.FieldValue.serverTimestamp()});
        });
        if(!snap.empty) batch.commit().catch(function(){});
      }).catch(function(){});
  } var right=document.getElementById('dm-right'); var _wrap=right.closest('.dm-wrap'); if(_wrap) _wrap.classList.add('chat-open'); right.innerHTML='<div class="chat-hd"><button class="back-to-list" aria-label="Back" onclick="var w=this.closest(\'.dm-wrap\'); if(w) w.classList.remove(\'chat-open\')">←</button><div class="dm-av" style="background:'+(otherColor||COLORS[0])+';width:32px;height:32px">'+esc((otherName||'U').charAt(0))+'</div><div style="font-size:13px;font-weight:700;color:var(--white)">'+esc(otherName)+'</div><div class="chat-call-btns"><button class="chat-call-btn" title="Voice call" aria-label="Voice call" onclick="MVCall.start(\''+otherId+'\',\''+escJs(otherName)+'\',\'audio\')">📞</button><button class="chat-call-btn" title="Video call" aria-label="Video call" onclick="MVCall.start(\''+otherId+'\',\''+escJs(otherName)+'\',\'video\')">🎥</button></div></div><div class="chat-msgs" id="cm-'+dmId+'"></div><div class="chat-bar"><textarea class="chat-inp" id="ci-'+dmId+'" placeholder="Message…" rows="1"></textarea><button class="chat-send" onclick="sendMsg(\''+dmId+'\',\''+otherId+'\',\''+escJs(otherName)+'\',\''+escJs(otherColor||COLORS[0])+'\')">➤</button></div>'; if(window.__mvChatUnsub){ try{ window.__mvChatUnsub(); }catch(e){} } window.__mvChatUnsub=db.collection('dms').doc(dmId).collection('messages').orderBy('createdAt','desc').limit(100).onSnapshot(function(snap){ var __docs=snap.docs.slice().reverse().filter(function(d){ return window.MVChatActions?MVChatActions.visible(dmId,d):true; }); var box=document.getElementById('cm-'+dmId); if(!box) return; box.innerHTML=__docs.map(function(d){
    var m=d.data({serverTimestamps:'estimate'}), mine=m.fromId===state.user.uid;
    var col=mine?(state.profile.color||COLORS[0]):(otherColor||COLORS[0]);
    var editedTag = m.edited ? '<span class="msg-edited">(edited)</span>' : '';
    var safeText = (m.text||'').replace(/'/g,"&#39;").replace(/"/g,"&quot;");
    var actions = mine ?
      '<div class="msg-actions" style="right:0">' +
        '<button class="act-btn" data-action="edit-msg" data-dmid="'+dmId+'" data-msgid="'+d.id+'" data-text="'+safeText+'">✏️ Edit</button>' +
        '<button class="act-btn del" data-action="del-msg" data-dmid="'+dmId+'" data-msgid="'+d.id+'">🗑 Delete</button>' +
      '</div>' : '';
// Read receipts — show ticks on sender's messages
    var readReceipt = '';
    if (mine) {
      if (m.read) {
// Double blue tick — message was read
        readReceipt = '<span style="color:#22c55e;font-size:11px;margin-left:4px" title="Read">✓✓</span>';
      } else {
// Single grey tick — sent but not read
        readReceipt = '<span style="color:var(--muted);font-size:11px;margin-left:4px" title="Sent">✓</span>';
      }
    }
    var quote = (m.replyTo && m.replyTo.id) ? '<div class="mv-quote" data-to="'+esc(m.replyTo.id)+'"><b>'+esc(m.replyTo.name||'')+'</b> '+esc(m.replyTo.text||'')+'</div>' : '';
    return '<div class="msg'+(mine?' mine':'')+'" data-mid="'+d.id+'">'+
      '<div class="msg-av" style="background:'+col+'">'+
        (mine?(state.profile.name||'U').charAt(0):(otherName||'U').charAt(0))+
      '</div>'+
      '<div style="position:relative">'+
        actions+
        quote+
        '<div class="msg-bub">'+esc(m.text||'')+'</div>'+
        '<div class="msg-t">'+timeAgo(m.createdAt)+editedTag+readReceipt+'</div>'+
      '</div>'+
    '</div>';
  }).join('')||'<div style="text-align:center;padding:20px;font-size:12px;color:var(--muted)">No messages yet</div>'; box.scrollTop=box.scrollHeight; }, function(err){ console.warn('[chat] messages listener', err); }); document.getElementById('ci-'+dmId).addEventListener('keydown',function(e){ if(e.key==='Enter'&&!e.shiftKey){ e.preventDefault(); sendMsg(dmId,otherId,otherName,otherColor||COLORS[0]); } }); };
  var baseLoad = function(){ if(!state.user) return; db.collection('dms').where('members','array-contains',state.user.uid).limit(20).get().then(function(snap){ var list=document.getElementById('dm-list'); list.innerHTML=''; if(!snap.docs.length){ list.innerHTML='<div style="padding:20px;text-align:center;font-size:12px;color:var(--muted)">No conversations yet</div>'; return; } snap.docs.slice().sort(function(a,b){ var k='pin_'+state.user.uid; return (b.data()[k]?1:0)-(a.data()[k]?1:0); }).forEach(function(d){ var dm=d.data(),oid=dm.members.find(function(m){ return m!==state.user.uid; }),oname=dm.names?dm.names[oid]:'User',ocolor=dm.colors?dm.colors[oid]:COLORS[0]; if(window.MVChatActions && !MVChatActions.listed(d.id,dm)) return; var row=document.createElement('div'); row.className='dm-row'; row.innerHTML='<div class="dm-av" style="background:'+ocolor+'">'+esc(oname.charAt(0).toUpperCase())+'</div><div style="flex:1;min-width:0"><div class="dm-nm">'+esc(oname)+(dm['pin_'+state.user.uid]?' 📌':'')+(window.MVChatActions?MVChatActions.badges(dm):'')+'</div><div class="dm-pv">'+esc(dm.lastMsg||'')+'</div></div>'+(dm.unread?'<div class="dm-ud"></div>':''); row.addEventListener('click',function(){ openChat(d.id,oid,oname,ocolor); }); list.appendChild(row); }); if(window.MVChatActions) MVChatActions.afterList(list, snap); }).catch(function(err){ console.warn('[chat] conversations', err); }); };
  // ── state ────────────────────────────────────────────────────────────
  function me() { return window.state && state.user ? state.user.uid : null; }
  function fdb() { return window.db; }
  function toast(t) { if (typeof showToast === 'function') showToast(t); }
  function hx(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function other(dmId) { var u = me(); return String(dmId || '').split('_').filter(function (x) { return x && x !== u; })[0] || null; }
  function ts(v) { return v && v.toMillis ? v.toMillis() : (v ? +new Date(v) : 0); }
  function SV() { return firebase.firestore.FieldValue.serverTimestamp(); }
  var docs = {}, watchers = {}, unlocked = {}, blockedMe = {}, showArchived = false, cur = null;

  function watchDm(dmId) {
    if (watchers[dmId] || !fdb()) return;
    watchers[dmId] = fdb().collection('dms').doc(dmId).onSnapshot(function (d) { docs[dmId] = d.exists ? d.data() : {}; refreshHeader(dmId); }, function () {});
  }
  function ready(dmId) {
    if (docs[dmId]) return Promise.resolve(docs[dmId]);
    return fdb().collection('dms').doc(dmId).get().then(function (d) { docs[dmId] = d.exists ? d.data() : {}; return docs[dmId]; }).catch(function () { return {}; });
  }
  function iBlocked(uid) { return !!(uid && window.state && state.profile && (state.profile.blockedUsers || []).indexOf(uid) !== -1); }
  function checkBlockedMe(uid) {
    if (!uid || !fdb()) return Promise.resolve(false);
    return fdb().collection('users').doc(uid).get().then(function (d) {
      blockedMe[uid] = !!(d.exists && (d.data().blockedUsers || []).indexOf(me()) !== -1); return blockedMe[uid];
    }).catch(function () { return !!blockedMe[uid]; });
  }
  function pairBlocked(uid) { return iBlocked(uid) || !!blockedMe[uid]; }
  function upd(dmId, obj) {
    var d = docs[dmId] || {};
    if (!d.members) obj.members = String(dmId).split('_');
    return fdb().collection('dms').doc(dmId).set(obj, { merge: true }).then(function () { docs[dmId] = Object.assign({}, d, obj); });
  }
  function key(k) { return k + '_' + me(); }

  // ── small dialog (choice list / text / password) ─────────────────────
  function dialog(o) {
    return new Promise(function (resolve) {
      var ov = document.createElement('div');
      ov.style.cssText = 'position:fixed;inset:0;z-index:100000;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;padding:16px';
      var opts = (o.options || []).map(function (x, i) {
        return '<label style="display:flex;gap:8px;align-items:center;padding:8px 4px;color:#e6f4ea;font-size:14px;cursor:pointer"><input type="radio" name="mvdlg" value="' + i + '"' + (i === 0 ? ' checked' : '') + '> ' + hx(x) + '</label>';
      }).join('');
      ov.innerHTML = '<div style="background:#0f1418;border:1px solid #1f2a30;border-radius:16px;max-width:360px;width:100%;padding:16px;color:#e6f4ea">' +
        '<div style="font-weight:700;font-size:15px;margin-bottom:8px">' + hx(o.title) + '</div>' +
        (o.text ? '<div style="font-size:13px;color:#9aa0a6;margin-bottom:8px">' + hx(o.text) + '</div>' : '') + opts +
        (o.input ? '<input id="mvdlg-in" type="' + (o.input === 'password' ? 'password' : 'text') + '" inputmode="' + (o.numeric ? 'numeric' : 'text') + '" placeholder="' + hx(o.placeholder || '') + '" style="width:100%;box-sizing:border-box;margin-top:6px;padding:10px;border-radius:10px;border:1px solid #2a3a40;background:#0b0f12;color:#fff;-webkit-text-fill-color:#fff;font-size:14px' + (o.options ? ';display:none' : '') + '">' : '') +
        '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px"><button data-x="0" style="padding:8px 14px;border-radius:10px;border:1px solid #2a3a40;background:transparent;color:#e6f4ea">Cancel</button>' +
        '<button data-x="1" style="padding:8px 14px;border-radius:10px;border:none;background:' + (o.danger ? '#dc2626' : '#16a34a') + ';color:#fff;font-weight:700">' + hx(o.ok || 'OK') + '</button></div></div>';
      document.body.appendChild(ov);
      var inp = ov.querySelector('#mvdlg-in');
      if (o.options && inp) ov.addEventListener('change', function () { var r = ov.querySelector('input[name=mvdlg]:checked'); inp.style.display = (r && +r.value === o.options.length - 1 && o.otherText) ? 'block' : 'none'; });
      if (inp && !o.options) setTimeout(function () { inp.focus(); }, 50);
      ov.addEventListener('click', function (e) {
        var b = e.target.closest('button[data-x]'); if (!b && e.target !== ov) return;
        var okd = b && b.getAttribute('data-x') === '1', r = ov.querySelector('input[name=mvdlg]:checked');
        ov.remove();
        if (!okd) return resolve(null);
        resolve({ choice: r ? +r.value : -1, label: r ? o.options[+r.value] : null, value: inp ? inp.value.trim() : '' });
      });
    });
  }

  // ── chat lock ────────────────────────────────────────────────────────
  function sha(s) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)).then(function (b) { return Array.prototype.map.call(new Uint8Array(b), function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); });
  }
  function pinKey() { return 'mv_chatpin_' + me(); }
  function setPin() {
    return dialog({ title: 'Set a chat lock PIN', text: '4–8 digits. You will need it to open locked chats on this device.', input: 'password', numeric: true, placeholder: 'New PIN', ok: 'Save PIN' }).then(function (r) {
      if (!r) return false;
      if (!/^\d{4,8}$/.test(r.value)) { toast('PIN must be 4–8 digits'); return false; }
      return sha(me() + ':' + r.value).then(function (hsh) { try { localStorage.setItem(pinKey(), hsh); } catch (e) {} return true; });
    });
  }
  function verifyOwner(title) {
    var saved = null; try { saved = localStorage.getItem(pinKey()); } catch (e) {}
    if (saved) {
      return dialog({ title: title, input: 'password', numeric: true, placeholder: 'Chat lock PIN', ok: 'Unlock' }).then(function (r) {
        if (!r) return false;
        return sha(me() + ':' + r.value).then(function (hsh) { if (hsh === saved) return true; toast('Wrong PIN'); return false; });
      });
    }
    // No PIN on this device: prove it is the account owner by signing in again.
    var u = firebase.auth().currentUser; if (!u) return Promise.resolve(false);
    var google = (u.providerData || []).some(function (p) { return p.providerId === 'google.com'; });
    if (google && !(u.providerData || []).some(function (p) { return p.providerId === 'password'; })) {
      return u.reauthenticateWithPopup(new firebase.auth.GoogleAuthProvider()).then(function () { return true; }).catch(function () { toast('Could not confirm it is you'); return false; });
    }
    return dialog({ title: title, text: 'Enter your Mindvora account password.', input: 'password', placeholder: 'Password', ok: 'Unlock' }).then(function (r) {
      if (!r || !r.value) return false;
      return u.reauthenticateWithCredential(firebase.auth.EmailAuthProvider.credential(u.email, r.value)).then(function () { return true; }).catch(function () { toast('Wrong password'); return false; });
    });
  }

  // ── actions ──────────────────────────────────────────────────────────
  var BLOCK_REASONS = ['Harassment', 'Spam', 'Inappropriate behavior', 'Fake account', 'Unwanted contact', 'Other'];
  var REPORT_REASONS = ['Harassment', 'Spam', 'Inappropriate behavior', 'Fake account', 'Scam or fraud', 'Other'];
  function backToList() {
    var right = document.getElementById('dm-right'), w = right && right.closest('.dm-wrap');
    if (w) w.classList.remove('chat-open');
    if (right) right.innerHTML = '';
    if (window.__mvChatUnsub) { try { window.__mvChatUnsub(); } catch (e) {} window.__mvChatUnsub = null; }
    if (typeof loadConversations === 'function') loadConversations();
  }
  function reopen() { if (cur) window.openChat(cur.dmId, cur.otherId, cur.otherName, cur.otherColor); }
  function fail(what) { return function (e) { console.warn('[chat-actions]', what, e); toast('Could not ' + what + ' — ' + (e && e.code === 'permission-denied' ? 'not allowed' : 'check your connection')); }; }

  function doBlock(dmId, uid, name) {
    return dialog({ title: 'Block ' + (name || 'this user') + '?', text: 'They will not be able to message or call you. Why are you blocking them?', options: BLOCK_REASONS, input: 'text', otherText: true, placeholder: 'Tell us more (required for Other)', ok: 'Block', danger: true }).then(function (r) {
      if (!r) return;
      if (r.label === 'Other' && !r.value) { toast('Please type a reason'); return; }
      return fdb().collection('users').doc(me()).update({ blockedUsers: firebase.firestore.FieldValue.arrayUnion(uid) }).then(function () {
        state.profile.blockedUsers = (state.profile.blockedUsers || []).filter(function (x) { return x !== uid; }).concat([uid]);
        fdb().collection('reports').add({ reporterUid: me(), reportedUid: uid, kind: 'block', context: 'chat', dmId: dmId, reason: r.label, details: r.label === 'Other' ? r.value.slice(0, 500) : '', createdAt: SV() }).catch(function () {});
        toast('🚫 ' + (name || 'User') + ' blocked'); reopen();
      }).catch(fail('block'));
    });
  }
  function doUnblock(uid, name) {
    return fdb().collection('users').doc(me()).update({ blockedUsers: firebase.firestore.FieldValue.arrayRemove(uid) }).then(function () {
      state.profile.blockedUsers = (state.profile.blockedUsers || []).filter(function (x) { return x !== uid; });
      toast('✅ ' + (name || 'User') + ' unblocked'); reopen();
    }).catch(fail('unblock'));
  }
  function doReport(dmId, uid, name) {
    return dialog({ title: 'Report ' + (name || 'this user'), options: REPORT_REASONS, input: 'text', otherText: true, placeholder: 'Describe the problem (required for Other)', ok: 'Report', danger: true }).then(function (r) {
      if (!r) return;
      if (r.label === 'Other' && !r.value) { toast('Please describe the problem'); return; }
      return fdb().collection('reports').add({ reporterUid: me(), reportedUid: uid, kind: 'user', context: 'chat', dmId: dmId, reason: r.label, details: r.value.slice(0, 500), createdAt: SV() })
        .then(function () { toast('🚩 Report sent. Our team will review it.'); }).catch(fail('send the report'));
    });
  }
  function act(a, dmId) {
    var d = docs[dmId] || {}, uid = other(dmId), name = cur && cur.dmId === dmId ? cur.otherName : 'User', o = {};
    switch (a) {
      case 'pin': o[key('pin')] = !d[key('pin')]; return upd(dmId, o).then(function () { toast(o[key('pin')] ? '📌 Chat pinned' : 'Chat unpinned'); }).catch(fail('pin'));
      case 'mute': o[key('muted')] = !d[key('muted')]; return upd(dmId, o).then(function () { toast(o[key('muted')] ? '🔕 Chat muted' : '🔔 Chat unmuted'); }).catch(fail('mute'));
      case 'unread': o[key('unread')] = true; return upd(dmId, o).then(function () { toast('📩 Marked as unread'); backToList(); }).catch(fail('mark as unread'));
      case 'archive': o[key('archived')] = !d[key('archived')]; return upd(dmId, o).then(function () { toast(o[key('archived')] ? '🗂 Chat archived' : 'Chat moved back to your inbox'); backToList(); }).catch(fail('archive'));
      case 'lock':
        if (d[key('locked')]) return verifyOwner('Remove chat lock').then(function (ok) { if (!ok) return; o[key('locked')] = false; return upd(dmId, o).then(function () { toast('🔓 Chat unlocked'); }); }).catch(fail('unlock'));
        var has = null; try { has = localStorage.getItem(pinKey()); } catch (e) {}
        return (has ? Promise.resolve(true) : setPin()).then(function (ok) { if (!ok) return; o[key('locked')] = true; unlocked[dmId] = true; return upd(dmId, o).then(function () { toast('🔒 Chat locked'); }); }).catch(fail('lock'));
      case 'clear':
        return dialog({ title: 'Clear this chat?', text: 'All messages will be removed from your view. ' + name + ' will still see them.', ok: 'Clear', danger: true }).then(function (r) {
          if (!r) return; o[key('cleared')] = SV(); return upd(dmId, o).then(function () { docs[dmId][key('cleared')] = { toMillis: function () { return Date.now(); } }; toast('🧹 Chat cleared'); reopen(); });
        }).catch(fail('clear'));
      case 'delete':
        return dialog({ title: 'Delete this chat?', text: 'It disappears from your list and messages are removed from your view. It comes back only if a new message arrives.', ok: 'Delete', danger: true }).then(function (r) {
          if (!r) return; o[key('cleared')] = SV(); o[key('deleted')] = SV(); o[key('archived')] = false; o[key('pin')] = false;
          return upd(dmId, o).then(function () { docs[dmId][key('deleted')] = docs[dmId][key('cleared')] = { toMillis: function () { return Date.now(); } }; toast('🗑 Chat deleted'); backToList(); });
        }).catch(fail('delete'));
      case 'report': return doReport(dmId, uid, name);
      case 'block': return iBlocked(uid) ? doUnblock(uid, name) : doBlock(dmId, uid, name);
    }
  }

  // ── header menu (⋮) ─────────────────────────────────────────────────
  var menu = null;
  function closeMenu() { if (menu) { menu.remove(); menu = null; } }
  function openMenu(btn, dmId) {
    closeMenu();
    var d = docs[dmId] || {}, uid = other(dmId);
    var items = [
      ['pin', d[key('pin')] ? '📌 Unpin chat' : '📌 Pin chat'],
      ['mute', d[key('muted')] ? '🔔 Unmute' : '🔕 Mute'],
      ['unread', '📩 Mark as unread'],
      ['archive', d[key('archived')] ? '🗂 Unarchive' : '🗂 Archive'],
      ['lock', d[key('locked')] ? '🔓 Remove lock' : '🔒 Lock chat'],
      ['clear', '🧹 Clear chat'],
      ['delete', '🗑 Delete chat'],
      ['report', '🚩 Report'],
      ['block', iBlocked(uid) ? '✅ Unblock' : '🚫 Block']
    ];
    menu = document.createElement('div');
    menu.className = 'mv-chat-menu';
    menu.style.cssText = 'position:fixed;z-index:99999;background:#0f1418;border:1px solid #1f2a30;border-radius:12px;padding:6px;min-width:190px;box-shadow:0 8px 30px rgba(0,0,0,.5)';
    menu.innerHTML = items.map(function (it) { return '<button data-mvact="' + it[0] + '" style="display:block;width:100%;text-align:left;padding:9px 12px;border:none;background:transparent;color:' + (it[0] === 'block' || it[0] === 'delete' || it[0] === 'report' ? '#fca5a5' : '#e6f4ea') + ';font-size:13px;border-radius:8px;cursor:pointer">' + it[1] + '</button>'; }).join('');
    document.body.appendChild(menu);
    var r = btn.getBoundingClientRect();
    menu.style.top = Math.min(r.bottom + 4, window.innerHeight - menu.offsetHeight - 8) + 'px';
    menu.style.left = Math.max(8, Math.min(r.right - menu.offsetWidth, window.innerWidth - menu.offsetWidth - 8)) + 'px';
    menu.addEventListener('click', function (e) { var b = e.target.closest('[data-mvact]'); if (!b) return; closeMenu(); act(b.getAttribute('data-mvact'), dmId); });
  }
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('.mv-chat-more');
    if (b) { e.stopPropagation(); openMenu(b, b.getAttribute('data-dm')); return; }
    if (menu && !menu.contains(e.target)) closeMenu();
  }, true);

  function decorate() {
    var right = document.getElementById('dm-right'); if (!right) return;
    var box = right.querySelector('.chat-msgs[id^="cm-"]'), hd = right.querySelector('.chat-hd'); if (!box || !hd) return;
    var dmId = box.id.slice(3);
    if (!hd.querySelector('.mv-chat-more')) {
      var b = document.createElement('button');
      b.className = 'mv-chat-more'; b.setAttribute('data-dm', dmId); b.setAttribute('aria-label', 'Chat actions'); b.title = 'Chat actions'; b.textContent = '⋮';
      b.style.cssText = 'margin-left:6px;background:transparent;border:none;color:var(--moon,#e6f4ea);font-size:22px;line-height:1;padding:4px 8px;cursor:pointer';
      hd.appendChild(b);
    }
    refreshHeader(dmId);
  }
  function refreshHeader(dmId) {
    var right = document.getElementById('dm-right'); if (!right || !right.querySelector('#cm-' + dmId)) return;
    var uid = other(dmId), bar = right.querySelector('.chat-bar'), note = right.querySelector('.mv-block-note');
    var blocked = pairBlocked(uid);
    if (bar) bar.style.display = blocked ? 'none' : '';
    if (blocked && !note) {
      note = document.createElement('div'); note.className = 'mv-block-note';
      note.style.cssText = 'padding:12px;text-align:center;font-size:12px;color:#fca5a5;border-top:1px solid var(--border,#1f2a30)';
      (bar ? bar.parentNode : right).appendChild(note);
    }
    if (note) { if (blocked) note.textContent = iBlocked(uid) ? 'You blocked this user. Open ⋮ → Unblock to message or call them.' : 'You can’t message or call this account.'; else note.remove(); }
  }
  new MutationObserver(function () { try { decorate(); } catch (e) {} }).observe(document.documentElement, { childList: true, subtree: true });

  // ── open chat: lock gate, unread reset, block state ─────────────────
  window.openChat = function (dmId, otherId, otherName, otherColor) {
    var self = this, args = arguments, u = me();
    if (!u || !fdb()) return baseOpen.apply(self, args);
    cur = { dmId: dmId, otherId: otherId, otherName: otherName, otherColor: otherColor };
    watchDm(dmId);
    checkBlockedMe(otherId).then(function () { refreshHeader(dmId); });
    return ready(dmId).then(function (d) {
      function go() {
        baseOpen.apply(self, args);
        if (d[key('unread')]) { var o = {}; o[key('unread')] = false; upd(dmId, o).catch(function () {}); }
        decorate();
      }
      if (d[key('locked')] && !unlocked[dmId]) return verifyOwner('🔒 This chat is locked').then(function (ok) { if (ok) { unlocked[dmId] = true; go(); } });
      go();
    });
  };

  // ── conversation list filters ───────────────────────────────────────
  function listed(id, dm) {
    docs[id] = dm;
    var u = me();
    if (dm['deleted_' + u] && ts(dm.lastAt) <= ts(dm['deleted_' + u])) return false;
    return showArchived ? !!dm['archived_' + u] : !dm['archived_' + u];
  }
  function badges(dm) {
    var u = me(), b = '';
    if (dm['muted_' + u]) b += ' 🔕';
    if (dm['locked_' + u]) b += ' 🔒';
    if (dm['unread_' + u]) b += ' <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;vertical-align:middle"></span>';
    return b;
  }
  function afterList(list, snap) {
    var u = me(), n = snap.docs.filter(function (d) { var x = d.data(); return x['archived_' + u] && !(x['deleted_' + u] && ts(x.lastAt) <= ts(x['deleted_' + u])); }).length;
    if (!n && !showArchived) return;
    var row = document.createElement('div');
    row.className = 'dm-row mv-archived-row';
    row.style.cssText = 'font-size:13px;color:var(--muted,#9aa0a6);justify-content:flex-start';
    row.textContent = showArchived ? '← Back to chats' : '🗂 Archived chats (' + n + ')';
    row.addEventListener('click', function () { showArchived = !showArchived; loadConversations(); });
    list.insertBefore(row, list.firstChild);
    if (showArchived && list.querySelectorAll('.dm-row').length === 1) { var e = document.createElement('div'); e.style.cssText = 'padding:20px;text-align:center;font-size:12px;color:var(--muted)'; e.textContent = 'No archived chats'; list.appendChild(e); }
  }
  window.loadConversations = function () { return baseLoad.apply(this, arguments); };

  // ── send guard (blocked either way) ─────────────────────────────────
  function guardSend(fn) {
    return function (dmId, otherId) {
      if (pairBlocked(otherId)) { toast(iBlocked(otherId) ? 'You blocked this user. Unblock them to send messages.' : 'You can’t message this account.'); return; }
      return fn.apply(this, arguments);
    };
  }
  if (typeof window.sendMsg === 'function') window.sendMsg = guardSend(window.sendMsg);
  // A Firestore refusal (e.g. blocked) must not look like a sent message.
  window.addEventListener('unhandledrejection', function (e) {
    var r = e.reason; if (r && r.code === 'permission-denied' && document.querySelector('#dm-right .chat-msgs')) toast('Message not sent — you can’t message this account.');
  });

  // ── calls from/to blocked users ─────────────────────────────────────
  function wrapCall() {
    if (!window.MVCall || !MVCall.start || MVCall.__mvBlockWrapped) return !!(window.MVCall && MVCall.__mvBlockWrapped);
    var orig = MVCall.start;
    MVCall.start = function (uid) {
      if (pairBlocked(uid)) { toast(iBlocked(uid) ? 'You blocked this user. Unblock them to call.' : 'You can’t call this account.'); return; }
      return orig.apply(this, arguments);
    };
    MVCall.__mvBlockWrapped = true; return true;
  }
  if (!wrapCall()) { var tries = 0, t = setInterval(function () { if (wrapCall() || ++tries > 40) clearInterval(t); }, 500); }

  window.MVChatActions = {
    visible: function (dmId, d) { var c = ts((docs[dmId] || {})[key('cleared')]); if (!c) return true; var t = ts(d.data({ serverTimestamps: 'estimate' }).createdAt); return !t || t > c; },
    listed: listed, badges: badges, afterList: afterList,
    blocked: iBlocked, pairBlocked: pairBlocked,
    isMuted: function (dmId) { return !!(docs[dmId] || {})[key('muted')]; }
  };

  // ── Advanced Search: typed text always white (this input only) ──────
  var st = document.createElement('style');
  st.textContent = '#adv-search-inp{color:#fff!important;-webkit-text-fill-color:#fff!important;caret-color:#fff!important;background-color:#0f1418!important;color-scheme:dark;-webkit-appearance:none;appearance:none}' +
    '#adv-search-inp::placeholder{color:#9aa0a6!important;-webkit-text-fill-color:#9aa0a6!important;opacity:1}' +
    '#adv-search-inp:-webkit-autofill{-webkit-text-fill-color:#fff!important;-webkit-box-shadow:0 0 0 1000px #0f1418 inset!important}';
  document.head.appendChild(st);

  // ── Sound Board: real recordings for Laugh and Dog Bark ─────────────
  var REAL = { '😂 Laugh': '/sounds/laughter.mp3', '🐶 Dog Bark': '/sounds/dog-bark.mp3' }, clips = {};
  if (typeof SOUNDS !== 'undefined' && SOUNDS && SOUNDS.forEach) SOUNDS.forEach(function (s) {
    var src = REAL[s.label]; if (!src) return;
    var fallback = s.play;
    s.play = function () {
      var a = clips[src] || (clips[src] = new Audio(src));
      try { a.pause(); a.currentTime = 0; } catch (e) {}
      var p = a.play(); if (p && p.catch) p.catch(function () { try { fallback(); } catch (e) {} });
    };
  });
})();
