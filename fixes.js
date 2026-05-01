
// ═══════════════════════════════════════════════════════════════
// MINDVORA FIXES v2.0 — May 2026
// ═══════════════════════════════════════════════════════════════

// ── TASK 1: FORGOT PASSWORD — handle domain not allowlisted ──
(function(){
  window.doForgotPassword = function() {
    var emailEl = document.getElementById('li-email');
    var errEl = document.getElementById('li-err');
    var email = emailEl ? emailEl.value.trim().toLowerCase() : '';
    if (!email) {
      if (errEl) errEl.textContent = '📧 Enter your email above first.';
      if (emailEl) emailEl.focus();
      return;
    }
    if (email.indexOf('@') === -1) {
      if (errEl) errEl.textContent = '📧 Enter your email address (not username) to reset.';
      return;
    }
    if (!/^[^@]+@[^@]+\.[^@]+$/.test(email)) {
      if (errEl) errEl.textContent = '❌ Please enter a valid email.';
      return;
    }
    var btn = document.getElementById('btn-login');
    if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
    auth.sendPasswordResetEmail(email)
    .then(function() {
      if (errEl) { errEl.style.color = '#86efac'; errEl.textContent = '✅ Reset link sent to ' + email + '. Check inbox & spam.'; }
      showToast('📧 Reset link sent!');
      if (btn) { btn.disabled = false; btn.textContent = 'Enter Mindvora →'; }
    })
    .catch(function(e) {
      if (btn) { btn.disabled = false; btn.textContent = 'Enter Mindvora →'; }
      if (errEl) errEl.style.color = '#fca5a5';
      var c = e.code || '';
      var m = e.message || '';
      if (c === 'auth/unauthorized-continue-uri' || m.indexOf('allowlisted') > -1 || m.indexOf('unauthorized') > -1) {
        if (errEl) errEl.innerHTML = '⚠️ Reset unavailable on this domain. Use <strong style="color:#86efac">Google Sign-In</strong> below or email <em>mindvoraofficial@outlook.com</em>.';
      } else if (c === 'auth/user-not-found') {
        if (errEl) errEl.textContent = '❌ No account with this email. Register instead.';
      } else if (c === 'auth/too-many-requests') {
        if (errEl) errEl.textContent = '⏳ Too many attempts. Wait and retry.';
      } else {
        if (errEl) errEl.textContent = '❌ ' + (m || 'Could not send reset email.');
      }
    });
  };
})();

// ── TASK 4: SIGN-OUT ICON — clear exit icon ──────────────────
(function(){
  var outBtn = document.getElementById('btn-out');
  if (outBtn) {
    outBtn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3h5a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-5"/><path d="M11 17l-5-5 5-5"/><path d="M6 12h12"/></svg>';
    outBtn.title = 'Sign out of Mindvora';
  }
})();

// ── TASK 3: SOCIAL FEATURES — Reactions, Save, Share, Comment Toggle ─────

// Inject CSS for reaction buttons
(function(){
  var s = document.createElement('style');
  s.textContent =
    '.rx-bar{display:flex;gap:4px;padding:6px 14px;flex-wrap:wrap}' +
    '.rx-btn{background:var(--deep);border:1px solid var(--border);border-radius:16px;padding:3px 10px;font-size:12px;cursor:pointer;color:var(--moon);display:inline-flex;align-items:center;gap:3px;transition:all .2s;font-family:"DM Sans",sans-serif}' +
    '.rx-btn:hover{border-color:var(--green3);background:rgba(34,197,94,.08)}' +
    '.rx-btn.rx-active{border-color:var(--green3);background:rgba(34,197,94,.15);color:var(--green3)}' +
    '.rx-btn span{font-size:11px;min-width:8px}' +
    '.social-extra{display:flex;gap:6px;padding:2px 14px 8px;flex-wrap:wrap}';
  document.head.appendChild(s);
})();

var MV_REACTIONS = [
  {emoji:'👍',label:'Like',key:'like'},
  {emoji:'❤️',label:'Love',key:'love'},
  {emoji:'🤗',label:'Care',key:'care'},
  {emoji:'👎',label:'Dislike',key:'dislike'}
];

function toggleReaction(sparkId, reactionKey) {
  if (!state.user) { showToast('Login first'); return; }
  var uid = state.user.uid;
  var ref = db.collection('sparks').doc(sparkId);
  ref.get().then(function(doc) {
    if (!doc.exists) return;
    var reactions = doc.data().reactions || {};
    var myOld = null;
    Object.keys(reactions).forEach(function(k) {
      if (reactions[k] && reactions[k].indexOf(uid) > -1) myOld = k;
    });
    var upd = {};
    if (myOld === reactionKey) {
      upd['reactions.' + reactionKey] = firebase.firestore.FieldValue.arrayRemove(uid);
    } else {
      if (myOld) upd['reactions.' + myOld] = firebase.firestore.FieldValue.arrayRemove(uid);
      upd['reactions.' + reactionKey] = firebase.firestore.FieldValue.arrayUnion(uid);
    }
    ref.update(upd).then(function(){ refreshRxUI(sparkId); });
  });
}

function refreshRxUI(sparkId) {
  var bar = document.getElementById('rx-' + sparkId);
  if (!bar) return;
  db.collection('sparks').doc(sparkId).get().then(function(doc) {
    if (!doc.exists) return;
    var reactions = doc.data().reactions || {};
    var uid = state.user ? state.user.uid : '';
    bar.innerHTML = MV_REACTIONS.map(function(r) {
      var arr = reactions[r.key] || [];
      var active = arr.indexOf(uid) > -1;
      return '<button class="rx-btn' + (active ? ' rx-active' : '') + '" onclick="toggleReaction(\'' + sparkId + '\',\'' + r.key + '\')" title="' + r.label + '">' + r.emoji + ' <span>' + (arr.length || '') + '</span></button>';
    }).join('');
  });
}

function saveSpark(sparkId) {
  if (!state.user) { showToast('Login first'); return; }
  var ref = db.collection('users').doc(state.user.uid);
  ref.get().then(function(doc) {
    var saved = (doc.data() && doc.data().savedSparks) || [];
    if (saved.indexOf(sparkId) > -1) {
      ref.update({ savedSparks: firebase.firestore.FieldValue.arrayRemove(sparkId) });
      showToast('🔖 Removed from saved');
    } else {
      ref.update({ savedSparks: firebase.firestore.FieldValue.arrayUnion(sparkId) });
      showToast('🔖 Saved!');
    }
  });
}

function shareSparkLink(sparkId, text) {
  var url = window.location.origin + '?spark=' + sparkId;
  if (navigator.share) {
    navigator.share({ title: 'Mindvora Spark', text: (text || '').substring(0, 100), url: url }).catch(function(){});
  } else if (navigator.clipboard) {
    navigator.clipboard.writeText(url).then(function(){ showToast('🔗 Link copied!'); });
  } else {
    prompt('Copy this link:', url);
  }
}

function shareSparkToDMFromProfile(sparkId, text) {
  if (typeof sharePostToDM === 'function') {
    sharePostToDM(sparkId, text);
  } else {
    shareSparkLink(sparkId, text);
  }
}

function toggleCommentLock(sparkId) {
  if (!state.user) return;
  db.collection('sparks').doc(sparkId).get().then(function(doc) {
    if (!doc.exists) return;
    if (doc.data().authorId !== state.user.uid) { showToast('Only the author can toggle comments'); return; }
    var locked = !doc.data().commentsLocked;
    db.collection('sparks').doc(sparkId).update({ commentsLocked: locked });
    showToast(locked ? '🔒 Comments turned off' : '🔓 Comments turned on');
  });
}

// Inject social features into spark cards in the feed
function injectSocialFeatures() {
  document.querySelectorAll('.spark-card').forEach(function(card) {
    if (card.dataset.socialDone) return;
    card.dataset.socialDone = '1';
    var sparkId = card.dataset.id;
    if (!sparkId) return;
    var actRow = card.querySelector('.s-act');
    if (!actRow) return;

    // Insert reaction bar
    var rxBar = document.createElement('div');
    rxBar.id = 'rx-' + sparkId;
    rxBar.className = 'rx-bar';
    actRow.parentNode.insertBefore(rxBar, actRow);
    refreshRxUI(sparkId);

    // Insert save/share/DM-share buttons
    var safeText = (card.querySelector('.s-text') ? card.querySelector('.s-text').textContent : '').replace(/'/g, '').substring(0,50);
    var extra = document.createElement('div');
    extra.className = 'social-extra';
    extra.innerHTML =
      '<button class="rx-btn" onclick="saveSpark(\'' + sparkId + '\')" title="Save">🔖 Save</button>' +
      '<button class="rx-btn" onclick="shareSparkLink(\'' + sparkId + '\',\'' + safeText + '\')" title="Copy link">🔗 Share</button>' +
      '<button class="rx-btn" onclick="shareSparkToDMFromProfile(\'' + sparkId + '\',\'' + safeText + '\')" title="Send to DM">📨 DM</button>';

    // Comment lock toggle for post author
    if (state.user) {
      var authorEl = card.querySelector('[data-author-id]');
      var authorId = authorEl ? authorEl.dataset.authorId : (card.dataset.authorId || '');
      if (authorId === state.user.uid) {
        extra.innerHTML += '<button class="rx-btn" onclick="toggleCommentLock(\'' + sparkId + '\')" title="Toggle comments">🔒 Comments</button>';
      }
    }

    if (actRow.nextSibling) {
      actRow.parentNode.insertBefore(extra, actRow.nextSibling);
    } else {
      actRow.parentNode.appendChild(extra);
    }
  });
}

// Auto-inject on feed changes
(function(){
  var obs = new MutationObserver(function(){ setTimeout(injectSocialFeatures, 300); });
  setTimeout(function(){
    var fc = document.getElementById('feed-cont');
    if (fc) obs.observe(fc, { childList: true, subtree: true });
    injectSocialFeatures();
  }, 3000);
})();

// ── TASK 3b: Enhanced user profile with all social actions ───
(function(){
  window.openUserProfile = function(uid, userData) {
    var u = userData;
    var existing = document.getElementById('user-profile-sheet');
    if (existing) existing.remove();
    var isMe = state.user && uid === state.user.uid;
    var sheet = document.createElement('div');
    sheet.id = 'user-profile-sheet';
    sheet.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:999;display:flex;align-items:flex-end;justify-content:center';
    var followBtn = (!isMe && state.user) ?
      '<button onclick="toggleFollow(\'' + uid + '\',\'' + esc(u.name) + '\');var b=this;setTimeout(function(){b.textContent=isFollowing(\'' + uid + '\')?\'✅ Following\':\'➕ Follow\'},300)" style="flex:1;padding:10px;border-radius:12px;background:var(--green2);border:none;color:#fff;font-weight:700;cursor:pointer">' + (isFollowing(uid) ? '✅ Following' : '➕ Follow') + '</button>' : '';
    var msgBtn = (!isMe && state.user) ?
      '<button onclick="var dmId=[\'' + uid + '\',\'' + (state.user?state.user.uid:'') + '\'].sort().join(\'_\');openChat(dmId,\'' + uid + '\',\'' + esc(u.name) + '\',\'' + esc(u.color||COLORS[0]) + '\');document.getElementById(\'user-profile-sheet\').remove();openModal(\'modal-dm\')" style="flex:1;padding:10px;border-radius:12px;border:1px solid var(--border);background:transparent;color:var(--moon);font-weight:700;cursor:pointer">💬 Message</button>' : '';
    sheet.innerHTML =
      '<div style="background:var(--card);border-radius:20px 20px 0 0;width:100%;max-width:480px;padding:20px;max-height:80vh;overflow-y:auto">' +
        '<div style="display:flex;align-items:center;gap:14px;margin-bottom:16px">' +
          '<div style="width:56px;height:56px;border-radius:50%;background:' + esc(u.color||COLORS[0]) + ';display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#fff">' + esc((u.name||'U').charAt(0).toUpperCase()) + '</div>' +
          '<div><div style="font-size:15px;font-weight:700;color:var(--moon)">' + esc(u.name||'User') + (u.isVerified?'<span style="color:var(--green3);margin-left:4px">✓</span>':'') + '</div><div style="font-size:12px;color:var(--muted)">@' + esc(u.handle||'user') + '</div></div>' +
          '<button onclick="document.getElementById(\'user-profile-sheet\').remove()" style="margin-left:auto;background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer">✕</button>' +
        '</div>' +
        (u.bio ? '<div style="font-size:13px;color:var(--moon);margin-bottom:12px;line-height:1.6">' + esc(u.bio) + '</div>' : '') +
        '<div style="display:flex;gap:20px;margin-bottom:16px">' +
          '<div style="text-align:center"><div style="font-size:16px;font-weight:700;color:var(--green3)">' + (u.sparksCount||0) + '</div><div style="font-size:11px;color:var(--muted)">Sparks</div></div>' +
          '<div style="text-align:center"><div style="font-size:16px;font-weight:700;color:var(--green3)">' + (u.followers||0) + '</div><div style="font-size:11px;color:var(--muted)">Followers</div></div>' +
        '</div>' +
        '<div style="display:flex;gap:8px;margin-bottom:12px">' + followBtn + msgBtn + '</div>' +
        (!isMe && state.user ? '<div style="display:flex;gap:6px;flex-wrap:wrap"><button class="rx-btn" onclick="blockUser(\'' + uid + '\',\'' + esc(u.name) + '\');document.getElementById(\'user-profile-sheet\').remove()" style="padding:6px 12px;border-radius:8px;border:1px solid rgba(239,68,68,.3);background:transparent;color:#fca5a5;cursor:pointer;font-size:11px">🚫 Block</button></div>' : '') +
      '</div>';
    document.body.appendChild(sheet);
    sheet.addEventListener('click', function(e) { if (e.target === sheet) sheet.remove(); });
  };
})();

// ── TASK 5: CRYPTO PAYMENT — Retry + Keep-alive ──────────────
(function(){
  // Keep backend warm
  function pingBackend() {
    fetch('/api/crypto/status/ping', { method: 'GET' }).catch(function(){});
  }
  setInterval(pingBackend, 240000);
  setTimeout(pingBackend, 5000);

  // Override with retry logic
  window.createCryptoPayment = function(amountUSD, description, onSuccess) {
    if (!state.user) { showToast('Login first'); return; }
    showToast('₿ Connecting to payment server…');
    fetch('/api/crypto/status/warmup').catch(function(){});
    setTimeout(function() {
      _cryptoRetry(amountUSD, description, onSuccess, 0);
    }, 1000);
  };

  function _cryptoRetry(amountUSD, description, onSuccess, attempt) {
    fetch(BACKEND_URL + '/api/crypto/create-invoice', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        price_amount: amountUSD, price_currency: 'usd', pay_currency: 'usdtbsc',
        order_id: 'MV-' + state.user.uid + '-' + Date.now(),
        order_description: description,
        ipn_callback_url: BACKEND_URL + '/api/crypto/webhook',
        success_url: window.location.href, cancel_url: window.location.href,
      })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (!data.invoice_url) {
        if (attempt < 3) {
          showToast('⏳ Retrying... (' + (attempt+1) + '/3)');
          setTimeout(function(){ _cryptoRetry(amountUSD, description, onSuccess, attempt+1); }, 3000);
        } else {
          showToast('❌ Payment server unavailable. Try card payment.');
        }
        return;
      }
      db.collection('crypto_payments').add({
        uid: state.user.uid, email: state.user.email, name: state.profile.name,
        amountUSD: amountUSD, description: description,
        invoiceId: data.id, invoiceUrl: data.invoice_url,
        status: 'pending', createdAt: firebase.firestore.FieldValue.serverTimestamp()
      }).then(function(docRef) { pollCryptoPayment(data.id, docRef.id, onSuccess); });
      window.open(data.invoice_url, '_blank');
      showToast('₿ Payment page opened! Complete in new tab.');
    })
    .catch(function() {
      if (attempt < 3) {
        showToast('⏳ Server waking up... (' + (attempt+1) + '/3)');
        setTimeout(function(){ _cryptoRetry(amountUSD, description, onSuccess, attempt+1); }, 4000);
      } else {
        showToast('❌ Could not connect. Try Card/Bank payment.');
      }
    });
  }
})();
