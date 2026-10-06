
// MINDVORA FIXES v2.0 — May 2026

// TASK 1: FORGOT PASSWORD — handle domain not allowlisted
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
    auth.sendPasswordResetEmail(email, {
      url: window.location.origin,
      handleCodeInApp: false
    })
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

// TASK 4: SIGN-OUT ICON — clear exit icon
(function(){
  var outBtn = document.getElementById('btn-out');
  if (outBtn) {
    outBtn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3h5a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-5"/><path d="M11 17l-5-5 5-5"/><path d="M6 12h12"/></svg>';
    outBtn.title = 'Sign out of Mindvora';
  }
})();

// TASK 3: SOCIAL FEATURES — Reactions, Save, Share, Comment Toggle

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

// TASK 3b: Enhanced user profile with all social actions
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

// TASK 5: CRYPTO PAYMENT — Retry + Keep-alive
(function(){
// Keep backend warm
  function pingBackend() {
    fetch(BACKEND_URL + '/api/crypto/status/ping', { method: 'GET' }).catch(function(){});
  }
  setInterval(pingBackend, 240000);
  setTimeout(pingBackend, 5000);

// Crypto invoice creation + retry now lives in script.js createCryptoPayment()
// (server-priced, server-fulfilled). The old override here sent the price from
// the browser and wrote payment records client-side.
})();


// PAYSTACK REDIRECT RETURN — when the popup could not load we used hosted
// checkout; Paystack sends the user back with ?reference=… — confirm it.
(function(){
  var q = new URLSearchParams(location.search);
  var ref = q.get('reference') || q.get('trxref');
  if (!ref || typeof auth === 'undefined') return;
  var done = false;
  auth.onAuthStateChanged(function(u){
    if (!u || done) return; done = true;
    history.replaceState(null, '', location.pathname);
    confirmPaystackPayment(ref).then(function(){ showToast('✅ Payment confirmed!'); })
      .catch(function(e){ showToast('⚠️ ' + e.message); });
  });
})();

// ── v5: show the bottom menu only when the user is logged in and the main app is visible ──
(function () {
  function appVisible() {
    var app = document.getElementById('app-screen');
    if (!app) return false;
    var cs = getComputedStyle(app);
    var loggedIn = !!(window.state && window.state.user);
    return loggedIn && cs.display !== 'none' && cs.visibility !== 'hidden';
  }
  function sync() { if (document.body) document.body.classList.toggle('mv-authed', appVisible()); }
  function start() {
    sync();
    ['app-screen', 'auth-screen', 'otp-screen'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) new MutationObserver(sync).observe(el, { attributes: true, attributeFilter: ['style', 'class'] });
    });
    setInterval(sync, 1000); // safety net for login/logout paths that don't touch those screens
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();


// ── v6: FORGOT PASSWORD — send through our server (Brevo) first, Firebase as backup ──
(function(){
  var firebaseReset = window.doForgotPassword;   // the Firebase version above
  window.doForgotPassword = function() {
    var emailEl = document.getElementById('li-email');
    var errEl = document.getElementById('li-err');
    var email = emailEl ? emailEl.value.trim().toLowerCase() : '';
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { return firebaseReset && firebaseReset(); }
    if (typeof mvApi !== 'function') { return firebaseReset && firebaseReset(); }
    var btn = document.getElementById('btn-login');
    if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
    mvApi('/api/auth/password-reset', { email: email, continueUrl: window.location.origin }).then(function(d) {
      if (btn) { btn.disabled = false; btn.textContent = 'Enter Mindvora →'; }
      if (d && d.status) {
        if (errEl) { errEl.style.color = '#86efac'; errEl.textContent = '✅ If an account exists for ' + email + ', a reset link is on its way. Check inbox and spam.'; }
        showToast('📧 Reset link sent');
        return;
      }
      if (d && (d.code === 'RATE_LIMIT' || d.code === 'BAD_EMAIL')) {
        if (errEl) { errEl.style.color = '#fca5a5'; errEl.textContent = '❌ ' + d.message; }
        return;
      }
      console.warn('[reset] server route unavailable (' + ((d && d.code) || 'no response') + ') — using Firebase email');
      firebaseReset && firebaseReset();
    }).catch(function() {
      if (btn) { btn.disabled = false; btn.textContent = 'Enter Mindvora →'; }
      firebaseReset && firebaseReset();
    });
  };
})();


// ── v7: VISIBLE reCAPTCHA ("I'm not a robot" checkbox, v2) ──────────────────
// Turns on automatically when the server has RECAPTCHA_V2_SITE_KEY set
// (or window.RECAPTCHA_V2_SITE_KEY in index.html). Otherwise the old
// invisible check keeps working, so nothing breaks before the keys exist.
(function(){
  var v3Get = window.getCaptchaToken || (typeof getCaptchaToken === 'function' ? getCaptchaToken : null);
  var cfg = { v2: window.RECAPTCHA_V2_SITE_KEY || '' };
  var cfgPromise = cfg.v2 ? Promise.resolve(cfg) : new Promise(function(done){
    var tries = 0;
    (function ask(){
      tries++;
      fetch((window.BACKEND_URL || '') + '/api/recaptcha-config', { cache: 'no-store' })
        .then(function(r){ return r.json(); })
        .then(function(d){ if (d && d.version === 'v2' && d.siteKey) cfg.v2 = d.siteKey; done(cfg); })
        .catch(function(){ if (tries < 6) setTimeout(ask, 8000); else done(cfg); });
    })();
  });
  var apiP = null;
  function loadV2(){
    if (window.grecaptcha && grecaptcha.render) return Promise.resolve();
    if (apiP) return apiP;
    apiP = new Promise(function(res){
      window.__mvCaptchaReady = function(){ res(); };
      var hosts = ['https://www.google.com', 'https://www.recaptcha.net'], i = 0;
      (function add(){
        var sc = document.createElement('script');
        sc.async = true; sc.src = hosts[i] + '/recaptcha/api.js?onload=__mvCaptchaReady&render=explicit';
        sc.onerror = function(){ i++; if (i < hosts.length) add(); else { apiP = null; res(); } };
        document.head.appendChild(sc);
      })();
    });
    return apiP;
  }
  var inlineId = null, inlineTok = '';
  function setRegBtn(){ var b = document.getElementById('btn-reg'); if (b && inlineId !== null && !b.dataset.busy) b.disabled = !inlineTok; }
  function renderInline(){
    var box = document.getElementById('r-captcha');
    if (!box || inlineId !== null || !window.grecaptcha || !grecaptcha.render) return;
    box.style.display = 'block';
    inlineId = grecaptcha.render(box, { sitekey: cfg.v2, theme: 'dark',
      callback: function(t){ inlineTok = t; setRegBtn(); var e = document.getElementById('r-err'); if (e && /robot/i.test(e.textContent)) e.textContent = ''; },
      'expired-callback': function(){ inlineTok = ''; setRegBtn(); },
      'error-callback': function(){ inlineTok = ''; setRegBtn(); } });
    setRegBtn();
  }
  function resetInline(){ inlineTok = ''; if (inlineId !== null) try { grecaptcha.reset(inlineId); } catch(e){} setRegBtn(); }
  // Pop-up checkbox for "Resend code" and the login flow.
  function popupToken(){
    return new Promise(function(res){
      var ov = document.createElement('div');
      ov.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;padding:16px';
      ov.innerHTML = '<div style="background:#0a1a0f;border:1px solid #166534;border-radius:14px;padding:18px;text-align:center;max-width:340px;width:100%">' +
        '<div style="color:#e2e8f0;font-weight:700;margin-bottom:10px">Quick security check</div>' +
        '<div id="mv-cap-pop" style="display:inline-block;min-height:78px"></div>' +
        '<div><button type="button" id="mv-cap-cancel" style="margin-top:10px;background:none;border:1px solid #334155;color:#94a3b8;border-radius:8px;padding:6px 14px;cursor:pointer">Cancel</button></div></div>';
      document.body.appendChild(ov);
      var finish = function(t){ if (ov.parentNode) ov.parentNode.removeChild(ov); res(t || ''); };
      document.getElementById('mv-cap-cancel').onclick = function(){ finish(''); };
      try { grecaptcha.render('mv-cap-pop', { sitekey: cfg.v2, theme: 'dark', callback: function(t){ setTimeout(function(){ finish(t); }, 300); } }); }
      catch(e){ finish(''); }
    });
  }
  window.getCaptchaToken = getCaptchaToken = function(action){
    return cfgPromise.then(function(){
      if (!cfg.v2) return v3Get ? v3Get(action) : '';
      return loadV2().then(function(){
        if (!window.grecaptcha || !grecaptcha.render) { showToast('❌ Security check could not load. Check your internet and refresh.'); return ''; }
        if (inlineTok) { var t = inlineTok; inlineTok = ''; setTimeout(resetInline, 500); return t; }
        return popupToken();
      });
    });
  };
  cfgPromise.then(function(){
    if (!cfg.v2) return;
    console.log('[reCAPTCHA] Visible checkbox (v2) is ON');
    loadV2().then(renderInline);
  });
  // Block "Create Account" until the box is ticked (when v2 is on).
  var origReg = window.doRegister || (typeof doRegister === 'function' ? doRegister : null);
  if (origReg) window.doRegister = doRegister = function(){
    if (cfg.v2 && inlineId !== null && !inlineTok) { var e = document.getElementById('r-err'); if (e) e.textContent = 'Tick "I\'m not a robot" first.'; return; }
    return origReg.apply(this, arguments);
  };
})();


// ── "Get the Android app" bar (Android browsers only, not inside the app) ──
(function () {
  var APK_URL = 'https://github.com/ilohgreat-25x/mindvora-mobile/releases/latest/download/mindvora.apk';
  window.MV_APK_URL = APK_URL;
  function show() {
    try {
      if (!/Android/i.test(navigator.userAgent) || window.Capacitor) return;
      if (Date.now() - Number(localStorage.getItem('mv_apk_bar') || 0) < 7 * 86400000) return;
      if (!document.body || document.getElementById('mv-apk-bar')) return;
      var b = document.createElement('div');
      b.id = 'mv-apk-bar';
      b.style.cssText = 'position:fixed;left:10px;right:10px;bottom:76px;z-index:9998;background:#111827;color:#fff;border-radius:14px;padding:10px 12px;display:flex;align-items:center;gap:10px;box-shadow:0 6px 20px rgba(0,0,0,.35);font-size:14px';
      b.innerHTML = '<span style="flex:1">Get the Mindvora Android app</span>' +
        '<a href="' + APK_URL + '" style="background:#16a34a;color:#fff;padding:7px 12px;border-radius:10px;font-weight:700;text-decoration:none">Download</a>' +
        '<button type="button" aria-label="Close" style="background:none;border:0;color:#fff;font-size:18px">✕</button>';
      b.querySelector('button').onclick = function () { b.remove(); try { localStorage.setItem('mv_apk_bar', String(Date.now())); } catch (e) {} };
      document.body.appendChild(b);
    } catch (e) {}
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { setTimeout(show, 4000); });
  else setTimeout(show, 4000);
})();

// ROUND 6 — STORIES (moved here so the 545 KB script.js stays untouched)
// • The ＋ button calls window.postStory() at click time, so story-music.js's photo/music composer is used
//   (it loads deferred; the old code bound the ORIGINAL prompt()-only postStory before it existed).
// • Story docs carry `uid` — firestore.rules require uid == auth.uid, so text stories were being rejected.
// • Taps pass the whole story list to viewStory so next/previous works.
(function(){
  window.loadStories = function loadStories(){ var cutoff=Date.now()-48*60*60*1000; db.collection('stories').where('expiresAt','>',new Date(cutoff)).limit(20).get().then(function(snap){ var bar=document.getElementById('stories-bar'); bar.innerHTML='<div class="s-add" id="story-add">＋</div>'; var list=snap.docs.map(function(x){ return {id:x.id,s:x.data()}; }); snap.docs.forEach(function(d){ var s=d.data(),seen=state.user&&(s.seenBy||[]).indexOf(state.user.uid)>-1; var el=document.createElement('div'); el.className='s-item'; el.innerHTML='<div class="s-ring'+(seen?' seen':'')+'"><div class="s-av">'+esc((s.authorName||'Z').charAt(0).toUpperCase())+'</div></div><div class="s-name">'+esc(s.authorName||'')+'</div>'; el.addEventListener('click',function(){ window.viewStory(d.id,s,list); }); bar.appendChild(el); }); document.getElementById('story-add').addEventListener('click',function(){ window.postStory(); }); }); };
  window.postStory = function postStory(){ var text=prompt('Share a story (disappears in 48h):'); if(!text||!text.trim()||!state.user) return; db.collection('stories').add({text:text.trim(),uid:state.user.uid,authorId:state.user.uid,authorName:state.profile.name,authorHandle:state.profile.handle,authorColor:state.profile.color,seenBy:[],createdAt:firebase.firestore.FieldValue.serverTimestamp(),expiresAt:new Date(Date.now()+48*60*60*1000)}).then(function(){ showToast('Story posted! 48h ⏱'); loadStories(); }); };
})();

// ROUND 6 — LIVE FOOTBALL + ANIME MOVIES menu entries (index.html stays untouched; panels live in live-hub.js)
(function(){
  var sc = document.createElement('script'); sc.src = '/live-hub.js?v=1'; sc.defer = true; document.head.appendChild(sc);
  function run(name) {
    try { if (typeof closeDrawer === 'function') closeDrawer(); } catch (e) {}
    if (typeof window[name] === 'function') return window[name]();
    var tries = 0, t = setInterval(function () {
      if (typeof window[name] === 'function') { clearInterval(t); window[name](); }
      else if (++tries > 40) { clearInterval(t); try { showToast('⚠️ Could not load. Check your connection and try again.'); } catch (e) {} }
    }, 250);
  }
  window.mvOpenLive = run;
  function add() {
    if (document.getElementById('mv-dr-football')) return;
    var anchor = document.querySelector('.drawer-item[onclick*="openMindvoraTV"]') || document.querySelector('.drawer-item[onclick*="openSoundboard"]');
    if (!anchor) return;
    [['mv-dr-anime', 'openAnimeMovies', '🎬 Stream Live Anime Movies'], ['mv-dr-football', 'openLiveFootball', '⚽ Stream Live Football Matches']].forEach(function (d) {
      var b = document.createElement('button'); b.type = 'button'; b.className = 'drawer-item'; b.id = d[0]; b.textContent = d[2];
      b.addEventListener('click', function () { run(d[1]); });
      anchor.parentNode.insertBefore(b, anchor.nextSibling);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', add); else add();
})();

// ROUND 7 — ONE call system on ONE WebSocket. script.js still contains an old Firestore-based call system
// (calls collection + onSnapshot listener started 3s after login). Nothing starts calls with it any more, but its
// listener still popped a second "incoming call" banner for old 'ringing' docs. Route everything to MVCall
// (backend WebSocket signalling) and switch the old listener off. script.js itself stays untouched.
(function(){
  window.listenForIncomingCalls = function(){};
  window.startCall = function (targetUid, targetName, targetColor, isVideo) {
    if (window.MVCall && MVCall.start) return MVCall.start(targetUid, targetName, isVideo ? 'video' : 'audio');
  };
})();

// ROUND 8 — chat view fix, chat actions, Sound Board recordings, Advanced Search text colour.
(function(){ var sc = document.createElement('script'); sc.src = '/chat-actions.js?v=1'; sc.defer = true; document.head.appendChild(sc); })();
