/* MINDVORA — owner batch (Oct 7): Go Live alerts → watch, Aria voice like Siri, Scheduled Posts, Leaderboard.
 * Additive overrides only; nothing else is touched. Real-time stays on the existing MindvoraRT WebSocket. */
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }
  function toast(t) { if (typeof showToast === 'function') showToast(t); }
  function esc2(t) { return typeof esc === 'function' ? esc(t) : String(t || '').replace(/[<>&"]/g, ''); }

  // ── 1. Go Live: open the stream from a push tap / in-app alert ─────────────────────────────
  function watchLive(id) {
    if (!id) { if (typeof openLivesList === 'function') openLivesList(); return; }
    db.collection('live_streams').doc(id).get().then(function (d) {
      if (!d.exists || !d.data().live) { toast('That live stream has ended.'); if (typeof openLivesList === 'function') openLivesList(); return; }
      var s = d.data();
      if (typeof joinStream === 'function') joinStream(id, s.hostName || 'Mindvora user', s.hostHandle || 'user', s.hostColor || '');
    }).catch(function () { if (typeof openLivesList === 'function') openLivesList(); });
  }
  window.mvWatchLive = watchLive;
  var baseRoute = window.handleOpenUrl;
  window.handleOpenUrl = function (url) {
    var q; try { q = new URL(url, location.origin).searchParams; } catch (e) { q = null; }
    if (q && q.get('action') === 'live') return watchLive(q.get('id'));
    return baseRoute && baseRoute.apply(this, arguments);
  };
  // Cold start from a push tap: fixes.js waits for login, then calls window.handleOpenUrl (this override).
  // In-app alert over the existing WebSocket (server sends RT_NOTIF ntype 'live_now' to every user).
  function liveBanner(m) {
    var b = $('mv-live-alert'); if (b) b.remove();
    b = document.createElement('div'); b.id = 'mv-live-alert';
    b.style.cssText = 'position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:99999;background:#b91c1c;color:#fff;padding:10px 16px;border-radius:14px;font-size:13px;font-weight:700;box-shadow:0 6px 24px rgba(0,0,0,.4);cursor:pointer;max-width:92vw';
    b.textContent = '🔴 ' + (m.text || ((m.hostName || 'Someone') + ' is LIVE now — tap to watch'));
    b.onclick = function () { b.remove(); watchLive(m.liveId); };
    document.body.appendChild(b); setTimeout(function () { if (b.parentNode) b.remove(); }, 12000);
  }
  (function hook() {
    if (window.MindvoraRT && MindvoraRT.onMessage) MindvoraRT.onMessage(function (m) { if (m && m.type === 'RT_NOTIF' && m.ntype === 'live_now') liveBanner(m); });
    else setTimeout(hook, 1000);
  })();

  // ── 5. Aria voice: listens like Siri (live words while you speak, stops on silence, sends) ────
  // "service-not-allowed" = the Android app's WebView has no Web Speech service. Inside the Capacitor
  // app we use the native speech plugin (@capacitor-community/speech-recognition); browsers use Web Speech.
  function ariaVoice() {
    var old = $('aria-voice-btn'); if (!old || old.__mvVoice) return !!old;
    var btn = old.cloneNode(true); btn.__mvVoice = true; old.parentNode.replaceChild(btn, old);   // drops the old handler
    var inp = $('aria-inp'), listening = false, rec = null, silence = null, finalText = '';
    function ui(on) { listening = on; btn.classList.toggle('recording', on); btn.textContent = on ? '⏹️' : '🎤'; if (inp) inp.placeholder = on ? 'Listening… speak now' : 'Ask ARIA anything…'; }
    function send() { ui(false); if (inp && inp.value.trim()) { var s = $('aria-send'); if (s) s.click(); } }
    var NativeSR = window.Capacitor && Capacitor.isNativePlatform && Capacitor.isNativePlatform() && Capacitor.Plugins && Capacitor.Plugins.SpeechRecognition;
    btn.addEventListener('click', function () {
      if (listening) { try { NativeSR ? NativeSR.stop() : rec && rec.stop(); } catch (e) {} return; }
      if (NativeSR) {
        NativeSR.requestPermissions().then(function (p) {
          if (p && p.speechRecognition && p.speechRecognition !== 'granted') { toast('🎤 Allow microphone access for Mindvora in your phone settings.'); return; }
          ui(true); finalText = '';
          NativeSR.removeAllListeners && NativeSR.removeAllListeners();
          NativeSR.addListener('partialResults', function (d) { if (d && d.matches && d.matches[0]) { finalText = d.matches[0]; if (inp) inp.value = finalText; } });
          NativeSR.addListener('listeningState', function (d) { if (d && d.status === 'stopped') send(); });
          NativeSR.start({ language: navigator.language || 'en-US', partialResults: true, popup: false, maxResults: 1 })
            .then(function (r) { if (r && r.matches && r.matches[0] && inp) inp.value = r.matches[0]; })
            .catch(function (e) { ui(false); toast('Voice: ' + (e && e.message || 'could not start')); });
        }).catch(function () { toast('🎤 Microphone permission needed.'); });
        return;
      }
      var SR = window.SpeechRecognition || window.webkitSpeechRecognition;
      if (!SR) { toast(window.Capacitor ? '🎤 Voice needs the updated Mindvora app.' : 'Voice input is not supported in this browser. Try Chrome.'); return; }
      rec = new SR(); rec.continuous = true; rec.interimResults = true; rec.lang = navigator.language || 'en-US'; finalText = '';
      rec.onstart = function () { ui(true); };
      rec.onresult = function (e) {
        var interim = '';
        for (var i = e.resultIndex; i < e.results.length; i++) { if (e.results[i].isFinal) finalText += e.results[i][0].transcript; else interim += e.results[i][0].transcript; }
        if (inp) inp.value = (finalText + interim).trim();
        clearTimeout(silence); silence = setTimeout(function () { try { rec.stop(); } catch (x) {} }, 1600);   // stop after ~1.6 s of silence
      };
      rec.onerror = function (e) {
        ui(false);
        var why = { 'not-allowed': 'Allow microphone access to talk to Aria.', 'service-not-allowed': (window.Capacitor ? 'Voice needs the updated Mindvora app.' : 'Allow microphone access to talk to Aria.'),
          'no-speech': "I didn't hear anything — tap 🎤 and speak.", 'audio-capture': 'No microphone found.', network: 'Voice needs an internet connection.' };
        toast('🎤 ' + (why[e.error] || 'Voice stopped. Tap 🎤 to try again.'));
      };
      rec.onend = function () { clearTimeout(silence); if (listening) send(); };
      try { rec.start(); } catch (e) { ui(false); }
    });
    return true;
  }
  (function v() { if (!ariaVoice()) setTimeout(v, 1000); })();

  // ── 6. Scheduled Posts: clean empty state instead of "Error loading" ───────────────────────
  window.openScheduled = function () {
    if (!state.user) { toast('Login first'); return; }
    openModal('modal-scheduled');
    var list = $('sched-list'), empty = '<div style="text-align:center;padding:20px;color:var(--muted)">No scheduled posts yet.</div>';
    list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading...</div>';
    db.collection('scheduled_posts').where('authorId', '==', state.user.uid).get().then(function (snap) {
      if (snap.empty) { list.innerHTML = empty; return; }
      list.innerHTML = snap.docs.sort(function (a, b) { return (a.data().scheduledAt || 0) - (b.data().scheduledAt || 0); }).map(function (d) {
        var s = d.data();
        return '<div class="sched-item"><div style="font-size:12px;color:var(--moon)">' + esc2(s.text || '') + '</div>' +
          '<div style="font-size:10px;color:var(--muted);margin-top:4px">Scheduled: ' + new Date(s.scheduledAt).toLocaleString() + '</div>' +
          '<button onclick="deleteScheduled(\'' + d.id + '\')" style="margin-top:6px;font-size:10px;background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);border-radius:20px;padding:3px 10px;color:#fca5a5;cursor:pointer">Delete</button></div>';
      }).join('');
    }).catch(function (e) { console.warn('[scheduled]', e && e.message); list.innerHTML = empty; });
  };

  // ── 7. Leaderboard: Sparks = real posts, Fans = every user, Earners = only real recent earners ──
  var EARNER_WINDOW_DAYS = 30;
  function row(i, color, name, sub, badge) {
    var medals = ['🥇', '🥈', '🥉'];
    return '<div class="lb-item"><div class="lb-rank">' + (medals[i] || ('#' + (i + 1))) + '</div>' +
      '<div class="lb-av" style="background:' + esc2(color || 'var(--green)') + '">' + esc2((name || 'M').charAt(0).toUpperCase()) + '</div>' +
      '<div style="flex:1"><div style="font-size:12px;font-weight:700;color:var(--moon)">' + esc2(name || 'Mindvora user') + (badge ? '<span class="vbadge" style="margin-left:4px"></span>' : '') + '</div>' +
      '<div style="font-size:10px;color:var(--muted)">' + sub + '</div></div></div>';
  }
  window.loadLeaderboard = function (type) {
    var list = $('lb-list'); if (!list) return;
    var none = function (t) { list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">' + t + '</div>'; };
    list.innerHTML = '<div style="text-align:center;padding:20px;color:var(--muted)">Loading...</div>';
    if (type === 'sparks') {
      db.collection('sparks').orderBy('createdAt', 'desc').limit(200).get().then(function (snap) {
        var posts = snap.docs.map(function (d) { var s = d.data(); s._score = (s.likes || []).length * 2 + (s.commentCount || 0) * 3 + (s.reposts || 0) * 4 + (s.views || 0) * 0.01; return s; })
          .filter(function (s) { return !s.isLiveAnnouncement; }).sort(function (a, b) { return b._score - a._score; }).slice(0, 20);
        if (!posts.length) return none('No posts yet.');
        list.innerHTML = posts.map(function (s, i) {
          var kind = s.mediaType === 'video' ? '🎬 ' : s.mediaType === 'image' ? '📷 ' : '✦ ';
          return row(i, s.authorColor, s.authorName, kind + esc2(String(s.text || (s.mediaType ? 'Media post' : '')).slice(0, 60)) + ' · ❤️ ' + (s.likes || []).length + ' 💬 ' + (s.commentCount || 0) + ' 🔁 ' + (s.reposts || 0), s.isVerified || s.isPremium);
        }).join('');
      }).catch(function () { none('No posts yet.'); });
      return;
    }
    if (type === 'fans') {
      db.collection('users').limit(500).get().then(function (snap) {
        var us = snap.docs.map(function (d) { return d.data(); }).filter(function (u) { return u.name || u.handle; })
          .sort(function (a, b) { return (b.followers || 0) - (a.followers || 0); });
        if (!us.length) return none('No users yet.');
        list.innerHTML = us.slice(0, 100).map(function (u, i) { return row(i, u.color, u.name, '@' + esc2(u.handle || 'user') + ' · ' + (u.followers || 0) + ' fans', u.isVerified || u.isPremium); }).join('');
      }).catch(function () { none('No users yet.'); });
      return;
    }
    // Earners: only users with a real earning recorded by the server in the last 30 days.
    var cutoff = new Date(Date.now() - EARNER_WINDOW_DAYS * 864e5);
    db.collection('users').where('lastEarnedAt', '>=', cutoff).limit(200).get().then(function (snap) {
      var us = snap.docs.map(function (d) { return d.data(); }).filter(function (u) { return (u.earnings || 0) + (u.tips || 0) > 0 || (u.grossEarnings || 0) > 0; })
        .sort(function (a, b) { return (b.grossEarnings || b.earnings || 0) - (a.grossEarnings || a.earnings || 0); });
      if (!us.length) return none('No earners yet. Users appear here once they earn on Mindvora, and drop off after ' + EARNER_WINDOW_DAYS + ' days without earning.');
      list.innerHTML = us.slice(0, 50).map(function (u, i) { return row(i, u.color, u.name, '@' + esc2(u.handle || 'user') + ' · $' + Number(u.grossEarnings || u.earnings || 0).toFixed(2) + ' earned', u.isVerified || u.isPremium); }).join('');
    }).catch(function () { none('No earners yet.'); });
  };
})();
