// Mindvora — voice & video calls (1-to-1, WebRTC)
// Signalling runs over the existing backend WebSocket (MindvoraRT).
// Media goes directly phone-to-phone, or through a TURN relay when a
// mobile network blocks direct connections.
// ONE socket only: returning to the app (visibilitychange) used to open a second socket while the
// first was still open; the call's offer/answer then went to the wrong socket -> "Connecting…" / "answer failed".
(function () {
  if (window.MindvoraRT && MindvoraRT.connect && !MindvoraRT._oneSocket) {
    var _connect = MindvoraRT.connect;
    MindvoraRT.connect = function () { if (MindvoraRT.isConnected && MindvoraRT.isConnected()) return; return _connect.apply(this, arguments); };
    MindvoraRT._oneSocket = true;
  }
})();
var MVCall = (function () {
  'use strict';

  var call = null;           // { id, peer, peerName, media, role, pc, local, remote, state, startedAt }
  var iceCache = null, iceAt = 0, authFail = false;
  var authed = false;
  var ringCtx = null, ringTimer = null;
  var pendingIce = [];

  // ── helpers ──────────────────────────────────────────────────────────
  function $(id) { return document.getElementById(id); }
  function toast(m) { if (typeof showToast === 'function') showToast(m); }
  function uid() { return (typeof auth !== 'undefined' && auth.currentUser) ? auth.currentUser.uid : null; }
  function myName() { return (typeof state !== 'undefined' && state.profile && state.profile.name) || 'Someone'; }
  function newId() { return 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
  function send(o) { MindvoraRT.send(o); }
  function safe(t) { return String(t || '').replace(/[<>&"']/g, function (c) { return '&#' + c.charCodeAt(0) + ';'; }); }

  // ── auth on every (re)connect ───────────────────────────────────────
  function authSocket() {
    var u = (typeof auth !== 'undefined') ? auth.currentUser : null;
    if (!u) return;
    u.getIdToken(authFail).then(function (t) {
      authFail = false;
      send({ type: 'AUTH', token: t });
      if (call && call.state === 'active') send({ type: 'CALL_REATTACH', callId: call.id });
    }).catch(function () {});
  }

  var STUN_ONLY = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];
  // A single bad relay address (space, typo, missing password) makes the browser
  // refuse to create the call connection — keep only valid entries.
  function cleanIce(list) {
    var out = [];
    (Array.isArray(list) ? list : []).forEach(function (s) {
      if (!s) return;
      var urls = [].concat(s.urls || s.url || []).join(',').split(/[\s,]+/).filter(function (u) { return /^(stun|turns?):[^\s]+$/i.test(u); });
      var hasCred = !!(s.username && s.credential !== undefined && s.credential !== null);
      if (!hasCred) urls = urls.filter(function (u) { return /^stun:/i.test(u); });
      if (!urls.length) return;
      var e = { urls: urls };
      if (hasCred) { e.username = String(s.username); e.credential = String(s.credential); }
      out.push(e);
    });
    return out.length ? out : STUN_ONLY;
  }
  function getIce() {
    if (iceCache && Date.now() - iceAt < 20 * 60 * 1000) return Promise.resolve(iceCache);
    var fallback = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] },
      { urls: ['turn:openrelay.metered.ca:80', 'turn:openrelay.metered.ca:443', 'turn:openrelay.metered.ca:443?transport=tcp'],
        username: 'openrelayproject', credential: 'openrelayproject' }];
    if (typeof mvApi !== 'function') return Promise.resolve(fallback);
    return mvApi('/api/rtc/ice-servers').then(function (d) {
      if (d && d.iceServers) { iceCache = cleanIce(d.iceServers); iceAt = Date.now(); return iceCache; }
      return fallback;
    }).catch(function () { return fallback; });
  }
  // Warm up the ICE list early so the call doesn't wait on it.
  setTimeout(function () { if (uid()) getIce(); }, 8000);

  // ── ringtones (generated, no audio files = no extra download) ──────
  // Voice call  : classic double ring  (ring-ring … pause)
  // Video call  : rising 3-note chime  (ding-ding-DING … pause)
  // Calling out : soft long "ringback" beep so the caller hears it ringing
  var actx = null;
  function getCtx() {
    try {
      if (!actx) actx = new (window.AudioContext || window.webkitAudioContext)();
      if (actx.state === 'suspended') actx.resume().catch(function () {});
    } catch (e) { actx = null; }
    return actx;
  }
  // Phones only allow sound after the user has touched the page once — unlock early.
  ['pointerdown', 'touchstart', 'keydown'].forEach(function (ev) {
    document.addEventListener(ev, function () { getCtx(); }, { passive: true, capture: true });
  });
  function tone(freqs, at, dur, vol, type) {
    var c = actx; if (!c) return;
    var g = c.createGain();
    g.gain.setValueAtTime(0.0001, at);
    g.gain.exponentialRampToValueAtTime(vol, at + 0.03);
    g.gain.setValueAtTime(vol, at + Math.max(0.04, dur - 0.06));
    g.gain.exponentialRampToValueAtTime(0.0001, at + dur);
    g.connect(c.destination);
    freqs.forEach(function (f) {
      var o = c.createOscillator(); o.type = type || 'sine'; o.frequency.value = f;
      o.connect(g); o.start(at); o.stop(at + dur + 0.02);
    });
  }
  var PATTERNS = {
    voice:    { every: 3000, vib: [700, 300, 700], play: function (t) { tone([400, 450], t, 0.4, 0.22); tone([400, 450], t + 0.6, 0.4, 0.22); } },
    video:    { every: 2400, vib: [150, 100, 150, 100, 500], play: function (t) {
      [659.3, 784, 1046.5].forEach(function (f, i) { tone([f], t + i * 0.2, 0.32, 0.2, 'triangle'); });
      [659.3, 784, 1046.5].forEach(function (f, i) { tone([f], t + 0.8 + i * 0.2, 0.32, 0.2, 'triangle'); }); } },
    ringback: { every: 4000, vib: null, play: function (t) { tone([440, 480], t, 1.4, 0.08); } },
  };
  function ring(kind) {
    stopRing();
    var pat = PATTERNS[kind] || PATTERNS.voice;
    var beat = function () {
      var c = getCtx();
      if (c && c.state === 'running') { try { pat.play(c.currentTime + 0.02); } catch (e) {} }
      if (pat.vib && navigator.vibrate) { try { navigator.vibrate(pat.vib); } catch (e) {} }
    };
    beat(); ringTimer = setInterval(beat, pat.every);
  }
  function stopRing() {
    clearInterval(ringTimer); ringTimer = null;
    if (navigator.vibrate) { try { navigator.vibrate(0); } catch (e) {} }
  }

  // ── UI ──────────────────────────────────────────────────────────────
  function ui() {
    var el = $('mv-call');
    if (el) return el;
    el = document.createElement('div');
    el.id = 'mv-call';
    el.className = 'mv-call';
    el.innerHTML =
      '<video id="mv-call-remote" class="mv-call-remote" autoplay playsinline muted></video>' +
      '<video id="mv-call-local" class="mv-call-local" autoplay playsinline muted></video>' +
      '<div class="mv-call-info"><div class="mv-call-av" id="mv-call-av"></div>' +
      '<div class="mv-call-name" id="mv-call-name"></div><div class="mv-call-status" id="mv-call-status"></div>' +
      '<div class="mv-call-timer" id="mv-call-timer" style="display:none;font-size:18px;font-weight:700;margin-top:6px;font-variant-numeric:tabular-nums;text-shadow:0 1px 4px rgba(0,0,0,.6)"></div>' +
      '<button type="button" id="mv-call-unmute" onclick="MVCall.playSound()" style="display:none;margin-top:10px;background:#16a34a;color:#fff;border:0;border-radius:20px;padding:8px 16px;font-weight:700">🔊 Tap to hear the call</button></div>' +
      '<div class="mv-call-bar" id="mv-call-bar-in">' +
        '<button class="mv-cb mv-cb-decline" onclick="MVCall.decline()" aria-label="Decline">✕</button>' +
        '<button class="mv-cb mv-cb-accept" onclick="MVCall.accept()" aria-label="Accept">✓</button>' +
      '</div>' +
      '<div class="mv-call-bar" id="mv-call-bar-on">' +
        '<button class="mv-cb" id="mv-cb-mute" onclick="MVCall.toggleMute()" aria-label="Mute">🎙️</button>' +
        '<button class="mv-cb" id="mv-cb-cam" onclick="MVCall.toggleCam()" aria-label="Camera">📷</button>' +
        '<button class="mv-cb" id="mv-cb-flip" onclick="MVCall.flip()" aria-label="Switch camera">🔄</button>' +
        '<button class="mv-cb" id="mv-cb-spk" onclick="MVCall.toggleSpeaker()" aria-label="Speaker">🔊</button>' +
        '<button class="mv-cb mv-cb-decline" onclick="MVCall.hangup()" aria-label="Hang up">✕</button>' +
      '</div>' +
      '<audio id="mv-call-audio" autoplay></audio>';
    document.body.appendChild(el);
    return el;
  }
  function show(mode) {
    var el = ui();
    el.classList.add('open');
    el.classList.toggle('video', call && call.media === 'video');
    $('mv-call-name').textContent = call ? call.peerName : '';
    $('mv-call-av').textContent = call ? String(call.peerName || '?').charAt(0).toUpperCase() : '';
    $('mv-call-bar-in').style.display = mode === 'incoming' ? 'flex' : 'none';
    $('mv-call-bar-on').style.display = mode === 'incoming' ? 'none' : 'flex';
    var isVid = call && call.media === 'video';
    $('mv-cb-cam').style.display = isVid ? '' : 'none';
    $('mv-cb-flip').style.display = isVid ? '' : 'none';
  }
  function status(t) { var s = $('mv-call-status'); if (s) s.textContent = t; }
  var durTimer = null, connectTimer = null;
  function fmt(sec) {
    var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), x = sec % 60;
    return (h ? h + ':' + ('0' + m).slice(-2) : ('0' + m).slice(-2)) + ':' + ('0' + x).slice(-2);
  }
  function startDuration() {
    if (!call || call.connectedAt) return;
    call.connectedAt = Date.now();
    clearTimeout(connectTimer); connectTimer = null;
    status(call.media === 'video' ? 'Video call' : 'Voice call');
    var el = $('mv-call-timer'); if (el) { el.style.display = 'block'; el.textContent = '00:00'; }
    clearInterval(durTimer);
    durTimer = setInterval(function () {
      if (!call || !call.connectedAt) return clearInterval(durTimer);
      var t = $('mv-call-timer'); if (t) t.textContent = fmt(Math.floor((Date.now() - call.connectedAt) / 1000));
    }, 1000);
  }
  function onConnected() {
    if (!call) return;
    call.retries = 0;
    if (!call.connectedAt) { startDuration(); logRoute(); }
    else status(call.media === 'video' ? 'Video call' : 'Voice call');
  }
  // Give up cleanly if the two phones can't reach each other.
  function armConnectTimeout() {
    clearTimeout(connectTimer);
    connectTimer = setTimeout(function () {
      if (!call || call.connectedAt) return;
      status('Still connecting…');
      if (call.role === 'caller' && call.pc) restartIce();
      connectTimer = setTimeout(function () {
        if (!call || call.connectedAt) return;
        console.warn('[call] could not connect — candidate types seen:', call.candTypes);
        toast('Could not connect the call. One of you may be on a network that blocks calls — try Wi-Fi, or try again.');
        hangup();
      }, 25000);
    }, 20000);
  }
  function restartIce() {
    var pc = call.pc;
    pc.createOffer({ iceRestart: true }).then(function (o) { return pc.setLocalDescription(o); })
      .then(function () { send({ type: 'CALL_SIGNAL', callId: call.id, data: { sdp: pc.localDescription } }); })
      .catch(function (e) { console.warn('[call] ICE restart failed', e); });
  }
  function logRoute() {
    var pc = call && call.pc; if (!pc || !pc.getStats) return;
    pc.getStats().then(function (st) {
      st.forEach(function (r) {
        if (r.type === 'candidate-pair' && (r.selected || r.nominated) && r.state === 'succeeded') {
          var lc = st.get(r.localCandidateId);
          console.log('[call] connected via', lc ? lc.candidateType : '?', '(relay = through TURN)');
        }
      });
    }).catch(function () {});
  }
  function playRemote() {
    var a = $('mv-call-audio'), v = $('mv-call-remote'), btn = $('mv-call-unmute');
    var p = a && a.srcObject ? a.play() : null;
    if (v && v.srcObject) v.play().catch(function () {});
    if (p && p.catch) p.then(function () { if (btn) btn.style.display = 'none'; })
      .catch(function () { if (btn) btn.style.display = 'inline-block'; });
  }
  function hide() {
    var el = $('mv-call');
    if (el) el.classList.remove('open', 'video');
    clearInterval(durTimer); clearTimeout(connectTimer); connectTimer = null;
    var t = $('mv-call-timer'); if (t) { t.style.display = 'none'; t.textContent = ''; }
    var b = $('mv-call-unmute'); if (b) b.style.display = 'none';
  }

  // ── media ───────────────────────────────────────────────────────────
  function getMedia(media, facing) {
    var audio = { echoCancellation: true, noiseSuppression: true, autoGainControl: true };
    var video = media === 'video'
      ? { width: { ideal: 1280, max: 1280 }, height: { ideal: 720, max: 720 }, frameRate: { ideal: 30, max: 30 }, facingMode: facing || 'user' }
      : false;
    return navigator.mediaDevices.getUserMedia({ audio: audio, video: video }).catch(function (e) {
      // Some phones reject the size/frame-rate hints — retry with plain settings.
      if (e && (e.name === 'OverconstrainedError' || e.name === 'NotReadableError' || e.name === 'AbortError'))
        return navigator.mediaDevices.getUserMedia({ audio: true, video: media === 'video' ? { facingMode: facing || 'user' } : false });
      throw e;
    });
  }
  function mediaError(e) {
    var n = e && e.name;
    if (n === 'NotAllowedError') return 'Allow microphone' + (call && call.media === 'video' ? ' and camera' : '') + ' access in your browser settings to call.';
    if (n === 'NotFoundError') return 'No microphone or camera found on this device.';
    if (n === 'NotReadableError') return 'Your camera or microphone is being used by another app.';
    if (location.protocol !== 'https:' && location.hostname !== 'localhost') return 'Calls only work on https:// pages.';
    return 'Could not start your microphone/camera.';
  }

  // ── peer connection ─────────────────────────────────────────────────
  function buildPc(ice) {
    var cfg = { iceServers: cleanIce(ice), bundlePolicy: 'max-bundle', rtcpMuxPolicy: 'require' };
    var pc;
    try { pc = new RTCPeerConnection(cfg); }
    catch (e) { console.warn('[call] relay settings rejected, using STUN only:', e && e.message); cfg.iceServers = STUN_ONLY; pc = new RTCPeerConnection(cfg); }
    call.pc = pc;
    call.local.getTracks().forEach(function (t) {
      var sender = pc.addTrack(t, call.local);
      if (t.kind === 'video') {
        try { t.contentHint = 'motion'; } catch (e) {}
        try {
          var p = sender.getParameters();
          p.degradationPreference = 'maintain-framerate';   // drop resolution before frames: smoother on weak networks
          if (p.encodings && p.encodings[0]) p.encodings[0].maxBitrate = 1500000;
          sender.setParameters(p).catch(function () {});
        } catch (e) {}
      }
    });
    if (!call.noCodecPrefs) preferCodecs(pc);
    call.candTypes = {};
    pc.onicecandidate = function (e) {
      if (!call || call.pc !== pc || !e.candidate) return;
      var ty = (String(e.candidate.candidate).match(/ typ (\w+)/) || [])[1] || '?';
      call.candTypes[ty] = (call.candTypes[ty] || 0) + 1;
      send({ type: 'CALL_SIGNAL', callId: call.id, data: { ice: e.candidate.toJSON ? e.candidate.toJSON() : e.candidate } });
    };
    pc.ontrack = function (e) {
      if (!call || call.pc !== pc) return;
      var stream = (e.streams && e.streams[0]) || call.remote || new MediaStream();
      if (!e.streams || !e.streams[0]) { try { stream.addTrack(e.track); } catch (x) {} }
      call.remote = stream;
      if (call.media === 'video') $('mv-call-remote').srcObject = stream;
      $('mv-call-audio').srcObject = stream;
      playRemote();
    };
    var stateChange = function () {
      if (!call || call.pc !== pc) return;
      var st = pc.connectionState || pc.iceConnectionState, ice = pc.iceConnectionState;
      if (st === 'connected' || ice === 'connected' || ice === 'completed') { onConnected(); return; }
      if (st === 'disconnected' || ice === 'disconnected') { if (call.connectedAt) status('Reconnecting…'); return; }
      if (st === 'failed' || ice === 'failed') {
        // ICE restart instead of dropping the call (network switch Wi-Fi ↔ mobile data)
        if (call.role === 'caller' && (call.retries = (call.retries || 0) + 1) <= 3) { status('Reconnecting…'); restartIce(); }
        else if (call.role !== 'caller') status('Reconnecting…');
        else { toast(call.connectedAt ? 'Call dropped — network too weak.' : 'Could not connect the call. Try Wi-Fi, or try again.'); hangup(); }
      }
    };
    pc.onconnectionstatechange = stateChange;
    pc.oniceconnectionstatechange = stateChange;
    return pc;
  }
  // Opus for voice; for video prefer the codec phones decode in hardware (H.264), then VP8.
  function preferCodecs(pc) {
    if (!window.RTCRtpSender || !RTCRtpSender.getCapabilities) return;
    pc.getTransceivers().forEach(function (tr) {
      if (!tr.sender || !tr.sender.track || !tr.setCodecPreferences) return;
      // Codec preferences are RECEIVE preferences: they must come from the receiver's
      // list. Using the sender's list made phones offer codecs they cannot decode,
      // and setting the answer then failed ("answer failed").
      var kind = tr.sender.track.kind, caps = window.RTCRtpReceiver && RTCRtpReceiver.getCapabilities ? RTCRtpReceiver.getCapabilities(kind) : null;
      if (!caps) return;
      var order = kind === 'audio' ? ['audio/opus'] : ['video/H264', 'video/VP8', 'video/VP9'];
      var sorted = caps.codecs.slice().sort(function (a, b) {
        var ia = order.indexOf(a.mimeType), ib = order.indexOf(b.mimeType);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      });
      try { tr.setCodecPreferences(sorted); } catch (e) {}
    });
  }
  // Make sure an offer/answer has proper CRLF line endings before handing it to WebRTC.
  // If any layer in between turned \r\n into \n (or added spaces), setRemoteDescription fails.
  function fixSdp(d) {
    if (!d || typeof d.sdp !== 'string') return d;
    var t = d.sdp.replace(/\r\n|\r|\n/g, '\n').split('\n').map(function (l) { return l.replace(/\s+$/, ''); })
      .filter(function (l) { return l.length; }).join('\r\n') + '\r\n';
    return { type: d.type, sdp: t };
  }
  function flushIce() {
    var pc = call && call.pc;
    if (!pc || !pc.remoteDescription) return;
    pendingIce.splice(0).forEach(function (c) { if (!c || !c.candidate) return; pc.addIceCandidate(c).catch(function (e) { console.warn('[call] bad ICE', e && e.message); }); });
  }

  // ── outgoing ────────────────────────────────────────────────────────
  function start(peerUid, peerName, media) {
    if (!uid()) { toast('Log in to make calls.'); return; }
    if (call) { toast('You are already in a call.'); return; }
    if (!window.RTCPeerConnection || !navigator.mediaDevices) { toast('This browser does not support calls. Try Chrome or Safari.'); return; }
    call = { id: newId(), peer: peerUid, peerName: peerName || 'User', media: media === 'video' ? 'video' : 'audio', role: 'caller', state: 'calling' };
    show('outgoing'); status('Starting…');
    Promise.all([getMedia(call.media), getIce()]).then(function (r) {
      if (!call) { r[0].getTracks().forEach(function (t) { t.stop(); }); return; }
      call.local = r[0]; call.ice = r[1];
      if (call.media === 'video') $('mv-call-local').srcObject = call.local;
      if (!MindvoraRT.isConnected()) { MindvoraRT.connect(); status('Connecting…'); }
      var go = function () {
        if (!call) return;
        send({ type: 'CALL_INVITE', callId: call.id, to: call.peer, media: call.media, name: myName() });
        status('Calling…'); ring('ringback');
        // Build the connection while it rings, so it starts instantly on answer.
        buildPc(call.ice);
      };
      if (authed) go(); else {
        call.onAuth = go; authSocket();
        // The free server sleeps; wake it and keep retrying sign-in for up to ~45s.
        try { fetch((window.BACKEND_URL || '') + '/api/health', { cache: 'no-store' }).catch(function(){}); } catch (e) {}
        var tries = 0;
        var retry = setInterval(function () {
          if (!call || !call.onAuth) { clearInterval(retry); return; }
          tries++;
          if (!MindvoraRT.isConnected()) MindvoraRT.connect(); else authSocket();
          if (tries === 2) status('Waking up the call server…');
          if (tries >= 9) {
            clearInterval(retry);
            status(authFail ? 'Call server could not confirm your login. Log out, log in again, then retry.' : 'Could not reach the call server. Check your internet and try again.');
          }
        }, 5000);
      }
    }).catch(function (e) { toast(mediaError(e)); cleanup(); });
  }

  // ── incoming ────────────────────────────────────────────────────────
  var autoAnswer = null;
  try {
    var q0 = new URLSearchParams(location.search);
    if (q0.get('call') && q0.get('answer') === '1') autoAnswer = q0.get('call');
    if (q0.get('call')) history.replaceState(null, '', location.pathname);
  } catch (e) {}
  function incoming(m) {
    if (call && call.id === m.callId) return;          // same call delivered twice (reconnect)
    if (call) { send({ type: 'CALL_DECLINE', callId: m.callId, reason: 'busy' }); return; }
    call = { id: m.callId, peer: m.from, peerName: m.fromName || 'User', media: m.media === 'video' ? 'video' : 'audio', role: 'callee', state: 'ringing' };
    show('incoming');
    status(call.media === 'video' ? 'Incoming video call' : 'Incoming voice call');
    ring(call.media === 'video' ? 'video' : 'voice');
    getIce(); // warm up
    if (autoAnswer && autoAnswer === m.callId) { autoAnswer = null; setTimeout(accept, 300); }
  }
  function accept() {
    if (!call || call.state !== 'ringing') return;
    stopRing(); status('Connecting…'); show('active');
    call.state = 'accepting';
    Promise.all([getMedia(call.media), getIce()]).then(function (r) {
      if (!call) { r[0].getTracks().forEach(function (t) { t.stop(); }); return; }
      call.local = r[0]; call.ice = r[1];
      if (call.media === 'video') $('mv-call-local').srcObject = call.local;
      try { buildPc(r[1]); } catch (e) { toast('Could not start the call (' + why(e) + ').'); decline(); return; }
      call.state = 'active';
      send({ type: 'CALL_ACCEPT', callId: call.id });
      armConnectTimeout();
      flushIce();
      if (call.offer) answerOffer(call.offer);
    }).catch(function (e) { console.error('[call] accept failed', e); toast(mediaError(e)); decline(); });
  }
  function why(e) { return String((e && (e.name ? e.name + ': ' : '') + (e.message || e)) || 'unknown').slice(0, 110); }
  function answerOffer(sdp) {
    sdp = fixSdp(sdp);
    var c = call; if (!c || !c.pc) return;
    c.sigQ = (c.sigQ || Promise.resolve()).then(function () {
      var pc = c.pc;
      if (call !== c || pc.signalingState === 'closed') return;
      if (c.lastOffer === sdp.sdp && pc.signalingState === 'stable' && pc.remoteDescription) return; // same offer twice
      c.lastOffer = sdp.sdp;
      var pre = pc.signalingState === 'have-local-offer' ? pc.setLocalDescription({ type: 'rollback' }) : Promise.resolve();
      return pre.then(function () { return pc.setRemoteDescription(sdp); })
        .then(function () { flushIce(); return pc.createAnswer(); })
        .then(function (a) { return pc.setLocalDescription(a); })
        .then(function () { send({ type: 'CALL_SIGNAL', callId: c.id, data: { sdp: pc.localDescription } }); });
    }).catch(function (e) {
      console.error('[call] answer failed', e);
      if (call !== c) return;
      if (!c.answerRetried) {
        // Retry once on a fresh connection with default codecs.
        c.answerRetried = true; c.noCodecPrefs = true; c.lastOffer = null;
        try { c.pc.close(); } catch (x) {}
        buildPc(c.ice);
        pendingIce = (c.allIce || []).slice();
        return answerOffer(sdp);
      }
      toast('Call could not connect (answer failed: ' + why(e) + '). Try again.');
      hangup();
    });
  }
  function decline() {
    if (!call) return;
    send({ type: 'CALL_DECLINE', callId: call.id });
    cleanup();
  }
  function hangup() {
    if (!call) return;
    send({ type: 'CALL_END', callId: call.id });
    cleanup();
  }
  function cleanup() {
    stopRing();
    if (call && call.connectedAt) toast((call.media === 'video' ? 'Video' : 'Voice') + ' call ended · ' + fmt(Math.floor((Date.now() - call.connectedAt) / 1000)));
    if (call) {
      if (call.pc) { try { call.pc.close(); } catch (e) {} }
      if (call.local) call.local.getTracks().forEach(function (t) { t.stop(); });
    }
    call = null; pendingIce = [];
    ['mv-call-remote', 'mv-call-local', 'mv-call-audio'].forEach(function (id) { var v = $(id); if (v) v.srcObject = null; });
    hide();
  }

  // ── controls ────────────────────────────────────────────────────────
  function toggleMute() {
    if (!call || !call.local) return;
    var t = call.local.getAudioTracks()[0]; if (!t) return;
    t.enabled = !t.enabled; $('mv-cb-mute').classList.toggle('off', !t.enabled);
  }
  function toggleCam() {
    if (!call || !call.local) return;
    var t = call.local.getVideoTracks()[0]; if (!t) return;
    t.enabled = !t.enabled; $('mv-cb-cam').classList.toggle('off', !t.enabled);
  }
  function flip() {
    if (!call || !call.local || call.media !== 'video') return;
    call.facing = call.facing === 'environment' ? 'user' : 'environment';
    navigator.mediaDevices.getUserMedia({ video: { facingMode: call.facing, width: { ideal: 1280 }, height: { ideal: 720 } } }).then(function (s) {
      var nt = s.getVideoTracks()[0], old = call.local.getVideoTracks()[0];
      var sender = call.pc.getSenders().find(function (x) { return x.track && x.track.kind === 'video'; });
      if (sender) sender.replaceTrack(nt);
      if (old) { call.local.removeTrack(old); old.stop(); }
      call.local.addTrack(nt); $('mv-call-local').srcObject = call.local;
    }).catch(function () { toast('Could not switch camera.'); });
  }
  function toggleSpeaker() {
    var a = $('mv-call-audio'); if (!a) return;
    a.muted = !a.muted; $('mv-cb-spk').classList.toggle('off', a.muted);
  }

  // ── signalling messages ─────────────────────────────────────────────
  MindvoraRT.onOpen(function () { authed = false; authSocket(); });
  MindvoraRT.onMessage(function (m) {
    switch (m.type) {
      case 'AUTH_OK':
        authed = true;
        if (call && call.onAuth) { var f = call.onAuth; call.onAuth = null; f(); }
        break;
      case 'CALL_INCOMING': incoming(m); break;
      case 'CALL_RINGING':
        if (call && call.id === m.callId) status('Ringing…');
        break;
      case 'CALL_ACCEPTED':
        if (!call || call.id !== m.callId) return;
        stopRing(); call.state = 'active'; status('Connecting…');
        armConnectTimeout();
        call.pc.createOffer().then(function (o) { return call.pc.setLocalDescription(o); })
          .then(function () { send({ type: 'CALL_SIGNAL', callId: call.id, data: { sdp: call.pc.localDescription } }); })
          .catch(function (e) { console.error('[call] offer failed', e); toast('Call could not connect (' + why(e) + '). Try again.'); hangup(); });
        break;
      case 'CALL_SIGNAL':
        if (!call || call.id !== m.callId || !m.data) return;
        if (m.data.sdp) {
          if (m.data.sdp.type === 'offer') {
            if (!call.pc) { call.offer = m.data.sdp; return; }
            answerOffer(m.data.sdp);
          } else if (m.data.sdp.type === 'answer' && call.pc) {
            call.pc.setRemoteDescription(fixSdp(m.data.sdp)).then(flushIce).catch(function (e) { console.error('[call] set answer failed', e); toast('Call could not connect (set answer failed: ' + why(e) + '). Try again.'); hangup(); });
          }
        } else if (m.data.ice) {
          (call.allIce = call.allIce || []).push(m.data.ice);
          pendingIce.push(m.data.ice); flushIce();
        }
        break;
      case 'CALL_DECLINED':
        if (call && call.id === m.callId) { toast(m.reason === 'busy' ? (call.peerName + ' is on another call.') : 'Call declined.'); cleanup(); }
        break;
      case 'CALL_ENDED':
        if (call && call.id === m.callId) {
          var why = { 'no-answer': 'No answer.', 'connection-lost': 'Call dropped.', cancelled: 'Missed call.' }[m.reason];
          if (why) toast(why);
          cleanup();
        }
        break;
      case 'CALL_TAKEN':
        if (call && call.id === m.callId && call.role === 'callee' && call.state === 'ringing') cleanup();
        break;
      case 'CALL_ERROR':
        if (m.code === 'AUTH_FAILED') { authed = false; authFail = true; return; }
        toast(m.message || 'Call failed.');
        if (call && (!m.callId || m.callId === call.id)) cleanup();
        break;
    }
  });
  // Re-auth when the user logs in after the socket opened.
  if (typeof auth !== 'undefined') auth.onAuthStateChanged(function (u) { if (u && MindvoraRT.isConnected()) authSocket(); });
  window.addEventListener('beforeunload', function () { if (call) send({ type: 'CALL_END', callId: call.id }); });

  // Android app: separate notification channels so voice and video calls ring with different sounds
  // (sound files voice_ring / video_ring are bundled in the app's res/raw).
  try {
    var CAP = window.Capacitor;
    if (CAP && CAP.isNativePlatform && CAP.isNativePlatform()) {
      var PN = CAP.Plugins && CAP.Plugins.PushNotifications;
      if (PN && PN.createChannel) {
        PN.createChannel({ id: 'calls_voice', name: 'Voice calls', importance: 5, sound: 'voice_ring', vibration: true, visibility: 1 }).catch(function () {});
        PN.createChannel({ id: 'calls_video', name: 'Video calls', importance: 5, sound: 'video_ring', vibration: true, visibility: 1 }).catch(function () {});
      }
    }
  } catch (e) {}

  return { start: start, accept: accept, decline: decline, hangup: hangup, toggleMute: toggleMute,
    toggleCam: toggleCam, flip: flip, toggleSpeaker: toggleSpeaker, playSound: playRemote, active: function () { return !!call; } };
})();
