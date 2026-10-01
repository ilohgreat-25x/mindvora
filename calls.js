// Mindvora — voice & video calls (1-to-1, WebRTC)
// Signalling runs over the existing backend WebSocket (MindvoraRT).
// Media goes directly phone-to-phone, or through a TURN relay when a
// mobile network blocks direct connections.
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

  function getIce() {
    if (iceCache && Date.now() - iceAt < 20 * 60 * 1000) return Promise.resolve(iceCache);
    var fallback = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];
    if (typeof mvApi !== 'function') return Promise.resolve(fallback);
    return mvApi('/api/rtc/ice-servers').then(function (d) {
      if (d && d.iceServers) { iceCache = d.iceServers; iceAt = Date.now(); return iceCache; }
      return fallback;
    }).catch(function () { return fallback; });
  }
  // Warm up the ICE list early so the call doesn't wait on it.
  setTimeout(function () { if (uid()) getIce(); }, 8000);

  // ── ringtone (generated, no audio file = no extra download) ─────────
  function ring(kind) {
    stopRing();
    try {
      ringCtx = new (window.AudioContext || window.webkitAudioContext)();
      var beep = function () {
        var o = ringCtx.createOscillator(), g = ringCtx.createGain();
        o.frequency.value = kind === 'in' ? 520 : 440;
        g.gain.setValueAtTime(0.0001, ringCtx.currentTime);
        g.gain.exponentialRampToValueAtTime(0.25, ringCtx.currentTime + 0.05);
        g.gain.exponentialRampToValueAtTime(0.0001, ringCtx.currentTime + 0.9);
        o.connect(g); g.connect(ringCtx.destination); o.start(); o.stop(ringCtx.currentTime + 1);
      };
      beep(); ringTimer = setInterval(beep, kind === 'in' ? 2000 : 3000);
    } catch (e) {}
    if (kind === 'in' && navigator.vibrate) { try { navigator.vibrate([400, 200, 400]); } catch (e) {} }
  }
  function stopRing() {
    clearInterval(ringTimer); ringTimer = null;
    if (ringCtx) { try { ringCtx.close(); } catch (e) {} ringCtx = null; }
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
      '<video id="mv-call-remote" class="mv-call-remote" autoplay playsinline></video>' +
      '<video id="mv-call-local" class="mv-call-local" autoplay playsinline muted></video>' +
      '<div class="mv-call-info"><div class="mv-call-av" id="mv-call-av"></div>' +
      '<div class="mv-call-name" id="mv-call-name"></div><div class="mv-call-status" id="mv-call-status"></div></div>' +
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
  var durTimer = null;
  function startDuration() {
    clearInterval(durTimer);
    call.startedAt = Date.now();
    durTimer = setInterval(function () {
      if (!call) return clearInterval(durTimer);
      var s = Math.floor((Date.now() - call.startedAt) / 1000);
      status(Math.floor(s / 60) + ':' + ('0' + (s % 60)).slice(-2));
    }, 1000);
  }
  function hide() {
    var el = $('mv-call');
    if (el) el.classList.remove('open', 'video');
    clearInterval(durTimer);
  }

  // ── media ───────────────────────────────────────────────────────────
  function getMedia(media, facing) {
    var audio = { echoCancellation: true, noiseSuppression: true, autoGainControl: true };
    var video = media === 'video'
      ? { width: { ideal: 1280, max: 1280 }, height: { ideal: 720, max: 720 }, frameRate: { ideal: 30, max: 30 }, facingMode: facing || 'user' }
      : false;
    return navigator.mediaDevices.getUserMedia({ audio: audio, video: video });
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
    var pc = new RTCPeerConnection({
      iceServers: ice, bundlePolicy: 'max-bundle', rtcpMuxPolicy: 'require', iceCandidatePoolSize: 4,
    });
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
    preferCodecs(pc);
    pc.onicecandidate = function (e) {
      if (e.candidate) send({ type: 'CALL_SIGNAL', callId: call.id, data: { ice: e.candidate } });
    };
    pc.ontrack = function (e) {
      var stream = e.streams[0];
      if (call.media === 'video') $('mv-call-remote').srcObject = stream;
      $('mv-call-audio').srcObject = stream;
    };
    pc.onconnectionstatechange = function () {
      if (!call || call.pc !== pc) return;
      var st = pc.connectionState;
      if (st === 'connected') { if (!call.startedAt) startDuration(); call.retries = 0; }
      else if (st === 'disconnected') status('Reconnecting…');
      else if (st === 'failed') {
        // ICE restart instead of dropping the call (network switch Wi-Fi ↔ mobile data)
        if (call.role === 'caller' && (call.retries = (call.retries || 0) + 1) <= 3) {
          status('Reconnecting…');
          pc.createOffer({ iceRestart: true }).then(function (o) { return pc.setLocalDescription(o); })
            .then(function () { send({ type: 'CALL_SIGNAL', callId: call.id, data: { sdp: pc.localDescription } }); })
            .catch(function () {});
        } else if (call.role !== 'caller') status('Reconnecting…');
        else { toast('Call dropped — network too weak.'); hangup(); }
      }
    };
    return pc;
  }
  // Opus for voice; for video prefer the codec phones decode in hardware (H.264), then VP8.
  function preferCodecs(pc) {
    if (!window.RTCRtpSender || !RTCRtpSender.getCapabilities) return;
    pc.getTransceivers().forEach(function (tr) {
      if (!tr.sender || !tr.sender.track || !tr.setCodecPreferences) return;
      var kind = tr.sender.track.kind, caps = RTCRtpSender.getCapabilities(kind);
      if (!caps) return;
      var order = kind === 'audio' ? ['audio/opus'] : ['video/H264', 'video/VP8', 'video/VP9'];
      var sorted = caps.codecs.slice().sort(function (a, b) {
        var ia = order.indexOf(a.mimeType), ib = order.indexOf(b.mimeType);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      });
      try { tr.setCodecPreferences(sorted); } catch (e) {}
    });
  }
  function flushIce() {
    var pc = call && call.pc;
    if (!pc || !pc.remoteDescription) return;
    pendingIce.splice(0).forEach(function (c) { pc.addIceCandidate(c).catch(function () {}); });
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
        status('Calling…'); ring('out');
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
  function incoming(m) {
    if (call) { send({ type: 'CALL_DECLINE', callId: m.callId, reason: 'busy' }); return; }
    call = { id: m.callId, peer: m.from, peerName: m.fromName || 'User', media: m.media === 'video' ? 'video' : 'audio', role: 'callee', state: 'ringing' };
    show('incoming');
    status(call.media === 'video' ? 'Incoming video call' : 'Incoming voice call');
    ring('in');
    getIce(); // warm up
  }
  function accept() {
    if (!call || call.state !== 'ringing') return;
    stopRing(); status('Connecting…'); show('active');
    call.state = 'accepting';
    Promise.all([getMedia(call.media), getIce()]).then(function (r) {
      if (!call) { r[0].getTracks().forEach(function (t) { t.stop(); }); return; }
      call.local = r[0];
      if (call.media === 'video') $('mv-call-local').srcObject = call.local;
      buildPc(r[1]);
      call.state = 'active';
      send({ type: 'CALL_ACCEPT', callId: call.id });
      flushIce();
      if (call.offer) answerOffer(call.offer);
    }).catch(function (e) { toast(mediaError(e)); decline(); });
  }
  function answerOffer(sdp) {
    var pc = call.pc;
    pc.setRemoteDescription(sdp).then(function () { flushIce(); return pc.createAnswer(); })
      .then(function (a) { return pc.setLocalDescription(a); })
      .then(function () { send({ type: 'CALL_SIGNAL', callId: call.id, data: { sdp: pc.localDescription } }); })
      .catch(function (e) { console.error('[call] answer failed', e); });
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
        if (call && call.id === m.callId) status(m.calleeOnline ? 'Ringing…' : 'Calling… (their app is closed — we sent a notification)');
        break;
      case 'CALL_ACCEPTED':
        if (!call || call.id !== m.callId) return;
        stopRing(); call.state = 'active'; status('Connecting…');
        call.pc.createOffer().then(function (o) { return call.pc.setLocalDescription(o); })
          .then(function () { send({ type: 'CALL_SIGNAL', callId: call.id, data: { sdp: call.pc.localDescription } }); });
        break;
      case 'CALL_SIGNAL':
        if (!call || call.id !== m.callId || !m.data) return;
        if (m.data.sdp) {
          if (m.data.sdp.type === 'offer') {
            if (!call.pc) { call.offer = m.data.sdp; return; }
            answerOffer(m.data.sdp);
          } else if (m.data.sdp.type === 'answer' && call.pc) {
            call.pc.setRemoteDescription(m.data.sdp).then(flushIce).catch(function (e) { console.error('[call]', e); });
          }
        } else if (m.data.ice) {
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

  return { start: start, accept: accept, decline: decline, hangup: hangup, toggleMute: toggleMute,
    toggleCam: toggleCam, flip: flip, toggleSpeaker: toggleSpeaker, active: function () { return !!call; } };
})();
