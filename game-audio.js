/* Mindvora game audio — additive module; game rules and UI remain unchanged. */
(function () {
  'use strict';
  if (window.MVGameAudio) return;

  var tracks = {
    typing: '/music/electric-dreams.mp3',
    memory: '/music/chill-vibes.mp3',
    trivia: '/music/deep-focus.mp3'
  };
  var bg = null;
  var audioCtx = null;

  function stopBackground() {
    if (!bg) return;
    try { bg.pause(); bg.currentTime = 0; } catch (e) {}
    bg = null;
  }
  function startBackground(game) {
    stopBackground();
    var src = tracks[game]; if (!src) return;
    bg = new Audio(src); bg.loop = true; bg.volume = 0.18; bg.preload = 'auto';
    bg.play().catch(function () {}); // the game launch click is the user gesture
  }
  function context() {
    if (!audioCtx) {
      var C = window.AudioContext || window.webkitAudioContext;
      if (C) audioCtx = new C();
    }
    if (audioCtx && audioCtx.state === 'suspended') audioCtx.resume().catch(function () {});
    return audioCtx;
  }
  function tone(freq, at, length, gain, type) {
    var c = context(); if (!c) return;
    var o = c.createOscillator(), g = c.createGain();
    o.type = type || 'sine'; o.frequency.setValueAtTime(freq, c.currentTime + at);
    g.gain.setValueAtTime(0.0001, c.currentTime + at);
    g.gain.exponentialRampToValueAtTime(gain || 0.08, c.currentTime + at + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, c.currentTime + at + length);
    o.connect(g); g.connect(c.destination); o.start(c.currentTime + at); o.stop(c.currentTime + at + length + 0.03);
  }
  function melody(notes, type) { notes.forEach(function (n) { tone(n[0], n[1], n[2] || 0.22, n[3] || 0.07, type); }); }
  function result(kind, score, total) {
    stopBackground();
    if (kind === 'trivia') {
      var pct = total ? score / total : 0;
      if (pct >= 0.8) melody([[523.25, 0, .22], [659.25, .18, .22], [783.99, .36, .35], [1046.5, .62, .5]], 'triangle');
      else melody([[392, 0, .24], [349.23, .2, .24], [293.66, .4, .42]], 'sine');
    } else if (kind === 'typing') {
      melody([[523.25, 0, .18], [659.25, .15, .18], [783.99, .3, .4]], 'square');
    } else if (kind === 'memory') {
      if (score <= 16) melody([[392, 0, .16], [523.25, .14, .16], [659.25, .28, .2], [783.99, .46, .42]], 'triangle');
      else melody([[293.66, 0, .25], [246.94, .22, .3], [196, .48, .5]], 'sawtooth');
    }
  }
  window.MVGameAudio = { start: startBackground, stop: stopBackground, result: result };

  var oldLaunch = window.launchGame;
  if (typeof oldLaunch === 'function') {
    window.launchGame = function (game) {
      startBackground(game);
      return oldLaunch.apply(this, arguments);
    };
  }
  var oldClose = window.closeGame;
  if (typeof oldClose === 'function') {
    window.closeGame = function () { stopBackground(); return oldClose.apply(this, arguments); };
  }
})();
