/*
 * MINDVORA — Sound Board sounds on photos / videos  ·  media-sounds.js
 *  • Post composer: after a photo/video is attached, "🔊 Add sound" opens a picker (preview, select, volume, start delay, remove).
 *  • Story composer: "🔊 Sound" next to 🎵 Music (photo stories).
 *  • The choice is saved on the post/story as sound:{id, vol, delay}. Only the id is stored; the file is always resolved
 *    from this app's own /sounds/ list, so nothing outside Mindvora can inject audio.
 *  • Viewing: photos play the sound when they scroll into view (🔊/🔇 toggle); videos play it in step with the video.
 *    Stories play it with the photo. The media file itself is never changed, so downloads stay silent/original.
 */
(function () {
  if (window.MVMediaSounds) return;
  var LIST = [
    ['laugh', '😂 Laugh', 'laughter'], ['dog', '🐶 Dog Bark', 'dog-bark'], ['applause', '👏 Applause', 'applause'],
    ['drumroll', '🥁 Drum Roll', 'drum-roll'], ['fanfare', '🎺 Fanfare', 'fanfare'], ['bell', '🔔 Bell', 'bell'],
    ['boom', '💥 Boom', 'boom'], ['partyhorn', '🎉 Party Horn', 'party-horn'], ['sadtrombone', '😢 Sad Trombone', 'sad-trombone'],
    ['zap', '⚡ Zap', 'zap'], ['cat', '🐱 Cat Meow', 'cat-meow'], ['guitar', '🎸 Guitar', 'guitar'],
    ['spooky', '👻 Spooky', 'spooky'], ['snore', '😴 Snore', 'snore'], ['ding', '🎵 Ding', 'ding'],
    ['scream', '😱 Scream', 'scream'], ['hahaha', '🤣 Ha Ha Ha', 'ha-ha-ha'], ['levelup', '🏆 Level Up', 'level-up'],
    ['wrongbuzz', '❌ Wrong Buzz', 'wrong-buzz']
  ].map(function (x) { return { id: x[0], label: x[1], url: '/sounds/' + x[2] + '.mp3' }; });

  function $(id) { return document.getElementById(id); }
  function toast(t) { if (typeof showToast === 'function') showToast(t); }
  function hx(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function byId(id) { for (var i = 0; i < LIST.length; i++) if (LIST[i].id === id) return LIST[i]; return null; }
  /** Validate a stored sound (data from Firestore is untrusted). */
  function clean(s) {
    if (!s || typeof s !== 'object') return null;
    var b = byId(s.id); if (!b) return null;
    var v = Number(s.vol); v = isFinite(v) ? Math.min(1, Math.max(0, v)) : 0.8;
    var d = Number(s.delay); d = isFinite(d) ? Math.min(10, Math.max(0, d)) : 0;
    return { id: b.id, label: b.label, url: b.url, vol: v, delay: d };
  }
  function stored(s) { return { id: s.id, vol: Math.round(s.vol * 100) / 100, delay: s.delay }; }

  // ── picker ──────────────────────────────────────────────────────────
  var pending = { post: null, story: null }, prev = null;
  function stopPrev() { if (prev) { try { prev.pause(); } catch (e) {} prev = null; } }
  function picker(slot, done) {
    stopPrev(); var old = $('mv-snd-pick'); if (old) old.remove();
    var cur = pending[slot] || { vol: 0.8, delay: 0 }, sel = cur.id || null;
    var ov = document.createElement('div'); ov.id = 'mv-snd-pick';
    ov.style.cssText = 'position:fixed;inset:0;z-index:100000;background:rgba(0,0,0,.75);display:flex;align-items:flex-end;justify-content:center';
    var delays = [0, 0.5, 1, 2, 3, 5].map(function (d) { return '<option value="' + d + '"' + (d === cur.delay ? ' selected' : '') + '>' + (d ? d + ' s' : 'Right away') + '</option>'; }).join('');
    ov.innerHTML = '<div style="background:#0f1418;color:#fff;width:100%;max-width:460px;max-height:82vh;overflow:auto;border-radius:16px 16px 0 0;padding:14px;font-family:inherit;box-sizing:border-box">' +
      '<div style="display:flex;justify-content:space-between;align-items:center"><b style="font-size:15px">🔊 Add a sound</b><button type="button" data-x style="background:none;border:0;color:#fff;font-size:20px;cursor:pointer">✕</button></div>' +
      '<div style="font-size:12px;opacity:.7;margin:4px 0 10px">Plays with your photo or video inside Mindvora. Downloaded files stay unchanged.</div>' +
      LIST.map(function (s) {
        return '<div data-row="' + s.id + '" style="display:flex;align-items:center;gap:8px;padding:8px;border-radius:10px;margin-bottom:4px;cursor:pointer;border:1px solid ' + (s.id === sel ? '#22c55e' : '#1f2a30') + '">' +
          '<button type="button" data-play="' + s.id + '" aria-label="Preview" style="width:34px;height:34px;border-radius:50%;border:0;background:#1f2a30;color:#fff;cursor:pointer">▶</button>' +
          '<span style="flex:1;font-size:14px">' + hx(s.label) + '</span><span data-tick style="color:#22c55e;font-weight:700">' + (s.id === sel ? '✓' : '') + '</span></div>';
      }).join('') +
      '<label style="display:flex;align-items:center;gap:10px;margin-top:10px;font-size:13px">Volume <input id="mv-snd-vol" type="range" min="0" max="100" value="' + Math.round(cur.vol * 100) + '" style="flex:1"></label>' +
      '<label style="display:flex;align-items:center;gap:10px;margin-top:8px;font-size:13px">Start <select id="mv-snd-delay" style="flex:1;padding:6px;border-radius:8px;background:#fff;color:#000">' + delays + '</select></label>' +
      '<div style="display:flex;gap:8px;margin-top:12px"><button type="button" data-rm style="flex:1;padding:11px;border-radius:10px;border:1px solid #374151;background:transparent;color:#fca5a5;cursor:pointer">Remove sound</button>' +
      '<button type="button" data-done style="flex:1;padding:11px;border-radius:10px;border:0;background:#16a34a;color:#fff;font-weight:700;cursor:pointer">Done</button></div></div>';
    document.body.appendChild(ov);
    function close() { stopPrev(); ov.remove(); }
    function mark() {
      ov.querySelectorAll('[data-row]').forEach(function (r) {
        var on = r.getAttribute('data-row') === sel;
        r.style.borderColor = on ? '#22c55e' : '#1f2a30'; r.querySelector('[data-tick]').textContent = on ? '✓' : '';
      });
    }
    ov.addEventListener('click', function (e) {
      var t = e.target;
      if (t === ov || t.closest('[data-x]')) return close();
      var pl = t.closest('[data-play]');
      if (pl) {
        e.stopPropagation(); var s = byId(pl.getAttribute('data-play')); stopPrev();
        prev = new Audio(s.url); prev.volume = +$('mv-snd-vol').value / 100;
        prev.play().catch(function () { toast('Could not play that sound. Check your connection.'); });
        sel = s.id; mark(); return;
      }
      var row = t.closest('[data-row]'); if (row) { sel = row.getAttribute('data-row'); mark(); return; }
      if (t.closest('[data-rm]')) { pending[slot] = null; close(); done(); return; }
      if (t.closest('[data-done]')) {
        pending[slot] = sel ? clean({ id: sel, vol: +$('mv-snd-vol').value / 100, delay: +$('mv-snd-delay').value }) : null;
        close(); done(); if (pending[slot]) toast('🔊 ' + pending[slot].label + ' added');
      }
    });
    $('mv-snd-vol').addEventListener('input', function () { if (prev) prev.volume = +this.value / 100; });
  }

  // ── post composer (#media-prev appears once a photo/video is uploaded) ──
  function postBtn() {
    var mp = $('media-prev'); if (!mp) return;
    var b = $('mv-snd-post');
    if (!b) {
      b = document.createElement('button'); b.type = 'button'; b.id = 'mv-snd-post';
      b.style.cssText = 'display:block;margin:6px 0 0;padding:7px 12px;border-radius:999px;border:1px solid #22c55e;background:rgba(34,197,94,.12);color:#22c55e;font-size:13px;font-weight:600;cursor:pointer';
      b.addEventListener('click', function (e) { e.preventDefault(); e.stopPropagation(); picker('post', postBtn); });
      mp.appendChild(b);
    }
    b.textContent = pending.post ? '🔊 ' + pending.post.label + ' · change' : '🔊 Add sound';
  }
  document.addEventListener('click', function (e) { if (e.target && e.target.closest && e.target.closest('#media-rm')) { pending.post = null; postBtn(); } }, true);

  // ── story composer (story-music.js builds #mv-story-comp on first use) ──
  function storyBtn() {
    var mus = $('mv-sc-mus'); if (!mus) return;
    var b = $('mv-sc-snd');
    if (!b) {
      b = document.createElement('button'); b.type = 'button'; b.id = 'mv-sc-snd';
      b.style.cssText = 'flex:1;padding:10px;border-radius:10px;border:0;background:rgba(255,255,255,.08);color:inherit;cursor:pointer';
      b.addEventListener('click', function (e) { e.preventDefault(); e.stopPropagation(); picker('story', storyBtn); });
      mus.parentNode.insertBefore(b, mus.nextSibling);
      var info = document.createElement('div'); info.id = 'mv-sc-sndinfo'; info.style.cssText = 'font-size:13px;margin-top:6px;opacity:.85';
      var m = $('mv-sc-music'); if (m) m.parentNode.insertBefore(info, m.nextSibling);
    }
    b.textContent = '🔊 Sound';
    var i = $('mv-sc-sndinfo'); if (i) i.textContent = pending.story ? '🔊 ' + pending.story.label + ' (plays with your photo)' : '';
  }

  // ── save: add sound:{id,vol,delay} to the post/story the app is creating ──
  function wrapAdd() {
    var CR = window.firebase && firebase.firestore && firebase.firestore.CollectionReference;
    if (!CR || !CR.prototype.add) return false;
    if (CR.prototype.add.__mvSnd) return true;
    var orig = CR.prototype.add;
    var w = function (data) {
      var slot = null;
      try {
        if (this.id === 'sparks' && pending.post && data && data.mediaUrl && (data.mediaType === 'image' || data.mediaType === 'video')) slot = 'post';
        else if (this.id === 'stories' && pending.story && data && data.media && data.media.url) slot = 'story';
        else if (this.id === 'stories' && pending.story && data && !data.media) toast('Sounds play with photo stories — add a photo to include it.');
        if (slot) data = Object.assign({}, data, { sound: stored(pending[slot]) });
      } catch (e) { slot = null; }
      var p = orig.call(this, data);
      if (slot && p && p.then) p.then(function () { pending[slot] = null; if (slot === 'post') { var b = $('mv-snd-post'); if (b) b.textContent = '🔊 Add sound'; } else storyBtn(); }, function () {});
      return p;
    };
    w.__mvSnd = true; CR.prototype.add = w; return true;
  }

  // ── viewing posts: mark media that carries a sound ──
  function wrapBuild() {
    var base = window.buildSparkHTML;
    if (typeof base !== 'function') return false;
    if (base.__mvSnd) return true;
    var w = function (s) {
      var html = base.apply(this, arguments);
      try {
        var c = s && s.mediaUrl && clean(s.sound); if (!c) return html;
        var attr = ' data-mvsnd="' + c.id + '|' + c.vol + '|' + c.delay + '"';
        var tog = '<button type="button" class="mv-snd-tog" aria-label="Sound on/off" style="position:absolute;top:8px;left:8px;z-index:4;background:rgba(0,0,0,.55);color:#fff;border:0;border-radius:999px;padding:5px 10px;font-size:12px;cursor:pointer">' + (muted() ? '🔇 ' : '🔊 ') + hx(c.label) + '</button>';
        if (html.indexOf('<div class="sk-media-img-wrap">') > -1) html = html.replace('<div class="sk-media-img-wrap">', '<div class="sk-media-img-wrap mv-snd-host"' + attr + ' style="position:relative">' + tog);
        else html = html.replace(/<div class="sk-media-wrap" /, '<div class="sk-media-wrap mv-snd-host"' + attr + ' style="position:relative" ').replace(/(<div class="sk-media-wrap mv-snd-host"[^>]*>)/, '$1' + tog);
      } catch (e) {}
      return html;
    };
    w.__mvSnd = true; window.buildSparkHTML = w; return true;
  }

  // ── playback ──
  var KEY = 'mv_media_snd_muted', active = null;
  function muted() { try { return localStorage.getItem(KEY) === '1'; } catch (e) { return false; } }
  function setMuted(m) { try { localStorage.setItem(KEY, m ? '1' : '0'); } catch (e) {} document.querySelectorAll('.mv-snd-tog').forEach(function (b) { b.textContent = (m ? '🔇 ' : '🔊 ') + b.textContent.replace(/^\S+\s/, ''); }); }
  function info(host) { var p = (host.getAttribute('data-mvsnd') || '').split('|'); return clean({ id: p[0], vol: p[1], delay: p[2] }); }
  function audio(host) {
    if (!host.__mvA) { var c = info(host); if (!c) return null; host.__mvA = new Audio(c.url); host.__mvA.volume = c.vol; host.__mvC = c; }
    return host.__mvA;
  }
  function stop(host) { if (!host) return; clearTimeout(host.__mvT); if (host.__mvA) { try { host.__mvA.pause(); } catch (e) {} } if (active === host) active = null; }
  function play(host, fromStart) {
    if (muted()) return; var a = audio(host); if (!a) return;
    if (active && active !== host) stop(active);
    active = host; clearTimeout(host.__mvT);
    var start = function () { if (fromStart) { try { a.currentTime = 0; } catch (e) {} } a.play().catch(function () {}); };
    var d = host.__mvC.delay * 1000; if (d && fromStart) host.__mvT = setTimeout(start, d); else start();
  }
  function video(host) { return host.querySelector('video.sk-media-main'); }
  var io = window.IntersectionObserver ? new IntersectionObserver(function (es) {
    es.forEach(function (en) {
      var host = en.target; if (video(host)) { if (!en.isIntersecting) stop(host); return; } // videos follow the video's own play/pause
      if (en.intersectionRatio >= 0.6) { if (!host.__mvPlayed) { host.__mvPlayed = true; play(host, true); } }
      else if (!en.isIntersecting) { stop(host); host.__mvPlayed = false; }
    });
  }, { threshold: [0, 0.6] }) : null;
  function bind(host) {
    if (host.__mvBound) return; host.__mvBound = true;
    if (io) io.observe(host);
    var v = video(host);
    if (v) {
      v.addEventListener('play', function () {
        var c = info(host); if (!c) return; var a = audio(host); if (!a || muted()) return;
        if (active && active !== host) stop(active); active = host; clearTimeout(host.__mvT);
        var off = v.currentTime - c.delay;
        if (off < 0) host.__mvT = setTimeout(function () { if (!v.paused) { try { a.currentTime = 0; } catch (e) {} a.play().catch(function () {}); } }, -off * 1000);
        else if (off < (a.duration || 1e9)) { try { a.currentTime = off; } catch (e) {} a.play().catch(function () {}); }
      });
      v.addEventListener('pause', function () { stop(host); });
      v.addEventListener('ended', function () { stop(host); });
      v.addEventListener('seeked', function () { if (!v.paused) { stop(host); v.dispatchEvent(new Event('play')); } });
    }
  }
  document.addEventListener('click', function (e) {
    var b = e.target && e.target.closest && e.target.closest('.mv-snd-tog'); if (!b) return;
    e.stopPropagation(); e.preventDefault();
    var host = b.closest('.mv-snd-host'), m = !muted(); setMuted(m);
    if (m) { if (active) stop(active); }
    else if (host) { var v = video(host); if (v) { if (!v.paused) v.dispatchEvent(new Event('play')); } else play(host, true); }
  }, true);

  // ── stories: called by story-music.js for each story shown ──
  var svA = null, svT = null;
  function stopStory() { clearTimeout(svT); if (svA) { try { svA.pause(); } catch (e) {} svA = null; } }
  function story(s, isMuted) {
    stopStory();
    var c = s && s.media && s.media.url && clean(s.sound); if (!c) return false;
    svA = new Audio(c.url); svA.volume = c.vol; svA.muted = !!isMuted;
    var a = svA; svT = setTimeout(function () { if (a === svA) a.play().catch(function () {}); }, c.delay * 1000);
    return true;
  }
  function muteStory(m) { if (svA) svA.muted = !!m; }

  // ── wiring ──
  var mpWatched = false;
  function scan() {
    try {
      var mp = $('media-prev');
      if (mp && !mpWatched) { mpWatched = true; new MutationObserver(function () { if (mp.style.display !== 'none') postBtn(); }).observe(mp, { attributes: true, attributeFilter: ['style'] }); }
      if (mp && mp.style.display === 'block' && !$('mv-snd-post')) postBtn();
      if ($('mv-sc-mus') && !$('mv-sc-snd')) storyBtn();
      document.querySelectorAll('.mv-snd-host').forEach(bind);
    } catch (e) {}
  }
  new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });
  scan();
  var tries = 0, t = setInterval(function () { var a = wrapAdd(), b = wrapBuild(); if ((a && b) || ++tries > 60) clearInterval(t); }, 500);
  wrapAdd(); wrapBuild();

  window.MVMediaSounds = { list: LIST, story: story, stopStory: stopStory, muteStory: muteStory, pending: pending, clean: clean };
})();
