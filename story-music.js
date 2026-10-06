/**
 * MINDVORA — STORIES (text + photo + music)  ·  story-music.js
 *
 * Root causes fixed here:
 *  1. Music was lost on normal stories: the "＋" button was bound to the ORIGINAL postStory before this file
 *     loaded (this file is injected later by calls.js), so the music-aware version never ran. loadStories now
 *     calls window.postStory()/window.viewStory() at click time (script.js).
 *  2. Plain stories had no `uid` field, but firestore.rules require `uid == auth.uid` → creates were rejected.
 *  3. Viewers could not mark a story seen (update rule only allowed the owner) → console errors. Rules fixed.
 *  4. No photo support at all (postStory was a prompt() for text). Now a composer: text and/or photo + music.
 *  5. Music always played a fixed 15 s regardless of the story. Now every story has durationMs derived from its
 *     content; the track is trimmed to it (looped if shorter), fades out, and stops on close/next/exit.
 * Stories still expire after 48 hours (expiresAt); the backend sweeps expired docs + photos (lib/story-cleanup.js).
 */
(function () {
  'use strict';
  function T(name, file) { return { name: name, url: '/music/' + file + '.mp3' }; }
  // Only tracks served from this site. The 3 third-party Pixabay hotlinks were removed: hotlinked CDN files
  // break without notice (three already had) and could not be checked for licence/content.
  var TRACKS = [
    T('Chill Vibes', 'chill-vibes'), T('Dreamy', 'dreamy'), T('Happy Tune', 'happy-tune'),
    T('Sunrise Drive', 'sunrise-drive'), T('Night City', 'night-city'), T('Midnight Groove', 'midnight-groove'),
    T('Ocean Breeze', 'ocean-breeze'), T('Golden Hour', 'golden-hour'), T('Neon Pulse', 'neon-pulse'),
    T('Cloud Nine', 'cloud-nine'), T('Street Beat', 'street-beat'), T('Summer Glow', 'summer-glow'),
    T('Deep Focus', 'deep-focus'), T('Starlight', 'starlight'), T('Rush Hour', 'rush-hour'),
    T('Electric Dreams', 'electric-dreams'), T('Lagos Nights', 'lagos-nights'), T('Feel Good', 'feel-good'),
    T('Moonwalk', 'moonwalk'), T('Victory Lap', 'victory-lap'), T('Calm Waves', 'calm-waves'),
    T('Hype Mode', 'hype-mode'), T('After Party', 'after-party')
  ];
  var PREVIEW_MS = 15000, STORY_TTL = 48 * 60 * 60 * 1000, MAX_IMG = 10 * 1024 * 1024;
  try { STORY_TRACKS.length = 0; TRACKS.forEach(function (t) { STORY_TRACKS.push(t); }); }
  catch (e) { window.STORY_TRACKS = TRACKS; }

  function toast(m) { if (typeof showToast === 'function') showToast(m); }
  function $(id) { return document.getElementById(id); }

  /** How long a story is shown — and therefore how long its music plays. */
  function storyDuration(text, hasPhoto) {
    var len = String(text || '').trim().length;
    var base = hasPhoto ? 7000 : 5000;
    return Math.max(5000, Math.min(15000, base + len * 60)); // ~ reading time, 5–15 s
  }
  window.mvStoryDuration = storyDuration;

  // ── music preview in the picker ─────────────────────────────────────
  var preview = null, previewT = null;
  function stopPreview() {
    clearTimeout(previewT);
    if (preview) { try { preview.pause(); } catch (e) {} preview.removeAttribute('src'); try { preview.load(); } catch (e) {} preview = null; }
    document.querySelectorAll('.music-item').forEach(function (el) { el.style.background = ''; });
  }
  window.previewTrack = previewTrack = function (i) {
    stopPreview();
    var t = STORY_TRACKS[i]; if (!t) return;
    preview = new Audio(t.url); preview.preload = 'auto'; preview.volume = 0.6;
    preview.play().then(function () {
      toast('▶ Playing: ' + t.name);
      var el = $('music-item-' + i); if (el) el.style.background = 'rgba(34,197,94,.1)';
    }).catch(function () { toast('⚠️ Could not play "' + t.name + '". Check your connection.'); });
    previewT = setTimeout(stopPreview, PREVIEW_MS);
  };
  var origSelect = window.selectTrack || selectTrack;
  window.selectTrack = selectTrack = function (i) {
    stopPreview(); var r = origSelect(i);
    // Picking a song from the post box opens the story composer that carries it.
    setTimeout(function () { if (pendingStoryMusic) openComposer(); }, 300);
    return r;
  };
  var origCloseMP = window.closeMusicPicker || closeMusicPicker;
  window.closeMusicPicker = closeMusicPicker = function () { stopPreview(); return origCloseMP(); };

  // ── photo upload (same Cloudinary account/preset the rest of the app uses) ──
  function uploadPhoto(file) {
    if (!file || !/^image\/(jpeg|png|webp|gif|heic|heif)$/i.test(file.type)) return Promise.reject(new Error('Choose a JPG, PNG, WEBP or GIF photo.'));
    if (file.size > MAX_IMG) return Promise.reject(new Error('Photo too large (max 10 MB).'));
    var fd = new FormData();
    fd.append('file', file); fd.append('upload_preset', 'ml_default'); fd.append('folder', 'stories');
    fd.append('tags', 'mindvora_story');
    var cloud = (typeof CLOUD_NAME !== 'undefined' && CLOUD_NAME) || 'dk4svvssf';
    return fetch('https://api.cloudinary.com/v1_1/' + cloud + '/image/upload', { method: 'POST', body: fd })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d || d.error || !d.secure_url) throw new Error((d && d.error && d.error.message) || 'Upload failed');
        return { url: d.secure_url, type: 'image', publicId: d.public_id || '', width: d.width || 0, height: d.height || 0 };
      });
  }

  // ── composer ────────────────────────────────────────────────────────
  var compFile = null;
  function composer() {
    var m = $('mv-story-comp'); if (m) return m;
    m = document.createElement('div'); m.id = 'mv-story-comp';
    m.style.cssText = 'position:fixed;inset:0;z-index:99990;background:rgba(0,0,0,.75);display:none;align-items:center;justify-content:center;padding:16px';
    m.innerHTML = '<div style="background:var(--card,#111);color:var(--text,#fff);border-radius:16px;width:100%;max-width:420px;padding:16px;font-family:inherit">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><b>New story · 48h</b><button type="button" id="mv-sc-x" style="background:none;border:0;color:inherit;font-size:20px">✕</button></div>' +
      '<textarea id="mv-sc-text" maxlength="500" placeholder="Write something (optional with a photo)…" style="width:100%;min-height:80px;border-radius:10px;padding:10px;font-size:16px;background:rgba(255,255,255,.06);color:inherit;border:1px solid rgba(255,255,255,.15)"></textarea>' +
      '<img id="mv-sc-prev" alt="" style="display:none;width:100%;max-height:260px;object-fit:contain;border-radius:10px;margin-top:8px;background:#000">' +
      '<div id="mv-sc-music" style="font-size:13px;margin-top:8px;opacity:.85"></div>' +
      '<div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">' +
      '<label style="flex:1;text-align:center;padding:10px;border-radius:10px;background:rgba(255,255,255,.08);cursor:pointer">📷 Photo<input id="mv-sc-file" type="file" accept="image/*" style="display:none"></label>' +
      '<button type="button" id="mv-sc-mus" style="flex:1;padding:10px;border-radius:10px;border:0;background:rgba(255,255,255,.08);color:inherit">🎵 Music</button>' +
      '<button type="button" id="mv-sc-post" style="flex:1 1 100%;padding:12px;border-radius:10px;border:0;background:var(--green,#16a34a);color:#fff;font-weight:700">Post story</button></div></div>';
    document.body.appendChild(m);
    $('mv-sc-x').onclick = closeComposer;
    $('mv-sc-mus').onclick = function () { closeComposer(true); if (typeof openMusicPicker === 'function') openMusicPicker(); };
    $('mv-sc-file').onchange = function (e) {
      var f = e.target.files && e.target.files[0]; if (!f) return;
      if (!/^image\//.test(f.type)) { toast('Choose a photo.'); return; }
      if (f.size > MAX_IMG) { toast('Photo too large (max 10 MB).'); return; }
      compFile = f; var img = $('mv-sc-prev'); img.src = URL.createObjectURL(f); img.style.display = 'block';
    };
    $('mv-sc-post').onclick = submit;
    return m;
  }
  function openComposer() {
    if (!state.user) { toast('Log in to post a story.'); return; }
    var m = composer(); m.style.display = 'flex';
    var mu = $('mv-sc-music');
    mu.textContent = pendingStoryMusic ? ('🎵 ' + pendingStoryMusic.name + ' (tap 🎵 to change)') : 'No music';
  }
  function closeComposer(keep) {
    var m = $('mv-story-comp'); if (m) m.style.display = 'none';
    if (keep) return;
    compFile = null;
    var img = $('mv-sc-prev'); if (img) { if (img.src) try { URL.revokeObjectURL(img.src); } catch (e) {} img.removeAttribute('src'); img.style.display = 'none'; }
    var t = $('mv-sc-text'); if (t) t.value = '';
    var f = $('mv-sc-file'); if (f) f.value = '';
  }
  var posting = false;
  function submit() {
    if (posting) return;
    var text = ($('mv-sc-text').value || '').trim().slice(0, 500);
    if (!text && !compFile) { toast('Add text or a photo.'); return; }
    var chosen = pendingStoryMusic, btn = $('mv-sc-post');
    posting = true; btn.disabled = true; btn.textContent = compFile ? 'Uploading photo…' : 'Posting…';
    (compFile ? uploadPhoto(compFile) : Promise.resolve(null)).then(function (media) {
      var doc = {
        text: text, uid: state.user.uid, authorId: state.user.uid,
        authorName: state.profile.name || '', authorHandle: state.profile.handle || '', authorColor: state.profile.color || '',
        seenBy: [], durationMs: storyDuration(text, !!media),
        createdAt: firebase.firestore.FieldValue.serverTimestamp(), expiresAt: new Date(Date.now() + STORY_TTL)
      };
      if (media) doc.media = media;
      if (chosen && chosen.url) doc.music = { name: String(chosen.name || '').slice(0, 60), url: chosen.url };
      return db.collection('stories').add(doc);
    }).then(function () {
      pendingStoryMusic = null;
      var b = $('btn-story-music'); if (b) b.style.color = '';
      toast('Story posted' + (chosen ? ' with 🎵 ' + chosen.name : '') + '! 48h ⏱');
      closeComposer(); if (typeof loadStories === 'function') loadStories();
    }).catch(function (e) {
      console.warn('[story] post failed', e); toast('⚠️ Story not posted: ' + ((e && e.message) || 'try again'));
    }).then(function () { posting = false; btn.disabled = false; btn.textContent = 'Post story'; });
  }
  window.postStory = postStory = openComposer;

  // ── viewer: photo, music trimmed to the story, tap left/right, mute ──
  var svAudio = null, svT = null, fadeT = null, svList = [], svIdx = -1, svMuted = false;
  function stopSv() {
    clearTimeout(svT); clearInterval(fadeT); svT = fadeT = null;
    if (window.MVMediaSounds) MVMediaSounds.stopStory();
    if (svAudio) { try { svAudio.pause(); } catch (e) {} svAudio.removeAttribute('src'); try { svAudio.load(); } catch (e) {} svAudio = null; }
  }
  function closeViewer() { stopSv(); var ov = $('sv-overlay'); if (ov) ov.classList.remove('open'); svList = []; svIdx = -1; }
  function ensureExtras() {
    var ov = $('sv-overlay'); if (!ov || $('sv-img')) return;
    var img = document.createElement('img'); img.id = 'sv-img'; img.alt = '';
    img.style.cssText = 'display:none;max-width:100%;max-height:60vh;object-fit:contain;border-radius:12px;margin:10px auto';
    var txt = $('sv-text'); txt.parentNode.insertBefore(img, txt);
    var mute = document.createElement('button'); mute.id = 'sv-mute'; mute.type = 'button';
    mute.style.cssText = 'position:absolute;bottom:24px;right:20px;z-index:5;background:rgba(0,0,0,.5);color:#fff;border:0;border-radius:50%;width:40px;height:40px;font-size:18px;display:none';
    mute.onclick = function (e) { e.stopPropagation(); svMuted = !svMuted; if (svAudio) svAudio.muted = svMuted; if (window.MVMediaSounds) MVMediaSounds.muteStory(svMuted); mute.textContent = svMuted ? '🔇' : '🔊'; };
    ov.appendChild(mute);
    ov.addEventListener('click', function (e) {
      if (e.target.closest && e.target.closest('#sv-x, #sv-mute')) return;
      if (!svList.length) return;
      if (e.clientX < window.innerWidth / 3) show(svIdx - 1); else show(svIdx + 1);
    });
    var x = $('sv-x'); if (x) x.addEventListener('click', function (e) { e.stopPropagation(); closeViewer(); });
    document.addEventListener('visibilitychange', function () { if (document.hidden) closeViewer(); });
    window.addEventListener('popstate', closeViewer);
  }
  function playMusic(music, ms) {
    svAudio = new Audio(music.url); svAudio.volume = 0.7; svAudio.muted = svMuted; svAudio.loop = true; // loop if track shorter than story
    svAudio.play().catch(function () { var m = $('sv-mute'); if (m) { m.textContent = '🔇'; } }); // autoplay blocked → user taps 🔊
    var a = svAudio;
    setTimeout(function () { // fade out over the last 600 ms so the cut at the story's end is clean
      if (a !== svAudio) return; var v = a.volume; clearInterval(fadeT);
      fadeT = setInterval(function () { if (a !== svAudio) { clearInterval(fadeT); return; } v -= 0.07; a.volume = Math.max(0, v); if (v <= 0) clearInterval(fadeT); }, 60);
    }, Math.max(0, ms - 600));
  }
  function show(i) {
    stopSv();
    if (i < 0 || i >= svList.length) { closeViewer(); return; }
    svIdx = i; var id = svList[i].id, s = svList[i].s || {};
    var hasMusic = !!(s.music && s.music.url), hasImg = !!(s.media && s.media.url && s.media.type === 'image');
    var ms = Number(s.durationMs) > 0 ? Math.min(15000, Math.max(3000, Number(s.durationMs))) : storyDuration(s.text, hasImg);
    $('sv-av').textContent = (s.authorName || 'Z').charAt(0).toUpperCase();
    $('sv-av').style.background = s.authorColor || COLORS[0];
    $('sv-nm').textContent = s.authorName || 'Mindvora user';
    $('sv-tm').textContent = timeAgo(s.createdAt) + (hasMusic ? ' · 🎵 ' + (s.music.name || '') : '');
    $('sv-text').textContent = s.text || '';
    var img = $('sv-img'); if (img) { if (hasImg) { img.src = s.media.url; img.style.display = 'block'; } else { img.removeAttribute('src'); img.style.display = 'none'; } }
    var hasSnd = !!(window.MVMediaSounds && MVMediaSounds.story(s, svMuted)); // Sound Board sound on a photo story
    var mute = $('sv-mute'); if (mute) { mute.style.display = (hasMusic || hasSnd) ? 'block' : 'none'; mute.textContent = svMuted ? '🔇' : '🔊'; }
    $('sv-overlay').classList.add('open');
    var fill = $('sv-fill'); fill.style.transition = 'none'; fill.style.width = '0%';
    setTimeout(function () { fill.style.transition = 'width ' + (ms / 1000) + 's linear'; fill.style.width = '100%'; }, 50);
    if (hasMusic) playMusic(s.music, ms);
    svT = setTimeout(function () { show(svIdx + 1); }, ms + 100);
    if (state.user && (s.seenBy || []).indexOf(state.user.uid) < 0) {
      db.collection('stories').doc(id).update({ seenBy: firebase.firestore.FieldValue.arrayUnion(state.user.uid) }).catch(function () {});
    }
  }
  window.viewStory = viewStory = function (id, s, list) {
    ensureExtras();
    svList = Array.isArray(list) && list.length ? list : [{ id: id, s: s }];
    var i = 0; svList.forEach(function (x, k) { if (x.id === id) i = k; });
    show(i);
  };
})();
