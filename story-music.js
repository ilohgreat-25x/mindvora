/**
 * MINDVORA — STORY MUSIC  ·  story-music.js
 *  • Tracks are small 30-second clips served from this website (/music/…),
 *    streamed on demand — nothing is stored inside the APK or the offline cache.
 *  • The 3 dead tracks (Chill Vibes, Dreamy, Happy Tune — their old host
 *    returned 403 Forbidden) are replaced, and 20 new tracks are added.
 *  • Preview plays 15 seconds. The chosen track is saved WITH the story and
 *    plays for 15+ seconds when anyone opens it (before, the choice was never saved).
 */
(function () {
  'use strict';
  function T(name, file) { return { name: name, url: '/music/' + file + '.mp3' }; }
  var TRACKS = [
    T('Chill Vibes', 'chill-vibes'),
    { name: 'Upbeat Energy', url: 'https://cdn.pixabay.com/download/audio/2021/11/25/audio_91b32e02f9.mp3' },
    T('Dreamy', 'dreamy'),
    { name: 'Lo-Fi Beat', url: 'https://cdn.pixabay.com/download/audio/2022/05/27/audio_1808fbf07a.mp3' },
    { name: 'Ambient', url: 'https://cdn.pixabay.com/download/audio/2022/08/02/audio_884fe92c21.mp3' },
    T('Happy Tune', 'happy-tune'),
    T('Sunrise Drive', 'sunrise-drive'), T('Night City', 'night-city'), T('Midnight Groove', 'midnight-groove'),
    T('Ocean Breeze', 'ocean-breeze'), T('Golden Hour', 'golden-hour'), T('Neon Pulse', 'neon-pulse'),
    T('Cloud Nine', 'cloud-nine'), T('Street Beat', 'street-beat'), T('Summer Glow', 'summer-glow'),
    T('Deep Focus', 'deep-focus'), T('Starlight', 'starlight'), T('Rush Hour', 'rush-hour'),
    T('Electric Dreams', 'electric-dreams'), T('Lagos Nights', 'lagos-nights'), T('Feel Good', 'feel-good'),
    T('Moonwalk', 'moonwalk'), T('Victory Lap', 'victory-lap'), T('Calm Waves', 'calm-waves'),
    T('Hype Mode', 'hype-mode'), T('After Party', 'after-party')
  ];
  var PLAY_MS = 15000;
  // Fill the original array in place, so every existing reference sees the new list.
  try { STORY_TRACKS.length = 0; TRACKS.forEach(function (t) { STORY_TRACKS.push(t); }); }
  catch (e) { window.STORY_TRACKS = TRACKS; }

  var preview = null, previewT = null;
  function stopPreview() {
    clearTimeout(previewT);
    if (preview) { try { preview.pause(); } catch (e) {} preview.src = ''; preview = null; }
    document.querySelectorAll('.music-item').forEach(function (el) { el.style.background = ''; });
  }
  window.previewTrack = previewTrack = function (i) {
    stopPreview();
    var t = STORY_TRACKS[i]; if (!t) return;
    preview = new Audio(t.url); preview.preload = 'auto'; preview.volume = 0.6;
    preview.play().then(function () {
      showToast('▶ Playing: ' + t.name);
      var el = document.getElementById('music-item-' + i); if (el) el.style.background = 'rgba(34,197,94,.1)';
    }).catch(function () { showToast('⚠️ Could not play "' + t.name + '". Check your connection.'); });
    previewT = setTimeout(stopPreview, PLAY_MS);
  };
  var origSelect = window.selectTrack || selectTrack;
  window.selectTrack = selectTrack = function (i) { stopPreview(); return origSelect(i); };
  var origCloseMP = window.closeMusicPicker || closeMusicPicker;
  window.closeMusicPicker = closeMusicPicker = function () { stopPreview(); return origCloseMP(); };

  // Save the chosen track with the story.
  var origPost = window.postStory || postStory;
  window.postStory = postStory = function () {
    var chosen = pendingStoryMusic;
    if (!chosen) return origPost.apply(this, arguments);
    var text = prompt('Share a story (disappears in 48h):');
    if (!text || !text.trim() || !state.user) return;
    db.collection('stories').add({
      text: text.trim(), authorId: state.user.uid, authorName: state.profile.name, authorHandle: state.profile.handle,
      authorColor: state.profile.color, seenBy: [], music: { name: chosen.name, url: chosen.url },
      createdAt: firebase.firestore.FieldValue.serverTimestamp(), expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000)
    }).then(function () {
      pendingStoryMusic = null;
      var b = document.getElementById('btn-story-music'); if (b) b.style.color = '';
      showToast('Story posted with 🎵 ' + chosen.name + '! 48h ⏱'); loadStories();
    });
  };

  // Viewer: a story with music stays open 15s and plays the track; others keep the old 5s.
  var svAudio = null, svT = null;
  function stopSv() { clearTimeout(svT); if (svAudio) { try { svAudio.pause(); } catch (e) {} svAudio.src = ''; svAudio = null; } }
  window.viewStory = viewStory = function (id, s) {
    stopSv();
    var hasMusic = !!(s && s.music && s.music.url), ms = hasMusic ? PLAY_MS : 5000;
    document.getElementById('sv-av').textContent = (s.authorName || 'Z').charAt(0).toUpperCase();
    document.getElementById('sv-av').style.background = s.authorColor || COLORS[0];
    document.getElementById('sv-nm').textContent = s.authorName || 'Mindvora user';
    document.getElementById('sv-tm').textContent = timeAgo(s.createdAt) + (hasMusic ? ' · 🎵 ' + (s.music.name || '') : '');
    document.getElementById('sv-text').textContent = s.text || '';
    var ov = document.getElementById('sv-overlay'); ov.classList.add('open');
    var fill = document.getElementById('sv-fill'); fill.style.transition = 'none'; fill.style.width = '0%';
    setTimeout(function () { fill.style.transition = 'width ' + (ms / 1000) + 's linear'; fill.style.width = '100%'; }, 50);
    if (hasMusic) { svAudio = new Audio(s.music.url); svAudio.volume = 0.7; svAudio.play().catch(function () {}); }
    svT = setTimeout(function () { ov.classList.remove('open'); stopSv(); }, ms + 100);
    if (state.user) db.collection('stories').doc(id).update({ seenBy: firebase.firestore.FieldValue.arrayUnion(state.user.uid) });
  };
  var x = document.getElementById('sv-x'); if (x) x.addEventListener('click', stopSv);
})();
