(function () {
  'use strict';
  var KEY = 'mindvora.learn.progress.v1';
  var tracks = [
    { id: 'academic', icon: '🎓', name: 'Academic foundations', text: 'Structured lessons for school, university, and formal study.' },
    { id: 'technology', icon: '💻', name: 'Technology & coding', text: 'Hands-on practice for developers and digital builders.' },
    { id: 'business', icon: '▦', name: 'Business & office', text: 'Practical operations, records, communication, and entrepreneurship.' },
    { id: 'teaching', icon: '◇', name: 'Teaching & research', text: 'Lesson planning, research habits, and classroom practice.' }
  ];
  var progress = {}; try { progress = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch (e) {}
  function esc(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]; }); }
  function save() { try { localStorage.setItem(KEY, JSON.stringify(progress)); } catch (e) {} }
  function open() {
    var old = document.getElementById('mv-learn'); if (old) old.remove();
    var el = document.createElement('section'); el.id = 'mv-learn'; el.className = 'mv-learn-shell';
    el.innerHTML = '<header class="mv-learn-header"><button type="button" data-close aria-label="Close Learn">←</button><div><span>MIN­DVORA / LEARN</span><h1>Learn anything with a path that fits you</h1></div><b>Study · Practice · Progress</b></header><main class="mv-learn-main"><p class="mv-learn-intro">Choose a track, take a focused lesson, and mark a hands-on practice task complete. Paid courses and formal providers can be connected later; the workspace below is ready now.</p><div class="mv-learn-grid">' + tracks.map(function (t) { var done = Number(progress[t.id] || 0); return '<article class="mv-learn-card"><div class="mv-learn-icon">' + t.icon + '</div><h2>' + esc(t.name) + '</h2><p>' + esc(t.text) + '</p><div class="mv-learn-progress"><i style="width:' + Math.min(100, done * 25) + '%"></i></div><small>' + done + '/4 lessons complete</small><button type="button" data-track="' + t.id + '">' + (done >= 4 ? 'Review track' : 'Open next lesson') + ' →</button></article>'; }).join('') + '</div></main>';
    document.body.appendChild(el); el.classList.add('open'); document.body.style.overflow = 'hidden';
    el.querySelector('[data-close]').addEventListener('click', function () { el.classList.remove('open'); document.body.style.overflow = ''; });
    el.querySelectorAll('[data-track]').forEach(function (b) { b.addEventListener('click', function () { var id = b.getAttribute('data-track'), t = tracks.filter(function (x) { return x.id === id; })[0], current = Number(progress[id] || 0); var lesson = ['Learn the core ideas', 'Study a worked example', 'Complete a hands-on exercise', 'Reflect and apply it to your work'][Math.min(current, 3)]; if (confirm(t.name + '\n\nNext: ' + lesson + '\n\nMark this lesson complete?')) { progress[id] = Math.min(4, current + 1); save(); open(); } }); });
  }
  window.openMindvoraLearn = open;
  window.openMindvoraLearnFromDrawer = function () { window.__mvLearnOpenedFromDrawer = true; open(); };
})();
