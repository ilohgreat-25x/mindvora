(function () {
  'use strict';
  function esc(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]; }); }
  function source(icon, title, text, url) { return '<a class="mv-learn-source" href="' + esc(url) + '" target="_blank" rel="noopener noreferrer"><span>' + icon + '</span><strong>' + esc(title) + '</strong><small>' + esc(text) + ' ↗</small></a>'; }
  function liveButton(label, action) { return '<button type="button" class="mv-learn-live" data-live="' + action + '">' + label + '</button>'; }
  function open() {
    var old = document.getElementById('mv-learn'); if (old) old.remove();
    var el = document.createElement('section'); el.id = 'mv-learn'; el.className = 'mv-learn-shell';
    el.innerHTML = '<header class="mv-learn-header"><button type="button" data-close aria-label="Close Learn">←</button><div><span>MINDVORA / LEARN</span><h1>Learn from the world around you</h1></div><b>Watch · Read · Practice</b></header>' +
      '<main class="mv-learn-main"><p class="mv-learn-intro">Learn is now a real discovery layer. Watch live reporting, sports context, and anime storytelling inside Mindvora, or continue to trusted education providers for structured study and hands-on practice.</p>' +
      '<section class="mv-learn-feature"><div><span class="mv-learn-kicker">MINDVORA LIVE SOURCES</span><h2>Start learning through live media</h2><p>Use the same official-source players already powering Mindvora’s live areas. Availability varies by region and rights.</p></div><div class="mv-learn-live-row">' + liveButton('📰 Live news', 'news') + liveButton('🏟️ Live sports', 'sports') + liveButton('🎬 Anime movies', 'anime') + '</div></section>' +
      '<section class="mv-learn-section"><div class="mv-learn-section-head"><span class="mv-learn-kicker">REAL STUDY SOURCES</span><h2>Choose a trusted next step</h2></div><div class="mv-learn-sources">' +
      source('🎓', 'Khan Academy', 'Free lessons and practice across maths, science, computing, and more.', 'https://www.khanacademy.org/') +
      source('💻', 'freeCodeCamp', 'Hands-on coding curriculum with projects and certifications.', 'https://www.freecodecamp.org/learn/') +
      source('🏛️', 'MIT OpenCourseWare', 'University lecture materials, assignments, and open course content.', 'https://ocw.mit.edu/search/') +
      source('🌍', 'Coursera', 'Structured courses and professional certificates from universities and companies.', 'https://www.coursera.org/courses') +
      '</div></section>' +
      '<section class="mv-learn-section"><div class="mv-learn-section-head"><span class="mv-learn-kicker">PRACTICE IN EVOLVE</span><h2>Turn what you learn into work</h2></div><p class="mv-learn-practice">After studying, open <strong>Orbit</strong> to capture notes and tasks, or ask <strong>Nexora</strong> to build a reviewable practice blueprint. Learn does not pretend that a fake progress bar is a lesson; it takes you to actual material and gives you a place to apply it.</p><div class="mv-learn-actions"><button type="button" data-open-evolve="orbit">Open Orbit workspace</button><button type="button" data-open-evolve="nexora">Ask Nexora to build practice</button></div></section></main>';
    document.body.appendChild(el); el.classList.add('open'); document.body.style.overflow = 'hidden';
    el.querySelector('[data-close]').addEventListener('click', function () { close(el); });
    el.querySelectorAll('[data-live]').forEach(function (b) { b.addEventListener('click', function () { var fn = { news: 'openLiveNews', sports: 'openLiveSports', anime: 'openAnimeMovies' }[b.getAttribute('data-live')]; if (typeof window[fn] === 'function') window[fn](); else if (typeof window.showToast === 'function') window.showToast('This live source is still loading. Try again in a moment.'); }); });
    el.querySelectorAll('[data-open-evolve]').forEach(function (b) { b.addEventListener('click', function () { close(el); if (typeof window.openMindvoraEvolve === 'function') { window.openMindvoraEvolve(); setTimeout(function () { var target = document.querySelector('#mv-evolve [data-view="' + b.getAttribute('data-open-evolve') + '"]'); if (target) target.click(); }, 100); } }); });
  }
  function close(el) { el.classList.remove('open'); document.body.style.overflow = ''; if (window.__mvLearnOpenedFromDrawer && typeof window.toggleDrawer === 'function' && document.getElementById('app-drawer') && !document.getElementById('app-drawer').classList.contains('open')) { window.__mvLearnOpenedFromDrawer = false; window.toggleDrawer(); } }
  window.openMindvoraLearn = open;
  window.openMindvoraLearnFromDrawer = function () { window.__mvLearnOpenedFromDrawer = true; open(); };
})();
