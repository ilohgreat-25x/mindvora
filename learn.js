(function () {
  'use strict';
  function esc(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]; }); }
  function source(icon, title, text, url, tag) { return '<a class="mv-learn-source" href="' + esc(url) + '" target="_blank" rel="noopener noreferrer"><span>' + icon + '</span><strong>' + esc(title) + '</strong><small>' + esc(tag) + '</small><p>' + esc(text) + ' ↗</p></a>'; }
  function open() {
    var old = document.getElementById('mv-learn'); if (old) old.remove();
    var el = document.createElement('section'); el.id = 'mv-learn'; el.className = 'mv-learn-shell';
    el.innerHTML = '<header class="mv-learn-header"><button type="button" data-close aria-label="Close Learn">←</button><div><span>MINDVORA / LEARN</span><h1>Real courses for real progress</h1></div><b>Study · Practice · Apply</b></header>' +
      '<main class="mv-learn-main"><p class="mv-learn-intro">Learn connects you with structured courses, university material, professional certificates, and project-based practice. Choose a path, study on the provider’s official platform, then bring your notes and next actions back into Mindvora.</p>' +
      '<section class="mv-learn-feature"><div><span class="mv-learn-kicker">COURSE DISCOVERY</span><h2>Choose a serious learning path</h2><p>These are direct links to established course platforms. Pricing, certificates, enrollment, and availability are controlled by each provider.</p></div><div class="mv-learn-course-badge">🎓<strong>Verified course sources</strong><small>Official provider pages</small></div></section>' +
      '<section class="mv-learn-section"><div class="mv-learn-section-head"><span class="mv-learn-kicker">COURSE PROVIDERS</span><h2>Find your next course</h2></div><div class="mv-learn-sources">' +
      source('🎓', 'Khan Academy', 'Free lessons and practice in maths, science, computing, economics, and more.', 'https://www.khanacademy.org/', 'Free lessons and practice') +
      source('💻', 'freeCodeCamp', 'Project-based web development, data, and machine-learning curriculum with certifications.', 'https://www.freecodecamp.org/learn/', 'Hands-on coding') +
      source('🏛️', 'MIT OpenCourseWare', 'Open university lecture notes, assignments, exams, and course materials from MIT.', 'https://ocw.mit.edu/search/', 'University material') +
      source('🌐', 'edX', 'Courses and programs from universities and institutions, including professional certificates.', 'https://www.edx.org/learn', 'University and professional') +
      source('📚', 'Coursera', 'Guided courses, certificates, and degrees from universities and companies.', 'https://www.coursera.org/courses', 'Guided courses') +
      source('🧭', 'OpenLearn', 'Free courses and learning activities from The Open University.', 'https://www.open.edu/openlearn/', 'Free university learning') +
      source('🛠️', 'Google Skillshop', 'Official training for Google tools, analytics, advertising, and business products.', 'https://skillshop.withgoogle.com/', 'Professional skills') +
      source('⚡', 'Microsoft Learn', 'Interactive modules and learning paths for Azure, data, security, and development.', 'https://learn.microsoft.com/training/', 'Technical learning') +
      '</div></section>' +
      '<section class="mv-learn-section"><div class="mv-learn-section-head"><span class="mv-learn-kicker">PRACTICE IN EVOLVE</span><h2>Turn study into work</h2></div><p class="mv-learn-practice">After opening a course, use <strong>Orbit</strong> to capture notes, deadlines, and practice tasks, or ask <strong>Nexora</strong> to build a reviewable study plan. Learn does not simulate lessons or pretend that a progress bar is a course.</p><div class="mv-learn-actions"><button type="button" data-open-evolve="orbit">Open Orbit workspace</button><button type="button" data-open-evolve="nexora">Ask Nexora to build a study plan</button></div></section></main>';
    document.body.appendChild(el); el.classList.add('open'); document.body.style.overflow = 'hidden';
    el.querySelector('[data-close]').addEventListener('click', function () { close(el); });
    el.querySelectorAll('[data-open-evolve]').forEach(function (b) { b.addEventListener('click', function () { close(el); if (typeof window.openMindvoraEvolve === 'function') { window.openMindvoraEvolve(); setTimeout(function () { var target = document.querySelector('#mv-evolve [data-view="' + b.getAttribute('data-open-evolve') + '"]'); if (target) target.click(); }, 100); } }); });
  }
  function close(el) { el.classList.remove('open'); document.body.style.overflow = ''; if (window.__mvLearnOpenedFromDrawer && typeof window.toggleDrawer === 'function' && document.getElementById('app-drawer') && !document.getElementById('app-drawer').classList.contains('open')) { window.__mvLearnOpenedFromDrawer = false; window.toggleDrawer(); } }
  window.openMindvoraLearn = open;
  window.openMindvoraLearnFromDrawer = function () { window.__mvLearnOpenedFromDrawer = true; open(); };
})();
