/*
 * MINDVORA EVOLVE — unified intelligence dashboard
 * Self-contained feature surface: no existing Mindvora state or navigation is rewritten.
 */
(function () {
  'use strict';

  var divisions = [
    { id: 'sentinel', icon: '🛡️', name: 'Sentinel', label: 'Digital Protection', text: 'Review link safety, identity alerts, and connected-service risks.' },
    { id: 'autopilot', icon: '⚙️', name: 'Autopilot', label: 'Automated Operations', text: 'Design approved workflows and keep background activity visible.' },
    { id: 'pulse', icon: '◉', name: 'Pulse', label: 'Information Intelligence', text: 'Track topics, trends, opportunities, and relevant developments.' },
    { id: 'identity', icon: '◈', name: 'Identity', label: 'Digital Identity', text: 'Manage credentials, access, sharing, and impersonation signals.' },
    { id: 'lifeos', icon: '✦', name: 'LifeOS', label: 'Personal & Business Hub', text: 'Bring schedules, goals, projects, and routines into one view.' },
    { id: 'core', icon: '⬡', name: 'Evolve Core', label: 'Cloud & Infrastructure', text: 'Organize environments, deployments, resources, and recovery.' }
  ];

  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function getPanel() {
    var panel = document.getElementById('mv-evolve');
    if (panel) return panel;
    panel = document.createElement('section');
    panel.id = 'mv-evolve';
    panel.className = 'mv-evolve-shell';
    panel.setAttribute('aria-label', 'Mindvora Evolve');
    panel.innerHTML = '<header class="mv-evolve-header"><button type="button" data-evolve-close aria-label="Close Evolve">←</button><div><span class="mv-evolve-kicker">MINDVORA / EVOLVE</span><h1>One intelligence layer for your digital world</h1></div><span class="mv-evolve-status"><i></i> Core ready</span></header>' +
      '<div class="mv-evolve-layout"><nav class="mv-evolve-nav" aria-label="Evolve divisions"><button class="active" data-evolve-view="overview">◌ Overview</button>' + divisions.map(function (d) { return '<button data-evolve-view="' + esc(d.id) + '">' + d.icon + ' ' + esc(d.name) + '</button>'; }).join('') + '</nav><main class="mv-evolve-main" data-evolve-main></main></div>';
    document.body.appendChild(panel);
    panel.querySelector('[data-evolve-close]').addEventListener('click', function () { closePanel(panel); });
    panel.querySelectorAll('[data-evolve-view]').forEach(function (button) {
      button.addEventListener('click', function () { render(panel, button.getAttribute('data-evolve-view')); });
    });
    return panel;
  }

  function card(title, value, detail, tone) {
    return '<article class="mv-evolve-metric ' + (tone || '') + '"><span>' + esc(title) + '</span><strong>' + esc(value) + '</strong><small>' + esc(detail) + '</small></article>';
  }

  function overview() {
    return '<div class="mv-evolve-hero"><div><span class="mv-evolve-eyebrow">EVOLVE INTELLIGENCE CORE</span><h2>A calmer control room for everything that matters.</h2><p>Evolve brings protection, automation, information, identity, life management, and infrastructure together without scattering the Mindvora experience.</p></div><div class="mv-evolve-orbit" aria-hidden="true"><b>EVOLVE</b><span></span><span></span><span></span></div></div>' +
      '<div class="mv-evolve-metrics">' + card('Security posture', 'Protected', 'Sentinel is ready for a review', 'green') + card('Active operations', '0', 'No background actions running', '') + card('Information pulse', 'Quiet', 'No priority alerts yet', 'gold') + card('Resources', 'Not connected', 'Connect a workspace when ready', '') + '</div>' +
      '<section class="mv-evolve-section"><div class="mv-evolve-section-head"><div><span class="mv-evolve-eyebrow">YOUR EVOLVE LAYER</span><h3>Choose a division to begin</h3></div><span class="mv-evolve-chip">Permission-aware by design</span></div><div class="mv-evolve-grid">' + divisions.map(function (d) { return '<button class="mv-evolve-division" data-evolve-view="' + esc(d.id) + '"><span class="mv-evolve-division-icon">' + d.icon + '</span><span><strong>' + esc(d.name) + '</strong><small>' + esc(d.label) + '</small><em>' + esc(d.text) + '</em></span><b>→</b></button>'; }).join('') + '</div></section>' +
      '<p class="mv-evolve-note">Sensitive actions will require explicit approval. Connected services, automations, and infrastructure remain isolated until you authorize them.</p>';
  }

  function divisionView(id) {
    var division = divisions.filter(function (d) { return d.id === id; })[0] || divisions[0];
    var actions = {
      sentinel: ['Scan a link', 'Review security alerts', 'Connected services'],
      autopilot: ['Create a workflow', 'Scheduled operations', 'Activity history'],
      pulse: ['Add a topic', 'Intelligence reports', 'Opportunity watch'],
      identity: ['Identity records', 'Access management', 'Sharing controls'],
      lifeos: ['Today overview', 'Goals & projects', 'Routine planner'],
      core: ['Cloud workspaces', 'Deployments', 'Resource monitor']
    }[id] || [];
    return '<div class="mv-evolve-division-head"><span class="mv-evolve-division-icon large">' + division.icon + '</span><div><span class="mv-evolve-eyebrow">EVOLVE DIVISION</span><h2>' + esc(division.name) + '</h2><p>' + esc(division.text) + '</p></div></div><div class="mv-evolve-action-grid">' + actions.map(function (action) { return '<button class="mv-evolve-action" type="button" data-evolve-action="' + esc(action) + '"><strong>' + esc(action) + '</strong><span>Set up this workspace when you are ready →</span></button>'; }).join('') + '</div><div class="mv-evolve-empty"><span>✦</span><strong>This centre is ready for your next connection.</strong><p>Mindvora keeps the shell lightweight until an authorized service, workspace, or data source is connected.</p></div>';
  }

  function render(panel, view) {
    panel.querySelectorAll('[data-evolve-view]').forEach(function (button) { button.classList.toggle('active', button.getAttribute('data-evolve-view') === view); });
    var main = panel.querySelector('[data-evolve-main]');
    main.innerHTML = view === 'overview' ? overview() : divisionView(view);
    main.querySelectorAll('[data-evolve-view]').forEach(function (button) { button.addEventListener('click', function () { render(panel, button.getAttribute('data-evolve-view')); }); });
    main.querySelectorAll('[data-evolve-action]').forEach(function (button) { button.addEventListener('click', function () { if (typeof window.showToast === 'function') window.showToast(button.getAttribute('data-evolve-action') + ' will be available after you connect this centre.'); }); });
  }

  function closePanel(panel) { panel.classList.remove('open'); document.body.style.overflow = ''; }
  window.openMindvoraEvolve = function () { var panel = getPanel(); render(panel, 'overview'); panel.classList.add('open'); document.body.style.overflow = 'hidden'; };
})();
