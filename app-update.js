// Mindvora — update check.
// Asks the backend which versions are still supported. If this copy of the
// app is older than `minSupported`, it shows a full-screen "Update required"
// page with a button to the Play Store / App Store. If it's only older than
// `latest`, it shows a dismissible "Update available" note.
// Also loads the test/live Paystack key and push key from the server.
(function () {
  'use strict';
  // The installed Android/iOS app tells us its version in the user agent ("MindvoraApp/3.0.0",
  // set from versionName at build time). The website itself uses WEB_VERSION.
  var WEB_VERSION = '3.0.0';
  var uaV = (navigator.userAgent.match(/MindvoraApp\/(\d+\.\d+\.\d+)/) || [])[1];
  var APP_VERSION = uaV || WEB_VERSION;
  window.MV_APP_VERSION = APP_VERSION;
  // Hidden features: switched on only by the server (config/app-version.json) AND only for
  // app versions that include them. Code checks MVFeatures.isOn('name') before showing a feature.
  var features = {};
  window.MVFeatures = { isOn: function (n) { return !!features[n]; }, all: function () { return features; } };

  function platform() {
    var C = window.Capacitor;
    if (C && C.getPlatform) { var p = C.getPlatform(); if (p === 'android' || p === 'ios') return p; }
    return 'web';
  }
  function cmp(a, b) {
    var x = String(a || '0').split('.').map(Number), y = String(b || '0').split('.').map(Number);
    for (var i = 0; i < 3; i++) { var d = (x[i] || 0) - (y[i] || 0); if (d) return d > 0 ? 1 : -1; }
    return 0;
  }
  function screen(info, forced) {
    if (document.getElementById('mv-update')) return;
    var el = document.createElement('div');
    el.id = 'mv-update'; el.className = 'mv-update';
    var p = platform();
    var action = p === 'web'
      ? '<button onclick="location.reload(true)">Reload now</button>'
      : (info.storeUrl ? '<a href="' + info.storeUrl + '" target="_blank" rel="noopener">Update on ' + (p === 'ios' ? 'App Store' : 'Play Store') + '</a>' : '');
    el.innerHTML = '<h2>' + (forced ? 'Update required' : 'Update available') + '</h2>' +
      '<p>' + (info.message || 'A new version of Mindvora is available.') +
      (forced ? ' This version is no longer supported.' : '') +
      (info.minOs && p !== 'web' ? '<br><br>The new version needs ' + info.minOs + ' or newer.' : '') + '</p>' + action +
      (forced ? '' : '<button class="later" onclick="this.parentNode.remove()">Later</button>');
    document.body.appendChild(el);
  }
  function check() {
    var base = window.BACKEND_URL || '';
    if (!base || typeof fetch !== 'function') return;
    fetch(base + '/api/app/version?platform=' + platform() + '&version=' + encodeURIComponent(APP_VERSION)).then(function (r) { return r.json(); }).then(function (v) {
      if (!v || !v.status) return;
      features = v.features || {};
      try { document.dispatchEvent(new CustomEvent('mv:features', { detail: features })); } catch (e) {}
      if (v.minSupported && cmp(APP_VERSION, v.minSupported) < 0) screen(v, true);
      else if (v.latest && cmp(APP_VERSION, v.latest) < 0 && platform() !== 'web') screen(v, false);
    }).catch(function () {});
    fetch(base + '/api/public-config').then(function (r) { return r.json(); }).then(function (c) {
      if (!c || !c.status) return;
      if (c.paystackPublicKey) window.MV_PAYSTACK_PK = c.paystackPublicKey;
      if (c.vapidKey) window.MV_VAPID_KEY = c.vapidKey;
      if (c.paystackTestMode) console.info('[Mindvora] Paystack is in TEST mode — use test cards.');
    }).catch(function () {});
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', check); else check();
  document.addEventListener('visibilitychange', function () { if (!document.hidden) check(); });
})();
