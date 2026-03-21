// ══════════════════════════════════════════════════════════════
// Mindvora Service Worker — sw.js
// ══════════════════════════════════════════════════════════════
const CACHE = 'mindvora-v4';
const OFFLINE_URL = '/';

// ── INSTALL ──────────────────────────────────────────────────
self.addEventListener('install', function(e) {
  e.waitUntil(
    caches.open(CACHE).then(function(cache) {
      return cache.addAll([
        '/',
        '/index.html',
        '/manifest.json'
      ]).catch(function(){});
    }).then(function() {
      return self.skipWaiting();
    })
  );
});

// ── ACTIVATE ─────────────────────────────────────────────────
self.addEventListener('activate', function(e) {
  e.waitUntil(
    caches.keys().then(function(keys) {
      return Promise.all(
        keys.filter(function(k){ return k !== CACHE; })
            .map(function(k){ return caches.delete(k); })
      );
    }).then(function() {
      return self.clients.claim();
    })
  );
});

// ── FETCH: Network first, cache fallback ─────────────────────
self.addEventListener('fetch', function(e) {
  if (e.request.method !== 'GET') return;
  var url = e.request.url;
  if (url.indexOf('firestore.googleapis.com') > -1) return;
  if (url.indexOf('firebase') > -1) return;
  if (url.indexOf('googleapis.com') > -1) return;
  if (url.indexOf('cloudinary.com') > -1) return;
  if (url.indexOf('paystack') > -1) return;
  if (url.indexOf('mixpanel') > -1) return;

  e.respondWith(
    fetch(e.request)
      .then(function(res) {
        if (res && res.status === 200) {
          var clone = res.clone();
          caches.open(CACHE).then(function(c){ c.put(e.request, clone); });
        }
        return res;
      })
      .catch(function() {
        return caches.match(e.request)
          .then(function(cached){ return cached || caches.match(OFFLINE_URL); });
      })
  );
});

// ── PUSH NOTIFICATIONS ───────────────────────────────────────
self.addEventListener('push', function(e) {
  var data = {};
  try { data = e.data ? e.data.json() : {}; } catch(err) {}
  var title   = data.title   || 'Mindvora';
  var body    = data.body    || 'You have a new notification';
  var icon    = data.icon    || '/icons/icon-192.png';
  var url     = data.url     || '/';
  e.waitUntil(
    self.registration.showNotification(title, {
      body:    body,
      icon:    icon,
      badge:   '/icons/icon-96.png',
      vibrate: [200, 100, 200],
      data:    { url: url },
      actions: [
        { action: 'open',    title: '🌿 Open Mindvora' },
        { action: 'dismiss', title: 'Dismiss' }
      ]
    })
  );
});

// ── NOTIFICATION CLICK ───────────────────────────────────────
self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  if (e.action === 'dismiss') return;
  var url = (e.notification.data && e.notification.data.url) || '/';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(function(list) {
        for (var i = 0; i < list.length; i++) {
          if (list[i].url.indexOf(self.location.origin) > -1 && 'focus' in list[i]) {
            list[i].postMessage({ type: 'NOTIFICATION_CLICK', url: url });
            return list[i].focus();
          }
        }
        if (clients.openWindow) return clients.openWindow(url);
      })
  );
});

// ── BACKGROUND SYNC ──────────────────────────────────────────
self.addEventListener('sync', function(e) {
  if (e.tag === 'sync-posts') {
    e.waitUntil(
      self.clients.matchAll().then(function(list) {
        list.forEach(function(c){ c.postMessage({ type: 'SYNC_POSTS' }); });
      })
    );
  }
});

// ── PERIODIC BACKGROUND SYNC ─────────────────────────────────
self.addEventListener('periodicsync', function(e) {
  if (e.tag === 'refresh-feed') {
    e.waitUntil(
      self.clients.matchAll().then(function(list) {
        list.forEach(function(c){ c.postMessage({ type: 'REFRESH_FEED' }); });
      })
    );
  }
});

// ── MESSAGE HANDLER ──────────────────────────────────────────
self.addEventListener('message', function(e) {
  if (e.data && e.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

console.log('[Mindvora SW] v4 active');
