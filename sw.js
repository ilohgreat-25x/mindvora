// Mindvora Service Worker — sw.js
// One worker does everything: small offline cache + push notifications.
// (Two workers on the same scope used to replace each other, so push stopped
//  working whenever the other one registered.)
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey:            "AIzaSyDdTgIqJuOYJhRAhEF9vMuMA8oZViRPlts",
  authDomain:        "zync-social.firebaseapp.com",
  projectId:         "zync-social",
  storageBucket:     "zync-social.appspot.com",
  messagingSenderId: "720726547858",
  appId:             "1:720726547858:web:3175ba8d0b7c987e31754b"
});

const CACHE = 'mindvora-v15';
const OFFLINE_URL = '/';
const MAX_ENTRIES = 40;              // keeps the cache to a few MB instead of growing forever
const SHELL = ['/', '/index.html', '/manifest.json', '/style.css', '/auth.css', '/responsive.css',
               '/script.js', '/fixes.js', '/calls.js', '/app-update.js', '/icons/icon-192.png'];

self.addEventListener('install', function(e) {
  e.waitUntil(caches.open(CACHE).then(function(c){ return c.addAll(SHELL).catch(function(){}); })
    .then(function(){ return self.skipWaiting(); }));
});

self.addEventListener('activate', function(e) {
  e.waitUntil(caches.keys().then(function(keys) {
    return Promise.all(keys.filter(function(k){ return k !== CACHE; }).map(function(k){ return caches.delete(k); }));
  }).then(function(){ return self.clients.claim(); }));
});

function trim(cache) {
  cache.keys().then(function(keys) {
    if (keys.length > MAX_ENTRIES) keys.slice(0, keys.length - MAX_ENTRIES).forEach(function(k){ cache.delete(k); });
  });
}

// FETCH: network first, cache fallback — ONLY for this site's own small files.
// Images/videos from Cloudinary, Firebase, APIs etc. are no longer stored on the phone.
self.addEventListener('fetch', function(e) {
  var req = e.request;
  if (req.method !== 'GET') return;
  var url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (req.headers.get('range')) return;
  if (/\.(mp4|webm|mov|m4a|mp3|wav|jpg|jpeg|png|gif|webp)$/i.test(url.pathname) && url.pathname.indexOf('/icons/') !== 0) return;
  e.respondWith(
    fetch(req).then(function(res) {
      if (res && res.status === 200 && res.type === 'basic') {
        var clone = res.clone();
        caches.open(CACHE).then(function(c){ c.put(req, clone).then(function(){ trim(c); }); });
      }
      return res;
    }).catch(function() {
      return caches.match(req).then(function(hit){ return hit || (req.mode === 'navigate' ? caches.match(OFFLINE_URL) : undefined); });
    })
  );
});

// PUSH — the backend sends data-only messages; we decide how they look.
function showPush(d) {
  d = d || {};
  var isCall = d.type === 'call';
  return self.registration.showNotification(d.title || 'Mindvora', {
    body: d.body || 'You have a new notification',
    icon: '/icons/icon-192.png',
    badge: '/icons/icon-96.png',
    tag: d.tag || d.type || 'mindvora',
    renotify: true,
    requireInteraction: isCall,
    // Voice call = long double buzz, video call = quick triple pulse (browsers don't allow custom sounds here)
    vibrate: isCall ? (d.media === 'video' ? [150, 100, 150, 100, 500, 400, 150, 100, 150, 100, 500] : [700, 300, 700, 1000, 700, 300, 700]) : [200, 100, 200],
    data: { url: d.url || '/', type: d.type, callId: d.callId, media: d.media },
    actions: isCall ? [{ action: 'open', title: 'Answer' }, { action: 'dismiss', title: 'Ignore' }]
                    : [{ action: 'open', title: 'Open' }]
  });
}
const messaging = firebase.messaging();
messaging.onBackgroundMessage(function(payload) {
  if (payload.notification) return; // the browser already shows notification-type messages itself
  return showPush(payload.data);
});

// NOTIFICATION CLICK
self.addEventListener('notificationclick', function(e) {
  e.notification.close();
  if (e.action === 'dismiss') return;
  var url = (e.notification.data && e.notification.data.url) || '/';
  // "Answer" on a call notification opens the app and answers straight away.
  if (e.notification.data && e.notification.data.type === 'call' && e.action !== 'dismiss') url += (url.indexOf('?') > -1 ? '&' : '?') + 'answer=1';
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

// BACKGROUND SYNC
self.addEventListener('sync', function(e) {
  if (e.tag === 'sync-posts') {
    e.waitUntil(
      self.clients.matchAll().then(function(list) {
        list.forEach(function(c){ c.postMessage({ type: 'SYNC_POSTS' }); });
      })
    );
  }
});

// PERIODIC BACKGROUND SYNC
self.addEventListener('periodicsync', function(e) {
  if (e.tag === 'refresh-feed') {
    e.waitUntil(
      self.clients.matchAll().then(function(list) {
        list.forEach(function(c){ c.postMessage({ type: 'REFRESH_FEED' }); });
      })
    );
  }
});

// MESSAGE HANDLER
self.addEventListener('message', function(e) {
  if (e.data && e.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});


