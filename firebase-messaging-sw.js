// ╔══════════════════════════════════════════════════════════════╗
// ║         MINDVORA — Firebase Push Notification                ║
// ║         Service Worker (firebase-messaging-sw.js)            ║
// ║   Upload this file to GitHub ROOT (same folder as index.html)║
// ╚══════════════════════════════════════════════════════════════╝

importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');

// Same Firebase config as your main app
firebase.initializeApp({
  apiKey:            "AIzaSyDdTgIqJuOYJhRAhEF9vMuMA8oZViRPlts",
  authDomain:        "zync-social.firebaseapp.com",
  projectId:         "zync-social",
  storageBucket:     "zync-social.appspot.com",
  messagingSenderId: "720726547858",
  appId:             "1:720726547858:web:3175ba8d0b7c987e31754b"
});

const messaging = firebase.messaging();

// ── Handle background notifications (app closed or in background) ─────────
messaging.onBackgroundMessage(function(payload) {
  console.log('Mindvora background notification:', payload);

  const title = payload.notification?.title || 'Mindvora';
  const body  = payload.notification?.body  || 'You have a new notification';
  const icon  = payload.notification?.icon  || '/icon-192.png';

  const notificationOptions = {
    body:  body,
    icon:  icon,
    badge: '/icon-192.png',
    tag:   payload.data?.type || 'mindvora-notif',
    data:  payload.data || {},
    actions: [
      { action: 'open',    title: 'Open Mindvora' },
      { action: 'dismiss', title: 'Dismiss' }
    ],
    vibrate: [200, 100, 200],
    requireInteraction: false,
  };

  return self.registration.showNotification(title, notificationOptions);
});

// ── Handle notification click ─────────────────────────────────────────────
self.addEventListener('notificationclick', function(event) {
  event.notification.close();

  if (event.action === 'dismiss') return;

  // Open the app when notification is tapped
  const appURL = 'https://mindvora-own8.vercel.app'

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(function(clientList) {
        // If app is already open — focus it
        for (var i = 0; i < clientList.length; i++) {
          var client = clientList[i];
          if (client.url.includes('vercel.app') && 'focus' in client) {
            return client.focus();
          }
        }
        // Otherwise open a new tab
        if (clients.openWindow) {
          return clients.openWindow(appURL);
        }
      })
  );
});

// ── Service worker install & activate ────────────────────────────────────
self.addEventListener('install',  function(e) { self.skipWaiting(); });
self.addEventListener('activate', function(e) { e.waitUntil(clients.claim()); });
