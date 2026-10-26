(function () {
  'use strict';

  var STORAGE_KEY = 'mindvora.settings.v2';
  var LEGACY_STORAGE_KEY = 'mindvora.settings.v1';
  var PIN_KEY = 'mindvora.chatLock.pinHash';
  var CRED_KEY = 'mindvora.chatLock.credentialId';
  var defaults = {
    chatLock: false,
    seenMark: true,
    onlineVisibility: true,
    typingIndicator: true,
    notifications: true,
    messageNotifications: true,
    soundNotifications: true,
    autoplay: true,
    dataSaver: false
  };
  var prefs = loadPrefs();
  var chatUnlocked = false;
  var pendingChat = null;
  var originalOpenChat = window.openChat;

  function loadPrefs() {
    try { return Object.assign({}, defaults, JSON.parse(localStorage.getItem(STORAGE_KEY) || localStorage.getItem(LEGACY_STORAGE_KEY) || '{}')); }
    catch (e) { return Object.assign({}, defaults); }
  }
  function savePrefs() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs)); } catch (e) {}
  }
  function getPref(name) { return prefs[name]; }
  function hasPin() { try { return !!localStorage.getItem(PIN_KEY); } catch (e) { return false; } }
  function hasCredential() { try { return !!localStorage.getItem(CRED_KEY); } catch (e) { return false; } }
  function bytesToBase64(bytes) { var s = ''; for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]); return btoa(s); }
  function base64ToBytes(value) { var s = atob(value), out = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }
  function hashPin(pin) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(pin)).then(bytesToBase64);
  }
  function biometricAvailable() { return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create && navigator.credentials.get); }
  function dispatchSettingsChange() { try { document.dispatchEvent(new CustomEvent('mv:settings-changed', { detail: { prefs: Object.assign({}, prefs) } })); } catch (e) {} }
  function applyPrefs() {
    var root = document.documentElement;
    Object.keys(prefs).forEach(function (key) { root.setAttribute('data-mv-' + key, prefs[key] ? 'on' : 'off'); });
    document.querySelectorAll('video, audio').forEach(function (media) {
      if (!prefs.autoplay) { media.autoplay = false; media.removeAttribute('autoplay'); media.pause(); }
      if (prefs.dataSaver) media.preload = 'none';
    });
    dispatchSettingsChange();
  }
  function setPreference(key, value) {
    if (key === 'chatLock' && value && !hasPin()) { setOrChangePin(true); return; }
    prefs[key] = !!value;
    if (key === 'chatLock' && !value) chatUnlocked = false;
    savePrefs(); applyPrefs(); renderSettings();
  }
  function wrapPreferenceGate(name, gate) {
    var fn = window[name];
    if (typeof fn !== 'function' || fn.__mvSettingsWrapped) return;
    var wrapped = function () { if (!gate()) return; return fn.apply(this, arguments); };
    wrapped.__mvSettingsWrapped = true; window[name] = wrapped;
  }
  function installPreferenceHooks() {
    wrapPreferenceGate('showNativeNotification', function () { return prefs.notifications && prefs.messageNotifications; });
    wrapPreferenceGate('playNotificationSound', function () { return prefs.notifications && prefs.soundNotifications; });
    wrapPreferenceGate('startRealtimeNotifListener', function () { return prefs.notifications && prefs.messageNotifications; });
    wrapPreferenceGate('subscribePush', function () { return prefs.notifications; });
    applyPrefs();
  }
  function toast(message) { if (typeof window.showToast === 'function') window.showToast(message); else alert(message); }
  function esc(value) { return String(value).replace(/[&<>"']/g, function (c) { return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }

  function ensureModal() {
    var modal = document.getElementById('modal-settings');
    if (modal) return modal;
    modal = document.createElement('div');
    modal.id = 'modal-settings';
    modal.className = 'mv-settings-overlay';
    modal.innerHTML = '<div class="mv-settings-modal" role="dialog" aria-modal="true" aria-labelledby="mv-settings-title"><div class="mv-settings-head"><h2 id="mv-settings-title">⚙️ Settings</h2><button type="button" class="mv-settings-close" data-action="close">✕</button></div><div class="mv-settings-body" id="mv-settings-body"></div></div>';
    document.body.appendChild(modal);
    modal.addEventListener('click', function (event) { if (event.target === modal || event.target.getAttribute('data-action') === 'close') closeSettings(); });
    return modal;
  }
  function settingRow(key, label, description) {
    return '<label class="mv-setting-row"><span><strong>' + label + '</strong><small>' + description + '</small></span><input type="checkbox" data-pref="' + key + '" ' + (prefs[key] ? 'checked' : '') + '><span class="mv-switch" aria-hidden="true"></span></label>';
  }
  function renderSettings() {
    var body = ensureModal().querySelector('#mv-settings-body');
    body.innerHTML = '<section class="mv-settings-section"><h3>Privacy & presence</h3>' +
      settingRow('chatLock', 'Chat Lock', 'Require a PIN/password or supported device biometric before opening private chats.') +
      settingRow('seenMark', 'SeenMark', 'Show read receipts and mark incoming messages as read when a chat opens.') +
      settingRow('onlineVisibility', 'Online visibility', 'Let other people see when you are online.') +
      settingRow('typingIndicator', 'Typing indicator', 'Show typing activity in conversations.') + '</section>' +
      '<section class="mv-settings-section"><h3>Notifications</h3>' +
      settingRow('notifications', 'Notifications', 'Allow Mindvora notifications.') +
      settingRow('messageNotifications', 'Message notifications', 'Notify about new direct messages.') +
      settingRow('soundNotifications', 'Notification sounds', 'Play sounds for notifications.') + '</section>' +
      '<section class="mv-settings-section"><h3>Media & data</h3>' +
      settingRow('autoplay', 'Autoplay', 'Automatically play supported media.') +
      settingRow('dataSaver', 'Data saver', 'Reduce media data usage.') + '</section>' +
      '<section class="mv-settings-section mv-settings-actions"><h3>Chat Lock controls</h3>' +
      '<p class="mv-settings-help">Set a PIN/password first. If fingerprint, Face ID, Touch ID, or another supported device biometric is available, Mindvora will then offer it for faster unlock. A mismatch or cancellation always falls back to your PIN/password.</p>' +
      '<button type="button" class="mv-settings-btn" data-action="pin">' + (hasPin() ? 'Change PIN/password' : 'Set PIN/password') + '</button>' +
      '<button type="button" class="mv-settings-btn" data-action="biometric">' + (hasCredential() ? 'Re-register biometric' : 'Enable device biometric') + '</button>' +
      (hasCredential() ? '<button type="button" class="mv-settings-btn" data-action="remove-biometric">Remove biometric</button>' : '') +
      '<button type="button" class="mv-settings-btn" data-action="lock">Lock chats now</button>' +
      '<button type="button" class="mv-settings-btn danger" data-action="reset">Logout / reset settings</button></section>';
    body.querySelectorAll('[data-pref]').forEach(function (input) { input.addEventListener('change', function () { setPreference(input.getAttribute('data-pref'), input.checked); }); });
    body.querySelectorAll('[data-action]').forEach(function (button) { button.addEventListener('click', function () { var action = button.getAttribute('data-action'); if (action === 'pin') setOrChangePin(false); if (action === 'biometric') registerBiometric(true); if (action === 'remove-biometric') { localStorage.removeItem(CRED_KEY); renderSettings(); toast('Device biometric removed. PIN/password remains enabled.'); } if (action === 'lock') { chatUnlocked = false; toast('🔒 Chats locked'); } if (action === 'reset') resetSettings(); }); });
  }
  window.openSettings = function () { renderSettings(); ensureModal().classList.add('open'); };
  window.closeSettings = function () { var modal = document.getElementById('modal-settings'); if (modal) modal.classList.remove('open'); };

  function setOrChangePin(fromToggle) {
    var pin = prompt(hasPin() ? 'Enter a new PIN/password:' : 'Create a PIN/password (4–12 digits or 6–64 characters):');
    var valid = /^\d{4,12}$/.test(pin || '') || ((pin || '').length >= 6 && (pin || '').length <= 64);
    if (!valid) { if (pin !== null) toast('Use a 4–12 digit PIN or a 6–64 character password.'); if (fromToggle) { prefs.chatLock = false; savePrefs(); renderSettings(); } return; }
    hashPin(pin).then(function (hash) { localStorage.setItem(PIN_KEY, hash); localStorage.removeItem(CRED_KEY); prefs.chatLock = true; savePrefs(); chatUnlocked = false; applyPrefs(); renderSettings(); toast('✅ PIN/password saved.'); if (biometricAvailable() && confirm('Enable fingerprint, Face ID, Touch ID, or another device biometric for faster unlock?')) registerBiometric(false); }).catch(function () { toast('Unable to save PIN/password on this device.'); });
  }
  function registerBiometric(showUnavailable) {
    if (!hasPin()) { toast('Set a PIN/password first.'); setOrChangePin(true); return; }
    if (!biometricAvailable()) { if (showUnavailable) toast('No supported device biometric is available. Your PIN/password will unlock chats.'); return; }
    var challenge = new Uint8Array(32); crypto.getRandomValues(challenge);
    var userId = new Uint8Array(16); crypto.getRandomValues(userId);
    navigator.credentials.create({ publicKey: { challenge: challenge, rp: { name: 'Mindvora' }, user: { id: userId, name: 'mindvora-user', displayName: 'Mindvora user' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' }, timeout: 60000 } }).then(function (credential) {
      localStorage.setItem(CRED_KEY, bytesToBase64(new Uint8Array(credential.rawId))); prefs.chatLock = true; savePrefs(); applyPrefs(); renderSettings(); toast('✅ Device biometric enabled. PIN/password fallback remains available.');
    }).catch(function () { toast('Biometric setup was cancelled or unavailable. Your PIN/password still unlocks chats.'); });
  }
  function unlockWithPin() {
    var pin = prompt('Biometric verification failed. Enter your PIN/password to access chats:');
    if (!pin) return Promise.resolve(false);
    return hashPin(pin).then(function (hash) { if (hash === localStorage.getItem(PIN_KEY)) { chatUnlocked = true; return true; } toast('Incorrect PIN/password.'); return false; });
  }
  function unlockWithBiometric() {
    if (!hasCredential() || !navigator.credentials || !navigator.credentials.get) return Promise.reject(new Error('Biometric unavailable'));
    var challenge = new Uint8Array(32); crypto.getRandomValues(challenge);
    return navigator.credentials.get({ publicKey: { challenge: challenge, allowCredentials: [{ type: 'public-key', id: base64ToBytes(localStorage.getItem(CRED_KEY)) }], userVerification: 'required', timeout: 60000 } }).then(function () { chatUnlocked = true; return true; });
  }
  function unlockChat() { if (!hasPin()) { toast('Set a PIN/password in Settings before opening locked chats.'); return Promise.resolve(false); } return (hasCredential() ? unlockWithBiometric().catch(function () { toast('Biometric verification failed. Enter your PIN/password.'); return unlockWithPin(); }) : unlockWithPin()); }
  function resetSettings() { if (!confirm('Reset Chat Lock and local Mindvora preferences on this device?')) return; localStorage.removeItem(STORAGE_KEY); localStorage.removeItem(PIN_KEY); localStorage.removeItem(CRED_KEY); prefs = Object.assign({}, defaults); chatUnlocked = false; applyPrefs(); renderSettings(); toast('Settings reset.'); }
  window.MVSettings = { get: getPref, set: setPreference, lock: function () { chatUnlocked = false; }, unlock: unlockChat, apply: applyPrefs };

  if (typeof originalOpenChat === 'function') {
    window.openChat = function () {
      var args = arguments;
      if (!prefs.chatLock || chatUnlocked || (!hasPin() && !hasCredential())) return originalOpenChat.apply(window, args);
      pendingChat = Array.prototype.slice.call(args);
      unlockChat().then(function (ok) { if (ok && pendingChat) { var call = pendingChat; pendingChat = null; originalOpenChat.apply(window, call); } });
    };
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', installPreferenceHooks); else installPreferenceHooks();
}());
