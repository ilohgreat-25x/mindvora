(function () {
  'use strict';

  var STORAGE_KEY = 'mindvora.settings.v1';
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
    try { return Object.assign({}, defaults, JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}')); }
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
      settingRow('chatLock', 'Chat Lock', 'Require a PIN or platform authenticator before opening chats.') +
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
      '<button type="button" class="mv-settings-btn" data-action="pin">' + (hasPin() ? 'Change PIN' : 'Set PIN') + '</button>' +
      '<button type="button" class="mv-settings-btn" data-action="biometric">' + (hasCredential() ? 'Re-register biometric' : 'Register biometric') + '</button>' +
      '<button type="button" class="mv-settings-btn" data-action="lock">Lock chats now</button>' +
      '<button type="button" class="mv-settings-btn danger" data-action="reset">Logout / reset settings</button></section>';
    body.querySelectorAll('[data-pref]').forEach(function (input) { input.addEventListener('change', function () { prefs[input.getAttribute('data-pref')] = input.checked; savePrefs(); }); });
    body.querySelectorAll('[data-action]').forEach(function (button) { button.addEventListener('click', function () { var action = button.getAttribute('data-action'); if (action === 'pin') setOrChangePin(); if (action === 'biometric') registerBiometric(); if (action === 'lock') { chatUnlocked = false; toast('🔒 Chats locked'); } if (action === 'reset') resetSettings(); }); });
  }
  window.openSettings = function () { renderSettings(); ensureModal().classList.add('open'); };
  window.closeSettings = function () { var modal = document.getElementById('modal-settings'); if (modal) modal.classList.remove('open'); };

  function setOrChangePin() {
    var pin = prompt(hasPin() ? 'Enter a new 4–12 digit PIN:' : 'Create a 4–12 digit PIN:');
    if (!/^\d{4,12}$/.test(pin || '')) { if (pin !== null) toast('PIN must contain 4–12 digits.'); return; }
    hashPin(pin).then(function (hash) { localStorage.setItem(PIN_KEY, hash); prefs.chatLock = true; savePrefs(); chatUnlocked = false; renderSettings(); toast('✅ PIN saved.'); }).catch(function () { toast('Unable to save PIN on this device.'); });
  }
  function registerBiometric() {
    if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) { toast('Platform biometric authentication is not supported here.'); return; }
    var challenge = new Uint8Array(32); crypto.getRandomValues(challenge);
    var userId = new Uint8Array(16); crypto.getRandomValues(userId);
    navigator.credentials.create({ publicKey: { challenge: challenge, rp: { name: 'Mindvora' }, user: { id: userId, name: 'mindvora-user', displayName: 'Mindvora user' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' }, timeout: 60000 } }).then(function (credential) {
      localStorage.setItem(CRED_KEY, bytesToBase64(new Uint8Array(credential.rawId))); prefs.chatLock = true; savePrefs(); renderSettings(); toast('✅ Platform authenticator registered.');
    }).catch(function () { toast('Biometric registration was cancelled or unavailable.'); });
  }
  function unlockWithPin() {
    var pin = prompt('Enter your Chat Lock PIN:');
    if (!pin) return Promise.resolve(false);
    return hashPin(pin).then(function (hash) { if (hash === localStorage.getItem(PIN_KEY)) { chatUnlocked = true; return true; } toast('Incorrect PIN.'); return false; });
  }
  function unlockWithBiometric() {
    if (!hasCredential() || !navigator.credentials || !navigator.credentials.get) return Promise.resolve(false);
    var challenge = new Uint8Array(32); crypto.getRandomValues(challenge);
    return navigator.credentials.get({ publicKey: { challenge: challenge, allowCredentials: [{ type: 'public-key', id: base64ToBytes(localStorage.getItem(CRED_KEY)) }], userVerification: 'required', timeout: 60000 } }).then(function () { chatUnlocked = true; return true; }).catch(function () { return false; });
  }
  function unlockChat() { return (hasCredential() ? unlockWithBiometric() : Promise.resolve(false)).then(function (ok) { return ok || unlockWithPin(); }); }
  function resetSettings() { if (!confirm('Reset Chat Lock and local Mindvora preferences on this device?')) return; localStorage.removeItem(STORAGE_KEY); localStorage.removeItem(PIN_KEY); localStorage.removeItem(CRED_KEY); prefs = Object.assign({}, defaults); chatUnlocked = false; renderSettings(); toast('Settings reset.'); }
  window.MVSettings = { get: getPref, lock: function () { chatUnlocked = false; }, unlock: unlockChat };

  if (typeof originalOpenChat === 'function') {
    window.openChat = function () {
      var args = arguments;
      if (!prefs.chatLock || chatUnlocked || (!hasPin() && !hasCredential())) return originalOpenChat.apply(window, args);
      pendingChat = Array.prototype.slice.call(args);
      unlockChat().then(function (ok) { if (ok && pendingChat) { var call = pendingChat; pendingChat = null; originalOpenChat.apply(window, call); } });
    };
  }
}());
