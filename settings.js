(function () {
  'use strict';

  var STORAGE_KEY = 'mindvora.settings.v2';
  var LEGACY_STORAGE_KEY = 'mindvora.settings.v1';
  var PIN_KEY = 'mindvora.chatLock.pinHash';
  var CRED_KEY = 'mindvora.chatLock.credentialId';
  var defaults = {
    chatLock: false,
    appLock: false,
    seenMark: true,
    onlineVisibility: true,
    typingIndicator: true,
    notifications: true,
    messageNotifications: true,
    soundNotifications: true,
    autoplay: true,
    dataSaver: false,
    autoLock: '5m'
  };
  var prefs = loadPrefs();
  var appUnlocked = false;
  var autoLockTimer = null;
  var lockOverlay = null;
  var lastActivityAt = Date.now();

  function loadPrefs() {
    try {
      var stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || localStorage.getItem(LEGACY_STORAGE_KEY) || '{}');
      if (typeof stored.appLock === 'undefined' && stored.chatLock === true) stored.appLock = true;
      return Object.assign({}, defaults, stored);
    }
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
  var NATIVE_BIOMETRIC_CREDENTIAL = 'mindvora-native-biometric-v1';
  function hashPin(pin) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(pin)).then(function (digest) { return bytesToBase64(new Uint8Array(digest)); });
  }
  function nativeBiometricPlugin() {
    var cap = window.Capacitor;
    if (!cap || typeof cap.isNativePlatform !== 'function' || !cap.isNativePlatform() || typeof cap.registerPlugin !== 'function') return null;
    if (typeof cap.isPluginAvailable === 'function' && !cap.isPluginAvailable('BiometricAuthNative')) return null;
    try {
      var bridge = cap.registerPlugin('BiometricAuthNative');
      if (!bridge) return null;
      // The plugin’s public authenticate() wrapper lives in its bundled JS module.
      // Mindvora calls the native bridge directly, whose registered method is internalAuthenticate.
      return { checkBiometry: bridge.checkBiometry.bind(bridge), authenticate: bridge.internalAuthenticate.bind(bridge) };
    } catch (e) { return null; }
  }
  function biometricLabel(info, native) {
    if (!native) return 'device biometric or platform authenticator';
    var platform = window.Capacitor && typeof window.Capacitor.getPlatform === 'function' ? window.Capacitor.getPlatform() : '';
    var type = Number(info && info.biometryType);
    if (platform === 'ios' && type === 1) return 'Touch ID';
    if (platform === 'ios' && type === 2) return 'Face ID';
    if (platform === 'android' && info && info.isAvailable && info.strongBiometryIsAvailable && type === 3) return 'fingerprint';
    if (platform === 'android' && info && info.isAvailable) return 'device biometric';
    return 'device biometric';
  }
  function detectBiometricAvailability() {
    var plugin = nativeBiometricPlugin();
    if (plugin && typeof plugin.checkBiometry === 'function' && typeof plugin.authenticate === 'function') {
      return Promise.resolve().then(function () { return plugin.checkBiometry(); }).then(function (info) {
        info = info || {};
        return { available: info.isAvailable === true, native: true, plugin: plugin, label: biometricLabel(info, true), reason: info.reason || '' };
      }).catch(function () {
        return { available: false, native: true, plugin: plugin, label: 'device biometric', reason: 'Mindvora could not verify biometric availability on this device.' };
      });
    }
    if (!window.isSecureContext) return Promise.resolve({ available: false, native: false, reason: 'Biometric unlock requires a secure HTTPS connection or a supported native app.' });
    var publicKey = window.PublicKeyCredential;
    if (!publicKey || !navigator.credentials || typeof navigator.credentials.create !== 'function' || typeof navigator.credentials.get !== 'function' || typeof publicKey.isUserVerifyingPlatformAuthenticatorAvailable !== 'function') {
      return Promise.resolve({ available: false, native: false, reason: 'This browser does not expose an app-usable biometric or platform authenticator.' });
    }
    return Promise.resolve().then(function () { return publicKey.isUserVerifyingPlatformAuthenticatorAvailable(); }).then(function (available) {
      return { available: available === true, native: false, label: 'device biometric or platform authenticator', reason: available ? '' : 'No enrolled platform authenticator is available to this browser.' };
    }).catch(function () {
      return { available: false, native: false, reason: 'Mindvora could not verify biometric availability in this browser.' };
    });
  }
  function biometricAuthOptions() {
    return { reason: 'Confirm your identity to unlock Mindvora.', cancelTitle: 'Use Mindvora PIN/password', allowDeviceCredential: false, iosFallbackTitle: '', androidTitle: 'Unlock Mindvora', androidSubtitle: 'Confirm your identity', androidConfirmationRequired: false, androidBiometryStrength: 0 };
  }
  function biometricUnavailableMessage(result) {
    return (result.reason || 'No enrolled app-usable biometric is available.') + (result.native ? ' If you expected it to be available, enroll a biometric in your device security settings and reopen this section.' : '') + ' Your Mindvora PIN/password remains available.';
  }
  function showBiometricStatus() {
    var status = document.querySelector('#modal-settings [data-biometric-status]');
    var button = document.querySelector('#modal-settings [data-action="biometric"]');
    if (!status || !button) return;
    if (!hasPin()) {
      status.textContent = 'Set a Mindvora PIN/password first. Biometrics will be offered only as a quicker unlock method after that.';
      button.textContent = 'Set PIN/password first';
      button.disabled = true;
      return;
    }
    status.textContent = 'Checking whether this device has an enrolled biometric authenticator…';
    button.textContent = 'Checking device…';
    button.disabled = true;
    detectBiometricAvailability().then(function (result) {
      if (!button.isConnected || !status.isConnected) return;
      if (!result.available) {
        status.textContent = biometricUnavailableMessage(result);
        button.textContent = 'Biometric unavailable';
        button.disabled = true;
        return;
      }
      status.textContent = 'Available: ' + result.label + '. Your device chooses the prompt. Mindvora never receives biometric data; if recognition fails or is cancelled, use your Mindvora PIN/password.';
      button.textContent = (hasCredential() ? 'Re-register ' : 'Enable ') + result.label;
      button.disabled = false;
    });
  }
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
    if (key === 'autoLock') { setAutoLock(value); return; }
    if (key === 'appLock' && value && !hasPin()) { setOrChangePin(true); return; }
    prefs[key] = !!value;
    if (key === 'appLock') {
      if (!value) { appUnlocked = false; clearTimeout(autoLockTimer); autoLockTimer = null; hideAppLock(); }
      else { appUnlocked = appIsVisible(); lastActivityAt = Date.now(); }
    }
    savePrefs(); applyPrefs(); renderSettings();
    if (key === 'appLock' && value) scheduleAutoLock();
  }
  var AUTO_LOCK_OPTIONS = [
    { value: 'immediate', label: 'Immediately' },
    { value: '30s', label: '30 secs' },
    { value: '1m', label: '1 min' },
    { value: '3m', label: '3 mins' },
    { value: '5m', label: '5 mins' },
    { value: '2h', label: '2 hrs' },
    { value: '4h', label: '4 hrs' },
    { value: '1d', label: '1 day' }
  ];
  function autoLockMs() { return ({ '30s': 30000, '1m': 60000, '3m': 180000, '5m': 300000, '2h': 7200000, '4h': 14400000, '1d': 86400000 })[prefs.autoLock] || 0; }
  function lockApp(reason) {
    if (!prefs.appLock) return;
    appUnlocked = false;
    clearTimeout(autoLockTimer); autoLockTimer = null;
    if (appIsVisible()) showStartupLock();
    if (reason) setLockError('Mindvora locked after inactivity.');
  }
  function scheduleAutoLock() {
    clearTimeout(autoLockTimer); autoLockTimer = null;
    if (!prefs.appLock || !appUnlocked) return;
    var ms = autoLockMs();
    if (ms > 0) {
      var remaining = ms - (Date.now() - lastActivityAt);
      if (remaining <= 0) { lockApp(true); return; }
      autoLockTimer = setTimeout(function () { lockApp(true); }, remaining);
    }
  }
  function recordActivity() { if (prefs.appLock && appUnlocked) { lastActivityAt = Date.now(); scheduleAutoLock(); } }
  function setAutoLock(value) {
    if (!AUTO_LOCK_OPTIONS.some(function (option) { return option.value === value; })) value = '5m';
    prefs.autoLock = value; lastActivityAt = Date.now(); savePrefs(); applyPrefs(); renderSettings(); scheduleAutoLock();
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
  function billingDate(value) {
    var date = value ? new Date(value) : null;
    return date && !isNaN(date.getTime()) ? date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : 'not available';
  }
  function openPremiumPlans() {
    if (typeof window.closeSettings === 'function') window.closeSettings();
    var modal = document.getElementById('modal-prem');
    if (!modal) { toast('Premium plans are unavailable right now.'); return; }
    try {
      if (typeof window.openModal === 'function') window.openModal('modal-prem');
      else modal.classList.add('open');
    } catch (error) {
      modal.classList.add('open');
      console.warn('[Mindvora] Premium modal dispatcher failed; opened directly.', error);
    }
  }
  function renderBillingStatus(data) {
    var target = document.getElementById('mv-billing-status');
    if (!target) return;
    if (!data || !data.status) {
      target.innerHTML = '<p class="mv-settings-help">Subscription status is temporarily unavailable. Your current billing setting has not been changed.</p><button type="button" class="mv-settings-btn" data-action="billing-plans">View Premium plans</button>';
      var unavailablePlans = target.querySelector('[data-action="billing-plans"]');
      if (unavailablePlans) unavailablePlans.addEventListener('click', openPremiumPlans);
      return;
    }
    try { document.dispatchEvent(new CustomEvent('mv:subscription-status', { detail: data })); } catch (e) {}
    var sub = data.subscription;
    var html = '';
    if (sub && sub.canManage) {
      var statusText = sub.lastPaymentStatus === 'failed'
        ? 'Your last renewal payment failed; verify the payment method. Auto-renew remains ' + (sub.autoRenew ? 'on.' : 'off.')
        : (sub.autoRenew ? 'Auto-renew is on.' : 'Auto-renew is off; no further renewal charge is scheduled.');
      var paidThrough = sub.currentPeriodEnd ? billingDate(sub.currentPeriodEnd) : 'not available';
      var amount = sub.amountKobo ? 'NGN ' + (sub.amountKobo / 100).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' monthly' : 'monthly';
      html = '<p class="mv-settings-help">' + esc(statusText) + ' ' + esc(sub.planName) + ' · ' + esc(amount) + '. Access is paid through ' + esc(paidThrough) + '.</p>' +
        '<label class="mv-setting-row mv-billing-toggle"><span><strong>Auto-renew subscription</strong><small>Turn off to stop future Paystack charges. Your current paid access remains until the paid-through date.</small></span><input type="checkbox" data-sub-renewal ' + (sub.autoRenew ? 'checked' : '') + '><span class="mv-switch" aria-hidden="true"></span></label>';
    } else if (sub && sub.autoRenew) {
      html = '<p class="mv-settings-help">Paystack reports auto-renew is on, but its cancellation credential is not available to this app yet. No setting has been changed. Contact Mindvora support to prevent future charges.</p>';
    } else if (data.pending) {
      html = '<p class="mv-settings-help">Paystack is confirming the first subscription payment. Refresh Settings shortly to see the cancellation control once the subscription is registered.</p>';
    } else if (data.premium && data.premium.isActive && data.premium.expiresAt) {
      html = '<p class="mv-settings-help">Premium is active and paid through ' + esc(billingDate(data.premium.expiresAt)) + ', but this purchase is not set to auto-renew. Existing access is unchanged.</p>';
    } else if (data.premium && data.premium.isActive) {
      html = '<p class="mv-settings-help">Premium is active on this account and is not enrolled in auto-renew. Existing access is unchanged; no recurring charge will be made.</p>';
    } else {
      html = '<p class="mv-settings-help">No auto-renewing Premium subscription is active. To enroll, choose a Premium plan and explicitly select auto-renew at Paystack checkout. Crypto payments remain one-time.</p>';
    }
    html += '<button type="button" class="mv-settings-btn" data-action="billing-plans">View Premium plans</button>';
    target.innerHTML = html;
    var plansButton = target.querySelector('[data-action="billing-plans"]');
    if (plansButton) plansButton.addEventListener('click', openPremiumPlans);
    var toggle = target.querySelector('[data-sub-renewal]');
    if (toggle) toggle.addEventListener('change', function () {
      var desired = toggle.checked;
      toggle.disabled = true;
      if (typeof window.mvApi !== 'function') { toast('Billing service is unavailable.'); loadSubscriptionBilling(); return; }
      window.mvApi('/api/pay/subscription/renewal', { enabled: desired }).then(function (result) {
        if (!result || !result.status) throw new Error((result && result.message) || 'Could not update auto-renew.');
        renderBillingStatus(result);
        toast(desired ? 'Auto-renew is on.' : 'Auto-renew is off. You keep access through the paid-through date.');
      }).catch(function (error) {
        toast(error.message || 'Could not update auto-renew.');
        loadSubscriptionBilling();
      });
    });
  }
  function loadSubscriptionBilling() {
    var target = document.getElementById('mv-billing-status');
    if (!target) return;
    target.innerHTML = '<p class="mv-settings-help">Checking subscription status…</p>';
    if (typeof window.mvApi !== 'function') { renderBillingStatus(null); return; }
    window.mvApi('/api/pay/subscription/status').then(renderBillingStatus).catch(function () { renderBillingStatus(null); });
  }
  function renderSettings() {
    var body = ensureModal().querySelector('#mv-settings-body');
    body.innerHTML = '<section class="mv-settings-section"><h3>Privacy & presence</h3>' +
      settingRow('appLock', 'App Lock', 'Require a PIN/password or supported device biometric when Mindvora opens. Private-message locking is controlled separately by Lock Chat in each conversation.') +
      settingRow('seenMark', 'SeenMark', 'Show read receipts and mark incoming messages as read when a chat opens.') +
      settingRow('onlineVisibility', 'Online visibility', 'Let other people see when you are online.') +
      settingRow('typingIndicator', 'Typing indicator', 'Show typing activity in conversations.') + '</section>' +
      '<section class="mv-settings-section"><h3>Subscription billing</h3><div id="mv-billing-status"><p class="mv-settings-help">Checking subscription status…</p></div></section>' +
      '<section class="mv-settings-section"><h3>Notifications</h3>' +
      settingRow('notifications', 'Notifications', 'Allow Mindvora notifications.') +
      settingRow('messageNotifications', 'Message notifications', 'Notify about new direct messages.') +
      settingRow('soundNotifications', 'Notification sounds', 'Play sounds for notifications.') + '</section>' +
      '<section class="mv-settings-section"><h3>Media & data</h3>' +
      settingRow('autoplay', 'Autoplay', 'Automatically play supported media.') +
      settingRow('dataSaver', 'Data saver', 'Reduce media data usage.') + '</section>' +
      '<section class="mv-settings-section mv-settings-actions"><h3>App Lock controls</h3>' +
      '<p class="mv-settings-help">App Lock covers the whole app after inactivity and whenever Mindvora is reopened. It does not change or lock individual conversations; use Lock Chat in a conversation only when you want that separate feature. Set a PIN/password first, then enable an enrolled device biometric such as fingerprint, Touch ID, or Face ID if available. Your operating system chooses the sensor. Mindvora never receives or stores biometric data; if recognition fails or is cancelled, enter your Mindvora PIN/password.</p>' +
      '<label class="mv-settings-select"><span><strong>Automatically lock app</strong><small>Lock the whole app after inactivity or when it is backgrounded.</small></span><select data-auto-lock>' + AUTO_LOCK_OPTIONS.map(function (option) { return '<option value="' + option.value + '"' + (prefs.autoLock === option.value ? ' selected' : '') + '>' + option.label + '</option>'; }).join('') + '</select></label>' +
      '<button type="button" class="mv-settings-btn" data-action="pin">' + (hasPin() ? 'Change PIN/password' : 'Set PIN/password') + '</button>' +
      '<p class="mv-settings-help" data-biometric-status>Checking whether this device has an enrolled biometric authenticator…</p>' +
      '<button type="button" class="mv-settings-btn" data-action="biometric" ' + (hasPin() ? '' : 'disabled') + '>' + (hasCredential() ? 'Re-register biometric' : (hasPin() ? 'Checking device…' : 'Set PIN/password first')) + '</button>' +
      (hasCredential() ? '<button type="button" class="mv-settings-btn" data-action="remove-biometric">Remove biometric</button>' : '') +
      '<button type="button" class="mv-settings-btn" data-action="lock">Lock Mindvora now</button>' +
      '<button type="button" class="mv-settings-btn danger" data-action="reset">Logout / reset settings</button></section>';
    body.querySelectorAll('[data-pref]').forEach(function (input) { input.addEventListener('change', function () { setPreference(input.getAttribute('data-pref'), input.checked); }); });
    var autoLockSelect = body.querySelector('[data-auto-lock]');
    if (autoLockSelect) autoLockSelect.addEventListener('change', function () { setAutoLock(autoLockSelect.value); });
    body.querySelectorAll('[data-action]').forEach(function (button) { button.addEventListener('click', function () { var action = button.getAttribute('data-action'); if (action === 'pin') setOrChangePin(false); if (action === 'biometric') registerBiometric(true); if (action === 'remove-biometric') { localStorage.removeItem(CRED_KEY); renderSettings(); toast('Device biometric removed. PIN/password remains enabled.'); } if (action === 'lock') lockApp(false); if (action === 'reset') resetSettings(); }); });
    loadSubscriptionBilling();
    showBiometricStatus();
  }
  window.openSettings = function () { renderSettings(); ensureModal().classList.add('open'); };
  window.closeSettings = function () { var modal = document.getElementById('modal-settings'); if (modal) modal.classList.remove('open'); };

  function setOrChangePin(fromToggle) {
    var pin = prompt(hasPin() ? 'Enter a new PIN/password:' : 'Create a PIN/password (4–12 digits or 6–64 characters):');
    var valid = /^\d{4,12}$/.test(pin || '') || ((pin || '').length >= 6 && (pin || '').length <= 64);
    if (!valid) { if (pin !== null) toast('Use a 4–12 digit PIN or a 6–64 character password.'); if (fromToggle) { prefs.appLock = false; savePrefs(); renderSettings(); } return; }
    hashPin(pin).then(function (hash) {
      localStorage.setItem(PIN_KEY, hash); localStorage.removeItem(CRED_KEY); prefs.appLock = true; savePrefs(); appUnlocked = appIsVisible(); if (appUnlocked) lastActivityAt = Date.now(); applyPrefs(); renderSettings(); scheduleAutoLock(); toast('✅ PIN/password saved.');
      return detectBiometricAvailability().then(function (result) {
        if (result.available && confirm('Enable ' + result.label + ' for quicker Mindvora unlock? The operating system will ask you to verify it. Your Mindvora PIN/password remains the fallback.')) registerBiometric(false, true, result);
        else if (!result.available) toast('PIN/password saved. ' + biometricUnavailableMessage(result));
      });
    }).catch(function () { toast('Unable to save PIN/password on this device.'); });
  }
  function saveBiometricCredential(credential, label) {
    localStorage.setItem(CRED_KEY, credential); prefs.appLock = true; savePrefs(); appUnlocked = appIsVisible(); if (appUnlocked) lastActivityAt = Date.now(); applyPrefs(); renderSettings(); scheduleAutoLock(); toast('✅ ' + label + ' enabled. If recognition fails or is cancelled, use your Mindvora PIN/password.');
  }
  function registerBiometric(showUnavailable, passwordJustSaved, detected) {
    if (!passwordJustSaved && !hasPin()) { toast('Set a PIN/password first.'); setOrChangePin(true); return; }
    Promise.resolve(detected || detectBiometricAvailability()).then(function (result) {
      if (!result.available) {
        if (showUnavailable) toast((result.reason || 'No enrolled app-usable biometric is available.') + ' Your PIN/password will unlock the app.');
        showBiometricStatus();
        return;
      }
      if (result.native) {
        return result.plugin.authenticate(biometricAuthOptions()).then(function () { saveBiometricCredential(NATIVE_BIOMETRIC_CREDENTIAL, result.label); }).catch(function () { toast('Biometric setup was cancelled or did not match. Your Mindvora PIN/password remains available.'); });
      }
      var challenge = new Uint8Array(32); crypto.getRandomValues(challenge);
      var userId = new Uint8Array(16); crypto.getRandomValues(userId);
      return navigator.credentials.create({ publicKey: { challenge: challenge, rp: { name: 'Mindvora' }, user: { id: userId, name: 'mindvora-user', displayName: 'Mindvora user' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' }, timeout: 60000 } }).then(function (credential) {
        saveBiometricCredential(bytesToBase64(new Uint8Array(credential.rawId)), result.label);
      }).catch(function () { toast('Biometric setup was cancelled or unavailable. Your Mindvora PIN/password still unlocks the app.'); });
    }).catch(function () { toast('Biometric setup could not start. Your Mindvora PIN/password still unlocks the app.'); });
  }
  function setLockError(message) {
    var error = document.getElementById('mv-lock-error');
    if (error) error.textContent = message || '';
  }
  function unlockWithPin(pin) {
    pin = String(pin || '');
    if (!pin) { setLockError('Enter your PIN or password to unlock Mindvora.'); return Promise.resolve(false); }
    return hashPin(pin).then(function (hash) {
      if (hash === localStorage.getItem(PIN_KEY)) { appUnlocked = true; setLockError(''); return true; }
      setLockError('Incorrect PIN or password. Try again.');
      return false;
    });
  }
  function unlockWithBiometric() {
    if (!hasCredential()) return Promise.reject(new Error('Biometric unavailable'));
    var credential = localStorage.getItem(CRED_KEY);
    if (credential === NATIVE_BIOMETRIC_CREDENTIAL) {
      var plugin = nativeBiometricPlugin();
      if (!plugin || typeof plugin.checkBiometry !== 'function' || typeof plugin.authenticate !== 'function') return Promise.reject(new Error('Native biometric unavailable'));
      return plugin.checkBiometry().then(function (info) {
        if (!info || info.isAvailable !== true) throw new Error('Biometric is no longer available');
        return plugin.authenticate(biometricAuthOptions());
      }).then(function () { appUnlocked = true; return true; });
    }
    if (!navigator.credentials || !navigator.credentials.get) return Promise.reject(new Error('Platform authenticator unavailable'));
    var challenge = new Uint8Array(32); crypto.getRandomValues(challenge);
    return navigator.credentials.get({ publicKey: { challenge: challenge, allowCredentials: [{ type: 'public-key', id: base64ToBytes(credential) }], userVerification: 'required', timeout: 60000 } }).then(function () { appUnlocked = true; return true; });
  }
  function unlockApp(method) {
    if (!hasPin()) { setLockError('A PIN or password is required to unlock Mindvora.'); return Promise.resolve(false); }
    if (method === 'biometric') {
      return unlockWithBiometric().then(function (ok) { if (ok) finishAppUnlock(); return ok; }).catch(function () { setLockError('Biometric verification failed. Enter your PIN or password instead.'); return false; });
    }
    var input = lockOverlay && lockOverlay.querySelector('[data-lock-pin]');
    return unlockWithPin(input ? input.value : '').then(function (ok) { if (ok) finishAppUnlock(); return ok; });
  }
  function finishAppUnlock() { appUnlocked = true; lastActivityAt = Date.now(); hideAppLock(); scheduleAutoLock(); }
  function hideAppLock() {
    if (lockOverlay) { lockOverlay.remove(); lockOverlay = null; }
    document.body.classList.remove('mv-app-locked');
    var app = document.getElementById('app-screen');
    if (app) { app.removeAttribute('inert'); app.removeAttribute('aria-hidden'); }
  }
  function appIsVisible() {
    var app = document.getElementById('app-screen');
    var currentUser = false;
    try { currentUser = !!(window.state && state.user); } catch (e) {}
    try { currentUser = currentUser || !!(window.firebase && firebase.auth && firebase.auth().currentUser); } catch (e) {}
    return !!(app && app.style.display !== 'none' && currentUser);
  }
  function showStartupLock() {
    if (!prefs.appLock || !hasPin() || !appIsVisible() || appUnlocked || lockOverlay) return;
    var overlay = document.createElement('div'); overlay.id = 'mv-startup-lock'; overlay.className = 'mv-startup-lock';
    overlay.setAttribute('role', 'dialog'); overlay.setAttribute('aria-modal', 'true'); overlay.setAttribute('aria-label', 'Unlock Mindvora');
    overlay.innerHTML = '<div class="mv-startup-lock-card"><div class="mv-startup-lock-icon">🔒</div><h2>Mindvora is locked</h2><p>The app is locked. Your conversations and messages are unchanged.</p><label class="mv-lock-label" for="mv-lock-pin">PIN or password</label><input id="mv-lock-pin" data-lock-pin type="password" autocomplete="current-password" aria-label="PIN or password"><div id="mv-lock-error" role="alert" aria-live="polite"></div><button type="button" class="mv-settings-btn" data-unlock>Unlock Mindvora</button>' + (hasCredential() ? '<button type="button" class="mv-settings-btn" data-biometric>Use device biometric</button>' : '') + '<button type="button" class="mv-lock-signout" data-lock-signout>Sign out</button></div>';
    lockOverlay = overlay;
    document.body.classList.add('mv-app-locked');
    var app = document.getElementById('app-screen');
    if (app) { app.setAttribute('inert', ''); app.setAttribute('aria-hidden', 'true'); }
    document.body.appendChild(overlay);
    function attempt(method) {
      var button = overlay.querySelector(method === 'biometric' ? '[data-biometric]' : '[data-unlock]');
      if (button) button.disabled = true;
      unlockApp(method).then(function (ok) {
        if (!ok && button) { button.disabled = false; overlay.querySelector('[data-lock-pin]').focus(); }
      });
    }
    overlay.querySelector('[data-unlock]').addEventListener('click', function () { attempt('pin'); });
    var biometricButton = overlay.querySelector('[data-biometric]');
    if (biometricButton) biometricButton.addEventListener('click', function () { attempt('biometric'); });
    overlay.querySelector('[data-lock-pin]').addEventListener('keydown', function (event) { if (event.key === 'Enter') { event.preventDefault(); attempt('pin'); } });
    overlay.querySelector('[data-lock-signout]').addEventListener('click', function () {
      if (window.firebase && firebase.auth) firebase.auth().signOut().catch(function () { setLockError('Could not sign out. Please try again.'); });
    });
    overlay.addEventListener('keydown', function (event) { if (event.key === 'Escape') event.preventDefault(); });
    overlay.querySelector('[data-lock-pin]').focus();
  }
  function watchForStartupLock() {
    var timer = setInterval(function () { if (appIsVisible()) { clearInterval(timer); showStartupLock(); } }, 500);
    if (window.firebase && firebase.auth) firebase.auth().onAuthStateChanged(function (user) {
      if (!user) { appUnlocked = false; clearTimeout(autoLockTimer); autoLockTimer = null; hideAppLock(); return; }
      if (appIsVisible()) showStartupLock();
    });
    var app = document.getElementById('app-screen');
    if (app && window.MutationObserver) new MutationObserver(function () { if (appIsVisible()) showStartupLock(); }).observe(app, { attributes: true, attributeFilter: ['style', 'class'] });
  }
  function resetSettings() { if (!confirm('Reset App Lock and local Mindvora preferences on this device?')) return; localStorage.removeItem(STORAGE_KEY); localStorage.removeItem(PIN_KEY); localStorage.removeItem(CRED_KEY); prefs = Object.assign({}, defaults); appUnlocked = false; clearTimeout(autoLockTimer); autoLockTimer = null; hideAppLock(); applyPrefs(); renderSettings(); toast('Settings reset.'); }
  window.MVSettings = { get: getPref, set: setPreference, lock: lockApp, unlock: unlockApp, apply: applyPrefs };

  ['click', 'keydown', 'touchstart', 'scroll'].forEach(function (eventName) { document.addEventListener(eventName, recordActivity, { passive: true, capture: true }); });
  document.addEventListener('visibilitychange', function () {
    if (!prefs.appLock) return;
    if (document.hidden) { if (prefs.autoLock === 'immediate') lockApp(true); return; }
    if (!appUnlocked) { showStartupLock(); return; }
    var ms = autoLockMs();
    if (ms > 0 && Date.now() - lastActivityAt >= ms) lockApp(true);
    else scheduleAutoLock();
  });
  window.addEventListener('blur', function () { if (prefs.appLock && prefs.autoLock === 'immediate') lockApp(true); });
  window.addEventListener('pagehide', function () { if (prefs.appLock) lockApp(false); });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', installPreferenceHooks); else installPreferenceHooks();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', watchForStartupLock); else watchForStartupLock();
}());
