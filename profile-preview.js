(function () {
  'use strict';

  function installProfilePreview() {
    var modal = document.getElementById('modal-edit-profile');
    if (!modal || modal.dataset.profilePreviewInstalled === 'true') return;

    var nameInput = document.getElementById('ep-name');
    var handleInput = document.getElementById('ep-handle');
    var bioInput = document.getElementById('ep-bio');
    var websiteInput = document.getElementById('ep-website');
    if (!nameInput || !handleInput || !bioInput || !websiteInput) return;

    modal.dataset.profilePreviewInstalled = 'true';

    var preview = document.createElement('section');
    preview.setAttribute('aria-label', 'Profile preview');
    preview.setAttribute('aria-live', 'polite');
    preview.style.cssText = 'margin:16px 0;padding:14px;border:1px solid var(--border);border-radius:12px;background:var(--card);color:var(--white);';

    var badge = document.createElement('div');
    badge.textContent = 'PREVIEW · Not saved';
    badge.style.cssText = 'font-size:11px;font-weight:700;letter-spacing:.08em;opacity:.7;margin-bottom:10px;';

    var name = document.createElement('div');
    name.style.cssText = 'font-size:18px;font-weight:700;overflow-wrap:anywhere;';
    var handle = document.createElement('div');
    handle.style.cssText = 'font-size:13px;opacity:.7;overflow-wrap:anywhere;';
    var bio = document.createElement('p');
    bio.style.cssText = 'font-size:14px;white-space:pre-wrap;overflow-wrap:anywhere;margin:10px 0;';
    var website = document.createElement('div');
    website.style.cssText = 'font-size:13px;opacity:.8;overflow-wrap:anywhere;';

    preview.append(badge, name, handle, bio, website);
    var saveButton = document.getElementById('ep-save-btn');
    if (saveButton && saveButton.parentNode) {
      saveButton.parentNode.insertBefore(preview, saveButton);
    } else {
      modal.appendChild(preview);
    }

    function refresh() {
      var displayName = nameInput.value.trim();
      var displayHandle = handleInput.value.trim();
      var displayBio = bioInput.value.trim();
      var displayWebsite = websiteInput.value.trim();
      name.textContent = displayName || 'Your name';
      handle.textContent = displayHandle ? (displayHandle.charAt(0) === '@' ? displayHandle : '@' + displayHandle) : '@username';
      bio.textContent = displayBio || 'Your bio will appear here.';
      website.textContent = displayWebsite || 'Your website will appear here.';
    }

    [nameInput, handleInput, bioInput, websiteInput].forEach(function (input) {
      input.addEventListener('input', refresh);
      input.addEventListener('change', refresh);
    });

    // openEditProfile() opens the modal and then populates field values in the same task.
    // Defer the refresh until those values have been assigned.
    function scheduleRefresh() {
      window.setTimeout(refresh, 0);
    }
    var observer = new MutationObserver(function (records) {
      if (records.some(function (record) {
        return record.attributeName === 'class' || record.attributeName === 'style' || record.attributeName === 'aria-hidden';
      })) scheduleRefresh();
    });
    observer.observe(modal, { attributes: true, attributeFilter: ['class', 'style', 'aria-hidden'] });

    // Delegation also covers future modal open controls without coupling to save/auth code.
    document.addEventListener('click', function (event) {
      var opener = event.target.closest('[onclick*="modal-edit-profile"], [onclick*="openEditProfile"]');
      if (opener) scheduleRefresh();
    });
    refresh();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', installProfilePreview, { once: true });
  } else {
    installProfilePreview();
  }
})();
