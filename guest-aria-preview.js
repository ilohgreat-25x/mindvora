(function () {
  'use strict';

  var used = false;
  var sending = false;
  function byId(id) { return document.getElementById(id); }
  function open() {
    var modal = byId('modal-guest-aria');
    if (modal) modal.classList.add('open');
    var input = byId('guest-aria-inp');
    if (input) input.focus();
  }
  function close() {
    var modal = byId('modal-guest-aria');
    if (modal) modal.classList.remove('open');
  }
  function message(text, kind) {
    var box = byId('guest-aria-response');
    if (!box) return;
    box.textContent = text;
    box.className = 'guest-aria-response' + (kind ? ' ' + kind : '');
    box.style.display = text ? 'block' : 'none';
  }
  function ask() {
    if (sending || used) return;
    var input = byId('guest-aria-inp'), button = byId('guest-aria-send');
    var question = input ? input.value.trim() : '';
    if (!question) { message('Enter a question first.', 'error'); return; }
    if (question.length > 800) { message('Please keep your question under 800 characters.', 'error'); return; }
    if (!window.BACKEND_URL) { message('ARIA is unavailable right now. Please try again later.', 'error'); return; }

    sending = true;
    if (button) { button.disabled = true; button.textContent = 'Asking ARIA…'; }
    message('ARIA is preparing a reply…', 'pending');
    fetch(window.BACKEND_URL + '/api/aria/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: [{ role: 'user', content: question }] })
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        if (!response.ok || !data || !data.status || !data.reply) {
          throw new Error(data && data.message ? data.message : 'ARIA could not reply just now. Please try again later.');
        }
        return String(data.reply);
      });
    }).then(function (reply) {
      used = true;
      if (input) input.disabled = true;
      message(reply, 'answer');
      var note = byId('guest-aria-limit-note');
      if (note) note.textContent = 'That was your one-question preview. Join Mindvora to continue using ARIA in the app.';
    }).catch(function (error) {
      message(error && error.message ? error.message : 'ARIA could not reply just now. Please try again later.', 'error');
    }).finally(function () {
      sending = false;
      if (button) { button.textContent = used ? 'Preview used' : 'Ask ARIA'; button.disabled = used; }
    });
  }
  function join() {
    close();
    if (typeof window.showAuthTab === 'function') window.showAuthTab('reg');
    var screen = byId('auth-screen');
    if (screen) screen.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  window.openGuestAriaPreview = open;
  window.closeGuestAriaPreview = close;
  function bind() {
    var send = byId('guest-aria-send'), input = byId('guest-aria-inp'), joinButton = byId('guest-aria-join'), modal = byId('modal-guest-aria');
    if (send) send.addEventListener('click', ask);
    if (input) input.addEventListener('keydown', function (event) { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); ask(); } });
    if (joinButton) joinButton.addEventListener('click', join);
    if (modal) modal.addEventListener('click', function (event) { if (event.target === modal) close(); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind, { once: true });
  else bind();
})();
