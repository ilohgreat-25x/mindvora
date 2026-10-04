// Mindvora — ARIA chat UI: streamed answers over the app's single WebSocket (HTTP fallback),
// safe Markdown rendering (code blocks with Copy, lists, tables, checklists) and truthful errors.
// Loaded after script.js; script.js's ariaSend() hands the network part to MVAria.ask().
(function () {
  'use strict';
  if (window.MVAria) return;

  // ── safe Markdown → HTML (everything is escaped first; only our own tags are added) ──
  function esc(t) { return String(t == null ? '' : t).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function inline(raw) {
    var codes = [];
    var s = esc(raw).replace(/`([^`\n]+)`/g, function (m, c) { codes.push(c); return '\u0000' + (codes.length - 1) + '\u0000'; });
    s = s.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
         .replace(/__([^_\n]+)__/g, '<strong>$1</strong>')
         .replace(/(^|[^*\w])\*([^*\n]+)\*(?![*\w])/g, '$1<em>$2</em>')
         .replace(/~~([^~\n]+)~~/g, '<del>$1</del>')
         .replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)"'<>]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
    return s.replace(/\u0000(\d+)\u0000/g, function (m, i) { return '<code class="ar-ic">' + codes[+i] + '</code>'; });
  }
  function codeBlock(lang, body) {
    return '<div class="ar-code"><div class="ar-code-h"><span>' + esc(lang || 'code') + '</span>' +
      '<button type="button" class="ar-copy">Copy</button></div><pre><code>' + esc(body) + '</code></pre></div>';
  }
  function render(md) {
    var lines = String(md || '').replace(/\r/g, '').split('\n');
    var out = [], i = 0, para = [];
    function flush() { if (para.length) { out.push('<p>' + para.map(inline).join('<br>') + '</p>'); para = []; } }
    while (i < lines.length) {
      var ln = lines[i], m;
      if ((m = ln.match(/^\s*```\s*([\w+#.-]*)\s*$/))) {            // fenced code (may be unfinished while streaming)
        flush(); var lang = m[1], body = []; i++;
        while (i < lines.length && !/^\s*```\s*$/.test(lines[i])) { body.push(lines[i]); i++; }
        i++; out.push(codeBlock(lang, body.join('\n'))); continue;
      }
      if ((m = ln.match(/^(#{1,6})\s+(.*)$/))) { flush(); var lv = Math.min(m[1].length + 2, 6); out.push('<h' + lv + ' class="ar-h">' + inline(m[2]) + '</h' + lv + '>'); i++; continue; }
      if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(ln)) { flush(); out.push('<hr>'); i++; continue; }
      if (/^\s*\|.*\|\s*$/.test(ln) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])) {   // table
        flush();
        var cells = function (r) { return r.trim().replace(/^\||\|$/g, '').split('|').map(function (c) { return c.trim(); }); };
        var head = cells(ln); i += 2; var rows = [];
        while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) { rows.push(cells(lines[i])); i++; }
        out.push('<div class="ar-tw"><table><thead><tr>' + head.map(function (c) { return '<th>' + inline(c) + '</th>'; }).join('') + '</tr></thead><tbody>' +
          rows.map(function (r) { return '<tr>' + r.map(function (c) { return '<td>' + inline(c) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div>');
        continue;
      }
      if (/^\s*([-*+]|\d+[.)])\s+/.test(ln)) {                         // lists (incl. checklists)
        flush(); var ordered = /^\s*\d/.test(ln), items = [];
        while (i < lines.length && /^\s*([-*+]|\d+[.)])\s+/.test(lines[i]) && (/^\s{2,}/.test(lines[i]) || /^\s*\d/.test(lines[i]) === ordered)) {
          var t = lines[i].replace(/^\s*([-*+]|\d+[.)])\s+/, ''), ind = /^\s{2,}/.test(lines[i]);
          var cb = t.match(/^\[([ xX])\]\s+(.*)$/);
          items.push('<li' + (ind ? ' class="ar-sub"' : '') + '>' + (cb ? '<span class="ar-cb">' + (cb[1] === ' ' ? '☐' : '☑') + '</span> ' + inline(cb[2]) : inline(t)) + '</li>');
          i++;
        }
        out.push(ordered ? '<ol>' + items.join('') + '</ol>' : '<ul>' + items.join('') + '</ul>'); continue;
      }
      if (/^\s*>\s?/.test(ln)) { flush(); var q = []; while (i < lines.length && /^\s*>\s?/.test(lines[i])) { q.push(lines[i].replace(/^\s*>\s?/, '')); i++; } out.push('<blockquote>' + q.map(inline).join('<br>') + '</blockquote>'); continue; }
      if (!ln.trim()) { flush(); i++; continue; }
      para.push(ln); i++;
    }
    flush();
    var html = out.join('');
    if (window.DOMPurify && DOMPurify.sanitize) html = DOMPurify.sanitize(html, { ADD_ATTR: ['target'] });
    return html;
  }

  // ── styles (scoped to Aria bubbles) ──
  var css = '.ar-md p{margin:0 0 8px}.ar-md p:last-child{margin-bottom:0}.ar-md .ar-h{margin:10px 0 6px;font-size:13px;font-weight:700}' +
    '.ar-md ul,.ar-md ol{margin:4px 0 8px;padding-left:18px}.ar-md li{margin:2px 0}.ar-md li.ar-sub{margin-left:14px}' +
    '.ar-md .ar-ic{background:rgba(127,127,127,.18);padding:1px 4px;border-radius:4px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px}' +
    '.ar-code{margin:8px 0;border:1px solid var(--border,#333);border-radius:8px;overflow:hidden;background:#0d1117}' +
    '.ar-code-h{display:flex;justify-content:space-between;align-items:center;padding:4px 8px;background:#161b22;color:#8b949e;font-size:10px;text-transform:lowercase}' +
    '.ar-code pre{margin:0;padding:8px 10px;overflow-x:auto;max-height:420px}.ar-code code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;line-height:1.5;color:#e6edf3;white-space:pre}' +
    '.ar-copy,.ar-act{background:none;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;font-size:10px;padding:2px 8px;cursor:pointer}' +
    '.ar-acts{display:flex;gap:6px;margin-top:8px;flex-wrap:wrap}.ar-acts .ar-act{border-color:var(--border,#444);color:var(--muted,#aaa)}' +
    '.ar-tw{overflow-x:auto;margin:6px 0}.ar-md table{border-collapse:collapse;font-size:11px}.ar-md th,.ar-md td{border:1px solid var(--border,#444);padding:4px 6px;text-align:left;vertical-align:top}' +
    '.ar-md blockquote{margin:6px 0;padding-left:8px;border-left:3px solid var(--green,#3a7);opacity:.9}.ar-md hr{border:0;border-top:1px solid var(--border,#444);margin:8px 0}' +
    '.ar-md a{color:var(--green,#4c9);text-decoration:underline}.ar-note{font-size:10px;opacity:.7;margin-top:6px}.ar-err{color:#f0a0a0}' +
    '.ar-cursor::after{content:"▍";animation:arb 1s steps(1) infinite;opacity:.7}@keyframes arb{50%{opacity:0}}';
  var st = document.createElement('style'); st.textContent = css; document.head.appendChild(st);

  // ── helpers ──
  function $(id) { return document.getElementById(id); }
  function copyText(t, btn) {
    function done() { if (btn) { var o = btn.textContent; btn.textContent = 'Copied ✓'; setTimeout(function () { btn.textContent = o; }, 1500); } }
    if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(t).then(done, function () { legacy(); }); } else legacy();
    function legacy() { var ta = document.createElement('textarea'); ta.value = t; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); done(); } catch (e) {} ta.remove(); }
  }
  function nearBottom(el) { return el.scrollHeight - el.scrollTop - el.clientHeight < 120; }
  function newBubble() {
    var msgs = $('aria-msgs'); var div = document.createElement('div'); div.className = 'aria-msg';
    div.innerHTML = '<div class="aria-av">🤖</div><div class="aria-bub ar-md"></div>';
    msgs.appendChild(div); msgs.scrollTop = msgs.scrollHeight; return div.querySelector('.aria-bub');
  }
  function addActions(bub, text) {
    var a = document.createElement('div'); a.className = 'ar-acts';
    a.innerHTML = '<button type="button" class="ar-act" data-a="copy">Copy answer</button><button type="button" class="ar-act" data-a="dl">Download .md</button>';
    a._text = text; bub.appendChild(a);
  }
  // one delegated listener for all Copy / Download / Try again buttons
  document.addEventListener('click', function (e) {
    var b = e.target && e.target.closest ? e.target.closest('.ar-copy,.ar-act') : null; if (!b) return;
    if (b.classList.contains('ar-copy')) { var c = b.closest('.ar-code').querySelector('code'); copyText(c.textContent, b); return; }
    var a = b.getAttribute('data-a'), box = b.parentNode;
    if (a === 'copy') copyText(box._text || '', b);
    else if (a === 'dl') {
      var blob = new Blob([box._text || ''], { type: 'text/markdown' }); var u = URL.createObjectURL(blob);
      var l = document.createElement('a'); l.href = u; l.download = 'aria-' + new Date().toISOString().slice(0, 10) + '.md'; document.body.appendChild(l); l.click(); l.remove();
      setTimeout(function () { URL.revokeObjectURL(u); }, 2000);
    } else if (a === 'retry') { var inp = $('aria-inp'); if (inp) { inp.value = box._q || ''; var s = $('aria-send'); if (s) s.click(); } }
  });
  function showError(msg, q) {
    if (typeof ariaRemoveTyping === 'function') ariaRemoveTyping();
    var bub = newBubble(); bub.innerHTML = '<span class="ar-err">' + esc(msg) + '</span>';
    if (q) { var a = document.createElement('div'); a.className = 'ar-acts'; a.innerHTML = '<button type="button" class="ar-act" data-a="retry">Try again</button>'; a._q = q; bub.appendChild(a); }
  }

  // ── streaming over the app's single WebSocket ──
  var pending = null;   // { reqId, ... } only one Aria request at a time
  document.addEventListener('mv:aria', function (ev) { if (pending) pending.on(ev.detail); });
  function wsReady() {
    return !!(window.MVRealtime && MVRealtime.live && MVRealtime.live() && typeof auth !== 'undefined' && auth.currentUser && window.MindvoraRT);
  }
  function askWs(history) {
    return new Promise(function (resolve) {
      var reqId = 'a' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
      var text = '', bub = null, started = false, lastRender = 0, renderT = null, finished = false;
      var msgs = $('aria-msgs');
      function paint(final) {
        renderT = null; lastRender = Date.now(); if (!bub) return;
        var stick = nearBottom(msgs);
        bub.innerHTML = render(text); bub.classList.toggle('ar-cursor', !final);
        if (stick) msgs.scrollTop = msgs.scrollHeight;
      }
      function finish(res) {
        if (finished) return; finished = true; pending = null;
        clearTimeout(startT); clearTimeout(totalT); clearInterval(watch); clearTimeout(renderT);
        resolve(res);
      }
      var startT = setTimeout(function () { if (!started) { try { MindvoraRT.send({ type: 'RT_ARIA_CANCEL', reqId: reqId }); } catch (e) {} finish({ fallback: true }); } }, 8000);
      var totalT = setTimeout(function () { try { MindvoraRT.send({ type: 'RT_ARIA_CANCEL', reqId: reqId }); } catch (e) {} done(text ? { truncated: false, cut: true } : null, 'Aria took too long to answer. Please try again.'); }, 135000);
      var watch = setInterval(function () {                   // the socket dropped mid-answer
        if (!(MVRealtime.live && MVRealtime.live())) { if (!started) finish({ fallback: true }); else done(text ? { cut: true } : null, 'The connection dropped before Aria could answer. Please try again.'); }
      }, 3000);
      function done(meta, errMsg) {
        if (text && meta) {
          paint(true);
          if (meta.cut) bub.insertAdjacentHTML('beforeend', '<div class="ar-note">(The connection was interrupted — this answer may be incomplete.)</div>');
          else if (meta.truncated) bub.insertAdjacentHTML('beforeend', '<div class="ar-note">(This answer reached the length limit — say "continue" for the rest.)</div>');
          addActions(bub, text);
          finish({ text: text });
        } else {
          if (bub) bub.parentNode.remove();
          finish({ error: errMsg || 'Aria could not answer just now. Please try again.' });
        }
      }
      pending = {
        reqId: reqId,
        on: function (m) {
          if (m.type === 'RT_ERROR' && !started && m.code === 'NOT_AUTHED') { finish({ fallback: true }); return; }
          if (m.reqId !== reqId) return;
          if (m.type === 'RT_ARIA_START') { started = true; return; }
          if (m.type === 'RT_ARIA_CHUNK') {
            started = true;
            if (!bub) { if (typeof ariaRemoveTyping === 'function') ariaRemoveTyping(); bub = newBubble(); }
            text += m.delta || '';
            if (!renderT) renderT = setTimeout(paint, Math.max(0, 120 - (Date.now() - lastRender)));
            return;
          }
          if (m.type === 'RT_ARIA_RESET') { text = ''; if (bub) bub.innerHTML = ''; return; }
          if (m.type === 'RT_ARIA_DONE') { done({ truncated: !!m.truncated }); return; }
          if (m.type === 'RT_ARIA_ERROR') { done(null, m.message); return; }
        },
      };
      MindvoraRT.send({ type: 'RT_ARIA', reqId: reqId, messages: history });
    });
  }

  // ── HTTP fallback (logged-out users, or socket not available) ──
  function askHttp(history) {
    if (!window.BACKEND_URL) return Promise.resolve({ offline: true });
    var u = (typeof auth !== 'undefined' && auth.currentUser) ? auth.currentUser : null;
    return (u ? u.getIdToken() : Promise.resolve(null)).then(function (tok) {
      var ctrl = new AbortController(); var t = setTimeout(function () { ctrl.abort(); }, 125000);
      var h = { 'Content-Type': 'application/json' }; if (tok) h.Authorization = 'Bearer ' + tok;
      return fetch(window.BACKEND_URL + '/api/aria/chat', { method: 'POST', headers: h, body: JSON.stringify({ messages: history }), signal: ctrl.signal })
        .then(function (r) {
          return r.json().catch(function () { return { status: false, message: r.status >= 500 ? 'The Mindvora server is waking up — please try again in a few seconds.' : 'Unexpected server response.' }; })
            .then(function (d) { clearTimeout(t); d._http = r.status; return d; });
        }, function (e) { clearTimeout(t); throw e; });
    }).then(function (d) {
      if (d && d.status && d.reply) {
        if (typeof ariaRemoveTyping === 'function') ariaRemoveTyping();
        var bub = newBubble(); bub.innerHTML = render(d.reply);
        if (d.truncated) bub.insertAdjacentHTML('beforeend', '<div class="ar-note">(This answer reached the length limit — say "continue" for the rest.)</div>');
        addActions(bub, d.reply); var msgs = $('aria-msgs'); msgs.scrollTop = msgs.scrollHeight;
        return { text: d.reply };
      }
      if (d && d.message) return { error: d.message };
      return { error: 'Aria could not answer just now. Please try again.' };
    }, function (e) {
      return (e && e.name === 'AbortError') ? { error: 'Aria took too long to answer. Please try again.' } : { offline: true };
    });
  }

  // Ask Aria. Resolves { text } on success, or { error } after the error is already shown in the chat.
  function ask(history, question) {
    var p = wsReady() ? askWs(history).then(function (r) { return r.fallback ? askHttp(history) : r; }) : askHttp(history);
    return p.then(function (r) {
      if (r.text) return r;
      if (r.offline) {
        // No connection at all: answer Mindvora questions from the built-in guide, and say so honestly.
        var local = (typeof ariaGetResponse === 'function') ? ariaGetResponse(question || '') : '';
        var generic = /Could you be more specific|Try asking about Mindvora|Could you rephrase that/.test(local);
        if (local && !generic && /mindvora|spark|stor|reel|premium|verif|badge|earn|withdraw|referr|tip|gift|airtime|wallet|follow|post|profile|password|account|notif|call|message|chat|group|live|boost|paystack/i.test(question || '')) {
          if (typeof ariaRemoveTyping === 'function') ariaRemoveTyping();
          var bub = newBubble(); bub.innerHTML = render(local) + '<div class="ar-note">(You seem to be offline — this answer is from Aria\'s built-in Mindvora guide.)</div>';
          return { text: local };
        }
        showError("I can't reach the Mindvora server — please check your internet connection and try again.", question);
        return { error: 'offline' };
      }
      showError(r.error, question);
      return r;
    });
  }

  var sending = false;
  async function sendNew() {
    if (sending) return;
    var inp = $('aria-inp'); if (!inp) return;
    var text = inp.value.trim(), img = window.ariaPendingImage;
    if (!text && !img) return;
    inp.value = '';
    window.ariaAddMsg('user', img ? '🖼️ ' + (text || 'What do you see in this image?') : text);
    var content = text;
    if (img) {
      // Images are not sent to the AI yet — tell the model so it answers honestly instead of pretending to see it.
      content = (text || 'What do you see in this image?') + '\n\n(The user attached an image, but you cannot see images in this chat yet. Say so briefly, then help with any text question.)';
      window.ariaPendingImage = null;
      var pv = $('aria-img-preview'); if (pv) pv.style.display = 'none';
      var pi = $('aria-preview-img'); if (pi) pi.src = '';
      var ib = $('aria-img-btn'); if (ib) { ib.style.borderColor = ''; ib.style.color = ''; }
    }
    var H = Array.isArray(window.ariaHistory) ? window.ariaHistory : (window.ariaHistory = []);
    H.push({ role: 'user', content: content });
    if (typeof ariaTyping === 'function') ariaTyping();
    sending = true; var sb = $('aria-send'); if (sb) sb.disabled = true;
    try {
      var res = await ask(H.slice(-20), text);
      if (res && res.text) H.push({ role: 'assistant', content: res.text });
      else H.pop();                       // unanswered: drop it so "Try again" doesn't send it twice
      if (H.length > 20) window.ariaHistory = H.slice(-20);
    } catch (e) {
      H.pop(); showError('Sorry, something went wrong on my side. Please try again.', text);
    }
    sending = false; if (sb) sb.disabled = false;
  }
  function install() {
    var btn = $('aria-send');
    if (!btn || typeof window.ariaAddMsg !== 'function') return false;
    if (btn._mvAria) return true;
    var fresh = btn.cloneNode(true); fresh._mvAria = true;   // clone drops script.js's old click handler
    btn.parentNode.replaceChild(fresh, btn);
    fresh.addEventListener('click', sendNew);
    window.ariaSend = sendNew;                                // the Enter key handler calls ariaSend() by name
    var origAdd = window.ariaAddMsg;
    window.ariaAddMsg = function (role, text) {
      if (role === 'user') return origAdd(role, text);
      if (/^Hey! I'm ARIA, your Mindvora AI assistant/.test(String(text))) text = "Hey! I'm ARIA, your Mindvora AI assistant 🌿 Ask me anything — Mindvora help, general questions, writing, planning events or projects, or writing and debugging code. What's on your mind?";
      var b = newBubble(); b.innerHTML = render(text);
    };
    window.MVAria.installed = true;
    return true;
  }
  window.MVAria = { ask: ask, render: render, send: sendNew };
  if (!install()) { var tries = 0, iv = setInterval(function () { if (install() || ++tries > 40) clearInterval(iv); }, 250); }
})();
