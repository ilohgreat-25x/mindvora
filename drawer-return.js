/* Return to the slide-out menu after closing a feature launched from it. */
(function () {
  'use strict';

  var SURFACE_SELECTOR = [
    '.modal-overlay', '[id^="modal-"]', '[role="dialog"]', '[aria-modal="true"]', 'dialog[open]',
    '[class*="overlay"]', '[class*="modal"]', '[class*="viewer"]', '[class*="hub"]',
    '.game-container', '#game-container', '#live-host-view', '#live-watch-view',
    '#mv-sports', '#mv-news-live', '#mv-install-guide', '#mv-evolve', '#mv-learn',
    '.mv-evolve-shell', '.mv-learn-shell'
  ].join(',');
  var current = null;

  function isDrawerSurface(el) {
    return !!(el && el.closest && el.closest('#app-drawer, #drawer-overlay'));
  }

  function isCandidate(el) {
    return !!(el && el.nodeType === 1 && el.matches && el.matches(SURFACE_SELECTOR));
  }

  function isVisibleSurface(el) {
    if (!el || !el.isConnected || el.hidden || isDrawerSurface(el)) return false;
    for (var node = el; node && node !== document.documentElement; node = node.parentElement) {
      var parentStyle = window.getComputedStyle(node);
      if (parentStyle.display === 'none' || parentStyle.visibility === 'hidden') return false;
    }
    var style = window.getComputedStyle(el);
    if (el.matches('dialog[open]') || (el.classList && el.classList.contains('open'))) return true;
    if (Number(style.opacity) <= 0.01) return false;
    var zIndex = parseInt(style.zIndex, 10);
    return style.position === 'fixed' || (isFinite(zIndex) && zIndex >= 100) ||
      el.getAttribute('role') === 'dialog' || el.getAttribute('aria-modal') === 'true';
  }

  function openSurfaces() {
    var matches = Array.prototype.slice.call(document.querySelectorAll(SURFACE_SELECTOR))
      .filter(isVisibleSurface);
    return matches.filter(function (el) {
      return !matches.some(function (other) { return other !== el && other.contains(el); });
    });
  }

  function clearCurrent() {
    if (!current) return;
    if (current.timer) window.clearInterval(current.timer);
    if (current.observer) current.observer.disconnect();
    current = null;
  }

  function reopenDrawer(record) {
    if (current !== record) return;
    clearCurrent();
    var drawer = document.getElementById('app-drawer');
    if (!drawer || drawer.classList.contains('open') || typeof window.toggleDrawer !== 'function') return;
    window.toggleDrawer();
    var body = drawer.querySelector('.drawer-body');
    if (body) {
      var top = record.scrollTop;
      window.requestAnimationFrame(function () { body.scrollTop = top; });
    }
  }

  function checkForClose(record) {
    if (current !== record || !record.surface || isVisibleSurface(record.surface)) return;
    var alternatives = openSurfaces().filter(function (el) { return el !== record.surface; });
    if (alternatives.length) {
      record.surface = alternatives[0];
      return;
    }
    reopenDrawer(record);
  }

  function isRelevantMutation(record, state) {
    var target = record.target;
    if (state.surface && target && target.nodeType === 1 &&
        (target === state.surface || target.contains(state.surface) || state.surface.contains(target))) return true;
    if (record.type === 'attributes') return isCandidate(target);
    var changedNodes = Array.prototype.slice.call(record.addedNodes || []).concat(
      Array.prototype.slice.call(record.removedNodes || []));
    return changedNodes.some(function (node) {
      return node.nodeType === 1 && (isCandidate(node) ||
        (node.querySelector && !!node.querySelector(SURFACE_SELECTOR)));
    });
  }

  function watchForClose(record) {
    if (record.observer) record.observer.disconnect();
    record.observer = new MutationObserver(function (mutations) {
      if (mutations.some(function (mutation) { return isRelevantMutation(mutation, record); })) {
        checkForClose(record);
      }
    });
    record.observer.observe(document.body, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ['class', 'style', 'hidden', 'aria-hidden']
    });
  }

  function isSectionNavigation(item) {
    var label = (item.textContent || '').replace(/\s+/g, ' ').trim().toLowerCase();
    if (label === 'feed' || label === 'discover' || label === 'saved' || label === 'trending' ||
        label === 'sign out' || label === 'delete account' || /^referral\s*:/.test(label)) return true;
    var action = (item.getAttribute('onclick') || '').replace(/\s+/g, '');
    return /getElementById\('nav-(feed|disc|saved)'\)\.click\(\)/.test(action);
  }

  document.addEventListener('click', function (event) {
    var item = event.target && event.target.closest && event.target.closest('#app-drawer .drawer-item');
    if (!item || isSectionNavigation(item)) return;

    clearCurrent();
    var record = {
      before: new Set(openSurfaces()),
      surface: null,
      scrollTop: (document.querySelector('#app-drawer .drawer-body') || {}).scrollTop || 0,
      timer: null,
      observer: null,
      deadline: Date.now() + 3500
    };
    current = record;
    record.timer = window.setInterval(function () {
      if (current !== record) { window.clearInterval(record.timer); return; }
      var next = openSurfaces().filter(function (el) { return !record.before.has(el); });
      if (next.length) {
        record.surface = next[0];
        window.clearInterval(record.timer);
        record.timer = null;
        watchForClose(record);
      } else if (Date.now() >= record.deadline) {
        clearCurrent();
      }
    }, 75);
  }, true);
})();
