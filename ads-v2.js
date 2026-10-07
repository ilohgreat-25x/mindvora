/* MINDVORA — Advertise, now run by the server (Oct 7).
 * Free ads: submit → auto-moderation → live. Paid ads: saved first, then Paystack; they serve only after the
 * server confirms the payment, and stop at exactly the purchased unique views. Harmful ads are auto-rejected
 * and auto-refunded. The owner sees every ad event live in the admin panel (existing WebSocket). */
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }
  function toast(t) { if (typeof showToast === 'function') showToast(t); }
  function val(id) { var e = $(id); return e ? e.value.trim() : ''; }
  function rebind(id, fn) { var o = $(id); if (!o) return false; var n = o.cloneNode(true); o.parentNode.replaceChild(n, o); n.addEventListener('click', fn); return true; }
  function fields(p) { return { title: val(p + '-ad-title'), description: val(p + '-ad-desc'), cta: val(p + '-ad-cta'), url: val(p + '-ad-url'), emoji: val(p + '-ad-emoji') }; }
  function clear(p) { ['title', 'desc', 'cta', 'url', 'emoji'].forEach(function (k) { var e = $(p + '-ad-' + k); if (e) e.value = ''; }); }
  function check(f, err) {
    if (!f.title) { err.textContent = 'Enter ad title'; return false; }
    if (!f.description) { err.textContent = 'Enter ad description'; return false; }
    if (!f.cta) { err.textContent = 'Enter call to action text'; return false; }
    if (f.url && !/^https:\/\//i.test(f.url)) { err.textContent = 'Use a valid https:// link.'; return false; }
    return true;
  }

  function bindForms() {
    var ok1 = rebind('btn-submit-free', function () {
      var btn = this, err = $('free-ad-err'), f = fields('free'); err.textContent = '';
      if (!state.user) { toast('Login first'); return; }
      if (!check(f, err)) return;
      btn.disabled = true; btn.textContent = 'Checking your ad…';
      mvApi('/api/ads/free', f).then(function (d) {
        btn.disabled = false; btn.textContent = '🆓 Submit Free Ad →';
        if (d && d.ok) { clear('free'); toast('✅ Your free ad is live!'); closeModal('modal-ads'); loadAds(); }
        else err.textContent = (d && d.message) || 'Could not submit the ad.';
      }).catch(function () { btn.disabled = false; btn.textContent = '🆓 Submit Free Ad →'; err.textContent = 'Network error. Try again.'; });
    });
    var ok2 = rebind('btn-submit-paid', function () {
      var btn = this, err = $('paid-ad-err'), f = fields('paid'); err.textContent = '';
      if (!state.user) { toast('Login first'); return; }
      if (!check(f, err)) return;
      f.budget = adState.budget;
      btn.disabled = true; var label = btn.textContent; btn.textContent = 'Checking your ad…';
      mvApi('/api/ads/paid/draft', f).then(function (d) {
        btn.disabled = false; btn.textContent = label;
        if (!d || !d.ok) { err.textContent = (d && d.message) || 'Could not create the ad.'; return; }
        payWithPaystack({
          amount: usdToNGNKobo(d.budget), currency: 'NGN', ref: 'ZAD-' + Date.now(),
          purpose: 'ad', params: { adId: d.adId, budget: d.budget },
          onSuccess: function (r) {
            toast('Confirming your payment…');
            mvApi('/api/pay/paystack/verify', { reference: r.reference }).then(function (v) {
              var res = (v && (v.result || v)) || {};
              if (res.status === 'active') { clear('paid'); toast('🚀 Paid! Your ad is live for ' + d.views.toLocaleString() + ' views.'); closeModal('modal-ads'); loadAds(); }
              else if (res.status === 'rejected') toast('⛔ Ad rejected (' + res.reason + '). Your payment is being refunded.');
              else toast((v && v.message) || 'Payment received — your ad will go live shortly.');
            }).catch(function () { toast('Payment received — your ad will go live once it is confirmed.'); });
          },
          onClose: function () { toast('Ad payment cancelled'); }
        });
      }).catch(function () { btn.disabled = false; btn.textContent = label; err.textContent = 'Network error. Try again.'; });
    });
    return ok1 && ok2;
  }
  (function b() { if (!bindForms()) setTimeout(b, 1000); })();

  // Real, unique impressions counted by the server; the ad disappears when its views are used up.
  var sent = {};
  function impression(id) {
    if (!id || sent[id] || !state.user) return; sent[id] = 1;
    mvApi('/api/ads/impression', { adId: id }).then(function (d) {
      if (d && d.stop && window.adState) adState.currentAds = adState.currentAds.filter(function (a) { return a.id !== id; });
    }).catch(function () { delete sent[id]; });
  }
  var io = 'IntersectionObserver' in window ? new IntersectionObserver(function (es) {
    es.forEach(function (e) { if (e.isIntersecting && e.intersectionRatio >= 0.5) { var b = e.target.querySelector('[data-ad-id]'); if (b) impression(b.dataset.adId); io.unobserve(e.target); } });
  }, { threshold: [0.5] }) : null;
  new MutationObserver(function () {
    document.querySelectorAll('.ad-banner:not([data-mv-seen])').forEach(function (el) { el.setAttribute('data-mv-seen', '1'); if (io) io.observe(el); });
  }).observe(document.body, { childList: true, subtree: true });
  var baseVideoAd = window.showVideoAd;
  if (baseVideoAd) window.showVideoAd = function (ad, cb) { impression(ad && ad.id); return baseVideoAd.apply(this, arguments); };
  window.trackAdClick = function (adId, url) {
    mvApi('/api/ads/click', { adId: adId }).catch(function () {});
    if (url && url !== '#' && /^https:\/\//i.test(url)) window.open(url, '_blank', 'noopener');
  };
  // Only show ads that are live (paid ads stop being served once they finish).
  window.loadAds = function () {
    db.collection('ads').where('status', '==', 'active').limit(30).get().then(function (snap) {
      adState.currentAds = snap.docs.map(function (d) { return Object.assign({ id: d.id }, d.data()); })
        .filter(function (a) { return a.type === 'free' || (a.type === 'paid' && a.paid && (a.views || 0) < (a.impressionsTarget || 0)); });
    }).catch(function () {});
  };
  try { if (window.state && state.user) loadAds(); } catch (e) {}

  // Admin panel: approve / reject through the server (refunds paid ads automatically).
  window.adminApproveAd = function (id) {
    mvApi('/api/admin/ads/' + encodeURIComponent(id) + '/approve', {}).then(function (d) {
      toast(d && d.ok ? '✅ Ad approved' : '❌ ' + ((d && d.message) || 'Failed')); if (typeof switchAdminTab === 'function') try { loadAdminAds('pending', 'pending-ads-list'); } catch (e) {}
    });
  };
  window.adminRejectAd = function (id) {
    var reason = prompt('Reason for rejecting this ad?', 'Does not meet Mindvora ad guidelines'); if (reason === null) return;
    mvApi('/api/admin/ads/' + encodeURIComponent(id) + '/reject', { reason: reason }).then(function (d) {
      toast(d && d.ok ? ('Ad rejected' + (d.refund === 'issued' ? ' — refund sent' : d.refund === 'failed' ? ' — ⚠️ refund failed, see alerts' : '')) : '❌ ' + ((d && d.message) || 'Failed'));
      try { loadAdminAds('pending', 'pending-ads-list'); } catch (e) {}
    });
  };

  // Owner: live ad activity feed + pop-up for every ad event.
  function isOwner() { try { return typeof isAdmin === 'function' && isAdmin(); } catch (e) { return false; } }
  function feed() {
    var box = $('mv-ad-events'), host = $('modal-admin') && $('modal-admin').querySelector('.admin-tabs');
    if (!host || box) return;
    box = document.createElement('div'); box.id = 'mv-ad-events';
    box.style.cssText = 'margin:8px 0;padding:8px;border:1px solid rgba(255,255,255,.1);border-radius:12px;max-height:170px;overflow:auto;font-size:11px';
    box.innerHTML = '<div style="font-weight:700;margin-bottom:4px">📡 Live ad activity</div><div id="mv-ad-events-list" style="color:var(--muted)">No ad activity yet.</div>';
    host.parentNode.insertBefore(box, host);
    db.collection('admin_events').orderBy('createdAt', 'desc').limit(30).onSnapshot(function (snap) {
      var l = $('mv-ad-events-list'); if (!l) return;
      l.innerHTML = snap.empty ? 'No ad activity yet.' : snap.docs.map(function (d) {
        var e = d.data(), t = e.createdAt && e.createdAt.toDate ? e.createdAt.toDate().toLocaleString() : '';
        var red = /refund_failed|rejected/.test(e.kind);
        return '<div style="padding:4px 0;border-bottom:1px solid rgba(255,255,255,.05);color:' + (red ? '#fca5a5' : 'var(--moon)') + '">' + esc(e.text || e.kind) + ' <span style="color:var(--muted)">' + t + '</span></div>';
      }).join('');
    }, function () {});
  }
  (function f() { if (window.state && state.user && isOwner()) { if ($('modal-admin')) feed(); } setTimeout(f, 3000); })();
  (function hook() {
    if (window.MindvoraRT && MindvoraRT.onMessage) MindvoraRT.onMessage(function (m) {
      if (m && m.type === 'ADMIN_EVENT' && isOwner()) toast(m.text);
      if (m && m.type === 'RT_NOTIF' && m.ntype === 'ad_status') toast(m.text);
    });
    else setTimeout(hook, 1000);
  })();
})();
