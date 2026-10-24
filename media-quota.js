/* Mindvora media quota UI and signed upload helper. Never contains Cloudinary secrets. */
(function () {
  'use strict';
  var LIMIT_MESSAGE = 'You have reached your media allowance, kindly delete older media to continue posting.';
  var lastQuota = null;
  function api(path, body) {
    var u = window.firebase && firebase.auth && firebase.auth().currentUser;
    if (!u) return Promise.reject(new Error('Please log in again.'));
    return u.getIdToken().then(function (token) {
      return fetch((window.BACKEND_URL || '') + path, {
        method: body ? 'POST' : 'GET',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
        body: body ? JSON.stringify(body) : undefined
      });
    }).then(function (r) {
      return r.json().then(function (d) {
        if (!r.ok) { var e = new Error(d.message || 'Media authorization failed'); e.code = d.code; throw e; }
        return d;
      });
    });
  }
  function show(q) {
    lastQuota = q;
    var el = document.getElementById('media-quota-status');
    if (el && q) el.textContent = q.configured === false ? 'Media uploads are temporarily unavailable.' : ('Media allowance: ' + Math.max(0, (q.quotaBytes - q.usedBytes - q.reservedBytes) / (1024 * 1024 * 1024)).toFixed(2) + ' GB available');
  }
  function quota() { return api('/api/media/quota').then(function (d) { show(d.quota); return d.quota; }); }
  function release(id, publicId, resourceType) { return api('/api/media/reservations/' + encodeURIComponent(id) + '/release', { publicId: publicId || null, resourceType: resourceType || null }); }
  function deleteAsset(publicId, resourceType) { return api('/api/media/assets/delete', { publicId: publicId, resourceType: resourceType || null }); }
  function upload(file, resourceType) {
    if (!file) return Promise.reject(new Error('No file selected'));
    var type = resourceType || (file.type.indexOf('video/') === 0 ? 'video' : 'image');
    return api('/api/media/authorize', { bytes: file.size, resourceType: type, fileName: file.name || 'upload' }).then(function (a) {
      var fd = new FormData();
      Object.keys(a.params).forEach(function (k) { fd.append(k, a.params[k]); });
      fd.append('file', file, file.name || 'upload');
      return fetch(a.uploadUrl, { method: 'POST', body: fd }).then(function (r) {
        return r.json().then(function (d) {
          if (!r.ok || !d.secure_url) { var e = new Error((d.error && d.error.message) || 'Cloudinary upload failed'); e.reservationId = a.reservationId; e.publicId = d.public_id || null; throw e; }
          return api('/api/media/reservations/' + encodeURIComponent(a.reservationId) + '/finalize', { bytes: file.size, publicId: d.public_id, resourceType: type }).then(function () { quota().catch(function () {}); d.reservationId = a.reservationId; d.bytes = file.size; d.publicId = d.public_id || null; d.resourceType = type; return d; });
        });
      }).catch(function (e) { return release(a.reservationId, e.publicId, type).catch(function () {}).then(function () { throw e; }); });
    });
  }
  window.MVMediaQuota = { quota: quota, upload: upload, release: release, deleteAsset: deleteAsset, limitMessage: LIMIT_MESSAGE, last: function () { return lastQuota; } };
  window.addEventListener('load', function () { if (window.firebase && firebase.auth) firebase.auth().onAuthStateChanged(function (u) { if (u) quota().catch(function () {}); }); });
})();
