'use strict';

const crypto = require('crypto');

const OTP_TTL_MS          = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS    = 5;
const OTP_COOLDOWN_MS     = 60 * 1000;
const OTP_COOLDOWN_PER_EMAIL_MS = 60 * 60 * 1000;

const rateHits = new Map();
const otpStore = new Map();

function getClientIP(req) {
  const fwd = req.headers && (req.headers['x-forwarded-for'] || '');
  if (fwd) {
    const parts = fwd.split(',').map(s => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function rateLimit(req, scope, max, windowMs) {
  if (rateHits.size > 20000) rateHits.clear();
  const key = scope + '|' + getClientIP(req);
  const now = Date.now();
  const arr = (rateHits.get(key) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) {
    rateHits.set(key, arr);
    return true;
  }
  arr.push(now);
  rateHits.set(key, arr);
  return false;
}

async function verifyRecaptcha(req) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;
  if (!secret) return { ok: false, configured: false };
  const token = (req.body && req.body.recaptcha) || '';
  if (!token) return { ok: false, configured: true };
  try {
    const r = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret, response: token }).toString(),
    });
    const d = await r.json();
    return { ok: !!(d && d.success), configured: true };
  } catch (_) {
    return { ok: false, configured: true };
  }
}

function normalizePhoneNG(input) {
  if (typeof input !== 'string') return null;
  let p = input.replace(/[\s\-()]/g, '');
  if (!/^[0-9+]+$/.test(p)) return null;
  if (p.startsWith('+234')) p = '234' + p.slice(4);
  if (p.startsWith('0') && p.length === 11) p = '234' + p.slice(1);
  if (p.startsWith('234') && p.length === 13 && /^[789][01]/.test(p.slice(3))) return '+' + p;
  return null;
}

function sha256(s) {
  return crypto.createHash('sha256').update(String(s)).digest('hex');
}

function issueEmailOtp(email) {
  const now = Date.now();
  const rec = otpStore.get(email);
  if (rec && rec.lastSentAt && now - rec.lastSentAt < OTP_COOLDOWN_MS) {
    return { cooldown: true, retryAfter: Math.ceil((OTP_COOLDOWN_MS - (now - rec.lastSentAt)) / 1000) };
  }
  if (rec && rec.sentCount) {
    const firstWindow = (rec.firstSentAt || now);
    if (now - firstWindow < OTP_COOLDOWN_PER_EMAIL_MS && rec.sentCount >= 3) {
      return { rateLimited: true };
    }
  }
  const code = crypto.randomInt(0, 1000000).toString().padStart(6, '0');
  const prev = otpStore.get(email);
  otpStore.set(email, {
    hash: sha256(email + '|' + code),
    expiresAt: now + OTP_TTL_MS,
    attempts: 0,
    lastSentAt: now,
    sentCount: (prev && prev.sentCount || 0) + 1,
    firstSentAt: prev && prev.firstSentAt || now,
  });
  return { code: code };
}

function checkEmailOtp(email, code) {
  const rec = otpStore.get(email);
  if (!rec) return { status: 'not_found', message: 'No code was sent to this email. Request a new one.' };
  if (Date.now() > rec.expiresAt) {
    otpStore.delete(email);
    return { status: 'expired', message: 'Code expired. Request a new one.' };
  }
  if (rec.attempts >= OTP_MAX_ATTEMPTS) {
    otpStore.delete(email);
    return { status: 'too_many', message: 'Too many attempts. Request a new code.' };
  }
  rec.attempts++;
  if (sha256(email + '|' + String(code).trim()) !== rec.hash) {
    return { status: 'invalid', message: 'Incorrect code. ' + (OTP_MAX_ATTEMPTS - rec.attempts) + ' attempts left.' };
  }
  otpStore.delete(email);
  return { status: 'ok' };
}

const HUSMO_NETWORKS = ['mtn', 'airtel', 'glo', '9mobile', 'etisalat'];
const HUSMO_DATA_PLANS = {
  mtn: /^[0-9]{3,6}$/,
  airtel: /^[0-9]{3,6}$/,
  glo: /^[0-9]{3,6}$/,
  '9mobile': /^[0-9]{3,6}$/,
};

function validHusmoNetwork(network) {
  return HUSMO_NETWORKS.indexOf(String(network || '').toLowerCase()) !== -1;
}

async function verifyPaystackRef(ref, expectedAmountKobo) {
  const secret = process.env.PAYSTACK_SECRET_KEY;
  if (!secret) return { ok: false, configured: false };
  if (!ref || typeof ref !== 'string' || !/^[A-Za-z0-9_-]{6,100}$/.test(ref)) {
    return { ok: false, configured: true, error: 'invalid ref' };
  }
  try {
    const r = await fetch('https://api.paystack.co/transaction/verify/' + encodeURIComponent(ref), {
      headers: { 'Authorization': 'Bearer ' + secret },
    });
    const d = await r.json();
    if (!d || !d.status || !d.data) return { ok: false, configured: true, error: 'paystack_verify_failed' };
    const statusOk = d.data.status === 'success';
    const amountOk = expectedAmountKobo ? d.data.amount === Number(expectedAmountKobo) : true;
    if (!statusOk) return { ok: false, configured: true, error: 'not_paid' };
    if (!amountOk) return { ok: false, configured: true, error: 'amount_mismatch' };
    return { ok: true, configured: true, paidAt: d.data.paid_at, currency: d.data.currency };
  } catch (_) {
    return { ok: false, configured: true, error: 'verify_network_error' };
  }
}

module.exports = {
  OTP_TTL_MS,
  OTP_MAX_ATTEMPTS,
  OTP_COOLDOWN_MS,
  getClientIP,
  rateLimit,
  verifyRecaptcha,
  normalizePhoneNG,
  issueEmailOtp,
  checkEmailOtp,
  validHusmoNetwork,
  HUSMO_DATA_PLANS,
  verifyPaystackRef,
};
