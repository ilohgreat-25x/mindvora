const {
  rateLimit,
  checkEmailOtp,
} = require('../_lib/security');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ status: false, message: 'Method not allowed' });
  }
  if (rateLimit(req, 'otp:verify-email', 10, 60000)) {
    return res.status(429).json({ status: false, message: 'Too many requests. Try again in a minute.' });
  }
  const { email, code } = req.body || {};
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(email))) {
    return res.status(400).json({ status: false, message: 'Invalid email address.' });
  }
  if (!/^\d{6}$/.test(String(code || ''))) {
    return res.status(400).json({ status: false, message: 'Enter the 6-digit code you received.' });
  }
  const result = checkEmailOtp(String(email).toLowerCase().trim(), String(code).trim());
  if (result.status === 'ok') {
    return res.json({ status: true, message: 'Email verified.' });
  }
  return res.status(400).json({ status: false, message: result.message });
};
