const {
  rateLimit,
  normalizePhoneNG,
} = require('../_lib/security');

const TWILIO_SID    = process.env.TWILIO_ACCOUNT_SID        || '';
const TWILIO_TOKEN  = process.env.TWILIO_AUTH_TOKEN         || '';
const TWILIO_VERIFY = process.env.TWILIO_VERIFY_SERVICE_SID || '';

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ status: false, message: 'Method not allowed' });
  }
  if (rateLimit(req, 'otp:verify-sms', 10, 60000)) {
    return res.status(429).json({ status: false, message: 'Too many requests. Try again in a minute.' });
  }
  const { phone, code } = req.body || {};
  const normalized = normalizePhoneNG(phone);
  if (!normalized || !/^\d{4,8}$/.test(String(code || ''))) {
    return res.status(400).json({ status: false, message: 'Invalid verification details.' });
  }
  if (!(TWILIO_SID && TWILIO_TOKEN && TWILIO_VERIFY)) {
    return res.status(500).json({ status: false, message: 'SMS service is not configured yet (Twilio env vars missing).' });
  }
  try {
    const auth = 'Basic ' + Buffer.from(TWILIO_SID + ':' + TWILIO_TOKEN).toString('base64');
    const resp = await fetch('https://verify.twilio.com/v2/Services/' + TWILIO_VERIFY + '/VerificationCheck', {
      method: 'POST',
      headers: {
        'Authorization': auth,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ To: normalized, Code: String(code) }).toString(),
    });
    const data = await resp.json();
    if (data && data.status === 'approved') {
      return res.json({ status: true, message: 'Phone verified.' });
    }
    return res.status(400).json({ status: false, message: 'Incorrect or expired code. Try again.' });
  } catch (_) {
    res.status(500).json({ status: false, message: 'Could not verify the code. Please try again.' });
  }
};
