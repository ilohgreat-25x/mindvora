const TWILIO_SID    = process.env.TWILIO_ACCOUNT_SID        || '';
const TWILIO_TOKEN  = process.env.TWILIO_AUTH_TOKEN         || '';
const TWILIO_VERIFY = process.env.TWILIO_VERIFY_SERVICE_SID || '';

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ status: false, message: 'Method not allowed' });
  }
  const { phone } = req.body || {};
  if (!phone || typeof phone !== 'string' || phone.trim().length < 7) {
    return res.status(400).json({ status: false, message: 'Enter a valid phone number.' });
  }
  if (!(TWILIO_SID && TWILIO_TOKEN && TWILIO_VERIFY)) {
    return res.status(500).json({ status: false, message: 'SMS service is not configured yet (Twilio env vars missing).' });
  }
  try {
    const auth = 'Basic ' + Buffer.from(`${TWILIO_SID}:${TWILIO_TOKEN}`).toString('base64');
    const resp = await fetch(`https://verify.twilio.com/v2/Services/${TWILIO_VERIFY}/Verifications`, {
      method: 'POST',
      headers: {
        'Authorization': auth,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ To: phone.trim(), Channel: 'sms' }).toString(),
    });
    const data = await resp.json();
    if (!resp.ok) {
      console.error('[OTP] Twilio send failed:', data && data.message);
      return res.status(resp.status).json({ status: false, message: (data && data.message) || 'Could not send SMS.' });
    }
    res.json({ status: true, message: 'SMS code sent.' });
  } catch (_) {
    res.status(500).json({ status: false, message: 'Could not send SMS. Please try again.' });
  }
};
