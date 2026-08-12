const {
  rateLimit,
  normalizePhoneNG,
  validHusmoNetwork,
  verifyPaystackRef,
} = require('./_lib/security');

const HUSMO_BASE = 'https://husmodata.com/api';
const MIN_AMOUNT = 50;
const MAX_AMOUNT = 200000;

const deliveredRefs = new Set();

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ status: false, message: 'Method not allowed' });
  }
  if (rateLimit(req, 'husmo:airtime', 20, 600000)) {
    return res.status(429).json({ status: false, message: 'Too many requests. Try again later.' });
  }
  const { phone, network, amount, ref } = req.body || {};

  const normalized = normalizePhoneNG(phone);
  if (!normalized) {
    return res.status(400).json({ status: false, message: 'Enter a valid Nigerian phone number.' });
  }
  if (!validHusmoNetwork(network)) {
    return res.status(400).json({ status: false, message: 'Unsupported network.' });
  }
  if (!amount || !Number.isInteger(Number(amount)) || Number(amount) < MIN_AMOUNT || Number(amount) > MAX_AMOUNT) {
    return res.status(400).json({ status: false, message: 'Amount must be between ' + MIN_AMOUNT + ' and ' + MAX_AMOUNT + ' NGN.' });
  }

  if (deliveredRefs.size > 5000) deliveredRefs.clear();
  if (ref && deliveredRefs.has(ref)) {
    return res.status(409).json({ status: false, message: 'This payment reference was already used.' });
  }

  const check = await verifyPaystackRef(ref, Number(amount) * 100);
  if (!check.configured) {
    return res.status(500).json({ status: false, message: 'Paystack is not configured yet (PAYSTACK_SECRET_KEY missing).' });
  }
  if (!check.ok) {
    const msg = check.error === 'not_paid' ? 'Payment not completed. Nothing was sent.'
      : check.error === 'amount_mismatch' ? 'Payment amount does not match. Nothing was sent.'
      : 'Could not confirm your payment. Try again.';
    return res.status(402).json({ status: false, message: msg });
  }

  try {
    const response = await fetch(HUSMO_BASE + '/topup/', {
      method: 'POST',
      headers: {
        'Authorization': 'Token ' + process.env.HUSMODATA_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        mobile_number: normalized,
        network: String(network).toUpperCase(),
        amount: Number(amount),
        Ported_number: true,
        airtime_type: 'VTU',
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      console.error('[HUSMO] airtime failed:', JSON.stringify(data));
      return res.status(response.status).json({ status: false, message: 'VTU provider error.' });
    }
    if (ref) deliveredRefs.add(ref);
    res.json({ status: 'success', reference: (data && data.ref) || ref, ...data });
  } catch (_) {
    res.status(500).json({ status: false, message: 'Unable to process airtime. Please try again.' });
  }
};
