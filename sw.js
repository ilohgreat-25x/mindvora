// ╔══════════════════════════════════════════════════════════════╗
// ║         MINDVORA SECURE BACKEND — Render.com                ║
// ║  Handles: NOWPayments crypto, Paystack airtime/data         ║
// ╚══════════════════════════════════════════════════════════════╝

const express = require('express');
const cors    = require('cors');
const fetch   = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ─────────────────────────────────────────────────
app.use(cors({
  origin: [
    'https://zync-social-vf8e.vercel.app',
    'https://mindvora.app',
    'http://localhost:3000',
  ]
}));
app.use(express.json());

// ── Health check ───────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'Mindvora Backend Running ✅', time: new Date().toISOString() });
});

// ══════════════════════════════════════════════════════════════
// 1. NOWPAYMENTS — Create crypto invoice
// ══════════════════════════════════════════════════════════════
app.post('/api/crypto/create-invoice', async (req, res) => {
  const { amountUSD, description, orderId, userEmail } = req.body;
  if (!amountUSD || !description) {
    return res.status(400).json({ status: false, message: 'Missing fields' });
  }
  try {
    const response = await fetch('https://api.nowpayments.io/v1/invoice', {
      method: 'POST',
      headers: {
        'x-api-key':    process.env.NOWPAYMENTS_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        price_amount:      amountUSD,
        price_currency:    'usd',
        pay_currency:      'usdtbsc',
        order_id:          orderId || ('MV-' + Date.now()),
        order_description: description,
        ipn_callback_url:  process.env.IPN_URL || 'https://zync-backend-ickl.onrender.com/api/crypto/webhook',
        success_url:       process.env.APP_URL  || 'https://mindvora.app',
        cancel_url:        process.env.APP_URL  || 'https://mindvora.app',
      }),
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
// 2. NOWPAYMENTS — Check payment status
// ══════════════════════════════════════════════════════════════
app.get('/api/crypto/status/:invoiceId', async (req, res) => {
  const { invoiceId } = req.params;
  try {
    const response = await fetch(`https://api.nowpayments.io/v1/invoice/${invoiceId}`, {
      headers: { 'x-api-key': process.env.NOWPAYMENTS_API_KEY }
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
// 3. PAYSTACK — Deliver airtime
// ══════════════════════════════════════════════════════════════
app.post('/api/deliver-airtime', async (req, res) => {
  const { email, amount, phone, network, ref } = req.body;
  if (!email || !amount || !phone || !network) {
    return res.status(400).json({ status: false, message: 'Missing fields' });
  }
  try {
    const response = await fetch('https://api.paystack.co/charge', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify({
        email, amount,
        mobile_money: { phone, provider: network },
        metadata: { type: 'airtime', phone, network, reference: ref }
      }),
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
// 4. PAYSTACK — Deliver data bundle
// ══════════════════════════════════════════════════════════════
app.post('/api/deliver-data', async (req, res) => {
  const { email, amount, phone, network, bundle, ref } = req.body;
  if (!email || !amount || !phone || !network) {
    return res.status(400).json({ status: false, message: 'Missing fields' });
  }
  try {
    const response = await fetch('https://api.paystack.co/charge', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify({
        email, amount,
        mobile_money: { phone, provider: network },
        metadata: { type: 'data', phone, network, bundle, reference: ref }
      }),
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// ══════════════════════════════════════════════════════════════
// 5. NOWPAYMENTS — IPN Webhook (payment confirmed callback)
// ══════════════════════════════════════════════════════════════
app.post('/api/crypto/webhook', async (req, res) => {
  const payload = req.body;
  console.log('NOWPayments IPN received:', payload);
  // Payment statuses: waiting, confirming, confirmed, sending, finished, failed
  if (payload.payment_status === 'finished' || payload.payment_status === 'confirmed') {
    console.log('✅ Crypto payment confirmed:', payload.order_id, '$'+payload.price_amount);
    // Firestore update handled by frontend polling — this is just a log
  }
  res.status(200).send('OK');
});

// ══════════════════════════════════════════════════════════════
// 6. EXCHANGE RATE PROXY (avoids CORS issues)
// ══════════════════════════════════════════════════════════════
app.get('/api/rate/:from/:to', async (req, res) => {
  const { from, to } = req.params;
  try {
    const response = await fetch(`https://api.exchangerate-api.com/v4/latest/${from}`);
    const data = await response.json();
    const rate = data.rates[to] || 1;
    res.json({ from, to, rate });
  } catch (err) {
    res.json({ from, to, rate: 1 });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Mindvora Backend running on port ${PORT}`);
});

// ══════════════════════════════════════════════════════════════
// HUSMODATA VTU API — Airtime & Data Delivery
// API key stored securely as environment variable on Render
// NEVER exposed to frontend
// ══════════════════════════════════════════════════════════════
const HUSMO_KEY = process.env.HUSMODATA_API_KEY; // set on Render dashboard
const HUSMO_BASE = 'https://husmodata.com/api';

// ── AIRTIME DELIVERY ──────────────────────────────────────────
app.post('/api/husmo-airtime', async (req, res) => {
  try {
    const { phone, network, amount, ref } = req.body;
    if (!phone || !network || !amount) {
      return res.status(400).json({ status: false, message: 'Missing required fields' });
    }
    const response = await fetch(`${HUSMO_BASE}/topup/`, {
      method: 'POST',
      headers: {
        'Authorization': `Token ${HUSMO_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        mobile_number: phone,
        network:       network.toUpperCase(),
        amount:        amount,
        Ported_number: true,
        airtime_type:  'VTU'
      })
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// ── DATA BUNDLE DELIVERY ──────────────────────────────────────
app.post('/api/husmo-data', async (req, res) => {
  try {
    const { phone, network, bundle, amount, ref } = req.body;
    if (!phone || !network || !bundle) {
      return res.status(400).json({ status: false, message: 'Missing required fields' });
    }
    // Map network name to Husmodata network ID
    const networkMap = { mtn: 1, airtel: 2, glo: 3, '9mobile': 4, etisalat: 4 };
    const networkId = networkMap[network.toLowerCase()] || 1;

    const response = await fetch(`${HUSMO_BASE}/data/`, {
      method: 'POST',
      headers: {
        'Authorization': `Token ${HUSMO_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        network:       networkId,
        mobile_number: phone,
        plan:          bundle,
        Ported_number: true
      })
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});

// ── CHECK HUSMO BALANCE ───────────────────────────────────────
app.get('/api/husmo-balance', async (req, res) => {
  try {
    const response = await fetch(`${HUSMO_BASE}/balance/`, {
      headers: { 'Authorization': `Token ${HUSMO_KEY}` }
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ status: false, message: err.message });
  }
});
