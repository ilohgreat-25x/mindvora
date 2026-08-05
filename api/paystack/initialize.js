module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ status: false, message: 'Method not allowed' });
  }
  const { email, amount, currency, reference, metadata, description } = req.body || {};
  const secret = process.env.PAYSTACK_SECRET_KEY;
  if (!secret) {
    return res.status(500).json({ status: false, message: 'Paystack is not configured yet (PAYSTACK_SECRET_KEY missing).' });
  }
  if (!email || !amount || isNaN(Number(amount)) || Number(amount) <= 0) {
    return res.status(400).json({ status: false, message: 'Missing payment details.' });
  }
  try {
    const resp = await fetch('https://api.paystack.co/transaction/initialize', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${secret}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        amount: Number(amount),
        currency: currency || 'NGN',
        reference: reference || `MV-${Date.now()}`,
        metadata: metadata || {},
        description: description || 'Mindvora payment',
      }),
    });
    const data = await resp.json();
    if (!resp.ok || !data.status) {
      console.error('[PAYSTACK] initialize failed:', data && data.message);
      return res.status(resp.status).json({ status: false, message: (data && data.message) || 'Paystack error.' });
    }
    return res.json({ status: true, authorization_url: data.data.authorization_url, reference: data.data.reference });
  } catch (error) {
    console.error('[PAYSTACK] initialize error:', error && error.message);
    return res.status(500).json({ status: false, message: 'Could not initialize payment.' });
  }
};
