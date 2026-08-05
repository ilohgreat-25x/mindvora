export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, amount, phone, network, bundle, ref } = req.body;

  if (!email || !amount || !phone || !network) {
    return res.status(400).json({ status: false, message: 'Missing required fields' });
  }

  try {
    const response = await fetch('https://api.paystack.co/charge', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        amount,
        mobile_money: { phone, provider: network },
        metadata: { type: 'data', phone, network, bundle, reference: ref }
      }),
    });

    const data = await response.json();
    return res.status(200).json(data);
  } catch (error) {
    return res.status(500).json({ status: false, message: error.message });
  }
}
