export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  const { phone, network, amount, ref } = req.body;
  if (!phone || !network || !amount) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  try {
    const response = await fetch('https://husmodata.com/api/topup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Token ${process.env.HUSMODATA_API_KEY}`
      },
      body: JSON.stringify({
        network: network,
        mobile_number: phone,
        amount: amount,
        Ported_number: true,
        airtime_type: 'VTU'
      })
    });
    const data = await response.json();
    return res.status(200).json(data);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
