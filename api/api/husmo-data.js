export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  const { phone, network, bundle, amount } = req.body;
  if (!phone || !network || !bundle) {
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const networkMap = { 'mtn':'1', 'glo':'2', 'airtel':'4', '9mobile':'3' };
  try {
    const response = await fetch('https://husmodata.com/api/data/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Token ${process.env.HUSMODATA_API_KEY}`
      },
      body: JSON.stringify({
        network: networkMap[network.toLowerCase()] || '1',
        mobile_number: phone,
        plan: bundle,
        Ported_number: true
      })
    });
    const data = await response.json();
    return res.status(200).json(data);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
