export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  console.log('NOWPayments webhook received:', req.body);
  return res.status(200).json({ status: 'received' });
}
