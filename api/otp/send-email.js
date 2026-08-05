const nodemailer = require('nodemailer');

const SMTP_HOST   = process.env.SMTP_HOST   || '';
const SMTP_PORT   = Number(process.env.SMTP_PORT || 465);
const SMTP_SECURE = String(process.env.SMTP_SECURE || 'true') === 'true';
const SMTP_USER   = process.env.SMTP_USER   || '';
const SMTP_PASS   = process.env.SMTP_PASS   || '';
const SMTP_FROM   = process.env.SMTP_FROM   || SMTP_USER;

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ status: false, message: 'Method not allowed' });
  }
  const { email, code } = req.body || {};
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(email))) {
    return res.status(400).json({ status: false, message: 'Invalid email address.' });
  }
  if (!/^\d{6}$/.test(String(code || ''))) {
    return res.status(400).json({ status: false, message: 'Invalid code.' });
  }
  if (!(SMTP_HOST && SMTP_USER && SMTP_PASS)) {
    return res.status(500).json({ status: false, message: 'Email service is not configured yet (SMTP env vars missing).' });
  }
  try {
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
    });
    await transporter.sendMail({
      from: `Mindvora <${SMTP_FROM}>`,
      to: email,
      subject: 'Mindvora — Your verification code',
      html:
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:auto;background:#0d2118;border:1px solid #166534;border-radius:16px;padding:28px">' +
          '<div style="text-align:center;color:#ffffff;font-size:22px;font-weight:700;margin-bottom:4px">🌿 Mindvora</div>' +
          '<div style="text-align:center;color:#00C896;font-size:11px;letter-spacing:2px;margin-bottom:24px">WHERE MINDS CONNECT</div>' +
          '<div style="color:#e2e8f0;font-size:14px;line-height:1.7;margin-bottom:16px">Hello! Your Mindvora verification code is:</div>' +
          '<div style="text-align:center;font-size:32px;font-weight:700;letter-spacing:10px;color:#00C896;background:#0a1a0f;border:1px solid #166534;border-radius:12px;padding:16px;margin-bottom:16px">' + String(code) + '</div>' +
          '<div style="color:#94a3b8;font-size:12px;line-height:1.6">This code expires in 10 minutes. If you did not request this, you can safely ignore this email.</div>' +
        '</div>',
    });
    res.json({ status: true, message: 'OTP email sent.' });
  } catch (err) {
    console.error('[OTP] Email send failed:', err && err.message);
    res.status(500).json({ status: false, message: 'Could not send the email. Please try again.' });
  }
};
