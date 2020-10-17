const express = require('express');
const { users: User } = require('../models');
const config = require('../../config');
const {
  response,
  token: { getToken },
  otp: { generateOTP },
  emails: { sendActivationEmail },
} = require('../utils');

const router = express.Router();

router.post('/register', async (req, res) => {
  const { email, phone } = req.body;
  if (!email && !phone) {
    return res.status(400).json(response(400, 'email atau nomor telephone harus ada'));
  }
  try {
    const otp = generateOTP();

    if (email) {
      const user = await User.findOne({ where: { email } });
      if (user) {
        return res.status(400).json(response(400, 'email sudah terdaftar'));
      }
      const { key } = await getToken({ email, otp, for: 'register' }, 30);
      if (!key) {
        return res.status(500).json(response(500, 'Internal Server Error'));
      }

      sendActivationEmail({
        email,
        tokenUrl: `${config.serverDomain}/auth/confirm-email?${key}`,
        otp,
      });
    } else if (phone) {
      const user = await User.findOne({ where: { phone } });
      if (user) {
        return res.status(400).json(response(400, 'nomor telephone sudah terdaftar'));
      }
    }

    return res.status(201).json(response(200, 'Berhasil Mengirimkan Konfirmasi Registrasi'));
  } catch (error) {
    return res.status(500).json(response(500, 'Internal Server Error!', error));
  }
});

module.exports = router;
