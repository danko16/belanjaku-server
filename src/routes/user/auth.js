const express = require('express');
const { body, query, validationResult } = require('express-validator');
const { users: User } = require('../../models');
const config = require('../../../config');
const {
  response,
  token: { checkToken, getToken },
  otp: { generateOTP },
  emails: { sendActivationEmail },
} = require('../../utils');
const { encrypt, getPayload } = require('../../utils/token');

const router = express.Router();

router.post('/register', [body('type', 'type must be present').exists()], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json(response(422, errors.array()));
  }

  const { email, phone, type } = req.body;

  if (!email && !phone) {
    return res.status(400).json(response(400, 'email atau nomor telephone harus ada'));
  }

  try {
    const otp = generateOTP();
    let payload;

    if (type === 'email') {
      let user = await User.findOne({ where: { email } });

      if (user) {
        return res.status(400).json(response(400, 'Email sudah terdaftar', null, 'user_exist'));
      }

      const { pure, key } = await getToken({ email, otp, type: 'email', for: 'confirm' }, 60 * 30);

      if (!key) {
        throw new Error('Failed to create token');
      }

      const token = await getPayload(pure);

      payload = { confirm_token: { key, exp: token.exp }, email };

      sendActivationEmail({
        email,
        tokenUrl: `${config.serverDomain}/user/auth/confirm-token?tokenUrl=${key}`,
        otp,
      });
    } else if (type === 'phone') {
      let user = await User.findOne({ where: { phone } });

      if (user) {
        return res
          .status(400)
          .json(response(400, 'Nomor telephone sudah terdaftar', null, 'user_exist'));
      }

      const { pure, key } = await getToken({ phone, otp, type: 'phone', for: 'confirm' }, 60 * 30);

      if (!key) {
        throw new Error('Failed to create token');
      }

      const token = await getPayload(pure);

      payload = { confirm_token: { key, exp: token.exp }, phone };
      /* Todo Send OTP to mobile */
    } else {
      return res.status(400).json(response(400, 'Type tidak di temukan'));
    }

    return res
      .status(200)
      .json(response(200, 'Berhasil Mengirimkan Konfirmasi Registrasi', payload));
  } catch (error) {
    return res.status(500).json(response(500, 'Internal Server Error!', error));
  }
});

router.get(
  '/confirm-token',
  [query('tokenUrl', 'token url must be present').exists()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json(response(422, errors.array()));
    }

    const { tokenUrl } = req.query;
    try {
      const registerPayload = await checkToken(tokenUrl.replace(/ /g, '+'), 'register');
      if (!registerPayload) {
        return res.status(400).json(response(400, 'Invalid token'));
      }

      const { email, type } = registerPayload;

      const { pure, key } = await getToken({ email, type, for: 'register' }, 60 * 30);

      if (!key) {
        throw new Error('Failed to create token');
      }

      const token = await getPayload(pure);

      return res.status(200).json(
        response(200, 'Konfirmasi Berhasil', {
          register_token: { key, exp: token.exp },
        })
      );
    } catch (error) {
      return res.status(500).json(response(500, 'Internal Server Error', error));
    }
  }
);

router.post('/confirm-otp', [body('otp', 'otp must be present').exists()], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json(response(422, errors.array()));
  }

  let token = req.headers['x-confirm-token'];
  if (!token) {
    return res.status(401).json(response(401, 'Confirm Token is Required'));
  }

  const { otp } = req.body;

  try {
    token = token.split(' ')[1];
    if (!token) return res.status(401).json(response(401, 'Invalid Token!'));

    const confirmPayload = await checkToken(token, 'confirm');
    if (!confirmPayload) return res.status(401).json(response(401, 'Invalid Token!'));

    const { type, email, phone, otp: otpPayload } = confirmPayload;

    if (otp !== otpPayload) {
      return res
        .status(400)
        .json(response(400, 'Kode konfirmasi tidak cocok', null, 'unmatch_otp'));
    }

    let registerToken;
    if (type === 'email') {
      const { pure, key } = await getToken({ email, type, for: 'register' }, 60 * 30);
      const token = await getPayload(pure);
      registerToken = { key, exp: token.exp };
    } else if (type === 'phone') {
      const { pure, key } = await getToken({ phone, type, for: 'register' }, 60 * 30);
      const token = await getPayload(pure);
      registerToken = { key, exp: token.exp };
    } else {
      return res.status(400).json(response(400, 'type tidak di temukan'));
    }

    return res
      .status(200)
      .json(response(200, 'Konfirmasi Berhasil', { register_token: registerToken }));
  } catch (error) {
    console.log(error);
    return res.status(500).json(response(500, 'Internal Server Error', error));
  }
});

router.post(
  '/register-complete',
  [
    body('full_name', 'full name must be present').exists(),
    body('password', 'password must be present')
      .exists()
      .matches(/^.{8,}$/)
      .withMessage('invalid password'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json(response(422, errors.array()));
    }

    let token = req.headers['x-register-token'];
    if (!token) return res.status(401).json(response(401, 'Register Token is Required'));

    const { full_name, password } = req.body;

    try {
      token = token.split(' ')[1];
      if (!token) return res.status(401).json(response(401, 'Invalid Token'));

      const registerPayload = await checkToken(token, 'register');
      if (!registerPayload) return res.status(401).json(response(401, 'Invalid Token'));

      const { email, phone, type } = registerPayload;

      let user;
      if (type === 'email') {
        user = await User.findOne({ where: { email } });

        if (user) {
          return res.status(400).json(response(400, 'Email sudah terdaftar', null, 'user_exist'));
        }
        user = await User.create({ full_name, email, password: encrypt(password) });
      } else if (type === 'phone') {
        user = await User.findOne({ where: { phone } });

        if (user) {
          return res
            .status(400)
            .json(response(400, 'Nomor telephone sudah terdaftar', null, 'user_exist'));
        }

        user = await User.create({ full_name, phone, password: encrypt(password) });
      } else {
        return res.status(400).json(response(400, 'Type tidak di temukan'));
      }

      if (!user) {
        throw new Error('Failed to create user');
      }

      const { pure, key } = await getToken({ uid: user.id, type: 'user', for: 'login' }, '1d');
      const { exp } = await getPayload(pure);

      return res.status(201).json(
        response(201, 'Registrasi Selesai', {
          token: { key, exp },
          user: {
            id: user.id,
            full_name: user.full_name,
            email: user.email,
            phone: user.phone,
            avatar: null,
            type: 'user',
          },
        })
      );
    } catch (error) {
      return res.status(500).json(response(500, 'Internal Server Error', error));
    }
  }
);

module.exports = router;
