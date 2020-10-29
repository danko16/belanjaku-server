const express = require('express');
const RateLimit = require('express-rate-limit');
const router = express.Router();

const limitedAccess = new RateLimit({
  windowMs: 1 * 60 * 1000,
  max: 15,
  delayMs: 0,
  statusCode: 500,
  message: 'LIMITED ACCESS!',
});

router.use('/auth', limitedAccess, require('./auth'));

module.exports = router;
