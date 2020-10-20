const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const RateLimit = require('express-rate-limit');
const config = require('../config');
const app = express();

const limitedAccess = new RateLimit({
  windowMs: 1 * 60 * 1000,
  max: 15,
  delayMs: 0,
  statusCode: 500,
  message: 'LIMITED ACCESS!',
});

//Init Protection
app.use(cors());
app.use(helmet());
app.disable('etag');

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use('/uploads', express.static(config.uploads));
app.use('/documents', express.static(config.documents));

app.use('/user', limitedAccess, require('./routes/user'));

module.exports = app;
