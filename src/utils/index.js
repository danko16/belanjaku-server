const token = require('./token');
const response = require('./response');
const otp = require('./otp');
const emails = require('./emails');
const auth = require('./auth');

module.exports = Object.freeze({
  auth,
  token,
  response,
  otp,
  emails,
});
