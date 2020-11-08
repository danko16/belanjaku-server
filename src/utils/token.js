const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { AES, enc } = require('crypto-js');
const config = require('../../config');

const encrypt = (pass) => {
  const hash = crypto
    .createHmac('sha256', pass)
    .update('AzntbaZ87JeEL3MgLdA4Hqf3y7rBsuJaTjbBCPKU')
    .digest('hex');
  return hash;
};

const getToken = async (payload, expiresIn) => {
  try {
    const token = await jwt.sign(payload, config.jwtsecret, { expiresIn });
    return { pure: token, key: AES.encrypt(token, config.aessecret).toString() };
  } catch (error) {
    return null;
  }
};

const checkToken = async (token, tokenFor) => {
  try {
    const decrypted = AES.decrypt(token, config.aessecret).toString(enc.Utf8);
    const verify = await jwt.verify(decrypted, config.jwtsecret, function (err, decoded) {
      if (err) {
        return false;
      } else {
        if (decoded.for === tokenFor) return decoded;
        else return false;
      }
    });

    return verify;
  } catch (error) {
    return false;
  }
};

const getPayload = async (token) => {
  try {
    const verify = await jwt.verify(token, config.jwtsecret, function (err, decoded) {
      if (err) return false;
      else return decoded;
    });

    return verify;
  } catch (error) {
    return false;
  }
};

module.exports = Object.freeze({
  encrypt,
  getToken,
  checkToken,
  getPayload,
});
