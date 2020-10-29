const config = require('./config.global');

config.serverDomain = 'http://localhost:3000';
config.clientDomain = 'http://localhost:3006';
config.host = 'http://localhost';
config.port = 3000;
config.jwtsecret = process.env.JWT_SECRET;
config.aessecret = process.env.AES_SECRET;
config.googleId = process.env.GOOGLE_ID;
config.googleSecret = process.env.GOOGLE_SECRET;
config.facebookId = process.env.FACEBOOK_ID;
config.facebookSecret = process.env.FACEBOOK_SECRET;

module.exports = config;
