const config = require('./config.global');

config.serverDomain = 'http://localhost:3000';
config.clientDomain = 'http://localhost:3006';
config.host = 'http://localhost';
config.port = 3000;
config.jwtsecret = process.env.JWT_SECRET;
config.aessecret = process.env.AES_SECRET;

module.exports = config;
