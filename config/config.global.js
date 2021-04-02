const config = {};

config.documents = 'public/documents';
config.uploads = 'public/uploads';
config.email = {
  host: 'smtp-relay.sendinblue.com',
  port: 587,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
};

config.jwtsecret = process.env.JWT_SECRET;
config.aessecret = process.env.AES_SECRET;
config.googleId = process.env.GOOGLE_ID;
config.googleSecret = process.env.GOOGLE_SECRET;
config.facebookId = process.env.FACEBOOK_ID;
config.facebookSecret = process.env.FACEBOOK_SECRET;

module.exports = config;
