const config = {};

config.documents = 'public/documents';
config.uploads = 'public/uploads';
config.email = {
  host: 'smtp-relay.sendinblue.com',
  port: 587,
  auth: {
    user: 'danangekoyudanto1995@gmail.com',
    pass:
      'xsmtpsib-03a217676e23ddd8692e0c1b2d05fcfe53bb1a6354c8302505635699fb35c73a-6nkpcZ4QNGTOSKMt',
  },
};

module.exports = config;
