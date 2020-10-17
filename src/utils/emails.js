const nodemailer = require('nodemailer');
const Email = require('email-templates');
const config = require('../../config');
const transporter = nodemailer.createTransport(config.email);

const emailSender = new Email({
  message: {
    from: '"Belanjaku.id" admin@belanjaku.id',
  },
  send: true,
  transport: transporter,
});

const sendActivationEmail = (data) => {
  emailSender
    .send({
      template: 'register',
      message: {
        to: data.email,
      },
      locals: {
        subject: 'Silahkan Aktifasi Emailmu',
        ctaLink: data.tokenUrl,
        otp: data.otp,
      },
    })
    .then((res) => {
      return true;
    })
    .catch((err) => {
      return false;
    });
};

module.exports = { sendActivationEmail };
