const express = require('express');
const passport = require('passport');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const config = require('../config');
const app = express();

//Init Protection
app.use(cors());
app.use(helmet());
app.disable('etag');

const sess = {
  secret: '2Gn@x:TF`RBYW9QGxy^YAK*DW4kHEX"2Y-v:Fa{m',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 15,
  },
};

if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
  sess.cookie.secure = true;
}

app.use(session(sess));

app.use(passport.initialize());
app.use(passport.session());

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.use('/uploads', express.static(config.uploads));
app.use('/documents', express.static(config.documents));

app.use('/user', require('./routes/user'));

module.exports = app;
