const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const config = require('../../../config');

const GOOGLE_CLIENT_ID = config.googleId;
const GOOGLE_CLIENT_SECRET = config.googleSecret;
const FACEBOOK_CLIENT_ID = config.facebookId;
const FACEBOOK_CLIENT_SECRET = config.facebookSecret;

passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: `${config.serverDomain}/user/auth/google/callback`,
    },
    function (accessToken, refreshToken, profile, done) {
      done(null, {
        full_name: profile._json.name,
        email: profile._json.email,
        is_active: profile._json.email_verified,
        avatar: profile._json.picture,
      });
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: FACEBOOK_CLIENT_ID,
      clientSecret: FACEBOOK_CLIENT_SECRET,
      callbackURL: `${config.serverDomain}/user/auth/facebook/callback`,
      profileFields: ['id', 'email', 'name'],
    },
    function (accessToken, refreshToken, profile, done) {
      done(null, {
        email: profile._json.email,
      });
    }
  )
);

passport.serializeUser(function (user, done) {
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  done(null, user);
});

module.exports = passport;
