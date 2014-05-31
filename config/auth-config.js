var passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,
    HmacStrategy = require('../lib/passport-hmac').Strategy,
    FacebookStrategy = require('passport-facebook').Strategy,
    User = require('../models/user').model,
    oauthConfigs = {
        fb: {
          appId: '260907493994161',
          appSecret: '374abde8cd83d33bbea039b14ab208d9'
        },
        twitter: {
            consumerKey: 'PyyZ8tnqCrLqpZHrLx56w',
            consumerSecret: 'USgcvujBuqpRRLwWXRCXK159gNtJ4zj0FBmMvhNDbKM'
        },
        google: {
            clientId: '278080134499.apps.googleusercontent.com',
            clientSecret: 'lQD_LRWm1aNkJLuUJZ_pn1oI'
        }
    };

passport.use(new LocalStrategy(
  {
    usernameField: 'email'
  },
  User.authenticate
));

passport.use(new HmacStrategy({
  name : 'device',
  scheme : 'BPN_DEVICE',
  getUser : User.getByPublicDeviceKey,
  headerSaltField : 'X-Bpn-Fert'
}));

passport.use(new HmacStrategy({
  name : 'api',
  scheme : 'BPN_API',
  getUser : User.getByPublicApiKey
}));

      
// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
// http://passportjs.org/guide/configure/
passport.serializeUser(function(user, done) {
  done(null, user._id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

module.exports = function(app){
   /*
   * Passport Facebook Strategy
   */
  passport.use(new FacebookStrategy({
      clientID: oauthConfigs.fb.appId,
      clientSecret: oauthConfigs.fb.appSecret,
      callbackURL: app.config.appUrl + '/auth/facebook/callback'
    },
    function(accessToken, refreshToken, profile, done) {
      User.findOrCreate(accessToken, refreshToken, profile, done);
    }
  ));     
};

