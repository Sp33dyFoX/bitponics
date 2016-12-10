var connect    = require('connect'),
  express    = require('express'),
  http       = require('http'),
  net        = require('net'),
  fs         = require('fs'),
  stylus     = require('stylus'),
  nib        = require('nib'),
  mongodb    = require('mongodb'),
  mongoose   = require('mongoose'),
  // MongoStore = require('connect-mongo')(express),
  passport   = require('passport'),
  csv        = require('express-csv'),
  winston    = require('winston'),
  flash      = require('connect-flash'),
  semver  = require('semver'),
  path    = require('path'),
  // Session = connect.middleware.session.Session,
  session = require('express-session'),
  MongoStore = require('connect-mongo')(session),
  cookieParser = require('cookie-parser'),
  cookie  = require('cookie'),
  s3Config = require('../config/s3-config'),
  intercomConfig = require('../config/intercom-config'),
  crypto = require('crypto'),
  breakpoints = require('../public/assets/config/media-queries'),
  getenv = require('getenv');

var favicon = require('serve-favicon'),
    logger = require('morgan'),
    methodOverride = require('method-override'),
    bodyParser = require('body-parser'),
    // multer = require('multer'),
    errorHandler = require('errorhandler'),
    basicAuth = require('basic-auth-connect');


module.exports = function(app){

  /**
   * Standard config.
   * Should go first so env-specific ones are simply adding on to it
   * & guaranteeing that their middleware executes after this is all set up
   */
  app.use(stylus.middleware({
    src: __dirname + '/../stylus/', // .styl files are located in `/stylus`
    dest: __dirname + '/../public/', // .styl resources are compiled `/stylesheets/*.css`
    debug: true,
    compile: function(str, path) { // optional, but recommended
      return stylus(str)
        //.define('url', stylus.url({ paths: [__dirname + '/public'] }))
        .set('filename', path)
        .set('warn', true)
        .set('compress', false)
        .use(nib());
    }
  })
  );

  app.set('view engine', 'jade');
  app.locals.basedir = path.join(__dirname, '/../views');
  app.locals.breakpoints = breakpoints;

  //express log messages through winston
  if (app.settings.env === 'local') {
    app.use(logger('default', {
      stream: {
        write: function(message, encoding){
          winston.info(message);
        }
      }
    }));
    // app.use(express.logger(':method :url :status'));
  }

  // Since we're on Heroku (and hence behind a proxy), tell express proxied requests are cool
  // http://expressjs.com/guide.html#proxies
  app.enable('trust proxy');

  
  // If we've got a device request or an HMAC-authed request, need the raw body
  app.use (function(req, res, next) {
    var contentType = req.headers['content-type'] || '',
      authHeader = req.headers['authorization'] || '';

    if( (contentType.indexOf('application/vnd.bitponics') >= 0) ||
        (authHeader.indexOf('BPN_DEVICE') >= 0) ||
        (authHeader.indexOf('BPN_API') >= 0)
      ){
      var data='';
      req.setEncoding('utf8');
      req.on('data', function(chunk) {
        data += chunk;
      });
      req.on('end', function() {
        req.rawBody = data;
        next();
      });
    } else{
      next();
    }
  });

  
  app.use(bodyParser.json())
  app.use(bodyParser.urlencoded({ extended: true }))
  // app.use(multer())
  app.use(methodOverride());

  app.use(favicon(__dirname + '/../public/favicon.ico', { maxAge: 2592000000 }));
  app.use(express.static(path.join(__dirname, '/../public')));

  // by default, express adds an "X-Powered-By:ExpressJS" header. prevent that.
  app.disable('x-powered-by');

  // Set the CDN options after express setup
  // require('./express-cdn-config');
  var options = {
    publicDir  : path.join(__dirname, '/../public')
    , viewsDir   : path.join(__dirname, '/../views')
    , domain     : s3Config.cloudFrontEndpoint
    , bucket     : s3Config.bucketCDN
    , key        : s3Config.key
    , secret     : s3Config.secret
    , hostname   : 'localhost'
    , port       : 80
    , ssl        : true
    , production : app.settings.env !== 'local' ? true : false //false means we use local assets
    , logger     : winston.info
  };

  // Initialize the CDN magic
  var CDN = require('express-cdn')(app, options);

  // Add the view helper
  app.locals.CDN = CDN();


  // Method for views to generate intercom.io hash
  app.locals.intercomSecureModeHash = function(str) { 
      return crypto.createHmac('sha256', intercomConfig.secretKey).update(str.toString()).digest('hex');
    };



  require('./mongoose-connection').open(app.settings.env, function(err, mongooseConnection){
    if (err) { 
      winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
    }

    winston.info('Finished mongoose config');

    app.config.mongooseConnection = mongooseConnection;

    app.config.session = {
      secret : getenv('BPN_SESSION_KEY', false),
      key : 'express.sid'
      // store : new MongoStore({
      //   //mongoose_connection : app.config.mongooseConnection
      //   db : app.config.mongooseConnection.db
      // })
    };  

    // cookieParser and session handling are needed for everyauth (inside mongooseAuth) to work  (https://github.com/bnoguchi/everyauth/issues/27)
    app.use(cookieParser());
    app.use(session(app.config.session));

    app.use(passport.initialize());
    app.use(passport.session());

    winston.info('Finished session config');
  });

  

  //flash messages are separate as of express 3
  app.use(flash());
  
  //  app.use(function(req, res, next){
  //    res.locals.flashMessages = req.flash();
  // });


  // custom "verbose errors" setting
  // which we can use in the templates
  // via settings['verbose errors']
  app.enable('verbose errors');

  // Configure options that most environments should have
  if (app.settings.env === 'local' || 
      app.settings.env === 'development' || 
      app.settings.env === 'staging') {
      
      app.use(errorHandler({ dumpExceptions: true, showStack: true }));

      // make the response markup pretty-printed
      app.locals.pretty = true;

      app.use(function(req, res, next){
        var authorization = req.headers.authorization,
          scheme;

        if (authorization){
          scheme = authorization.split(' ')[0];
        }

        switch(scheme){
          case 'BPN_DEVICE':
            return passport.authenticate('device', {session: false})(req, res, next);
          case 'BPN_API':
            return passport.authenticate('api', {session: false})(req, res, next);
          default:
            if (req.user){
              //not currently doing anything here
            }

            return next();
        }
      });
  }

  if (app.settings.env === 'development') {
    app.use(basicAuth('bitponics', '8bitpass'));
  }
  
  if (app.settings.env === 'staging'){
    
    app.enable('view cache');
  }

  if (app.settings.env === 'production'){
    app.disable('verbose errors');

    app.use(function(req, res, next){
      var authorization = req.headers.authorization,
        scheme;

      if (authorization){
        scheme = authorization.split(' ')[0];
      }
        
      switch(scheme){
        case 'BPN_DEVICE':
          return passport.authenticate('device', {session: false})(req, res, next);
        case 'BPN_API':
          return passport.authenticate('api', {session: false})(req, res, next);
        // no default. just let it flow down to the connect.basicAuth
        default:
          return next();
      }
      
    });

    app.enable('view cache');
  }

  // Expose user to the view templates
  app.use(function(req, res, next) {
    res.locals.user = req.user;
    next();
  });
};