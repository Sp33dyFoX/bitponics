var connect    = require('connect'),
  express    = require('express'),
  http       = require('http'),
  net        = require('net'),
  fs         = require('fs'),
  stylus     = require('stylus'),
  nib        = require('nib'),
  mongodb    = require('mongodb'),
  mongoose   = require('mongoose'),
  MongoStore = require('connect-mongo')(express),
  passport   = require('passport'),
  csv        = require('express-csv'),
  winston    = require('winston'),
  flash      = require('connect-flash'),
  semver  = require('semver'),
  path    = require('path'),
  Session = connect.middleware.session.Session,
  cookie  = require('express/node_modules/cookie'),
  s3Config = require('../config/s3-config'),
  intercomConfig = require('../config/intercom-config'),
  crypto = require('crypto'),
  breakpoints = require('../public/assets/config/media-queries');
  

module.exports = function(app){

  /**
   * Standard config.
   * Should go first so env-specific ones are simply adding on to it
   * & guaranteeing that their middleware executes after this is all set up
   */
  app.configure(function(){

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
    app.locals({ basedir: path.join(__dirname, '/../views'), breakpoints: breakpoints });

    app.use(express.logger(':method :url :status'));


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

    
    app.use(express.bodyParser());
    app.use(express.methodOverride());

    app.use(express.favicon(__dirname + '/../public/favicon.ico', { maxAge: 2592000000 }));
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
    app.locals({ CDN: CDN() });


    // Method for views to generate intercom.io hash
    app.locals({
      intercomSecureModeHash : function(str) { 
        return crypto.createHmac('sha256', intercomConfig.secretKey).update(str.toString()).digest('hex');
      }
    });



    require('./mongoose-connection').open(app.settings.env, function(err, mongooseConnection){
      if (err) { 
        winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
      }

      winston.info('Finished mongoose config');

      app.config.mongooseConnection = mongooseConnection;

      app.config.session = {
        secret : 'somethingrandom',
        key : 'express.sid',
        store : new MongoStore({
          //mongoose_connection : app.config.mongooseConnection
          db : app.config.mongooseConnection.db
        })
      };  

      // cookieParser and session handling are needed for everyauth (inside mongooseAuth) to work  (https://github.com/bnoguchi/everyauth/issues/27)
      app.use(express.cookieParser());
      app.use(express.session(app.config.session));

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
  });

  // Configure options that most environments should have
  switch(app.settings.env){
    case 'local':
    case 'development':
    case 'staging':
      app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));

      // make the response markup pretty-printed
      app.locals({pretty: true });

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

            // return connect.basicAuth(
            //   function(basicAuthUsername, basicAuthPassword){
            //     switch (basicAuthUsername) {
            //       case "bitponics":
            //         return basicAuthPassword === "8bitpass";
            //       case "braintree":
            //         return basicAuthPassword === "dendrite";
            //     }
            //     return false;
            //   }
            // )(req, res, next);

            return next();
        }
      });
      break;
    case 'production':
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

      //we probably want to do something like this on heroku:
      //redirect to https
      // app.use(function(req, res, next) {
      //    //this is only present on heroku
      //     var schema = req.headers["x-forwarded-proto"];

      //     if (schema === "https")
      //         return next();

      //     res.redirect("https://" + req.headers.host + req.url);
      // });


      break;
  }

  app.configure('local', function(){
  });

  app.configure('development', function(){
    app.use(express.basicAuth('bitponics', '8bitpass'));
  });

  app.configure('staging', function(){
    app.use(express.errorHandler());
    app.enable('view cache');

    
    
  });

  app.configure('production', function(){
    app.use(express.errorHandler());
    app.enable('view cache');

    app.socketIOs.forEach(function(io){
      io.enable('browser client minification');  // send minified client
      io.enable('browser client etag');          // apply etag caching logic based on version number
      io.enable('browser client gzip');          // gzip the file
      io.set('log level', 1);
    });
  });

  // Expose user to the view templates
  app.use (function(req, res, next) {
    res.locals.user = req.user;
    next();
  });
};
