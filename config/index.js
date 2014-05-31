var winston = require('winston'),
    appDomains = require('./app-domain-config');

/**
 * module.exports : function to be immediately invoked when this file is require()'ed 
 * 
 * @param app : app instance. Will have the configs appended to a .config property. 
 */
module.exports = function(app, callback) {
  //var // on local machine, routing bitponics.com to localhost in order to have external oauth's (goog, fb) route back without complaining 
      //PORT = process.env.PORT || 80, // run node as sudo to use port 80
      //HOST = process.env.HOST || 'bitponics.com', // update host file with the line "127.0.0.1 bitponics.com"

  winston.info('NODE_ENV ');

  var appDomain = process.env.BITPONICS_APP_DOMAIN,
      appUrl;

  // TODO: app.settings.env automatically reads from process.env.NODE_ENV & defaults to 'development'.
  //       For some reason, process.env isn't reading my environment's NODE_ENV variable.
  //       Setting it manually for now, but figure out what's going on
  app.settings.env = process.env.NODE_ENV || 'local';
  
  require('./winston-config')(app.settings.env);

  winston.info(app.settings.env);
  
  winston.info('Connecting to mongoose');
	
  appDomain = appDomain || appDomains[app.settings.env];
  
  appUrl = 'http://' + appDomain;

  winston.info("ENVIRONMENT VARIABLES");
  winston.info(JSON.stringify(process.env));
      
  app.config = {
    //auth : require('./auth-config'),
    css : require('./css-config'),
    appUrl : appUrl,
    secureAppUrl : 'https://' + appDomain,
    appDomain : appDomain,
    js : require('./js-config')
  };


  // locals are passed down to the views
  app.locals({
    title : 'Bitponics',
    className: undefined
  });


  if (app.settings.env === 'local'){
    var fs = require('fs'),
        https = require('https');
        
    var httpOptions = {
      key: fs.readFileSync('config/ssl/local/server.key'),
      cert: fs.readFileSync('config/ssl/local/server.crt')
    };

    var httpsServer = https.createServer(httpOptions, app);

    app.config.https = {
      server : httpsServer,
      io : require('socket.io').listen(httpsServer)
    };

    app.socketIOs.push(app.config.https.io);
  }

  require('./mongoose-connection').open(app.settings.env);

  require('./auth-config')(app);
  require('./app-config')(app);
  
  require('../config/socket-config')(app);
  winston.info('Finished socket config');

  // warm up the redis cache
  var cache = require('../lib/redis-cache');
  cache.set('application started', new Date(), 1);
  cache.get('application started', function(err, value){
    winston.info('cache response: application started ' + value);
  });

  require('../lib/mixpanel-wrapper').init(app);

	// This has to occur after the connection has been set up
	require('../models/user').setEmailVariables(app.config);
};

