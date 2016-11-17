var passportSocketIo = require("passport.socketio")
    , winston = require('winston')
    , getenv = require('getenv')
    , express = require('express')
    , cookieParser = require('cookie-parser')
    // https://devcenter.heroku.com/articles/rediscloud#using-redis-from-node-js
    , redis = require("redis")
    , url = require('url')
    , redisURL = url.parse(getenv('BPN_REDIS_URL', false) || 'http://@localhost') // need empty auth on local
    //, client = redis.createClient(redisURL.port, redisURL.hostname, {no_ready_check: true});
    , password = redisURL.auth.split(":")[1];


var ioRedis = require('socket.io-redis')
  , pub    = redis.createClient(redisURL.port, redisURL.hostname, {no_ready_check: true})
  , sub    = redis.createClient(redisURL.port, redisURL.hostname, {no_ready_check: true})
  , client = redis.createClient(redisURL.port, redisURL.hostname, {no_ready_check: true});

var redisAuthCallback = function(err){
  if (err){
    winston.err(JSON.stringify(err));
  }
};

pub.auth(password, redisAuthCallback);
sub.auth(password, redisAuthCallback);
client.auth(password, redisAuthCallback);

client.set('socket.io client test-connection', 'connected');
client.get('socket.io client test-connection', function (err, reply) {
  if (err){
    winston.err(err.toString());
  } else {
    winston.info('redis connection is: ' + reply.toString()); // Will print `connected`  
  }
});


process.on('exit', function(){
  winston.info('socket.io redis closing clients')
  if (pub){
    pub.close();
  }
  if (sub){
    sub.close();    
  }
  if (client){
    client.close();    
  }
});

module.exports = function(app){
  app.socketIOs.forEach(function(io){
    
    // io.set("log level", 3);
    // var store = new SocketMongoStore({
    //   url: app.config.mongooseConnection.db
    // });
    // store.on('error', console.error);
    // io.set('store', store);
    io.adapter(ioRedis({
      pubClient : pub,
      subClient : sub,
      host: redisURL.hostname,
      port: redisURL.port
    }));


    // if (app.settings.env === 'staging'){
    //   io.enable('browser client minification');  // send minified client
    //   io.enable('browser client etag');          // apply etag caching logic based on version number
    //   io.enable('browser client gzip');          // gzip the file
    //   // io.set('log level', 1);
    // }

    // if (app.settings.env === 'production') {
    //   io.enable('browser client minification');  // send minified client
    //   io.enable('browser client etag');          // apply etag caching logic based on version number
    //   io.enable('browser client gzip');          // gzip the file
    //   // io.set('log level', 1);
    // }


    // Make socket.io handlers aware of user sessions
    // http://stackoverflow.com/questions/13095418/how-to-use-passport-with-express-and-socket-io
    // http://howtonode.org/socket-io-auth
    // http://www.danielbaulig.de/socket-ioexpress/
    // Just attach the session if found, don't reject the handshake.
    // Make individual session routes/namespaces ensure auth'ed user when necessary
    io.set('authorization', passportSocketIo.authorize({
      cookieParser: cookieParser,
      key:         app.config.session.key,
      secret:      app.config.session.secret,
      store:       app.config.session.store
    }));

    
    // /**
    //  * Global onConnection handler. Do 
    //  * these things for all socket connections
    //  */
    // io.sockets.on('connection', function (socket) {
    //   var session = socket.handshake.session;
    //   // setup an inteval that will keep the session fresh
    //   var sessionRefreshIntervalId = setInterval(function () {
    //       // reload the session (just in case something changed,
    //       // we don't want to override anything, but the age)
    //       // reloading will also ensure we keep an up2date copy
    //       // of the session with our connection.
    //       session.reload( function () { 
    //         // "touch" it (resetting maxAge and lastAccess)
    //         // and save it back again.
    //         session.touch().save();
    //       });
    //   }, 5 * 1000);

    //   socket.on('disconnect', function () {
    //     winston.info('A socket with sessionId ' + socket.handshake.sessionID
    //         + ' disconnected!');
    //     // clear the socket interval to stop refreshing the session
    //     clearInterval(sessionRefreshIntervalId);
    //   });

    // });


  });  
}
    
