/**
 * Lots of code pulled from http://blog.stevenlu.com/2013/03/07/using-redis-for-caching-in-nodejs/
 * 
 * @module redis-cache
 * @author Amit Kumar
 */

var redis = require("redis")
    , url = require('url')
    , redisURL = url.parse(process.env.REDISCLOUD_URL || 'http://@localhost') // need empty auth on local
    //, client = redis.createClient(redisURL.port, redisURL.hostname, {no_ready_check: true});
    , password = redisURL.auth.split(":")[1];
    

var Cache = function(){
  var client = this.client = redis.createClient(redisURL.port, redisURL.hostname, {no_ready_check: true});

  client.auth(password, function(err){
    if (err){
      winston.err(JSON.stringify(err));
    }
  });

  client.set('cache connection', 'connected');
  client.get('cache connection', function (err, reply) {
    winston.info('redis cache connection is: ' + reply.toString()); // Will print `connected`
  });

  process.on('exit', function(){
    console.log('redis-cache closing client')
    if (this.client){
      this.client.close();    
    }
  });
};

Cache.prototype = {
  /**
   * Defaults to caching the value for a timeToLive of 24 hours
   * @param {String} key
   * @param {*} value - will be stringified with JSON.stringify()
   * @param {Number} [timeToLive] - optional. milliseconds.
   */
  set : function(key, value, timeToLive){
    //console.log('this.client.setex', this.client.setex.toString())
    return this.client.setex(key, 86400000, JSON.stringify(value) );
  },
  get : function(key, callback){
    return this.client.get(key, function(err, result){
      try {
        result = JSON.parse(result);
      } catch(e){}
      return callback(err, result);
    });
  }
};



//module.Cache = Cache;

module.exports = new Cache();
