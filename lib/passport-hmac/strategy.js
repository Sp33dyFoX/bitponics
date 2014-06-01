/**
 * Module dependencies.
 */
var passport = require('passport')
  , uri = require('url')
  , crypto = require('crypto')
  , util = require('util')
  , winston = require('winston')
  , async = require('async')
  , DeviceModel = require('../../models/device').model
  , ModelUtils = require('../../models/utils');


function Strategy(options) {
  if (!options.getUser) throw new Error('HMAC authentication strategy requires a getUser function');
  
  passport.Strategy.call(this);
  this.name = options.name || 'hmac';
  this.scheme = options.scheme || 'HMAC';
  this.headerSaltField = options.headerSaltField;
  this._getUser = options.getUser;
  this._realm = 'Users';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);


/**
 * Authenticate request based on the contents of a HTTP Authorization
 * header
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req) {
  var self = this,
      parts,
      credentials,
      scheme,
      authHeader = req.headers['authorization'],
      publicKey,
      hmacSignature,
      headerSaltValue = '';

  winston.info('REQUEST HEADERS: ' + JSON.stringify(req.headers));
      
  if (!authHeader) {
    return this.fail(400);
  }

  parts = authHeader.split(' ');
  scheme = parts[0];
  credentials = parts[1].split(':');
  
  
  if (!scheme.toLowerCase() === this.scheme.toLowerCase()) {
    return this.fail(400)
  } 
  

  if (!credentials.length === 2) {
    return this.fail(this._challenge('Invalid credential format'));
  }

  if (this.headerSaltField){
    headerSaltValue = req.headers[this.headerSaltField.toLowerCase()];

    if (!headerSaltValue) {
      return this.fail(this._challenge('Missing header field ' + this.headerSaltField));   
    }
  }

  publicKey = credentials[0];
  hmacSignature = credentials[1];

  this._getUser(publicKey, function(err, user, matchingKey) {
    var hmac,
        hmacSource,
        computedSignature,
        privateKey;

    if (err) { return self.error(err); }
    if (!user) { return self.fail(self._challenge('bpn_access_token_rejected')); }
    if (!matchingKey) { return self.fail(self._challenge('bpn_access_token_rejected')); }
    
    privateKey = matchingKey.private;

    // HACK (slight hack) : Assume this method is only called for device API requests. There
    // may be a cleaner way to inject the deviceId in, but this will suffice for now
    var deviceIdBeginningIndex = (req.url.indexOf("api/devices/") + "api/devices/".length);
    var deviceIdEndIndex = deviceIdBeginningIndex + (req.url.substr(deviceIdBeginningIndex).indexOf("/"));
    if (deviceIdEndIndex < deviceIdBeginningIndex){
      deviceIdEndIndex = req.url.length;
    }
    var deviceId = req.url.substring(deviceIdBeginningIndex, deviceIdEndIndex).replace(/:/g,'');
    

    async.waterfall(
      [
        function verifyKey(innerCallback){
          // Verified keys get the deviceId assigned and verified set to true
          if (matchingKey.deviceId === deviceId && matchingKey.verified === true){
            return innerCallback(null, true);
          }

          // if the key is verified but the deviceId doesn't match, something has gone awry. 
          // Device is sending a public key that doesn't match its id. 
          // shouldn't ever happen but need to handle all cases here
          if (matchingKey.verified){
            winston.info("PUBLIC KEY IS VERIFIED BUT HAS A DIFFERENT DEVICE ID, " + matchingKey.deviceId + ", THAN EXPECTED " + deviceId);
            return innerCallback(null, false);
          }

          // else this is a key that's pending verification, so retrieve the device 
          // and verify the key
          DeviceModel
          .findOne({ _id: deviceId })
          .exec(function(err, device){
            if (err) { return self.error(err); }  
            
            if (!device){
              winston.info("DEVICE API AUTH COULD NOT FIND DEVICE " + deviceId);
              return innerCallback(null, false);
            }

            if (device.serial !== matchingKey.serial){
              winston.info("FAILED KEY VERIFICATION ATTEMPTED ON DEVICE " + deviceId + ", deviceKey.public " + matchingKey.public);
              return innerCallback(null, false);
            }
          
            var dKeys = user.deviceKeys,
                dKey,
                found = false,
                i = dKeys.length;
            for (; i--;){
              dKey = dKeys[i];
              if ((matchingKey.serial === dKey.serial) && (dKey.public === matchingKey.public)){
                found = true;
                break;
              }
            }

            if (found){
              winston.info("ASSIGNING DEVICE " + deviceId + " TO USER " + user._id);
              ModelUtils.assignDeviceToUser({
                user : user,
                deviceKey : dKey,
                device : device
              },
              function(err){
                if (err) { return self.error(err); }
                return innerCallback(null, true);
              });
            } else {
              winston.info("FAILED KEY VERIFICATION ATTEMPTED ON DEVICE " + deviceId + ", deviceKey.public " + matchingKey.public);
              return innerCallback(null, false);
            }
          });
        },
        function processVerification(passedVerification, innerCallback){
          if (!passedVerification){
            return innerCallback(null, false);
          }

          winston.info('PASSED KEY VERIFICATION');
          winston.info('PRIVATE KEY: ' + privateKey);
          hmac = crypto.createHmac('sha256', privateKey)

          winston.info('HMAC COMPARISON HAPPENING NOW');
          winston.info('HMAC req.rawBody: ' + req.rawBody);
          winston.info('HMAC headerSaltValue: ' + headerSaltValue);
          
          hmacSource = req.method + ' ' + req.url + ' HTTP/' + req.httpVersion + req.rawBody + headerSaltValue;
          
          winston.info('HMAC SOURCE: ' + hmacSource);
          computedSignature = hmac.update(hmacSource).digest('hex');
          winston.info('HMAC PRIVATE KEY: ' + privateKey);
          winston.info('HMAC PROVIDED SIGNATURE: ' + hmacSignature);
          winston.info('HMAC COMPUTED SIGNATURE: ' + computedSignature);
          if (hmacSignature !== computedSignature) {
            return self.fail(self._challenge('signature_invalid'));
          }

          req.deviceKey = matchingKey;

          return innerCallback(null, true);
        }
      ],
      function (err, succeededAuthentication){
        if (err) { return self.error(err)}

        if (succeededAuthentication){
          return self.success(user);  
        } else {
          winston.info("MISMATCHING KEY ATTEMPTED ON DEVICE " + deviceId);
          return self.fail(self._challenge('bpn_access_token_rejected'));
        }
      }
    );

    

  });
}

/**
 * Authentication challenge.
 *
 * References:
 *  - [Problem Reporting](http://wiki.oauth.net/w/page/12238543/ProblemReporting)
 *
 * @api private
 */
Strategy.prototype._challenge = function(problem, advice) {
  var challenge = this.scheme;
  if (problem) {
    challenge += ', hmac_problem="' + encodeURIComponent(problem) + '"';
  }
  if (advice && advice.length) {
    challenge += ', hmac_problem_advice="' + encodeURIComponent(advice) + '"';
  }
  winston.warn('FAILED AUTH ' + challenge);
  return challenge;
}


module.exports = Strategy;
