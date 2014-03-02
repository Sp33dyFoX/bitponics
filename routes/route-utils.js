/**
 * @module routes/route-utils
 */


module.exports = {
	middleware : {
		ensureLoggedIn : function(req, res, next){
			if( !(req.user && req.user._id)){
				return res.redirect('/login?redirect=' + req.url);
			}
			next();
		},

    ensureLoggedIn : function(req, res, next){
      if( !(req.user && req.user._id)){
        return res.redirect('/login?redirect=' + req.url);
      }
      next();
    },
/*
    ensureDeviceKeyVerified : function(req, res, next){
    	var async = require('async'),
    			DeviceModel = require('../models/device').model;
    	// get the key on the req.user. check whether it has a device and is verified.
    	// if not verified, use the id on the request to retrieve
    	// the device. check whether device.serial matches the serial that we have
    	// on the req.deviceKey. If so, set the device & set verified & save the user
    	var deviceKey = req.deviceKey;

    	if (!deviceKey) { return next(); }

    	if (deviceKey.deviceId && deviceKey.verified){ return next(); }
			
			var id = req.params.id.replace(/:/g,'');
    	DeviceModel
      .findOne({ _id: id })
      .exec(function(err, device){
      	if (err) { return next(err); }	
      	if (device.serial === deviceKey.serial){
      
      		var dKeys = req.user.deviceKeys,
      				dKey,
      				found = false,
      				i = dKeys.length;
    			for (; i--;){
    				dKey = dKeys[i];
    				if ((deviceKey.serial === dKey.serial) && (dKey.public === deviceKey.public)){
    					found = true;
    					break;
    				}
    			}

    			if (found){
    				ModelUtils.assignDeviceToUser({
              user : req.user,
              deviceKey : dKey,
              device : device
            },
            function(err){
              return next(err);
            });
    			} else {
    				return next(new Error("Could not verify device for the serial number " + deviceKey.serial));

    },
    */


    ensureDeviceLoggedIn : function(req, res, next){
      if( !(req.user && req.user._id)){
        var error = new Error("Invalid device request auth");
        error.status = 403; // TODO: should be a 401 but for some reason server is returning an empty response if it's a 401
        error.headers = {
          "WWW-Authenticate" : "BPN_DEVICE"
        };
        return next(error);
      }
      next();
    },

		
    ensureUserIsAdmin : function(req, res, next){
			if( !(req.user && req.user._id && req.user.admin)){
				return res.redirect('/login?redirect=' + req.url);
			}
			next();
		},
		

    /**
		 * References:
		 * http://stackoverflow.com/questions/7450940/automatic-https-connection-redirect-with-node-js-express
		 * http://stackoverflow.com/questions/13186134/node-js-express-and-heroku-how-to-handle-http-and-https
		 */
		ensureSecure : (function(){
			var app = require('../app');
			if (app.settings.env === 'local'){
				return function(req, res, next){
					if (req.secure){
						return next();
					}
					res.redirect("https://" + req.headers.host + req.url); 
				}
			} else {
				// else, assumed to be hosted on heroku
				return function(req, res, next){
					if (req.headers['x-forwarded-proto'] === 'https'){
						return next();
					}
					res.redirect("https://" + req.headers.host + req.url); 
				}
			}
		}()),
    

    ensureInsecure : (function(){
      var app = require('../app');
      if (app.settings.env === 'local'){
        return function(req, res, next){
          if (!req.secure){
            return next();
          }
          res.redirect("http://" + req.headers.host + req.url); 
        }
      } else {
        // else, assumed to be hosted on heroku
        return function(req, res, next){
          if (req.headers['x-forwarded-proto'] !== 'https'){
            return next();
          }
          res.redirect("http://" + req.headers.host + req.url); 
        }
      }
    }())
	},

  
  /**
   * Providing a standard way to return JSON responses
   * 
   * @param {response} res : Express response object
   * @param {Number} statusCode : Required.
   * @param {Array|Object=} options.data : Required if options.statusCode == 200. Should be an array response for most GET queries
   * @param {Number=} options.count : Required if options.statusCode == 200. Total count of results matching query
   * @param {Number=} options.limit : Required if options.statusCode == 200. Limit on the number of results returned
   * @param {Number=} options.skip : Required if options.statusCode == 200. Number of results skipped in the query
   * @param {Error|String=} options.error : Required if options.statusCode != 200
   */
  sendJSONResponse : function(res, statusCode, options){
    res.send(statusCode, options);
  },


  
  /**
   * Check whether a user is allowed to read a certain piece of data
   * 
   * If resource is a UserModel object, returns true if user is object. 
   * If resource is any other type of object, assumes resource has "owner", "users", or "createdBy" properties
   * Assumes resource.owner and resource.users[] contain ObjectIds, not populated User documents
   *
   * @param {Object} resource
   * @param {User} user
   * @return {Boolean}
   */
  checkResourceReadAccess : function(resource, user){
    // return true if resource is public, or user is in allowed list, or user is admin.
    // else, return false
    if (resource.visibility === feBeUtils.VISIBILITY_OPTIONS.PUBLIC){
      return true;
    }
    
    var userId = user && user._id;
    if (!userId){ return false; }
    if (resource._id && resource._id.toString() === userId.toString()) { return true; }
    return (  user.admin ||
              (resource.owner ? resource.owner.equals(userId) : false) || 
              (resource.createdBy ? resource.createdBy.equals(userId) : false) || 
              resource.users.some(function(resourceUser){ return resourceUser.equals(userId);})
        );
  },


  /**
   * Check whether a user is allowed to modify a certain piece of data
   * 
   * Assumes resource has "owner" and "users" properties or that user is modifying self
   * Assumes resource.owner and resource.users[] contain ObjectIds, not populated User documents
   *
   * @param {Object} resource
   * @param {User} user
   * @return {Boolean}
   */
  checkResourceModifyAccess : function(resource, user){
    // return true if user is in allowed list or user is admin.
    // else, return false
    if (!user || !user._id){ return false; }
    var userId = user._id;
    if (resource._id && resource._id.toString() === userId.toString()) { return true; }
    return (  user.admin ||
          (resource.owner ? resource.owner.equals(userId) : false) ||
          (resource.createdBy ? resource.createdBy.equals(userId) : false) ||
          (resource.users ? resource.users.some(function(resourceUser){ return resourceUser.equals(userId);}) : false)
    );
  },

  /**
   * Check whether a request carries a logged-in user
   * @param {HTTP Request} req
   */
  isUserLoggedIn: function(req){
    return (req.user && req.user._id);
  },


  getPhoto : function(req, res, next){
    var async = require('async'),
      winston = require('winston'),
      routeUtils = require('./route-utils'),
      mongoose = require('mongoose'),
      ModelUtils = require('../models/utils'),
      PhotoModel = require('../models/photo').model,
      GrowPlanInstanceModel = require('../models/garden').model,
      routeUtils = require('./route-utils'),
      s3Config = require('../config/s3-config'),
      s3Policy = require('s3policy'),
      policyGenerator = new s3Policy(s3Config.key, s3Config.secret),
      expirationSeconds = 10;
      requirejs = require('../lib/requirejs-wrapper'),
      feBeUtils = requirejs('fe-be-utils'),
      filesKeys = Object.keys(req.files),
      now = new Date();

    async.waterfall(
      [
        function checkAuth(innerCallback){
          PhotoModel.findById(req.params.photoId)
          .select('owner ref.documentId visibility')
          .lean()
          .exec(function(err, photoResult){
            if (err) { return innerCallback(err); }
            
            // to just return redirect URL regardless:
            // if (!photoResult){ return innerCallback(null, true);}
            
            if (!photoResult){ return innerCallback(new Error("Invalid photo id"));}
            
            // first check access on the photo
            if (routeUtils.checkResourceReadAccess(photoResult, req.user)){
              return innerCallback(null, true);
            }
            
            // if that returns false, maybe the user has access by being a member of the referenced resource
            if (photoResult.ref.collectionName){
              ModelUtils.getModelFromCollectionName(photoResult.ref.collectionName).findById(photoResult.ref.documentId)
              .select('owner users visibility')
              .lean()
              .exec(function(err, referenceDocumentResult){
                if (err) { return innerCallback(err); }
                return innerCallback(null, routeUtils.checkResourceReadAccess(referenceDocumentResult, req.user));
              });
            } 
            else {
              return innerCallback(null, false);
            }
          });
        }
      ],
      function (err, isAuthorized){
        if (err) { return next(err); }
        if (isAuthorized){
          // Create a fast-expiring signed S3 url
          // http://www.arbitrarytech.com/2013/03/nodejs-library-for-client-side-uploads.html
          var s3PhotoPath = s3Config.photoPathPrefix + req.params.photoId;
          if (req.params.size){
            s3PhotoPath += '/' + req.params.size;
          }

          var url = policyGenerator.readPolicy(s3PhotoPath, s3Config.bucket, expirationSeconds);

          // let the browser cache for expirationSeconds
          res.setHeader("Expires", (new Date(Date.now() + (expirationSeconds * 1000))).toUTCString());
          return res.redirect(302, url);  
        } else {
          // TODO : create a stylized 401 page
          return res.send(401); 
        }
      }
    );
  },


  /**
   * Utility method for processing photo uploads.
   * We have multiple routes that a user can upload a photo at 
   * (gardens, growPlans, growSystems, etc)
   * 
   * Process by uploading it to S3 and storing a 
   * Photo document
   *
   * Returns a JSON response
   * 
   * @param {[File]} req.files
   * @param {feBeUtils.VISIBILITY_OPTIONS=} req.body.visibility
   * @param {[String]=} req.body.tags
   * @param {ObjectId=} req.body.gpi
   * @param {string} req.body.ref.collectionName
   * @param {string} req.body.ref.documentId
   */
  processPhotoUpload : function(req, res, next){
    var PhotoModel = require('../models/photo').model,
      async = require('async'),
      requirejs = require('../lib/requirejs-wrapper'),
      feBeUtils = requirejs('fe-be-utils'),
      filesKeys = Object.keys(req.files),
      now = new Date(),
      responseData = [];

    // to send the photo back as the response:
    //res.sendfile(req.files.photo.path);

    async.each(filesKeys, 
      function fileIterator(fileKey, iteratorCallback){
        var photo = req.files[fileKey];

        PhotoModel.createAndStorePhoto(
        {
          owner : req.user,
          originalFileName : photo.name,
          name : photo.name,
          contentType : photo.type,
          date : photo.lastModifiedDate || (new Date()),
          size : photo.size,
          tags : req.body.tags,
          gpi : req.body.gpi,
          ref : req.body.ref,
          visibility : req.body.visibility || feBeUtils.VISIBILITY_OPTIONS.PUBLIC,
          filePath : photo.path
        },
        function(err, photo){
          if (err) { 
            winston.error("ERROR IN processPhotoUpload PhotoModel.createAndStorePhoto " + JSON.stringify(err));
            return iteratorCallback(err); 
          }
          responseData.push(photo);
          return iteratorCallback();
        });
      },
      function fileLoopEnd(err){
        if (err) { return next(err); }
        return module.exports.sendJSONResponse(res, 200, { data : responseData });
      }
    );
  },

  /**
   * @param {HTTP Request} req
   * @param {function(err, cart)} callback
   */
  getCart: function(req, callback){
    var async = require('async'),
        requirejs = require('../lib/requirejs-wrapper'),
        feBeUtils = requirejs('fe-be-utils'),
        OrderModel = require('../models/order').model;

    var orderQuery = { status : feBeUtils.ORDER_STATUSES.ACTIVE_CART };

    // If it's a logged-in user, see if they have a cart open
    if(module.exports.isUserLoggedIn(req)){
      orderQuery.owner = req.user._id;
    } else {
      orderQuery.sessionId = req.sessionID;
    }

    OrderModel.findOne(orderQuery)
    .exec(function(err, cart){
      if (err) { return callback(err); }
      if (cart){
        return callback(null, cart);
      } else {
        OrderModel.create({
          owner : (module.exports.isUserLoggedIn(req) ? req.user : undefined),
          sessionId : req.sessionID,
          status : feBeUtils.ORDER_STATUSES.ACTIVE_CART
        }, 
        callback);
      }
    });
  }
};
