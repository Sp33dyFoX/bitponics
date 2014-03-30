var async = require('async'),
  path    = require('path'),
  express    = require('express'),
  winston = require('winston'),
  routeUtils = require('./route-utils'),
  ModelUtils = require('../models/utils');
  
module.exports = function(app){
  
  /**
   * Intercept all admin routes and require authenticated user with property admin=true
   */
  app.all('/admin*',
    routeUtils.middleware.ensureSecure, 
    routeUtils.middleware.ensureUserIsAdmin);


  /**
   * Admin landing
   */
  app.get('/admin', function (req, res) {
    res.render('admin', {
      title: 'Bitponics Admin',
      pageType: "app-page"
    })
  });

  
  /**
   * 
   */
  app.get('/admin/generate-sample-device-request', function (req, res) {
    res.render('admin/generate-sample-device-request', {
      title: 'Bitponics Admin'
    })
  });


  /**
   * 
   */
  app.get('/admin/devices', function (req, res) {
    var DeviceModel = require('../models/device').model,
        locals = {
          title: 'Bitponics Admin | Devices',
          devices : []
        };

    DeviceModel.find()
    .select('_id serial name owner lastConnectionAt sensors')
    .populate('owner', '_id email')
    .sort('_id')
    .lean()
    .exec(function(err, deviceResults){
      if (err) { return next(err);}

      locals.devices = deviceResults;
      res.render('admin/devices', locals);
    });

  });



  /**
   * 
   */
  app.post('/admin/trigger-clearPendingNotifications', function (req, res) {
    var NotificationModel = require('../models/notification').model;
    NotificationModel.clearPendingNotifications({env : app.settings.env}, function(err, numberNotificationsAffected){
      if (err) { 
        if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); }
        return res.send(500, err);
      }
      return res.send(200, 'success, ' + numberNotificationsAffected + ' records affected');
    });
  });

  
  /**
   * 
   */
  app.post('/admin/trigger-scanForPhaseChanges', function (req, res) {
    ModelUtils.scanForPhaseChanges(require('../models/garden').model, function(err){
      if (err) { 
        winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack']));
        return res.send(500, err);
      }
      return res.send(200, 'success');
    });
  });


  /**
   * 
   */
  app.post('/admin/trigger-checkDeviceConnections', function (req, res) {
    ModelUtils.checkDeviceConnections(function(err){
      if (err) { 
        winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack']));
        return res.send(500, err);
      }
      return res.send(200, 'success');
    });
  });


  /**
   * 
   */
  app.post('/admin/trigger-processUnreadEmailPhotos', function (req, res) {
    var PhotoModel = require('../models/photo').model,
      emailFetcher = require('../utils/email-photo-fetcher');

    emailFetcher.processUnreadEmails(function(err, photos){
      console.log("processUnreadEmails result ", err, photos);
      if (err){
        return res.send(500, err);
      }
      return res.send(200, photos);
    });
  });



  /**
   * 
   */
  app.post('/admin/trigger-processNewFTPPhotos', function (req, res) {
    var PhotoModel = require('../models/photo').model,
      ftpPhotoFetcher = require('../utils/ftp-photo-fetcher');

    winston.info("/admin/trigger-processNewFTPPhotos");
    ftpPhotoFetcher.processNewPhotos(PhotoModel, function(err, photos){
      console.log("processNewPhotos result ", err, photos);
      if (err){
        return res.send(500, err);
      }
      return res.send(200, photos);
    });
  });


  
  /**
   * Get listing of all photos in database or S3
   */
  app.get('/admin/photos', function (req, res, next){
    var PhotoModel = require('../models/photo').model,
      s3Config = require('../config/s3-config'),
      knox = require('knox'),
      knoxClient = knox.createClient(s3Config);

    if (req.query.s3){
      knoxClient.list({ prefix: s3Config.photoPathPrefix }, function(err, results){
        if (err) { return next(err); }
        res.send(results);
      }); 
    } else {
      PhotoModel.find().exec(function(err, results){
        if (err) { return next(err); }
        res.send(results);
      })
    }
  });


  
  /**
   * Get the photo upload form
   */
  app.get('/admin/photos/upload', function (req, res){
    res.render('admin/upload-photo', {
      title: 'Bitponics Admin'
    });
  });

  
  
  /**
   * Process an uploaded photo by uploading it to S3 and storing a 
   * Photo document
   */
  app.post('/admin/photos/upload', routeUtils.processPhotoUpload);
  
  

  app.get('/admin/gardens', function(req, res, next){
    var GrowPlanInstanceModel = require('../models/garden').model,
        locals = {
          title: 'Bitponics Admin | Gardens',
          growPlanInstances : []
        };

    GrowPlanInstanceModel.find()
    .select('owner _id device active startDate name')
    .populate('owner', '_id name')
    .exec(function(err, growPlanInstanceResults){
      if (err) { return next(err);}

      locals.growPlanInstances = growPlanInstanceResults;
      res.render('admin/gardens', locals);
    });
  });


  app.get('/admin/grow-plans', function(req, res, next){
    var GrowPlanModel = require('../models/growPlan').growPlan.model,
        locals = {
          title: 'Bitponics Admin | Grow Plans',
          growPlans : []
        };

    GrowPlanModel.find()
    .select('createdBy _id name active activeGardenCount')
    .populate('createdBy', '_id name')
    .exec(function(err, growPlanResults){
      if (err) { return next(err);}

      locals.growPlans = growPlanResults;
      res.render('admin/grow-plans', locals);
    });
  });


  app.get('/admin/grow-systems', function(req, res, next){
    var GrowSystemModel = require('../models/growSystem').model,
        locals = {
          title: 'Bitponics Admin | Grow Systems',
          growSystems : []
        };

    GrowSystemModel.find()
    .select('createdBy _id name active photos')
    .populate('createdBy', '_id name')
    .exec(function(err, results){
      if (err) { return next(err);}

      locals.growSystems = results;
      res.render('admin/grow-systems', locals);
    });
  });



  app.use('/admin/docs', express.static(path.join(__dirname, '/../docs')));
  app.use('/admin/docs', express.directory(path.join(__dirname, '/../docs')));

  // app.get('/admin/docs', function (req, res){
  //   res.redirect('/admin/docs/');
  // });
};
