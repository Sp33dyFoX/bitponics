#! /usr/bin/env node

var environment = process.argv.slice(2)[0], //gets first cmd line arg
  cronJob = require('cron').CronJob,
  winston = require('winston'),
  mongoose = require('mongoose'),
  async = require('async'),
  moment = require('moment'),
  winston = require('winston'),
  mongooseConnection = require('./config/mongoose-connection').open(environment),
  ModelUtils = require('./models/utils'),
  NotificationModel = require('./models/notification').model,
  GrowPlanInstanceModel = require('./models/garden').model,
  PhotoModel = require('./models/photo').model,
    winston = require('./config/winston-config')('worker');


winston.info('Started worker-process.js for environment:' + environment);

mongooseConnection.open(environment);


/**
 * Once a day at 00:00
 * - phase advancement checks. Should eventually be switched to every hour to handle all timezones
 *
 */
new cronJob('0 0 0 * * *', function(){
    var now = moment();
    winston.info(environment + ' Every day at 00:00, starting at ' + now.format());
    
    winston.info(environment + ' ModelUtils.scanForPhaseChanges');
    
    ModelUtils.scanForPhaseChanges(GrowPlanInstanceModel, function(err, count){
      if (err) { winston.info(err); }
      var finishedEnvironmentAt = moment();
      winston.info(environment + ' ModelUtils.scanForPhaseChanges started at ' + now.format() + ', ended at ' + finishedEnvironmentAt.format() + ', duration ' + now.diff(finishedEnvironmentAt) + 'ms');
      winston.info((count || 0) + " records affected");
    });
    
}, null, true, "America/New_York");


/**
 * Every 20 minutes
 * - Check device connections
 */
 new cronJob('00 */20 * * * * ', function(){
    var now = moment();

    winston.info(environment + ' Every 20 minutes, starting at ' + now.format());

    winston.info(environment + ' ModelUtils.checkDeviceConnections');
    
    ModelUtils.checkDeviceConnections(function(err, count){
        if (err) { winston.info(err); }
        var finishedEnvironmentAt = moment();
        winston.info(environment + ' ModelUtils.checkDeviceConnections started at ' + now.format() + ', ended at ' + finishedEnvironmentAt.format() + ', duration ' + now.diff(finishedEnvironmentAt) + 'ms');
        winston.info((count || 0) + " records affected");
    });

}, null, true, "America/New_York");


/**
 * Every 10 minutes
 * // - Fetch FTP photos
 * - Fetch email photos
 */
 new cronJob('00 */10 * * * * ', function(){
    var now = moment(),
    // ftpPhotoFetcher = require('./utils/ftp-photo-fetcher'),
        emailPhotoFetcher = require('./utils/email-photo-fetcher');

    winston.info(environment + ' Every 10 minutes, starting at ' + now.format());

  if (environment === 'production'){
    
        // winston.info(environment + ' ftpPhotoFetcher.processNewPhotos')

        // ftpPhotoFetcher.processNewPhotos(PhotoModel, function(err, results){
        //     if (err) { winston.info(err); }
        //     var finishedEnvironmentAt = moment();
        //     winston.info(environment + 'ftpPhotoFetcher.processNewPhotos started at ' + now.format() + ', ended at ' + finishedEnvironmentAt.format() + ', duration ' + now.diff(finishedEnvironmentAt) + 'ms');
        //     winston.info((results ? results.length : 0) + " images processed");
        // });

        winston.info(environment + ' emailPhotoFetcher.processUnreadEmails')
        
        emailPhotoFetcher.processUnreadEmails(function(err, results){
            if (err) { winston.info(err); }
            var finishedEnvironmentAt = moment();
            winston.info('production emailPhotoFetcher.processUnreadEmails started at ' + now.format() + ', ended at ' + finishedEnvironmentAt.format() + ', duration ' + now.diff(finishedEnvironmentAt) + 'ms');
            winston.info((results ? results.length : 0) + " email images processed");
        });
    }

}, null, true, "America/New_York");



/**
 * Every 1 minute
 * - Clearing pending Notifications
 */
 new cronJob('00 */1 * * * * ', function(){
    var now = moment();
    winston.info(environment + ' Every 1 minutes, starting at ' + now.format());

  
    winston.info(environment + ' NotificationModel.clearPendingNotifications');

    NotificationModel.clearPendingNotifications({env: environment}, function(err, count){
    if (err) { winston.info(err); }
      
      var finishedEnvironmentAt = moment();
      winston.info(environment + ' ModelUtils.clearPendingNotifications started at ' + now.format() + ', ended at ' + finishedEnvironmentAt.format() + ', duration ' + now.diff(finishedEnvironmentAt) + 'ms');
      winston.info((count || 0) + " records affected");
    });
    
}, null, true, "America/New_York");




winston.info('Started worker');


setInterval(function(){
  var x = 'break here';
}, 1000);
