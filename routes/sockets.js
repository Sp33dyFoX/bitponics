var DeviceModel = require('../models/device').model,
    CalibrationStatusLogModel = require('../models/calibrationStatusLog').model,
    CalibrationLogModel = require('../models/calibrationLog').model,
    GrowPlanInstanceModel = require('../models/garden').model,
    SensorLogModel = require('../models/sensorLog').model,
    TextLogModel = require('../models/textLog').model,
    NotificationModel = require('../models/notification').model,
    UserModel = require('../models/user').model,
    PhotoModel = require('../models/photo').model,
    requirejs = require('../lib/requirejs-wrapper'),
    feBeUtils = requirejs('fe-be-utils'),
    async = require('async'),
    winston = require('winston'),
    routeUtils = require('./route-utils');

module.exports = function(app){
  
  app.socketIOs.forEach(function(io){
    
    io
    .of('/calibrate')
    .on('connection', function(socket){
      var user = socket.handshake.user,
          checkIntervalId;

      if (!user.logged_in){ return; }
      //userId = session.passport.user,

      socket.on('disconnect', function () {
        clearInterval(checkIntervalId);
      });

      socket.on('ready', function (data) {
        var deviceId = data.deviceId,
            mode = data.mode,
            started = Date.now(),
            type;

        if (!deviceId) { return; }

        clearInterval(checkIntervalId);

        switch (mode) {
          case feBeUtils.CALIB_MODES["PH_4"] :
          case feBeUtils.CALIB_MODES["PH_7"] :
          case feBeUtils.CALIB_MODES["PH_10"] :
          case feBeUtils.CALIB_MODES["EC_DRY"] :
          case feBeUtils.CALIB_MODES["EC_LO"] :
          case feBeUtils.CALIB_MODES["EC_HI"] :
            DeviceModel.update({_id : deviceId }, { "status.calibrationMode" : mode }).exec();            

            checkIntervalId = setInterval(function(){
              CalibrationStatusLogModel.find({
                d : deviceId,
                ts : { $gt : started },
                m : mode
              })
              .sort('-ts')
              .limit(1)
              .exec(function (err, calibrationStatusLogResults){
                if (err) { return handleSocketError(err); }
                if (!(calibrationStatusLogResults && calibrationStatusLogResults.length)) { return; }
                
                socket.emit(
                  'device_calibration_response', 
                  calibrationStatusLogResults[0]
                );
              });
            }, 5 * 1000);
            break;
          
          default:
            // if not one of those, assume it was a "done" message.
            DeviceModel.update({_id : deviceId }, { $unset : { "status.calibrationMode" : 1 } }).exec();
            
            switch (mode){
              case feBeUtils.CALIB_MODES["PH_DONE"] :
                type = feBeUtils.CALIB_LOG_TYPES.PH;
                break;
              case feBeUtils.CALIB_MODES["EC_DONE"] :
                type = feBeUtils.CALIB_LOG_TYPES.EC;
                break;
            }

            if (type){
              CalibrationLogModel.create({
                device : deviceId,
                timestamp : Date.now(),
                type : type
              },
              function(err, newCalibrationLog){
                if (err) { return handleSocketError(err); }
              });  
            }
        }
      });
    }); // /calibrate

  


    io
    .of('/setup')
    .on('connection', function(socket){
      var //session = socket.handshake.session,
          //userId = session.passport.user,
          checkIntervalId;

      socket.on('disconnect', function () {
        clearInterval(checkIntervalId);
      });

      socket.on('ready', function (data) {
        var serial = data.serial,
            started = Date.now();

        if (!serial) { return; }

        clearInterval(checkIntervalId);
        
        checkIntervalId = setInterval(function(){
          
          UserModel.findById(socket.handshake.user._id)
          .select('deviceKeys')
          .exec(function (err, user){
            if (err){ return handleSocketError(err); }
            if (!user) { return; }

            socket.emit(
              'keys',
              user.deviceKeys
            );
          });
        }, 5 * 1000);
      });
    }); // /setup    



    /**
     * Socket for monitoring latest grow plan instance data
     * - sensor logs
     * - device status
     *
     * Does not send repeat data, only updates since the last time 
     * data were sent.
     */
    io
    .of('/latest-grow-plan-instance-data')
    .on('connection', function(socket){
      var //session = socket.handshake.session,
          //userId = session.passport.user,
          checkIntervalId;

      socket.on('disconnect', function () {
        clearInterval(checkIntervalId);
      });

      socket.on('ready', function (data) {
        var growPlanInstanceId = data.growPlanInstanceId,
            started = new Date(),
            lastChecked = started;

        if (!growPlanInstanceId) { return; }

        // before we set up the interval, 
        // make sure the user has permission on the GPI

        async.parallel(
          [
            function getGPI(innerCallback){
              GrowPlanInstanceModel.findById(growPlanInstanceId)
              .select('owner users visibility device')
              .exec(innerCallback);
            },
            function getUser(innerCallback){
              UserModel.findById(socket.handshake.user._id)
              .select('admin')
              .exec(innerCallback);
            }
          ],
          function(err, results){
            if (err) { return handleSocketError(err); }

            var growPlanInstance = results[0],
                user = results[1];

            if (!growPlanInstance){ 
              socket.disconnect();
              return; 
            }
            if (!routeUtils.checkResourceReadAccess(growPlanInstance, user)){
              winston.info("UNAUTHORIZED ATTEMPT AT SOCKET latest-grow-plan-instance-data, " + user._id.toString() + ", gpi " + growPlanInstanceId);
              socket.disconnect();
              return;
            }

            // if we've gotten here, we're good
            clearInterval(checkIntervalId);
        
            checkIntervalId = setInterval(function(){
              winston.info("SOCKET /latest-grow-plan-instance-data interval, " + user._id.toString() + ", gpi " + growPlanInstanceId);
              async.parallel(
                [
                  function getSensorLogs(innerCallback){
                    SensorLogModel.find({
                      gpi : growPlanInstanceId,
                      ts : { $gte : lastChecked }
                    })
                    .limit(1)
                    .exec(innerCallback);
                  },
                  function getTextLogs(innerCallback){
                    TextLogModel.find({
                      gpi : growPlanInstanceId,
                      ts : { $gte : lastChecked }
                    })
                    .limit(1)
                    .exec(innerCallback);
                  },
                  function getDeviceStatus(innerCallback){
                    if (!growPlanInstance.device){
                      return innerCallback();
                    }

                    // Only retrieve it if it's been updated
                    // since lastChecked and status.expires is in the future
                    // (only want to retrieve a status that will actually
                    // be sent to the device
                    DeviceModel.findOne({
                      _id : growPlanInstance.device,
                      activeGrowPlanInstance : growPlanInstanceId//,
                      //updatedAt : { $gte : lastChecked },
                      //"status.expires" : { $gte : lastChecked }
                    })
                    .select('status')
                    .populate('status.actions')
                    .populate('status.activeActions')
                    .exec(function(err, deviceResult){
                      if (err) { return innerCallback(err);}

                      if(deviceResult) {
                        deviceResult.getStatusResponse({}, function(err, deviceStatusResponse){
                          var deviceStatus = deviceResult.toObject().status;
                          deviceStatus.outputValues = JSON.parse(deviceStatusResponse).states;
                          return innerCallback(err, deviceStatus);
                        });
                      }
                    });
                  },
                  function getNotifications(innerCallback){
                    NotificationModel.find({
                      gpi : growPlanInstanceId,
                      tts : { $ne : null },
                      createdAt : { $gte : lastChecked }
                    })
                    .exec(innerCallback);
                  },
                  function getPhotos(innerCallback){
                    PhotoModel.find({
                      "ref.documentId" : growPlanInstanceId,
                      createdAt : { $gte : lastChecked }
                    })
                    .exec(innerCallback);
                  }
                ],
                function parallelFinal(err, results){
                  if (err) { return handleSocketError(err); }

                  var sensorLog = results[0][0],
                      textLog = results[1][0],
                      deviceStatus = results[2],
                      notifications = results[3],
                      photos = results[4],
                      responseData;

                  if (sensorLog || textLog || deviceStatus || notifications.length){
                    responseData = {};
                    if (sensorLog){
                      responseData.sensorLog = sensorLog;
                    }
                    if (textLog){
                      responseData.textLog = textLog;
                    }
                    if (deviceStatus){
                      responseData.deviceStatus = deviceStatus;
                    }
                    if (notifications.length){
                      responseData.notifications = notifications;
                    }
                    if (photos.length){
                      responseData.photos = photos; 
                    }
                    
                    socket.emit('update', responseData);
                  }

                  lastChecked = new Date();
                }
              );

            }, 15 * 1000);
          }
        );
        
        
      });
    }); // /latest-grow-plan-instance-data



  }); // /app.socketIOs.forEach(function(io){


  function handleSocketError(err){
    winston.error("SOCKET ERROR" + JSON.stringify(err));
    return;
  }
};
