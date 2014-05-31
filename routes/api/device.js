var mongoose = require('mongoose'),
    Device = require('../../models/device'),
    DeviceModel = Device.model,
    DeviceUtils = Device.utils,
    GrowPlanModel = require('../../models/growPlan').growPlan.model,
    GrowPlanInstanceModel = require('../../models/garden').model,
    Action = require('../../models/action'),
    ActionModel = Action.model,
    SensorModel = require('../../models/sensor').model,
    SensorLogModel = require('../../models/sensorLog').model,
    ModelUtils = require('../../models/utils'),
    winston = require('winston'),
    async = require('async'),
    timezone = require('../../lib/timezone-wrapper'),
    routeUtils = require('../route-utils'),
    requirejs = require('../../lib/requirejs-wrapper'),
    feBeUtils = requirejs('fe-be-utils');


/**
 * module.exports : function to be immediately invoked when this file is require()'ed 
 * 
 * @param app : app instance. Will have the configs appended to a .config property. 
 */
module.exports = function(app) {

   //List devices
  app.get('/api/devices',
    routeUtils.middleware.ensureSecure,
    routeUtils.middleware.ensureUserIsAdmin,
    function (req, res, next){
      return DeviceModel.find(function (err, devices) {
        if (err) { return next(err); }
        return res.send(devices);
      });
    }
  );

  /*
   * Create single device
   *
   *  Test with:
   *  jQuery.post("/api/devices", {
   *    "id": "_id"
   *    "name": "pump",
   *    "owner": "userid",
   *    "users": ["userid", "userid1", "userid2"],
   *    "sensors": ["sensorid", "sensorid1", "sensorid2"],
   *    "outputMap": [{ 
   *        "control": "controlid",
   *        "outputId": "outlet1"
   *      },
   *      { 
   *        "control": "controlid",
   *        "outputId": "outlet2"
   *    }]
   *  }, function (data, textStatus, jqXHR) {
   *    console.log("Post response:"); console.dir(data); console.log(textStatus); console.dir(jqXHR);
   *  });
   */
  app.post('/api/devices', 
    routeUtils.middleware.ensureSecure, 
    routeUtils.middleware.ensureUserIsAdmin, 
    function (req, res, next){
      var device;
      winston.info("POST: ");
      winston.info(req.body);
      device = new DeviceModel(req.body);
      device.save(function (err) {
        if (err) { return next(err); }
        winston.info("created device");
        return res.send(device);
      });
      
    }
  );

  /*
   * Read a device
   *
   * To test:
   * jQuery.get("/api/devices/${id}", function(data, textStatus, jqXHR) {
   *     console.log("Get response:");
   *     console.dir(data);
   *     console.log(textStatus);
   *     console.dir(jqXHR);
   * });
   */
  app.get('/api/devices/:id', 
    routeUtils.middleware.ensureSecure, 
    routeUtils.middleware.ensureUserIsAdmin, 
    function (req, res, next){
      return DeviceModel.findOne({ _id: req.params.id }, function (err, device) {
        if (err) { return next(err); }
        return res.send(device);
      });
    }
  );

  /*
   * Update a device
   * All properties are optional
   * Undefined properties are left unchanged.
   * To delete a property, it should be assigned null.
   * 
   * To test:
   * jQuery.ajax({
   *     url: "/api/devices/${id}",
   *     type: "PUT",
   *     data: {
   *       "name": "updated pump"
   *     },
   *     success: function (data, textStatus, jqXHR) {
   *         console.log("Post response:");
   *         console.dir(data);
   *         console.log(textStatus);
   *         console.dir(jqXHR);
   *     }
   * });
   */
  app.put('/api/devices/:id', 
    routeUtils.middleware.ensureSecure,
    function (req, res, next){
      
      winston.info('in PUT /api/devices/' + req.params.id);
      
      DeviceModel.findById(req.params.id, function(err, device){
        if (err) { return next(err); }

        if (!routeUtils.checkResourceModifyAccess(device, req.user)){
          return res.send(401, "Only resource owner may modify a resource.");
        }

        // Update the shallow props the user can modify
        if (typeof req.body.deviceType !== 'undefined'){
          device.deviceType = req.body.deviceType;
        }

        if (typeof req.body.name !== 'undefined'){
          device.name = req.body.name;
        }

        if (typeof req.body.activeGrowPlanInstance !== 'undefined'){
          device.activeGrowPlanInstance = req.body.activeGrowPlanInstance;
        }

        if (typeof req.body.outputMap !== 'undefined'){
          device.outputMap = req.body.outputMap.map(function(output){ 
            console.log(output);
            return { 
              control: output.control ? output.control._id : null, 
              outputId: output.outputId
            }
          });
        }

        if (typeof req.body.sensors !== 'undefined'){
          device.sensors = req.body.sensors;
        }


        // Update the shallow props only an admin can modify
        if (req.user.admin){
          
          if (typeof req.body.serial !== 'undefined'){
            device.serial = req.body.serial;
          }

          if (typeof req.body.owner !== 'undefined'){
            device.owner = req.body.owner;
          }

        } // /.req.user.admin

        device.save(function(err){
          if (err) { return next(err); }

          winston.info("updated device " + req.params.id + JSON.stringify(req.body));

          return res.send(device);
        });

      });

      // var data = {
      //   deviceType: req.body.deviceType,
      //   name: req.body.name,
      //   serial: req.body.serial,
      //   owner: req.body.owner,
      //   activeGrowPlanInstance: req.body.activeGrowPlanInstance._id,
      //   // status: {
      //   //   actions: req.body.status.actions,
      //   //   activeActions: req.body.status.activeAction,
      //   //   immediateActions: req.body.status.immediateActions
      //   // },
      //   outputMap: req.body.outputMap.map(function(output){ return { control: output.control._id, outputId: output.outputId } }),
      //   sensors : req.body.sensors
      //   // sensorMap: req.body.sensorMap,
      //   // userAssignmentLogs: req.body.userAssignmentLogs,
      //   // users: req.body.users
      // }
      


      // DeviceModel.findByIdAndUpdate(req.params.id, data, function (err, device) {
      //   if (err) { return next(err); }
      //   return device.save(function (err, device) {
      //     if (err) { return next(err); }
          
      //     winston.info("updated device");

      //     //TODO: use a more generic pop helper for any obj/prop that we want to return from server to UI
      //     // ModelUtils.populateObjArray(
      //     //   device.outputMap, 
      //     //   [{'key': 'control', 'dataModel': require('./control')}], 
      //     //   function(err, obj){
      //     //     if (err) { return next(err); }
      //     //     return res.send(obj);
      //     //   }
      //     // );

      //     //For now, can just return nothing and Angular will ignore
      //     return res.send();
          
      //   });
      // });

    }
  );

  /*
   * Delete a device
   *
   * To test:
   * jQuery.ajax({
   *     url: "/api/devices/${id}", 
   *     type: "DELETE",
   *     success: function (data, textStatus, jqXHR) { 
   *         console.log("Post resposne:"); 
   *         console.dir(data); 
   *         console.log(textStatus); 
   *         console.dir(jqXHR); 
   *     }
   * });
   */
  app.delete('/api/devices/:id', 
    routeUtils.middleware.ensureSecure, 
    routeUtils.middleware.ensureUserIsAdmin, 
    function (req, res, next){
      // TODO
      return res.send('NOT IMPLEMENTED');
    }
  );

  


  /**
   * Get the current cycle data & mode for the device. 
   * Pulls from the active GrowPlanInstance that's paired with the device.
   *
   * For now, only responds with device CSV. 
   */
  app.get('/api/devices/:id/status',
    routeUtils.middleware.ensureDeviceLoggedIn,
    function (req, res, next){
      var id = req.params.id.replace(/:/g,'');
      sendDeviceStatusResponse(req, res, next, id);
    }
  );


  /**
   * Post status for this Device. sensor logs & calibration mode.
   * 
   * @param {string} req.id. mac address of device
   * @param {Object.<SensorLog>} req.body.sensors. JSON.
   * @param req.body.calib
   * @param req.body.calib.mode
   * @param req.body.calib.status
   * @param req.body.calib.message
   */
  app.post('/api/devices/:id/status',
    routeUtils.middleware.ensureDeviceLoggedIn,
    function (req, res, next){
      var id = req.params.id.replace(/:/g,''),
          reqBody = {},
          pendingSensorLog = { ts : Date.now(), logs : []},
          pendingDeviceLogs,
          calibrationStatusLog,
          device,
          growPlanInstance,
          contentTypeVersion,
          requestContentType = req.headers['content-type'];

      winston.info('/status POST headers');
      winston.info(req.headers);
      winston.info('/status POST req.rawBody');
      winston.info(JSON.stringify(req.rawBody));

      // For now, only accept requests that use the device content-type
      if(!requestContentType || requestContentType.indexOf(feBeUtils.MIME_TYPES.BITPONICS.PREFIX) === -1){
        winston.error("Invalid content type " + requestContentType + " received at " + req.url + " . Continuing execution with implied content-type.");
        // return next(new Error('Invalid Content-Type'));
      }

      
      // HACK - in certain as-yet-unknown scenarios, device firmware submits undefined content-type. Let this go through and assume v2 content-type.
      if (typeof requestContentType === 'undefined'){
        requestContentType = "application/vnd.bitponics.v2.deviceText";
        winston.error("Undefined content type " + requestContentType + " received at " + req.url + " . Request body:" + req.rawBody);
      }

      if(requestContentType.indexOf(feBeUtils.MIME_TYPES.BITPONICS.PREFIX) > -1 && req.rawBody){

        
        contentTypeVersion = requestContentType.split("/")[1].split(".")[2];

        switch(contentTypeVersion) {
          case "v1":
            // we get req.rawBody created for all requests that come from a device
            reqBody = JSON.parse(req.rawBody);
            pendingDeviceLogs = reqBody["sensors"];
            calibrationStatusLog = reqBody["calib"];
            break;
          case "v2":
            var csvRequestBodyParts = req.rawBody.split(",");
            if (req.headers['x-bpn-mode'] === "calib") {
              // [calibration mode],[calibration status]
              // we get req.rawBody created for all requests that come from a device
              calibrationStatusLog = {
                mode : csvRequestBodyParts[0],
                status : csvRequestBodyParts[1]
              };
            } else {
              // [lfull ight],[air],[water],[hum],[ph],[ec/do],[wl],[custom sensor 1],[custom sensor 2(optional)]
              var tempDeviceLogs = {};
              tempDeviceLogs.full = csvRequestBodyParts[0];
              tempDeviceLogs.air = csvRequestBodyParts[1];
              tempDeviceLogs.water = csvRequestBodyParts[2];
              tempDeviceLogs.hum = csvRequestBodyParts[3];
              tempDeviceLogs.ph = csvRequestBodyParts[4];
              tempDeviceLogs.ec = csvRequestBodyParts[5];
              
              // TODO : make sure device document specifies that it actually has a water level sensor
              tempDeviceLogs.wl = csvRequestBodyParts[6];

              pendingDeviceLogs = {};
              Object.keys(tempDeviceLogs).forEach(function(key){
                if ((typeof tempDeviceLogs[key] !== "undefined") && (tempDeviceLogs[key] !== "")){
                  try{
                    pendingDeviceLogs[key] = parseFloat(tempDeviceLogs[key]);
                  } catch(e){
                    winston.error(JSON.stringify(e, ['message', 'arguments', 'type', 'name', 'stack']));
                    delete pendingDeviceLogs[key];
                  }
                }
              });
            }
            break;
          // no default case
        }
      }

      async.waterfall(
        [
          function getDevice(callback){
            
            // TODO : in addition to setting lastConnectionAt, clear any pending device-connection-dropped Notifications

            DeviceModel
            .findByIdAndUpdate(id, 
            {
              $set : {
                lastConnectionAt : new Date()
              }
            })
            .populate('activeGrowPlanInstance')
            .exec(function(err, device){
              if (!device){ 
                return next(new Error('Attempted to log to a nonexistent device'));
              }
              if (pendingSensorLog){
                pendingSensorLog.deviceId = id;  
              }
              return callback(err, device);
            });
          },
          function logLogs(device, callback){
            // Run in series so that we don't attempt to update an outdated device document
            async.series(
              [
                function logSensorLogs(innerCallback){
                  if (!pendingDeviceLogs){
                    return innerCallback();
                  }
                  
                  
                  Object.keys(pendingDeviceLogs).forEach(function(key){
                    // Make sure the device doc actually specifies that it has the sensor. If a probe isn't plugged in, device reports garbage values for it anyway. It's lovely.
                    if (device.sensors.indexOf(key) > -1){
                      pendingSensorLog.logs.push({
                        sCode : key,
                        val : pendingDeviceLogs[key]
                      });
                    } else {
                      winston.info("discarding " + key + ","  + pendingDeviceLogs[key] + " for device " + device._id);
                    }
                  });
                  
                  winston.info('/status logSensorLogs');
                  winston.info(JSON.stringify(pendingSensorLog));

                  ModelUtils.logSensorLog(
                    {
                      pendingSensorLog : pendingSensorLog, 
                      growPlanInstance : device.activeGrowPlanInstance, 
                      device : device, 
                      user : req.user 
                    },
                    innerCallback
                  );
                },
                function logCalibrationStatusLog(innerCallback){
                  if (!calibrationStatusLog){
                    return innerCallback();
                  }
                  winston.info('/status logCalibrationStatusLog');
                  calibrationStatusLog.timestamp = calibrationStatusLog.timestamp || Date.now();

                  DeviceModel.logCalibrationStatus({
                    device : device,
                    calibrationStatusLog : calibrationStatusLog
                  },
                  innerCallback
                  );
                }
              ],
              function seriesFinal(err, results){
                winston.info('/status seriesFinal', err);
                return callback(err);
              }
            );
          }
        ],
        function waterfallFinal(err){
          winston.info('/status waterfallFinal', err);
          if (err) { return next(err); }
          winston.info('/status waterfallFinal sending device status response');
          return sendDeviceStatusResponse(req, res, next, id, device);
        }
      );
    }
  );

  
  var sendDeviceStatusResponse = function(req, res, next, id, deviceModel){
    async.waterfall([
      function getDevice(innerCallback){
        // Ensure we're working with the latest device document
        DeviceModel
        .findOne({ _id: id })
        .exec(innerCallback);
      },
      function getStatus(device, innerCallback){
        if (!device){ 
          return innerCallback(new Error('No device found for id ' + req.params.id));
        }
        
        //console.log('forceRefreshParam', req.params['forceRefresh']);
        
        return device.getStatusResponse(
          { 
            forceRefresh : req.params['forceRefresh'] ? true : false,
            contentType : req.headers['content-type']
          }, 
          innerCallback
        );
      }
    ],
    function(err, deviceStatusResponse){
      if (err) { return next(err); }

      return sendDeviceResponse({
        req : req,
        res : res,
        next : next,
        resourceName : "status",
        responseBody : deviceStatusResponse
      });
    });
  };


  /**
   *
   * @param {object} settings
   * @param {Request} settings.req : Express request object
   * @param {Response} settings.res : Express response object
   * @param {string} settings.resourceName : "refresh_status"|"cycle"|"calibration"
   * @param {string=} settings.responseBody. If set, sent and HTTP code is 200. If not set, HTTP code is 204 (no content)
   */
  var sendDeviceResponse = function(settings){
    var DEVICE_RESPONSE_END_CHAR = String.fromCharCode(7), // BELL CHAR
      req = settings.req,
      res = settings.res,
      responseBody = settings.responseBody;

    req.session.destroy();
    res.clearCookie('connect.sid', { path: '/' }); 
    res.header('X-Bpn-ResourceName', settings.resourceName);
    res.header('Content-Type', feBeUtils.MIME_TYPES.BITPONICS.V1.DEVICE_TEXT);
    res.header('Connection', 'close');

    if (responseBody){
      res.status(200);

      if (responseBody.charAt(responseBody.length - 1) !== DEVICE_RESPONSE_END_CHAR) {
        responseBody += DEVICE_RESPONSE_END_CHAR;
      }
    } else {
      // 204 No Content
      res.status(204);
    }
    
    res.send(responseBody);
  };
};
