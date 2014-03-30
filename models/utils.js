/**
 * @module models/Utils
 */

module.exports = {};

/**
 * Log a sensorLog to the sensorLog collection as well as the
 * device.recentSensorLogs & growPlanInstance.recentSensorLogs.
 * Increment GardenPreaggregation
 * Verify against IdealRanges and trigger Actions if necessary.
 *
 * @alias module:models/Utils.logSensorLog
 * @function
 * @static
 * 
 * @param {Object} options.pendingSensorLog - object in a format matching SensorLogSchema. gpid is optional, and if omitted, the log will only be logged to the device's recentSensorLogs
 * @param {GrowPlanInstance} [options.growPlanInstance] - GrowPlanInstance model instance on which to log this to recentSensorLogs. Optional since we may want to log logs for a device during device setup, before there's been a GPI pairing.
 * @param {Device} [options.device] - Device Model instance on which to log this to recentSensorLogs
 * @param {User} options.user - Only needs the timezone property populated.
 * @param {function(err)} callback 
 */
module.exports.logSensorLog = function (options, callback){
  const GrowPlanModel = require('./growPlan').growPlan.model,
      async = require('async'),
      SensorLogModel = require('./sensorLog').model,
      GardenPreaggregationModel = require('./gardenPreaggregation').model,
      requirejs = require('../lib/requirejs-wrapper'),
      feBeUtils = requirejs('fe-be-utils'),
      moment = require('moment'),
      timestamp;

  var pendingSensorLog = options.pendingSensorLog,
      growPlanInstance = options.growPlanInstance,
      device = options.device,
      user = options.user,
      timezone = user.timezone,
      activeGrowPlanInstancePhase;

  if (growPlanInstance){
    activeGrowPlanInstancePhase = growPlanInstance.phases.filter(function(phase){ return phase.active; })[0];
    pendingSensorLog.gpi = growPlanInstance._id;
  }

  if (!(pendingSensorLog instanceof SensorLogModel)) {
    pendingSensorLog = new SensorLogModel(pendingSensorLog);
  }

  if (!pendingSensorLog.ts){
    pendingSensorLog.ts = new Date();
  }

  timestamp = pendingSensorLog.ts;
  
  async.parallel(
    [
    function saveToDevice(innerCallback){
      if (!device){ return innerCallback(); }
      // for some goddamn mysterious reason, unshift is causing pendingSensorLog.logs to 
      // be an empty array when persisted to device.recentSensorLogs. 
      // Only push is getting the whole thing in. Gotta
      // abandon desc-sorted recentSensorLogs for now because of that
      //console.log(pendingSensorLog);
      //device.recentSensorLogs.unshift(pendingSensorLog.toObject());
      //device.save(innerCallback);
      return innerCallback();
    },
    function saveToGPI(innerCallback){
      if (!growPlanInstance) { return innerCallback();}
      //garden.recentSensorLogs.push(pendingSensorLog);          
      //garden.save(innerCallback);
      innerCallback();
    },
    function saveSensorLog(innerCallback){
      pendingSensorLog.save(innerCallback);
    },
    function updateGardenPreaggregation(innerCallback){
      if (!growPlanInstance){ return innerCallback(); }
      
      var timestampMoment = moment.utc(timestamp),
        dateMoment = moment.utc(timestamp).startOf('day'),
        date = dateMoment.toDate(),
        hour = timestampMoment.hour(),
        minute = timestampMoment.minute(),
        fiveMinutes = feBeUtils.floorToNearestMultiple(minute, 5);
        
      var incrementClauses = {};
      
      pendingSensorLog.logs.forEach(function(log){
        incrementClauses["totals.sensors." + log.sCode + ".sum"] = log.val;
        incrementClauses["totals.sensors." + log.sCode + ".count"] = 1;
        incrementClauses[hour.toString() + ".totals.sensors." + log.sCode + ".sum"] = log.val;
        incrementClauses[hour.toString() + ".totals.sensors." + log.sCode + ".count"] = 1;
        incrementClauses[hour.toString() + "." + fiveMinutes.toString() + ".totals.sensors." + log.sCode + ".sum"] = log.val;
        incrementClauses[hour.toString() + "." + fiveMinutes.toString() + ".totals.sensors." + log.sCode + ".count"] = 1;
      });

      if (device){
        incrementClauses["totals.deviceLogCount"] = 1;
        incrementClauses[hour.toString() + ".totals.deviceLogCount"] = 1;
        incrementClauses[hour.toString() + "." + fiveMinutes.toString() + ".totals.deviceLogCount"] = 1;
      }

      GardenPreaggregationModel.update(
        { g: growPlanInstance._id, date : date }, 
        {
          $set : {
            g: growPlanInstance._id, 
            date : date
          },
          $inc: incrementClauses
        }, 
        { upsert: true },
        innerCallback
      );
    },
    function checkIdealRanges(innerCallback){
      if (!growPlanInstance) { return innerCallback();}
      GrowPlanModel
      .findById(growPlanInstance.growPlan)
      .exec(function(err, growPlan){
        if (err){ return innerCallback(err); }
        if (!growPlan){ return new Error('GrowPlanInstance.growPlan not found'); }
        
        var phase = growPlan.phases.filter(function(item){ return item._id.equals(activeGrowPlanInstancePhase.phase); })[0];
        if (!phase){ return new Error('Active phase not found for this grow plan instance'); }
        if (!(phase.idealRanges && phase.idealRanges.length)){ return innerCallback();}
        

        var phaseDaySummary = {
          status : feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD,
          sensorSummaries : {},
          date : pendingSensorLog.ts
        };


        // Run this in series so that idealRange triggers don't stumble over each other with attempting to update an outdated
        // device document resulting in mongo VersionErrors
        async.eachSeries(
          pendingSensorLog.logs, 
          function(log, iteratorCallback){
            var idealRange = phase.idealRanges.filter(function(idealRange){ return idealRange.sCode == log.sCode})[0],
                valueRange,
                message = '';

            phaseDaySummary.sensorSummaries[log.sCode] = feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD;

            if (!idealRange){ return iteratorCallback(); }
            valueRange = idealRange.valueRange;
            
            if (log.val < valueRange.min) {
              if (!idealRange.checkIfWithinTimespan(timezone, pendingSensorLog.ts)){ return iteratorCallback(); }
              
              phaseDaySummary.sensorSummaries[log.sCode] = feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD;
              phaseDaySummary.status = feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD;

              module.exports.processIdealRangeViolation(
                {
                  idealRange : idealRange,
                  sensorValue : log.val,
                  growPlanPhase : phase,
                  timestamp : pendingSensorLog.ts,
                  growPlanInstance : growPlanInstance, 
                  device : device, 
                  user : user
                },
                iteratorCallback
              );

            } else if (log.val > valueRange.max){
              if (!idealRange.checkIfWithinTimespan(timezone, pendingSensorLog.ts)){ return iteratorCallback(); }
              
              phaseDaySummary.sensorSummaries[log.sCode] = feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD;
              phaseDaySummary.status = feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD;
              
              //message = log.sCode + ' is above recommended maximum of ' + valueRange.max;
              
              module.exports.processIdealRangeViolation(
                {
                  idealRange : idealRange,
                  sensorValue : log.val,
                  growPlanPhase : phase,
                  timestamp : pendingSensorLog.ts,
                  growPlanInstance : growPlanInstance, 
                  device : device, 
                  user : user
                },
                iteratorCallback
              );

            } else { 
              return iteratorCallback(); 
            }
          },
          function(err){
            if (err) { return innerCallback(err);}

            growPlanInstance.mergePhaseDaySummary(
              {
                growPlanInstancePhase : activeGrowPlanInstancePhase,
                daySummary : phaseDaySummary
              },
              innerCallback
            );
          }
        );
      });
    }
    ], 
    function parallelFinal(err, results){
      console.log("RESULTS[3]", results[3])
      return callback(err, results);
    }
  );
};




/**
 * Create a Notification and triggers an ImmediateAction if defined
 * Should only be called after verifying an IdealRange was violated.
 *
 * @alias module:models/Utils.processIdealRangeViolation
 * @function
 * @static
 * 
 * @param {IdealRange} options.idealRange : required
 * @param {Number} options.sensorValue : required
 * @param {Date} options.timestamp : required
 * @param {Phase} options.growPlanPhase : required
 * @param {GrowPlanInstance} options.growPlanInstance : GrowPlanInstanceModel 
 * @param {Device=} options.device : optional. Device of GrowPlanInstance. Should be full DeviceModel doc, not just an ObjectId
 * @param {User} options.user : required. owner of GrowPlanInstance
 * @param {function(err, { notification : Notification, immediateAction : ImmediateAction })} callback
 */
module.exports.processIdealRangeViolation = function (options, callback){
  var idealRange = options.idealRange,
      valueRange = options.idealRange.valueRange,
      sensorValue = options.sensorValue,
      NotificationModel = require('./notification').model,
      winston = require('winston'),
      async = require('async'),
      requirejs = require('../lib/requirejs-wrapper'),
      feBeUtils = requirejs('fe-be-utils'),
      message;
    
  
  if (sensorValue < valueRange.min) {
    if (options.idealRange.actionBelowMin){
      module.exports.triggerImmediateAction(
        {
          growPlanInstance : options.growPlanInstance, 
          device : options.device, 
          actionId : idealRange.actionBelowMin,
          immediateActionMessage : (idealRange.sCode + ' is below recommended minimum of ' + valueRange.min),
          user : options.user,
          idealRangeViolation : {
            gpPhaseId : options.growPlanPhase._id,
            sensorValue : options.sensorValue,
            idealRangeId : idealRange._id,
            timestamp : options.timestamp
          }
        },
        callback
      );  
    } else {
      NotificationModel.create(
        {
          users : options.growPlanInstance.users,
          type : feBeUtils.NOTIFICATION_TYPES.ACTION_NEEDED,
          gpi : options.growPlanInstance._id,
          trigger : feBeUtils.NOTIFICATION_TRIGGERS.IDEAL_RANGE_VIOLATION,
          triggerDetails : {
            gpPhaseId : options.growPlanPhase._id,
            sensorValue : options.sensorValue,
            idealRangeId : options.idealRange._id,
            timestamp : options.timestamp
          }
        }, 
        function(err, notification){
          return callback(err, { notification : notification });
        }
      );
    }
    
  } else if (sensorValue > valueRange.max){

    if (options.idealRange.actionAboveMax){
      module.exports.triggerImmediateAction(
        {
          growPlanInstance : options.growPlanInstance, 
          device : options.device, 
          actionId : idealRange.actionAboveMax,
          immediateActionMessage : (idealRange.sCode + ' is above recommended max of ' + valueRange.max),
          user : options.user,
          idealRangeViolation : {
            gpPhaseId : options.growPlanPhase._id,
            sensorValue : options.sensorValue,
            idealRangeId : idealRange._id,
            timestamp : options.timestamp
          }
        },
        callback
      );  
    } else {
      NotificationModel.create(
        {
          users : options.growPlanInstance.users,
          type : feBeUtils.NOTIFICATION_TYPES.ACTION_NEEDED,
          gpi : options.growPlanInstance._id,
          trigger : feBeUtils.NOTIFICATION_TRIGGERS.IDEAL_RANGE_VIOLATION,
          triggerDetails : {
            gpPhaseId : options.growPlanPhase._id,
            sensorValue : options.sensorValue,
            idealRangeId : options.idealRange._id,
            timestamp : options.timestamp
          }
        }, 
        function(err, notification){
          return callback(err, { notification : notification });
        }
      );
    }

  } else {
    return callback(new Error('ModelUtils.processIdealRangeViolation was called without an actual violation'));
  }
};


/**
 * Trigger an immediate action. Can be called manually or because of an IdealRange violation.
 *
 * If there's an assumedociated control for the action, expires the override with the next iteration of an action cycle on the given control.
 *
 * @alias module:models/Utils.triggerImmediateAction
 * @function
 * @static
 *
 * @param {object} options  
 * @param {GrowPlanInstance} options.growPlanInstance : GrowPlanInstanceModel. Should have populated "owner" (just need timezone) 
 * @param {ObjectId|string} options.actionId : ObjectID 
 * @param {Device=} options.device : optional. Device of GrowPlanInstance. Should be full DeviceModel doc, not just an ObjectId
 * @param {string} options.immediateActionMessage : message to log with the immediateAction
 * @param {User} options.user : required. owner of GrowPlanInstance
 * @param {Object} options.idealRangeViolation : optional. Set if triggered by idealRangeViolation, else this is assumed to be triggered manually. Used to define Notification trigger
 * @param {function(err, {{immediateAction: ImmediateAction, notification : Notification }} )} callback 
 */
module.exports.triggerImmediateAction = function (options, callback){
  var Device = require('./device'),
    DeviceModel = Device.model,
    DeviceUtils = Device.utils,
    GrowPlanInstanceModel = require('./garden').model,
    GrowPlanModel = require('./growPlan').growPlan.model,
    Action = require('./action'),
    ActionModel = Action.model,
    ImmediateActionModel = require('./immediateAction').model,
    NotificationModel = require('./notification').model,
    winston = require('winston'),
    async = require('async'),
    tz = require('../lib/timezone-wrapper'),
    i18nKeys = require('../i18n/keys'),
    requirejs = require('../lib/requirejs-wrapper'),
    feBeUtils = requirejs('fe-be-utils'),
    getObjectId = module.exports.getObjectId;

  var growPlanInstance = options.growPlanInstance,
      device = options.device, 
      actionId = options.actionId,
      immediateActionMessage = options.immediateActionMessage,
      user = options.user,
      timezone = user.timezone,
      action;

  if (growPlanInstance.device && !device){ return callback(new Error('If a GrowPlanInstance has a device, Device document must be passed into triggerImmediateAction'))}

  ActionModel.findById(actionId, function(err, actionResult){
    if (err) { return callback(err);}
    if (!actionResult) { return callback(new Error(i18nKeys.get('Invalid action id')));}

    action = actionResult;

    // calculate when the immediateAction should expire.
    var now = new Date(),
        nowAsMilliseconds = now.valueOf(),
        expires = nowAsMilliseconds + (365 * 24 * 60 * 60 * 1000),
        actionHasDeviceControl = false;

    winston.info("IN triggerImmediateAction: gpi " + growPlanInstance._id + ", action " + actionId + ", device " + (device ? device._id : ''));

    async.series(
      [
        function(innerCallback){
          if (!action.control){ return innerCallback(); }

          // If we're here, action does have a control
          winston.info("IN triggerImmediateAction: gpi " + growPlanInstance._id + ", action " + actionId + ", device " + (device ? device._id : '') + ", action has control");
          if (device){
            // get any other phase actions that exist for the same control.
            var growPlanInstancePhase = growPlanInstance.phases.filter(function(phase) { return phase.active;})[0];
            
            actionHasDeviceControl = device.outputMap.some(
              function(outputMapItem){
                return getObjectId(outputMapItem.control).equals(getObjectId(action.control));
              }
            );
        
            winston.info("IN triggerImmediateAction: gpi " + growPlanInstance._id + ", action " + actionId + ", device " + (device ? device._id : '') + ", action has device control " + actionHasDeviceControl);

            // Expire the immediateAction on the next cycle of a baseline phase action
            ActionModel.findOne()
            .where('_id')
            .in(device.status.actions)
            .where('control')
            .equals(action.control)
            .exec(function(err, actionResult){
              if (err) { return innerCallback(err);}
              if (!actionResult){ return innerCallback(); }
              var cycleRemainder = ActionModel.getCycleRemainder(now, growPlanInstancePhase, actionResult, timezone);
              expires = nowAsMilliseconds + cycleRemainder;
              return innerCallback();  
            });

          } else {
            GrowPlanModel.findById(growPlanInstance.growPlan)
            .populate('phases.actions')
            .exec(function(err, growPlan){
                if (err) { return innerCallback(err);}
                var growPlanInstancePhase = growPlanInstance.phases.filter(function(phase){return phase.active;})[0];
                var phase = growPlan.phases.filter(function(phase){return phase._id.equals(growPlanInstancePhase.phase);})[0];
                ActionModel.findOne()
                .where('_id')
                .in(phase.actions)
                .where('control')
                .equals(action.control)
                .exec(function(err, actionResult){
                  if (err) { return innerCallback(err);}
                  if (!actionResult){ return innerCallback(); }
                  var cycleRemainder = ActionModel.getCycleRemainder(now, growPlanInstancePhase, actionResult, timezone);
                  expires = nowAsMilliseconds + cycleRemainder;
                  return innerCallback();  
                });
              }
            );            
          }
        }
      ],
      function(err, result){
        if (err) { return callback(err); }
        
        var notificationType,
            notificationTrigger = (options.idealRangeViolation ? feBeUtils.NOTIFICATION_TRIGGERS.IDEAL_RANGE_VIOLATION : feBeUtils.NOTIFICATION_TRIGGERS.IMMEDIATE_ACTION),
            notificationTriggerDetails = options.idealRangeViolation || {};

        notificationTriggerDetails.actionId = actionId;
        notificationTriggerDetails.handledByDeviceControl = actionHasDeviceControl;


        winston.info('Logging immediateAction for gpi ' + growPlanInstance._id + ' "' + immediateActionMessage + '", action ' + action._id);
        
        if (!actionHasDeviceControl){ 
          notificationType = feBeUtils.NOTIFICATION_TYPES.ACTION_NEEDED;
        } else {
          notificationType = feBeUtils.NOTIFICATION_TYPES.INFO;
        }

        // In parallel: 
        // log to ImmediateAction
        // log a Notification, and 
        // if device has a relevant control, refresh its commands
        async.series(
          [
            function createImmediateAction(innerCallback){
              winston.info("IN triggerImmediateAction: gpi " + growPlanInstance._id + ", action " + actionId + ", device " + (device ? device._id : '') + ", creating an ImmediateAction");
              ImmediateActionModel.create({
                  gpi : growPlanInstance._id,
                  message : immediateActionMessage,
                  timeRequested : now,
                  action : action,
                  // TODO : handle expires for the no-device case
                  expires : expires
                },
                function(err, immediateAction){
                  notificationTriggerDetails.immediateActionId = immediateAction._id;
                  return innerCallback(err, immediateAction);
                });
            },
            function createNotification(innerCallback){
              winston.info("IN triggerImmediateAction: gpi " + growPlanInstance._id + ", action " + actionId + ", device " + (device ? device._id : '') + ", creating Notification");
              NotificationModel.create(
                {
                    users : growPlanInstance.users,
                    growPlanInstance : growPlanInstance,
                    timeToSend : now,
                    type : notificationType,
                    trigger : notificationTrigger,
                    triggerDetails : notificationTriggerDetails
                },
                innerCallback
              );
            },
            function updateDevice(innerCallback){
              winston.info("IN triggerImmediateAction: gpi " + growPlanInstance._id + ", action " + actionId + ", device " + (device ? device._id : '') + ", checking actionHasDeviceControl " + actionHasDeviceControl);
              if (!actionHasDeviceControl){ 
                return innerCallback();
              }
              
              winston.info('Calling refreshStatus for device : ' + device._id.toString());
              DeviceModel.findById(device._id)
              .exec(function(err, deviceResult){
                if (err) { return innerCallback(err); }
                return deviceResult.refreshStatus(innerCallback);
              });
              
              
            }
          ],
          function (err, results){
            winston.info("IN triggerImmediateAction: gpi " + growPlanInstance._id + ", action " + actionId + ", device " + (device ? device._id : '') + ", in parallel final, err: " + (err ? err.toString() : '') + ", results: " + results.length);
            if (err) { return callback(err); }
            var data = {
              immediateAction : results[0],
              notification : results[1][0],
              device : results[2]
            };
            return callback(null, data);
          }
        );
      }
    );
  });
};


/**
 *
 * @alias module:models/Utils.scanForPhaseChanges
 * @function
 * @static
 */
module.exports.scanForPhaseChanges = function (GrowPlanInstanceModel, callback){
  var GrowPlanInstanceModel = require('./garden').model,
      NotificationModel = require('./notification').model,
      winston = require('winston'),
      async = require('async'),
      requirejs = require('../lib/requirejs-wrapper'),
      feBeUtils = requirejs('fe-be-utils'),
      i18nKeys = require('../i18n/keys');

  var now = new Date(),
      nowAsMilliseconds = now.valueOf(),
      tomorrow = new Date(nowAsMilliseconds + (24 * 60 * 60 * 1000)),
      callback = callback || function(){};

    GrowPlanInstanceModel
    .find()
    .where('active')
    .equals(true)
    .where('phases.expectedEndDate')
    .gt(now).lt(tomorrow)
    .populate('growPlan')
    .select('_id users growPlan phases')
    .exec(function(err, growPlanInstanceResults){
      if (err) { winston.error(JSON.stringify(err)); return callback(err); }
      if (!growPlanInstanceResults.length) { return callback(); }

      async.eachLimit(growPlanInstanceResults, 10,
        function growPlanInstanceIterator(growPlanInstance, iteratorCallback){
          var currentGrowPlanInstancePhase,
            currentGrowPlanInstancePhaseIndex, 
            nextGrowPlanInstancePhase,
            nextPhase;

          growPlanInstance.phases.some(
            function(item, index){ 
              if (item.active === true){
                currentGrowPlanInstancePhase = item;
                currentGrowPlanInstancePhaseIndex = index;
                return true;
              }
            }
          );
        
          nextGrowPlanInstancePhase = growPlanInstance.phases[currentGrowPlanInstancePhaseIndex + 1];

          if (!nextGrowPlanInstancePhase) { return iteratorCallback(); }
          
          growPlanInstance.growPlan.phases.some(function(item){
            if (item._id.equals(nextGrowPlanInstancePhase.phase)){
              nextPhase = item;
              return true;
            }
          });

          NotificationModel.create(
            {
              gpi : growPlanInstance._id,
              users : growPlanInstance.users,
              type : feBeUtils.NOTIFICATION_TYPES.INFO,
              timeToSend : now,
              trigger : feBeUtils.NOTIFICATION_TRIGGERS.PHASE_ENDING_SOON,
              triggerDetails : {
                gpPhaseId : currentGrowPlanInstancePhase.phase,
                nextGpPhaseId : nextGrowPlanInstancePhase.phase,
                gpiPhaseId : nextGrowPlanInstancePhase._id
              }
            },
            iteratorCallback
          );
        },
        function growPlanInstancesAllDone(err){
          return callback(err, growPlanInstanceResults.length);
        }
      );
    }
  );
};



/**
 *
 * @alias module:models/Utils.checkDeviceConnections
 * @function
 * @static
 * @param {function(err, devicesAffected)} callback
 */
module.exports.checkDeviceConnections = function(callback){
  var NotificationModel = require('./notification').model,
      DeviceModel = require('./device').model,
      async = require('async'),
      winston = require('winston'),
      requirejs = require('../lib/requirejs-wrapper'),
      feBeUtils = requirejs('fe-be-utils'),
      i18nKeys = require('../i18n/keys'),
      moment = require('moment'),
      getObjectId = module.exports.getObjectId;

  var now = new Date(),
      nowAsMilliseconds = now.valueOf(),
      cutOffDate = new Date(nowAsMilliseconds - (20 * 60 * 1000)); // 20 minutes

  DeviceModel.find({
    activeGrowPlanInstance : { $ne : null },
    $or : [ 
      {
        lastConnectionAt : { $exists : false }
      }, 
      {
        lastConnectionAt : { $lte : cutOffDate }
      }
    ]
  })
  .select('name owner users activeGrowPlanInstance lastConnectionAt')
  .populate('activeGrowPlanInstance', 'name owner users active')
  .exec(function(err, deviceResults){
    if (err) { return callback(err); }
    
    async.eachLimit(deviceResults, 10,
      function iterator(device, iteratorCallback){
        if (!device.activeGrowPlanInstance) { 
          winston.error("ModelUtils.checkDeviceConnections retrieved device with not null activeGrowPlanInstance but could not populate activeGrowPlanInstance " + device._id)
        }
        if (!device.activeGrowPlanInstance || !device.activeGrowPlanInstance.active) { return iteratorCallback(); }
        
        var usersToNotify = [];
        if (device.users && device.users.length){
          usersToNotify = usersToNotify.concat(device.users);
        }
        device.activeGrowPlanInstance.users.forEach(function(gardenUser){
          var userAlreadyExists = usersToNotify.some(function(notificationUser){
            return getObjectId(notificationUser).equals(getObjectId(gardenUser));
          });
          if (!userAlreadyExists){
            usersToNotify.push(gardenUser);
          }
        });

        NotificationModel.create({
          users : usersToNotify,
          gpi : device.activeGrowPlanInstance._id,
          timeToSend : now,
          type : feBeUtils.NOTIFICATION_TYPES.ACTION_NEEDED,
          trigger : feBeUtils.NOTIFICATION_TRIGGERS.DEVICE_MISSING,
          triggerDetails : {
            deviceId : device._id,
            lastConnectionAt : device.lastConnectionAt
          }
        }, iteratorCallback)
      },
      function loopEnd(err){
        return callback(err, deviceResults.length);
      }
    );
  });
};



/**
 * Returns the ObjectId of the object, taking into account
 * whether the object is a populated Model or an ObjectId
 *
 *
 * @alias module:models/Utils.getObjectId
 * @function
 * @static
 * 
 * @param object
 * @return ObjectId
 */
module.exports.getObjectId = function(object){
  var ObjectID = require('mongodb').ObjectID;
  var constructor = object.constructor.name.toLowerCase();
  if (constructor === 'objectid'){ return object; }
  if (constructor === 'string'){ return new ObjectID(object); } 
  // else, assume it's a populated model and has an _id property
  var _idConstructor = object._id.constructor.name.toLowerCase();
  if (_idConstructor === 'objectid') { return object._id; } 
  // might be a POJO so coerce it to an ObjectID object
  return new ObjectID(object._id.toString());
}



/**
 * TODO: docs
 */
module.exports.getDocumentIdString = function(object){
  if (object._id){ return object._id.toString(); }
  return object.toString();
};



/**
 * Retrieves a GrowPlan and populates all of its nested objects:
 * plants
 * phases.nutrients
 * phases.growSystem
 * phases.light
 * phases.light.fixture
 * phases.light.bulb
 * phases.actions
 * phases.phaseEndActions
 * phases.idealRanges.sensor
 * phases.idealRanges.actionBelowMin
 * phases.idealRanges.actionAboveMax
 *
 * Returns a plain-old-JS-object GrowPlan (not a GrowPlan Mongoose model) 
 * because of the lack of support for assigning models to ObjectId reference fields
 * 
 * Omits GrowPlan.sensors and GrowPlan.controls properties as those will be converted 
 * into virtuals soon (they'll simply be compiled views of all the sensors & controls used across all phases)
 * 
 * @param query {Object} Mongoose query parameters.
 * @param callback {function} Function with the signature function(err, [GrowPlan]){}. "GrowPlan" param is an array of POJO GrowPlans.
 *
 * @alias module:models/Utils.getFullyPopulatedGrowPlan
 * @function
 * @static
 */
module.exports.getFullyPopulatedGrowPlan = function(query, callback){
  var GrowPlanModel = require('./growPlan').growPlan.model,
      async = require('async'),
      winston = require('winston'),
      Action = require('./action'),
      ActionModel = Action.model,
      LightModel = require('./light').model,
      LightBulbModel = require('./lightBulb').model,
      LightFixtureModel = require('./lightFixture').model,
      growPlans,
      getObjectId = module.exports.getObjectId;
      
  async.series(
    [
      function getGrowPlan(innerCallback) {
        GrowPlanModel.find(query)
        .populate('plants')
        .populate('phases.nutrients')
        .populate('phases.growSystem')
        .populate('phases.actions')
        .populate('phases.phaseEndActions')
        .populate('phases.light')
        .exec(function(err, growPlanResults){
          if (err) { return innerCallback(err); }
          
          growPlans = growPlanResults.map(function(growPlanResult){ return growPlanResult.toObject(); });
          innerCallback();
        });
      },
      function populateIdealRangeActions(innerCallback) {
        var actionIds = [];
        growPlans.forEach(function(growPlan) {
          growPlan.phases.forEach(function(phase) {
            phase.idealRanges.forEach(function(idealRange, i) {
              if (idealRange.actionAboveMax){
                actionIds.push(idealRange.actionAboveMax);  
              }
              if (idealRange.actionBelowMin){
                actionIds.push(idealRange.actionBelowMin);
              }
            });
          });
        });
        
        //if (!actionIds.length){ return innerCallback(); }

        ActionModel.find({})
        .where('_id').in(actionIds)
        .exec(function (err, actions) {
          if (err) { return innerCallback(err); }
          
          var actionsById = {};
          actions.forEach(function(item, index) {
             actionsById[item._id.toString()] = item;
          });

          growPlans.forEach(function(growPlan) {
            growPlan.phases.forEach(function(phase) {
              phase.idealRanges.forEach(function(idealRange, i) {
                if (idealRange.actionBelowMin) { 
                  idealRange.actionBelowMin = actionsById[getObjectId(idealRange.actionBelowMin).toString()];
                }
                if (idealRange.actionAboveMax) { 
                  idealRange.actionAboveMax = actionsById[getObjectId(idealRange.actionAboveMax).toString()];
                }
              });
            });
          });

          innerCallback();
        });
      },

      function populateLights(innerCallback){
        var lightFixtureIds = [];
        var lightBulbIds = [];
        growPlans.forEach(function(growPlan) {
          growPlan.phases.forEach(function(phase) {
            if (phase.light){
              if (phase.light.fixture){
                lightFixtureIds.push(getObjectId(phase.light.fixture));
              }
              if (phase.light.bulb){
                lightBulbIds.push(getObjectId(phase.light.bulb));
              }
            }
          });
        });

        async.parallel(
          [
            function loadLightFixtures(innerInnerCallback){
              LightFixtureModel.find({})
              .where('_id').in(lightFixtureIds)
              .exec(function (err, lightFixtures) {
                if (err) { return innerCallback(err); }
                
                var lightFixturesById = {};
                lightFixtures.forEach(function(item, index) {
                   lightFixturesById[item._id.toString()] = item;
                });

                growPlans.forEach(function(growPlan) {
                  growPlan.phases.forEach(function(phase) {
                    if (phase.light && phase.light.fixture){
                      phase.light.fixture = lightFixturesById[getObjectId(phase.light.fixture).toString()];
                    }
                  });
                });

                return innerInnerCallback();
              });
            },

            function loadLightBulbs(innerInnerCallback){
              LightBulbModel.find({})
              .where('_id').in(lightBulbIds)
              .exec(function (err, lightBulbs) {
                if (err) { return innerCallback(err); }
                
                var lightBulbsById = {};
                lightBulbs.forEach(function(item, index) {
                   lightBulbsById[item._id.toString()] = item;
                });

                growPlans.forEach(function(growPlan) {
                  growPlan.phases.forEach(function(phase) {
                    if (phase.light && phase.light.bulb){
                      phase.light.bulb = lightBulbsById[getObjectId(phase.light.bulb).toString()];
                    }
                  });
                });

                return innerInnerCallback();
              });
            }
          ],
          function lightParallelEnd(err, results){
            innerCallback();
          }
        );
        
      }
    ],
    function (err, result) {
      //console.log(JSON.stringify(growPlans, null, 2));
      return callback(err, growPlans);
    }
  );
};


/**
 * Assigns a User to a Device as an owner.
 * Pairs by assigning user to device.owner, assigning device to a User.deviceKey, and adding user to device.users list
 *
 * Designed to be called by /setup route. Assumes that the setup page echoed the available deviceKey
 * that was created or retrieved on pageload of /setup
 * 
 * @param {object} settings
 * @param {User} settings.user
 * @param {DeviceKeySchema} settings.deviceKey : Instance from User.deviceKeys
 * @param {User} settings.device
 * @param {function(err, {device: Device, user: User})} callback 
 *
 *
 * @alias module:models/Utils.assignDeviceToUser
 * @function
 * @static
 */
module.exports.assignDeviceToUser = function(settings, callback){
  var Device = require('./device'),
      DeviceModel = Device.model,
      DeviceUtils = Device.utils,
      async = require('async'),
      winston = require('winston'),
      UserModel = require('./user').model,
      device = settings.device,
      deviceKey = settings.deviceKey,
      user = settings.user,
      device,
      getObjectId = module.exports.getObjectId,
      userId = getObjectId(user);

  async.series(
    [
      function deviceStep(innerCallback){
        device.userAssignmentLogs = device.userAssignmentLogs || [];
        device.userAssignmentLogs.push({
          ts: new Date(),
          user : user,
          assignmentType : DeviceUtils.ROLES.OWNER
        });
        device.owner = user;
        
        var userAlreadyIncluded = device.users.some(function(deviceUserId){
          return deviceUserId.equals(userId);
        });

        if (!userAlreadyIncluded){
          device.users.push(user);
        }

        device.save(innerCallback)
      },
      function userStep(innerCallback){
        deviceKey.deviceId = device._id;
        deviceKey.serial = device.serial;
        deviceKey.verified = true;
        deviceKey.verifiedDate = Date.now();

        user.save(innerCallback);
      }
    ],
    function(err, results){
      if (err) { return callback(err); }
      var data = {
        device : results[0][0],
        user : results[1][0]
      }
      return callback(null, data);
    }
  );
};

/**
 * TODO: IMPLEMENT THIS...
 * Pass in a doc and what fields you want populated with their data model
 * 
 * @param {Array} arrayOfObjects - array of mongoose objects
 * @param {Array} fields - array of object of form: { 'key': key, 'dataModel': require('./someModel')}
 * @param {function} callback - Function with the signature function(err, [Obj]){}. "Obj" param is a POJO.
 *
 *
 * @alias module:models/Utils.populateObjArray
 * @function
 * @static
 */
module.exports.populateObjArray = function(arrayOfDocs, fields, callback) {
  var 
      async = require('async'),
      // arrayOfObjects = arrayOfDocs.map(function(obj){ return obj.toObject() }),
      functionSeries = [];

  async.series([
    function getIds(innerCallback){
      arrayOfDocs.forEach(function(doc){
        
      });

      innerCallback();
    },

    function populate(innerCallback){
      fields.forEach(function(fieldObj){
        var Model = fieldObj.dataModel,
            newFunction = function(innerInnerCallback){ 
              console.log(doc[fieldObj.key]);

              Model.find({})
                .where('_id').in(lightBulbIds)
                .exec(function (err, lightBulbs) {
                  if (err) { return innerCallback(err); }
                  
                  var lightBulbsById = {};
                  lightBulbs.forEach(function(item, index) {
                     lightBulbsById[item._id.toString()] = item;
                  });

                  growPlans.forEach(function(growPlan) {
                    growPlan.phases.forEach(function(phase) {
                      if (phase.light && phase.light.bulb){
                        phase.light.bulb = lightBulbsById[getObjectId(phase.light.bulb).toString()];
                      }
                    });
                  });

                  return innerInnerCallback();
                });
            };
        functionSeries.push(newFunction);
      });
      innerCallback();
    }],
    function(err, results){
      if (err) { return callback(err); }
      

      console.log(functionSeries);
  
      async.parallel(
        functionSeries,
        function(err, results){
          if (err) { return callback(err); }
          var data = results;
          console.log('data:');
          console.log(data);
          return callback(null, data);
        }
      );

    }
  );
};


/**
 *
 * @alias module:models/Utils.getModelFromCollectionName
 * @function
 * @static
 */
module.exports.getModelFromCollectionName = function(collectionName) {
  var mongoose = require('mongoose'),
  mongooseConnection = require('../config/mongoose-connection').defaultConnection,
  modelNames = mongooseConnection.modelNames();
  if (!module.exports.getModelFromCollectionName.cachedMap){
    module.exports.getModelFromCollectionName.cachedMap = {};

    modelNames.forEach(function(modelName){
      var model = mongooseConnection.model(modelName);
      module.exports.getModelFromCollectionName.cachedMap[model.collection.name] = model;
    });
  }

  return module.exports.getModelFromCollectionName.cachedMap[collectionName];
};
