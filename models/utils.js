var Device = require('./device'),
    DeviceModel = Device.model,
    DeviceUtils = Device.utils,
    GrowPlanInstanceModel = require('./growPlanInstance').model,
    GrowPlanModel = require('./growPlan').growPlan.model,
    Action = require('./action'),
    ActionModel = Action.model,
    ActionUtils = Action.utils,
    ActionOverrideLogModel = require('./actionOverrideLog').model,
    NotificationModel = require('./notification').model,
    SensorModel = require('./sensor').model,
    SensorLogModel = require('./sensorLog').model,
    winston = require('winston'),
    async = require('async');


/**
 * logSensorLog : Log a sensorLog to the sensorLog collection as well as the
 * device.recentSensorLogs & growPlanInstance.recentSensorLogs. Verify against
 * IdealRanges and trigger Actions if necessary.
 *
 * @param pendingSensorLog : object in a format matching SensorLogSchema. gpid is optional, and if omitted, the log will only be logged to 
 *      the device's recentSensorLogs
 * @param growPlanInstance : GrowPlanInstance model instance on which to log this to recentSensorLogs
 * @param device : optional. Device Model instance on which to log this to recentSensorLogs
 */
function logSensorLog(options, callback){
  var pendingSensorLog = options.pendingSensorLog,
      growPlanInstance = options.growPlanInstance,
      device = options.device,
      user = options.user,
      timezone = user.timezone,
      activeGrowPlanInstancePhase = growPlanInstance.phases.filter(function(phase){ return phase.active; })[0];
  
  pendingSensorLog.gpi = growPlanInstance._id;
  
  async.parallel(
    [
    function parallel1(innerCallback){
      if (!device){ return innerCallback(); }
      device.recentSensorLogs.push(pendingSensorLog);
      device.save(innerCallback);
    },
    function parallel2(innerCallback){
      growPlanInstance.recentSensorLogs.push(pendingSensorLog);          
      growPlanInstance.save(innerCallback);
    },
    function parallel3(innerCallback){
      var sensorLog = new SensorLogModel(pendingSensorLog);
      sensorLog.save(innerCallback);
    },
    function parallel4(innerCallback){
      GrowPlanModel
      .findById(growPlanInstance.growPlan)
      .exec(function(err, growPlan){
        if (err){ return innerCallback(err); }
        if (!growPlan){ return new Error('GrowPlanInstance.growPlan not found'); }
        
        var phase = growPlan.phases.filter(function(item){ return item._id.equals(activeGrowPlanInstancePhase.phase); })[0];
        if (!phase){ return new Error('Active phase not found for this grow plan instance'); }
        if (!phase.idealRanges){ return innerCallback();}
        
        async.forEach(
          pendingSensorLog.logs, 
          function(log, iteratorCallback){
            var idealRange = phase.idealRanges.filter(function(idealRange){ return idealRange.sCode == log.sCode})[0],
                valueRange,
                message = '';
            if (!idealRange){ return iteratorCallback(); }
            valueRange = idealRange.valueRange;
            if (log.val < valueRange.min) {
              if (!idealRange.checkIfWithinTimespan(timezone, pendingSensorLog.ts)){ return iteratorCallback(); }
              
              // TODO : replace log.sCode with the sensor name
              message = log.sCode + ' is below recommended minimum of ' + valueRange.min;
              triggerActionOverride(
                {
                  growPlanInstance : growPlanInstance, 
                  device : device, 
                  actionId : idealRange.actionBelowMin, 
                  actionOverrideMessage : message, 
                  user : user 
                },
                function(err){
                  if (err) { return iteratorCallback(err); }
                  iteratorCallback();
                }
              );
            } else if (log.val > valueRange.max){
              if (!idealRange.checkIfWithinTimespan(timezone, pendingSensorLog.ts)){ return iteratorCallback(); }
              message = log.sCode + ' is above recommended maximum of ' + valueRange.max;
              triggerActionOverride(
                {
                  growPlanInstance : growPlanInstance, 
                  device : device, 
                  actionId : idealRange.actionBelowMin, 
                  actionOverrideMessage : message, 
                  user : user 
                },
                function(err){
                  if (err) { return iteratorCallback(err); }
                  iteratorCallback();
                }
              );
            } else { 
              return iteratorCallback(); 
            }
          },
          innerCallback
        );
      });
    }
    ], 
    function parallelFinal(err, result){
      if (err) { return callback(err); }
      return callback();
    }
  );
};


/**
 * Activate a grow plan. If there's a device, update the device's activeGrowPlanInstance property
 * and remove the device from any other GPI's that are using it. 
 */
function activateGrowPlanInstance(growPlanInstance, callback){
  growPlanInstance.active = true;

  if (!growPlanInstance.device){
    return growPlanInstance.save(callback);
  }
  else {
    DeviceModel.findById(growPlanInstance.device, function(err, deviceResult){
      if (err) { return callback(err); }
      if (!deviceResult){ return callback(new Error('No device found for specified id')); }

      deviceResult.activeGrowPlanInstance = growPlanInstance;

      deviceResult.save(function(err){
        if (err) { return callback(err); }
        return growPlanInstance.save(callback);     
      });
    });

    // TODO : check for other Devices that have activeGrowPlanInstance set to this. do something....
  }
};


function triggerActionOverride(options, callback){
  var growPlanInstance = options.growPlanInstance,
      device = options.device, 
      actionId = options.actionId,
      actionOverrideMessage = options.actionOverrideMessage,
      user = options.user,
      timezone = user.timezone;
  ActionModel.findById(actionId, function(err, action){
    if (err) { return next(err);}
    if (!action) { return next(new Error('Invalid action id'));}

    // calculate when the actionOverride should expire.
    var now = new Date(),
        expires = now + (365 * 24 * 60 * 60 * 1000),
        actionHasDeviceControl = false;

    async.series(
      [
        function(innerCallback){
          if (!action.control){ return innerCallback(); }

          if (!device){
            GrowPlanModel.findById(growPlanInstance.growPlan)
            .populate('phases.actions')
            .exec(function(err, phaseResult){
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
                  var cycleRemainder = ActionUtils.getCycleRemainder(growPlanInstancePhase, actionResult, timezone);      
                  expires = now.valueOf() + cycleRemainder;
                  return innerCallback();  
                });
                
              }
            );
            
          } else {
            // get any other actions that exist for the same control.
            var growPlanInstancePhase = growPlanInstance.phases.filter(function(phase) { return phase.active;})[0];
            
            ActionModel.findOne()
            .where('_id')
            .in(device.activeActions.actions)
            .where('control')
            .equals(action.control)
            .exec(function(err, actionResult){
              if (err) { return innerCallback(err);}
              if (!actionResult){ return innerCallback(); }
              var cycleRemainder = ActionUtils.getCycleRemainder(growPlanInstancePhase, actionResult, timezone);      
              expires = now.valueOf() + cycleRemainder;
              actionHasDeviceControl = true;
              return innerCallback();  
            });
          }
        }
        ],
        function(err, result){
          if (err) { return callback(err); }
          var actionLog = new ActionOverrideLogModel({
            gpi : growPlanInstance._id,
            msg : actionOverrideMessage,
            timeRequested : now,
            action : action,
            // TODO : handle expires for the no-device case 
            expires : expires
          });

        // push the log to ActionOverrideLogModel
        actionLog.save(function(err){
          if (err){ return callback(err); }
          winston.info('Logged actionOverride for ' + growPlanInstance._id + ' "' + actionOverrideMessage + '", action ' + action._id);
          if (!actionHasDeviceControl){ 
            var notification = new NotificationModel({
              users : [user],
              gpi : growPlanInstance,
              ts : now,
              timeSent : now,
              msg : actionOverrideMessage,
              type : 'actionNeeded'
            });
            winston.info('Creating notification : ' + notification.toString());
            notification.save(function(err){
              if (err) { return callback(err); }
              return callback();
            });
          } else {
            device.refreshActiveActionsOverride(function(err){
              if (err) { return callback(err); }
              return callback();
            });  
          }
          
        });
      }
    );
  });
};


module.exports = {
  logSensorLog : logSensorLog,
  activateGrowPlanInstance : activateGrowPlanInstance,
  triggerActionOverride : triggerActionOverride
};