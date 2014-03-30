/**
 * @todo Refactor this to be Garden
 * @module models/Garden
 */

var mongoose = require('mongoose'),
  mongoosePlugins = require('../lib/mongoose-plugins'),
  useTimestamps = mongoosePlugins.useTimestamps,
  Schema = mongoose.Schema,
  ObjectIdSchema = Schema.ObjectId,
  GrowPlanModel = require('./growPlan').growPlan.model,
  User = require('./user').model,
  GrowPlanInstanceModel,
  async = require('async'),
  winston = require('winston'),
  tz = require('../lib/timezone-wrapper'),
  DeviceModel = require('./device').model,
  utils = require('./utils'),
  getObjectId = utils.getObjectId,
  getDocumentIdString = utils.getDocumentIdString,
  SensorLog = require('./sensorLog'),
  SensorLogSchema = SensorLog.schema,
  SensorLogModel = SensorLog.model,
  HarvestLogModel = require('./harvestLog').model,
  ImmediateActionModel = require('./immediateAction').model,
  NotificationModel = require('./notification').model,
  TextLogModel = require('./textLog').model,
  i18nKeys = require('../i18n/keys'),
  requirejs = require('../lib/requirejs-wrapper'),
  feBeUtils = requirejs('fe-be-utils'),
  mongooseConnection = require('../config/mongoose-connection').defaultConnection;


var PhaseDaySummarySchema = new Schema({
  
  status : { 
  
    type: String, 
  
    enum: [
      feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD,
      feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD,
      feBeUtils.PHASE_DAY_SUMMARY_STATUSES.EMPTY
    ],
  
    default: feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD
  },
  
  
  /**
   * Localized midnight of the day for this phase day
   */
  date : { type : Date },


  /**
   * sensorSummaries is a hash, 
   * Keys are Sensor.sCode
   * Values are feBeUtils.PHASE_DAY_SUMMARY_STATUSES
   */
  sensorSummaries : Schema.Types.Mixed
}, 
// Don't need ObjectId entries for PhaseDaySummaries
{ id : false, _id : false });



/**
 * GrowPlanInstance 
 */
var GrowPlanInstanceSchema = new Schema({

  users : [{ type: ObjectIdSchema, ref: 'User' }],
  
  owner : { type: ObjectIdSchema, ref: 'User', required: true },

  growPlan : { type : ObjectIdSchema, ref : 'GrowPlan', required: true },
  
  device : { type : String, ref : 'Device', match: /^([a-z0-9_-]){12}$/, required: false }, //the bitponics device
  
  name : { type : String },

  startDate: { type: Date },

  endDate: { type: Date },

  active: { type: Boolean },

  tz: { type : String, default : 'America/New_York' },

  // TODO
  //servicePlan : { type : ObjectIdSchema, ref : 'ServicePlan' },


  /**
   * Record of the phases this GPI has been through. 
   * Last one should be the active one.
   */
  phases: [{
    
    /**
     * ObjectId of GrowPlan. Stored because it's possible for a GPI 
     * to be shifted to a new 
     */
    growPlan : { type : ObjectIdSchema, ref : 'GrowPlan' },

    /**
     * ObjectId of GrowPlan.Phase
     */
    phase: Schema.Types.ObjectId,


    /**
     * actual date the phase was started. null/undefined if not yet started
     */
    startDate: { type: Date },


    /**
     * Day of the GrowPlan phase on which this GPI Phase started.
     * 0-based.
     * Allows for saying "I started on day 5 of this phase"
     */
    startedOnDay : { type : Number, default : 0 },


    /**
     * actual date the phase was ended. null/undefined if not yet ended
     */
    endDate: { type: Date },


    /**
     * set whenever a phase is started, based on GrowPlan.Phase.expectedNumberOfDays. 
     * used by the worker process to query & notify of impending phase advancement
     *
     * If null, means the user has opted out of automatic phase advancement, so just let this phase continue on indefinitely.
     */
    expectedEndDate : { type : Date, required : false },


    /**
     * Whether the phase is currently active. Should be max 1 phase active at a time.
     */
    active: { type: Boolean },

    
    /**
     * Summary of each day that's passed in this GPI Phase.
     * Used in Dashboard display.
     */
    daySummaries : [ PhaseDaySummarySchema ],

  }],


  growPlanMigrations : [
    {
      oldGrowPlan : { type : ObjectIdSchema, ref : 'GrowPlan' },
      newGrowPlan : { type : ObjectIdSchema, ref : 'GrowPlan' },
      ts : { type : Date }
    }
  ],


  settings : {
    visibleSensors : [],
    units: {
      FULL: { type: String, enum: [ feBeUtils.UNITS.FULL.units[0].id ], default : feBeUtils.UNITS.FULL.units[0].id },
      HUM: { type: String, enum: [ feBeUtils.UNITS.HUM.units[0].id ], default : feBeUtils.UNITS.HUM.units[0].id },
      AIR: { type: String, enum: [ feBeUtils.UNITS.AIR.units[0].id, feBeUtils.UNITS.AIR.units[1].id], default: feBeUtils.UNITS.AIR.units[0].id },
      WL: { type: String, enum: [ feBeUtils.UNITS.WL.units[0].id, feBeUtils.UNITS.WL.units[1].id], default: feBeUtils.UNITS.WL.units[0].id },
      PH: { type: String, enum: [ feBeUtils.UNITS.PH.units[0].id ], default: feBeUtils.UNITS.PH.units[0].id },
      EC: { type: String, enum: [ feBeUtils.UNITS.EC.units[0].id ], default: feBeUtils.UNITS.EC.units[0].id },
      WATER: { type: String, enum: [ feBeUtils.UNITS.AIR.units[0].id, feBeUtils.UNITS.AIR.units[1].id], default: feBeUtils.UNITS.AIR.units[0].id },
      LUX: { type: String, enum: [ feBeUtils.UNITS.LUX.units[0].id ], default: feBeUtils.UNITS.LUX.units[0].id }
    }
  },
  
  visibility : { 
    type: String, 
    enum: [
      feBeUtils.VISIBILITY_OPTIONS.PUBLIC,
      feBeUtils.VISIBILITY_OPTIONS.PRIVATE
    ], 
    default : feBeUtils.VISIBILITY_OPTIONS.PUBLIC
  },

  trackGrowPlanUpdates : { type : Boolean, default : true }
},
{ id : false });


GrowPlanInstanceSchema.plugin(useTimestamps); // adds createdAt/updatedAt fields to the schema, and adds the necessary middleware to populate those fields 

GrowPlanInstanceSchema.plugin(mongoosePlugins.recoverableRemove, {
  callback : function(err, removedDocumentResults, callback){
    if (err) { return callback(err); }

    winston.info("IN GPI REMOVE CALLBACK args " + JSON.stringify(arguments));
    
    // Remove associated documents (various logs)
    var ids = removedDocumentResults.map(function(doc) { return doc._id; });

    async.parallel([
      function clearDeviceAssociations(innerCallback){
        DeviceModel.update(
          { 
            "activeGrowPlanInstance": { $in : ids }
          }, 
          { "$unset": { "activeGrowPlanInstance": 1 } },
          innerCallback
        );
      },
      function removeSensorLogs(innerCallback){
        SensorLogModel.remove({'gpi' : { $in: ids }}, innerCallback);
      },
      function removeHarvestLogs(innerCallback){
        HarvestLogModel.remove({'gpi' : { $in: ids }}, innerCallback);
      },
      function removeImmediateActions(innerCallback){
        ImmediateActionModel.remove({'gpi' : { $in: ids }}, innerCallback);
      },
      function removeNotifications(innerCallback){
        NotificationModel.remove({'gpi' : { $in: ids }}, innerCallback);
      },
      function removeTextLogs(innerCallback){
        TextLogModel.remove({'gpi' : { $in: ids }}, innerCallback);
      }
    ],
    function parallelRemoveCallback(err){
      return callback(err, removedDocumentResults);
    });
  }
});


GrowPlanInstanceSchema.virtual('timezone')
  .get(function(){
    return this.tz;
  })
  .set(function(timezone){
    this.tz = timezone;
  });

GrowPlanInstanceSchema.index({ users: 1 });
GrowPlanInstanceSchema.index({ growPlan: 1 });
GrowPlanInstanceSchema.index({ device: 1, active: 1 });
GrowPlanInstanceSchema.index({ active: 1, 'phases.expectedEndDate' : 1 });





/******************** STATIC METHODS  ***************************/

/**
 * Create a new GrowPlanInstance from the specified GrowPlan
 * 
 * @param options.growPlan (required) GrowPlan model, ObjectID instance, or objectId string
 * @param options.owner (required) User model, ObjectID instance, or objectId string
 * @param options.users (optional). Members of the GPI. If undefined, we'll just use options.owner
 * @param options.active (required) Boolean indicating whether to immediately activate the grow plan instance
 * @param options.device (optional) If present, sets the device property on the grow plan instance
 * @param options.activePhaseId (optional) The _id of a growPlan.phase. If present, sets the active phase on the grow plan instance
 * @param options.activePhaseDay (optional) Indicates the number of days into the active phase. Used to offset gpi.phases.expectedEndDate
 * @param options.name (optional) Name of the GPI

 * @param callback. Function called with (err, growPlanInstance)
 */

GrowPlanInstanceSchema.static('create', function(options, callback) {
  var gpiInitData = {
    owner : options.owner,
    users : options.users || [options.owner],
    device : options.device
  };
  if (options._id){
    gpiInitData._id = options._id;
  };

  if (!options.owner) { return callback(new Error('options.owner must be defined')); }
  if (!options.growPlan) { return callback(new Error('options.growPlan must be defined')); }

  var gpi = new GrowPlanInstanceModel(gpiInitData);
 
  async.series(
    [
      function initGrowPlanData (innerCallback){
        GrowPlanModel.findById(options.growPlan, function(err, growPlan){
          if (err) { return innerCallback(err); }
          if (!growPlan) { return innerCallback(new Error('Invalid grow plan id')); }
          gpi.growPlan = growPlan;

          // set the name
          if (options.name){
            gpi.name = options.name;
          } else {
            gpi.name = growPlan.name + " Garden";
          }

          if (!options.activePhaseId){
            options.activePhaseId = growPlan.phases[0]._id;
          }

          // Don't add the phases. Phases are appended to the gpi.phases array as they're activated
          
          return innerCallback();
        });
      }
    ],
    function(err, results){
      if (err) { return callback(err); }

      gpi.save(function(err, createdGarden){
        if (err) { return callback(err); }

        winston.info('Created new gpi for user ' + createdGarden.owner + ' gpi id ' + createdGarden._id);
       
        if (!options.active){
          return callback(err, createdGarden);
        }
         
        return createdGarden.activate({ 
          activePhaseId : options.activePhaseId,
          activePhaseDay : options.activePhaseDay        
        },
        function(err, activatedGPI){
          return callback(err, activatedGPI);
        });
      });
    }
  );
});


/******************* END STATIC METHODS  ***************************/




/************** INSTANCE METHODS ********************/


/**
 * Given a target date, get the number of days elapsed since phase start.
 * Since phase starts are always normalized to the localized 00:00 of the user's timezone,
 * we can be sure we're getting a useful number here.
 *
 * Zero-based.
 *
 * @param {GrowPlanInstancePhase} growPlanInstancePhase
 * @param {Date|Number} targetDate
 *
 */
GrowPlanInstanceSchema.method('getPhaseDay', function(growPlanInstancePhase, targetDate){
  var moment = require('moment'),
      phaseStart = moment(growPlanInstancePhase.startDate).subtract('days', growPlanInstancePhase.startedOnDay),
      target = moment(targetDate);

  return target.diff(phaseStart, 'days');
});


/**
 * Given the id of a GrowPlan Phase, return the GrowPlanInstance phase object
 * 
 * @param {ObjectId} growPlanPhaseId
 * @return {GrowPlanInstancePhase}
 */
GrowPlanInstanceSchema.method('getPhaseByGrowPlanPhaseId', function(growPlanPhaseId) {
    for (var i = this.phases.length; i--;){
      if (this.phases[i].phase.equals(growPlanPhaseId)){
        return this.phases[i];
      }
    }
});


/**
 * Get the active phase
 */
GrowPlanInstanceSchema.method('getActivePhase', function() {
    for (var i = this.phases.length; i--;){
      if (this.phases[i].active){
        return this.phases[i];
      }
    }
});


/**
 * Add a phaseDaySummary to the specified GPI Phase, merging if a summary already exists.
 * Day summary statuses are by default good and can only turn from good to bad.
 * 
 * Saves the GrowPlanInstance.
 *
 * @param {GrowPlanInstancePhase} settings.growPlanInstancePhase
 * @param {PhaseDaySummary} settings.daySummary
 * @param {function(err, GrowPlanInstance)} callback : function called after GPI has been modified and saved
 */
GrowPlanInstanceSchema.method('mergePhaseDaySummary', function(settings, callback) {
  var moment = require('moment'),
      gpi = this,
      growPlanInstancePhase = settings.growPlanInstancePhase,
      submittedPhaseDaySummary = settings.daySummary,
      date = submittedPhaseDaySummary.date,
      phaseDay = gpi.getPhaseDay(growPlanInstancePhase, date),
      daySummary = growPlanInstancePhase.daySummaries[phaseDay],
      sensorKey,
      phaseStartMoment = moment(growPlanInstancePhase.startDate),
      normalizedDate = phaseStartMoment.add("days", phaseStartMoment.diff(date, "days"));

  // TODO : normalize the date to localized midnight. need owner.timezone

  if (daySummary){
    if (submittedPhaseDaySummary.status === feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD){
      daySummary.status = feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD;
    }
    
    for (sensorKey in submittedPhaseDaySummary.sensorSummaries){
      if (submittedPhaseDaySummary.sensorSummaries.hasOwnProperty(sensorKey)) {

        if (
            (submittedPhaseDaySummary.sensorSummaries[sensorKey] === feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD) 
            || 
            (!daySummary.sensorSummaries[sensorKey])
           ){
          daySummary.sensorSummaries[sensorKey] = submittedPhaseDaySummary.sensorSummaries[sensorKey];
        }    
      }
    }
  } else {
    daySummary = submittedPhaseDaySummary;
  }

  // http://mongoosejs.com/docs/faq.html
  growPlanInstancePhase.daySummaries.set(phaseDay, daySummary);

  gpi.save(callback);
});


/**
 * Pair a device with this grow plan instance.
 * 
 * Pairing has no relation to activating. Non-active gpi's can have devices paired to them
 * 
 * @param {ObjectId|string} options.deviceId : ObjectId of device to pair
 * @param {bool=} options.saveGrowPlanInstance (optional) Boolean indicating whether the GrowPlanInstance should be saved in the end (should be false if caller will execute a save). Device will be saved regardless.
 * @param {function(err, { device : Device, growPlanInstance : growPlanInstance })} callback
 */
GrowPlanInstanceSchema.method('pairWithDevice', function(options, callback) {
  var gpi = this;

  DeviceModel.findById(options.deviceId, function(err, deviceResult){
    if (err) { return callback(err); }
    
    if (!deviceResult){ return callback(new Error(i18nKeys.get('no device', options.deviceId))); }
    
    if (deviceResult.owner && !getObjectId(deviceResult.owner).equals(getObjectId(gpi.owner))){
      return callback(new Error(i18nKeys.get('Only device owner can assign a device to their garden')));
    }
    
    DeviceModel.update(
      { 
        "activeGrowPlanInstance": gpi._id,
        "_id" : { "$ne" : deviceResult._id }
      }, 
      { "$unset": { "activeGrowPlanInstance": 1 } }, 
      function(err, numberAffected){
        async.parallel(
          [
            function updateDevice(innerCallback){
              deviceResult.activeGrowPlanInstance = gpi;
              deviceResult.refreshStatus(innerCallback);
            },
            function updateGPI(innerCallback){
              gpi.device = deviceResult._id;
              gpi.save(innerCallback);
            }
          ],
          function parallelFinal(err, results){
            if (err) { return callback(err); }
            var data = {
              device : results[0],
              growPlanInstance : results[1][0]
            };
            return callback(null, data);
          }
        );
      }
    );
  });
});


/**
 * Unpair device from this grow plan instance.
 * 
 * @param {function(err, growPlanInstance)} callback
 */
GrowPlanInstanceSchema.method('unpairDevice', function(callback) {
  var gpi = this;

  if (!gpi.device){ return callback(null, gpi); }

  gpi.device = undefined;

  async.parallel(
    [
      function saveGPI(innerCallback){
        gpi.save(innerCallback);
      },
      function updateDevice(innerCallback){
        DeviceModel.update(
          { 
            "_id" : deviceResult._id
          }, 
          { "$unset": { "activeGrowPlanInstance": 1 } }, 
          innerCallback
        );
      }
    ],
    function parallelEnd(err, results){
      return callback(err, results[0]);
    }
  );
});


/**
 * Activate an existing grow plan instance. If there's a device, update the device's activeGrowPlanInstance property
 * and remove the device from any other GPI's that are using it. 
 *
 * @param {Object}           options
 * @param {ObjectId|string=} options.activePhaseId : optional. The _id of a growPlan.phase. If present, sets the active phase on the grow plan instance. If not present,
 *                                                   the first phase will be activated.
 * @param {Number=}          options.activePhaseDay : optional. Indicates the number of days into the active phase. Used to offset gpi.phases.expectedEndDate
 * @param {function(err, gpi)} callback
 */
GrowPlanInstanceSchema.method('activate', function(options, callback) {
  var gpi = this,
      now = new Date(),
      activePhaseId = options.activePhaseId || gpi.phases[0].phase;

    gpi.active = true;
    gpi.startDate = now;
    
    gpi.save(function (err){
      if (err) { return callback(err);}

      async.waterfall([
        function activatePhase(innerCallback){
          gpi.activatePhase({
            phaseId : activePhaseId,
            phaseDay : options.activePhaseDay,
            save : true
          },
          innerCallback);
        },
        function pairWithDevice(gpiWithActivePhase, innerCallback){
          if (!gpiWithActivePhase.device){ return innerCallback(null, gpiWithActivePhase); }

          gpiWithActivePhase.pairWithDevice({
            deviceId : getDocumentIdString(gpiWithActivePhase.device)
          },
          function(err, pairResult){
            return innerCallback(err, pairResult ? pairResult.growPlanInstance : undefined);
          });
        },
        function incrementGrowPlanActivationCount(activatedGPI, innerCallback){
          GrowPlanModel.findByIdAndUpdate(activatedGPI.growPlan, { $inc: { activeGardenCount: 1 }}, function (err) {
            return innerCallback(err, activatedGPI);
          });
        }
      ],
      function(err, activatedGPI){
        return callback(err, activatedGPI);
      }
    );
  });
});


/**
 * Activate a grow plan phase on a grow plan instance.
 * Expire existing actions/notifications and activate new ones
 * 
 * Assumes it's passed a phase from gpi.growPlan
 *
 * @param {ObjectId|string} options.phaseId : (required) phaseId of the growPlan.phase
 * @param {Number=} options.phaseDay : (optional) Number of days into the phase. Used to offset phase.expectedEndDate
 * @param {bool=} options.save : (optional) Indicates whether the GrowPlanInstance should be saved in the end (should be false if caller will execute a save)
 * @param {function(err, GrowPlanInstance)} callback
 */
GrowPlanInstanceSchema.method('activatePhase', function(options, callback) {
  var Action = require('./action'),
      ActionModel = Action.model,
      NotificationModel = require('./notification').model,
      ImmediateActionModel = require('./immediateAction').model,
      UserModel = require('./user').model,
      growPlanInstance = this,
      growPlan = growPlanInstance.growPlan,
      phaseId = options.phaseId,
      device,
      now = new Date(),
      nowAsMilliseconds = now.valueOf(),
      phaseDay = options.phaseDay || 0,
      growPlanPhase,
      growPlanInstancePhase,
      actionsWithDeviceControl = [],
      prevPhase,
      owner,
      isPhaseReactivation = false;
  
  // First, populate growPlan, owner, device
  // then, set the phase properties & save the gpi
  // Then, in parallel:
  // expire any existing immediate actions
  // expire all existing notifications
  // Finally,
  // activate the new phases' actions & trigger notifications
  
  
  // Make sure the gpi is active
  growPlanInstance.active = true;

//console.trace();
console.log('activatePhase', options)

  async.series(
    [
      function getPopulatedOwner(innerCallback){
        /*
        growPlanInstance.populate({
          path: 'owner',
          select: 'timezone'
        }, function(err, gpiResult){
          if (err) { return innerCallback(err); }
          growPlanInstance = gpiResult;
          owner = gpiResult.owner;
          return innerCallback();
        });
        */

        UserModel.findById(growPlanInstance.owner)
        .select('timezone') // only property we actually need here is timezone
        .lean()
        .exec(function (err, user){
          if (err) { return innerCallback(err);}
          if (!user) { return innerCallback(new Error("GrowPlanInstance owner could not be found")); }
          owner = user;
          return innerCallback();
        });
      },

      function updateGrowPlanInstancePhases(innerCallback){
        GrowPlanModel
        .findById(growPlanInstance.growPlan)
        .populate('phases.actions')
        .populate('phases.phaseEndActions')
        .exec(function (err, growPlan){
          if (err) { return innerCallback(err); }

          growPlanPhase = growPlan.phases.filter(function(item){ return item._id.equals(phaseId);})[0];

          // Scan garden's past & current phases
          // if we find that we're reactivating the current phase, cool
          // if we find a different phase as the currently-active one, deactivate it
          growPlanInstance.phases.forEach(function(phase){
            if (phase.phase.equals(phaseId) && phase.active){
              growPlanInstancePhase = phase;
              isPhaseReactivation = true;
            } else {
              if (phase.active == true){
                prevPhase = phase;
                phase.endDate = now;
              }
              phase.active = false;
            }
          });

          if (!growPlanInstancePhase){
            var expectedEndDate = nowAsMilliseconds + (growPlanPhase.expectedNumberOfDays * 24 * 60 * 60 * 1000) - (phaseDay * 24 * 60 * 60 * 1000);
            if (expectedEndDate < nowAsMilliseconds){
              expectedEndDate = nowAsMilliseconds;
            }

            growPlanInstancePhase = {
              phase : phaseId,
              growPlan : growPlanInstance.growPlan,
              active : true,
              startDate : now,
              startedOnDay : phaseDay,
              expectedEndDate : expectedEndDate
            };
            growPlanInstance.phases.push(growPlanInstancePhase);
          }
          
          return innerCallback();
        });
      },

      function getDeviceControllableActions(innerCallback){
        if (!growPlanInstance.device){ return innerCallback(); }
        console.log('getDocumentIdString(growPlanInstance.device)', getDocumentIdString(growPlanInstance.device));
        DeviceModel.findById(getDocumentIdString(growPlanInstance.device), function (err, deviceResult){
          if (err) { return innerCallback(err); }

          device = deviceResult;
          actionsWithDeviceControl = growPlanPhase.actions.filter(
            function(item){ 
              return (item.control && device.outputMap.some(function(controlPair){ return item.control.equals(controlPair.control);})); 
            }
          );
          
          return innerCallback();
        });
      },

      function saveGPI(innerCallback){
        // At this point, the growPlanInstance is done being edited.
        if (!options.save) {
          return innerCallback();
        }
        
        growPlanInstance.save(function(err, updatedGrowPlanInstance){
          if (err) { return innerCallback(err); }
          // update the outer scope's growPlanInstance
          growPlanInstance = updatedGrowPlanInstance;
          return innerCallback();
        });

      },

      function expireExistingNotificationsAndImmediateActions(innerCallback){

        async.parallel([
          
          // Expire existing notifications for this GPI
          function expireExistingNotifications(innerParallelCallback){
            NotificationModel.expireAllGrowPlanInstanceNotifications(
              growPlanInstance._id,
              innerParallelCallback
            );
          },
          
          // Force refresh of device status on next request
          function updateDeviceStatus(innerParallelCallback){
            if (!device){ return innerParallelCallback(); }
            
            device.status.expires = now;

            device.save(innerParallelCallback);
          },
          
          // Expire immediateActions that conflict with a device controlled action in the new phase
          function updateImmediateActions(innerParallelCallback){
            if (!device){ return innerParallelCallback(); }
            
            ImmediateActionModel
            .find()
            .where('gpi')
            .equals(growPlanInstance._id)
            .where('e')
            .gt(now)
            .populate('a')
            .exec(function(err, immediateActionResults){
              if (err) { return innerParallelCallback(err);}
              if (!immediateActionResults.length){ return innerParallelCallback(); }
            
              var immediateActionsToExpire = [];
              immediateActionResults.forEach(function(immediateAction){
                if (!immediateAction.action.control) { return; } 
                if (actionsWithDeviceControl.some(function(action){
                  return immediateAction.action.control.equals(action.control);
                })){
                  immediateActionsToExpire.push(immediateAction);
                }
              });

              async.forEach(immediateActionsToExpire, 
                function(immediateAction, iteratorCallback){
                  immediateAction.expires = now;
                  immediateAction.save(iteratorCallback);
                }, 
                function(err){
                  if (err) { return innerParallelCallback(err);}
                  return innerParallelCallback();
                }
              );
            });
          }
        ],
        function (err, results){  
          return innerCallback(err);
        }
        );
      },

      // Trigger notifications for the just-ended phase 
      function triggerPhaseEndNotifications(innerCallback){
        // If no endActions, or we're simply re-activating the current phase, don't send any phase-end notifications
        if (
          !(prevPhase && prevPhase.phaseEndActions) 
          || 
          (isPhaseReactivation)
        ){ return innerCallback(); }

        ActionModel
        .find()
        .where('_id')
        .in(prevPhase.phaseEndActions)
        .populate('control')
        .exec(function (err, actionResults){
          if (err) { return innerCallback(err); }
          if (!actionResults.length) { return innerCallback(); }

          async.forEach(
            actionResults, 
            function(action, iteratorCallback){
              NotificationModel.create(
              {
                users : growPlanInstance.users,
                gpi : growPlanInstance._id,
                timeToSend : now,
                type : feBeUtils.NOTIFICATION_TYPES.ACTION_NEEDED,
                trigger : feBeUtils.NOTIFICATION_TRIGGERS.PHASE_END_ACTION,
                triggerDetails : {
                  phaseName : prevPhase.name,
                  actionId : action._id,
                  gpPhaseId : prevPhase._id
                }
              },
              iteratorCallback);
            },
            function (err){
              return innerCallback(err);
            }
          );
        });
      },

      // Trigger notifications for the newly activated phase
      function triggerPhaseStartNotifications(innerCallback){
        ActionModel
        .find()
        .where('_id')
        .in(growPlanPhase.actions)
        .populate('control')
        .exec(function (err, actionResults){
          if (err) { return innerCallback(err); }
          if (!actionResults.length) { return innerCallback(); }
          
          async.forEach(
            actionResults, 
            function(action, iteratorCallback){
              // Prevent notification if it's a phase reactivation and there's no action repeat (meaning it's a one-off phase start action). User's already started phase, so these wouldn't make sense to send at this point
              if (isPhaseReactivation && !action.cycle.repeat){
                return iteratorCallback();
              }

              var notificationsToSave = [],
                actionNotification = {
                  users : growPlanInstance.users,
                  gpi : growPlanInstance._id,
                  timeToSend : now,
                  type : undefined, // will be set below
                  trigger : feBeUtils.NOTIFICATION_TRIGGERS.PHASE_ACTION,
                  triggerDetails : {
                    phaseName : growPlanPhase.name,
                    actionId : action._id,
                    gpPhaseId : growPlanPhase._id,
                    handledByDeviceControl : false
                  }
                };

              notificationsToSave.push(actionNotification);

              // Check if this has a device control
              if (action.control && 
                  actionsWithDeviceControl.some(function(item){
                    return action.control._id.equals(item.control);
                  })
                  ){
                    actionNotification.type = feBeUtils.NOTIFICATION_TYPES.INFO;
                    actionNotification.triggerDetails.handledByDeviceControl = true;
              } 

              // else it either doesn't require a control, or device doesn't have the required control
              else {
                actionNotification.type = feBeUtils.NOTIFICATION_TYPES.ACTION_NEEDED;
                
                if (action.cycle.repeat){
                  
                  // cycles with repeat=true are required to have 2 states (through validation rules)
                  var states = action.cycle.states,
                      overallDurationObject = action.getOverallCycleDurationObject(),
                      actionRepeatNotificationTemplate = {
                        users : growPlanInstance.users,
                        growPlanInstance : growPlanInstance._id,
                        timeToSend : undefined,
                        trigger : feBeUtils.NOTIFICATION_TRIGGERS.PHASE_ACTION,
                        triggerDetails : {
                          phaseName : growPlanPhase.name,
                          actionId : action._id,
                          gpPhaseId : growPlanPhase._id
                        },
                        repeat : {
                          durationType : overallDurationObject.durationType,
                          duration : overallDurationObject.duration,
                          timezone : owner.timezone
                        },
                        type : feBeUtils.NOTIFICATION_TYPES.ACTION_NEEDED
                      },
                      actionRepeatNotificationState0,
                      actionRepeatNotificationState1;
                  
                  if (states[0].durationType){
                    actionRepeatNotificationState1 = JSON.parse(JSON.stringify(actionRepeatNotificationTemplate));
                    actionRepeatNotificationState1.timeToSend = nowAsMilliseconds + ActionModel.convertDurationToMilliseconds(states[0].duration, states[0].durationType);
                    actionRepeatNotificationState1.triggerDetails.cycleStateIndex = 1;
                    notificationsToSave.push(actionRepeatNotificationState1);
                  }

                  if (states[1].durationType){
                    actionRepeatNotificationState0 = JSON.parse(JSON.stringify(actionRepeatNotificationTemplate));
                    actionRepeatNotificationState0.timeToSend = now;
                    actionRepeatNotificationState0.triggerDetails.cycleStateIndex = 0;
                    notificationsToSave.push(actionRepeatNotificationState0);
                  }
                }
              }

              async.each(
                notificationsToSave, 
                function(notificationToSave, innerIteratorCallback){
                  NotificationModel.create(notificationToSave, innerIteratorCallback);
                },
                function(err){
                  return iteratorCallback(err);
                }
              );
            },
            function(err){
              return innerCallback(err);
            }
          );
        });
      }
    ],
    function(err, results){
      return callback(err, growPlanInstance);
    }
  );
});




/**
 * Deactivate an existing grow plan instance. 
 * Expire any actions/notifications
 * If there's a device, unset the device's activeGrowPlanInstance property
 *
 * @param {function(err, gpi)} callback
 */
GrowPlanInstanceSchema.method('deactivate', function(callback) {
  var gpi = this,
      now = new Date();

    gpi.active = false;
    gpi.endDate = now;
    gpi.phases.forEach(function(phase){
      if (phase.active){
        phase.endDate = now;
      }
    });
    
    gpi.save(function (err){
      if (err) { return callback(err);}

      async.parallel([
        function expireNotifications(innerCallback){
          NotificationModel.expireAllGrowPlanInstanceNotifications(
            gpi._id,
            innerCallback
          );
        },
        function expireImmediateActions(innerCallback){
          ImmediateActionModel.update(
            {
              'gpi' : gpi._id,
              'e' : { $gte: now }
            },
            {
              $set : {
                'e' : now
              }
            },
            { multi : true },
            innerCallback
          );
        },
        function updateDevice(innerCallback){
          if (!gpi.device){ return innerCallback(); }

          DeviceModel.findByIdAndUpdate(
            getDocumentIdString(gpi.device),
            {
              $unset : { 
                'activeGrowPlanInsance' : 1 
              },
              $set : {
                'status.expires' : now
              }
            },
            innerCallback
          );
        },
        function updateGrowPlanCounts(innerCallback){
          GrowPlanModel.findByIdAndUpdate(
            gpi.growPlan, 
            { 
              $inc: { 
                activeGardenCount: -1,
                completedGardenCount: 1
              }
            }, 
            innerCallback
          );
        }
      ],
      function(err){
        return callback(err);
      }
    );
  });
});



/**
 * Called when a GP that the GPI is tracking has been updated (meaning either edited or branched).
 * We then need to migrate this GPI to the new GrowPlan, updating all notifications, actions, etc.
 * Can be called with the original Grow Plan when we need to refresh the notifications etc.
 *
 *
 * @param {GrowPlanModel} options.newGrowPlan : Should be a GrowPlanModel or fully-populated GP, not just an id
 * @param {ObjectId} options.newGrowPlanPhaseId : TODO. Allow the target phase to be specified
 * @param {function(err)} callback
 */
GrowPlanInstanceSchema.method("migrateToGrowPlan", function(options, callback){
  var self = this,
      NotificationModel = require('./notification').model,
      newGrowPlan = options.newGrowPlan,
      now = new Date(),
      activeGPIPhase,
      activeGrowPlanPhase,
      elapsedPhaseDays,
      matchingNewGrowPlanPhase;


  if (!newGrowPlan._id.equals(getObjectId(self.growPlan))
      &&
      !(newGrowPlan.parentGrowPlanId && 
        newGrowPlan.parentGrowPlanId.equals(getObjectId(self.growPlan))
      )
    ){
    return callback(new Error(i18nKeys.get("A GrowPlanInstanece can only be migrated to a the updated original Grow Plan or a descendent of it."))); 
  }


  GrowPlanModel.findById(self.growPlan).exec(function(err, originalGrowPlan){
    if (err) { return callback(err); }

    activeGPIPhase = self.getActivePhase();
    activeGrowPlanPhase = originalGrowPlan.phases.filter(function(phase){ return phase._id.equals(activeGPIPhase.phase); })[0];
    elapsedPhaseDays = self.getPhaseDay(activeGPIPhase, now);

    

    // First, try to find the equivalent phase in the new GrowPlan to transition the GPI to
    // Matching : match on name only...anything else might result in unexpected
    // behavior from the perspective of the user
    if (originalGrowPlan._id.equals(newGrowPlan._id)){
      matchingNewGrowPlanPhase = newGrowPlan.phases.filter(function(newPhase){
        return newPhase._id.equals(activeGrowPlanPhase._id);
      })[0];
    } else {
      matchingNewGrowPlanPhase = newGrowPlan.phases.filter(function(newPhase){
        return newPhase.name === activeGrowPlanPhase.name;
      })[0];
    }
    

    if (!matchingNewGrowPlanPhase){
      // Notify the user that there was a GrowPlan update that we couldn't automatically handle, so they're still on the old Grow Plan
      NotificationModel.create(
      {
        users : self.users,
        gpi : self._id,
        timeToSend : now,
        type : feBeUtils.NOTIFICATION_TYPES.INFO,
        trigger : feBeUtils.NOTIFICATION_TRIGGERS.GROW_PLAN_UPDATE,
        triggerDetails : {
          newGrowPlanId : newGrowPlan._id,
          migrationSuccessful : false
        }
      }, 
      callback);

    } else {
      self.growPlan = newGrowPlan;

      
      self.activatePhase({
        phaseId : matchingNewGrowPlanPhase._id,
        phaseDay : elapsedPhaseDays,
        save : false
      }, function(err){
        self.growPlanMigrations.push({
          oldGrowPlan : newGrowPlan.parentGrowPlanId || newGrowPlan,
          newGrowPlan : newGrowPlan,
          ts : now
        });

        self.save(function(err, updatedGrowPlanInstance){
          if (err) { return callback(err); }

          NotificationModel.create(
          {
            users : self.users,
            gpi : self._id,
            timeToSend : now,
            type : feBeUtils.NOTIFICATION_TYPES.INFO,
            trigger : feBeUtils.NOTIFICATION_TRIGGERS.GROW_PLAN_UPDATE,
            triggerDetails : {
              newGrowPlanId : newGrowPlan._id,
              migrationSuccessful : true
            }
          }, 
          callback);
        });  
      });

      
    }
  });
  
});
/************** END INSTANCE METHODS ********************/




/***************** MIDDLEWARE **********************/

/**
 * Remove old recentXLogs
 */
GrowPlanInstanceSchema.pre('save', true, function(next, done){
  next();

  var now = Date.now(),
    cutoff = now - (1000 * 60 * 2), // now - 2 hours
    logsToRemove = [];
  
  done();
});

/***************** END MIDDLEWARE **********************/

GrowPlanInstanceModel = mongooseConnection.model('GrowPlanInstance', GrowPlanInstanceSchema);


/**
 * @type {Schema}
 */
exports.schema = GrowPlanInstanceSchema;


/**
 * @constructor
 * @alias module:models/Garden.GrowPlanInstanceModel
 * @type {Model}
 */
exports.model = GrowPlanInstanceModel;
