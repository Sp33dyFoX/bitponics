/**
 * @module models/Notification
 */

var mongoose = require('mongoose'),
  Schema = mongoose.Schema,
  mongoosePlugins = require('../lib/mongoose-plugins'),
  useTimestamps = mongoosePlugins.useTimestamps,
  requirejs = require('../lib/requirejs-wrapper'),
  feBeUtils = requirejs('fe-be-utils'),
  ObjectIdSchema = Schema.ObjectId,
  ObjectId = mongoose.Types.ObjectId,
  mongooseConnection = require('../config/mongoose-connection').defaultConnection,
  async = require('async'),
  utils = require('./utils'),
  getObjectId = utils.getObjectId,
  winston = require('winston'),
  NotificationModel,
  ejs = require('../config/ejs-config'),
  path = require('path'),
  fs = require('fs'),
  notificationTemplateDirectory = path.join(__dirname, '/../views/notifications'),
  notificationTemplateTypes = ['email-subject', 'email-body-text', 'email-body-html', 'detail-html', 'summary-text'],
  compiledNotificationTemplates = {};

// Compile all the EJS templates
Object.keys(feBeUtils.NOTIFICATION_TRIGGERS).forEach(function(key){
  var keyValue = feBeUtils.NOTIFICATION_TRIGGERS[key];
  compiledNotificationTemplates[keyValue] = {};

  notificationTemplateTypes.forEach(function(templateType){
    // Enable the console.logs whenever making edits to the EJS templates...ejs.compile fails silently so that's
    // the only way to know which template failed compilation
    //console.log("COMPILING " + keyValue + " " + templateType);
    compiledNotificationTemplates[keyValue][templateType] = ejs.compile(fs.readFileSync(path.join(notificationTemplateDirectory, keyValue, templateType + ".ejs"), 'utf8'));
    //console.log("COMPLETED COMPILING " + keyValue + " " + templateType);
  });
});


/*************** Validate ******************************/
var dateNotInPast = function(date) {
  // 30s cutoff for ensuring notification has future tts date
  var futureCutoff = new Date((new Date()).valueOf() - 30 * 1000),
      date = date ? date : new Date();

  //if date not in past return true = valid date
  return (date.valueOf() > futureCutoff);
};

var dateValidationFns = [
  { validator: dateNotInPast, msg: 'Newly created notifications must have an immediate or future tts date.' }
];

var NotificationSentLogSchema = new Schema({ 
  /**
   * timestamp
   * The time this log was specified to be sent (timeToSend from parent Notification). 
   * TODO : migrate all db entries from ts to tts
   */
  ts : { type : Date },

  
  /**
   * emailedAt
   * If this tts was emailed, this is the time the email was sent
   */
  eA : { type : Date, required : false },


  /**
   * checkedAt
   * User can "check" a notification log to hide it/mark completed
   */
  cA : { type : Date, required : false }
},
{ _id : false, id : false });

NotificationSentLogSchema.virtual('timeToSend')
.get(function(){
  return this.ts;
})
.set(function(timeToSend){
  this.ts = timeToSend;
});

NotificationSentLogSchema.virtual('emailedAt')
.get(function(){
  return this.eA;
})
.set(function(value){
  this.eA = value;
});

NotificationSentLogSchema.virtual('checkedAt')
.get(function(){
  return this.cA;
})
.set(function(checkedAt){
  this.cA = checkedAt;
});

NotificationSentLogSchema.virtual('checked')
.get(function(){
  return !!this.cA;
})
.set(function(checked){
  if (this.cA) { return; }
  this.cA = new Date();
});


/**
 * Notification
 * 
 * - IdealRange violation that can be handled by device (type="info")
 * - IdealRange violation that can't be handled by device (type="actionNeeded")
 * - Phase Actions being started (at phase activation) 
 * - Actions triggered by IdealRange violations
 * - Action cycles that aren't handled by device triggering repeating notifications (type="actionNeeded")
 * - GrowPlan was updated and we updated your Garden to use it
 * - GrowPlan was updated but we couldn't automatically update your garden. Come select which phase of the new Grow Plan to use
 */
var NotificationSchema = new Schema({
  

  /**
   * users
   * Users to send the notification to.
   * Will usually be a copy of a GPI's or Device's users
   */
  u : [{ type: ObjectIdSchema, ref: 'User', required: true }],


  /**
   * GrowPlanInstance. Optional.
   */
  gpi: { type: ObjectIdSchema, ref: 'GrowPlanInstance', required: false },


  /**
   * timeToSend
   * The time to send the notification. 
   * Once a notification is sent and has no further repeats, this is set to null. 
   * To clear pending notifications, this field is queried for values <= now
   */ 
  tts : { type: Date, validate: dateValidationFns },


  /**
   * repeat
   * If present, defines a repeat schedule for a notification.
   * Once the notification is sent, it's used to update the 
   * "timeToSend" field to the next time the notification should be sent
   */
  r : {
    /**
     * durationType
     */
    durationType : { type: String, enum: feBeUtils.DURATION_TYPES },
    
    /**
     * duration
     */
    duration : { type : Number },
    
    /*
     * timezone
     */
    timezone : String
  },
  



  /**
   * sentLogs
   */
  sl : [ NotificationSentLogSchema ],

  
  /**
   * Storing the thing that triggered the notification.
   * Going to use this to group notifications together
   */
  trigger : {
    type : String,
    enum : [
      feBeUtils.NOTIFICATION_TRIGGERS.PHASE_END,
      feBeUtils.NOTIFICATION_TRIGGERS.PHASE_END_ACTION,
      feBeUtils.NOTIFICATION_TRIGGERS.PHASE_START,
      feBeUtils.NOTIFICATION_TRIGGERS.PHASE_ACTION,
      feBeUtils.NOTIFICATION_TRIGGERS.IDEAL_RANGE_VIOLATION,
      feBeUtils.NOTIFICATION_TRIGGERS.IMMEDIATE_ACTION,
      feBeUtils.NOTIFICATION_TRIGGERS.PHASE_ENDING_SOON,
      feBeUtils.NOTIFICATION_TRIGGERS.GROW_PLAN_UPDATE,
      feBeUtils.NOTIFICATION_TRIGGERS.DEVICE_MISSING
    ],
    required : true
  },

  
  /**
   * Mixed object type to let Notification triggers
   * store any pertinent data, intended to be interpolated
   * into the notification display
   * 
   * Current properties in use:
   * - phaseName {String}
   * - gpiPhaseId {ObjectId}
   * - gpPhaseId {ObjectId}
   * - actionId {ObjectId}
   * - newGrowPlanId {ObjectId}
   * - deviceId {String}
   *
   * PHASE_END
   * - phaseName
   * - gpPhaseId
   *
   * PHASE_ENDING_SOON
   * - gpPhaseId
   * - gpiPhaseId
   * - nextGpPhaseId
   *
   * PHASE_ACTION
   * - actionId {ObjectId}
   * - handledByDeviceControl {bool}
   * - cycleStateIndex {Number=}
   *
   * IMMEDIATE_ACTION
   * - actionId {ObjectId}
   * - immediateActionId {ObjectId}
   * - handledByDeviceControl {bool}
   *
   * IDEAL_RANGE_VIOLATION
   * - idealRangeId {ObjectId}
   * - sensorValue {Number}
   * - timestamp {Date}
   * - gpPhaseId {ObjectId}
   * - immediateActionId {ObjectId}
   * - actionId {ObjectId}
   * - handledByDeviceControl {bool}
   *
   * GROW_PLAN_UPDATE
   * - newGrowPlanId {ObjectId}
   * - migrationSuccessful {bool}
   *
   * DEVICE_MISSING
   * - deviceId {string}
   */
  triggerDetails : Schema.Types.Mixed,

  
  /**
   * type
   */
  type : { 
    type: String, 
    enum: [
      feBeUtils.NOTIFICATION_TYPES.INFO,
      feBeUtils.NOTIFICATION_TYPES.ACTION_NEEDED,
      feBeUtils.NOTIFICATION_TYPES.ERROR
    ],
    required : true,
    default : feBeUtils.NOTIFICATION_TYPES.INFO
  },
  

  /**
   * hash
   * MD5 hash of unique details (gpi + trigger + trigger details)
   * Used to prevent creation of contemporaneous duplicates
   */
  h : { type : String },

  
  /**
   * checked
   * User can "check" a notification log to hide it/mark completed
   *
   * "Checking" a notification should create a sentLog entry with "checkedAt" set
   * 
   * This is a dynamic property. It's false by default, set to true if 
   * a notification has been checked
   */
  //c : { type : Boolean }

},
{ id : false });

NotificationSchema.plugin(useTimestamps);
NotificationSchema.plugin(mongoosePlugins.recoverableRemove);


NotificationSchema.virtual('users')
  .get(function(){
    return this.u;
  })
  .set(function(users){
    this.u = users;
  });

NotificationSchema.virtual('growPlanInstance')
  .get(function(){
    return this.gpi;
  })
  .set(function(growPlanInstance){
    this.gpi = growPlanInstance;
  });

NotificationSchema.virtual('timeToSend')
  .get(function(){
    return this.tts;
  })
  .set(function(timeToSend){
    this.tts = timeToSend;
  });

NotificationSchema.virtual('repeat')
  .get(function(){
    return this.r;
  })
  .set(function(repeat){
    this.r = repeat;
  });

/*
NotificationSchema.virtual('r.durationType')
  .get(function(){
    return this.r.dT;
  })
  .set(function(durationType){
    this.r.dT = durationType;
  });

NotificationSchema.virtual('r.duration')
  .get(function(){
    return this.r.d;
  })
  .set(function(duration){
    this.r.d = duration;
  });

NotificationSchema.virtual('r.timezone')
  .get(function(){
    return this.r.tz;
  })
  .set(function(timezone){
    this.r.tz = timezone;
  });
*/

NotificationSchema.virtual('sentLogs')
  .get(function(){
    return this.sl;
  })
  .set(function(sentLogs){
    this.sl = sentLogs;
  });

// NotificationSchema.virtual('checked')
//   .get(function(){
//     return this.c;
//   })
//   .set(function(checked){
//     this.c = checked;
//   })

NotificationSchema.virtual('hash')
  .get(function(){
    return this.h;
  })
  .set(function(hash){
    this.h = hash;
  });


/*************** SERIALIZATION *************************/

/**
 * Remove the db-only-optimized property names and expose only the friendly names
 *
 * "Transforms are applied to the document and each of its sub-documents"
 * http://mongoosejs.com/docs/api.html#document_Document-toObject
 */
NotificationSchema.set('toObject', {
  getters : true,
  transform : function(doc, ret, options){
    if (doc.schema === NotificationSentLogSchema){
      delete ret.ts;
      delete ret.c;
      delete ret.cA;
    } else {
      // else we're operating on the parent doc (the NotificationSchema doc)
      delete ret.u;
      delete ret.gpi;
      delete ret.tts;
      delete ret.r;
      delete ret.sl;
      delete ret.h;

    }
  }
});
NotificationSchema.set('toJSON', {
  getters : true,
  transform : NotificationSchema.options.toObject.transform
});
/*************** END SERIALIZATION *************************/





/*************** INSTANCE METHODS *************************/

/**
 * Marks the provided "timeToSend" sentLog as checked
 * 
 * If the current notification.timeToSend was provided, creates a sentLog entry and resets timeToSend
 * 
 * @param {Date} [timeToSendToCheck] - Mark a specific tts as checked. If omitted, uses the most recent notification.timeToSend/notification.sentLog
 */
NotificationSchema.method('markAsChecked', function(timeToSendToCheck){
  var notification = this,
      timeToSendToCheckAsMilliseconds,
      sentLogFound,
      now = new Date(),
      nowAsMilliseconds = now.valueOf();

  if (!timeToSendToCheck){
    
    if (notification.timeToSend && (notification.timeToSend.valueOf() < nowAsMilliseconds)){
      timeToSendToCheck = notification.timeToSend;
    } else if (notification.sentLogs.length > 0){
      // notification.sentLogs are ordered by ascending timeToSend
      timeToSendToCheck = notification.sentLogs[notification.sentLogs.length-1].timeToSend;
    } else {
      // else, no valid date to use
      return;
    }
  }

  timeToSendToCheckAsMilliseconds = timeToSendToCheck.valueOf();

  sentLogFound = notification.sentLogs.some(function(sentLog){
    if (sentLog.timeToSend.valueOf() === timeToSendToCheckAsMilliseconds){
      sentLog.checked = true;
      return true;
    }
  });
  
  if (!sentLogFound){
    notification.sentLogs.push({
      timeToSend : timeToSendToCheck,
      checked : true
    });
  }

  if(notification.timeToSend && notification.timeToSend.valueOf() === timeToSendToCheckAsMilliseconds){
    notification.resetTimeToSend();
  }

});


/**
 * Resets notification's timeToSend to the next timeToSend, or null notification doesn't repeat
 * 
 * 
 */
NotificationSchema.method('resetTimeToSend', function(){
  var notification = this,
      now = new Date(),
      nowAsMilliseconds = now.valueOf(),
      //tz = require('../lib/timezone-wrapper');
      moment = require('moment');

  if (notification.timeToSend && notification.repeat && notification.repeat.timezone && notification.repeat.duration && notification.repeat.durationType){
    winston.info("IN clearPendingNotifications, resetting notification.repeat", notification._id.toString(), notification.timeToSend, notification.repeat.timezone, '+' + notification.repeat.duration + ' ' + notification.repeat.durationType)
    // Prevent notifications from getting stuck on repeat in the past...shouldn't actually ever happen
    // if we've got notifications regularly being processed
    //console.log('nowAsMilliseconds', nowAsMilliseconds);
    //console.log('timeToSend start', notification.timeToSend.valueOf());
    //console.log(tz(notification.timeToSend, '+' + notification.repeat.duration + ' ' + notification.repeat.durationType));

    while (notification.timeToSend.valueOf() < nowAsMilliseconds){
      notification.timeToSend = moment(notification.timeToSend).add(notification.repeat.durationType, notification.repeat.duration).toDate();
    } 
  } else {
    notification.timeToSend = null;
  }
});

/**
 * Creates a hash of the pertinent Notification details:
 * gpi, repeat, type, trigger, triggerDetails
 * 
 * Used to prevent insertion of duplicate Notifications 
 * by checking whether a pending Notification matches an existing one.
 *
 * Contains a couple rules custom to each Notification trigger type:
 * Ignores triggerDetails.sensorValue, 
 * since sensor values can change rapidly but we don't want to swamp a user with 
 * a bunch of Notifications on the same sensor
 * 
 * @return {string} hash of the Notification
 */
NotificationSchema.method('ensureHash', function(){
  if (!this.hash) { 
    var crypto = require('crypto'),
        stringToHash,
        // clone the triggerDetails so we can operate on the clone without affecting the original
        triggerDetailsToHash = JSON.parse(JSON.stringify(this.triggerDetails || {}));

    delete triggerDetailsToHash.sensorValue;
    
    // ImmediateActions can be created in response to every sensor reading, and should be created
    // in response to every violation. But as far as the Notification, immediateActionId isn't pertinent data.
    delete triggerDetailsToHash.immediateActionId;

    delete triggerDetailsToHash.timestamp;
    
    stringToHash = (
      (this.gpi ? this.gpi.toString() : '') + 
      (JSON.stringify(this.r) || '') + 
      this.type + 
      this.trigger + 
      JSON.stringify(triggerDetailsToHash)
    );

    this.hash = crypto.createHash('md5').update(stringToHash).digest('hex');
  }
  return this.hash;
});


/**
 * Returns the Notification populated into the specified display template
 *
 * 'summary' returns a string
 * 'detail' returns string of html
 * 'email' returns { subject: string, bodyHtml : string, bodyText: string }
 * 'json' returns the data retrieved for template population (garden, actions, growPlans, etc). For now just returns garden...no use cases yet to return everything & the data gets massive
 *
 * @param {string[]} options.displayTypes - List of display types. Must be one of 'email'|'summary'|'detail'
 * @param {string} options.secureAppUrl
 * @param {function} callback - Passed an object of displays keyed by displayType
 */
NotificationSchema.method('getDisplays', function(options, callback){
  var notification = this,
      ActionModel = require('./action').model,
      GrowPlanModel = require('./growPlan').growPlan.model,
      SensorModel = require('./sensor').model,
      DeviceModel = require('./device').model,
      ControlModel = require('./control').model, // need this so that mongoose registers Control schema in worker process
      UserModel = require('./user').model, // need this so that mongoose registers User schema in worker process
      ImmediateActionModel = require('./immediateAction').model,
      notificationTemplateLocals = {
        notification : notification,
        notificationDetails : JSON.parse(JSON.stringify(notification.triggerDetails)),
        NOTIFICATION_TYPES : feBeUtils.NOTIFICATION_TYPES,
        ACCESSORY_VALUES : feBeUtils.ACCESSORY_VALUES,
        secureAppUrl : options.secureAppUrl
      },
      notificationDisplays = {};

  
  async.waterfall(
    [
      function populateGPI(innerCallback){
        if (notification.gpi && !notification.populated('gpi')){ 
          notification.populate('gpi', innerCallback);
        } else {
          return innerCallback(null, notification); 
        }
      },
      function populateParallels(notification, waterfallCallback){
        async.parallel(
          [
            function populateAction(innerCallback){
              if (!notification.triggerDetails.actionId){ return innerCallback(); }
              
              ActionModel.findById(notification.triggerDetails.actionId)
              .populate('control', 'name')
              .exec(function(err, actionResult){
                notificationTemplateLocals.notificationDetails.action = actionResult;
                return innerCallback(err);
              });
              
            },
            function populateDevice(innerCallback){
              if (!notification.triggerDetails.deviceId){ return innerCallback(); }

              DeviceModel.findById(notification.triggerDetails.deviceId)
              .exec(function(err, deviceResult){
                notificationTemplateLocals.notificationDetails.device = deviceResult;
                return innerCallback(err);
              });
            },
            function populateImmediateAction(innerCallback){
              if (!notification.triggerDetails.immediateActionId){ return innerCallback(); }

              ImmediateActionModel.findById(notification.triggerDetails.immediateActionId)
              .exec(function(err, immediateActionResult){
                notificationTemplateLocals.notificationDetails.immediateAction = immediateActionResult;
                return innerCallback(err);
              });
            },
            function populateGrowPlan(innerCallback){
              if (!notification.gpi || !notification.triggerDetails.gpPhaseId){ return innerCallback(); }

              GrowPlanModel.findById(notification.gpi.growPlan)
              .exec(function(err, growPlanResult){
                if (err) { return innerCallback(err);}
                
                notificationTemplateLocals.notificationDetails.growPlanPhase = growPlanResult.phases.id(notification.triggerDetails.gpPhaseId);

                if (notification.triggerDetails.nextGpPhaseId){
                  notificationTemplateLocals.notificationDetails.nextGrowPlanPhase = growPlanResult.phases.id(notification.triggerDetails.nextGpPhaseId);  
                }
                
                if (notification.triggerDetails.gpiPhaseId){
                  notificationTemplateLocals.notificationDetails.growPlanInstancePhase = notification.gpi.phases.id(notification.triggerDetails.gpiPhaseId);
                }
                  
                if (!notification.triggerDetails.idealRangeId){ return innerCallback(); }
                
                notificationTemplateLocals.notificationDetails.idealRange = notificationTemplateLocals.notificationDetails.growPlanPhase.idealRanges.id(notification.triggerDetails.idealRangeId);
                
                // The line below is a quick & dirty fix for an exception...idealRange shouldn't actually be undefined here
                if (!notificationTemplateLocals.notificationDetails.idealRange) { 
                  winston.error("Invalid notification triggerDetails.idealRangeId " + notification._id.toString() + " " + JSON.stringify(notification.triggerDetails));
                  return innerCallback(); 
                }

                SensorModel.findOne({code : notificationTemplateLocals.notificationDetails.idealRange.sCode})
                .exec(function(err, sensorResult){
                  notificationTemplateLocals.notificationDetails.sensor = sensorResult;
                  return innerCallback();  
                });
                
              });
            },
            function populateNewGrowPlan(innerCallback){
              if (!notification.triggerDetails.newGrowPlanId){ return innerCallback(); }

              GrowPlanModel.findById(notification.triggerDetails.newGrowPlanId)
              .select('parentGrowPlanId name owner createdAt')
              .populate('owner','name')
              .exec(function(err, growPlanResult){
                notificationTemplateLocals.notificationDetails.newGrowPlan = growPlanResult;
                return innerCallback(err);
              });
            }
            
          ],
          function(err){
            //console.log("PARALLEL FINAL", err, options, notification, notificationTemplateLocals);
            return waterfallCallback(err);
          }
        );
      },
      function populateTimezone(waterfallCallback){
        notification.triggerDetails.timezone = "America/New_York";
        return waterfallCallback();
      }
    ],
    function waterfallFinal(err){
      if (err) { return callback(err); }
          
      // At this point, notificationTemplateLocals is fully populated
      // 2013-08-22 AK: Getting occasional errors that I don't have time to fully debug, just wrapping things in a try/finally to ensure execution continues

      options.displayTypes.forEach(function(displayType){
        var notificationDisplay,
            err;

        try {
          switch(displayType){
            case 'email':
              notificationDisplay = {
                subject : compiledNotificationTemplates[notification.trigger]['email-subject'](notificationTemplateLocals),
                bodyHtml : compiledNotificationTemplates[notification.trigger]['email-body-html'](notificationTemplateLocals),
                bodyText : compiledNotificationTemplates[notification.trigger]['email-body-text'](notificationTemplateLocals)
              };
              break;
            case 'summary':
              notificationDisplay = compiledNotificationTemplates[notification.trigger]['summary-text'](notificationTemplateLocals);
              break;
            case 'detail':
              notificationDisplay = compiledNotificationTemplates[notification.trigger]['detail-html'](notificationTemplateLocals);
              break;
            case 'json':
              notificationDisplay = {
                garden: {
                  _id : notificationTemplateLocals.notification.growPlanInstance._id,
                  name : notificationTemplateLocals.notification.growPlanInstance.name
                }
              };
          }
        } catch(e){
          winston.error(JSON.stringify(e, ['message', 'arguments', 'type', 'name', 'stack'])); 
        }

        if ((typeof notificationDisplay === 'undefined') || (options.displayType === 'email' && !(notificationDisplay.bodyHtml))){
          console.log("Error populating EJS notification template for " + notification._id.toString());
          console.log(JSON.stringify(notificationTemplateLocals));
          err = new Error("Error populating EJS notification template for " + notification._id.toString());
        }

        notificationDisplays[displayType] = notificationDisplay; 
      });

      return callback(err, notificationDisplays);
    }
  );
});

/*************** END INSTANCE METHODS *************************/



/*************** STATIC METHODS *************************/
/**
 * All new instances of Notification should be created with this method.
 * This method, by default, first checks whether we already have any existing duplicate of the submitted
 * notification that's active (tts is not null) or has recently been sent. 
 * If so, it returns that existing Notification.
 *
 * If options.repeat is defined, must be greater than 1 day.
 *
 * "Recently been sent" cutoff varies per trigger type.
 *
 * @param {Object} options : Properties of the NotificationModel object. All properties are expected to be in friendly form, if a friendly form exists (virtual prop name)
 * @param {function(err, Notification)} callback
 */
NotificationSchema.static('create', function(options, callback){
  // TODO : Investigate the performance of this query. Assuming it'll be fine because
  // mongo can filter with the index we have on tts+gpi first, which
  // should greatly lessen the load
  
  //do not create notifications with repeat of less than 1 day
  if (options.repeat && feBeUtils.isLessThanOneDay(options.repeat.duration, options.repeat.durationType)) {
    winston.info('not saving this notification due to repeat less than 1 day');
    return callback();
  }

  var newNotification = new NotificationModel(options),
      sentCutoff;

  switch(options.trigger){
    case feBeUtils.NOTIFICATION_TRIGGERS.DEVICE_MISSING:
      // for device missing, the hash takes into account the "lastConnectionAt" property
      // We don't want to bombard the user with multiple emails per connection outage...
      // cap it at 1 per day for a given continuous outage
      sentCutoff = new Date((new Date()).valueOf() - 24 * 60 * 60 * 1000);
      break;
    default:
      // default is 8 hour sent cutoff for dupes
      sentCutoff = new Date((new Date()).valueOf() - 8 * 60 * 60 * 1000);
  } 
  
  newNotification.ensureHash();

  NotificationModel.findOne({
    h : newNotification.h,
    $or: [
      { "sl.ts" : { $gte : sentCutoff } },
      { tts: { $ne : null } }
    ]
  })
  .exec(function(err, notificationResult){
    if (err) { return callback(err); }
    if (notificationResult){
      return callback(null, notificationResult);
    }
    
    newNotification.save(callback);

  });
});


/**
 * Called when moving to new phases in a Grow Plan
 */
NotificationSchema.static('expireAllGrowPlanInstanceNotifications', function(growPlanInstanceId, callback){
  var now = new Date();

  NotificationModel
  .update(
    { gpi : growPlanInstanceId }, 
    { $unset : { 'tts' : 1 }},
    { multi : true }
  ).exec(callback);
});



/** 
 * Send all pending notifications to their recipients.
 *
 * Gets Notifications with "timeToSend" in the past, sends them, then resets "timeToSend"
 *
 * @param {string} options.env - must be one of 'local'|'development'|'staging'|'production'
 * @param {function(err, numberResultsAffected)} callback
 */
NotificationSchema.static('clearPendingNotifications', function (options, callback){
  var ActionModel = require('./action').model,
      GrowPlanModel = require('./growPlan').growPlan.model,
      SensorModel = require('./sensor').model,
      DeviceModel = require('./device').model,
      ControlModel = require('./control').model, // need this so that mongoose registers Control schema in worker process
      ImmediateActionModel = require('./immediateAction').model,
      EmailConfig = require('../config/email-config'),
      nodemailer = require('nodemailer'),
      tz = require('../lib/timezone-wrapper'),
      async = require('async'),
      winston = require('winston'),
      requirejs = require('../lib/requirejs-wrapper'),
      feBeUtils = requirejs('fe-be-utils'),
      i18nKeys = require('../i18n/keys'),
      ejs = require('../config/ejs-config'),
      path = require('path'),
      fs = require('fs'),
      emailTemplates = require('email-templates'),
      emailTemplatesDir = path.join(__dirname, '/../views/emails'),
      appUrl = 'http://' + (require('../config/app-domain-config')[options.env || 'local']),
      secureAppUrl = 'https://' + (require('../config/app-domain-config')[options.env || 'local']),
      subscriptionPreferencesUrl = secureAppUrl + "/account/profile",
      now = new Date(),
      nowAsMilliseconds = now.valueOf();

  winston.info('IN clearPendingNotifications');

  NotificationModel
  .find()
  .where('tts')
  .lte(now)
  .populate('u', 'email notificationPreferences')
  .populate('gpi')
  .exec(function(err, notificationResults){
    if (err) { return callback(err); }
    if (!notificationResults.length){ return callback(null, 0); }

    // TEMP HACK : enable next line to disable emails
    //return callback(null, notificationResults.length);

    winston.info("IN clearPendingNotifications, db " + NotificationModel.db.name);
    winston.info('IN clearPendingNotifications, PROCESSING ' + notificationResults.length + ' RESULTS ' + now);

    var emailTransport = nodemailer.createTransport("SES", EmailConfig.amazonSES.api);
    
    async.waterfall(
      [
        function compileEmailTemplate(innerCallback){
          emailTemplates(emailTemplatesDir, innerCallback);
        },
        function processNotificationResults(runEmailTemplate, innerCallback){
          
          var notificationIterator = function (notification, iteratorCallback){
            winston.info("PROCESSING NOTIFICATION " + notification._id.toString());
            
            var shouldNotSendEmailNotification = function (notification) {
              return (notification.type === feBeUtils.NOTIFICATION_TYPES.INFO) ||
                (notification.trigger === feBeUtils.NOTIFICATION_TRIGGERS.PHASE_ACTION && typeof notification.triggerDetails.cycleStateIndex !== 'undefined') ||
                (feBeUtils.isLessThanOneDay(notification.repeat.duration, notification.repeat.durationType))
            };

            winston.info("EMAIL NOTIFICATION?");
            
            if (shouldNotSendEmailNotification(notification)) {
              winston.info("DID NOT SEND EMAIL NOTIFICATION " + notification._id.toString());
              winston.info("notification.repeat.duration: " + notification.repeat.duration);
              winston.info("notification.repeat.durationType: " + notification.repeat.durationType);
              console.log(feBeUtils.isLessThanOneDay(notification.repeat.duration, notification.repeat.durationType));
              return iteratorCallback();
            }

            winston.info("YES");

            // Populate trigger details
            notification.getDisplays(
              {
                secureAppUrl : secureAppUrl,
                displayTypes : ['email']
              },
              function(err, notificationDisplays){
                if (err) { return iteratorCallback(err); }

                winston.info("PROCESSING NOTIFICATION " + notification._id.toString() + " GOT NOTIFICATION DISPLAY " + now);

                // 
                if (!notificationDisplays.email){
                  winston.error("ERROR CREATING EMAIL FOR NOTIFICATION " + notification._id.toString());
                  return iteratorCallback(new Error("ERROR CREATING EMAIL FOR NOTIFICATION " + notification._id.toString()));
                }

                var emailTemplateLocals = {
                  emailSubject : notificationDisplays.email.subject,
                  emailBodyHtml : notificationDisplays.email.bodyHtml,
                  emailBodyText : notificationDisplays.email.bodyText,
                  subscriptionPreferencesUrl : subscriptionPreferencesUrl,
                  appUrl : appUrl
                },  
                users = notification.users,
                filteredUsers = users.filter(function(user) { 
                  return user.notificationPreferences.email;
                });

                // TEMP HACK : special alert for hyatt device
                try {
                  if (NotificationModel.db.name.indexOf('prod') >= 0){
                    if ( (notification.trigger === feBeUtils.NOTIFICATION_TRIGGERS.DEVICE_MISSING) &&
                         (notification.triggerDetails.deviceId === '000666809f5b')
                       ){
                      
                      winston.info('IN clearPendingNotifications, special case adding bitponics team');
                      // TEMP HACK : remove Hyatt from email notifications
                      filteredUsers = [{email : 'amit@bitponics.com'}, { email : 'michael@bitponics.com'}, {email : 'jack@bitponics.com'}];
                      emailTemplateLocals.emailSubject = "HYATT DEVICE CONNECTION DROPPED";
                    }
                  }
                } catch(e){
                  winston.error(JSON.stringify(e, ['message', 'arguments', 'type', 'name', 'stack']));
                }

                // TEMP HACK WHILE DEBUGGING : send all emails to self
                // filteredUsers = [{email : 'jack@bitponics.com'}];

                runEmailTemplate('default', emailTemplateLocals, function(err, finalEmailHtml, finalEmailText) {
                  winston.info("PROCESSING NOTIFICATION " + notification._id.toString() + " GOT NOTIFICATION EMAIL TEMPLATE POPULATED " + now);

                  if (err) { return iteratorCallback(err); }

                  var mailOptions = {
                    from: "notifications@bitponics.com",
                    to: filteredUsers.map(function(user) { return user.email; }).join(', '),
                    subject: emailTemplateLocals.emailSubject,
                    text: finalEmailText,
                    html: finalEmailHtml
                  };

                  winston.info("IN clearPendingNotifications, ATTEMPTING TO SEND EMAIL NOTIFICATION TO " + mailOptions.to);
                  
                  emailTransport.sendMail(mailOptions, function(err, response){
                    winston.info("PROCESSING NOTIFICATION " + notification._id.toString(), " GOT RESPONSE FROM EMAIL TRANSPORT " + now);
                    if (err) { return iteratorCallback(err); }
                    
                    notification.sentLogs.push({
                      timeToSend: notification.timeToSend,
                      emailedAt: now
                    });
                    
                    notification.resetTimeToSend();

                    winston.info("PROCESSING NOTIFICATION " + notification._id.toString() + " SAVING UPDATED NOTIFICATION DOCUMENT " + now);
                    notification.save(iteratorCallback);
                  });
                });
              }
            );
          };

          var notificationProcessingEnded = function(){
            return innerCallback(err, notificationResults.length);
          };

          if (!notificationResults.length){
            return notificationProcessingEnded();
          }
          
          var notificationResultProcessingQueue = async.queue(notificationIterator, 5);
          notificationResultProcessingQueue.drain = notificationProcessingEnded;
          notificationResultProcessingQueue.push(notificationResults, function(err){
            winston.info("NotificationModel.clearPendingNotifications FINISHED PROCESSING A NOTIFICATION " + now);
            if (err) { 
              winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack']));
            }
          });
        }
      ],
      function (err, numberResultsAffected){
        return callback(err, numberResultsAffected);
      }
    );
  });
});


/**
 * TODO: doc
 */
NotificationSchema.pre('save', function(next){
  // Since triggerDetails is a Mixed type, mongoose can't auto-detect whether it's modified.
  // Just always mark it modified.
  this.markModified('triggerDetails');
  this.ensureHash();
  next();
});



// Sparse index on timeToSend so that we skip nulls
NotificationSchema.index({ 'tts': -1 }, { sparse : true });
// Compound index on gpi+tts. Won't get expensive since all sent items will collapse into a single index entry of gpi+null
NotificationSchema.index({ 'gpi' : 1, 'tts': -1}, { sparse : true } );
NotificationSchema.index({ 'u' : 1, 'tts': -1}, { sparse : true } );
NotificationSchema.index({ 'h' : 1, 'sl.ts' : -1 });


/**
 * @type {Schema}
 */
exports.schema = NotificationSchema;

/**
 * @constructor
 * @alias module:models/Notification.NotificationModel
 * @type {Model}
 */
exports.model = NotificationModel = mongooseConnection.model('Notification', NotificationSchema);
