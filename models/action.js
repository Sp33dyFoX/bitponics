/**
 * @module models/Action
 */

var mongoose = require('mongoose'),
  Schema = mongoose.Schema,
  ObjectIdSchema = Schema.ObjectId,
  mongoosePlugins = require('../lib/mongoose-plugins'),
  useTimestamps = mongoosePlugins.useTimestamps,
  ObjectId = mongoose.Types.ObjectId,
  async = require('async'),
  timezone = require('../lib/timezone-wrapper'),
  moment = require('moment'),
  getObjectId = require('./utils').getObjectId,
  requirejs = require('../lib/requirejs-wrapper'),
  feBeUtils = requirejs('fe-be-utils'),
  i18nKeys = require('../i18n/keys'),
  winston = require('winston'),
  mongooseConnection = require('../config/mongoose-connection').defaultConnection,
  ActionModel,
  ActionSchema;


/**
 * Internal schema used for Action. Declared as its own Schema simply to remove unnecessary _id prop
 * @type {Schema}
 */
var ActionStateSchema = new Schema(
  {
    controlValue: { type: String },

    durationType: { type: String, enum: feBeUtils.DURATION_TYPES },

    duration: { type: Number },

    message: { type: String }
  },
  { _id : false, id : false }
);


ActionSchema = new Schema(
/**  
 * @lends module:models/Action.ActionModel.prototype
 */
{

  /** 
   * @type {string}
   */
  description: { type: String, required: true },

  /** 
   * @type {ObjectId}
   */
  control: { type: ObjectIdSchema, ref: 'Control', required: false },

  /**
   * Action schedules are represented by a cycle.
   * Cycles have a series of states. Discreet actions are
   * those with a "repeat" == false.
   *
   * Actions trigger with phase start. They can be offset
   * using an initial cycle state with no message or value,
   * just a duration.
   *
   * Cycles can have 1-3 states. See the pre-save hook below for validation details.
   *
   * Also, all fields are optional.
   *
   * The cycle itself is also optional. If undefined, the Action is considered a simple "reminder"
   * 
   * @type {object}
   * @property {ActionStateSchema[]} states
   * @property {object} offset (see source for docs)
   * @property {bool} repeat
   */
  cycle: {
    
    states: [ActionStateSchema],

    /**
     * Optional. 
     * Offset the starting point of the cycle by this amount.
     * 
     * Imagine cycle is a dial, with the beginning indicated by a line pointing straight up. 
     * The offset turns the dial so that states[0] starts [offset] later than it would. 
     * Which means that states[1] fills in the time from start until offset.
     * @type {object}
     * @memberof module:models/Action.ActionModel.prototype.cycle
     */
    offset : { 
      durationType: { type: String, enum: feBeUtils.DURATION_TYPES },
      duration: { type: Number, default : 0 }
    },

    repeat: { type: Boolean }
  }
},
{ id : false });

ActionSchema.plugin(useTimestamps);
ActionSchema.plugin(mongoosePlugins.recoverableRemove);


/**
 * Cycle timespan in milliseconds.
 * Used by the notification engine to set when actions should expire in
 * order to recalculate current actions.
 *
 * Single-state actions get a timespan of 1 year.
 *
 * @name module:models/Action.ActionModel.prototype.overallCycleTimespan
 * @instance
 * @type {Number} 
 */
ActionSchema.virtual('overallCycleTimespan')
  .get(function () {
    // default to a 1 year max duration
    var total = moment.duration(1, 'year').asMilliseconds(), //1000 * 60 * 60 * 24 * 365,
      cycle = this.cycle,
      states;

    if (!cycle || !cycle.states.length){ return total; }

    states = cycle.states;
    switch(states.length){
      case 1:
        // Single-state cycle. If it has a control, it's considered to be a one-time
        // trigger that should last until explicitly changed, which means it's effectively
        // an infinite duration. we cap "infinite" at 1-year.
        if (this.control){
          return total;
        } else {
          // if no control, it's just a message notification (aka, a reminder).
          // no duration
          return 0;
        }
        
        break;
      case 2:
        total = 0;
        states.forEach(function(state){
          total += ActionSchema.statics.convertDurationToMilliseconds(state.duration, state.durationType);
        });
        break;
      // no default; we've enforced that we have one of these values already
    }
    return total;
  });


/************************** INSTANCE METHODS ***************************/

/**
 * @returns {Duration} moment.js duration object
 * @name module:models/Action.ActionModel#getOverallCycleDurationObject
 * @function
 * @instance
 */
ActionSchema.method('getOverallCycleDurationObject', function(){
  return feBeUtils.getLargestWholeNumberDurationObject(this.overallCycleTimespan);
});

/************************** END INSTANCE METHODS ***************************/




/************************** STATIC METHODS ***************************/

/**
 * Given another Action object, determine whether they're equivalent.
 * Compares most properties, ignoring Action._id and Action.cycle.states._id.
 *
 * Synchronous.
 *
 * @param source {Action} Action model object
 * @param other {Action} Action model object
 * @returns {boolean}  true if the objects are equivalent, false if not
 * @name module:models/Action.ActionModel.isEquivalentTo
 * @function
 * @static
 */
ActionSchema.static('isEquivalentTo', function(source, other){
  if (source.description !== other.description){
    return false;
  }

  if (!((source.control && other.control) || (!source.control && !other.control))) {
    return false;
  }
  if (source.control){
    if (!getObjectId(source.control).equals(getObjectId(other.control))){
      return false;
    }
  }

  if (source.cycle.states.length !== other.cycle.states.length){
    return false;
  }

  if (source.cycle.repeat !== other.cycle.repeat){
    return false;
  }

  var allStatesEquivalent = source.cycle.states.every(function(state, index){
    var otherState = other.cycle.states[index];
    if (state.controlValue !== otherState.controlValue) {
      return false;
    }
    if (state.durationType !== otherState.durationType) {
      return false;
    }
    if (state.duration !== otherState.duration) {
      return false;
    }
    if (state.message !== otherState.message) {
      return false;
    }
    return true;
  });

  if (!allStatesEquivalent) { return false; }

  return true;
});


/**
 * Takes a fully-populated Action object, sees if it exists in the database as defined.
 * If not, creates a new Action and returns it
 * 
 * @param {object} options.action
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {bool} options.silentValidationFail : if true: if components fail validation, simply omit them from the created object instead of returning errors up the chain.
 * @param {function(err, Action)} callback
 * @name module:models/Action.ActionModel.createNewIfUserDefinedPropertiesModified
 * @function
 * @static
 */
ActionSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedAction = options.action,
      user = options.user,
      visibility = options.visibility,
      silentValidationFail = options.silentValidationFail,
      ActionModel = this;

    async.waterfall(
      [
        function getActionIdMatch(innerCallback){
          if (!feBeUtils.canParseAsObjectId(submittedAction._id)){
            return innerCallback(null, null);
          } 
          
          ActionModel.findById(submittedAction._id, innerCallback);
        },
        function (matchedAction, innerCallback){
          if (matchedAction && ActionModel.isEquivalentTo(submittedAction, matchedAction)){
            return innerCallback(null, matchedAction);
          }

          // If we've gotten here, either there was no matchedAction
          // or the item wasn't equivalent
          submittedAction._id = new ObjectId();
          submittedAction.createdBy = user;
          submittedAction.visibility = visibility;

          ActionModel.create(submittedAction, innerCallback);
        }
      ],
      function(err, validatedAction){
        if (silentValidationFail){
          if (err) { 
            winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
          }
          return callback(null, validatedAction);
        }
        return callback(err, validatedAction);
      }
    )
  } 
);


/**
 * @param {Number} duration 
 * @param {feBeUtils.DURATION_TYPES} durationType 
 * 
 * @name module:models/Action.ActionModel.convertDurationToMilliseconds
 * @function
 * @static
 */
ActionSchema.static('convertDurationToMilliseconds', function(duration, durationType){
  switch(durationType){
    case 'milliseconds':
    case 'seconds':
    case 'minutes':
    case 'hours':
    case 'days':
    case 'weeks':
    case 'months':
      return moment.duration(duration, durationType).asMilliseconds();
    default:
      return 0;
  }
});


/**
 * Returns the time remaining in the current iteration of the action's cycle.
 * Calculated assuming the action started at 00:00:00 on the day the phase started.
 *
 * @param {Date} fromDate - Date from which to calculate cycle remainder
 * @param {object} growPlanInstancePhase 
 * @param {Action} action 
 * @param {String} userTimezone 
 *
 * @returns {Number} Number of milliseconds remaining in the current action cycle iteration.
 *
 * @name module:models/Action.ActionModel.getCycleRemainder
 * @function
 * @static
 */
ActionSchema.static('getCycleRemainder', function(fromDate, growPlanInstancePhase, action, userTimezone){
  // http://en.wikipedia.org/wiki/Date_%28Unix%29
  // get the overall timespan of the cycle.
  // get the localized 00:00:00 of the phase start date (phase could have started later in the day, we need the day's start time)
  // get time elapsed from localized phase start
  // divide time elapsed by overall timespan. remainder is a component of the offset
  var fromDateAsMilliseconds = (fromDate instanceof Date) ? fromDate.valueOf() : fromDate,
      phaseStartDateParts = timezone(growPlanInstancePhase.startDate, userTimezone, '%T').split(':'),
  // get the midnight of the start date
    phaseStartDate = growPlanInstancePhase.startDate.valueOf() - ( (phaseStartDateParts[0] * 60 * 60 * 1000) + (phaseStartDateParts[1] * 60 * 1000) + (phaseStartDateParts[2] * 1000)),
    overallCycleTimespan = action.overallCycleTimespan,
    phaseTimeElapsed = fromDateAsMilliseconds - phaseStartDate,
    cycleRemainder = overallCycleTimespan - (phaseTimeElapsed % overallCycleTimespan);

  return cycleRemainder;
});


/**
 * Returns what the current controlValue should be, factoring in elapsed time in the phase and timezone
 *
 * @param {Date} fromDate - Date from which to calculate cycle remainder
 * @param {object} growPlanInstancePhase 
 * @param {Action} action 
 * @param {String} userTimezone 
 *
 * @returns {Number} 0 if control is OFF, 1 if control is ON.
 * 
 * @name module:models/Action.ActionModel.getCurrentControlValue
 * @function
 * @static
 */
ActionSchema.static('getCurrentControlValue', function(fromDate, growPlanInstancePhase, action, userTimezone){
  if (!growPlanInstancePhase){
    return 0;
  }

  var fromDateAsMilliseconds = (fromDate instanceof Date) ? fromDate.valueOf() : fromDate,
      phaseStartDateParts = timezone(growPlanInstancePhase.startDate, userTimezone, '%T').split(':'),
      // get the midnight of the start date
      phaseStartDate = growPlanInstancePhase.startDate.valueOf() - ( (phaseStartDateParts[0] * 60 * 60 * 1000) + (phaseStartDateParts[1] * 60 * 1000) + (phaseStartDateParts[2] * 1000)),
      offset = action.cycle.offset || {},
      offsetInMilliseconds = ActionSchema.statics.convertDurationToMilliseconds(offset.duration, offset.durationType),
      offsetPhaseStartDate = phaseStartDate + offsetInMilliseconds,
      phaseTimeElapsed = fromDateAsMilliseconds - phaseStartDate,
      offsetPhaseTimeElapsed = fromDateAsMilliseconds - offsetPhaseStartDate,
      offsetRemainder,
      cycleTimeElapsed,
      overallCycleTimespan,
      cycle = action.cycle,
      states,
      stateDurationsInMilliseconds = [];

  if (! action.control || !cycle || !cycle.states.length){ return 0; }

  states = cycle.states;

  switch(states.length){
    case 1:
      return parseInt(states[0].controlValue, 10);
      break;
    case 2:

      // if the from date is within the initial offset
      if(offsetPhaseTimeElapsed < 0){
        offsetRemainder = -1 * offsetPhaseTimeElapsed;
        while (offsetRemainder > 0) {
          for (var i = states.length; i--;) {
            offsetRemainder -= ActionSchema.statics.convertDurationToMilliseconds(states[i].duration, states[i].durationType);
            if (offsetRemainder <= 0) {
              return parseInt(states[i].controlValue, 10);
            }
          }
        }
      } else {
        overallCycleTimespan = 0;
        states.forEach(function(state, index){
          stateDurationsInMilliseconds[index] = ActionSchema.statics.convertDurationToMilliseconds(state.duration, state.durationType);
          overallCycleTimespan += stateDurationsInMilliseconds[index];
        });
        cycleTimeElapsed = (offsetPhaseTimeElapsed % overallCycleTimespan);

        if (cycleTimeElapsed < stateDurationsInMilliseconds[0]){
          return parseInt(states[0].controlValue, 10);
        } else if (cycleTimeElapsed < (stateDurationsInMilliseconds[0] + stateDurationsInMilliseconds[1])){
          return parseInt(states[1].controlValue, 10);
        } else {
          return parseInt(states[0].controlValue, 10);
        }
        break;  
      }
      
  }
});


/**
 * Parses cycles and returns a flat object formatted for the Bitponics device.
 * Should only be called for Actions that have a control.
 *
 * The device is only able to parse a single format, which means
 * we have to represent single-state cycles as having 2 states.
 * Single-state cycles simply become infinite durations of that state's controlValue.
 *
 * The firmware parses "infinite duration" by discovering that value1 and value2 are the same
 * and duration1 and duration2 are both non-zero.
 *
 * ControlValues are parsed into integers since that's all the firmware can parse.
 *
 * @param {Action.cycle} actionCycle
 * @param {number} [offset] - Only a factor in a 2-state cycle. Otherwise it's just written straight to the template. 
 *                For single-state cycles, this is ignored and offset is set to 0.
 *
 * @returns {Object} { offset: Number, value1: Number, duration1: Number, value2: Number, duration2: Number }
 * 
 * @name module:models/Action.ActionModel.getDeviceCycleFormat
 * @function
 * @static
 */
ActionSchema.static('getDeviceCycleFormat', function(actionCycle, offset){
  var states = actionCycle.states,
    actionOffset = actionCycle.offset || {},
    convertDurationToMilliseconds = ActionSchema.statics.convertDurationToMilliseconds,
    offset = (offset || 0) + convertDurationToMilliseconds(actionOffset.duration, actionOffset.durationType),
    result = {
      offset : 0,
      value1 : 0,
      duration1 : 0,
      value2 : 0,
      duration2 : 0
    };

  switch(states.length){
    case 1:
      var infiniteStateControlValue = parseInt(states[0].controlValue, 10);
      result.offset = 0;
      result.value1 = infiniteStateControlValue;
      result.duration1 = 1;
      result.value2 = infiniteStateControlValue;
      result.duration2 = 1;
      break;
    case 2:
      var state0 = states[0],
        state1 = states[1];

      result.offset = offset;
      result.value1 = parseInt(state0.controlValue, 10);
      result.duration1 = convertDurationToMilliseconds(state0.duration, state0.durationType);
      result.value2 = parseInt(state1.controlValue, 10);
      result.duration2 = convertDurationToMilliseconds(state1.duration, state1.durationType);
      break;
    default:
      winston.info('Serializing a blank actionCycle');
      result.offset = 0;
      result.value1 = 0;
      result.duration1 = 0;
      result.value2 = 0;
      result.duration2 = 0;
      break;
  }
  return result;
});


/**
 * Takes a string with the tokens {offset},{value1},{duration1},{value2},{duration2}
 * and replaces each field with the proper values. Offset is returned in milliseconds.
 *
 * Assumes it's passed an action with states with controlValues.
 *
 * @param {string} cycleTemplateoffset
 * @param {Action.cycle} actionCycle
 * @param {number} [offset] - Only a factor in an offset cycle. Otherwise it's just written straight to the template.
 * 
 * @returns {Object} 
  {
     cycleString : String,
     offset : Number,
     value1 : Number,
     duration1 : Number,
     value2 : Number,
     duration2 : Number
   }
 * 
 * @name module:models/Action.ActionModel.updateCycleTemplateWithStates
 * @function
 * @static
 */
ActionSchema.static('updateCycleTemplateWithStates', function(cycleTemplate, actionCycle, offset){
  var result = ActionSchema.statics.getDeviceCycleFormat(actionCycle, offset),
    resultCycleString = cycleTemplate;

  resultCycleString = resultCycleString.replace(/{offset}/, result.offset);
  resultCycleString = resultCycleString.replace(/{value1}/, result.value1);
  resultCycleString = resultCycleString.replace(/{duration1}/, result.duration1);
  resultCycleString = resultCycleString.replace(/{value2}/, result.value2);
  resultCycleString = resultCycleString.replace(/{duration2}/, result.duration2);
  result.cycleString = resultCycleString;

  return result;
});

/************************** END STATIC METHODS***************************/


/************************** MIDDLEWARE ***************************/



/*************** Validate ******************************/

/**
 *  Validate cycle states
 *
 *  A cycle either represents a discrete action or a pair of states.
 *
 *  Cycles always start with the start of a phase, and
 *  phases always start at the start of a day (at 00:00:00) local time.
 *  Cycles have 1 or 2 states (on/off).
 *
 *  An "offset" is represented by the offset property on a cycle.
 */
ActionSchema.path('cycle.states').validate(function(states) {
  if(states.length) {
    return states.length > 0 && states.length < 3;
  }

  return true;
}, "Invalid number of cycle states. Cycles have 1 or 2 states (on/off).");

ActionSchema.path('control').validate(function(control) {
  return control && this.cycle.states.length;
}, "An action with a control must define a cycle with 1 or 2 control states");

ActionSchema.pre('save', function(next){
  var action = this,
    cycle = action.cycle,
    states;

  // An Action can have no cycle. In this case it's a simple reminder.
  if (!cycle.states.length){
    delete this.cycle.repeat;
    return next();
  }

  states = cycle.states;

  //TODO: move to own validate function
  if (action.control){
    if (states.some(function(state){
      return (typeof state.controlValue === 'undefined' || state.controlValue === null);
    })){
      return next(new Error(i18nKeys.get('If an action has a control, every cycle state must specify a control value')));
    }
  }

  switch(states.length){
    case 1:
      // if a cycle has 1 state, it's considered a discrete action and must have a "repeat" of false
      delete this.cycle.repeat;
      break;
    case 2:
      // if 2 states, at least one must have a duration defined
      if ( !(states[0].durationType && states[0].duration) &&
           !(states[1].durationType && states[1].duration)){
        //TODO: move to own validate function
        return next(new Error(i18nKeys.get('In a 2-state cycle, at least one state must have a duration defined')));
      }
      break;
    // no default; we've enforced that we have one of these values already
  }

  return next();
});



/**
 *  Validate cycle state messages
 *
ActionSchema.pre('save', function(next){
  var Control = require('./control'),
      ControlSchema = Control.schema,
      ControlModel = Control.model,
      action = this;

  
  async.waterfall([
      function getControlName(innerCallback){
        if (!action.control){
          return innerCallback(null, '');
        }
        if (action.control.schema === ControlSchema){
          return innerCallback(null, action.control.name);
        } else {
          ControlModel.findById(action.control)
          .exec(function(err, controlResult){
            if (err) { return innerCallback(err);}
            return innerCallback(null, controlResult.name);
          });
        }
      },
      function (controlName, innerCallback){
        action.cycle.states.forEach(function(state){
          if (!state.message){
            if (controlName && state.controlValue){
              state.message = "Turn " + controlName + " " + (state.controlValue === '0' ? "off" : "on");
            } else {
              // no control, no message. Hopefully there's a duration. It's a waiting state!
              state.message = "Wait";
            }

            if (state.duration){
              state.message += " for " + state.duration + " " + state.durationType; 
            }
          } 
        });
        return innerCallback();
      }
    ],
    function(err){
      return next(err);
    }
  );
});
*/


ActionSchema.pre('save', 
/**
 * Validate description
 * @alias module:models/Action.ActionModel#save
 */
  function(next){
  var Control = require('./control'),
      ControlSchema = Control.schema,
      ControlModel = Control.model,
      action = this;

  if (this.description){
    return next();
  }
    
  async.waterfall(
    [
      function getControlName(innerCallback){
        if (!action.control){
          return innerCallback();
        }

        if (action.control.schema === ControlSchema){
          return innerCallback(null, action.control.name);
        } else {
          ControlModel.findById(action.control)
          .exec(function(err, controlResult){
            if (err) { return innerCallback(err);}
            return innerCallback(controlResult.name);
          });
        }
      },
      function (controlName, innerCallback){
        if (controlName && action.cycle.states.length > 1){
          action.description = controlName + " cycle";
        }

        if (!action.description){
          action.description = action.states[0].message || (action.states[1] ? action.states[1].message : '') || "No action description";  
        }
        
        return next();
      }
    ],
    function(err, results){
      return next(err);
    }
  );
});


/************************** END MIDDLEWARE ***************************/


// Now that schema is defined, add indices
// Want a sparse index on control (since it's an optional field)
ActionSchema.index({ control: 1, 'cycle.repeat': 1 }, { sparse: true});



ActionModel = mongooseConnection.model('Action', ActionSchema);


/**
 * Schema for ActionModels
 * @type {Schema}
 */
exports.schema = ActionSchema;


/**
 * @constructor
 * @alias module:models/Action.ActionModel
 * @type {Model}
 */
exports.model = ActionModel;
