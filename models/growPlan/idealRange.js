/**
 * @module models/GrowPlan/IdealRange
 */

var mongoose = require('mongoose'),
  Schema = mongoose.Schema,
  ObjectId = Schema.ObjectId,
  ActionModel = require('../action').model,
  getObjectId = require('../utils').getObjectId,
  async = require('async'),
  winston = require('winston');

var IdealRangeSchema = new Schema({

  /**
   * sCode references Sensor.code
   */
  sCode: { type: String, ref: 'Sensor', required: true },


  valueRange: {

    /**
     * Minimum end of the ideal range of values for this sensor
     */
    min: { type: Number, required: true },
    
    /**
     * Maximum end of the ideal range of values for this sensor
     */
    max: { type: Number, required: true },

    /**
     * Optimum value
     */
    opt : { type : Number, required : false }
  },

  actionBelowMin: { type: ObjectId, ref: 'Action', required: false },

  actionAboveMax: { type: ObjectId, ref: 'Action', required: false },


  /**
   * applicableTimeSpan. optional. Describes the portion of a 24-hour day
   * during which this idealRange is operational.
   *
   * Values are milliseconds since 00:00.
   *
   * If startTime is greater than endTime, it will be parsed as an "overnight" span.
   *
   * If undefined, idealRange is always operational.
   */
  applicableTimeSpan: {
    startTime: { type: Number },
    endTime: { type: Number }
  },


  /**
   * Source of information for this IdealRange. 
   */
  reference : { 
    name : { type : String, required : false },
    page : { type : Number, required : false },
    url : { type : String, required : false }
  }
},
{ id : false });


/************************** INSTANCE METHODS  ***************************/

IdealRangeSchema.method('checkIfWithinTimespan', function(userTimezone, date){
  var tz = require('../../lib/timezone-wrapper'),
    applicableTimeSpan = this.applicableTimeSpan;
  
  // Not sure of exact reason for this, but Mongoose is storing an empty object for applicableTimeSpan
  // instead of undefined, so we need to check properties as well
  if (!applicableTimeSpan || !applicableTimeSpan.startTime || !applicableTimeSpan.endTime){ return true; }
  
  var dateParts = tz(date, userTimezone, '%T').split(':'),
      millisecondsIntoDay = (dateParts[0] * 60 * 60 * 1000) + (dateParts[1] * 60 * 1000) + (dateParts[2] * 1000);

    if (applicableTimeSpan.startTime < applicableTimeSpan.endTime){
      return ( (millisecondsIntoDay >= applicableTimeSpan.startTime) && (millisecondsIntoDay <= applicableTimeSpan.endTime) );  
    } else {
      // overnight span
      // time can be after startTime or before endTime
      return ( (millisecondsIntoDay >= applicableTimeSpan.startTime) || (millisecondsIntoDay <= applicableTimeSpan.endTime) );
    }
});


/************************** END INSTANCE METHODS  ***************************/


/************************** STATIC METHODS  ***************************/

/**
 * Given two IdealRange objects, determine whether they're equivalent
 * by comparing user-defined properties.
 *
 * Synchronous, unlike parent "isEquivalentTo" functions.
 *
 * Assumes that if actionBelowMin and actionAboveMax are defined,
 * they are populated Action model objects and not simply ObjectIds or strings.
 * 
 * @param source {IdealRange}. IdealRange model object. 
 * @param other {IdealRange}. IdealRange model object. 
 * @return {boolean}. true if the objects are equivalent, false if not
 */
IdealRangeSchema.static('isEquivalentTo', function(source, other){
  if (source.sCode !== other.sCode) { return false;}
  if (source.valueRange.min !== other.valueRange.min) { return false;}
  if (source.valueRange.max !== other.valueRange.max) { return false;}
  
  if (!((source.actionBelowMin && other.actionBelowMin) || (!source.actionBelowMin && !other.actionBelowMin))) {
    return false;
  }
  if (source.actionBelowMin){
    if (!ActionModel.isEquivalentTo(source.actionBelowMin, other.actionBelowMin)) { return false;}
  }

  if (!((source.actionAboveMax && other.actionAboveMax) || (!source.actionAboveMax && !other.actionAboveMax))) {
    return false;
  }
  if (source.actionAboveMax){
    if (!ActionModel.isEquivalentTo(source.actionAboveMax, other.actionAboveMax)) { return false;}
  }

  if (!((source.applicableTimeSpan && other.applicableTimeSpan) || (!source.applicableTimeSpan && !other.applicableTimeSpan))) {
    return false;
  }
  if (source.applicableTimeSpan){
    if (!
      (source.applicableTimeSpan.startTime == other.applicableTimeSpan.startTime)
      &&
      (source.applicableTimeSpan.endTime == other.applicableTimeSpan.endTime)
      ){
      return false;
    }
  }

  return true;
});


/**
 * Takes a fully-populated IdealRange object (such as is submitted from grow-plans creation page)
 * and, for all nested documents (actionBelowMin, actionAboveMax), creates them if they don't match existing DB entries
 * Then returns IdealRange object
 * 
 * @param {object} options.idealRange
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {bool} options.silentValidationFail : if true: if components fail validation, simply omit them from the created object instead of returning errors up the chain.
 * @param {function(err, IdealRange)} callback
 */
IdealRangeSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedIdealRange = options.idealRange,
    user = options.user,
    visibility = options.visibility,
    silentValidationFail = options.silentValidationFail;

  async.parallel(
    [
      function validateActionBelowMin(innerCallback){
        if (!submittedIdealRange.actionBelowMin) { return innerCallback(); }
        
        ActionModel.createNewIfUserDefinedPropertiesModified({
          action : submittedIdealRange.actionBelowMin,
          user : user,
          visibility : visibility,
          silentValidationFail : silentValidationFail
        },
        function(err, validatedAction){
          if (validatedAction){
            submittedIdealRange.actionBelowMin = validatedAction._id;  
          }
          return innerCallback(err);
        });
      },
      function validateActionAboveMax(innerCallback){
        if (!submittedIdealRange.actionAboveMax) { return innerCallback(); }
        
        ActionModel.createNewIfUserDefinedPropertiesModified({
          action : submittedIdealRange.actionAboveMax,
          user : user,
          visibility : visibility,
          silentValidationFail : silentValidationFail
        },
        function(err, validatedAction){
          if (validatedAction){
            submittedIdealRange.actionAboveMax = validatedAction._id;  
          }
          return innerCallback(err);
        });
      },
    ],
    function parallelEnd(err, results){
      
      // force mongoose to create a new _id
      // TODO : investigate whether this is the right thing to do
      delete submittedIdealRange._id;

      if (silentValidationFail){
        if (err || 
            !submittedIdealRange.sCode || 
            !submittedIdealRange.valueRange ||
            !submittedIdealRange.valueRange.min || 
            !submittedIdealRange.valueRange.max
          ){
          if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack']));}
          return callback();
        }
        return callback(null, submittedIdealRange);
      }
      
      return callback(err, submittedIdealRange);
    }
  );
});
/************************** END STATIC METHODS  ***************************/

exports.schema = IdealRangeSchema;
