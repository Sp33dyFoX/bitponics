/**
 * @module models/LightBulb
 */

var mongoose = require('mongoose'),
  Schema = mongoose.Schema,
  mongoosePlugins = require('../lib/mongoose-plugins'),
  useTimestamps = mongoosePlugins.useTimestamps,
  ObjectIdSchema = Schema.ObjectId,
  ObjectId = mongoose.Types.ObjectId,
  requirejs = require('../lib/requirejs-wrapper'),
  async = require('async'),
  feBeUtils = requirejs('fe-be-utils'),
  mongooseConnection = require('../config/mongoose-connection').defaultConnection;

var LightBulbSchema = new Schema({
  type: { type : String },
  watts: { type : Number },
  brand : { type : String },
  name : { type : String },
  createdBy : { type : ObjectIdSchema, ref: 'User' },
  visibility : { 
    type: String, 
    enum: [
      feBeUtils.VISIBILITY_OPTIONS.PUBLIC, 
      feBeUtils.VISIBILITY_OPTIONS.PRIVATE
    ], 
    default: feBeUtils.VISIBILITY_OPTIONS.PUBLIC
  }
},
{ id : false });

LightBulbSchema.plugin(useTimestamps);
LightBulbSchema.plugin(mongoosePlugins.recoverableRemove);


/*********************** STATIC METHODS **************************/

/**
 * Compares all user-defined properties, returns boolean
 * 
 * @param {LightBulb} source
 * @param {LightBulb} other
 * @return {boolean} True if source and other are equivalent, false if not
 */
LightBulbSchema.static('isEquivalentTo', function(source, other){
  if (source.type !== other.type){
    return false;
  }
  if (source.watts !== other.watts){
    return false;
  }
  if (source.brand !== other.brand){
    return false;
  }
  if (source.name !== other.name){
    return false;
  }
  return true;
});

/**
 * Takes a LightBulb object, sees if it exists in the database as defined.
 * If not, creates a new LightBulb and returns it
 * 
 * @param {object} options.lightBulb
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {bool} options.silentValidationFail : if true: if components fail validation, simply omit them from the created object instead of returning errors up the chain.
 * @param {function(err, Action)} callback
 */
LightBulbSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedLightBulb = options.lightBulb,
      user = options.user,
      visibility = options.visibility,
      silentValidationFail = options.silentValidationFail,
      LightBulbModel = this;

    async.waterfall(
      [
        function getIdMatch(innerCallback){
          if (!feBeUtils.canParseAsObjectId(submittedLightBulb._id)){
            return innerCallback(null, null);
          } 
          
          LightBulbModel.findById(submittedLightBulb._id, innerCallback);
        },
        function (matchedLightBulb, innerCallback){
          if (matchedLightBulb && LightBulbModel.isEquivalentTo(submittedLightBulb, matchedLightBulb)){
            return callback(null, matchedLightBulb);
          }
          
          // If we've gotten here, either there was no matchedLightBulb
          // or the item wasn't equivalent
          submittedLightBulb._id = new ObjectId();
          submittedLightBulb.createdBy = user;
          submittedLightBulb.visibility = visibility;

          LightBulbModel.create(submittedLightBulb, innerCallback);
        }
      ],
      function(err, validatedLightBulb){
        if (silentValidationFail){
          if (err) { 
            winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
          }
          return callback(null, validatedLightBulb);
        }
        return callback(err, validatedLightBulb);
      }
    );
  } 
);


/*********************** END STATIC METHODS **************************/


/**
 * @type {Schema}
 */
exports.schema = LightBulbSchema;

/**
 * @constructor
 * @alias module:models/LightBulb.LightBulbModel
 * @type {Model}
 */
exports.model = mongooseConnection.model('LightBulb', LightBulbSchema);
