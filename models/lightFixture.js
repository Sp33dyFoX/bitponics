/**
 * @module models/LightFixture
 */

var mongoose = require('mongoose'),
  Schema = mongoose.Schema,
  mongoosePlugins = require('../lib/mongoose-plugins'),
  useTimestamps = mongoosePlugins.useTimestamps,
  ObjectIdSchema = Schema.ObjectId,
  ObjectId = mongoose.Types.ObjectId,
  async = require('async'),
  requirejs = require('../lib/requirejs-wrapper'),
  feBeUtils = requirejs('fe-be-utils'),
  mongooseConnection = require('../config/mongoose-connection').defaultConnection;

var LightFixtureSchema = new Schema({
  brand : { type : String },
  name : { type : String },
  type : { type : String },
  watts : { type : Number },
  /**
   * Number of bulbs the fixture holds
   */
  bulbCapacity : { type : Number, default:  1 },
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

LightFixtureSchema.plugin(useTimestamps);
LightFixtureSchema.plugin(mongoosePlugins.recoverableRemove);


/*********************** STATIC METHODS **************************/


/**
 * Compares all user-defined properties, returns boolean
 * 
 * @param {LightFixture} source
 * @param {LightFixture} other
 * @return {boolean} True if source and other are equivalent, false if not
 */
LightFixtureSchema.static('isEquivalentTo', function(source, other){
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
  if (source.bulbCapacity !== other.bulbCapacity){
    return false;
  }
  return true;
});


/**
 * Takes a LightFixture object, sees if it exists in the database as defined.
 * If not, creates a new LightFixture and returns it
 * 
 * @param {object} options.lightFixture
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {bool} options.silentValidationFail : if true: if components fail validation, simply omit them from the created object instead of returning errors up the chain.
 * @param {function(err, Action)} callback
 */
LightFixtureSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedLightFixture = options.lightFixture,
      user = options.user,
      visibility = options.visibility,
      silentValidationFail = options.silentValidationFail,
      LightFixtureModel = this;

    async.waterfall(
      [
        function getIdMatch(innerCallback){
          if (!feBeUtils.canParseAsObjectId(submittedLightFixture._id)){
            return innerCallback(null, null);
          } 
          
          LightFixtureModel.findById(submittedLightFixture._id, innerCallback);
        },
        function (matchedLightFixture, innerCallback){
          if (matchedLightFixture && LightFixtureModel.isEquivalentTo(submittedLightFixture, matchedLightFixture)){
            return callback(null, matchedLightFixture);
          }
          
          // If we've gotten here, either there was no matchedLightFixture
          // or the item wasn't equivalent
          submittedLightFixture._id = new ObjectId();
          submittedLightFixture.createdBy = user;
          submittedLightFixture.visibility = visibility;

          LightFixtureModel.create(submittedLightFixture, innerCallback);
        }
      ],
      function(err, validatedLightFixture){
        if (silentValidationFail){
          if (err) { 
            winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
          }
          return callback(null, validatedLightFixture);
        }
        return callback(err, validatedLightFixture);
      }
    );
  } 
);

/*********************** END STATIC METHODS **************************/


/**
 * @type {Schema}
 */
exports.schema = LightFixtureSchema;

/**
 * @constructor
 * @alias module:models/LightFixture.LightFixtureModel
 * @type {Model}
 */
exports.model = mongooseConnection.model('LightFixture', LightFixtureSchema);
