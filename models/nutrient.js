/**
 * @module models/Nutrient
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

var NutrientSchema = new Schema({
  brand: { type: String },
  name: { type: String, required: true },
  createdBy: { type: ObjectIdSchema, ref: 'User'},
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

NutrientSchema.plugin(useTimestamps);
NutrientSchema.plugin(mongoosePlugins.recoverableRemove);

/*********************** STATIC METHODS **************************/


/**
 * Compares all user-defined properties, returns boolean
 * 
 * @param {Nutrient} source
 * @param {Nutrient} other
 * @return {boolean} True if source and other are equivalent, false if not
 */
NutrientSchema.static('isEquivalentTo', function(source, other){
  if (source.brand !== other.brand){
    return false;
  }
  if (source.name !== other.name){
    return false;
  }
  return true;
});


/**
 * Takes a Nutrient object, sees if it exists in the database as defined.
 * If not, creates a new Nutrient and returns it
 * 
 * @param {object} options.nutrient
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {bool} options.silentValidationFail : if true: if components fail validation, simply omit them from the created object instead of returning errors up the chain.
 * @param {function(err, Action)} callback
 */
NutrientSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedNutrient = options.nutrient,
      user = options.user,
      visibility = options.visibility,
      silentValidationFail = silentValidationFail,
      NutrientModel = this;

    async.waterfall(
      [
        function getIdMatch(innerCallback){
          if (!feBeUtils.canParseAsObjectId(submittedNutrient._id)){
            return innerCallback(null, null);
          } 
          
          NutrientModel.findById(submittedNutrient._id, innerCallback);
        },
        function (matchedNutrient, innerCallback){
          if (matchedNutrient && NutrientModel.isEquivalentTo(submittedNutrient, matchedNutrient)){
            return callback(null, matchedNutrient);
          }
          
          // If we've gotten here, either there was no matchedNutrient
          // or the item wasn't equivalent
          submittedNutrient._id = new ObjectId();
          submittedNutrient.createdBy = user;
          submittedNutrient.visibility = visibility;

          NutrientModel.create(submittedNutrient, innerCallback);
        }
      ],
      function(err, validatedNutrient){
        if (silentValidationFail){
          if (err) { 
            winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
          }
          return callback(null, validatedNutrient);
        }
        return callback(err, validatedNutrient);
      }
    );
  } 
);

/*********************** END STATIC METHODS **************************/


/**
 * @type {Schema}
 */
exports.schema = NutrientSchema;

/**
 * @constructor
 * @alias module:models/Nutrient.NutrientModel
 * @type {Model}
 */
exports.model = mongooseConnection.model('Nutrient', NutrientSchema);
