/**
 * @module models/Photo
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
  mongooseConnection = require('../config/mongoose-connection').defaultConnection,
  winston = require('winston');

var PlantSchema = new Schema({
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

PlantSchema.plugin(useTimestamps);
PlantSchema.plugin(mongoosePlugins.recoverableRemove);


/*********************** STATIC METHODS **************************/


/**
 * Compares all user-defined properties, returns boolean
 * 
 * @param {Plant} source
 * @param {Plant} other
 * @return {boolean} True if source and other are equivalent, false if not
 */
PlantSchema.static('isEquivalentTo', function(source, other){
  return (source.name === other.name);
});


/**
 * Takes a Plant object, sees if it exists in the database as defined.
 * If not, creates a new Plant and returns it
 * 
 * @param {object} options.plant
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {function(err, Plant)} callback
 */
PlantSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedPlant = options.plant,
      user = options.user,
      visibility = options.visibility,
      silentValidationFail = options.silentValidationFail,
      PlantModel = this;

    async.waterfall(
      [
        function getPlantIdMatch(innerCallback){
          if (!feBeUtils.canParseAsObjectId(submittedPlant._id)){
            return PlantModel.findOne({ name : submittedPlant.name }, innerCallback);
          } 

          PlantModel
          .findOne()
          .or([{_id : submittedPlant._id }, { name : submittedPlant.name}])
          .exec(innerCallback);
        },
        function (matchedPlant, innerCallback){
          if (matchedPlant && PlantModel.isEquivalentTo(submittedPlant, matchedPlant)){
            return innerCallback(null, matchedPlant);
          }
          
          // If we've gotten here, either there was no matchedPlant
          // or the item wasn't equivalent
          submittedPlant._id = new ObjectId();
          submittedPlant.createdBy = user;
          submittedPlant.visibility = visibility;

          PlantModel.create(submittedPlant, innerCallback);
        }
      ],
      function(err, validatedPlant){
        if (silentValidationFail){
          if (err) { 
            winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack']));
          }
          return callback(null, validatedPlant);
        }
        return callback(err, validatedPlant);
      }
    )
  } 
);


/*********************** END STATIC METHODS **************************/

PlantSchema.path('name').index({ unique: true });

/**
 * @type {Schema}
 */
exports.schema = PlantSchema;

/**
 * @constructor
 * @alias module:models/Plant.PlantModel
 * @type {Model}
 */
exports.model = mongooseConnection.model('Plant', PlantSchema);
