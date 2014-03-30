/**
 * @module models/GrowSystem
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

var GrowSystemSchema = new Schema({
  
  name: { type: String, required: true },
   
  description: { type: String, required: false },

  createdBy: { type: ObjectIdSchema, ref: 'User'},
  
  type: { type: String},
  
  /**
   * reservoirSize is number of gallons
   */
  reservoirSize: { type: Number },
  
  plantCapacity: { type: Number },

  // Numbers in feet
  overallSize: {
    w: { type: Number },
    h: { type: Number },
    d: { type: Number }
  },

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

GrowSystemSchema.plugin(mongoosePlugins.useTimestamps);
GrowSystemSchema.plugin(mongoosePlugins.recoverableRemove);
GrowSystemSchema.plugin(mongoosePlugins.photos);


GrowSystemSchema.virtual('reservoirSizeWithUnits')
  /**
   * Setter takes an object of the form { value: Number, unit: String}
   * unit must be 'liters' or 'gallons'
   */
  .set(function(reservoirSizeWithUnits){
    var unit = reservoirSizeWithUnits.unit || 'gallons',
      value = reservoirSizeWithUnits.value;

    if (unit === 'liters'){
      // 1 liter = 0.264172052 gallons
      this.set('reservoirSize', value * 0.264172052);
    } else {
      this.set('reservoirSize', value);
    }
  });



/*********************** STATIC METHODS ******************************/


GrowSystemSchema.static('isEquivalentTo', function(source, other){
  if (source.name !== other.name){
    return false;
  }
  if (source.description !== other.description){
    return false;
  }
  if (source.type !== other.type){
    return false;
  }
  if (source.reservoirSize !== other.reservoirSize){
    return false;
  }
  if (source.plantCapacity !== other.plantCapacity){
    return false;
  }
  
  // deep check of overallSize
  if (source.overallSize && other.overallSize){
    if (source.overallSize.w !== other.overallSize.w){
      return false;
    }
    if (source.overallSize.h !== other.overallSize.h){
      return false;
    }
    if (source.overallSize.d !== other.overallSize.d){
      return false;
    }
  }
  return true;
});


/**
 * Takes a fully-populated GrowSystem object, sees if it exists in the database as defined.
 * If not, creates a new GrowSystem and returns it
 * 
 * @param {object} options.growSystem
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {bool} options.silentValidationFail : if true: if components fail validation, simply omit them from the created object instead of returning errors up the chain.
 * @param {function(err, Action)} callback
 */
GrowSystemSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedGrowSystem = options.growSystem,
      user = options.user,
      visibility = options.visibility,
      silentValidationFail = options.silentValidationFail,
      GrowSystemModel = this;

    async.waterfall(
      [
        function getIdMatch(innerCallback){
          if (!feBeUtils.canParseAsObjectId(submittedGrowSystem._id)){
            return innerCallback(null, null);
          } 
          
          GrowSystemModel.findById(submittedGrowSystem._id, innerCallback);
        },
        function (matchedGrowSystem, innerCallback){
          if (matchedGrowSystem && GrowSystemModel.isEquivalentTo(submittedGrowSystem, matchedGrowSystem)){
            return innerCallback(null, matchedGrowSystem);
          }
          // If we've gotten here, either there was no growSystemResult
          // or the item wasn't equivalent
          submittedGrowSystem._id = new ObjectId();
          submittedGrowSystem.createdBy = user;
          submittedGrowSystem.visibility = visibility;

          GrowSystemModel.create(submittedGrowSystem, innerCallback);
        }
      ],
      function(err, validatedGrowSystem){
        if (silentValidationFail){
          if (err) { 
            winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
          }
          return callback(null, validatedGrowSystem);
        }
        return callback(err, validatedGrowSystem);
      }
    );
  } 
);

/*********************** END STATIC METHODS ******************************/


/**
 * @type {Schema}
 */
exports.schema = GrowSystemSchema;

/**
 * @constructor
 * @alias module:models/GrowSystem.GrowSystemModel
 * @type {Model}
 */
exports.model = mongooseConnection.model('GrowSystem', GrowSystemSchema);
