/**
 * @module models/Light
 */

var mongoose = require('mongoose'),
  Schema = mongoose.Schema,
  mongoosePlugins = require('../lib/mongoose-plugins'),
  useTimestamps = mongoosePlugins.useTimestamps,
  ObjectIdSchema = Schema.ObjectId,
  ObjectId = mongoose.Types.ObjectId,
  LightBulbModel = require('./lightBulb').model,
  LightFixtureModel = require('./lightFixture').model,
  requirejs = require('../lib/requirejs-wrapper'),
  feBeUtils = requirejs('fe-be-utils'),
  async = require('async'),
  mongooseConnection = require('../config/mongoose-connection').defaultConnection;

var LightSchema = new Schema({
  fixture: { type: ObjectIdSchema, ref: 'LightFixture'},
  fixtureQuantity: { type : Number, default: 1 },
  bulb: { type : ObjectIdSchema, ref: 'LightBulb'},
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

LightSchema.plugin(useTimestamps);
LightSchema.plugin(mongoosePlugins.recoverableRemove);


/*********************** STATIC METHODS **************************/

/**
 * Compares all user-defined properties, returns boolean
 * Assumes it gets fully-populated Light documents (fixture and bulb objects)
 * 
 * @param {Light} source
 * @param {Light} other
 * @return {boolean} True if source and other are equivalent, false if not
 */
LightSchema.static('isEquivalentTo', function(source, other){
  if (source.fixtureQuantity !== other.fixtureQuantity){
    return false;
  }
  
  if ( !(
      (source.fixture && other.fixture) ||
      (!source.fixture && !other.fixture)
     )
    ){ 
    return false;
  }
  if (source.fixture){
    if (!LightFixtureModel.isEquivalentTo(source.fixture, other.fixture)){
      return false;
    }
  }

  if ( !(
      (source.bulb && other.bulb) ||
      (!source.bulb && !other.bulb)
     )
    ){ 
    return false;
  }
  if (source.bulb){
    if (!LightBulbModel.isEquivalentTo(source.bulb, other.bulb)){
      return false;
    }
  }

  return true;
});


/**
 * Assumes it gets a fully-populated Light object
 * Compares the referenced documents, creates them if they're new
 * Then returns the validated light
 *
 * @param {object} options.light
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {bool} options.silentValidationFail : if true: if components fail validation, simply omit them from the created object instead of returning errors up the chain.
 * @param {function(err, GrowPlan)} callback
 */
LightSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedLight = options.light,
      user = options.user,
      visibility = options.visibility,
      silentValidationFail = options.silentValidationFail,
      LightModel = this;

  
  async.waterfall(
    [
      function getActionIdMatch(innerCallback){
        if (!feBeUtils.canParseAsObjectId(submittedLight._id)){
          return innerCallback(null, null);
        } 
        
        LightModel.findById(submittedLight._id)
        .populate('fixture')
        .populate('bulb')
        .exec(innerCallback);
      },
      function (matchedLight, innerCallback){
        if (matchedLight && LightModel.isEquivalentTo(submittedLight, matchedLight)){
          return innerCallback(null, matchedLight);
        }
        
        // If we've gotten here, either there was no matchedLight
        // or the item wasn't equivalent
        submittedLight._id = new ObjectId();
        submittedLight.createdBy = user;
        submittedLight.visibility = visibility;
        
        async.parallel(
          [
            function validateFixture(innerInnerCallback){
              if (!submittedLight.fixture) { return innerInnerCallback(); }

              LightFixtureModel.createNewIfUserDefinedPropertiesModified(
                {
                  lightFixture : submittedLight.fixture,
                  user : user,
                  visibility : visibility,
                  silentValidationFail : silentValidationFail
                },
                function(err, validatedFixture){
                  if (validatedFixture){ submittedLight.fixture = validatedFixture; }
                  if (silentValidationFail){
                    if (err) { 
                      winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
                    }
                    return innerInnerCallback();
                  } 
                  return innerInnerCallback(err);
                }
              );
            },
            function validateBulb(innerInnerCallback){
              if (!submittedLight.bulb) { return innerInnerCallback(); }

              LightBulbModel.createNewIfUserDefinedPropertiesModified(
                {
                  lightBulb : submittedLight.bulb,
                  user : user,
                  visibility : visibility,
                  silentValidationFail : silentValidationFail
                },
                function(err, validatedBulb){
                  if (validatedBulb){ submittedLight.bulb = validatedBulb; }
                  if (silentValidationFail){
                    if (err) { 
                      winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
                    }
                    return innerInnerCallback();
                  } 
                  return innerInnerCallback(err);
                }
              );
            }
          ],
          function parallelEnd(err, results){
            LightModel.create(submittedLight, innerCallback);
          }
        );
      }
    ],
    function(err, validatedLight){
      if (silentValidationFail){
        if (err) { 
          winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); 
        }
        return callback(null, validatedLight);
      }
      return callback(err, validatedLight);
    }
  );
});

/*********************** END STATIC METHODS **************************/

/**
 * @type {Schema}
 */
exports.schema = LightSchema;

/**
 * @constructor
 * @alias module:models/Light.LightModel
 * @type {Model}
 */
exports.model = mongooseConnection.model('Light', LightSchema);
