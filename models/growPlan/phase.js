/**
 * @module models/GrowPlan/Phase
 */

var mongoose = require('mongoose'),
  mongoosePlugins = require('../../lib/mongoose-plugins'),
  Schema = mongoose.Schema,
  ObjectIdSchema = Schema.ObjectId,
  ObjectId = mongoose.Types.ObjectId,
  IdealRangeSchema = require('./idealRange').schema,
  async = require('async'),
  ActionModel = require('../action').model,
  GrowSystemModel = require('../growSystem').model,
  NutrientModel = require('../nutrient').model,
  LightModel = require('../light').model,
  getObjectId = require('../utils').getObjectId,
  requirejs = require('../../lib/requirejs-wrapper'),
  feBeUtils = requirejs('fe-be-utils');

var PhaseSchema = new Schema({
  
  name: { type: String, required: false },
  
  description: { type: String },

  /**
   * expectedNumberOfDays. undefined means infinite.
   */
  expectedNumberOfDays: { type: Number, default : 0 },
  
  /**
   * Light definition. Optional. Defines fixtures, bulbs, and quantities.
   */
  light: { type : ObjectIdSchema, ref: 'Light'  },

  growSystem: { type: ObjectIdSchema, ref: 'GrowSystem' },
  
  growMedium: { type: String },

  actions: [{ type: ObjectIdSchema, ref: 'Action' }],
  
  phaseEndActions : [{ type: ObjectIdSchema, ref: 'Action'}],

  phaseEndDescription : { type : String },

  idealRanges: [IdealRangeSchema],

  nutrients : [{ type: ObjectIdSchema, ref: 'Nutrient' }],
},
{ id : false });

/************************** INSTANCE METHODS  ***************************/


// TODO : Add validation on save. 
// Validation rules:
// Max 1 idealRange per sensor. 

/*********************** END INSTANCE METHODS *************************/



/*********************** STATIC METHODS ******************************/

/**
 * Given 2 Phase objects, determine whether they're equivalent.
 * Assumes fully-populated Phase objects.
 * Comparing only user-defined properties.
 * 
 * @param {Phase} source : Fully-populated Phase object
 * @param {Phase} other : Fully-populated Phase object
 * @param {function(err, bool)} callback : Function to be called with result. Passed a boolean argument,
 *          true if the objects are equivalent, false if not
 *
 */
PhaseSchema.static('isEquivalentTo', function(source, other, callback){
  // compare name
  if (source.name !== other.name) { return callback(null, false); }

  // compare description
  if (source.description !== other.description) { return callback(null, false); }

  // compare expectedNumberOfDays
  if (source.expectedNumberOfDays !== other.expectedNumberOfDays) { return callback(null, false); }

  // compare growMedium
  if (source.growMedium !== other.growMedium) { return callback(null, false); } 


  // compare phaseEndDescription
  if (source.phaseEndDescription !== other.phaseEndDescription) { return callback(null, false); }   

  // compare growSystem, shallow
  if ( !(
      (source.growSystem && other.growSystem)
      ||
      (!source.growSystem && !other.growSystem)
      )
    )
  { 
    return callback(null, false); 
  }
  if (source.growSystem){
    var thisGrowSystemId = getObjectId(source.growSystem),
      otherGrowSystemId = getObjectId(other.growSystem);
    if (!thisGrowSystemId.equals(otherGrowSystemId)){
      return callback(null, false);
    }
  }
  // compare light, shallow
  if (!(
    (source.light && other.light)
    ||
    (!source.light && !other.light)
    )){ 
    return callback(null, false); 
  }
  if (source.light){
    if ( !(
      (source.light.fixture && other.light.fixture) ||
      (!source.light.fixture && !other.light.fixture)
     )
    ){ 
      return callback(null, false); 
    }
    if ( !(
      (source.light.bulb && other.light.bulb) ||
      (!source.light.bulb && !other.light.bulb)
     )
    ){ 
      return callback(null, false); 
    }
    if ( source.light.fixtureQuantity !== other.light.fixtureQuantity)
    { 
      return callback(null, false); 
    }
  }

  // compare actions, shallow
  if ( !(
      (source.actions && other.actions) ||
      (!source.actions && !other.actions)
     )
    ){ 
    return callback(null, false); 
  }
  if (source.actions && other.actions && (source.actions.length !== other.actions.length)){
    return callback(null, false);
  }

  // compare phaseEndActions, shallow
  if ( !(
      (source.phaseEndActions && other.phaseEndActions) ||
      (!source.phaseEndActions && !other.phaseEndActions)
     )
    ){ 
    return callback(null, false); 
  }
  if (source.phaseEndActions && other.phaseEndActions && (source.phaseEndActions.length !== other.phaseEndActions.length)){
    return callback(null, false);
  }


  // compare idealRanges, shallow
  if ( !(
      (source.idealRanges && other.idealRanges) ||
      (!source.idealRanges && !other.idealRanges)
     )
    ){ 
    return callback(null, false); 
  }
  if (source.idealRanges && other.idealRanges && (source.idealRanges.length !== other.idealRanges.length)){
    return callback(null, false);
  }
  

  // compare nutrients, shallow
  if ( !(
      (source.nutrients && other.nutrients) ||
      (!source.nutrients && !other.nutrients)
     )
    ){ 
    return callback(null, false); 
  }
  if (source.nutrients && other.nutrients && (source.nutrients.length !== other.nutrients.length)){
    return callback(null, false);
  }
  
  async.parallel(
    [
      function growSystemComparison(innerCallback){
        if (!source.growSystem){ return innerCallback(null, true); }
        return innerCallback(null, GrowSystemModel.isEquivalentTo(source.growSystem, other.growSystem));
      },
      function lightComparison(innerCallback){
        if (!source.light){ return innerCallback(null, true); }

        if (source.light.fixture){
          var sourceLightFixtureId = getObjectId(source.light.fixture),
            otherLightFixtureId = getObjectId(other.light.fixture);
          if (!sourceLightFixtureId.equals(otherLightFixtureId)){
            return innerCallback(null, false);
          }
        }
        if (source.light.fixtureQuantity !== other.light.fixtureQuantity){
          return innerCallback(null, false);
        }
        if (source.light.bulb){
          var sourceLightBulbId = getObjectId(source.light.bulb),
            otherLightBulbId = getObjectId(other.light.bulb);
          if (!sourceLightBulbId.equals(otherLightBulbId)){
            return innerCallback(null, false);
          }
        }
        return innerCallback(null, true);
      },
      function actionsComparison(innerCallback){
        if (!source.actions || !source.actions.length) { return innerCallback(null, true); }

        var allActionsFound = true;
        for (var i = 0, length = source.actions.length; i < length; i++){
          var action = source.actions[i],
            actionFound = false;
          for (var j = 0; j < length; j++){
            var otherAction = other.actions[j];
            if (ActionModel.isEquivalentTo(action, otherAction)) {
              actionFound = true;
              break;
            }
          }
          if (!actionFound) { 
            allActionsFound = false;
            break;
          }
        }
        if (!allActionsFound){
          return innerCallback(null, false);
        }
        return innerCallback(null, true);
      },
      function phaseEndActionsComparison(innerCallback){
        if (!source.phaseEndActions || !source.phaseEndActions.length) { return innerCallback(null, true); }

        var allActionsFound = true;
        for (var i = 0, length = source.phaseEndActions.length; i < length; i++){
          var action = source.phaseEndActions[i],
            actionFound = false;
          for (var j = 0; j < length; j++){
            var otherAction = other.phaseEndActions[j];
            if (ActionModel.isEquivalentTo(action, otherAction)){
              actionFound = true;
              break;
            }
          }
          if (!actionFound) { 
            allActionsFound = false;
            break;
          }
        }
        if (!allActionsFound){
          return innerCallback(null, false);
        }
        return innerCallback(null, true); 
      },
      function idealRangesComparison(innerCallback){
        if (!source.idealRanges || !source.idealRanges.length) { return innerCallback(null, true); }

        var allIdealRangesFound = true;
        for (var i = 0, length = source.idealRanges.length; i < length; i++){
          var idealRangeFound = false;
          for (var j = 0; j < length; j++){
            if (IdealRangeSchema.statics.isEquivalentTo(source.idealRanges[i], other.idealRanges[j])){
              idealRangeFound = true;
              break;
            }
          }
          if (!idealRangeFound) { 
            allIdealRangesFound = false;
            break;
          }
        }
        if (!allIdealRangesFound){
          return innerCallback(null, false);
        }
        return innerCallback(null, true);
      },
      function nutrientsComparison(innerCallback){
        if (!source.nutrients || !source.nutrients.length) { return innerCallback(null, true); }

        var allNutrientsFound = true;
        for (var i = 0, length = source.nutrients.length; i < length; i++){
          var nutrientId = getObjectId(source.nutrients[i]),
            nutrientFound = false;
          for (var j = 0; j < length; j++){
            var otherNutrientId = getObjectId(other.nutrients[j]);
            if (nutrientId.equals(otherNutrientId)){
              nutrientFound = true;
              break;
            }
          }
          if (!nutrientFound) { 
            allNutrientsFound = false;
            break;
          }
        }
        if (!allNutrientsFound){
          return innerCallback(null, false);
        }
        return innerCallback(null, true); 
      }
    ],
    function parallelComparisonEnd(err, results){
      var allAsyncEquivalenceChecksPassed = results.every(function(result){ return result; });
      return callback(err, allAsyncEquivalenceChecksPassed);
    }
  );
});


/**
 * Takes a fully-populated Phase object (such as is submitted from grow-plans creation page)
 * and, for all nested documents (actions, nutrients, growSystem, light, idealRanges), creates them if they don't match existing DB entries
 * Then returns Phase object
 * 
 * @param {object} options.phase
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {bool} options.silentValidationFail : if true: if components fail validation, simply omit them from the created object instead of returning errors up the chain.
 * @param {bool} options.attemptInPlaceEdit : passed in from GrowPlan.createNewIfUserDefinedPropertiesModified. if true: make all changes in-place (don't create a new _id). else, normal behavior.
 * @param {function(err, Phase)} callback
 */
PhaseSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedPhase = options.phase,
      user = options.user,
      visibility = options.visibility,
      silentValidationFail = options.silentValidationFail;

  if (!feBeUtils.canParseAsObjectId(submittedPhase._id)){
    submittedPhase._id = new ObjectId();
  }

  async.parallel(
    [
      function validateActions(innerCallback){
        var validatedActions = [];

        if (!submittedPhase.actions && submittedPhase.actions.length){ return innerCallback(); }
        
        async.forEach(submittedPhase.actions, 
          function validateAction(action, actionCallback){
            ActionModel.createNewIfUserDefinedPropertiesModified({
              action : action,
              user : user,
              visibility : visibility,
              silentValidationFail : silentValidationFail
            },
            function(err, validatedAction){
              if (validatedAction){
                validatedActions.push(validatedAction._id);
              }
              if (silentValidationFail){
                if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); }
                return actionCallback();  
              }
              return actionCallback(err);
            });
          },
          function actionLoopEnd(err){
            submittedPhase.actions = validatedActions;
            return innerCallback(err);
          }
        );
      },
      function validatePhaseEndActions(innerCallback){
        var validatedActions = [];

        async.forEach(submittedPhase.phaseEndActions, 
          function validateAction(action, actionCallback){
            ActionModel.createNewIfUserDefinedPropertiesModified({
              action : action,
              user : user,
              visibility : visibility,
              silentValidationFail : silentValidationFail
            },
            function(err, validatedAction){
              if (validatedAction){
                validatedActions.push(validatedAction._id);  
              }
              if (silentValidationFail){
                if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); }
                return actionCallback();  
              }
              return actionCallback(err);
            });
          },
          function actionLoopEnd(err){
            submittedPhase.phaseEndActions = validatedActions;
            return innerCallback(err);
          }
        );
      },
      function validateGrowSystem(innerCallback){
        if (!submittedPhase.growSystem){ return innerCallback(); }
        
        GrowSystemModel.createNewIfUserDefinedPropertiesModified(
          {
            growSystem : submittedPhase.growSystem,
            user : user,
            visibility : visibility,
            silentValidationFail : silentValidationFail
          },
          function(err, validatedGrowSystem){
            if (validatedGrowSystem){
              submittedPhase.growSystem = validatedGrowSystem._id;  
            }
            if (silentValidationFail){
              if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); }
              return innerCallback();   
            }
            return innerCallback(err);
          }
        );
      },
      function validateNutrients(innerCallback){
        if (!(submittedPhase.nutrients && submittedPhase.nutrients.length)) { return innerCallback(); }

        var validatedNutrients = [];

        async.forEach(submittedPhase.nutrients, 
          function validateNutrient(nutrient, nutrientCallback){
            NutrientModel.createNewIfUserDefinedPropertiesModified({
              nutrient : nutrient,
              user : user,
              visibility : visibility,
              silentValidationFail : silentValidationFail
            },
            function(err, validatedNutrient){
              if (validatedNutrient){
                validatedNutrients.push(validatedNutrient._id);
              }
              if (silentValidationFail){
                if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); }
                return nutrientCallback();  
              }
              return nutrientCallback(err);
            });
          },
          function nutrientLoopEnd(err){
            submittedPhase.nutrients = validatedNutrients;
            return innerCallback(err);
          }
        );
      },
      function validateLight(innerCallback){
        if (!submittedPhase.light){ return innerCallback(); }

        LightModel.createNewIfUserDefinedPropertiesModified(
          {
            light : submittedPhase.light,
            user : user,
            visibility : visibility,
            silentValidationFail : silentValidationFail
          },
          function(err, validatedLight){
            if (validatedLight){
              submittedPhase.light = validatedLight._id;  
            }
            if (silentValidationFail){
              if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); }
              return innerCallback();  
            }
            return innerCallback(err);
          }
        );
      },
      function validateIdealRanges(innerCallback){
        var validatedIdealRanges = [];

        async.forEach(submittedPhase.idealRanges, 
          function (idealRange, idealRangeCallback){
            IdealRangeSchema.statics.createNewIfUserDefinedPropertiesModified(
              {
                idealRange : idealRange,
                user : user,
                visibility : visibility,
                silentValidationFail : silentValidationFail
              }, 
              function(err, validatedIdealRange){
                if (validatedIdealRange){
                  validatedIdealRanges.push(validatedIdealRange);
                }
                if (silentValidationFail){
                  if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); }
                  return idealRangeCallback();
                }
                return idealRangeCallback(err);  
              }
            );            
          },
          function idealRangeLoopEnd(err){
            submittedPhase.idealRanges = validatedIdealRanges;
            return innerCallback(err);
          }
        );  
      },
    ],
    function parallelEnd(err, results){
      if (options.attemptInPlaceEdit){

      } else {
        // force mongoose to create a new _id
        delete submittedPhase._id;
      }
      
      if (silentValidationFail && err){
        winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack']));
        return (null, null);
      } 
      return callback(err, submittedPhase);
    }
  );
});
/*********************** END STATIC METHODS **************************/

exports.schema = PhaseSchema;
