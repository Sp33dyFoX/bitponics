/**
 * @module models/GrowPlan
 */

var mongoose = require('mongoose'),
  mongoosePlugins = require('../../lib/mongoose-plugins'),
  useTimestamps = mongoosePlugins.useTimestamps,
  Schema = mongoose.Schema,
  ObjectIdSchema = Schema.ObjectId,
  ObjectId = mongoose.Types.ObjectId,
  PhaseSchema = require('./phase').schema,
  Phase = require('./phase').model,
  async = require('async'),
  ModelUtils = require('../utils'),
  getObjectId = ModelUtils.getObjectId,
  requirejs = require('../../lib/requirejs-wrapper'),
  feBeUtils = requirejs('fe-be-utils'),
  PlantModel = require('../plant').model,
  i18nKeys = require('../../i18n/keys'),
  winston = require('winston'),
  mongooseConnection = require('../../config/mongoose-connection').defaultConnection;
  

var GrowPlanModel,
  
GrowPlanSchema = new Schema({
  
  /**
   * The GrowPlan from which this GrowPlan was branched and customized
   */
  parentGrowPlanId: { type: ObjectIdSchema, ref: 'GrowPlan' },
  

  /**
   * User that created this GP
   */
  createdBy: { type: ObjectIdSchema, ref: 'User' },


  /**
   * List of users who can admin this GP
   */
  users : [{ type: ObjectIdSchema, ref: 'User' }],
  
  /**
   * Name
   */
  name: { type: String, required: true },
  

  description: { type: String, required: false },
  

  plants: [{ type: ObjectIdSchema, ref: 'Plant' }],
  

  phases: [PhaseSchema],

  activeGardenCount : { type : Number, default : 0 },
  
  completedGardenCount : { type : Number, default : 0 },
  
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

GrowPlanSchema.plugin(useTimestamps);
GrowPlanSchema.plugin(mongoosePlugins.recoverableRemove);


/************************** INDICES ***************************/
GrowPlanSchema.index({ plants: 1 });
GrowPlanSchema.index({ createdBy: 1 });
/************************** END INDICES ***************************/


/************************** VIRTUALS ***************************/

GrowPlanSchema.virtual('owner')
.get(function () {
    return this.createdBy;
});

/**
 * Sensors is a read-only view of all the sensors used by the GrowPlan.
 * Checks phases.idealRanges.sCode
 *
GrowPlanSchema.virtual('sensors')
.get(function () {
    var sensors = [];
    this.phases.each(function(phase){
        phase.idealRanges.each(function(idealRange){
            if (sensors.indexOf(idealRange.sCode) < 0){
                sensors.push(idealRange.sCode);
            }
        });
    });

    return sensors.sort();
});

/**
 * Controls is a read-only view of all the controls used by the GrowPlan.
 * Checks phases.actions.control.
 * TODO : check phases.idealRanges.actionBelowMin, phases.idealRanges.actionAboveMax
 * Follows the assumption that phaseEndActions will not have controls

GrowPlanSchema.virtual('controls')
    .get(function () {
        var controls = [];
        this.phases.each(function(phase){
            phase.actions.each(function(action){
                // TODO : decide how to handle idealRange actions...need to actually pull the action from the db
                if (!action.control){ return; }
                var controlId = getObjectId(action.control);
                // TODO : this indexOf check probably won't be adequate if controlid is actually an object
                // Maybe store the toString() values instead so we can use a reliable string comparison?
                if (controls.indexOf(controlId) < 0){
                    controls.push(controlId);
                }
            });
            phase.idealRanges.each(function(idealRange){
                // TODO : decide how to handle idealRange actions...need to actually pull the action from the db
                // if it isn't yet populated. Might get expensive.
                if (idealRange.actionBelowMin){ }
                if (idealRange.actionAboveMax){ }
            });
        });

        return controls;
    });
 */

/************************** END VIRTUALS ***************************/

/************************** MIDDLEWARE  ***************************/

/**
 *  Validate 
 *
 */
GrowPlanSchema.pre('save', function(next){
  var phases = this.phases;
  // Ensure unique names across phases
  for (var i = 0, length = phases.length; i < length; i++){
    var phaseName = phases[i].name;

    if (!phaseName){
      phases[i].name = feBeUtils.getOrdinal(i);
    }

    for (var j = i+1; j < length; j++){
      if (phaseName === phases[j].name){
        return next(new Error("Duplicate phase name \"" + phaseName + "\". Phases in a grow plan must have unique names."));
      }
    }
  }
  return next();
});

/************************** END MIDDLEWARE ***************************/



/************************** INSTANCE METHODS  ***************************/

/**
 * Given a number of days into the GrowPlan, find
 * the target phase & number of days into the phase.
 * If numberOfDays exceeds total span of GrowPlan,
 * returns last day of last phase
 * 
 * @param numberOfDays {Number}
 *
 * @return { { phaseId : phaseId, day : numberOfDaysIntoPhase } }
 *
 */
GrowPlanSchema.method('getPhaseAndDayFromStartDay', function(numberOfDays){
  var phases = this.phases,
    i = 0,
    length = phases.length,
    remainder = numberOfDays,
    phaseDays;

  for (; i < length; i++){
    phaseDays = phases[i].expectedNumberOfDays;
    if (remainder < phaseDays){
      return {
        phaseId : phases[i]._id,
        day : remainder
      };
    } else {
      remainder -= phaseDays;
    }
  }

  return {
    phaseId : phases[length - 1]._id,
    day : phases[length - 1].expectedNumberOfDays
  };
});


/************************** END INSTANCE METHODS  ***************************/


/************************** STATIC METHODS  ***************************/

/**
 * Given 2 GrowPlan objects, determine whether they're "equivalent" by comparing 
 * all user-defined properties (ignoring _id's, createdAt/updatedAt)
 * 
 * @param source {GrowPlan}. Fully populated, POJO GrowPlan model object. Retrieved using ModelUtils.getFullyPopulatedGrowPlan
 * @param other {GrowPlan}. Fully populated, POJO GrowPlan model object.
 * @param callback {function(err, bool)} : to be called with result. result is a boolean,
 *          true if the objects are equivalent, false if not
 *
 */
GrowPlanSchema.static('isEquivalentTo', function(source, other, callback){
  // compare name
  if (source.name !== other.name) { return callback(null, false); }


  // compare description
  if (source.description !== other.description) { return callback(null, false); }


  // compare plants

  if (source.plants.length !== other.plants.length) { return callback(null, false); }
  // TODO : this loop can probably be optimized
  var allPlantsFound = true;
  for (var i = 0, length = source.plants.length; i < length; i++){
    var plantId = getObjectId(source.plants[i]),
      plantFound = false;
    for (var j = 0; j < length; j++){
      if (plantId.equals(getObjectId(other.plants[j]))) {
        plantFound = true;
        break;
      }
    }
    if (!plantFound) { 
      allPlantsFound = false;
      break;
    }
  }
  if (!allPlantsFound){
    return callback(null, false);
  }
  
  
  // compare phases, shallow
  if (source.phases.length !== other.phases.length) { return callback(null, false); }
  
  // Now that we've passed all of the shallow comparisons, 
  // we need to do all of the async comparisons
  async.parallel(
    [
      function phasesComparison(innerCallback){
        var allPhasesAreEquivalent = true;
        async.forEach(source.phases, 
          function phaseIterator(phase, phaseCallback){
            var otherPhase = other.phases[source.phases.indexOf(phase)];
            return PhaseSchema.statics.isEquivalentTo(phase, otherPhase, function(err, isEquivalent){
              if (!isEquivalent){
                allPhasesAreEquivalent = false;
                // TODO : short-circuit the async loop by calling callback with an error? or is that too dirty
              }
              return phaseCallback();
            });
          },
          function phaseLoopEnd(err){
            return innerCallback(err, allPhasesAreEquivalent);
          }
        );
      }
    ],
    function parallelComparisonEnd(err, results){
      var allAsyncEquivalenceChecksPassed = results.every(function(result){ return result; });
      return callback(err, allAsyncEquivalenceChecksPassed)
    }
  );
});


/**
 * Takes a fully-populated GrowPlan object (such as is submitted from grow-plans creation page)
 * and, for all nested documents (plants, phases.actions, phases.nutrients, etc) creates them if they don't match existing DB entries.
 *
 * If the submitted GP is different than the original GP retrived from the database:
 * - If the the user is the owner of the GP and is also the sole user of it (no other users' gardens are running the GP), then simply update the original GP
 * - else, save as a new GP as a branch the original
 * 
 * If any differences are detected, this will also update any associated Gardens that have "trackGrowPlanUpdates == true".
 * It will attempt to keep the GPI's on the same phase, and update their active actions, etc. And send out a Notification of things
 * that have been done.
 * 
 * @param {object} options.growPlan : fully-populated grow plan POJO
 * @param {User} options.user : used to set "createdBy" field for new objects
 * @param {VISIBILITY_OPTION} options.visibility : used to set "visibility" field for new objects. value from fe-be-utils.VISIBILITY_OPTIONS
 * @param {bool} options.silentValidationFail : if true: if components fail validation, simply omit them from the created object instead of returning errors up the chain.
 * @param {function(err, GrowPlan)} callback : Returns the GrowPlanModel object (the document from the database, not a POJO)
 */
GrowPlanSchema.static('createNewIfUserDefinedPropertiesModified', function(options, callback){
  var submittedGrowPlan = options.growPlan,
      user = options.user,
      userId = getObjectId(user),
      visibility = options.visibility,
      silentValidationFail = options.silentValidationFail,
      GrowPlanModel = this,
      GrowPlanInstanceModel = require('../garden').model,
      originalGrowPlan,
      originalGrowPlanId,
      originalGrowPlanCreatedById,
      branch = false,
      isEquivalent = false;

  async.waterfall(
    [
      function getOriginalGrowPlan(innerCallback){
        if (!feBeUtils.canParseAsObjectId(submittedGrowPlan._id)){
          branch = true;
          return innerCallback();
        }

        ModelUtils.getFullyPopulatedGrowPlan( { _id: submittedGrowPlan._id }, function(err, growPlanResults){
          if (err) { return innerCallback(err); }

          originalGrowPlan = growPlanResults[0];

          if (!originalGrowPlan){ 
            return innerCallback(new Error(i18nKeys.get('Invalid Grow Plan id', submittedGrowPlan._id)));
          }

          originalGrowPlanId = originalGrowPlan._id.toString();
          originalGrowPlanCreatedById = getObjectId(originalGrowPlan.createdBy);
          
          // Decide on branching
          GrowPlanModel.isEquivalentTo(submittedGrowPlan, originalGrowPlan, function(err, isEquivalentResult){
            if (err) { return innerCallback(err); }

            isEquivalent = isEquivalentResult;

            if (isEquivalent) { 
              // need to return a model object
              //return GrowPlanModel.findById(originalGrowPlan._id, callback);
              return innerCallback();
            }
            
            winston.info("PROCESSING A GROW PLAN MODIFICATION " + submittedGrowPlan._id.toString());
            
            // If different user and non-admin, branch it
            if (!user.admin && !(userId.equals(originalGrowPlanCreatedById))) {
              winston.info("PROCESSING A GROW PLAN MODIFICATION " + originalGrowPlanId + " BRANCH POINT 1");
              branch = true;
              return innerCallback();
            }

            // else it's the original owner or admin. get the gardens using this, check their owners
            GrowPlanInstanceModel
            .find({growPlan : originalGrowPlan._id})
            .select('owner users active')
            .exec(function(err, growPlanInstanceResults){
              if (err) { return innerCallback(err); }
              
              winston.info("PROCESSING A GROW PLAN MODIFICATION " + originalGrowPlanId + " HAS OTHER USERS " + JSON.stringify(growPlanInstanceResults));
              
              var hasOtherUsers = growPlanInstanceResults.some(function(gpi){
                return !(originalGrowPlanCreatedById.equals(gpi.owner));
              });

              // If there are other users using the original GP, branch the submitted GP
              winston.info("PROCESSING A GROW PLAN MODIFICATION " + originalGrowPlanId + " HAS OTHER USERS " + hasOtherUsers);
              
              branch = hasOtherUsers;

              return innerCallback();
            });
          });
        });
      },

      function prepareSubdocuments(innerCallback){

        async.parallel(
        [
          function plantsCheck(innerInnerCallback){
            var validatedPlants = [];

            async.each(submittedGrowPlan.plants, 
              function validatePlant(plant, plantCallback){
                PlantModel.createNewIfUserDefinedPropertiesModified({
                  plant : plant,
                  user : user,
                  visibility : visibility,
                  silentValidationFail : silentValidationFail
                },
                function(err, validatedPlant){
                  if (validatedPlant){
                    validatedPlants.push(validatedPlant);    
                  }
                  if (silentValidationFail){
                    if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); }
                    return plantCallback();  
                  }
                  return plantCallback(err);
                });
              },
              function plantLoopEnd(err){
                submittedGrowPlan.plants = validatedPlants;
                return innerInnerCallback(err);
              }
            );
          },
          function phasesCheck(innerInnerCallback){
            var validatedPhases = [];

            async.eachSeries(submittedGrowPlan.phases, 
              function (phase, phaseCallback){
                PhaseSchema.statics.createNewIfUserDefinedPropertiesModified(
                  {
                    phase : phase,
                    user : user,
                    visibility : visibility,
                    silentValidationFail : silentValidationFail,
                    attemptInPlaceEdit : !branch // if we're not branching, try to update phases in-place rather than creating new ones
                  },
                  function(err, validatedPhase){
                    if (validatedPhase){
                      validatedPhases.push(validatedPhase);
                    }
                    return phaseCallback(err);  
                  }
                );            
              },
              function phaseLoopEnd(err){
                submittedGrowPlan.phases = validatedPhases;
                return innerInnerCallback(err);
              }
            );
          }
        ],
        function subdocumentParallelFinal(err, results){
          return innerCallback(err);
        });
      },
      
      function handleBranchingAndSave(innerCallback){
        //console.log("BRANCHING", branch);
        // at this point, everything should have valid, saved referenced documents

        if (branch){
          submittedGrowPlan._id = new ObjectId();
          
          if (originalGrowPlan){
            submittedGrowPlan.parentGrowPlanId = originalGrowPlan._id;  
          }
          
          submittedGrowPlan.createdBy = user;
          submittedGrowPlan.users = [user];
          submittedGrowPlan.visibility = visibility;

          GrowPlanModel.create(submittedGrowPlan, innerCallback);

        } else {
          
          // If not branching, store the previous version in history and update the current
          async.parallel([
            function saveHistory(innerInnerCallback){
              var GrowPlanHistoryModel = require('../growPlanHistory').model;
              GrowPlanHistoryModel.create({
                growPlanId : originalGrowPlan._id,
                growPlanObject : originalGrowPlan
              }, innerInnerCallback);
            },
            function saveGrowPlan(innerInnerCallback){
              GrowPlanModel.findById(originalGrowPlan._id, function(err, growPlanResult){
                if (err) { return innerCallback(err); }

                growPlanResult.name = submittedGrowPlan.name;
                growPlanResult.description = submittedGrowPlan.description;
                growPlanResult.visibility = submittedGrowPlan.visibility;
                growPlanResult.plants = submittedGrowPlan.plants;
                growPlanResult.phases = submittedGrowPlan.phases;
                growPlanResult.save(
                  function(err, savedGrowPlan, numberAffected){ 
                    //console.log("SAVED EXISTING GROW PLAN", err, savedGrowPlan, numberAffected);
                    return innerInnerCallback(err, savedGrowPlan);
                  }
                );
              });    
            }
          ],
          function nonBranchingParallelEnd(err, results){
            // pass the savedGrowPlan to the callback. will be the result of the 2nd parallel result
            return innerCallback(err, results[1]);
          });
        }
      },

      function updateGardens(savedGrowPlan, innerCallback){
        if (!originalGrowPlan) { return innerCallback(null, savedGrowPlan); }
        
        // Find all the GPI's using the old GP that are active and have "trackGrowPlanUpdates" set to true
        var gardenQuery = { growPlan : originalGrowPlanId, active : true, trackGrowPlanUpdates : true };

        // If user is the creator or admin, update all gardens that are tracking updates
        if (user.admin || userId.equals(originalGrowPlanCreatedById)) {
          
        } else {
          // Else, just update this user's gardens
          gardenQuery['owner'] = userId;
        }

        winston.info("PROCESSING A GROW PLAN MODIFICATION " + originalGrowPlanId + " SAVED GROW PLAN " + savedGrowPlan._id.toString() + " UPDATING GARDENS, QUERY " + JSON.stringify(gardenQuery));
        
        GrowPlanInstanceModel.find(gardenQuery)
        .exec(function(err, growPlanInstancesToUpdate){
          if (err) { return innerCallback(err); }

          winston.info("PROCESSING A GROW PLAN MODIFICATION " + originalGrowPlanId + " SAVED GROW PLAN " + savedGrowPlan._id.toString() + " UPDATING GARDENS " + JSON.stringify(growPlanInstancesToUpdate.map(function(gpi) { return gpi._id.toString(); })) );

          async.eachLimit(
            growPlanInstancesToUpdate,
            10,
            function gpiIterator(growPlanInstance, iteratorCallback){
              
              growPlanInstance.migrateToGrowPlan(
              {
                newGrowPlan : savedGrowPlan
              },
              iteratorCallback
              );
            },
            function loopComplete(err){
              return innerCallback(err, savedGrowPlan);
            }
          );
        });
      }
    ],
    function waterfallEnd(err, savedGrowPlan){
      return callback(err, savedGrowPlan);
    }
  );
}); // /.createNewIfUserDefinedPropertiesModified


/************************** END STATIC METHODS  ***************************/

GrowPlanModel = mongooseConnection.model('GrowPlan', GrowPlanSchema);
exports.schema = GrowPlanSchema;
exports.model = GrowPlanModel;
