var GrowPlanModel = require('../../../models/growPlan').growPlan.model,
    GrowPlanInstanceModel = require('../../../models/garden').model,
    ActionModel = require('../../../models/action').model,
    UserModel = require('../../../models/user').model,
    LightFixtureModel = require('../../../models/lightFixture').model,
    LightBulbModel = require('../../../models/lightBulb').model,
    ModelUtils = require('../../../models/utils'),
    winston = require('winston'),
    allPurposeGrowPlanId = '506de30c8eebf7524342cb70',
    async = require('async'),
    routeUtils = require('../../route-utils');

/**
 * module.exports : function to be immediately invoked when this file is require()'ed 
 * 
 * @param app : app instance. Will have the configs appended to a .config property. 
 */
module.exports = function(app) {
  /*
   * List all grow plans
   *  If no params, list all in db
   *  If id param, match on grow plan and return compact data
   *  If plants and growSystem params, filter on all grow plans (except All-Purpose) and return compact data
   */
  app.get('/api/grow-plans', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
    var filter = false,
        full = false,
        plants = req.query.plants,
        growSystem = req.query.growSystem;
    
    // if(!!plants && !!growSystem && typeof plants !== 'undefined' && typeof growSystem !== 'undefined'){
    //   filter = true;
    //   plants = typeof plants === 'object' ? plants : plants.split(',');
    //   growSystem = growSystem.split(',');
    // }else if(!!id){
    //   full = true;
    // }


    var query = GrowPlanModel.find();

    if (plants){
      console.log('plants', plants)
      plants = typeof plants === 'object' ? plants : plants.split(',');  
      query.where('plants').in(plants);
    }

    query.where('_id').ne(allPurposeGrowPlanId)
    query.select('name description phases.expectedNumberOfDays createdBy activeGardenCount plants createdAt')
    .populate('createdBy', 'name')
    .lean()
    .exec(function (err, growPlans) {
      if (err) { return next(err); }
      
      var userIds = [],
          gpObjects = [],
          overallTimeSpan = 0;

      growPlans.forEach(function(gp){
        var gpo = gp;//.toObject();
        userIds.push(gp.createdBy);
        gpo.overallTimeSpan = gpo.phases.reduce(function(prev, curr){
          var value1 = prev.expectedNumberOfDays,
              value2 = curr.expectedNumberOfDays;
          if(typeof value1 != 'number'){ value1 = 0; }
          if(typeof value2 != 'number'){ value2 = 0; }
          return value1 + value2
        }, 0);
        gpObjects.push(gpo);
        
      });
      return res.send(gpObjects);
    });
  });

  /*
   * Create single grow plan
   *
   *  Test with:
   *  jQuery.post("/api/grow-plans", {
   *    "parentGrowPlanId": "growplanid",
   *    "createdBy": "userid",
   *    "name": "Jack's Grow Plan",
   *    "description": "Herbs on a raft.",
   *    "plants": [{ name : "basil"}, { name : "rosemary"}, { name : "dill"}, { name : "swiss chard"} ],
   *    "sensors": "",
   *    "controls": "",
   *    "phases": ""
   *  }, function (data, textStatus, jqXHR) {
   *    console.log("Post resposne:"); console.dir(data); console.log(textStatus); console.dir(jqXHR);
   *  });
   */
  app.post('/api/grow-plans', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
	    var grow_plan;
	    winston.info("POST: ");
	    winston.info(req.body);
	    grow_plan = new GrowPlanModel({
	      parentGrowPlanId: req.body.parentGrowPlanId,
	      createdBy: req.body.createdBy,
	      name: req.body.name,
	      description: req.body.description,
	      plants: req.body.plants,
	      phases: req.body.phases
	    });
	    grow_plan.save(function (err) {
	      if (err) { return next(err); }
	      return res.send(grow_plan);
	    });
	  }
  );



  /*
   * Read a grow plan
   *
   * To test:
   * jQuery.get("/api/grow-plans/${id}", function(data, textStatus, jqXHR) {
   *     console.log("Get response:");
   *     console.dir(data);
   *     console.log(textStatus);
   *     console.dir(jqXHR);
   * });
   */
  app.get('/api/grow-plans/:id', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
	    ModelUtils.getFullyPopulatedGrowPlan( { _id: req.params.id }, function(err, growPlanResults){
        if (err) { return next(err); }

        var growPlanResult = growPlanResults[0];

        if (!growPlanResult){ 
          return next(new Error(i18nKeys.get('Invalid Grow Plan id', submittedGrowPlan._id)));
        }

        return res.send(growPlanResult);
      });
	  }
  );



  app.get('/api/grow-plans/:id/default-photo', 
    routeUtils.middleware.ensureLoggedIn,
    function (req, res, next){
      GrowPlanModel.findById(req.params.id)
      .select('plants owner users visibility')
      .exec(function(err, growPlanResult){
        if (err) { return next(err); }

        if (!growPlanResult){ 
          return next(new Error(i18nKeys.get('Invalid Grow Plan id', req.params.id)));
        }

        return res.send(302, '//s3.amazonaws.com/bitponics-cdn/assets/img/plants/' + growPlanResult.plants[0].toString() + '.jpg');
      });
    }
  );
  


  /*
   * Get number of gardens using Grow Plan, optionally forcing a refresh of the count calculation
   *
   * @param req.forceRefresh {bool}
   */
  app.get('/api/grow-plans/:id/active-garden-count', 
    routeUtils.middleware.ensureLoggedIn,
    function (req, res, next){
      
      if (req.params.forceRefresh){

      }
      // TEMP: for now, always recalculate
      GrowPlanInstanceModel.count({ growPlan : req.params.id, active : true }, function(err, count){
        if (err) { return next(err); }
        GrowPlanModel.findByIdAndUpdate(req.params.id, { activeGardenCount : count }, function(err){
          if (err) { return next(err); }
          return res.send({ activeGardenCount : count});
        });
      });
    }
  );

  
  /*
   * Update a grow plan
   *
   * 
   */
  app.post('/api/grow-plans/:id', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
	    console.log("got some grow plan POST!", JSON.stringify(req.body));
      
      var result = {};
      
      GrowPlanModel.createNewIfUserDefinedPropertiesModified(
        {
          growPlan : req.body,
          user : req.user,
          visibility : feBeUtils.VISIBILITY_OPTIONS.PUBLIC,
          silentValidationFail : true
        },
        function(err, validatedGrowPlan){
          winston.info("UPDATED GROW PLAN, err:" + JSON.stringify(err) + ", originalId " + req.params.id + ", newId " + (validatedGrowPlan ? validatedGrowPlan._id : ''));

          if (err) { 
            result.status = 'error';
            result.errors = [err.message];
            return res.json(500, result);
          }

          ModelUtils.getFullyPopulatedGrowPlan({_id : validatedGrowPlan._id}, function(err, fullyPopulatedGrowPlans){
            if (err) { 
              result.status = 'error';
              result.errors = [err.message];
              return res.json(500, result);
            }

            return res.json(fullyPopulatedGrowPlans[0]);
          })
          
        }
      );
	  }
  );

  /*
   * Delete a grow plan
   *
   * To test:
   * jQuery.ajax({
   *     url: "/api/grow-plans/${id}", 
   *     type: "DELETE",
   *     success: function (data, textStatus, jqXHR) { 
   *         console.log("Post resposne:"); 
   *         console.dir(data); 
   *         console.log(textStatus); 
   *         console.dir(jqXHR); 
   *     }
   * });
   */
  app.delete('/api/grow-plans/:id',
		routeUtils.middleware.ensureSecure, 
		routeUtils.middleware.ensureUserIsAdmin,
		function (req, res, next){
    return GrowPlanModel.findById(req.params.id, function (err, grow_plan) {
      if (err) { return next(err); }

      return grow_plan.remove(function (err) {
        if (err) { return next(err); }
        return res.send('');
      });
    });
  });

};
