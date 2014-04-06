var PlantModel = require('../../../models/plant').model,
    winston = require('winston'),
    routeUtils = require('../../route-utils'),
    requirejs = require('../../../lib/requirejs-wrapper'),
  	feBeUtils = requirejs('fe-be-utils'),
    apiUtils = require('../utils'),
    extend = require("xtend");

/**
 * module.exports : function to be immediately invoked when this file is require()'ed 
 * 
 * @param app : app instance. Will have the configs appended to a .config property. 
 */
module.exports = function(app) {

   //List plants
  app.get('/api/plants',
  	apiUtils.query({
      model : PlantModel
    })
  );

  /*
   * Create single plant
   *
   *  Test with:
   *  jQuery.post("/api/plants", {
   *    "name" : "big"
   *    }
   *  }, function (data, textStatus, jqXHR) {
   *    console.log("Post resposne:"); console.dir(data); console.log(textStatus); console.dir(jqXHR);
   *  });
   */
  app.post('/api/plants', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
	    PlantModel.create(
	    	req.body,
	    	function (err, createdPlant) {
	      	if (err) { return next(err); }
	      	return res.send(createdPlant);
	    	}
    	);
	  }
  );

  /*
   * Read a plant
   *
   * To test:
   * jQuery.get("/api/plants/${id}", function(data, textStatus, jqXHR) {
   *     console.log("Get response:");
   *     console.dir(data);
   *     console.log(textStatus);
   *     console.dir(jqXHR);
   * });
   */
  app.get('/api/plants/:id', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
	    return PlantModel.findById(req.params.id, function (err, plant) {
	      if (err) { return next(err); }
	      return res.send(plant);
	    });
	  }
  );

  /*
   * Update a plant
   *
   * To test:
   * jQuery.ajax({
   *     url: "/api/plants/${id}",
   *     type: "PUT",
   *     data: {
   *       "actionBelowMin": "actionid"
   *     },
   *     success: function (data, textStatus, jqXHR) {
   *         console.log("Post response:");
   *         console.dir(data);
   *         console.log(textStatus);
   *         console.dir(jqXHR);
   *     }
   * });
   */
  app.put('/api/plants/:id', 
  	routeUtils.middleware.ensureLoggedIn,
    routeUtils.middleware.ensureUserIsAdmin,
  	function (req, res, next){
	    return PlantModel.findById(req.params.id, function (err, plant) {
	      if (err) { return next(err); }
        var updated = {};
        // console.log('plant before:', plant);
        updated = extend(plant, req.params);
        // console.log('plant after:', updated);
	      return updated.save(function (err) {
	        if (err) { return next(err); }
	        return res.send(updated);
	      });

	    });
	  }
  );

  /*
   * Delete a plant
   *
   * To test:
   * jQuery.ajax({
   *     url: "/api/plants/${id}", 
   *     type: "DELETE",
   *     success: function (data, textStatus, jqXHR) { 
   *         console.log("Post resposne:"); 
   *         console.dir(data); 
   *         console.log(textStatus); 
   *         console.dir(jqXHR); 
   *     }
   * });
   */
  app.delete('/api/plants/:id', 
  	routeUtils.middleware.ensureLoggedIn,
  	routeUtils.middleware.ensureUserIsAdmin,
  	function (req, res, next){
	    return next(new Error("Not implemented"));
	  }
  );
};
