var LightBulbModel = require('../../models/lightBulb').model, 
    winston = require('winston'),
    routeUtils = require('../route-utils');

/**
 * module.exports : function to be immediately invoked when this file is require()'ed 
 * 
 * @param app : app instance. Will have the configs appended to a .config property. 
 */
module.exports = function(app) {

   //List lights
  app.get('/api/light-bulbs', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
	    return LightBulbModel.find(function (err, lights) {
	      if (err) { return next(err); }
	      return res.send(lights);
	      });
	  }
  );

  /*
   * Create single light
   *
   *  Test with:
   *  jQuery.post("/api/light-bulbs", {
   *    "type": "light type",
   *    "watts": "60",
   *    "brand" : "light brand",
   *    "name" : "big"
   *    }
   *  }, function (data, textStatus, jqXHR) {
   *    console.log("Post resposne:"); console.dir(data); console.log(textStatus); console.dir(jqXHR);
   *  });
   */
  app.post('/api/light-bulbs', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
	    var light;
	    winston.info("POST: ");
	    winston.info(req.body);
	    light = new LightBulbModel({
	      type: req.body.type,
	      watts: req.body.watts,
	      brand : req.body.brand,
	      name : req.body.name
	    });
	    light.save(function (err) {
	      if (err) { return next(err); }
	      return res.send(light);
	    });
	  }
  );

  /*
   * Read an light
   *
   * To test:
   * jQuery.get("/api/light-bulbs/${id}", function(data, textStatus, jqXHR) {
   *     console.log("Get response:");
   *     console.dir(data);
   *     console.log(textStatus);
   *     console.dir(jqXHR);
   * });
   */
  app.get('/api/light-bulbs/:id', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
	    return LightBulbModel.findById(req.params.id, function (err, light) {
	      if (err) { return next(err); }
	      return res.send(light);
	    });
	  }
  );

  /*
   * Update a light
   *
   * To test:
   * jQuery.ajax({
   *     url: "/api/light-bulbs/${id}",
   *     type: "PUT",
   *     data: {
   *     },
   *     success: function (data, textStatus, jqXHR) {
   *         console.log("Post response:");
   *         console.dir(data);
   *         console.log(textStatus);
   *         console.dir(jqXHR);
   *     }
   * });
   */
  app.put('/api/light-bulbs/:id', 
  	routeUtils.middleware.ensureLoggedIn,
  	function (req, res, next){
	    return LightBulbModel.findById(req.params.id, function (err, light) {
	      if (err) { return next(err); }
	      return light.save(function (err) {
	        if (err) { return next(err); }
	        return res.send(light);
	      });
	    });
	  }
  );

  /*
   * Delete a light
   *
   * To test:
   * jQuery.ajax({
   *     url: "/api/light_bulbs/${id}", 
   *     type: "DELETE",
   *     success: function (data, textStatus, jqXHR) { 
   *         console.log("Post resposne:"); 
   *         console.dir(data); 
   *         console.log(textStatus); 
   *         console.dir(jqXHR); 
   *     }
   * });
   */
  app.delete('/api/light-bulbs/:id',
  	routeUtils.middleware.ensureLoggedIn,
  	routeUtils.middleware.ensureUserIsAdmin, 
  	function (req, res, next){
	    return LightBulbModel.findById(req.params.id, function (err, light) {
	      if (err) { return next(err); }
	      return light.remove(function (err) {
	        if (err) { return next(err); }
	        return res.send('');
	      });
	    });
	  }
  );
};
