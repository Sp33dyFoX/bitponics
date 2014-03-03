var async = require('async'),
		routeUtils = require('../route-utils.js'),
		requirejs = require('../../lib/requirejs-wrapper'),
    feBeUtils = requirejs('fe-be-utils');

module.exports = {
	
	/**
	 * Attach a GET query handler
	 * 
	 * @param {Model} options.model
	 * @param {Model=} [options.parentModel]
	 * @param {string=} [options.parentModelFieldName = "ref.documentId"] - if parentModel is defined, used to query for parent id. 
	 * @param {string=} [options.dateFieldName] - document field to use for start-date/end-date query filters
	 * @param {string=} [options.defaultSort] - "fieldName" for ascending or "-fieldName" for descending
   * @param {object|function} [options.defaultWhere] - default query for filtering results. Can be overridden by request "where" param. If a function, the function is invoked and should return an object
   * @param {object} [options.defaultLimit=200] - default limit for number of results returned
   * @param {bool=} [options.restrictByVisibility = false] - optionally add a conditional clause to the query to limit to the documents the user has read-access to
	 * 
	 * @return {[function(req, res, next)]}
	 * 
	 * Request:
	 * @param {Date} [req.params.start-date] - Should be something parse-able by moment.js
   * @param {Date} [req.params.end-date] - Should be something parse-able by moment.js
   * @param {Number} [req.params.skip=0] - Number of results to skip (used for pagination)
   * @param {Number} [req.params.limit=200] - Number of results to return per page. Hard limit of 200.
   * @param {string=} [req.params.sort] - name of field to sort by. prefix with "-" for descending.
   * @param {CSV} [req.params.select] - CSV list of field names to include in the response. Fields on nested objects can be requested with dot-notation: "nestedDocument.name"
   * @param {Object} [req.params.where] - JSON-encoded query object. Follows mongodb query conventions. https://parse.com/docs/rest#queries
   * @param {string=} [req.params.search] String search term. Should usually be used to query fuzzy match on "name" field.
   *
   * Response:
   * @param {Array[model]} data
   * @param {Number} count
   * @param {Number} skip
   * @param {Number} limit
	 */
 	query : function(options){
	 	
	 	var Model = options.model,
	 		ParentModel = options.parentModel, 
	 		parentModelFieldName = options.parentModelFieldName;

	 	
	 	return [
	 		// routeUtils.middleware.ensureLoggedIn,
	 		function(req, res, next){

		 		var response = {
		 			statusCode : 200,
		 			body : {}
		 		},

        startDate = req.query['start-date'],
		    endDate = req.query['end-date'],
		    limit = req.query['limit'] || 200,
		    skip = req.query['skip'] || 0,
        sort = req.query['sort'],
        select = req.query['select'],
		    where,
        query;

        // cap the limit at 200
        limit = parseInt(limit, 10);
        if (limit > 200) { limit = 200; }

        skip = parseInt(skip, 10);

		 		async.series([
					function checkIfParentModel(innerCallback){
						if (!ParentModel){ return innerCallback(); }

  		 			ParentModel.findById(req.params.id)
  			 			.select('owner users createdBy visibility')
  			 			.exec(function(err, parentModelResult){
                if (!routeUtils.checkResourceReadAccess(parentModelResult, req.user)){
  				        response = {
  				        	statusCode : 401,
  				        	body : "The parent resource is private and only the owner may access its data."
  				        }
  				      } 
  			        return innerCallback();
  			 			});
			 		},
					function countResults(innerCallback){
						if (response.statusCode !== 200){
							return innerCallback();
						}

		        query = Model.find();

		        if (ParentModel){
		        	var parentQuery = {};
		        	//ParentModel.collection.name;
		        	if (parentModelFieldName){
		        		parentQuery[parentModelFieldName] = req.params.id;	
		        	} else {
		        		parentQuery["ref.documentId"] = req.params.id;
		        	}
		        	query.where(parentQuery);
		      	}

            
            if (options.restrictByVisibility){
              var restrictedQuery = [];
              if (req.user && req.user.admin){
                // no condition
              }
              if (req.user && req.user._id) {
                restrictedQuery.push({ owner: req.user && req.user._id });
              }
              restrictedQuery.push({ visibility: feBeUtils.VISIBILITY_OPTIONS.PUBLIC });
              console.log(restrictedQuery);
              query.or(restrictedQuery);
            }

            // Now handle the "where". First read the options.defaultWhere
            // into "where", then mix in the request's "where", then
            // add the compiled clause to the query
            if (options.defaultWhere){
              if (typeof options.defaultWhere === 'function'){
                where = options.defaultWhere();
              } else {
                where = options.defaultWhere;
              }
            }

            if (req.query['where']){
              var queryWhere;
              try {
                queryWhere = JSON.parse(req.query['where']);
              } catch(e){
                winston.error(e);
              }

              if (queryWhere){
                where = where || {};

                Object.keys(queryWhere).forEach(function(key) {
                  where[key] = queryWhere[key];
                });
              }
            }

            if (where){
              query.where(where);
            }
			      
			      // TODO : Localize start/end date based on owner's timezone if there's no tz embedded in the date?
			      if (startDate){
			        startDate = moment(startDate).toDate();
			        query.where('date').gte(startDate);
			      }
			      if (endDate){
			        endDate = moment(endDate).toDate();
			        query.where('date').lt(endDate);
			      }


			      query.count(function(err, count){
			      	response.body.count = count;

			      	return innerCallback(err);
			      });
					},

					function getResults(innerCallback){
						// Cast the query back to a find() operation so we can limit/skip/sort/select.
						// TODO: Expecting that this retains the prior .where clauses, but need to verify
        		query.find();

						query.limit(limit);
						
            if (skip){
							query.skip(skip);
						}

						if (sort){
              query.sort(sort);
            } else if (options.defaultSort){
              query.sort(options.defaultSort);
            }
            
  
            // If selecting nested objects, need to tell mongo the correct fields to populate
            if (select){
              select = select.split(',');

              var fieldRoots = {};
              select.forEach(function(field){
                var fieldParts = field.split('.'),
                  fieldRoot = fieldParts[0],
                  fieldNested = fieldParts[1];

                if (!fieldRoots[fieldRoot]){
                  fieldRoots[fieldRoot] = [];
                }
                fieldRoots[fieldRoot].push(fieldNested || '');
              });
              Object.keys(fieldRoots).forEach(function(fieldRoot){
                
                var //fieldParts = field.split('.'),
                  //fieldRoot = selectRoot,
                  fieldNested = fieldRoots[fieldRoot].join(' '),
                  modelPath = Model.schema.path(fieldRoot);
                
                // If fieldRoot is a ref'ed schema type
                if (modelPath.options.ref){
                  // populate fieldRoot, select field[1]
                  console.log('populating', fieldRoot, fieldNested);
                  query.select(fieldRoot);
                  query.populate(fieldRoot, fieldNested);
                }
                else{
                  // select field as one thing (no parts). Standard mongo subdoc selection.
                  query.select(fieldRoot + '.' + fieldNested);
                }
              });
            }            

						query.exec(function(err, queryResults){
							if (err){ return innerCallback(err); }

							response.body.data = queryResults;
							response.body.limit = limit;
							response.body.skip = skip;

							return innerCallback();
						});
					}
				], function seriesEnd(err, result){
					if (err) { return next(err); }

					return routeUtils.sendJSONResponse(res, response.statusCode, response.body);
				});
			}
	 	];
 	},

 
	get: function(Model, ParentModel){
		return function(req, res, next){

		};
	},


 	save : function(Model, ParentModel){
 		return function(req, res, next){

 		};
 	},

 

 	delete: function(Model, ParentModel){
 		return function(req, res, next){

 		}
	},


	/**
	 * Upload a photo and associate it to the referenced document
	 * 
	 * @param {Model=} [options.ref]
	 * @param {string=} [options.parentModelFieldName] - must be defined if parentModel is defined
	 * @param {string=} [options.dateFieldName] - document field to use for start-date/end-date query filters
	 * @param {string=} [options.defaultSort]  "fieldName" for ascending or "-fieldName" for descending
	 * 
	 * @return {[function(req, res, next)]}
	 * 
	 */
	photoPost : function(options){
		var ReferenceModel = options.refModel;

		return function(req, res, next){
	    ReferenceModel.findById(req.params.id)
	    .exec(function (err, refModelResult) {
	      if (err) { return next(err); }
	      if (!refModelResult){ return next(new Error('Invalid reference resource'));}
	      
	      if (!routeUtils.checkResourceModifyAccess(refModelResult, req.user)){
	        return res.send(401, "Inadequate permissions to modify the resource.");
	      }

	      // prepare the req.body to have the props expected of routeUtils.processPhotoUpload
	      req.body.ref = {
	      	collectionName : ReferenceModel.collection.name,
	      	documentId : req.params.id
      	};

	      // Unless otherwise specified, photo should use same visibility settings as reference, with public as default
	      req.body.visibility = req.body.visibility || refModelResult.visibility || feBeUtils.VISIBILITY_OPTIONS.PUBLIC;

	      return routeUtils.processPhotoUpload(req, res, next);
	    });
	  }
	}
};


	
