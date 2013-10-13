var ControlModel = require('../models/control').model,
GrowPlanModel = require('../models/growPlan').growPlan.model,
GrowPlanInstanceModel = require('../models/growPlanInstance').model,
SensorModel = require('../models/sensor').model,
SensorLogModel = require('../models/sensorLog').model,
ControlModel = require('../models/control').model,
Action = require('../models/action'),
ActionModel = Action.model,
DeviceModel = require('../models/device').model,
NotificationModel = require('../models/notification').model,
PhotoModel = require('../models/photo').model,
ModelUtils = require('../models/utils'),
routeUtils = require('./route-utils'),
winston = require('winston'),
async = require('async'),
moment = require('moment'); 

module.exports = function(app){
	
	/**
	 * List all public growPlanInstances
	 */
	app.get('/gardens', 
		routeUtils.middleware.ensureSecure,
		routeUtils.middleware.ensureLoggedIn,
		function (req, res, next) {
			var locals = {
				userGrowPlanInstances : [],
				communityGrowPlanInstances : [],
				className: "gardens app-page single-page",
    			pageType: "app-page"
			};

			GrowPlanInstanceModel
			.find({ 'users': req.user })
			.sort('-startDate')
			.exec(function(err, growPlanInstanceResults){
				if (err) { return next(err); }
				locals.userGrowPlanInstances = growPlanInstanceResults.map(function(gpi) { return gpi.toObject(); })
				locals.userGrowPlanInstances.forEach(function(gpi){
					gpi.friendlyStartDate = '';
					if (gpi.startDate){
						gpi.friendlyStartDate = moment(gpi.startDate).calendar();
					}
					
				})
				res.render('gardens', locals);
			});
		}
	);

	
	
	/**
	 * Show a "dashboard" view of a growPlanInstance
	 * TODO : Hide/show elements in the dashboard.jade depending on
	 * whether the req.user is the owner/permissioned member or not
	 */
	app.get('/gardens/:growPlanInstanceId',
		routeUtils.middleware.ensureSecure,
		routeUtils.middleware.ensureLoggedIn,
		function (req, res, next) {
			var locals = {
				title : 'Bitponics - Dashboard',
				user : req.user,
				growPlanInstance : undefined,
				sensors : undefined,
				controls : undefined,
				sensorDisplayOrder : ['full','hum','air','wl','ph','ec','water','tds','sal','lux','vis','ir'],
				className: "app-page dashboard",
				pageType: "app-page"
			};

			// First, verify that the user can see this
			GrowPlanInstanceModel.findById(req.params.growPlanInstanceId)
			.select('owner users visibility')
			.exec(function(err, growPlanInstanceResultToVerify){
				if (err) { return next(err); }
				if (!growPlanInstanceResultToVerify){ return next(new Error('Invalid grow plan instance id'));}

				if (!routeUtils.checkResourceReadAccess(growPlanInstanceResultToVerify, req.user)){
          return res.send(401, "This garden is private. You must be the owner to view it.");
      	}

      	locals.userCanModify = routeUtils.checkResourceModifyAccess(growPlanInstanceResultToVerify, req.user);

				async.parallel(
				[
					function getSensors(innerCallback){
						SensorModel.find({visible : true}).exec(innerCallback);
					},
					function getControls(innerCallback){
						ControlModel.find()
						.populate('onAction')
						.populate('offAction')
						.exec(innerCallback);
					},
					function getGpi(innerCallback){
						GrowPlanInstanceModel
						.findById(req.params.growPlanInstanceId)
						.exec(function(err, growPlanInstanceResult){
							if (err) { return innerCallback(err); }

							growPlanInstanceResult = growPlanInstanceResult.toObject();

							async.parallel(
							[
								function getDevice(innerInnerCallback){
									if (!growPlanInstanceResult.device){
										return innerInnerCallback();
									}

									DeviceModel.findById(growPlanInstanceResult.device)
									.populate('status.actions')
									.populate('status.activeActions')
									.exec(function(err, deviceResult){
										if (err) { return innerInnerCallback(err); }
										
                    deviceResult.getStatusResponse({}, function(err, deviceStatusResponse){
                      if (err) { return innerInnerCallback(err); }

                      var device = deviceResult.toObject();
                      device.status.outputValues = deviceStatusResponse.states;
                      growPlanInstanceResult.device = device;
                      return innerInnerCallback();
                    });
									});
								},
								function getGrowPlan(innerInnerCallback){
									ModelUtils.getFullyPopulatedGrowPlan({ _id: growPlanInstanceResult.growPlan }, function(err, growPlanResult){
										if (err) { return innerInnerCallback(err); }
										
										growPlanInstanceResult.growPlan = growPlanResult[0];
										return innerInnerCallback();
									});		
								}
							],
							function gpiParallelFinal(err){
								return innerCallback(err, growPlanInstanceResult);
							});
						});
					},
					function getNotifications(innerCallback){
						NotificationModel.find({
		          gpi : req.params.growPlanInstanceId,
		          tts : { $ne : null }
		        })
		        .sort({ 'tts' : -1 })
		        .limit(10)
		        .exec(function(err, notificationResults){
		        	if (err) { return innerCallback(err); }
		        	var notificationsWithSummaries = [];
		        	async.each(notificationResults, 
		        		//TODO: make this sync
		        		function notificationIterator(notification, iteratorCallback){
			        		var notificationObject = notification.toObject();
			        		notification.getDisplay(
			        			{ 
			        				secureAppUrl : app.config.secureAppUrl,
			        				displayType : 'summary'
			        			},
			        			function (err, notificationDisplay){
			        				if (err) { 
                        console.trace(); 
                        winston.error(err);
                        return iteratorCallback(); 
                      }
                      notificationObject.displays = {
					        			summary : notificationDisplay
					        		};
					        		notificationsWithSummaries.push(notificationObject);
			        				return iteratorCallback();
			        			}
		        			);
		        		},
		        		function notificationLoopEnd(err){
		        			innerCallback(err, notificationsWithSummaries);
		        		}
	        		);
		        });
		      },
		      function getPhotos(innerCallback){
		      	PhotoModel.find({
		      		gpi : req.params.growPlanInstanceId,
		      	})
		      	.sort('-date')
		      	.limit(15)
		      	.exec(innerCallback);
		      }
				],
				function(err, results){
					if (err) { return next(err); }

          locals.controls = results[1];
          locals.growPlanInstance = results[2];
          locals.notifications = results[3] || [];
          locals.photos = results[4] || [];


					var sortedSensors = [];
					results[0].forEach(function(sensor){
						sortedSensors[locals.sensorDisplayOrder.indexOf(sensor.code)] = sensor;
					});
					sortedSensors = sortedSensors.filter(function(sensor){ 
            // if the garden has a device, only sohw the senors that the device supports
            if (locals.growPlanInstance.device){
              return (locals.growPlanInstance.device.sensors.indexOf(sensor.code) >= 0);
            } else {
              return sensor;  
            }
          });

					locals.sensors = sortedSensors;
					

					res.render('gardens/dashboard', locals);
				});
			});
		}
	);



	app.get('/gardens/:growPlanInstanceId/details',
		routeUtils.middleware.ensureSecure,
		routeUtils.middleware.ensureLoggedIn,
		function (req, res, next) {
			var locals = {
				title : 'Bitponics - Dashboard',
				user : req.user,
				garden : undefined,
				className: "app-page garden-details",
				pageType: "app-page"
			};

			// First, verify that the user can see this
			GrowPlanInstanceModel.findById(req.params.growPlanInstanceId)
			.exec(function(err, growPlanInstanceResult){
				if (err) { return next(err); }
				if (!growPlanInstanceResult){ return next(new Error('Invalid grow plan instance id'));}

				if (!routeUtils.checkResourceReadAccess(growPlanInstanceResult, req.user)){
          return res.send(401, "This garden is private. You must be the owner to view it.");
      	}

      	locals.userCanModify = routeUtils.checkResourceModifyAccess(growPlanInstanceResult, req.user);

      	locals.garden = growPlanInstanceResult.toObject();

				res.render('gardens/details', locals);
			});
		}
	);


	/**
	 * 
	 */
	app.get('/gardens/:growPlanInstanceId/sensor-logs', 
		routeUtils.middleware.ensureSecure,
		routeUtils.middleware.ensureLoggedIn,
		function (req, res, next) {
			var locals = {
	    	title: "Bitponics | ",
	    	className: "garden-sensor-logs"
	    };
		  
		  GrowPlanInstanceModel
			.findById(req.params.growPlanInstanceId)
			.populate('growPlan')
			.exec(function(err, growPlanInstanceResult){
				if (!routeUtils.checkResourceReadAccess(growPlanInstanceResult, req.user)){
          return res.send(401, "This garden is private. You must be the owner to view it.");
      	}

      	locals.growPlanInstance = growPlanInstanceResult;


      	async.parallel(
					[
						function parallel1(innerCallback){
							SensorModel.find({visible : true}).exec(innerCallback);
						},
						function parallel2(innerCallback){
							ControlModel.find().exec(innerCallback);
						},
						function parallel3(innerCallback){
							SensorLogModel
							.find({ gpi : req.params.growPlanInstanceId})
							.select('ts l')
							.exec(innerCallback);
						}
					],
					function(err, results){
						if (err) { return next(err); }
						locals.sensors = results[0];
						locals.controls = results[1];
						locals.sensorLogs = results[2];

						res.render('gardens/sensor-logs', locals);
					}
		    );
			});
		}
	);
};