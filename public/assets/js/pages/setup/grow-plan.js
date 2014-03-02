define([
  'angular',
  'domReady',
  'view-models',
  'moment',
  'fe-be-utils',
  'es5shim',
  'angularRoute',
  'angularUI',
  'angularUIBootstrap',
  'angularUISelect2',
  'bpn',
  'bpn.services.growPlan',
  'selection-overlay',
  'overlay',
  'angularAnimate'
],
  function (angular, domReady, viewModels, moment, feBeUtils) {
    'use strict';

    var growPlanApp = angular.module('bpn.apps.setup.growPlan', ['bpn', 'ngRoute', 'ui', 'ui.bootstrap', 'ui.select2', 'ngAnimate']);

		growPlanApp.config(
			[
				'$locationProvider',
				'$routeProvider',
				function($locationProvider, $routeProvider) {
			    $locationProvider.html5Mode(true);
    			$locationProvider.hashPrefix = '!';

			    $routeProvider
			    	// .when('/', {
			     //    controller: 'bpn.controllers.setup.growPlan.Filter',
			     //    templateUrl: 'filter.html'
			     //  })
			      .when('/', {
			        controller: 'bpn.controllers.setup.growPlan.Browse',
			        templateUrl: 'browse.html'
			      })
			      .when('/customize/:growPlanId', {
			        controller: 'bpn.controllers.setup.growPlan.CustomizeOverview',
			        resolve: {
			          growPlan: ['GrowPlanLoader', function(GrowPlanLoader) {
			            return GrowPlanLoader();
			          }]
			        },
			        templateUrl:'customize-overview.html'
			      })
			      .when('/customize/:growPlanId/details', {
			        controller: 'bpn.controllers.setup.growPlan.CustomizeDetails',
			        templateUrl:'customize-details.html'
			      })
			      .otherwise({redirectTo:'/'}
	      	);
				}
			]
		);


		growPlanApp.factory('sharedDataService', [
      '$rootScope',
      function($rootScope){
			
        var sharedData = {
          selectedGrowPlan : {},
          plants : bpn.plants,
          lightFixtures : bpn.lightFixtures,
          lightBulbs : bpn.lightBulbs,
          growSystems : bpn.growSystems,
          nutrients : bpn.nutrients,
          controls : bpn.controls,
          sensors : bpn.sensors,
          userOwnedDevices : bpn.userOwnedDevices,
          filteredPlantList : angular.copy(bpn.plants),
          selectedPlants : [],
          activeOverlay : { is: undefined },
          selected: {
            plants : {},
            deviceId : undefined
          },
          modalOptions : {
            backdropFade: true,
            dialogFade: true,
            dialogClass : 'overlay'
          },
          growPlanInstance : {
            name : '',
            currentGrowPlanDay : 0
          },
          submit : {
            error : false,
            success : false,
            updateInProgress : false
          },
          growSystemSelectOptions : {
            width: '100%',
            placeholder: "Select",

            formatResult : function(object, container, query){
              var growSystem = angular.element(object.element).scope().growSystem,
              html = '<div style="float:left;width:30%"><img style="width:100%" src="/photos/' + (growSystem.photos[0] || '') + '/200" /></div><div style="float:right;width:65%;">' + growSystem.name + '</div><div style="clear:both;"></div>';
              return html;
            }
          }
        };

        $rootScope.close = function(){
          sharedData.activeOverlay = undefined;
        };

        return sharedData;
		  }
    ]);

		growPlanApp.factory('GrowPlanLoader', 
			[
				'GrowPlanModel', 
				'sharedDataService',
				'$route', 
				'$q',
		    function(GrowPlanModel, sharedDataService, $route, $q) {
		  		return function() {
		  			var selectedGrowPlanId = $route.current.params.growPlanId;

		  			if ((sharedDataService.selectedGrowPlan instanceof GrowPlanModel)
		  					&& 
		  					(sharedDataService.selectedGrowPlan._id.toString() === selectedGrowPlanId)) {
		  				console.log('returning existing selectedGrowPlan');
		  				return sharedDataService.selectedGrowPlan;
		  			} else {
		  				var delay = $q.defer();
			    		console.log('growPlanLoader doin its thing', $route.current.params.growPlanId)
			    		GrowPlanModel.get( { id : $route.current.params.growPlanId }, 
			    			function (growPlan) {
			    				viewModels.initGrowPlanViewModel(growPlan);
			    				sharedDataService.selectedGrowPlan = growPlan;
			      			delay.resolve(sharedDataService.selectedGrowPlan);
			    			}, 
			    			function() {
			      			delay.reject('Unable to fetch grow plan '  + $route.current.params.growPlanId );
			    			}
		    			);
			    		return delay.promise;	
		  			}
		  		};
				}
			]
		);

	

		growPlanApp.controller('bpn.controllers.setup.growPlan.PlantOverlay',
    	[
    		'$scope',
        '$rootScope',
    		'sharedDataService',
    		function($scope, $rootScope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.filteredPlantList;

    			$scope.close = function(){
            $scope.sharedDataService.updatefilteredGrowPlans();
            $rootScope.close();
    			};
    		}
    	]
  	);


		growPlanApp.controller('bpn.controllers.setup.growPlan.FixtureOverlay',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.lightFixtures;
    			
    			$scope.$watch('sharedDataService.selectedGrowPlan.currentVisiblePhase.light.fixture',
    				function(newValue, oldValue){
    					$scope.close();
    				}
  				);

    		}
    	]
  	);


		growPlanApp.controller('bpn.controllers.setup.growPlan.BulbOverlay',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.lightBulbs;
    			
    			$scope.$watch('sharedDataService.selectedGrowPlan.currentVisiblePhase.light.bulb',
    				function(newValue, oldValue){
    					$scope.close();
    				}
  				);

    		}
    	]
  	);

  	
  	growPlanApp.controller('bpn.controllers.setup.growPlan.GrowSystemOverlay',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.growSystems;
    			
    			$scope.$watch('sharedDataService.selectedGrowPlan.currentVisiblePhase.growSystem',
    				function(newValue, oldValue){
    					$scope.close();
    				}
  				);

    		}
    	]
  	);


  	growPlanApp.controller('bpn.controllers.setup.growPlan.NutrientOverlay',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.nutrients;
    			
    			$scope.$watch('sharedDataService.selectedGrowPlan.currentVisiblePhase.nutrientsViewModel',
    				function(newValue, oldValue){
    					$scope.close();
    				}
  				);

    			$scope.toggleItemSelection = function(nutrient, input){
    				if (nutrient.selected) {
    					sharedDataService.selectedGrowPlan.currentVisiblePhase.nutrientsViewModel[nutrient._id] = nutrient;
    				} else {
    					delete sharedDataService.selectedGrowPlan.currentVisiblePhase.nutrientsViewModel[nutrient._id];
    				}

    				$scope.close();
    			};

    		}
    	]
  	);

    growPlanApp.controller('bpn.controllers.setup.growPlan.ActivationOverlay',
      [
        '$scope',
        'sharedDataService',
        function($scope, sharedDataService){
          $scope.sharedDataService = sharedDataService;
          
          // $scope.$watch('sharedDataService.activeOverlay',
          //   function(newValue, oldValue) {
          //     console.log('watched var')
          //     if (newValue == 'ActivationOverlay') {
          //       $scope.open();
          //     }
          //   }
          // );

          // $scope.open = function(){
          //   // var d = $dialog.dialog($scope.sharedDataService.modalOptions);
          //   // d.open().then(function(result){
          //   //   if(result){
          //   //     alert('dialog closed with result: ' + result);
          //   //   }
          //   // });
          //   console.log('open it!');
          // };

        }
      ]
    );


    growPlanApp.controller('bpn.controllers.setup.growPlan.Filter',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    		}
    	]
  	);

    growPlanApp.controller('bpn.controllers.setup.growPlan.Browse',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
          $scope.expandedOption = '';

          $scope.toggleOption = function(optionName){
            if ($scope.expandedOption === optionName){
              $scope.expandedOption = '';
            } else {
              $scope.expandedOption = optionName;
            }

          }
    		}
    	]
  	);

  	growPlanApp.controller('bpn.controllers.setup.growPlan.CustomizeOverview',
    	[
    		'$scope',
    		'growPlan',
    		'sharedDataService',
    		function($scope, growPlan, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
					
          $scope.$watch('sharedDataService.growPlanInstance.name', function(){
            if (!$scope.sharedDataService.growPlanInstance.name){
              $scope.sharedDataService.growPlanInstance.name = "My " + $scope.sharedDataService.selectedGrowPlan.name + " Garden";
            }
          });

          $scope.updateSelectedGrowPlanPlants(true);
        }
    	]
  	);

  	growPlanApp.controller('bpn.controllers.setup.growPlan.CustomizeDetails',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;

    			$scope.init = function(){
    				//$scope.expectedGrowPlanDuration = $scope.sharedDataService.selectedGrowPlan.phases.reduce(function (prev, cur) { return prev.expectedNumberOfDays + cur.expectedNumberOfDays;}, 0);
  					$scope.setExpectedGrowPlanDuration();
          	//$scope.setCurrentPhaseTab(0);

            //auto-select the first device that is not already linked to a grow plan instance
          	if ($scope.sharedDataService.userOwnedDevices.length){
              $scope.sharedDataService.userOwnedDevices.some(function(device){
                if(!device.activeGrowPlanInstance){
                  $scope.sharedDataService.selected.deviceId = device._id;
                  return true;
                }
              });
          	}
  				};

  				$scope.toggleDevice = function(device){
            $scope.sharedDataService.selected.deviceId = device._id;
  				};

    			$scope.setExpectedGrowPlanDuration = function () {
            var currentExpectedPlanDuration = 0;
            $scope.sharedDataService.selectedGrowPlan.phases.forEach(function (phase) {
              currentExpectedPlanDuration += phase.expectedNumberOfDays;
            });
            $scope.expectedGrowPlanDuration = currentExpectedPlanDuration;
          };

          $scope.setCurrentVisiblePhase = function (phase) {
            $scope.sharedDataService.selectedGrowPlan.currentVisiblePhase = phase;
          };

          $scope.setCurrentPhaseSectionTab = function (index) {
            $scope.selected.selectedGrowPlanPhaseSection = index;
          };

          $scope.addPhase = function () {
            var existingPhaseLength = $scope.sharedDataService.selectedGrowPlan.phases.length,
              phase = {
                _id:existingPhaseLength.toString() + '-' + (Date.now().toString()), // this is just to make it unique in the UI. The server will detect that this is not an ObjectId and create a new IdealRange
                actionViewModels:[],
                idealRanges:[]
              };
            $scope.sharedDataService.selectedGrowPlan.phases.push(phase);
            $scope.setCurrentVisiblePhase(phase);
          };

          $scope.removePhase = function (index) {
            $scope.sharedDataService.selectedGrowPlan.phases.splice(index, 1);
            $scope.setCurrentVisiblePhase($scope.sharedDataService.selectedGrowPlan.phases[0]);
          };

          $scope.addIdealRange = function (phase) {
            var newIdealRange = {
                _id:phase.idealRanges.length.toString() + '-' + (Date.now().toString()), // this is just to make it unique in the UI. The server will detect that this is not an ObjectId and create a new IdealRange
                valueRange:{
                  min:0,
                  max:1
                }
              };
            // Unshift to make it show up first
            phase.idealRanges.unshift(newIdealRange);
          };

          $scope.addAction = function (phase) {
            var newAction = {
                _id:phase.actions.length.toString() + '-' + (Date.now().toString()), // this is just to make it unique in the UI. The server will detect that this is not an ObjectId and create a new Action
                cycle: { offset: { duration: 0, durationType: null } }
              };
            // Unshift to make it show up first
            phase.actions.unshift(newAction);
            phase.actionViewModels.unshift(viewModels.initActionViewModel(newAction));
          };

          $scope.removeIdealRange = function (phaseIndex, idealRangeIndex) {
            $scope.sharedDataService.selectedGrowPlan.currentVisiblePhase.idealRanges.splice(idealRangeIndex, 1);
          };

          $scope.removeAction = function (phaseIndex, actionIndex) {
            $scope.sharedDataService.selectedGrowPlan.currentVisiblePhase.actions.splice(actionIndex, 1);
            $scope.sharedDataService.selectedGrowPlan.currentVisiblePhase.actionViewModels.splice(actionIndex, 1)
          };

    			$scope.init();
        }
    	]
  	);


    growPlanApp.controller('bpn.controllers.setup.growPlan.Main',
      [
        '$scope',
        '$filter',
        'GrowPlanModel',
        'sharedDataService',
        '$timeout',
        function ($scope, $filter, GrowPlanModel, sharedDataService, $timeout) {
          $scope.sharedDataService = sharedDataService;
          
          //$scope.lights = bpn.lights;
          //$scope.lightFixtures = bpn.lightFixtures;
          //$scope.lightBulbs = bpn.lightBulbs;
          //$scope.nutrients = bpn.nutrients;
          $scope.controls = bpn.controls;
          $scope.sensors = bpn.sensors;
          $scope.userOwnedDevices = bpn.userOwnedDevices;
          $scope.plantSelections = {};
          $scope.plantQuery = '';
          //$scope.growSystems = bpn.growSystems;
          //$scope.selectedGrowPlan = {}; 
          // $scope.selectedGrowSystem = undefined;
          $scope.currentGrowPlanDay = 0;
          //$scope.growPlans = bpn.growPlans;
          $scope.filteredGrowPlanList = [];//angular.copy($scope.growPlans);
          $scope.timesOfDayList = feBeUtils.generateTimesOfDayArray();
          $scope.actionDurationTypeOptions = feBeUtils.DURATION_TYPES;
          $scope.actionWithNoAccessoryDurationTypeOptions = ['days', 'weeks', 'months'];
          $scope.overlayItems = []; //used by Overlay Ctrl
          $scope.overlayMetaData = {}; //pass additional config to overlay
          $scope.overlayStates = { //manage open state
            //'plant':false,
            'fixture':false,
            'growSystemOverlay':false,
            'growMediumOverlay':false,
            'nutrient':false
          }
          $scope.growPlanPhaseSectionUITabs = ['Grow System', 'Light', 'Sensor Ranges', 'Actions'];
          // $scope.UI.suggestions = {
          //     lightFixtures: bpn.utils.suggestions.lightFixtures,
          //     lightBulbs: bpn.utils.suggestions.lightTypes
          // }

          if ($scope.userOwnedDevices.length > 0) {
            $scope.growPlanPhaseSectionUITabs.push('Device')
          }

          //Wrapping our ng-model vars {}
          //This is necessary so ng-change always fires, due to: https://github.com/angular/angular.js/issues/1100
          $scope.selected = {
            // growSystem: undefined,
            growPlan : undefined,
            //plant:{},
            selectedGrowPlanPhase:0,
            selectedGrowPlanPhaseSection:0,
            selectedDevice:undefined,
            lightFixture:undefined,
            lightBulb:undefined,
            growMedium:undefined,
            nutrient:{}
          };


          $scope.selectedSensors = function () {
            var list = [];
            angular.forEach($scope.sensors, function (sensor) {
              list.push(sensor);
            });
            return list;
          };

          $scope.updateSelectedGrowSystem = function () {
            // $scope.selectedGrowSystem = $filter('filter')($scope.growSystems, { _id: $scope.selected.growSystem })[0];
            // if ($scope.sharedDataService.selectedPlants && $scope.sharedDataService.selectedPlants.length) {
              // $scope.updatefilteredGrowPlans();
            // }
          };

          $scope.addPlant = function (obj) {
            var newPlant = {_id:obj.query || $scope.query, name:obj.query || $scope.query };
            $scope.sharedDataService.filteredPlantList.push(newPlant);
            $scope.sharedDataService.selectedPlants.push(newPlant);
            $scope.sharedDataService.selected.plants[newPlant._id] = true;
            $scope.query = "";
            $scope.$$childHead.query = "";
            $scope.$$childHead.search();
            obj.query = "";
            $scope.close();
            
          };

          // $scope.updateSelectedPlants = function(){
          //     $scope.sharedDataService.selectedPlants = [];
          //     for (var i = $scope.sharedDataService.plants.length; i--;) {
          //         Object.keys($scope.sharedDataService.selected.plants).forEach(function(_id) {
          //             if ($scope.sharedDataService.selected.plants[_id] && $scope.sharedDataService.plants[i]._id == _id) {
          //                 $scope.sharedDataService.selectedPlants.push($scope.sharedDataService.plants[i]);
          //             }
          //         });
          //     }

          //     $scope.updateSelectedGrowPlanPlants();

          //     if($scope.selectedGrowSystem){
          //         $scope.updatefilteredGrowPlans();
          //     }
          // };

          $scope.$watch('sharedDataService.selectedGrowSystem', function () {
            // Re-enable this once we implement grow system filtering
            // For some reason though, it's firing on page initialization. Haven't traced down what's setting selectedGrowSystem on init
            //$scope.updatefilteredGrowPlans();
          });

          $scope.$watch('sharedDataService.selected.plants', function(){
            $scope.sharedDataService.selectedPlants= [];
            for (var i = $scope.sharedDataService.plants.length; i--;) {
              if ($scope.sharedDataService.selected.plants[$scope.sharedDataService.plants[i]._id]){
                $scope.sharedDataService.selectedPlants.push($scope.sharedDataService.plants[i]);
              }  
            }

            if($scope.sharedDataService.selectedGrowPlan){
              $scope.sharedDataService.selectedGrowPlan.plants = $scope.sharedDataService.selectedPlants;
            }

            $scope.updatefilteredGrowPlans();  

            $scope.close();
          }, true);

          $scope.updateSelected = {
            /*
            'plants':function () {
              $scope.sharedDataService.selectedPlants = [];
              for (var i = $scope.sharedDataService.plants.length; i--;) {
                Object.keys($scope.sharedDataService.selected.plants).forEach(function (_id) {
                  if ($scope.sharedDataService.selected.plants[_id] && $scope.sharedDataService.plants[i]._id == _id) {
                    $scope.sharedDataService.selectedPlants.push($scope.sharedDataService.plants[i]);
                  }

                  
                });
              }

              // if($scope.sharedDataService.selectedGrowPlan){
              //   if($scope.sharedDataService.selectedGrowPlan.plants){
              //     $scope.sharedDataService.selectedGrowPlan.plants.push($scope.sharedDataService.plants[i]);
              //   }else{
              //     $scope.sharedDataService.selectedGrowPlan.plants = [$scope.sharedDataService.plants[i]];
              //   }
              // }

              $scope.updateSelectedGrowPlanPlants();

              if ($scope.selectedGrowSystem) {
                $scope.updatefilteredGrowPlans();
              }
            },
            */

            'lightFixture':function (data, phase) {
              $scope.sharedDataService.selectedGrowPlan.phases[$scope.selected.selectedGrowPlanPhaseSection].light.fixture = data.item;
            },

            'lightBulb':function (data, phase) {
              $scope.sharedDataService.selectedGrowPlan.phases[$scope.selected.selectedGrowPlanPhaseSection].light.bulb = data.item;
            },

            'growSystem':function (data, phase) {
              $scope.sharedDataService.selectedGrowPlan.phases[$scope.selected.selectedGrowPlanPhaseSection].growSystem = data.item;
            },

            'growMedium':function (data, phase) {
              console.log('growMedium')
            },

            'nutrients':function (data, phase) {
              var nutrients = [];
              for (var i = $scope.nutrients.length; i--;) {
                Object.keys($scope.selected.nutrient[phase]).forEach(function (_id) {
                  if ($scope.selected.nutrient[phase][_id] && $scope.nutrients[i]._id == _id) {
                    nutrients.push($scope.nutrients[i]);
                  }
                });
              }
              $scope.sharedDataService.selectedGrowPlan.phases[$scope.selected.selectedGrowPlanPhaseSection].nutrients = nutrients;
            }

          };

          $scope.updateSelectedGrowPlanPlants = function (initial) {
            //add any selected plants that arent in grow plan, only once when grow plan requested
            if (initial) {
              $scope.sharedDataService.selectedPlants.forEach(function (plant, index) {
                if (0 === $.grep($scope.sharedDataService.selectedGrowPlan.plants,function (gpPlant) { return gpPlant.name == plant.name; }).length) {
                  //only add if not already in grow plan's plant list
                  $scope.sharedDataService.selectedGrowPlan.plants.push(plant);
                }
              });
              //also set any grow plan plants selected
              $scope.sharedDataService.selectedGrowPlan.plants.forEach(function (plant, index) {
                $scope.sharedDataService.selected.plants[plant._id] = true;
              });
            } else if (typeof $scope.selectedGrowPlan != 'undefined') {
              //else just add selected to grow plan plant list if its already defined (meaning we already requested it)
              $scope.sharedDataService.selectedGrowPlan.plants = $scope.sharedDataService.selectedPlants;
              $scope.sharedDataService.selectedGrowPlan.plants.sort(function (a, b) { return a.name < b.name; });
            }
          };        

          $scope.updatefilteredGrowPlans = function () {
            console.log('$scope.updatefilteredGrowPlans');
            var selectedPlantIds = $scope.sharedDataService.selectedPlants.map(function (plant) { return plant._id }),
              growPlanDefault = new GrowPlanModel(bpn.growPlanDefault);

            // TODO : show/hide a loading indicator here

            //hit API with params to filter grow plans
            $scope.filteredGrowPlanList = GrowPlanModel.query({
              plants:selectedPlantIds,
              growSystem:$scope.sharedDataService.selectedGrowSystem
            }, function () {
              //add default to end of filtered grow plan array
              $scope.filteredGrowPlanList.splice($scope.filteredGrowPlanList.length, 0, growPlanDefault);
            });
          };

          $scope.sharedDataService.updatefilteredGrowPlans = $scope.updatefilteredGrowPlans;

          $scope.submit = function (e) {

            if ($scope.sharedDataService.selectedGrowPlan) {
              var dataToSubmit = {
                submittedGrowPlan : viewModels.compileGrowPlanViewModelToServerModel($scope.sharedDataService.selectedGrowPlan),
                growPlanInstance : $scope.sharedDataService.growPlanInstance,
                deviceId : $scope.sharedDataService.selected.deviceId
              };

              $scope.sharedDataService.submit.updateInProgress = true;
              console.log(dataToSubmit);

              $.ajax({
                url: '/setup/grow-plan',
                type: 'POST',
                contentType: 'application/json; charset=utf-8',
                dataType: 'json',
                data: JSON.stringify(dataToSubmit),
                processData: false,
                success: function(data) {
                  console.log(data);
                  $scope.sharedDataService.createdGrowPlanInstanceId = data.createdGrowPlanInstanceId
                  $scope.sharedDataService.submit.success = true;
                },
                error: function(jqXHR, textStatus, error) {
                  console.log('error', jqXHR, textStatus, error);
                  $scope.sharedDataService.submit.error = true;
                  $scope.sharedDataService.submit.success = false;
                },
                complete: function() {
                  $scope.$apply(function() {
                    $scope.sharedDataService.activeOverlay = { is: 'ActivationOverlay' };
                  });
                }
              });
            }
          };

          $scope.init = function(){
            // updatefilteredGrowPlans is already being called by the selectedPlants watcher during init
            //$scope.updatefilteredGrowPlans();
          };

          $scope.init();
        }
      ]
    );
  


    growPlanApp.filter('keysToCSV', function(){
      return function(input){
        return Object.keys(input).join(',');
      };
    });
  


  	domReady(function () {
      angular.bootstrap(document, ['bpn.apps.setup.growPlan']);
    });

    return growPlanApp;
  }
);
