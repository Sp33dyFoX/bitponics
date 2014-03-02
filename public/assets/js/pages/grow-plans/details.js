/**
 * Main file for /grow-plans/:id
 *
 * Depends on following globals:
 * - bpn
 */
require([
  'angular',
  'domReady',
  'view-models',
  'moment',
  'fe-be-utils',
  'es5shim',
  'angularRoute',
  'angularUI',
  'angularUIBootstrap',
  'bpn',
  'selection-overlay',
  'overlay',
  'bpn.directives.graphs',
  'bpn.services.growPlan',
  'bpn.services.plant',
  'angularDialog'
],
  function (angular, domReady, viewModels, moment, feBeUtils) {
    'use strict';

    var growPlanApp = angular.module('bpn.apps.growPlan', ['bpn', 'ngRoute', 'ui', 'ui.bootstrap']);

		growPlanApp.config(
			[
				'$locationProvider',
				'$routeProvider',
				function($locationProvider, $routeProvider) {
			    $locationProvider.html5Mode(true);
    			$locationProvider.hashPrefix = '!';

			    $routeProvider
			      .when('/:growPlanId', {
			        controller: 'bpn.controllers.growPlan.CustomizeOverview',
			        resolve: {
			          growPlan: ['GrowPlanLoader', function(GrowPlanLoader) {
                  return GrowPlanLoader();
			          }]
			        },
			        templateUrl:'customize-overview.html'
			      })
			      .otherwise({redirectTo:'/'});
				}
			]
		);


		growPlanApp.factory('sharedDataService', 
      [
        '$route',
        '$location',
        '$rootScope',
        function($route, $location, $rootScope){
    			var sharedData = {
    				selectedGrowPlan : {},
            selectedPhaseIndex : 0, //default to first
    				plants : bpn.plants,
    				lightFixtures : bpn.lightFixtures,
            lightBulbs : bpn.lightBulbs,
    				lights : bpn.lights,
    				growSystems : bpn.growSystems,
    				nutrients : bpn.nutrients,
    				controls : bpn.controls,
            sensors : bpn.sensors,
            userOwnedDevices : bpn.userOwnedDevices,
    				filteredPlantList : angular.copy(bpn.plants),
    				selectedPlants : [],
    				activeOverlay : undefined,
    				selected: {
    					plants : {},
    					deviceId : undefined
    				},
    				modalOptions : {
              backdrop: true,
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
            }
    			};

          
          // Transform the data into viewModel-friendly formats
          sharedData.controlsById = {};
          sharedData.controls.forEach(function (control) {
            viewModels.initControlViewModel(control);
            sharedData.controlsById[control._id] = control;
          });


          sharedData.pageMode = ($location.search()['setup'] ? 'setup' : 'default');
          sharedData.additionalPlants = ($location.search()['plants'] ? $location.search()['plants'].split(',') : undefined);

          console.log('sharedData.additionalPlants', sharedData.additionalPlants);

          $rootScope.close = function(){
            sharedData.activeOverlay = undefined;
          };


          return sharedData;
    		}
      ]
    );

		growPlanApp.factory('GrowPlanLoader', 
			[
				'GrowPlanModel', 
				'sharedDataService',
				'$route', 
				'$q',
        '$timeout',
		    function(GrowPlanModel, sharedDataService, $route, $q, $timeout) {
		  		return function() {
            var selectedGrowPlanId = $route.current.params.growPlanId;
            if ((sharedDataService.selectedGrowPlan instanceof GrowPlanModel)
		  					&& 
		  					(sharedDataService.selectedGrowPlan._id.toString() === selectedGrowPlanId)) {
		  				return sharedDataService.selectedGrowPlan;
		  			} else {
              var delay = $q.defer();
              console.log('$route.current.params.growPlanId', $route.current.params.growPlanId );
			    		if ($route.current.params.growPlanId === 'new'){
                
                $timeout(function(){
                  //debugger;
                  sharedDataService.selectedGrowPlan = new GrowPlanModel(viewModels.initGrowPlanViewModel({
                    _id : "new",
                    name : "Name Your Grow Plan",
                    plants : [],
                    phases : [
                      {
                        _id : "",
                        name : "First",
                        idealRanges : [],
                        actions : [],
                        phaseEndActions : [],
                        nutrients : []
                      }
                    ]
                  }, bpn.sensors));
                  delay.resolve(sharedDataService.selectedGrowPlan);
                });
              } else {
                GrowPlanModel.get( { id : $route.current.params.growPlanId }, 
                  function (growPlan) {
                    sharedDataService.selectedGrowPlan = growPlan;
                    delay.resolve(sharedDataService.selectedGrowPlan);
                  }, 
                  function() {
                    delay.reject('Unable to fetch grow plan '  + $route.current.params.growPlanId );
                  }
                );  
              }

              
			    		return delay.promise;	
		  			}
		  		};
				}
			]
		);


    growPlanApp.factory('PlantLoader', 
      [
        'PlantModel', 
        'sharedDataService',
        '$route', 
        '$q',
        function(PlantModel, sharedDataService, $route, $q) {
          return function() {
            if (!(sharedDataService.additionalPlants && sharedDataService.additionalPlants.length)){
              return sharedDataService.selectedGrowPlan.plants;
            }

            var filteredPlants = angular.copy(sharedDataService.additionalPlants);

            console.log('sharedDataService.additionalPlants', sharedDataService.additionalPlants);
            console.log('sharedDataService.selectedGrowPlan.plants before', sharedDataService.selectedGrowPlan.plants);
            console.log('sharedDataService.selectedGrowPlan.plantsViewModel before', sharedDataService.selectedGrowPlan.plantsViewModel);

            if (!sharedDataService.selectedGrowPlan || !sharedDataService.selectedGrowPlan.plants || !sharedDataService.selectedGrowPlan.plants.length){
            } else {
              filteredPlants = filteredPlants.filter(function(additionalPlantId){
                if (sharedDataService.selectedGrowPlan.plants.some(function(plant){ return sharedplant._id === additionalPlantId; })){
                  return true;
                }
                return false;
              });  
            }

            console.log('filteredPlants', filteredPlants);
            
            var delay = $q.defer();
              PlantModel.query( { where: JSON.stringify({ "_id" : { "$in" : filteredPlants } })}, 
                function (additionalPlantsResult) {
                  if (additionalPlantsResult.count){
                    additionalPlantsResult.data.forEach(function(plant){
                      sharedDataService.selected.plants[plant._id] = true;
                    });
                  }
                  delay.resolve(additionalPlantsResult);
                }, 
                function() {
                  delay.reject('Unable to fetch additional plants');
                }
              );

            return delay.promise;
          };
        }
      ]
    );


    
    growPlanApp.controller('bpn.controllers.growPlan.PhasesGraph',
      [
        '$scope',
        'sharedDataService',
        function($scope, sharedDataService){

        }
      ]
    );

    growPlanApp.controller('bpn.controllers.growPlan.SensorOverlay',
      [
        '$scope',
        'sharedDataService',
        function($scope, sharedDataService){
          $scope.sharedDataService = sharedDataService;
        }
      ]
    );

    growPlanApp.controller('bpn.controllers.growPlan.ActionOverlay',
      [
        '$scope',
        'sharedDataService',
        '$rootScope',
        '$timeout',
        function($scope, sharedDataService, $rootScope, $timeout){
          $scope.sharedDataService = sharedDataService;

          $scope.removeAction = function(action){
            
            $scope.close();

            // Don't know why, but we have to defer the action deletion with a timeout, otherwise the overlay stays open
            $timeout(function(){
              if (action.control){
                delete sharedDataService.selectedGrowPlan.focusedPhase.actionViewModelsByControl[action.control];
              } else {
                var index = sharedDataService.selectedGrowPlan.focusedPhase.actionViewModelsNoControl.indexOf(action);
                sharedDataService.selectedGrowPlan.focusedPhase.actionViewModelsNoControl.splice(index, 1);
              }  
            }, 10);
          };
        }
      ]
    );

		growPlanApp.controller('bpn.controllers.growPlan.PlantOverlay',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.filteredPlantList;
    			
    		}
    	]
  	);


		growPlanApp.controller('bpn.controllers.growPlan.FixtureOverlay',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.lightFixtures;
    			
    		}
    	]
  	);


		growPlanApp.controller('bpn.controllers.growPlan.BulbOverlay',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.lightBulbs;
    			
    		}
    	]
  	);

  	
  	growPlanApp.controller('bpn.controllers.growPlan.GrowSystemOverlay',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.growSystems;
    			
    		}
    	]
  	);


  	growPlanApp.controller('bpn.controllers.growPlan.NutrientOverlay',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.nutrients;
    			

    			$scope.toggleItemSelection = function(nutrient, input){
    				if (nutrient.selected) {
    					sharedDataService.selectedGrowPlan.focusedPhase.nutrientsViewModel[nutrient._id] = nutrient;
    				} else {
    					delete sharedDataService.selectedGrowPlan.focusedPhase.nutrientsViewModel[nutrient._id];
    				}

    				$scope.close();
    			};
    		}
    	]
  	);

    growPlanApp.controller('bpn.controllers.growPlan.ActivationOverlay',
      [
        '$scope',
        'sharedDataService',
        function($scope, sharedDataService){
          $scope.sharedDataService = sharedDataService;
        }
      ]
    );


    growPlanApp.controller('bpn.controllers.growPlan.SaveOverlay',
      [
        '$scope',
        '$window',
        'sharedDataService',
        function($scope, $window, sharedDataService){
          $scope.sharedDataService = sharedDataService;
    
          $scope.loadGrowPlanPage = function(){
            $window.location.href = '/grow-plans/' + $scope.sharedDataService.selectedGrowPlan._id;
          }
        }
      ]
    );


    growPlanApp.controller('bpn.controllers.growPlan.Filter',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    		}
    	]
  	);

    growPlanApp.controller('bpn.controllers.growPlan.Browse',
    	[
    		'$scope',
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    		}
    	]
  	);

  	growPlanApp.controller('bpn.controllers.growPlan.CustomizeOverview',
    	[
    		'$scope',
    		'growPlan',
    		'sharedDataService',
    		function($scope, growPlan, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
          $scope.idealRanges = [];
					
          $scope.$watch('sharedDataService.selectedPhaseIndex', function(newValue){
            $scope.sharedDataService.selectedGrowPlan.phases[$scope.sharedDataService.selectedPhaseIndex].idealRanges.forEach(function(idealRange) {
              $scope.idealRanges[idealRange.sCode] = idealRange;
            });
          });

          // $scope.applyNameChange = function () {
          //   console.log(this);
          // };

          $scope.updateSelectedGrowPlanPlants(true);

    			$scope.init = function(){
    				//$scope.expectedGrowPlanDuration = $scope.sharedDataService.selectedGrowPlan.phases.reduce(function (prev, cur) { return prev.expectedNumberOfDays + cur.expectedNumberOfDays;}, 0);
  					$scope.setExpectedGrowPlanDuration();
          	//$scope.setCurrentPhaseTab(0);

          	if ($scope.sharedDataService.userOwnedDevices.length === 1){
          		$scope.sharedDataService.selected.device = $scope.sharedDataService.userOwnedDevices[0];
          	}
  				};

  				$scope.toggleDevice = function(device){
  					console.log(device);
  					console.log('selected', $scope.sharedDataService.selected.deviceId);
  				};

    			$scope.setExpectedGrowPlanDuration = function () {
            var currentExpectedPlanDuration = 0;
            $scope.sharedDataService.selectedGrowPlan.phases.forEach(function (phase) {
              currentExpectedPlanDuration += phase.expectedNumberOfDays;
            });
            $scope.expectedGrowPlanDuration = currentExpectedPlanDuration;
          };

          $scope.addPhase = function () {
            var existingPhaseLength = $scope.sharedDataService.selectedGrowPlan.phases.length,
              phase = {
                _id:existingPhaseLength.toString() + '-' + (Date.now().toString()), // this is just to make it unique in the UI. The server will detect that this is not an ObjectId and create a new IdealRange
                actionViewModels:[],
                idealRanges:[]
              };
            $scope.sharedDataService.selectedGrowPlan.phases.push(phase);
          };

          $scope.removePhase = function (index) {
            if($scope.sharedDataService.selectedGrowPlan.phases.length > 1) {
              $scope.sharedDataService.selectedGrowPlan.phases.splice(index, 1);
              $scope.sharedDataService.selectedPhaseIndex = 0;
            }
          };

          $scope.addIdealRange = function (index) {
            var phase = $scope.sharedDataService.selectedGrowPlan.phases[index],
                newIdealRange = {
                _id:phase.idealRanges.length.toString() + '-' + (Date.now().toString()), // this is just to make it unique in the UI. The server will detect that this is not an ObjectId and create a new IdealRange
                valueRange:{
                  min:0,
                  max:1
                }
              };
            // Unshift to make it show up first
            phase.idealRanges.unshift(newIdealRange);
          };

          $scope.addAction = function (index) {
            var phase = $scope.sharedDataService.selectedGrowPlan.phases[index],
                newAction = {
                  _id:phase.actions.length.toString() + '-' + (Date.now().toString()), // this is just to make it unique in the UI. The server will detect that this is not an ObjectId and create a new Action
                  cycle: { offset: { duration: 0, durationType: null } }
                };
            // Unshift to make it show up first
            phase.actions.unshift(newAction);
            phase.actionViewModels.unshift(viewModels.initActionViewModel(newAction));
          };

          $scope.removeIdealRange = function (phaseIndex, idealRangeIndex) {
            var phase = $scope.sharedDataService.selectedGrowPlan.phases[index];
            phase.idealRanges.splice(idealRangeIndex, 1);
          };

          $scope.removeAction = function (phaseIndex, actionIndex) {
            var phase = $scope.sharedDataService.selectedGrowPlan.phases[index];
            phase.actions.splice(actionIndex, 1);
            if (phase.actionViewModels) {
              phase.actionViewModels.splice(actionIndex, 1)
            }
          };

    			$scope.init();
        }
    	]
  	);



    growPlanApp.controller('bpn.controllers.growPlan.Actions',
      [
        '$scope',
        '$filter',
        'sharedDataService',
        'bpn.services.analytics',
        function ($scope, $filter, sharedDataService, analytics) {
          $scope.sharedDataService = sharedDataService;
          $scope.currentAction = false;
          
          /**
           * @param {Control=} [control] (optional)
           */
          $scope.addAction = function (control) {
            
            var newAction = {
                _id: "new_action" + '-' + (Date.now().toString()), // this is just to make it unique in the UI. The server will detect that this is not an ObjectId and create a new Action
                cycle: { offset: { duration: 0, durationType: 'days' }, states : [] }
              };
            
            if (control){
              

              newAction.control = control;
              
              newAction.cycle.states[0] = {
                controlValue : 1,
                duration: 1,
                durationType : 'hours'
              };
              newAction.cycle.states[1] = {
                controlValue : 0,
                duration: 1,
                durationType : 'hours'
              };

              viewModels.initActionViewModel(newAction, 'phaseStart');

              $scope.sharedDataService.selectedGrowPlan.focusedPhase.actionViewModelsByControl[control._id] = newAction;

              analytics.track("customize grow plan", { action : "add timer", control: control.name });
            } else {
              

              viewModels.initActionViewModel(newAction, 'phaseStart');
              $scope.sharedDataService.selectedGrowPlan.focusedPhase.actionViewModelsNoControl.push(newAction);

              analytics.track("customize grow plan", { action : "add reminder" });
            }

            return newAction;
          };


          /**
           * Pop up the overlay for the action. 
           * If action isn't defined, create one
           * 
           * @param {ActionViewModel} action
           * @param {Control} [control]
           */
          $scope.triggerActionOverlay = function(action, control){
            if (!action){
              action = $scope.addAction(control);
            }
            $scope.currentAction = action;
            $scope.sharedDataService.activeOverlay = 'ActionOverlay' + action._id;
          }

          $scope.close = function() {
            console.log('should re-render graph?');
            $scope.sharedDataService.activeOverlay = undefined;
            $scope.currentAction = false;
          }
        }
      ]
    );


    growPlanApp.controller('bpn.controllers.growPlan.Main',
      [
        '$scope',
        '$location',
        '$route',
        '$filter',
        'GrowPlanModel',
        'sharedDataService',
        'bpn.services.analytics',
        'PlantLoader',
        'ngDialog',
        function ($scope, $location, $route, $filter, GrowPlanModel, sharedDataService, analytics, PlantLoader, ngDialog) {
          $scope.sharedDataService = sharedDataService;

          //$scope.lights = bpn.lights;
          //$scope.lightFixtures = bpn.lightFixtures;
          //$scope.lightBulbs = bpn.lightBulbs;
          //$scope.nutrients = bpn.nutrients;
          $scope.controls = sharedDataService.controls;
          $scope.sensors = sharedDataService.sensors;
          $scope.userOwnedDevices = bpn.userOwnedDevices;
          $scope.plantSelections = {};
          $scope.plantQuery = '';
          //$scope.growSystems = bpn.growSystems;
          //$scope.selectedGrowPlan = {}; 
          //$scope.selectedGrowSystem = undefined;
          $scope.currentGrowPlanDay = 0;
          //$scope.growPlans = bpn.growPlans;
          //$scope.filteredGrowPlanList = angular.copy($scope.growPlans);
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
          };
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


          new PlantLoader();


          $scope.selectedSensors = function () {
            var list = [];
            angular.forEach($scope.sensors, function (sensor) {
              list.push(sensor);
            });
            return list;
          };


          $scope.refreshFocusedPhase = function(){
            if (sharedDataService.selectedGrowPlan.phases){
              sharedDataService.selectedGrowPlan.focusedPhase = sharedDataService.selectedGrowPlan.phases[sharedDataService.selectedPhaseIndex];
              
              // Create the sortedControls & sortedSensors arrays
              sharedDataService.selectedGrowPlan.focusedPhase.sortedControls = [];
              Object.keys(sharedDataService.selectedGrowPlan.focusedPhase.actionViewModelsByControl).forEach(function(actionControlId){
                sharedDataService.selectedGrowPlan.focusedPhase.sortedControls.push(sharedDataService.controlsById[actionControlId]);
              });
              sharedDataService.controls.forEach(function(control){
                if (!sharedDataService.selectedGrowPlan.focusedPhase.actionViewModelsByControl[control._id]){
                  sharedDataService.selectedGrowPlan.focusedPhase.sortedControls.push(control);
                }
              });

              sharedDataService.selectedGrowPlan.focusedPhase.sortedSensors = [];
              Object.keys(sharedDataService.selectedGrowPlan.focusedPhase.idealRangesBySensor).forEach(function(sensorCode){
                var idealRange = sharedDataService.selectedGrowPlan.focusedPhase.idealRangesBySensor[sensorCode];

                if (typeof idealRange.valueRange !== 'undefined' && (idealRange.valueRange.min !== 'undefined' || typeof idealRange.valueRange.max !== 'undefined')){
                  sharedDataService.selectedGrowPlan.focusedPhase.sortedSensors.unshift(sharedDataService.sensors[sensorCode]);  
                } else {
                  sharedDataService.selectedGrowPlan.focusedPhase.sortedSensors.push(sharedDataService.sensors[sensorCode]); 
                }
                
              });
              // Object.keys(sharedDataService.sensors).forEach(function(sensorCode){
              //   if (!sharedDataService.selectedGrowPlan.focusedPhase.idealRangesBySensor[sensorCode]){
              //     sharedDataService.selectedGrowPlan.focusedPhase.sortedSensors.push(sharedData.sensors[sensorCode]);
              //   }
              // });
            
              sharedDataService.selectedGrowPlan.focusedPhase.actionViewModelsNoControl.sort(function(action1, action2){
                var a = action1.scheduleType,
                  b = action2.scheduleType;

                if (a == 'phaseStart') { return -1; }
                else if (a == 'phaseEnd') { return 1; }
                else {
                  // else a is 'repeat'
                  if (b === 'phaseStart') { return 1; }
                  else if (b === 'phaseEnd') { return -1; }
                  else return 0;
                }
              });
            }
          };
          $scope.$watch('sharedDataService.selectedPhaseIndex', $scope.refreshFocusedPhase);
          $scope.$watch('sharedDataService.selectedGrowPlan', $scope.refreshFocusedPhase);



          $scope.updateSelectedGrowSystem = function () {
            // $scope.selectedGrowSystem = $filter('filter')($scope.growSystems, { _id: $scope.selected.growSystem })[0];
            if ($scope.sharedDataService.selectedPlants && $scope.sharedDataService.selectedPlants.length) {
              $scope.updatefilteredGrowPlans();
            }
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
          };


          $scope.triggerSensorOverlay = function(sensor){
            $scope.sharedDataService.activeOverlay = 'SensorOverlay' + sensor.abbrev;

            analytics.track("customize grow plan", { action : "edit sensor range", sensor: sensor.abbrev });
          }

          

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

          }, true);
          
          $scope.updateSelected = {

            // 'plants':function () {
            //   $scope.sharedDataService.selectedPlants = [];
            //   for (var i = $scope.sharedDataService.plants.length; i--;) {
            //     Object.keys($scope.sharedDataService.selected.plants).forEach(function (_id) {
            //       if ($scope.sharedDataService.selected.plants[_id] && $scope.sharedDataService.plants[i]._id == _id) {
            //         $scope.sharedDataService.selectedPlants.push($scope.sharedDataService.plants[i]);
            //       }
            //     });
            //   }

            //   $scope.updateSelectedGrowPlanPlants();

            //   if ($scope.selectedGrowSystem) {
            //     $scope.updatefilteredGrowPlans();
            //   }
            // },

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
            var selectedPlantIds = $scope.sharedDataService.selectedPlants.map(function (plant) { return plant._id }),
              growPlanDefault = new GrowPlanModel(bpn.growPlanDefault);

            //hit API with params to filter grow plans
            $scope.filteredGrowPlanList = GrowPlanModel.query({
              plants:selectedPlantIds,
              growSystem:$scope.selectedGrowSystem
              // growSystem: $scope.selectedGrowSystem._id
            }, function () {
              //add default to end of filtered grow plan array
              $scope.filteredGrowPlanList.splice($scope.filteredGrowPlanList.length, 0, growPlanDefault);
            });
          };


          $scope.$watch('sharedDataService.activeOverlay', function(newValue, oldValue){
            console.log('sharedDataService.activeOverlay', oldValue, newValue, new Date());
          })

          $scope.submit = function (e) {
            
            if (sharedDataService.pageMode === 'setup') {
              if ($scope.sharedDataService.selectedGrowPlan) {
                var dataToSubmit = {
                  submittedGrowPlan : viewModels.compileGrowPlanViewModelToServerModel(angular.copy($scope.sharedDataService.selectedGrowPlan)),
                  growPlanInstance : $scope.sharedDataService.growPlanInstance,
                  deviceId : $scope.sharedDataService.selected.deviceId
                };

                $scope.sharedDataService.submit.updateInProgress = true;
                //console.log(dataToSubmit);

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
                    $scope.sharedDataService.submit.updateInProgress = false;
                  },
                  error: function(jqXHR, textStatus, error) {
                    console.log('error', jqXHR, textStatus, error);
                    $scope.sharedDataService.submit.error = true;
                    $scope.sharedDataService.submit.success = false;
                  },
                  complete: function() {
                    $scope.$apply(function() {
                      ngDialog.open({ 
                        template: 'activation-overlay-template',
                        scope: $scope,
                        controller : "bpn.controllers.growPlan.ActivationOverlay",
                        className : "ngdialog-theme-overlay-message"
                      });
                    });
                  }
                });

                analytics.track("customize grow plan", { action : "activate garden" });
              }

            } else {
              
              $scope.sharedDataService.submit.updateInProgress = true;
              
              $scope.originalGrowPlan = angular.copy($scope.sharedDataService.selectedGrowPlan);

              $scope.sharedDataService.originalGrowPlanId = $route.current.params.growPlanId;            

              $scope.sharedDataService.selectedGrowPlan.$save(
                function(returnedGrowPlan){
                  console.log('successfully saved grow plan', returnedGrowPlan);
                  $scope.sharedDataService.submit.success = true;
                  $scope.sharedDataService.submit.updateInProgress = false;
                  //$scope.sharedDataService.activeOverlay = 'SaveOverlay';
                  ngDialog.open({ 
                    template: 'save-overlay-template',
                    scope: $scope,
                    controller : "bpn.controllers.growPlan.SaveOverlay",
                    className : "ngdialog-theme-overlay-message"
                  });

                }, function(){
                  console.log('error saving grow plan', arguments);
                  $scope.sharedDataService.submit.error = true;
                  $scope.sharedDataService.submit.success = false;
                  $scope.sharedDataService.submit.updateInProgress = false;
                  ngDialog.open({ 
                    template: 'save-overlay-template',
                    scope: $scope,
                    controller : "bpn.controllers.growPlan.SaveOverlay",
                    className : "ngdialog-theme-overlay-message"
                  });
                }
              );

              analytics.track("customize grow plan", { action : "save" });
            }
          };
        }
      ]
    );


    
    /**
     * Showcase phase graph so users know to interact there first
     */
    growPlanApp.directive('bpnDirectivesShowcaseReveal', function() {
      return {
        restrict : "EA",
        controller : [
          '$scope', '$element', '$attrs', '$transclude', 'sharedDataService',
          function ($scope, $element, $attrs, $transclude, sharedDataService){
            $scope.sharedDataService = sharedDataService;
          }
        ],
        link: function (scope, element, attrs, controller) {
          scope.el = $(element[0]);
          scope.fadeSides = function (inout) {
            var sideOpacity = inout == 'in' ? 1 : .25,
                phaseOpacity = 1;
            scope.el.find('#phases').css({ opacity: phaseOpacity });
            scope.el.find('.side').css({ opacity: sideOpacity });
          };
          scope.fadeSides('out');
          scope.el.on('click', function() {
            scope.fadeSides('in');
          });
        }
      }
    });

    // growPlanApp.directive('contenteditable', function() {
    //   return {
    //     restrict: 'A', // only activate on element attribute
    //     require: '?ngModel', // get a hold of NgModelController
    //     link: function(scope, element, attrs, ngModel) {
    //       if(!ngModel) return; // do nothing if no ng-model
   
    //       // Specify how UI should be updated
    //       ngModel.$render = function() {
    //         element.html(ngModel.$viewValue || '');
    //       };
   
    //       // Listen for change events to enable binding
    //       element.on('blur keyup change', function() {
    //         scope.$apply(read);
    //       });
    //       read(); // initialize
   
    //       // Write data to the model
    //       function read() {
    //         var html = element.html();
    //         // When we clear the content editable the browser leaves a <br> behind
    //         // If strip-br attribute is provided then we strip this out
    //         if( attrs.stripBr && html == '<br>' ) {
    //           html = '';
    //         }
    //         ngModel.$setViewValue(html);
    //       }
    //     }
    //   };
    // });
  	
  	domReady(function () {
      angular.bootstrap(document, ['bpn.apps.growPlan']);
    });
  }
);
