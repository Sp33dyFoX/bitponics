require([
  'angular',
  'domReady',
  'view-models',
  'moment',
  'fe-be-utils',
  '/assets/js/services/grow-plan.js',
  'es5shim',
  'angularUI',
  'angularUIBootstrap',
  '/assets/js/controllers/selection-overlay.js',
  'overlay'
],
  function (angular, domReady, viewModels, moment, feBeUtils) {
    'use strict';

    var growPlanApp = angular.module('bpn.apps.setup.growPlan', ['ui', 'ui.bootstrap', 'bpn.services', 'bpn.controllers']);

		growPlanApp.config(
			[
				'$locationProvider',
				'$routeProvider',
				function($locationProvider, $routeProvider) {
			    $locationProvider.html5Mode(true);
    			$locationProvider.hashPrefix = '!';

			    $routeProvider
			    	.when('/', {
			        controller: 'bpn.controllers.setup.growPlan.Filter',
			        templateUrl: 'filter.html'
			      })
			      .when('/browse', {
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


		growPlanApp.factory('sharedDataService', function(){
			return {
				selectedGrowPlan : {},
				plants : bpn.plants,
				lightFixtures : bpn.lightFixtures,
				lightBulbs : bpn.lightBulbs,
				filteredPlantList : angular.copy(bpn.plants),
				selectedPlants : [],
				activeOverlay : undefined,
				selected: {
					plants : {}
				},
				modalOptions : {
			    backdropFade: true,
			    dialogFade: true,
			    dialogClass : 'overlay'
			  }
			};
		});

		growPlanApp.factory('overlayService', function(){
			
			return {
				showPlantOverlay : false,
				
			};
		});

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
    		'sharedDataService',
    		function($scope, sharedDataService){
    			$scope.sharedDataService = sharedDataService;
    			$scope.overlayItems = $scope.sharedDataService.filteredPlantList;
    			
    			$scope.$watch('sharedDataService.selectedGrowPlan.currentVisiblePhase.plants',
    				function(newValue, oldValue){
    					$scope.close();
    				}
  				);

    			$scope.close = function(){
    				// TODO : update the growPlan's from sharedDataService.selected.plants
						$scope.sharedDataService.activeOverlay = undefined;
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

    			$scope.close = function(){
						$scope.sharedDataService.activeOverlay = undefined;
    			};
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

    			$scope.close = function(){
						$scope.sharedDataService.activeOverlay = undefined;
    			};
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
    				//$scope.expectedGrowPlanDuration = $scope.sharedDataService.selectedGrowPlan.phases.reduce(function (prev, cur) { return prev.expectedNumberOfDays + cur.expectedNumberOfDays;});
  					$scope.setExpectedGrowPlanDuration();
          	//$scope.setCurrentPhaseTab(0);
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
                actionsViewModel:[],
                idealRanges:[]
              };
            $scope.sharedDataService.selectedGrowPlan.phases.push(phase);
            $scope.setCurrentVisiblePhase(phase);
          };

          $scope.removePhase = function (index) {
            $scope.sharedDataService.selectedGrowPlan.phases.splice(index, 1);
            $scope.setCurrentVisiblePhase($scope.sharedDataService.selectedGrowPlan.phases[0]);
          };

          $scope.addIdealRange = function (e) {
            var phase = e.phase,
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

          $scope.addAction = function (e) {
            var phase = e.phase,
              newAction = {
                _id:phase.actions.length.toString() + '-' + (Date.now().toString()) // this is just to make it unique in the UI. The server will detect that this is not an ObjectId and create a new Action
              };
            // Unshift to make it show up first
            phase.actions.unshift(newAction);
          };

          $scope.removeIdealRange = function (phaseIndex, idealRangeIndex) {
            $scope.sharedDataService.selectedGrowPlan.phases[phaseIndex].idealRanges.splice(idealRangeIndex, 1);
          };

          $scope.removeAction = function (phaseIndex, actionIndex) {
            $scope.sharedDataService.selectedGrowPlan.phases[phaseIndex].actions.splice(actionIndex, 1);
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
        function ($scope, $filter, GrowPlanModel, sharedDataService) {
          $scope.sharedDataService = sharedDataService;
          
          $scope.lights = bpn.lights;
          //$scope.lightFixtures = bpn.lightFixtures;
          //$scope.lightBulbs = bpn.lightBulbs;
          $scope.nutrients = bpn.nutrients;
          $scope.controls = bpn.controls;
          $scope.sensors = bpn.sensors;
          $scope.userOwnedDevices = bpn.userOwnedDevices;
          $scope.plantSelections = {};
          $scope.plantQuery = '';
          $scope.growSystems = bpn.growSystems;
          //$scope.selectedGrowPlan = {}; 
          $scope.selectedGrowSystem = undefined;
          $scope.currentGrowPlanDay = 0;
          $scope.growPlans = bpn.growPlans;
          $scope.filteredGrowPlanList = angular.copy($scope.growPlans);
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

          $scope.updateSelected = {

            'plants':function () {
              $scope.sharedDataService.selectedPlants = [];
              for (var i = $scope.sharedDataService.plants.length; i--;) {
                Object.keys($scope.sharedDataService.selected.plants).forEach(function (_id) {
                  if ($scope.sharedDataService.selected.plants[_id] && $scope.sharedDataService.plants[i]._id == _id) {
                    $scope.sharedDataService.selectedPlants.push($scope.sharedDataService.plants[i]);
                  }
                });
              }

              $scope.updateSelectedGrowPlanPlants();

              if ($scope.selectedGrowSystem) {
                $scope.updatefilteredGrowPlans();
              }
            },

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

          
          $scope.toggleOverlay = function (overlayMetaData) {
            $scope.overlayMetaData = overlayMetaData;
            switch (overlayMetaData.type) {
              //case 'plant':
                //$scope.overlayItems = $scope.filteredPlantList;
                // $scope.overlayItemKey = "plants";
                //break;
              //case 'fixture':
                //$scope.overlayItems = $scope.lightFixtures;
                // $scope.overlayItemKey = "lightFixture";
                //break;
              //case 'bulb':
                //$scope.overlayItems = $scope.lightBulbs;
                // $scope.overlayItemKey = "lightBulb";
                //break;
              case 'growSystem':
                $scope.overlayItems = $scope.growSystems;
                // $scope.overlayItemKey = "growSystem";
                break;
              case 'nutrient':
                $scope.overlayItems = $scope.nutrients;
                // $scope.overlayItemKey = "nutrients";
                break;
              default:
                $scope.overlayItems = [];
                // $scope.overlayItemKey = '';
                break;
            }
            if ($scope.overlayStates[$scope.overlayMetaData.type]) {
              $scope.overlayItems = [];
              $scope.overlayStates[$scope.overlayMetaData.type] = false;
            } else {
              // $scope.$broadcast('newOverlay', [itemKey, $scope.overlayItems]);
              $scope.$broadcast('newOverlay');
              $scope.overlayStates[$scope.overlayMetaData.type] = true;
            }
          };

          $scope.submit = function (e) {
            //e.preventDefault();

            if ($scope.selectedGrowPlan) {
              var dataToSubmit = {
                submittedGrowPlan:viewModels.compileGrowPlanViewModelToServerModel($scope.selectedGrowPlan),
                growPlanInstance:{
                  currentGrowPlanDay:1 // TODO
                },
                deviceId:"" // TODO
              };

              console.log(dataToSubmit);

              // TODO : show spinner
              $.ajax({
                url:'/setup/grow-plan',
                type:'POST',
                contentType:'application/json; charset=utf-8',
                dataType:'json',
                data:JSON.stringify(dataToSubmit),
                processData:false,
                success:function (data) {
                  console.log(data);
                  // TODO : Show message, take user to /dashboard
                },
                error:function (jqXHR, textStatus, error) {
                  console.log('error', jqXHR, textStatus, error);
                  // TODO : show an error message
                }
              });
            }
          };
        }
      ]
    );
  	
  	domReady(function () {
      angular.bootstrap(document, ['bpn.apps.setup.growPlan']);
    });
  }
);