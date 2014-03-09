/**
 * Main file for garden dashboard
 *
 * Depends on following globals:
 * - bpn.pageData.growPlanInstance
 * - bpn.pageData.sensors
 * - bpn.pageData.controls
 * - bpn.pageData.notifications
 * - bpn.pageData.photos
 * - bpn.pageData.userCanModify
 * - bpn.user
 */
require([
  'angular',
  'domReady',
  'moment',
  'fe-be-utils',
  'view-models',
  'd3',
  'tooltip',
  'angularResource',
  'angularRoute',
  'angularUI',
  'angularUIBootstrap',
  'bpn',
  'bpn.directives.graphs',
  'bpn.services.garden',
  'bpn.services.photo',
  'bpn.services.socket',
  'selection-overlay',
  'overlay',
  'flexslider',
  'angular-flexslider',
  'throttle-debounce',
  'bpn.directives.fileUpload',
  'lvl.directives.fileUpload',
  'ngFacebook',
  'bpn.services.user'
],
  function (angular, domReady, moment, feBeUtils, viewModels, d3, Tooltip) {
    'use strict';

    var dashboardApp = angular.module('bpn.apps.dashboard', ['bpn', 'ui', 'ui.bootstrap', 'angular-flexslider', 'ngRoute', 'lvl.directives.fileupload', 'facebook']);

    dashboardApp.factory('sharedDataService', 
      [
        'GardenModel',
        'PhotosModel',
        'UserModel',
        'bpn.services.socket',
        '$http',
        '$q',
        function(GardenModel, PhotosModel, UserModel, socket, $http, $q){
          
          /**
           * All the properties this service will expose
           */ 
          var sharedData = {
            targetActiveDate : new Date(),
            activeDate : {},
            daySummaryData : {}, 
            notifications : bpn.pageData.notifications,
            dateDataCache : {},  // Keyed by Date, contains { sensorLogs, latestSensorLogs, growPlanInstancePhase, growPlanPhase }
            socket : socket,
            activeOverlay : undefined,
            activeOverlayPositionTop : undefined,
            modalOptions : {
              backdrop: true,
              backdropFade: true,
              dialogFade: true,
              dialogClass : 'overlay'
            },
            controls : bpn.pageData.controls,
            sensors : bpn.pageData.sensors,
            //garden : bpn.pageData.growPlanInstance,
            controlHash : {},
            photos : bpn.pageData.photos,
            units : feBeUtils.UNITS,
            gardenModel : new GardenModel(bpn.pageData.growPlanInstance),
            photosModel : PhotosModel,
            user : new UserModel(bpn.user),
            userCanModify : bpn.pageData.userCanModify
          };

          sharedData.controls.forEach(function(control){
            sharedData.controlHash[control._id] = control;
          });

          // Transform the data into viewModel-friendly formats
          sharedData.controls.forEach(function (control) {
            viewModels.initControlViewModel(control);
          });


          viewModels.initPhotosViewModel(sharedData.photos);

          viewModels.initGrowPlanInstanceViewModel(sharedData.gardenModel, sharedData.controlHash);

          console.log(sharedData.gardenModel);


          /**
           *
           */
          sharedData.getDayOfPhase = function (growPlanInstancePhase, growPlanPhase, date) {
            // diff between date & gpiPhase.start + offset
            return moment(date).diff(growPlanInstancePhase.calculatedStartDate, "days");
          };


          /**
           *
           */
          sharedData.getGrowPlanInstancePhaseFromDate = function (date) {
            var dateMoment = moment(date),
              growPlanInstancePhases = sharedData.gardenModel.phases,
              i,
              phaseStart;

            // Reverse-loop through the phases. Once we've found one with a calculatedStartDate before the targetDate,
            // we've found the phase
            for (i = growPlanInstancePhases.length; i--;) {
              phaseStart = growPlanInstancePhases[i].calculatedStartDate;
              if (dateMoment.isAfter(phaseStart)) {
                return growPlanInstancePhases[i];
              }
            }
            return growPlanInstancePhases[0];
          };

          // sharedData.getGrowPlanInstancePhotosFromDate = function (date) {
          //   var dateMoment = moment(date),
          //     growPlanInstancePhotos = sharedData.gardenModel.photos,
          //     i,
          //     photoDay;

          //   console.log(growPlanInstancePhotos.length);
          //   //find photos from this date
          //   if (growPlanInstancePhotos.length) {
          //     for (i = growPlanInstancePhotos.length; i--;) {
          //       photoDay = growPlanInstancePhotos[i].date;
          //       if (dateMoment.isSame(photoDay, 'day')) {
          //         return growPlanInstancePhotos[i];
          //       }
          //     }
          //   }

          //   return growPlanInstancePhotos;
          // };



          /**
           * Returns a an angular promise
           *
           * @return {Promise}
           */
          sharedData.getSensorLogsByDate = function (dateKey) {
            var dateMoment = moment(dateKey),
                deferred = $q.defer();

            $http.get(
              '/api/gardens/' + sharedData.gardenModel._id + '/sensor-logs',
              {
                params : {
                  "start-date" : dateMoment.startOf("day").format(),
                  "end-date" : dateMoment.endOf("day").format()
                }
              }
            )
            .success(function(data, status, headers, config) {
              sharedData.dateDataCache[dateKey].sensorLogs = viewModels.initSensorLogsViewModel(data.data);
              sharedData.dateDataCache[dateKey].latestSensorLogs = viewModels.initLatestSensorLogsViewModel(data.data);
              sharedData.dateDataCache[dateKey].loaded = true;
              deferred.resolve(data);
            })
            .error(function(data, status, headers, config) {
              deferred.reject(data);
            });

            return deferred.promise;
          };

          /**
           * Returns a an angular promise
           *
           * @return {Promise}
           */
          sharedData.getRecentTextLogs = function () {
            var deferred = $q.defer();

            $http.get(
              '/api/gardens/' + sharedData.gardenModel._id + '/text-logs',
              {
                params : {
                  "limit" : 3
                }
              }
            )
            .success(function(data, status, headers, config) {
              sharedData.recentTextLogs = data.data;
              // sharedData.dateDataCache[dateKey].latestTextLogs = viewModels.initLatestSensorLogsViewModel(data.data);
              sharedData.recentTextLogs.loaded = true;
              deferred.resolve(data);
            })
            .error(function(data, status, headers, config) {
              deferred.reject(data);
            });

            return deferred.promise;
          };

          /**
           * Returns a an angular promise
           *
           * @return {Promise}
           */
          sharedData.getPhotosByDate = function (dateKey) {
            var deferred = $q.defer(),
                dateMoment = moment(dateKey);

            sharedData.photosModel.query({
                'id': sharedData.gardenModel._id,
                'start-date' : dateMoment.startOf("day").format(),
                'end-date' : dateMoment.endOf("day").format()
              }, function(data){
                sharedData.dateDataCache[dateKey].photos = data.data.map(viewModels.initPhotoViewModel);
                deferred.resolve(data);
              });

            return deferred.promise;
          };


    
          /**
           * Manages the dateDataCache. 
           * Passed a date, and if that date is already populated, returns it.
           * If not, creates a new entry for that date & retrieves the sensor data for that date.
           *
           * @param {Date|String} date : a date processable by momentjs
           */
          sharedData.getDateDataCache = function(date, loadSensorData, loadPhotoData){
            var dateMoment = moment(date),
                dateKey = feBeUtils.getDateKey(dateMoment),
                dateDataCache = sharedData.dateDataCache[dateKey];


            if (loadSensorData){
              sharedData.getSensorLogsByDate(dateKey);  
            }

            if (loadPhotoData) {
              sharedData.getPhotosByDate(dateKey);
            }

            if (dateDataCache){
              return dateDataCache;
            } else {
              dateDataCache = {};
              dateDataCache.growPlanInstancePhase = sharedData.getGrowPlanInstancePhaseFromDate(date);
              dateDataCache.growPlanPhase = dateDataCache.growPlanInstancePhase.phase;
              dateDataCache.date = dateMoment.toDate();
              dateDataCache.dateKey = dateKey;
              dateDataCache.dayOfPhase = sharedData.getDayOfPhase(
                dateDataCache.growPlanInstancePhase, 
                dateDataCache.growPlanPhase,
                dateDataCache.date
              );
              dateDataCache.loaded = false;
              sharedData.dateDataCache[dateKey] = dateDataCache;
              
              return dateDataCache;
            }
          };


          /**
           * Set up the socket for live updates on sensors, device status, and notifications
           */
          var initSocket = function (){
            socket.connect('/latest-grow-plan-instance-data');

            socket.emit('ready', { growPlanInstanceId : sharedData.gardenModel._id });

            socket.on('update', function(data){
              console.log('socket update received', data);
              
              var sensorLog = data.sensorLog,
                  textLog = data.textLog,
                  deviceStatus = data.deviceStatus,
                  notifications = data.notifications,
                  photos = data.photos,
                  dateDataCache;
              
              if (sensorLog){
                sensorLog = viewModels.initSensorLogViewModel(sensorLog);
                dateDataCache = sharedData.getDateDataCache(sensorLog.timestamp);
                dateDataCache.sensorLogs.unshift(sensorLog);
                dateDataCache.latestSensorLogs = viewModels.initLatestSensorLogsViewModel(dateDataCache.sensorLogs);
              }
              
              if (textLog){
                textLog = textLog;
                sharedData.recentTextLogs.unshift(textLog);
              }
              if (deviceStatus) {
                viewModels.initDeviceViewModel(sharedData.gardenModel.device, deviceStatus, sharedData.controlHash);
              }
              if (notifications){
                notifications.forEach(function(notification){
                  sharedData.notifications.unshift(notification);
                });
              }
              if (photos){
                photos.forEach(viewModels.initPhotoViewModel);

                photos.forEach(function(photo){
                  var photoAlreadyExists = sharedData.photos.some(function(existingPhoto){
                    return (existingPhoto._id === photo._id);
                  });

                  if (!photoAlreadyExists){
                    sharedData.photos.push(photo);  
                  }
                });
              }
            });
          }

          initSocket();

          /*
           * Show the day summary overlay, triggered from the phase graph
           *
           * * @param {} data : { phase, dateKey, status, dayIndex }
           */
          sharedData.showDaySummaryOverlay = function (data) {
            //open overlay
            sharedData.activeOverlay = 'DaySummaryOverlay';

            //set day summary data
            sharedData.daySummaryData = angular.extend(sharedData.daySummaryData, data);

            //cache date data
            sharedData.getDateDataCache(data.dateKey, true, true);
          };

          return sharedData;
        }
      ]
    );
    

    dashboardApp.config(
      [
        '$facebookProvider',
        function($facebookProvider) {
          $facebookProvider.init({
            appId: '260907493994161'
          });
        }
      ]
    );


    dashboardApp.factory('sensorLogsService', function(){
      // TODO : consolidate the get/post/caching mechanisms for /gardens/:id/sensor-logs here
    });


    dashboardApp.controller('bpn.controllers.dashboard.Main',
      [
        '$scope',
        '$http',
        '$q',
        'sharedDataService',
        'NavService',
        'bpn.services.analytics',
        function ($scope, $http, $q, sharedDataService, NavService, analytics) {
          $scope.sharedDataService = sharedDataService;
          $scope.controls = bpn.pageData.controls;
          $scope.sensors = bpn.pageData.sensors;
          
          /*
           * Open garden settings overlay from nav settings
           */
          $scope.$watch( function () { return NavService.openGardenSettingsOverlay; }, function (oldData, newData) {
            if (newData) {
              $scope.sharedDataService.activeOverlay = 'SettingsOverlay';
              // NavService.openGardenSettingsOverlay = false;
            }
          }, true);

          /**
           * Trigger an action on a control
           */
          $scope.triggerImmediateAction = function(currentControlAction, actionId){
            currentControlAction.updateInProgress = true;

            $http.post(
              '/api/gardens/' + $scope.sharedDataService.gardenModel._id + '/immediate-actions',
              {
                actionId : actionId,
                message : "Triggered from dashboard"
              }
            )
            .success(function(data, status, headers, config) {
              currentControlAction.updateInProgress = false;
            })
            .error(function(data, status, headers, config) {
              currentControlAction.updateInProgress = false;
            });

            analytics.track("garden interaction", { "garden id" : $scope.sharedDataService.gardenModel._id, action : "trigger immediate action" });
          }

          /*
           * Get recent text log entries
           */
          $scope.sharedDataService.getRecentTextLogs();

          console.log($scope.sharedDataService.recentTextLogs);
          /**
           * Display data (sensor logs) for the provided date
           *
           * @param {Date|String} date
           */
          $scope.displayDate = function (date) {
            $scope.sharedDataService.activeDate = $scope.sharedDataService.getDateDataCache(date, true);
          };


          /**
           *
           */
          $scope.$watch('sharedDataService.activeDate.loaded', function (newValue) {
            
          });


          /**
           *
           */
          $scope.$watch('sharedDataService.targetActiveDate', function (newVal, oldVal) {
            $scope.displayDate($scope.sharedDataService.targetActiveDate);
          });


          
          // To have a continually-updating time:
          setInterval(function(){
            var todayKey = feBeUtils.getDateKey(moment());
            if (todayKey === $scope.sharedDataService.activeDate.dateKey){
              $scope.sharedDataService.activeDate.date = new Date();
              $scope.sharedDataService.activeDate.showTime = true;
              
            } else {
              $scope.sharedDataService.activeDate.showTime = false;
            }
            $scope.$apply();

          }, 1000);

        }
      ]
    );


    dashboardApp.controller('bpn.controllers.dashboard.DayOverview',
      [
        '$scope',
        'sharedDataService',
        function($scope, sharedDataService){
          $scope.sharedDataService = sharedDataService;

          $scope.close = function(){
            $scope.sharedDataService.activeOverlay = undefined;
          };
          // TODO: Add functions to handle interactions on anything in the DayOverview sidebar (clicks to open sensor detail overlay)

          $scope.getIdealRangeForSensor = function (sensor, date) {
            var idealRanges = $scope.sharedDataService.activeDate.growPlanPhase.idealRanges,
              idealRange,
              i,
              timeOfDayInMilliseconds,
              applicableTimeSpan;
            
            for (i = idealRanges.length; i--;) {
              idealRange = idealRanges[i];
              applicableTimeSpan = idealRange.applicableTimeSpan;

              if (idealRange.sCode === sensor.code) {
                if (applicableTimeSpan && date){
                  // get the localized time of day for the sensor log
                  // calling new Date(anything) in a browser will give the localized time.
                  // our dates are stored with a UTC timestamp, so we good
                  timeOfDayInMilliseconds = feBeUtils.getTimeOfDayInMilliseconds(date);

                  // Handle regular span vs overnight span
                  if (applicableTimeSpan.startTime < applicableTimeSpan.endTime) {
                    if ( (timeOfDayInMilliseconds >= applicableTimeSpan.startTime) && (timeOfDayInMilliseconds <= applicableTimeSpan.endTime) ){
                      return idealRange;
                    }
                  } else {
                    // overnight span
                    // time can be after startTime or before endTime
                    if ( (timeOfDayInMilliseconds >= applicableTimeSpan.startTime) || (timeOfDayInMilliseconds<= applicableTimeSpan.endTime) ){
                      return idealRange;
                    }
                  }
                } else {
                  return idealRange;  
                }
              }
            }
          };


          $scope.getSensorBlockClassNames = function (sensor, sensorLog) {
            var sensorCode = sensor.code,
              classNames = ['sensor', 'data-module', sensorCode],
              idealRange,
              sensorValue,
              sensorTimestamp;

            if (sensorLog){
               sensorValue = sensorLog[sensorCode].val;
               sensorTimestamp = sensorLog[sensorCode].timestamp;
               idealRange = $scope.getIdealRangeForSensor(sensor, new Date(sensorLog[sensorCode].timestamp));
            }

            // Determine whether we need to add the "warning" class
            if (idealRange) {
              if ((sensorValue < idealRange.valueRange.min) ||
                  (sensorValue > idealRange.valueRange.max)
                ) {
                classNames.push('warning');
              }
            }

            if (typeof sensorValue === 'undefined') {
              classNames.push('warning');
            }

            return classNames.join(' ');
          };
        }
      ]
    );


    dashboardApp.controller('bpn.controllers.dashboard.PhasesGraph',
      [
        '$scope',
        function ($scope) {
        }
      ]
    );

    dashboardApp.controller('bpn.controllers.dashboard.Photos',
      [
        '$scope',
        '$window',
        'sharedDataService',
        '$anchorScroll',
        'bpn.services.analytics',
        '$facebook',
        function($scope, $window, sharedDataService, $anchorScroll, analytics, $facebook){
          $scope.$window = $window;
          $scope.sharedDataService = sharedDataService;
          $scope.user = $scope.sharedDataService.user;
          $scope.modalOptions = {
            dialogClass : 'overlay photo'
          };
          
          $scope.open = function(photoId, index){
            // $scope.sharedDataService.activeOverlay = 'PhotosOverlay-' + photoId;
            //$scope.startAt = $scope.sharedDataService.photos.length - index;
            console.log('index', index);
            $scope.startAt = index;
            $scope.sharedDataService.activeOverlay = 'PhotosOverlay';
            $anchorScroll();
          };

          $scope.close = function(){
            $scope.sharedDataService.activeOverlay = undefined;
          };

          $scope.progress = function(percentDone) {
            console.log("progress: " + percentDone + "%");
            $scope.uploadInProgress = true;
          };
     
          $scope.done = function(files, responseData) {
            $scope.uploadInProgress = false;
            console.log("upload complete");
            console.log("responseData: " + JSON.stringify(responseData));
            if (responseData.data.length)
            var completedPhotos = responseData.data[0].filter(function(item){ return typeof item === 'object'; });
            completedPhotos.forEach(function(photo){
              viewModels.initPhotoViewModel(photo);
              sharedDataService.photos.push(photo);
              $scope.sharePhoto(photo);
            });
            analytics.track("garden interaction", { "garden id" : $scope.sharedDataService.gardenModel._id, action : "upload photo" });
          };
     
          $scope.getData = function(files) { 
            //this data will be sent to the server with the files
            return {msg: "from the client", date: new Date()};
          };
     
          $scope.error = function(files, type, msg) {
            console.log("Upload error: " + msg);
            console.log("Error type:" + type);
            
            var errorMessage = '';

            switch(type) {
              case "TOO_MANY_FILES":
                errorMessage = "Sorry, we can only process 5 files at a time. Please try again with fewer files.";
                break;
              case "MAX_SIZE_EXCEEDED":
                errorMessage = "Sorry, we can't process a file that large. Max file size is 5mb.";
                break;
              default:
                errorMessage = "Sorry, there was an error uploading your photo. If you see this error again, please let us know so we can track down the cause.";
            }
            $scope.logFiles(files);

          };

          $scope.sharePhoto = function(photo) {
            var prefs = $scope.user.socialPreferences;
            if (prefs.facebook.permissions.publish) {
              $facebook.login({ scope: 'publish_actions' }).then(
                function(response) {
                  if (response.authResponse) {
                    $facebook.api('/me/photos', 'POST',
                      { 
                        // 'url': 'https://www.bitponics.com/photos/52fa2d3cc926f50200000271', //for testing locally need a public-facing image
                        'url': $window.location.origin + photo.url,
                        'message':  sharedDataService.gardenModel.name + ', ' + 
                                    sharedDataService.activeDate.growPlanPhase.name + ' Phase, ' +
                                    'Day ' + sharedDataService.activeDate.dayOfPhase
                      }
                    ).then(
                      function(response) {
                        if (response && !response.error) {
                          console.info('success');
                        } else {
                          console.info('fail' + response.error);
                        }
                      }
                    );
                  } else {
                    console.info('User cancelled login or did not fully authorize.');
                  }
                },
                function(response) {
                  console.info('Login error so do not assume we have permission.');
                }
              );
            } else if (prefs.twitter.permissions.publish) {
              //TODO: twitter share integration
            }
          };
     
          $scope.logFiles = function(files) 
          {
            console.log('Files')
            for (var i = 0; i < files.length; i++) {
              console.log('\t' + files[i].name);
            }
          }

        }
      ]
    );

    dashboardApp.controller('bpn.controllers.dashboard.Controls',
      [
        '$scope',
        'sharedDataService',
        function ($scope, sharedDataService) {
          $scope.sharedDataService = sharedDataService;

        }
      ]
    );


    dashboardApp.controller('bpn.controllers.dashboard.Notifications',
      [
        '$scope',
        'sharedDataService',
        function ($scope, sharedDataService) {
          $scope.sharedDataService = sharedDataService;
          $scope.pastNotifications = [];
          $scope.impendingNotifications = []; // notifications for the next X days (2 days?)
          $scope.futureNotifications = [];

          $scope.$watch('sharedDataService.notifications', function(){
            var notifications = sharedDataService.notifications,
                nowMoment = moment();
            if (!notifications && notifications.length){
              $scope.pastNotifications = [];
              $scope.impendingNotifications = [];
              $scope.futureNotifications = [];
            } else {
              $scope.pastNotifications = sharedDataService.notifications;
              $scope.impendingNotifications = [];
              $scope.futureNotifications = [];
            }
            
          });
        }
      ]
    );


    dashboardApp.controller('bpn.controllers.dashboard.SettingsOverlay',
      [
        '$scope',
        '$timeout',
        'sharedDataService',
        'NavService',
        'GardenModel',
        '$rootScope',
        'bpn.services.analytics',
        function($scope, $timeout, sharedDataService, NavService, GardenModel, $rootScope, analytics){
          $scope.sharedDataService = sharedDataService;

          $scope.close = function(){
            $scope.sharedDataService.activeOverlay = undefined;
          };

          $rootScope.close = function(){
            $scope.sharedDataService.activeOverlay = undefined;
          };
          
          $scope.completeGarden = function() {
            sharedDataService.gardenModel.$complete();
          }
          
          $scope.deleteGarden = function() {
            sharedDataService.gardenModel.$delete();
          }

          $scope.updateName = function(){
            sharedDataService.gardenModel.$updateName();
          };

          /*
           * Save Settings to GardenModel
           */
          $scope.updateSettings = function() {
            sharedDataService.gardenModel.$updateSettings();
          }

          $scope.advancePhase = function(e){
            $scope.close();
            $timeout(function(){
              sharedDataService.activeOverlay = "AdvancePhaseOverlay";
            }, 200);

            analytics.track("garden interaction", { "garden id" : sharedDataService.gardenModel._id, action : "try advance phase" });
          }
        }
      ]
    );


    dashboardApp.controller('bpn.controllers.dashboard.AdvancePhaseOverlay',
      [
        '$scope',
        'sharedDataService',
        '$rootScope',
        'bpn.services.analytics',
        function($scope, sharedDataService, $rootScope, analytics){
          $scope.sharedDataService = sharedDataService;

          $scope.advancePhase = function(e){
            analytics.track("garden interaction", { "garden id" : sharedDataService.gardenModel._id, action : "confirm advance phase" });

            $scope.sharedDataService.gardenModel.$advancePhase({},
              function(){
                console.log('success');
                window.location.href = window.location.href;
              }
            );
          }
        }
      ]
    );


    dashboardApp.controller('bpn.controllers.dashboard.SensorDetailOverlay',
      [
        '$scope',
        'sharedDataService',
        function($scope, sharedDataService){
          $scope.sharedDataService = sharedDataService;
          $scope.manualSensorEntry = {};
          $scope.idealRanges = {}
          $scope.sharedDataService.gardenModel.activePhase.phase.idealRanges.forEach(function(idealRange) {
            $scope.idealRanges[idealRange.sCode] = idealRange;
          });

          $scope.close = function(){
            $scope.sharedDataService.activeOverlay = undefined;
          };

          $scope.drawSparkGraph = function (svgCont, setData, idealLow, idealHigh, belowResolution) {
            var width = 400;
            var height = 100;

            var yExtent = d3.extent(setData, function (d) { return d.value; });

            var xScale = d3.scale.linear()
              .domain(d3.extent(setData, function (d) {
              return d.time;
            }));
            xScale.range([0, width]);
            //.nice();      

            var yScale = d3.scale.linear()
              .domain(d3.extent(setData, function (d) { return d.value; }))
              .range([height, 0]);

            var yColorScale = d3.scale.linear()
              .domain([yExtent[0], idealLow, idealLow, idealHigh, idealHigh, yExtent[1]])
              .range(['red', 'red', 'green', 'green', 'red', 'red']);

            var line = d3.svg.line()
              .x(function (d) {
                return xScale(d.time);
              })
              .y(function (d) {
                return yScale(d.value);
              });

            var sparkGraph = d3.select(svgCont)
              .append('svg:svg')
              .attr('width', width)
              .attr('height', height);

            var arraySections = [];
            var curArr = [];

            var crossTime = '';
            var crossPercent = '';
            var crossPoint = '';

            var testScale = d3.scale.linear()
              .domain([yExtent[0], idealLow - belowResolution, idealLow, idealHigh, idealHigh + belowResolution, yExtent[1]])
              .range(['low', 'low', 'normal', 'normal', 'high', 'high']);

            for (var i = 0; i < setData.length; i++) {
              if (curArr.length == 0) {
                curArr.push(setData[i]);
              } else {
                if (testScale(setData[i - 1].value) != testScale(setData[i].value)) {
                  if ((testScale(setData[i - 1].value) == 'low' || testScale(setData[i - 1].value) == 'normal') && (testScale(setData[i].value) == 'low' || testScale(setData[i].value) == 'normal')) {
                    crossPercent = Math.abs(idealLow - setData[i - 1].value) / Math.abs(setData[i].value - setData[i - 1].value)
                    crossTime = ((setData[i].time - setData[i - 1].time) * crossPercent ) + setData[i - 1].time;

                    crossPoint = {'time':crossTime, 'value':idealLow - belowResolution};
                  } else if ((testScale(setData[i - 1].value) == 'high' || testScale(setData[i - 1].value) == 'normal') && (testScale(setData[i].value) == 'high' || testScale(setData[i].value) == 'normal')) {
                    crossPercent = Math.abs(idealHigh - setData[i - 1].value) / Math.abs(setData[i].value - setData[i - 1].value)
                    crossTime = ((setData[i].time - setData[i - 1].time) * crossPercent ) + setData[i - 1].time;

                    crossPoint = {'time':crossTime, 'value':idealHigh + belowResolution};
                  } else {
                    console.log("NOT SUPPOSED TO!! i-1 " + testScale(setData[i - 1].value) + " i " + testScale(setData[i - 1].value));
                  }

                  curArr.push(crossPoint);
                  arraySections.push(curArr);
                  curArr = [];
                  curArr.push(crossPoint);
                  curArr.push(setData[i]);
                } else {
                  curArr.push(setData[i]);
                }
              }
            }

            arraySections.push(curArr);

            sparkGraph
              .append('line')
              .attr('x1', 0)
              .attr('y1', yScale(idealLow))
              .attr('x2', width)
              .attr('y2', yScale(idealLow))
              .attr('stroke-width', 1)
              .attr('stroke', 'black');

            sparkGraph
              .append('line')
              .attr('x1', 0)
              .attr('y1', yScale(idealHigh))
              .attr('x2', width)
              .attr('y2', yScale(idealHigh))
              .attr('stroke-width', 1)
              .attr('stroke', 'black');


            sparkGraph.selectAll('path')
              .data(arraySections)
              .enter().append("path")
              .attr('stroke', function (d, i) {
                return yColorScale(d[1].value);
              })
              .attr('fill', 'none')
              .attr('stroke-width', '1')

              .attr("d", line);

            /*sparkGraph.append("path")
             .datum(setData)
             //.attr("class", "line")
             .attr('stroke', 'red')
             .attr('fill', 'none')
             .attr('stroke-width', '1')
             .attr("d", line);*/
          };
        }
      ]
    );

    dashboardApp.controller('bpn.controllers.dashboard.DaySummaryOverlay',
      [
        '$scope',
        '$http',
        'sharedDataService',
        function($scope, $http, sharedDataService){
          $scope.sharedDataService = sharedDataService;
          $scope.phase = {};
          $scope.dataCache = {};
          $scope.dayIndex = 1;
          $scope.activeSensor = {
            obj: $scope.sharedDataService.sensors[0]
          };

          $scope.close = function(){
            $scope.sharedDataService.activeOverlay = undefined;
          };

          $scope.$watch($scope.sharedDataService.daySummaryData, function(oldValue, newValue) {
            $scope.dataCache = $scope.sharedDataService.getDateDataCache($scope.sharedDataService.daySummaryData.dateKey);
            $scope.dayIndex = $scope.sharedDataService.daySummaryData.dayIndex + 1;
            $scope.phase = $scope.sharedDataService.daySummaryData.phase;
          });

        }
      ]
    );

    dashboardApp.controller('bpn.controllers.dashboard.ControlOverlay',
      [
        '$scope',
        '$http',
        'sharedDataService',
        function($scope, $http, sharedDataService){
          $scope.sharedDataService = sharedDataService;
          
          $scope.close = function(){
            $scope.sharedDataService.activeOverlay = undefined;
          };


          $scope.clearImmediateAction = function(currentControlAction, control){
            currentControlAction.updateInProgress = true;

            $http.post(
              '/api/gardens/' + $scope.sharedDataService.gardenModel._id + '/immediate-actions?expire=true',
              {
                actionId : currentControlAction._id,
                message : "Triggered from dashboard"
              }
            )
            .success(function(data, status, headers, config) {
              $scope.close();
            })
            .error(function(data, status, headers, config) {
            });
          }
        }
      ]
    );
    
    dashboardApp.controller('bpn.controllers.dashboard.ManualLog',
      [
        '$scope',
        '$http',
        'sharedDataService',
        function($scope, $http, sharedDataService){
          $scope.sharedDataService = sharedDataService;

          $scope.filterForJournalEntries = function(log){
            return !!log['journal'] && log['journal'].length > 0;
          };

          $scope.getRecentJournalEntries = function(){

            for (var i = 0; i < 5; i++) {
              // var  = sharedDataService.getSensorLogsByDate();

            }
          };

        }
      ]
    );

    dashboardApp.controller('bpn.controllers.dashboard.ManualLogOverlay',
      [
        '$scope',
        '$http',
        'sharedDataService',
        function($scope, $http, sharedDataService){
          $scope.sharedDataService = sharedDataService;
          $scope.manualSensorEntryMode = true;
          $scope.sensors = bpn.pageData.sensors;
          
          $scope.close = function(){
            $scope.sharedDataService.activeOverlay = undefined;
          };
        }
      ]
    );


    dashboardApp.directive('bpnDirectivesSensorSparklineGraph', function() { 
      return {
        restrict : "EA",
        replace : true,
        scope : {
          sensorCode : "=",
          sensorLogs : "="
        },
        template : '<div class="sparkline {{sensorCode}}"></div>',
        controller : [
          '$scope', '$element', '$attrs', '$transclude',
          function ($scope, $element, $attrs, $transclude){
          }
        ],
        link: function (scope, element, attrs, controller) { 
          // link is where we have a created directive element as
          // well as populated scope to work with
          // element is a jQuery wrapper on the element

          function render () {
            element.empty();

            if (!scope.sensorLogs || !scope.sensorLogs.length) {
              element.append('<div>No logs for this date.</div>');
              return;
            }

            var sensorReadings = scope.sensorLogs.map(function(sensorLog){
              return sensorLog[scope.sensorCode];
            });
            sensorReadings = sensorReadings.filter(function(sensorReading){
              return (typeof sensorReading === 'number');
            });
            sensorReadings = sensorReadings.reverse();

            var max=0, min=0, len=0;
            min = d3.min(sensorReadings);
            max = d3.max(sensorReadings);
            len = sensorReadings.length;
            
            // TODO : figure out how to make the size dynamic based on container
            var h = 50,
                w = 750,
                p = 2,
                x = d3.scale.linear().domain([0, len]).range([p, w - p]),
                y = d3.scale.linear().domain([min, max]).range([h - p, p]),
                line = d3.svg.line()
                       .x(function(d, i) { 
                        console.log('Plotting X value for data point: ' + d + ' using index: ' + i + ' to be at: ' + x(i) + ' using our xScale.');
                        // return the X coordinate where we want to plot this datapoint
                        return x(i); 
                       })
                       .y(function(d) { 
                          console.log('Plotting Y value for data point: ' + d + ' to be at: ' + y(d) + " using our yScale.");
                          // return the Y coordinate where we want to plot this datapoint
                          return y(d); 
                       });

            var svg = d3.select(element[0])
                        .append("svg:svg")
                        .attr("height", h)
                        .attr("width", w);

            var g = svg.append("svg:g");
            g.append("svg:path")
             .attr("d", line(sensorReadings));
             //.attr("stroke", function(d) { return fill("hello"); });
          }

          scope.$watch("sensorLogs", function(val) {
            render();
          });
        }
      };
    });


    dashboardApp.directive('bpnDirectivesManualEntryForm', function() { 
      return {
        restrict : "EA",
        replace : true,
        controller : [
          '$scope', 
          '$element',
          '$attrs', 
          '$transclude', 
          '$http', 
          'sharedDataService',
          'bpn.services.analytics',
          function ($scope, $element, $attrs, $transclude, $http, sharedDataService, analytics) {
            $scope.sharedDataService = sharedDataService;
            $scope.manualSensorEntry = $scope.manualSensorEntry ? $scope.manualSensorEntry : {};
            $scope.manualTextEntry = $scope.manualTextEntry ? $scope.manualTextEntry : '';
            $scope.sensorUnits = sharedDataService.units;
            // $scope.form = {};

            //if no device on garden, then just show the manual sensor entry forms
            $scope.manualSensorEntryMode = !$scope.sharedDataService.gardenModel.device;

            $scope.toggleManualEntry = function(){
              $scope.manualSensorEntryMode = $scope.manualSensorEntryMode ? false : true;
              if ($scope.sharedDataService) {
                $scope.sharedDataService.manualSensorEntryMode = $scope.manualSensorEntryMode;
              }
            };

            $scope.changeUnit = function(sensorCode, value) {
              var oldUnit = sharedDataService.gardenModel.settings.units[sensorCode],
                  oldValue = value,
                  newUnit,
                  newValue;

              // Object.keys(sharedDataService.units[sensorCode]).forEach(function(unitName){
              //   if (feBeUtils.units[sensorCode][unitName]) {}
              // });
              
              console.log('toggleUnitType for ' + sensorCode);
              console.log('has current unit of ' + oldUnit);
              console.log('will change to ' + newUnit);

            };

            $scope.hasMultipleUnits = function (sensorCode) {
              return $scope.sensorUnits[sensorCode.toUpperCase()].units.length > 1;
            };

            $scope.resetForm = function() {
              $scope.manualSensorEntry = {};
              $scope.manualTextEntry = '';
              // $scope.form.$setPristine();
            };

            $scope.submit = function(){
              var valid = true,
                  sensorDataObj = {},
                  textDataObj = {},
                  sensors = Object.keys($scope.manualSensorEntry),
                  text = $scope.manualTextEntry,
                  sensorlogsArray = [];

              for (var i = 0; i < sensors.length; i++) {
                if ($scope.manualSensorEntry[sensors[i]]) {
                  //construct sensor logs array for dataObj
                  sensorlogsArray.push({
                    val: $scope.manualSensorEntry[sensors[i]],
                    sCode: sensors[i]
                  });
                }
              }

              //construct sensorDataObj for server
              sensorDataObj = {
                sensorLog: {
                  gpi: $scope.sharedDataService.gardenModel._id,
                  timestamp: new Date(),
                  logs: sensorlogsArray
                }
              };

              //construct textDataObj for server
              textDataObj = {
                textLog: {
                  gpi: $scope.sharedDataService.gardenModel._id,
                  timestamp: new Date(),
                  logs: [{
                    val: text,
                    tags: []
                  }]
                }
              };
              
              if (valid) {
                analytics.track("garden interaction", { "garden id" : $scope.sharedDataService.gardenModel._id, action : "post sensor log" });
                //TODO: convert to $resource's
                $http({
                  method: 'post',
                  headers: {
                    'bpn-manual-log-entry': 'true'
                  },
                  url: '/api/gardens/' + $scope.sharedDataService.gardenModel._id + '/sensor-logs',
                  data: sensorDataObj
                })
                .success(function(data, status, headers, config) {
                  console.log('success');
                  if ($scope.resetForm) $scope.resetForm();
                  if ($scope.close) $scope.close();
                })
                .error(function(data, status, headers, config) {
                  console.log('error');

                });

                if(text) {
                  analytics.track("garden interaction", { "garden id" : $scope.sharedDataService.gardenModel._id, action : "post text log" });
                  $http({
                    method: 'post',
                    url: '/api/gardens/' + $scope.sharedDataService.gardenModel._id + '/text-logs',
                    data: textDataObj
                  })
                  .success(function(data, status, headers, config) {
                    console.log('success');
                  })
                  .error(function(data, status, headers, config) {
                    console.log('error');
                  });
                }
              }
            };

          }
        ],
        link: function (scope, element, attrs, controller) { 
          scope.sensorUnit = attrs.sensorUnit;
          scope.sensorCode = attrs.sensorCode;
          scope.sensorLogs = attrs.sensorLogs;
          // scope.form = element.find('form').eq(0);
        }
      }
    });
      
    

    domReady(function () {
      angular.bootstrap(document, ['bpn.apps.dashboard']);
    });
  });






















/*

// Kyle's code

$scope.getPhaseClass = function (data, index) {
            var status = data.data.status;

            switch(status){
              case feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD : 
                return "good";
              case feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD : 
                return "bad";
              default : 
                return "empty";
            }
          };

          $scope.drawBarSet = function (target, barWidth, barLength, barSpacing, numBars) {
            var svg,
              startLoc = 0,
              totalHeight = ((barWidth * numBars) + (barSpacing * (numBars - 1))),
            //startLoc = ((barWidth*numBars) + (barSpacing*numBars))/-2,
              bar,
              barGroup;

            svg = d3.select(target).append('svg:g').attr('class', 'barberPoleCont');

            barGroup = svg
              .attr('width', barLength)
              .attr('height', ((barWidth * numBars) + (barSpacing * (numBars - 1))))
              .append('svg:g')
              .attr('class', 'barberPolePattern');

            for (var i = 0; i < numBars; i++) {
              barGroup
                .append("svg:rect")
                .attr('x', (barLength / -2))
                .attr('y', ((startLoc + (barWidth * i) + (barSpacing * i)) + (totalHeight / -2)  ))
                .attr('width', barLength)
                .attr('height', barWidth);
            }
          };



$scope.makeDayProgressClock = function (svg, radius, triangleSize) {
            var triHeight = Math.cos(Math.PI / 6) * triangleSize,
              width = svg.clientWidth,
              height = svg.clientHeight;

            var circleCont = d3.select(svg)
              .append('svg:g')
              .attr('class', 'timeProgressThumb')
              .attr('width', width)
              .attr('height', height)
              //.attr("transform", "rotate(90, 250, 250)")
              .append("svg:polygon")
              .attr('stroke', 'black')
              .attr("points", width / 2 + "," + radius + " " + ((width / 2) + (triangleSize / 2)) + "," + (triHeight + radius) + " " + ((width / 2) - (triangleSize / 2)) + "," + (triHeight + radius));
          };


*/

