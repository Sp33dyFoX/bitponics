require([
  'angular',
  'domReady',
  'moment',
  'fe-be-utils',
  'angularResource',
  'angularRoute',
  'es5shim',
  'angularUI',
  'angularUIBootstrap',
  'bpn',
  'bpn.services.plant',
  'bpn.directives.fileUpload',
  'lvl.directives.fileUpload'
],
  function (angular, domReady, moment, feBeUtils) {
    'use strict';

    var app = angular.module('bpn.apps.admin.plants', ['bpn', 'ui', 'ui.bootstrap', 'lvl.directives.fileupload', 'ngRoute']);

    app.factory('sharedDataService',
      [
        // '$q',
        function(){
          var sharedData = {
            
            uploadCallback: function(id) {
              console.log(id);
              this.newPlant.photo = id;
            }

          };
          return sharedData
        }
      ]
    );

    app.controller('bpn.controllers.admin.plants.AddPlant',
      [
        '$scope',
        '$http',
        '$q',
        'PlantModel',
        'sharedDataService',
        '$window',
        function ($scope, $http, $q, PlantModel, sharedDataService, $window) {
          $scope.sharedDataService = sharedDataService;
          $scope.newPlant = { name: '' };
          $scope.submitted = false;

          $scope.setCurrentPlant = function(plant) {
            $scope.sharedDataService.newPlant = $scope.newPlant = plant;
          };

          $scope.clear = function() {
            $window.location.reload();
          };

          $scope.submit = function() {
            if ($scope.newPlant.name) {
              console.log($scope.newPlant.name);
              var plantToAdd = new PlantModel($scope.newPlant);
              plantToAdd.$save(function(data){
                console.log('saved', data);
                $scope.submitted = true;
                $scope.sharedDataService.newPlant = $scope.newPlant = plantToAdd;
              });
            }
          };
        }
      ]
    );

    app.controller('bpn.controllers.admin.plants.Main',
      [
        '$scope',
        '$http',
        '$q',
        'PlantModel',
        'sharedDataService',
        function ($scope, $http, $q, PlantModel, sharedDataService) {
          $scope.sharedDataService = sharedDataService;
          $scope.plants = bpn.pageData.plants.map(function(plant){
            return new PlantModel(plant);
          });
          $scope.cdnURL = bpn.pageData.cdnURL;
          $scope.photoPathPrefix = bpn.pageData.photoPathPrefix;
        }
      ]
    );

    domReady(function () {
      angular.bootstrap(document, ['bpn.apps.admin.plants']);
    });
  }
);
