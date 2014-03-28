require([
  'angular',
  'domReady',
  'angularResource',
  'es5shim',
  'angularUI',
  'bpn.services.socket',
  'angular-mask',
  'bpn'
],
function (angular, domReady) {
  'use strict';

  var setupApp = angular.module('bpn.apps.setup', ['bpn', 'ui.mask', 'ngResource']);



  setupApp.controller('bpn.controllers.setup.Main',
    [
      '$scope',
      '$filter',
      '$http',
      'bpn.services.socket',
      function ($scope, $filter, $http, socket) {
        $scope.serialServiceURL = undefined;
        $scope.serial = "";
        $scope.key = undefined;
        $scope.socket = socket;
        $scope.serialMask = "**-***-****";
        $scope.maskedSerial;

        $scope.$watch('serial', function(){
          $scope.maskedSerial = $('#serial')[0].value.substring(0, 11);
        });

        $scope.getStarted = function(){
          $scope.getStartedClicked = true;
        };

        $scope.sendSerialToServer = function() {
          $http.post(
            "/setup", 
            { 
              'serial': $scope.maskedSerial 
            }
          )
          .success(function (data) {
            if (typeof data === 'string'){
              data = JSON.parse(data);
            }
            $scope.key = data.combinedKey;
          });
        };

        $scope.openWifiPairingPage = function() {
          window.open('http://' + bpn.pageData.nextUrl, "_blank");

          $scope.pairingPending = true;

          $scope.socket.connect('/setup');
          $scope.socket.on('connect', function(){
            $scope.socket.emit('ready', { "serial" : $scope.serial } );
          });
          $scope.socket.on('keys', function (keys) {
            keys.forEach(function(key){
              if (key.serial === $scope.maskedSerial && key.verified){
                $scope.pairingComplete = true;
                $scope.socket.disconnect();
              }
            });
          });
          
        };

      }
    ]
  );

  

  domReady(function () {
    angular.bootstrap(document, ['bpn.apps.setup']);
  });

});
