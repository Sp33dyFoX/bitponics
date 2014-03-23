/**
 * Depends on following globals:
 * - bpn.user
 *
 * @module controllers/nav
 * 
 */
define(
  [
    'angular',
    'bpn.controllers',
    'fe-be-utils',
    'bpn',
    'angularResource',
    'bpn.services.nav',
    'bpn.services.user',
    'bpn.services.notification',
    'bpn.services.socket',
    'angularDialog'
  ],
  function (angular, bpnControllers, feBeUtils) {
    'use strict';

    var notificationsController = bpnControllers.controller('bpn.controllers.nav.Notifications',
      [
        '$scope',
        '$filter',
        '$compile',
        'UserModel',
        'NotificationModel',
        'NavService',
        function ($scope, $filter, $compile, UserModel, NotificationModel, NavService) {
          
          $scope.NavService = NavService;

          $scope.recentNotifications = $scope.NavService.recentNotifications;// $scope.$parent.ngDialogData;
          $scope.element = $scope.$parent.ngDialogElement;
          //console.log('gettin in here', $scope, $scope.element, $scope.recentNotifications)

          $scope.getNotificationClass = function(notification){
            var classNames = ['notification'];
            
            if (notification.checked){
              classNames.push('checked');
            } else {
              if (notification.type === feBeUtils.NOTIFICATION_TYPES.ACTION_NEEDED || notification.type === feBeUtils.NOTIFICATION_TYPES.ERROR){
                classNames.push('warning');  
              }
            }
            return classNames;
          };

          $scope.markAsChecked = function(notification){
            console.log('$scope.markAsChecked', notification);
            NotificationModel.markAsChecked(notification);
          };

          $scope.$on("$destroy", function(e){
            console.log('destroying notifications controller');
            
            // TODO : as an automatic action, we actually only want to clear the info notifications
            // Clearing all for now as temp hack
            NavService.clearAllNotifications();
            //NavService.clearInfoNotifications();

          });
        }
      ]
    );


    var menuController = bpnControllers.controller('bpn.controllers.nav.Menu',
      [
        '$scope',
        '$filter',
        '$compile',
        'NavService',
        function ($scope, $filter, $compile, NavService) {
          $scope.NavService = NavService;
          $scope.log('bpn.controllers.nav.Menu initialized')
        }
      ]
    );

    var mainController = bpnControllers.controller('bpn.controllers.nav.Main',
      [
        '$scope',
        '$filter',
        '$compile',
        'NavService',
        'UserModel',
        'ngDialog',
        'bpn.services.socket',
        function ($scope, $filter, $compile, NavService, UserModel, ngDialog, socket) {
          // init
          $scope.settingsDisplayVisible = false;
          $scope.navMenuDisplayVisible = false;

          //set show/hide of nav based on $mq_medium
          $scope.$on('match', function(event, mq) {
            if (mq === '$mq_medium') $scope.navMenuDisplayVisible = true;
          });
          $scope.$on('unmatch', function(event, mq) {
            if (mq === '$mq_medium') $scope.navMenuDisplayVisible = false;
          });

          $scope.socket = socket;
          $scope.NavService = NavService;

          $scope.toggleSettings = function(){
            $scope.settingsDisplayVisible = !$scope.settingsDisplayVisible;
            NavService.openGardenSettingsOverlay = false;
          };

          $scope.toggleNavMenu = function(){
            $scope.navMenuDisplayVisible = !$scope.navMenuDisplayVisible;
          };

          $scope.openGardenSettingsOverlay = function() {
            NavService.openGardenSettingsOverlay = true;
          };


          $scope.getNotificationsIconClass = function(){
            var classNames = ['icon-glyph notifications-icon'];
            if ($scope.hasUncheckedActionNeededNotifications){
              classNames.push('icon_notification_warning');
            } else if ($scope.hasUncheckedNotifications){
              classNames.push('icon_notification_info_textGray');
            } else {
              classNames.push('icon_notification_info_textGray');
            }
            return classNames;
          };

          $scope.$watch('NavService.recentNotifications', function(){
            $scope.recentNotifications = NavService.recentNotifications;
            $scope.hasUncheckedNotifications = NavService.hasUncheckedNotifications;
            $scope.hasUncheckedActionNeededNotifications = NavService.hasUncheckedActionNeededNotifications;
          });

          $scope.log('bpn.controllers.nav.Main initialized')
        }
      ]
    );

    return mainController;
  }
);
