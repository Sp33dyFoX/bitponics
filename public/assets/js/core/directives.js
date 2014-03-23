/**
 * Create top-level directives module
 * 
 * Include common shared directives
 */
define(['angular', 'jquery', 'throttle-debounce'], 
  function(angular, $) { 
    'use strict'; 
    var bpnDirectives = angular.module('bpn.directives', []);


    // http://stackoverflow.com/a/15253892/117331
    bpnDirectives.directive('bpnDirectivesUppercase', function() {
      return {
        priority: 200, // give it higher priority than the input mask
        require: 'ngModel',
        link: function(scope, element, attrs, modelCtrl) {
          var uppercase = function(inputValue) {
            var upperCased = inputValue.toUpperCase();
            if(upperCased !== inputValue) {
              modelCtrl.$setViewValue(upperCased);
              modelCtrl.$render();
            }         
            return upperCased;
          };
          modelCtrl.$parsers.push(uppercase);
          uppercase(scope[attrs.ngModel]); 
        }
      };
    });

    bpnDirectives.directive('bpnDirectivesPixelsToEms',
      [
        '$window',
        // 'sharedDataService',
        // function($window, sharedDataService) {
        function($window) {
          return {
            controller: [
              '$scope',
              function ($scope){
                // $scope.sharedDataService = sharedDataService;
              }
            ],
            link: function(scope, element) {
              var win = angular.element($window);
              var pixels = element[0].clientWidth;
              var scopeTest = angular.element('<div style="display: none; font-size: 1em; margin: 0; padding:0; height: auto; line-height: 1; border:0;">&nbsp;</div>').appendTo(element);
              var scopeVal = scopeTest.height();
              
              scopeTest.remove();
              // scope.sharedDataService.ems = scope.ems = (pixels / scopeVal).toFixed(8);
              scope.ems = (pixels / scopeVal).toFixed(8);
              
              win.bind('resize', function(){
                // scope.sharedDataService.ems = scope.ems = (element[0].clientWidth / scopeVal).toFixed(8);
                scope.ems = (element[0].clientWidth / scopeVal).toFixed(8);
                scope.$apply();
              });
            }
          };
        }
      ]
    );

    bpnDirectives.directive('bpnDirectivesSelectOnClick', function () {
      return function (scope, element, attrs) {
          element.click(function () {
              element.select();
          });
      };
    });


    bpnDirectives.directive('bpnDirectivesIfThumbnail404', function() {
      return {
        link: function(scope, element, attrs) {
          element.bind('error', function() {
            element.attr('src', attrs.ifThumbnail404);
          });
        }
      }
    });


    bpnDirectives.directive('bpnDirectivesSmartOverlay', [
      '$window',
      '$timeout',
      function($window, $timeout) {
        return {
          controller: [
            '$scope', '$element', '$attrs', '$transclude', '$http', 'sharedDataService',
            function ($scope, $element, $attrs, $transclude, $http, sharedDataService){
              $scope.$watch('sharedDataService.activeOverlay', function (newVal, oldVal) {
                $scope.sharedDataService.activeOverlayPositionTop = angular.element($window)[0].scrollY;
                if ($scope.sharedDataService.activeOverlay){
                  $scope.setOverlayPosition();
                }
              });

              $scope.setOverlayPosition = function() {
                $.throttle(1000, $timeout(function() {
                  var overlay = $element.parents('.page:first').siblings('.overlay:first'),
                      overlayHeight = overlay.height(),
                      topValue = $scope.sharedDataService.activeOverlayPositionTop,
                      windowHeight = angular.element($window).height(),
                      padding = 16;
                  if (overlay.length > 0) {
                    if ((windowHeight > overlayHeight + padding)) {
                      overlay.css({ top: topValue + padding });
                      $scope.$apply(); 
                    }
                  }
                }, 500));
              };

            }
          ],
          link: function(scope, element, attrs, controller) {
            angular.element($window).bind("scroll", function() {
              if (scope.sharedDataService.activeOverlay){
                scope.sharedDataService.activeOverlayPositionTop = this.scrollY;
                scope.setOverlayPosition();
              }
            });
          }
        };
      }
    ]);

    
    bpnDirectives.directive('bpnDirectivesIntercomTrigger', [
      '$timeout',
      function($timeout) {
        return {
          link: function(scope, element, attrs) {
            // TODO: this isn't working. investigate
            $timeout(function(){
              element.addClass('.intercom-trigger');
              window.Intercom('reattach_activator');
            }, 10);
          }
        }
      }
    ]);


    /** 
     * This overrides the default contenteditable to be one that can be bound to ng-model
     * 
     * Taken from http://docs.angularjs.org/api/ng.directive:ngModel.NgModelController
     * with the following changes:
     * - prevent assigning of <br> by default
     * - prevent automatic read() on creation
     * - on focus, select all text
     */
    bpnDirectives.directive('contenteditable', function() {
      return {
        restrict: 'A', // only activate on element attribute
        require: '?ngModel', // get a hold of NgModelController
        link: function(scope, element, attrs, ngModel) {
  
          if(!ngModel) return; // do nothing if no ng-model
  
          // Specify how UI should be updated
          ngModel.$render = function() {
            element.html(ngModel.$viewValue || '');
          };
   
          element.on('focus', function() {
            // selection needs to be done after a timeout so document 
            // has a chance to register this element as focused
            setTimeout(function(){
              document.execCommand('selectAll', false, null);
            }, 10);
          });

          // Listen for change events to enable binding
          element.on('blur keyup', function() {
            scope.$apply(read);
          });
          
          // Write data to the model
          function read() {
            var html = element.html();
            // When we clear the content editable the browser leaves a <br> behind
            if( html == '<br>' ) {
              html = '';
            }
            ngModel.$setViewValue(html);
          }
        }
      };
    });


    /**
     * Assumes growPlan.plants is an array of plant id's (not populated plant objects)
     * 
     * Dependent on following globals:
     * - bpn.plants
     */
    bpnDirectives.directive('bpnDirectivesGrowPlanPhotoGrid', function() {
      return {
        template : '<div class="img-wrapper"></div>',
        replace : true,
        controller : [
          '$scope', '$element', '$attrs', '$transclude',
          function ($scope, $element, $attrs, $transclude){
            $scope.photoTemplate = '<div class="plant-grid-image {{className}}" style="background-image:url(//s3.amazonaws.com/bitponics-cdn/assets/img/plants/{{plantId}}.jpg);"></div>';
            $scope.generatePhoto = function(plant, className){
              return $scope.photoTemplate.replace('{{className}}', className).replace('{{plantId}}', plant);
            }
          }
        ],
        link: function(scope, element, attrs) {
          var growPlan = scope.growPlan,
              plants = growPlan.plants,
              length = plants.length,
              i;
          
          // breakpoints
          // 0 (All-Purpose Grow Plan)
          // 1 (show single image)
          // >1, <=4 (show grid of 4, repeating to fill if <4)
          // >4 (show grid of 8 max, repeat to fill)
          if (!plants || (length === 0) ){
            // means it's the All-Purpose
            // to append the "b":
            //element.append('<div class="icon-glyph icon-__62_logo_00e36c"></div>');
            element.addClass('grid-16');
            for (i = 1; i <= 16; i++){
              element.append(scope.generatePhoto(bpn.plants[i%bpn.plants.length]._id));  
            }
            
          } else if (length === 1){ 
            element.append(scope.generatePhoto(plants[0]));
          } else if (length <= 4) {
            element.addClass('grid-4');
            for (i = 1; i <= 4; i++){
              element.append(scope.generatePhoto(plants[i%length]));  
            }
          } else {
            element.addClass('grid-16');
            for (i = 1; i <= 16; i++){
              element.append(scope.generatePhoto(plants[i%length]));  
            }
          }
        }
      }
    });

    /**
     * Assumes growPlan.plants is an array of plant id's (not populated plant objects)
     * 
     * Dependent on following globals:
     * - bpn.plants
     */
    bpnDirectives.directive('bpnDirectivesGardenPhotoGrid', function() {
      return {
        template : '<div bpn-directives-grow-plan-photo-grid></div>',
        // replace : true,
        controller : [
          '$scope', '$element', '$attrs', '$transclude',
          function ($scope, $element, $attrs, $transclude){
            $scope.growPlan = $scope.garden.growPlan;
          }
        ],
        // link: function(scope, element, attrs) {
        //   console.log('scope');
        //   element.append("<div bpn-directives-grow-plan-photo-grid></div>");
          
        // }
        
      }
    });


    return bpnDirectives;
  }
);
