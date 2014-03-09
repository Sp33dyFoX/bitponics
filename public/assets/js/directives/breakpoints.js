define(['bpn.directives'],
  function (bpnDirectives) {
   
   /*
    * Breakpoints
    * - Find media queries defined in page CSS
    *
    *
    * Depends on following globals:
    * 
    */
    bpnDirectives.directive('breakpoints', 
      [
        'sharedDataService',
        function(sharedDataService) {
          return {
            restrict:'EA',
            controller: function ($scope, $element, $attrs) {
              $scope.sharedDataService = sharedDataService;
              $scope.sharedDataService.breakpoints = []; 
              $scope.regex = {
                  media: /@media[^\{]+\{([^\{\}]*\{[^\}\{]*\})+/gi
              }; //from scott jehl https://github.com/scottjehl/Respond/blob/master/src/respond.js
            },
            link: function (scope, element, attrs) {
              var ss = document.styleSheets,
                  mediaQuery,
                  added = {};
                  
              for (var i = 0; i < ss.length; i++){
                for (var j = 0; j < ss[i].cssRules.length; j++) {
                  console.log(ss[i].cssRules[j].cssText.match(scope.regex.media));
                  debugger;
                  if (ss[i].cssRules[j].cssText.match(scope.regex.media)) {
                      mediaQuery = ss[i].cssRules[j].cssText.match(scope.regex.media)[0].split('{')[0].trim();
                      debugger;
                      if (!added[mediaQuery]) {
                        added[mediaQuery] = true;
                        // scope.breakpoints.push(mediaQuery);
                        scope.sharedDataService.breakpoints.push(mediaQuery);
                      }
                  }
                }
              }
            }
          }
        }
      ]
    );


  }
);
