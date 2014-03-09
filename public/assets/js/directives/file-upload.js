define(['angular', 'bpn.directives', 'drop', 'lvl.directives.fileUpload'],
  function (angular, bpnDirectives, Drop) {
    
    // bpnDirectives.config(['lvl.directives.fileupload', function(){}]);
    
    bpnDirectives.directive('bpnDirectivesFileUpload', 
      [
        function() {
          return {
            restrict : "EA",
            scope : {
              uploadUrl : "=",
              sharedDataService : "="
            },
            controller : [
              '$scope', '$element', '$attrs', '$transclude',
              function ($scope, $element, $attrs, $transclude){
                console.log('$scope.sharedDataService', $scope.sharedDataService);
                console.log('bpnDirectivesFileUpload $scope.uploadUrl', $scope.uploadUrl);
                
                $scope.uploadInProgress = false;

                $scope.progress = function(e){
                  $scope.uploadInProgress = true;
                  console.log('progress', e);
                };
                
                $scope.error = function(files, type, msg) {
                  console.log("Upload error: " + msg);
                  console.log("Error type:" + type);
                  
                  $scope.uploadInProgress = false;

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
                  // $scope.logFiles(files);

                  var errorDisplay = new Drop({
                    target: $element[0],
                    content: errorMessage,
                    position: 'top center',
                    openOn: null,
                    classes: 'drop-theme-arrows drop-theme-error'
                  });

                  errorDisplay.on('close', function(){
                    console.log('errorDisplay closed');
                    errorDisplay.tether.destroy();
                    angular.element(errorDisplay.drop).remove();
                    errorDisplay = undefined;
                  });

                  errorDisplay.open();

                  angular.element(document).one('click touchstart', function(){
                    errorDisplay.close();
                  });
                };

                $scope.done = function(files, data){
                  $scope.uploadInProgress = false;
                  console.log('bpnDirectivesFileUpload done', files, data);
                };
              }
            ],
            template : 
              '<img class="spinner" src="/assets/img/spinner.svg" ng-show="uploadInProgress" />' + 
              '<lvl-file-upload' +
              ' ng-hide="uploadInProgress"' + 
              ' auto-upload="true"' + 
              ' choose-file-button-text=""' + 
              ' upload-url="{{uploadUrl}}"' + 
              ' max-files="5"' + 
              ' max-file-size-mb="5"' + 
              ' get-additional-data="getData(files)"' + 
              ' on-done="done(files, data)"' + 
              ' on-progress="progress(percentDone)"' + 
              ' on-error="error(files, type, msg)"' + 
              '></lvl-file-upload>',
            link : function(scope, element, attrs, controller) {}
          }
        }
      ]
    );
  } 
);
