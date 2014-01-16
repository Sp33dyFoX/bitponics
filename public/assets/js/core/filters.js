define(['angular', 'fe-be-utils', 'throttle-debounce'], 
	function(angular, feBeUtils) { 
		'use strict';
		
		var bpnFilters = angular.module('bpn.filters', []); 

		
		bpnFilters.filter('controlValueToWord', function() {
      return function(input, lowercase) {
        var out = "";
        if(parseInt(input, 10) === 0){
          out += "Off";
        } else {
          out += "On"
        }
        // conditional based on optional argument
        if (lowercase) {
          out = out.toLowerCase();
        }
        return out;
      }
    });

    
    bpnFilters.filter('friendlyDate', function() {
      return function(input, format) {
        if (!input) { return ''; }
        
        var val = moment(input).calendar();

        if (format === 'lowercase'){
          return val.charAt(0).toLowerCase() + val.slice(1);  
        } else {
          return val.charAt(0).toUpperCase() + val.slice(1);  
        }
        
      }
    });


    bpnFilters.filter('sensorValueDisplay', function() {
      return function(input) {
        if (typeof input === 'undefined' || input === null) {
          return "----"
        } else {
          return input;
        }
      }
    });

    
    bpnFilters.filter('photoDate', function() {
      return function(input) {
        var val = moment(input).format("MMMM Do YYYY, h:mm a");
        return val;
      }
    });


    bpnFilters.filter('notificationDate', function() {
      return function(notification) {
        var date = notification.timeToSend || notification.sentLogs[0].timestamp,
          val = moment(date).calendar();
        return val.charAt(0).toUpperCase() + val.slice(1);
      }
    });


    bpnFilters.filter('timeOfDayFromMilliseconds', function() {
      return function(input) {
        return feBeUtils.getTimeOfDayFromMilliseconds(input);
      };
    });


    bpnFilters.filter('valueRangeDisplay', function() {
      return function(valueRange) {
        var result = '';
        
        if (!valueRange){
          return "----";
        }

        if (typeof valueRange.min !== 'undefined'){
          result += valueRange.min;
        }
        result += " - ";
        if (typeof valueRange.max !== 'undefined'){
          result += valueRange.max;
        }
        return result;
      };
    });
    


		return bpnFilters;
	}
);
