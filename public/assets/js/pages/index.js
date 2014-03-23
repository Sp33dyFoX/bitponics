/* Home Page */

require([
  'angular',
  'domReady',
  'scrollto',
  'localscroll',
  'es5shim',
  'utils',
  'flexslider',
  'throttle-debounce',
  'angular-flexslider',
  'bpn',
  'bpn.directives.breakpoints'
],
function (angular, domReady) {
  'use strict';

  var homePageApp = angular.module('bpn.apps.homepage', ['bpn', 'angular-flexslider']);
  
  homePageApp.factory('sharedDataService', 
      [
        function(){
          
          /**
           * All the properties this service will expose
           */ 
          var sharedData = {};

          return sharedData;
        }
      ]
  );

  homePageApp.controller('bpn.controllers.homepage.Main',
    [
      '$scope',
      'sharedDataService',
      function ($scope, sharedDataService) {
        $scope.sharedDataService = sharedDataService;
        // $scope.$on('match', function(event, data) {
        //   console.log('$on data =>', event);
        //   console.log(data);
        // });
      }
    ]
  );

  domReady(function () {
    angular.bootstrap(document, ['bpn.apps.homepage']);
  });

  //TODO: not angularized yet
  bpn.pages.home = {
    
    MIN_SECTION_HEIGHT: 800,

    sectionPositions: [],

    screenHeight: undefined,
    screenWidth: undefined,

    init: function() {
      var self = this,
          screenHeight;

      //bring in separate pages
      bpn.utils.setupPages($('nav ul > li a:not([data-page-include="false"])'), function(){
        
        //match section height to window
        //create fixed nav
        self.screenWidth = $(window).width();
        self.screenHeight = screenHeight = $(window).height() > self.MIN_SECTION_HEIGHT ? $(window).height() : self.MIN_SECTION_HEIGHT;
        
        if(self.screenWidth > 700 && self.screenHeight < 1000){
          bpn.utils.sectionHeightAlign(self.MIN_SECTION_HEIGHT, '#main > .content-module');
        }

        //create fixed nav
        self.sectionNavSetup(screenHeight);

        //smooth anchor scrolling to sections
        $('nav a:not([data-page-include="false"])').localScroll({
            onAfter: function(target){
              history.pushState({'target': target.id}, target.id, target.id);
            },
            lazy: true 
          });

        //TODO: get back/forward working with localscroll
        // $(window).bind('popstate', function(e){
        //   console.log(e.originalEvent.state.target)
        //   if(e.originalEvent.state.target){
        //     $(window).scrollTo($('#'+e.originalEvent.state.target));
        //   }
        // });

        //get section top values so we know when scrolling to highlight nav item
        $('#main > .content-module').each(function(i){
          var id = $(this).attr('id'),
              top = $(this).position().top;

          //eval any page inline scripts (like Wufoo form scipt)
          $(this).find('div.script').each(function(){
            eval($(this).text())
          });


          self.sectionPositions[i] = { 'id': id, 'top': Math.floor(top) };

          
        });
      });

      //setup carousel
      // $('.flexslider').flexslider({
      //   animation: "slide",
      //   useCSS: true,
      //   slideshow: true,
      //   touch: true,
      //   directionNav: true,
      //   controlNav: false,
      //   //controlsContainer: '.flex-direction-nav',
      //   prevText: "",
      //   nextText: ""
      // });
      
      // //add prev/next icons
      // $('.flex-direction-nav .flex-prev').append('<i class="icon-glyph icon-glypharrow-2" aria-hidden="true"></i>')
      // $('.flex-direction-nav .flex-next').append('<i class="icon-glyph icon-glypharrow" aria-hidden="true"></i>')
      
    },

    sectionNavSetup: function(screenHeight) {
      var self = this,
          headerFixed = $('.header:first').clone()
                            .addClass('header-fixed')
                            .attr('style', '')
                            .css({ 'top': screenHeight })
                            .attr('id', 'header-fixed')
                            .insertAfter('#home'),
          originalStyles = headerFixed.attr('style');
      
      $(window).scroll($.throttle( 250, sectionNavHighlight));

      function sectionNavHighlight(event) {
        var y = self.scrollTop = $(this).scrollTop(),
            secPos = self.sectionPositions;
        console.log(y)
        console.log(self.screenHeight)
        if (y >= self.screenHeight) {
          
          console.log(y);

          // setTimeout(function(){
            // var closest = null;

            // $.each(theArray, function(){
            //   if (closest == null || Math.abs(this - goal) < Math.abs(closest - goal)) {
            //     closest = this;
            //   }
            // });
            var i = secPos.length;
            while(i--){
              console.log(y + ' >= '+secPos[i].top+': '+secPos[i].id)
              if(y >= secPos[i].top){
                console.log(secPos[i].id)
                $('.header-fixed li').removeClass('active');
                $('.header-fixed li[data-name='+secPos[i].id+']').addClass('active');
                break;
              }
            };
          // }, 0);
          
          headerFixed.attr('style', '').addClass('fixed');

        } else {

          headerFixed.attr('style', originalStyles).removeClass('fixed');

        }

      }
    }



  }

  $(function () {
    bpn.pages.home.init();
  });

});
