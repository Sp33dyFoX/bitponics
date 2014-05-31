module.exports = function(config) {
  config.set({
    files : [
      //deps for tests
      'public/assets/js/libs/angular/1.2.9/angular.min.js',
      'public/assets/js/libs/angular/1.2.9/angular-route.min.js',
      'public/assets/js/libs/angular/1.2.9/angular-animate.min.js',
      { pattern: 'public/assets/js/libs/jquery-1.8.2.min.js', watched: false, served: true, included: true }, //jquery
      { pattern: 'test/front-end/libs/jasmine-jquery.js', watched: false, served: true, included: true }, //jasmine-jquery

      { pattern: 'public/assets/js/libs/**/*.js', included: false },
      { pattern: 'public/assets/js/**/*.js', included: false },

      { pattern: 'test/front-end/fixtures/**/*.html', served: true, watched: true, included: false }, //fixtures
      { pattern: 'test/front-end/fixtures/*.js', included: false }, //js fixtures
      { pattern: 'test/front-end/**/*Spec.js', included: false}, //unit tests

      'test/front-end/test-main.js' //main for tests
    ],
    basePath: '../..',
    frameworks: ['jasmine', 'requirejs'],
    reporters: ['progress', 'html'],
    htmlReporter: {
      outputFile: 'test/front-end/unit-test-results.html'
    },
    preprocessors: {
      '**/*.html': []
    },
    browsers: ['Chrome'],
    // browsers: ['PhantomJS'],
    autoWatch: false,
    singleRun: false,
    colors: true
  });
};
