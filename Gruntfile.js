module.exports = function(grunt) {

  grunt.loadNpmTasks('grunt-karma');
  grunt.loadNpmTasks('grunt-shell');
  grunt.loadNpmTasks('grunt-open');
  grunt.loadNpmTasks('grunt-contrib-connect');
  grunt.loadNpmTasks('grunt-contrib-watch');
  grunt.loadNpmTasks('grunt-contrib-concat');
  grunt.loadNpmTasks('grunt-protractor-runner');
  grunt.loadNpmTasks('grunt-shell-spawn');
  grunt.loadNpmTasks('grunt-jsdoc');
  grunt.loadNpmTasks('grunt-ngdocs');

  grunt.initConfig({
    shell: {
      options: {
        stdout: true
      },
      selenium: {
        command: './selenium/start',
        options: {
          stdout: false,
          async: true
        }
      },
      protractor_install: {
        command: 'node ./node_modules/protractor/bin/install_selenium_standalone'
      },
      npm_install: {
        command: 'npm install'
      },
      bower_install: {
        command: 'node ./node_modules/bower/bin/bower install'
      },
    },

    connect: {
      options: {
        base: 'app/'
      },
      webserver: {
        options: {
          port: 8888,
          keepalive: true
        }
      },
      devserver: {
        options: {
          port: 8888
        }
      },
      testserver: {
        options: {
          port: 9999
        }
      },
      coverage: {
        options: {
          base: 'coverage/',
          port: 5555,
          keepalive: true
        }
      }
    },

    protractor: {
      options: {
        keepAlive: false,
        configFile: "./test/front-end/protractor.conf.js"
      },
      singlerun: {},
      auto: {
        keepAlive: true,
        options: {
          args: {
            seleniumPort: 4444
          }
        }
      }
    },

    concat: {
      styles: {
        dest: './app/assets/app.css',
        src: [
          'app/styles/app.css',
          //place your Stylesheet files here
        ]
      },
      scripts: {
        options: {
          separator: ';'
        },
        dest: './app/assets/app.js',
        src: [
          'lib/angular-1.2.0-rc.2/angular.js',
          'lib/angular-1.2.0-rc.2/angular-route.js',
          'app/scripts/homePages.js',
          'app/scripts/app.js',
          //place your JavaScript files here
        ]
      },
    },

    watch: {
      options : {
        livereload: 7777
      },
      assets: {
        files: ['app/styles/**/*.css','app/scripts/**/*.js'],
        tasks: ['concat']
      },
      protractor: {
        files: ['app/scripts/**/*.js','test/front-end/e2e/**/*.js'],
        tasks: ['protractor:auto']
      }
    },

    open: {
      devserver: {
        path: 'http://localhost:8888'
      },
      coverage: {
        path: 'http://localhost:5555'
      }
    },

    karma: {
      unit: {
        configFile: './test/front-end/karma-unit.conf.js',
        autoWatch: false,
        singleRun: true
      },
      unit_auto: {
        configFile: './test/front-end/karma-unit.conf.js',
        autoWatch: true,
        singleRun: false
      },
      unit_coverage: {
        configFile: './test/front-end/karma-unit.conf.js',
        autoWatch: false,
        singleRun: true,
        reporters: ['progress', 'coverage'],
        preprocessors: {
          'app/scripts/*.js': ['coverage']
        },
        coverageReporter: {
          type : 'html',
          dir : 'coverage/'
        }
      },
    },

    ngdocs: {
      options: {
        dest: 'docs'
      },
      models: {
        src: ['models/**/*.js'],
        title: 'Tutorial'
      }
    },

    jsdoc: {
      dist : {
        src : ['models/**/*.js'],
        options: {
          destination: 'docs'
        }
      }
    }
  });

  //single run tests
  grunt.registerTask('test', ['test:unit', 'test:e2e']);
  grunt.registerTask('test:unit', ['karma:unit']);
  grunt.registerTask('test:e2e', ['connect:testserver','protractor:singlerun']);

  //autotest and watch tests
  grunt.registerTask('autotest', ['karma:unit_auto']);
  grunt.registerTask('autotest:unit', ['karma:unit_auto']);
  grunt.registerTask('autotest:e2e', ['connect:testserver','shell:selenium','watch:protractor']);

  //coverage testing
  grunt.registerTask('test:coverage', ['karma:unit_coverage']);
  grunt.registerTask('coverage', ['karma:unit_coverage','open:coverage','connect:coverage']);

  //installation-related
  grunt.registerTask('install', ['update','shell:protractor_install']);
  grunt.registerTask('update', ['shell:npm_install','shell:bower_install']);

  grunt.registerTask('doc', ['jsdoc']);

  //defaults
  grunt.registerTask('default', ['dev']);

  //development
  grunt.registerTask('dev', ['update', 'concat', 'connect:devserver', 'open:devserver', 'watch:assets']);
  
  //server daemon
  grunt.registerTask('serve', ['connect:webserver']);
};
