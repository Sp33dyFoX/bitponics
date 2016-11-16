#! /usr/bin/env node



var childProcess = require('child_process');

var running = false,
    queued = false;

var fs = require("fs");


var runTests = function(){
  if (!running){
    running = true;

    console.log("Starting new test run at " + (new Date()).toLocaleTimeString());
    childProcess.exec('npm test', { stdio : "inherit"}, function(err, stdout, stderr){
      console.log(stdout);
      console.log("Ended test run at " + (new Date()).toLocaleTimeString());
      running = false;
      if (queued) {
        queued = false;
        runTests();
      }
    });
  } else {
    queued = true;
  }
};


fs.watch("./models",function(event,file) {
  runTests();
});

fs.watch("./models/growPlan",function(event,file) {
  runTests();
});

fs.watch("./test",function(event,file) {
  runTests();
});

fs.watch("./i18n",function(event,file) {
  runTests();
});

fs.watch("./lib",function(event,file) {
  runTests();
});

fs.watch("./config",function(event,file) {
  runTests();
});

runTests();


/*
var spawn = require('child_process').spawn;
var testRunner = spawn('npm test');


testRunner.stdout.on('data', function (data) {
  console.log(data);
});

testRunner.stderr.on('data', function (data) {
  console.log('test-runner stderr: ' + data);
});

testRunner.on('close', function (code) {
  if (code !== 0) {
    console.log('test-runner process exited with code ' + code);
  }
});
*/