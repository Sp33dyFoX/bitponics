#! /usr/bin/env node

var environments = ['production'], //['development','staging','production'],
    childProcess = require('child_process'),
    childProcesses = [],
    winston = require('./config/winston-config')('worker');
    

environments.forEach(function(env){
	winston.info('Starting child worker process for ' + env);	
	childProcesses.push(childProcess.spawn('./worker-process.js', [env], { stdio : "inherit"}));
});


process.on('exit', function() {
    console.log('About to exit.');

    childProcesses.forEach(function(childProc){
        childProc.kill();
    });

    console.log('Killed all child processes.');
});