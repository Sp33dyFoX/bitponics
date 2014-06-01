/*
 * File we've designated to contain root-level hooks.
 *
 * Filename doesn't matter; Mocha will detect the root-level methods
 * in any test file and execute as expected
 *
 * http://visionmedia.github.com/mocha/, search for '“root” level hooks'
 */
var mongooseConnection = require('../../config/mongoose-connection').open('test'),
    exec = require('child_process').exec,
    winston = require('winston'),
    sinon = require('sinon');


/*
 * before Method
 *
 * The before method will execute every time Mocha is run. This
 * code will not run every time an individual test is run.
 */
 before(function(done){
    // Stub email sender
    sinon.stub(require("nodemailer"), "createTransport", function(){
      console.log('returning mock nodemailer.createTransport')
      return {
        sendMail : function(options, callback){
          console.log('calling mock sendMail')
          return callback();
        }
      }
    });

    


    // Connecting to a local test database or creating it on the fly
    exec('db_init test clear', 
      function (error, stdout, stderr){
        // if (error) { console.log(error); return done(new Error(error));}
        // if (stderr) { console.log(stderr); return done(new Error(stderr));}
        return done();
      }
    );
  }
);

/*
 * after Method
 *
 * Just like the before, after is run after Mocha has completed
 * running its queue.
 */
 after(function(done){
  mongooseConnection.close();
  done();
 });
