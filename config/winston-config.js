var winston = require('winston'),
  nodemailer = require('nodemailer'),
  getenv = require('getenv'),
  loggly = {
      subdomain : 'bitponics',
      tokens : {
        local : 'c8593ee1-8a09-426f-acd6-871b70b91fd0',
        development : '5cc07897-f3f8-46ab-aaa1-888f88ae6683',
        staging: 'fed14f46-e08e-43c5-b8c3-526c93c6f5fd',
        production : '437fee23-8d8a-4171-ab17-7e211c176003',
        worker : '62d435c3-412c-467c-ad55-2b1d5ce1cafb',
        ci : '2ea038cf-4f59-4f84-b29c-ec418f0ce0e2' // CircleCI 
      }  
    };

module.exports = function(env){
  winston.cli();
  winston.exitOnError = false;

  
  if (getenv.bool('BPN_EMAIL_ON_ERRORS')){
    winston.add(require('winston-nodemailer'), {
      to: "engineering@bitponics.com",
      from: "notifications@bitponics.com",
      level: 'error',
      handleExceptions : true,
      transport : nodemailer.createTransport("SES", require('./email-config').amazonSES.api)
    });
  }

  winston.add(require('winston-loggly').Loggly, {
    subdomain : loggly.subdomain,
    inputToken : loggly.tokens[env],
    level : 'error',
    handleExceptions: true
  });

  return winston;
};
