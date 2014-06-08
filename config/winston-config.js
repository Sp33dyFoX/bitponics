var winston = require('winston'),
  nodemailer = require('nodemailer'),
  getenv = require('getenv'),
  awsConfig = require('./aws-config'),
  loggly = {
    subdomain : 'bitponics',
    token : getenv('BPN_LOGGLY', false)
  };

module.exports = function(env){
  winston.cli();
  winston.exitOnError = false;

  
  if (getenv.bool('BPN_EMAIL_ON_ERRORS', false)){
    winston.add(require('winston-nodemailer'), {
      to: "engineering@bitponics.com",
      from: "notifications@bitponics.com",
      level: 'error',
      handleExceptions : true,
      transport : nodemailer.createTransport("SES", { 
        'AWSAccessKeyID': awsConfig.key,
        'AWSSecretKey': awsConfig.secret
      })
    });
  }

  winston.add(require('winston-loggly').Loggly, {
    subdomain : loggly.subdomain,
    inputToken : loggly.token,
    level : 'error',
    handleExceptions: true
  });

  return winston;
};
