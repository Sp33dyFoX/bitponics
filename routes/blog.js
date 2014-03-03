var path    = require('path'),
  express    = require('express'),
  winston = require('winston');
  
module.exports = function(app){
  
  /**
   * Blog
   */
  app.use('/blog', express.static(__dirname + '/../blog/public'));
};
