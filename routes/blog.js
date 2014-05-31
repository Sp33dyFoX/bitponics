var path    = require('path'),
  express    = require('express'),
  winston = require('winston'),
  getenv = require('getenv');
  
module.exports = function(app){
  
  /**
   * Blog
   */

  if (getenv.bool('BPN_BLOG_ENABLED', false)){
    winston.info("ENABLING BLOG");
    app.use('/blog', express.static(__dirname + '/../blog/public'));
  }
  
};
