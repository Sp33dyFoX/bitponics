var getenv = require('getenv');

module.exports = function(app){
	var token = getenv('BPN_MIXPANEL_KEY', false);
  
  // Expose mixpanel token to views
  app.locals.mixpanelToken = token;

  return token;
};
