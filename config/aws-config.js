var getenv = require('getenv');

module.exports = {
	key        : getenv('BPN_AWS_KEY', false),
  secret     : getenv('BPN_AWS_SECRET', false)
};
