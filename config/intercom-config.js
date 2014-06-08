var getenv = require('getenv');

module.exports = {
	secretKey : getenv('BPN_INTERCOM_KEY', false)
};
