var awsConfig = require('./aws-config');
var getenv = require('getenv');

module.exports = {
	key : awsConfig.key,
	secret : awsConfig.secret,
	bucket : "bitponics",
	bucketCDN : "bitponics-cdn",
	photoPathPrefix : getenv('BPN_PHOTOPATHPREFIX', false),
  cloudFrontEndpoint : getenv('BPN_CLOUDFRONT_ENDPOINT', false)
}

console.log('s3-config', module.exports)
