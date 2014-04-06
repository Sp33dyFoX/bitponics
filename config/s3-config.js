var awsConfig = require('./aws-config');

module.exports = {
	key : awsConfig.key,
	secret : awsConfig.secret,
	bucket : "bitponics",
	bucketCDN : "bitponics-cdn",
	photoPathPrefix : "photos/"	+ (process.env.NODE_ENV === 'production' ? '' : 'test/'),
  cloudFrontEndpoint : 'd1hhgm2blhd45d.cloudfront.net'
}

console.log('s3-config', module.exports)
