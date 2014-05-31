/**
 * @module models/User 
 */

var mongoose = require('mongoose'),
	mongooseTypes = require('../lib/mongoose-types-wrapper'),
	mongoosePlugins = require('../lib/mongoose-plugins'),
	useTimestamps = mongoosePlugins.useTimestamps,
	Schema = mongoose.Schema,
	ObjectIdSchema = Schema.ObjectId,
	UserSchema = undefined,
	User = undefined,
	nodemailer = require('nodemailer'),
	crypto = require('crypto'),
	bcrypt = require('bcrypt'),
	winston = require('winston'),
	timezone = require('../lib/timezone-wrapper'),	
	EmailConfig = require('../config/email-config'),
	mongooseConnection = require('../config/mongoose-connection').defaultConnection,
	async = require('async'),
	requirejs = require('../lib/requirejs-wrapper'),
	feBeUtils = requirejs('fe-be-utils'),
	ejs = require('../config/ejs-config'),
	fs = require('fs'),
	path = require('path'),
	passport = require('passport'),
  	FacebookStrategy = require('passport-facebook').Strategy,
  
  // emailVariables is passed in by a function call later in the startup process
  emailVariables = {
    appDomain : undefined,
    appUrl : undefined,
    secureAppUrl : undefined
  },
  emailTemplates = require('email-templates'),
  emailTemplatesDir = path.join(__dirname, '/../views/emails'),
  welcomeEmailTemplateDirectory = path.join(__dirname, '/../views/emails/welcome'),
  compiledWelcomeEmailBody = {
    html :  ejs.compile(fs.readFileSync(path.join(welcomeEmailTemplateDirectory, "email-body-html.ejs"), 'utf8')),
    text : ejs.compile(fs.readFileSync(path.join(welcomeEmailTemplateDirectory, "email-body-text.ejs"), 'utf8'))
  };



/**
 * Internal schema used only for User. Created separately just to exclude
 * unnecessary _id prop
 */
var DeviceKeySchema = new Schema({
  /**
   * deviceId not required. We temporarily create & save unassociated deviceKeys
   * for use during the setup process
   */
  deviceId : { type: String, ref : 'Device', match: /^([a-z0-9_-]){12}$/, required : false },

  serial : { type : String },

  verified : { type : Boolean, default : false },

  verifiedDate : { type : Date },

  createdAt : { type : Date, default: Date.now },

  /**
   * Public device key is a 16-char random hex string
   */
  public : String,
  /**
   * Private device key is a 16-char random hex string
   */
  private : String

}, 
{ _id : false, id : false, toObject : { virtuals: true }, toJSON : { virtuals : true } });

DeviceKeySchema.virtual('combinedKey')
.get(function(){
	return this.public + feBeUtils.COMBINED_DEVICE_KEY_SPLITTER + this.private;
});


UserSchema = new Schema({
  
  /**
   * Organizations will be treated as "standard users plus some features".
   */
  isOrganization : { type : Boolean },

  /**
   * Organization-only property
   */
  orgUsers : [
		{
			user : { type : ObjectIdSchema, ref: "User"},
			roles : [{ type : String, enum : [ "admin", "member" ]}]
		}  	
  ],


  name : {
    first: String,
	  last: String
	},
  
  email : { 
  	type : mongoose.SchemaTypes.Email, 
  	required : true, 
  	unique: true 
  },
  
  phone : { type : String },
  
  address : {
  	
    /**
     * Line 1
     */
    streetAddress : String,
  	
    /**
     * Line 2
     */
    extendedAddress : String,
  	
    /**
     * City
     */
    locality : String,

    /** 
     * State
     */
  	region : String,
  	
    /**
     * Zip
     */
    postalCode : String,


  	/**
     * 2-letter country code
     * http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
     */
    countryCode : { type: String, default: 'US' }
  },
  
  salt: { type: String },
  
  hash: { type: String },
  
  locale: { 
  	lang: { type: String, default : 'en' },
  	territory : { type : String, default: 'US'}
  },
  
  timezone: { type : String, default : 'America/New_York' }, 
  
  active : { type : Boolean, default : false },
  
  admin :  { type : Boolean, default : false },
  
  activationToken : { type : String, default : '' },
  
  resetToken : { type : String, default : '' },
  
  sentEmail : { type: Boolean, default: false },
  
  notificationPreferences: {
  	email: { type: Boolean, default: true },
  	sms: { type: Boolean, default: false }
  },
  

  promotionalCodes : [{ type : String, enum : [ 
    "KICKSTARTER_15", 
    "KICKSTARTER_500" 
  ]}],


  deviceKeys : [ DeviceKeySchema ],
  
  apiKey : {
  	/**
  	 * Public API key is a 16-char random hex string
  	 */
  	public: String,
  	/**
  	 * Private API key is a 32-char random hex string
  	 */
  	private: String
  },

  socialPreferences: {
  	facebook: {
  		accessToken: { type: String },
  		permissions: {
  			publish: { type: Boolean }
  		}
  	}
  }
},
{ id : false, toObject : { virtuals: true }, toJSON : { virtuals : true } });

UserSchema.plugin(useTimestamps); // adds createdAt/updatedAt fields to the schema, and adds the necessary middleware to populate those fields 
UserSchema.plugin(mongoosePlugins.recoverableRemove);

UserSchema.virtual('name.full')
	.get(function () {
		var fullName = '';
		if (this.name.first) { fullName += this.name.first; }
		if (this.name.last) { fullName += ' ' + this.name.last; }
		return fullName;
	})
	.set(function (setFullNameTo) {
	  	var split = setFullNameTo.split(' ')
	  		, firstName = split[0]
	    	, lastName = split[1];

		this.set('name.first', firstName);
		this.set('name.last', lastName);
	});

UserSchema.virtual('locale.full')
	.get(function () {
		return this.locale.language + this.locale.territory ? '_' + this.locale.territory : '';
	})
	.set(function (fullLocale) {
	  	var split = fullLocale.split('_')
	  		, language = split[0]
	    	, territory = split[1];

		this.set('locale.language', language);
		this.set('locale.territory', territory || '');
	});

/**
 *  Get the current timezone offset from UTC time. This can't be a static
 *  value since offsets change with daylight savings and stuff. 
 *
UserSchema.virtual('timezoneOffset')
	.get(function(){
		var now = new Date(),
			timezoneOffsetString = timezone(now, this.timezone, '%z'),
			timezoneOffsetDirection = timezoneOffsetString[0],
			timezoneOffsetHours = parseInt(timezoneOffsetString.substr(1,2), 10),
			timezoneOffsetMinutes = parseInt(timezoneOffsetString.substr(3,2), 10),
			timezoneOffset = (timezoneOffsetDirection == '-' ? -1 : 1) * (timezoneOffsetHours * 60 * 60 * 1000) + (timezoneOffsetMinutes * 60 * 1000);
		return timezoneoffset;
	});
*/
/************************** STATIC METHODS  ***************************/


/**
 *
 * @param {object} userProperties : any User model properties
 * @param {string} password
 * @param {function(err, user)} done
 */
UserSchema.static('createUserWithPassword', function(userProperties, password, done){
	var newUser = new User(userProperties);

	bcrypt.genSalt(10, function(err, salt) {
  	if (err) { return done(err); }
  	newUser.salt = salt;
  	
  	bcrypt.hash(password, salt, function(err, hash) {
  		if (err) { return done(err); }

    		newUser.hash = hash;

    		newUser.save(function(err) {
    		return done(err, newUser);
		    });
		});
	});
});


/**
 * calls callback with 3 params: err, user, info
 */
UserSchema.static('authenticate', function(email, password, done) {
  User.findOne({ email: email.toLowerCase() }, function(err, user) {
      if (err) { return done(err); }
      if (!user) { 
        return done(null, null, { message: 'No user found with that email' });
      }
      if (user && !user.hash) { 
        return done(null, null, { message: 'Incorrect password. Did you sign up through a social account?' });
      }
      user.verifyPassword(password, function(err, passwordCorrect) {
        if (err) { return done(err); }
        if (!passwordCorrect) { 
          return done(null, null, { message: 'Incorrect password' });
        }
        return done(null, user);
      });
    });
});


/**
 * Used by Passport BPN_DEVICE strategy
 */
UserSchema.static('getByPublicDeviceKey', function(key, done) {
  User.findOne({ 'deviceKeys.public': key })
  .exec(function(err, user) {
	  if (err) { return done(err); }
      if (!user) { return done(new Error('No such device key'), false); }
      var matchingKey = user.deviceKeys.filter(function(deviceKey){
      	return deviceKey.public === key;
      })[0];
      return done(null, user, matchingKey);
  });
});

UserSchema.static('getByPublicApiKey', function(key, done) {
  User.findOne({ 'apiKey.public': key }, function(err, user) {
      if (err) { return done(err); }
      if (!user) { return done(new Error('No such API key'), false); }

      return done(null, user, user.apiKey);
  });
});

UserSchema.static('findOrCreate', function(accessToken, refreshToken, profile, done) {
	console.log("PROFILE::");
	console.log(profile);
	var email = profile.email || profile.emails ? profile.emails[0].value : '',
		// newUser = new User({
		newUser = {
			email: email,
			name: {
				first: profile.name.givenName,
				last: profile.name.familyName
			}
		};
		// });
	if (email) {
		User.findOneAndUpdate(
			{ 
				email: email 
			},
			newUser, 
			{ 
				upsert: true 
			}, 
			function(err, user) {
				if (err) { 
					console.log('ERR::');
					console.log(err);
					return done(err); 
				}
				console.log('save user')
				user.save(function(err) {
					if (err) return done(err);
					return done(null, user);
				});
			}
		);
	} else {
		return done(new Error("No email associated with account."))
	}
});
/************************** END STATIC METHODS  ***************************/



/************** INSTANCE METHODS ********************/

UserSchema.method('verifyPassword', function(password, next) {
  bcrypt.compare(password, this.hash, next);
});

UserSchema.method('toPublicJSON', function() {
  return {
  	_id : this._id,
  	name : this.name,
  	email : this.email,
  	phone : this.phone,
  	address : this.country,
  	locale: this.locale,
  	timezone: this.timezone,
  	active : this.active,
  	notificationPreferences: this.notificationPreferences,
  	socialPreferences: this.socialPreferences,
  	deviceKeys : this.deviceKeys.map(
  		function(el){ 
  			return { device : el.device, 'public' : el.public};
  		}
	),
  	apiKey : {
  		public: this.apiKey.public
  	}
  };
});


/**
 * Get the first key matching provided options, 
 * or if options are empty, first available device key
 *
 * @param {string=} options.serial. optional.
 */
UserSchema.method('getDeviceKey', function(options) {
  var user = this,
  		serial,
			i,
			currentDeviceKey,
			deviceKeys = user.deviceKeys || [],
			length = deviceKeys.length;;

		if (options){
			serial = options.serial;			
		}

		for (i = 0; i < length; i++) {
			currentDeviceKey = deviceKeys[i];
			if (serial && (currentDeviceKey.serial === serial)) {
					return currentDeviceKey;
			} else if (!currentDeviceKey.deviceId){
				return currentDeviceKey;		
			}
		};
});




/**
 * Make sure User has an unassigned deviceKey
 *
 * @param {string} serial. THe serial number that the user entered that will be assigned to this device key
 * @param {function(err, object )} done : Passed the available deviceKey object (DeviceKeySchema)
 */
UserSchema.method('ensureDeviceKey', function(serial, done){
	var user = this,
		availableDeviceKey,
		i,
		currentDeviceKey,
		matchingDeviceKey;

	user.deviceKeys = user.deviceKeys || [];

	for (i = user.deviceKeys.length; i--;) {
		currentDeviceKey = user.deviceKeys[i];
		if (!currentDeviceKey.deviceId){
			availableDeviceKey = currentDeviceKey;
		}
		if(currentDeviceKey.serial === serial){
			matchingDeviceKey = currentDeviceKey;
		}
	};
	
	async.waterfall(
		[
			function updateAvailableDeviceKey(innerCallback){
				if (matchingDeviceKey){
					return innerCallback();
				}
				if (availableDeviceKey){
					availableDeviceKey.serial = serial;	
					return innerCallback();
				} else {
					crypto.randomBytes(32, function(err, buf) {
						if (err) { return innerCallback(err); }
				  	var keysSource = buf.toString('hex'),
				  		publicKey = keysSource.substr(0, 16),
				  		privateKey = keysSource.substr(16, 16);
				  	
				  	availableDeviceKey = {
				  		'public' : publicKey,
				  		'private' : privateKey,
				  		'serial' : serial
				  	};
				  	user.deviceKeys.push(availableDeviceKey);
				  	return innerCallback();
					});	
				}
			},
			function saveUser(innerCallback){
				user.save(innerCallback);
			}
		],
		function (err, updatedUser){
			if (err) { return done(err); }
			return done(null, updatedUser.getDeviceKey({serial : serial}), updatedUser);
		}
	);
});

/************** END INSTANCE METHODS ********************/




/***************** MIDDLEWARE **********************/


UserSchema.pre('save', function(next){
	this.email = this.email.toLowerCase();
	next();
});

/**
 *  Give user API keys if needed. Can be done in parallel with other pre save hooks. 
 *  http://mongoosejs.com/docs/middleware.html
 */
UserSchema.pre('save', true, function(next, done){
	var user = this;
	
	next();
	
	if (user.apiKey && user.apiKey.public && user.apiKey.private){ return done(); }

	crypto.randomBytes(48, function(ex, buf) {
		if (ex) { return done(ex); }
	  	var keysSource = buf.toString('hex'),
	  		publicKey = keysSource.substr(0, 16),
	  		privateKey = keysSource.substr(16, 32);
	  	
	  	user.apiKey = {
	  		public : publicKey,
	  		private : privateKey
	  	};
	  	done();
  	});
});

/**
 *  Give user activation token if needed. This also can be done in parallel.
 */
UserSchema.pre('save', true, function(next, done){
	var user = this,
		token = "";

	next();

	//winston.info('user.active:'+user.active)
	//winston.info('user.sentEmail:'+user.sentEmail)

	if(user.activationToken && user.active) { return done(); }
	
	//create random string to verify against
	crypto.randomBytes(48, function(ex, buf) {
		if (ex) { return done(ex); }
		
		token = buf.toString('hex');
		user.activationToken = user.activationToken || token;
		
	  // The welcome email should be one-time only, even if the user hasn't activated yet
		if(user.sentEmail){ return done(); }
			
		var emailTransport = nodemailer.createTransport("SES", EmailConfig.amazonSES.api);

		var welcomeEmailTemplateLocals = {
      verifyUrl : (emailVariables.secureAppUrl + '/register?verify=' + user.activationToken)
    };

    var emailTemplateLocals = {
      emailSubject : "Get started with Bitponics",
      emailBodyHtml : compiledWelcomeEmailBody.html(welcomeEmailTemplateLocals),
      emailBodyText : compiledWelcomeEmailBody.text(welcomeEmailTemplateLocals),
      subscriptionPreferencesUrl : emailVariables.secureAppUrl + "/account/profile",
      appUrl : emailVariables.appUrl,
      secureAppUrl : emailVariables.secureAppUrl
    };

    emailTemplates(emailTemplatesDir, function(err, runEmailTemplate){
      if (err) { return done(err); }
      
      runEmailTemplate('default', emailTemplateLocals, function(err, finalEmailHtml, finalEmailText) {
      
        if (err) { return done(err); }

        var mailOptions = {
          from: "accounts@bitponics.com",
          to: user.email,
          subject: emailTemplateLocals.emailSubject,
          text: finalEmailText,
          html: finalEmailHtml
        };

        emailTransport.sendMail(mailOptions, function(err, response){
          if(err){ return done(err); }
          winston.info("Email sent: " + response.message);
          user.sentEmail = true;
          done();
        });
      });
    });

    


	});
});
/***************** END MIDDLEWARE **********************/



/***************** INDEXES ************************************/
UserSchema.index({ 'email': 1 });
UserSchema.index({ 'deviceKeys.public': 1 });
UserSchema.index({ 'apiKey.public': 1 });
/***************** END INDEXES ********************************/


User = mongooseConnection.model('User', UserSchema);

module.exports.setEmailVariables = function(appConfig){
	emailVariables = {
    appUrl : appConfig.appUrl,
    secureAppUrl : appConfig.secureAppUrl,
    appDomain : appConfig.appDomain
  };
};


/**
 * @type {Schema}
 */
module.exports.schema = UserSchema;

/**
 * @constructor
 * @alias module:models/User.UserModel
 * @type {Model}
 */
module.exports.model = User;
