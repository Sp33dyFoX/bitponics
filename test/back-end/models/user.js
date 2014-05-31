var mongooseConnection = require('../../../config/mongoose-connection').open('test'),
	mongoose = require('mongoose'),
  User = require('../../../models/user').model,
  should = require('should');


/*
 * Mocha Test
 *
 * Tests are organized by having a "describe" and "it" method. Describe
 * basically creates a "section" that you are testing and the "it" method
 * is what runs your test code.
 *
 * For asynchronous tests you need to have a done method that you call after
 * your code should be done executing so Mocha runs to test properly.
 */
describe('User', function(){

  var currentUser = null;

  /**
   * beforeEach Method
   *
   * Run before each test.
   * Create an active user.
   */
  beforeEach(function(done){
    User.createUserWithPassword({
        email : 'unittest@bitponics.com',
        name : {
          first : "Testfirstname",
          last : "Testlastname"
        },
        locale: "en_US",
        active : true,
        activationToken : "1234567890",
        sentEmail : true
      },
      '8bitpass',
      done
    );
  });


  /*
   * afterEach method
   *
   * Run after each test.
   * Remove the test user.
   */
  afterEach(function(done){
    User.remove({email: 'unittest@bitponics.com'}, done);
  });


  it('creates a new user', function(done){
    User.findOne({ email : 'unittest@bitponics.com'},
      function(err, user){
        should.not.exist(err);
        should.exist(user);
        user.email.should.eql('unittest@bitponics.com');
        done();
      });

  });


  it('authenticates a user by email and password', function(done){
    User.authenticate('unittest@bitponics.com', '8bitpass', function(err, user){
      should.not.exist(err);
      should.exist(user);
      user.email.should.eql('unittest@bitponics.com');
      done();
    })
  });


  
  it('gets a user by device key', function(done){
    User.findOne({email : 'unittest@bitponics.com'},
      function(err, user){
        should.not.exist(err);
        should.exist(user);

        var serial = "TS-301-AAAA";

        user.ensureDeviceKey(serial, function(err, availableDeviceKey){
          should.not.exist(err);
          
          var keyFromUser = user.getDeviceKey({serial : serial});

          should.exist(keyFromUser);
          keyFromUser.should.equal(availableDeviceKey);
          availableDeviceKey.serial.should.equal(serial);
          keyFromUser.serial.should.equal(serial);

          User.getByPublicDeviceKey(user.deviceKeys[0].public, function(err, nestedUser, matchingKey){
            should.not.exist(err);
            should.exist(nestedUser);
            should.exist(matchingKey);
            matchingKey.public.should.equal(user.deviceKeys[0].public);
            (nestedUser._id.equals(user._id)).should.be.ok;
            done();
          });

        });
      });
  });



  it('gets a user by public api key', function(done){
    User.findOne({email : 'unittest@bitponics.com'},
      function(err, user){
        should.not.exist(err);
        should.exist(user);
        User.getByPublicApiKey(user.apiKey.public, function(err, nestedUser, matchingKey){
          should.not.exist(err);
          should.exist(nestedUser);
          (nestedUser._id.equals(user._id)).should.be.ok;
          done();
        });
      });
  });


  describe('User', function(){
    it('ensures an available deviceKey exists, creating one if not', function(done){
      User.findOne({email : 'unittest@bitponics.com'},
        function(err, user){
          should.not.exist(err);
          should.exist(user);
          var serial = "TS-301-AAAN";

          user.ensureDeviceKey(serial, function(err, availableDeviceKey){
            should.not.exist(err);

            var keyFromUser = user.getDeviceKey({serial : serial});
            should.exist(keyFromUser);
            keyFromUser.should.equal(availableDeviceKey);
            keyFromUser.serial.should.equal(serial);
            availableDeviceKey.serial.should.equal(serial);
            done();
          });
        }
      );
    });
  });
});
