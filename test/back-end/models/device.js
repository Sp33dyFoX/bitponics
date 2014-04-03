var mongooseConnection = require('../../../config/mongoose-connection').open('test'),
mongoose = require('mongoose'),
ObjectID = require('mongodb').ObjectID,
Models = require('../../../models'),
Device = require('../../../models/device'),
DeviceModel = Device.model,
ModelUtils = Models.utils,
should = require('should'),
timezone = require('../../../lib/timezone-wrapper'),
requirejs = require('../../../lib/requirejs-wrapper'),
feBeUtils = requirejs('fe-be-utils');

var createInstance = function(callback){
  DeviceModel.create({
    _id : (Date.now()).toString().substr(1), // need a 12-digit rando
    serial : (Date.now()).toString()
  }, callback);
};

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
 describe('Device', function(){
  
  /*
   * beforeEach Method
   *
   * Run before each test.
   */
   beforeEach(function(done){
    done();
   });


   /*
    * afterEach method
    *
    * Run after each test.
    * Remove the test user.
    */
    afterEach(function(done){
      done();
    });

    
    require('../test-utils').sharedTests.remove(DeviceModel, createInstance);


    describe('#refreshStatus', function(){
      beforeEach(function(done){
        done();        
      });

      afterEach(function(done){
        done();
      });
      
    });


    describe("#getStatusResponse", function(){
      /*
        {
          "__v" : 1,
          "_id" : "0006667211cf",
          "activeGrowPlanInstance" : ObjectId("514fe0c0658ae4f3f325e5b8"),
          "createdAt" : ISODate("2013-08-24T19:07:47.230Z"),
          "deviceType" : ObjectId("506de2fe8eebf7524342cb37"),
          "name" : "Bitponics Device 1",
          "outputMap" : [
            {
              "control" : ObjectId("506de2fd8eebf7524342cb32"),
              "outputId" : "1"
            },
            {
              "control" : ObjectId("506de2fc8eebf7524342cb2d"),
              "outputId" : "2"
            }
          ],
          "owner" : ObjectId("506de30a8eebf7524342cb6c"),
          "sensorMap" : [ ],
          "serial" : "AA-301-AAAA",
          "status" : {
            "actions" : [
              ObjectId("506de2f18eebf7524342cb27")
            ],
            "activeActions" : [
              ObjectId("506de2f18eebf7524342cb27")
            ],
            "expires" : ISODate("2013-09-03T19:07:47.550Z"),
            "immediateActions" : [ ]
          },
          "updatedAt" : ISODate("2013-08-24T19:07:48.113Z"),
          "userAssignmentLogs" : [ ],
          "users" : [
            ObjectId("506de3098eebf7524342cb66"),
            ObjectId("506de3098eebf7524342cb67"),
            ObjectId("506de30a8eebf7524342cb6c"),
            ObjectId("506de3098eebf7524342cb68"),
            ObjectId("506de30a8eebf7524342cb69"),
            ObjectId("506de30a8eebf7524342cb6a"),
            ObjectId("506de30a8eebf7524342cb6b")
          ]
        }

        {
          _id : '506de2f18eebf7524342cb27',
          description: "Light cycle, with lights on between 6am and 10pm.",
          control: "506de2fd8eebf7524342cb32",
          cycle: {
            states: [
              {
                controlValue: '1',
                durationType: 'hours',
                duration: 16
              },
              // finish off the 24 hour day with off
              {
                controlValue: '0',
                durationType: 'hours',
                duration: 8
              }
            ],
            // start the day with 6 hours off
            offset : {
              durationType: 'hours',
              duration: 6
            },
            repeat: true
          }
        },
       */
       it('returns ON state when light should be on', function(done){
        var now = new Date(),
            nowMonth = ("0" + (now.getMonth() + 1)).slice(-2),
            nowDay = ("0" + now.getDate()).slice(-2);
        
        // garden is started at the time of database init
        // generate the next day's 7am, accounting for timezone
        var next7am = new Date(
          timezone(
            timezone(now.getFullYear() + "-" + nowMonth + "-" + nowDay + " 07:00", "America/New_York"),
            "+1 day",
            "America/New_York"
          )
        );

        DeviceModel.findById("0006667211cf")
        .exec(function(err, deviceResult){
          should.not.exist(err);
          should.exist(deviceResult);
          
          deviceResult.getStatusResponse(
            {
              date : next7am
            }, 
            function(err, statusResponse){
              should.not.exist(err);
              JSON.parse(statusResponse).states["1"].should.equal(1);
              return done();
            }
          );
        });
       });

      it('returns OFF state when light should be off', function(done){
        var now = new Date(),
            // short way to get 2-digit month & day : http://stackoverflow.com/questions/6040515/how-do-i-get-month-and-date-of-javascript-in-2-digit-format
            nowMonth = ("0" + (now.getMonth() + 1)).slice(-2),
            nowDay = ("0" + now.getDate()).slice(-2);

        
        // garden is started at the time of database init
        // generate the next day's 5am, accounting for timezone
        var next5am = new Date(
          timezone(
            timezone(now.getFullYear() + "-" + nowMonth + "-" + nowDay + " 05:00", "America/New_York"),
            "+1 day",
            "America/New_York"
          )
        );

        DeviceModel.findById("0006667211cf")
        .exec(function(err, deviceResult){
          should.not.exist(err);

          deviceResult.getStatusResponse(
            {
              date : next5am
            }, 
            function(err, statusResponse){
              should.not.exist(err);
              JSON.parse(statusResponse).states["1"].should.equal(0);
              return done();
            }
          );
        });
       });


      it('returns response in specified mime type (V1), ON state', function(done){
        var now = new Date(),
            nowMonth = ("0" + (now.getMonth() + 1)).slice(-2),
            nowDay = ("0" + now.getDate()).slice(-2);
        
        // garden is started at the time of database init
        // generate the next day's 7am, accounting for timezone
        var next7am = new Date(
          timezone(
            timezone(now.getFullYear() + "-" + nowMonth + "-" + nowDay + " 07:00", "America/New_York"),
            "+1 day",
            "America/New_York"
          )
        );

        DeviceModel.findById("0006667211cf")
        .exec(function(err, deviceResult){
          should.not.exist(err);

          deviceResult.getStatusResponse(
            {
              date : next7am,
              contentType : feBeUtils.MIME_TYPES.BITPONICS.V1.DEVICE_TEXT
            }, 
            function(err, statusResponse){
              should.not.exist(err);
              statusResponse.should.equal("STATES=1,1;2,0;\n" + String.fromCharCode(7));
              return done();
            }
          );
        });
       });


      it('returns response in specified mime type (V2), ON state', function(done){
        var now = new Date(),
            nowMonth = ("0" + (now.getMonth() + 1)).slice(-2),
            nowDay = ("0" + now.getDate()).slice(-2);
        
        // garden is started at the time of database init
        // generate the next day's 7am, accounting for timezone
        var next7am = new Date(
          timezone(
            timezone(now.getFullYear() + "-" + nowMonth + "-" + nowDay + " 07:00", "America/New_York"),
            "+1 day",
            "America/New_York"
          )
        );

        DeviceModel.findById("0006667211cf")
        .exec(function(err, deviceResult){
          should.not.exist(err);

          deviceResult.getStatusResponse(
            {
              date : next7am,
              contentType : feBeUtils.MIME_TYPES.BITPONICS.V2.DEVICE_TEXT
            }, 
            function(err, statusResponse){
              should.not.exist(err);
              statusResponse.should.equal("STATES=1,1;2,0;\n" + String.fromCharCode(7));
              return done();
            }
          );
        });
       });


      it('returns response in specified mime type (JSON), ON state', function(done){
        var now = new Date(),
            nowMonth = ("0" + (now.getMonth() + 1)).slice(-2),
            nowDay = ("0" + now.getDate()).slice(-2);
        
        // garden is started at the time of database init
        // generate the next day's 7am, accounting for timezone
        var next7am = new Date(
          timezone(
            timezone(now.getFullYear() + "-" + nowMonth + "-" + nowDay + " 07:00", "America/New_York"),
            "+1 day",
            "America/New_York"
          )
        );

        DeviceModel.findById("0006667211cf")
        .exec(function(err, deviceResult){
          should.not.exist(err);

          deviceResult.getStatusResponse(
            {
              date : next7am,
              contentType : feBeUtils.MIME_TYPES.JSON
            }, 
            function(err, statusResponse){
              should.not.exist(err);
              statusResponse.should.equal('{"states":{"1":1,"2":0}}');
              return done();
            }
          );
        });
      });


      it('returns response in specified mime type (V1), OFF state', function(done){
        var now = new Date(),
            nowMonth = ("0" + (now.getMonth() + 1)).slice(-2),
            nowDay = ("0" + now.getDate()).slice(-2);
        
        // garden is started at the time of database init
        // generate the next day's 5am, accounting for timezone
        var next7am = new Date(
          timezone(
            timezone(now.getFullYear() + "-" + nowMonth + "-" + nowDay + " 05:00", "America/New_York"),
            "+1 day",
            "America/New_York"
          )
        );

        DeviceModel.findById("0006667211cf")
        .exec(function(err, deviceResult){
          should.not.exist(err);

          deviceResult.getStatusResponse(
            {
              date : next7am,
              contentType : feBeUtils.MIME_TYPES.BITPONICS.V1.DEVICE_TEXT
            }, 
            function(err, statusResponse){
              should.not.exist(err);
              statusResponse.should.equal("STATES=1,0;2,0;\n" + String.fromCharCode(7));
              return done();
            }
          );
        });
       });


      it('returns response in specified mime type (V2), OFF state', function(done){
        var now = new Date(),
            nowMonth = ("0" + (now.getMonth() + 1)).slice(-2),
            nowDay = ("0" + now.getDate()).slice(-2);
        
        // garden is started at the time of database init
        // generate the next day's 5am, accounting for timezone
        var next7am = new Date(
          timezone(
            timezone(now.getFullYear() + "-" + nowMonth + "-" + nowDay + " 05:00", "America/New_York"),
            "+1 day",
            "America/New_York"
          )
        );

        DeviceModel.findById("0006667211cf")
        .exec(function(err, deviceResult){
          should.not.exist(err);

          deviceResult.getStatusResponse(
            {
              date : next7am,
              contentType : feBeUtils.MIME_TYPES.BITPONICS.V2.DEVICE_TEXT
            }, 
            function(err, statusResponse){
              should.not.exist(err);
              statusResponse.should.equal("STATES=1,0;2,0;\n" + String.fromCharCode(7));
              return done();
            }
          );
        });
       });

    });

    describe('.logCalibrationStatus', function(){
      
      beforeEach(function(done){
        var self = this;
        self._id = "101010101010";
        self.serial = "SOMETHING RANDOM DEVICE";

        DeviceModel.create({
          _id: self._id,
          serial : self.serial
        }, 
        function(err, createdDevice){
          self.device = createdDevice;
          done();
        });
      });

      afterEach(function(done){
        DeviceModel.remove({_id: this._id}, done);
      });
      
      it('logs a calibration log, with the current timestamp', function(done){
        var self = this,
            now = Date.now();

        should.exist(self.device);
        self.device._id.should.equal(self._id);

        DeviceModel.logCalibrationStatus(
        {
          device : self.device,
          calibrationStatusLog : {
            mode : "ph_4",
            status : "success",
            message : "calibration message"
          }
        },
        function(err, calibrationStatusLog){
          should.not.exist(err);
          should.exist(calibrationStatusLog);
          
          calibrationStatusLog.mode.should.equal("ph_4");
          calibrationStatusLog.status.should.equal("success");
          calibrationStatusLog.message.should.equal("calibration message");
          calibrationStatusLog.timestamp.valueOf().should.be.above(now);
          
          done();
        });
      });
    });


  });
