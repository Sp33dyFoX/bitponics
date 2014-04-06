var mongooseConnection = require('../../../config/mongoose-connection').open('test'),
mongoose = require('mongoose'),
ObjectID = require('mongodb').ObjectID,
Models = require('../../../models'),
GrowPlanInstanceModel = require('../../../models/garden').model,
GrowPlan = require('../../../models/growPlan').growPlan.model,
ModelUtils = require('../../../models/utils'),
SensorLogModel = require('../../../models/sensorLog').model,
NotificationModel = require('../../../models/notification').model,
Device = require('../../../models/device').model,
should = require('should'),
sampleGrowPlanInstances = require('../../../utils/db_init/seed_data/growPlanInstances'),
async = require('async'),
requirejs = require('../../../lib/requirejs-wrapper'),
feBeUtils = requirejs('fe-be-utils');


var createInstance = function(callback){
  GrowPlanInstanceModel.create({
    growPlan : '506de2ff8eebf7524342cb3a',
    owner : '506de30a8eebf7524342cb6c',
    active : false
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
 describe('GrowPlanInstance', function(){
  
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


    require('../test-utils').sharedTests.remove(GrowPlanInstanceModel, createInstance);

    
    describe('.create', function(){
      
      it('returns an error if options.growPlan is not specified', function(done){
        GrowPlanInstanceModel.create({
          owner : '506de30a8eebf7524342cb6c',
          active : true
        },
        function(err, gpi){
          should.exist(err);
          return done();
        });
      });


      it('returns an error if options.owner is not specified', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a',
          active : true
        },
        function(err, gpi){
          should.exist(err);
          return done();
        });
      });


      it('returns an error if an invalid options.growPlan is specified', function(done){
        GrowPlanInstanceModel.create({
          growPlan : 'not a valid objectId',
          owner : '506de30a8eebf7524342cb6c',
          active : true
        },
        function(err, gpi){
          should.exist(err);
          return done();
        });
      });


      it('returns a GrowPlanInstance if valid options are specified', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a',
          owner : '506de30a8eebf7524342cb6c',
          active : false
        },
        function(err, gpi){
          should.not.exist(err);
          should.exist(gpi);
          gpi.should.be.an.instanceof(GrowPlanInstanceModel);
          should.not.exist(gpi.active);
          
          // Since active was false, all phases should be inactive
          gpi.phases.forEach(function(phase){
            should.not.exist(phase.active); // TODO: check falsiness instead
            should.not.exist(phase.startDate);
            should.not.exist(phase.endDate);
          });

          return done();
        });
      });


      it('returns a GrowPlanInstance if valid options are specified, and activates as specified', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a',
          owner : '506de30a8eebf7524342cb6c',
          active : true
        },
        function(err, gpi){
          should.not.exist(err);
          should.exist(gpi);
          gpi.should.be.an.instanceof(GrowPlanInstanceModel);
          should.exist(gpi.active);
          // Since phaseId and activePhaseDay weren't specified, they 
          // should be set to the first day of the first phase
          var todayDateString = (new Date()).toDateString();
          gpi.phases.forEach(function(phase, index){
            if (index === 0){
              phase.active.should.be.true;
              phase.startDate.toDateString().should.equal(todayDateString);
              should.exist(phase.expectedEndDate);
            } else {
              phase.active.should.be.false; // TODO: check falsiness instead
              should.not.exist(phase.startDate);
              should.not.exist(phase.endDate);  
            }
          });

          return done();
        });
      });

      
      it('activates specified phase if options.activePhaseId is defined', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a', // Tomato Grow Plan
          owner : '506de30a8eebf7524342cb6c',
          active : true,
          activePhaseId : '506de3048eebf7524342cb4f' // Vegetative phase
        },
        function(err, gpi){
          should.not.exist(err);
          should.exist(gpi);
          gpi.should.be.an.instanceof(GrowPlanInstanceModel);
          should.exist(gpi.active);
          // Since phaseId and activePhaseDay weren't specified, they 
          // should be set to the first day of the first phase
          var todayDateString = (new Date()).toDateString();
          var foundActivePhase = false;
          gpi.phases.forEach(function(phase, index){
            if (phase.phase.toString() == '506de3048eebf7524342cb4f'){
              
              phase.active.should.be.true;
              phase.startDate.toDateString().should.equal(todayDateString);
              should.exist(phase.expectedEndDate);
              foundActivePhase = true;
            } else {
              phase.active.should.be.false; // TODO: check falsiness instead
              should.not.exist(phase.startDate);
              should.not.exist(phase.endDate);  
            }
          });
          foundActivePhase.should.be.true;
          return done();
        });
      });


      it('activates specified phase and day if options.activePhaseId options.activePhaseDay are defined', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a', // Tomato Grow Plan
          owner : '506de30a8eebf7524342cb6c',
          active : true,
          activePhaseId : '506de3048eebf7524342cb4f', // Vegetative phase
          activePhaseDay : 3
        },
        function(err, gpi){
          should.not.exist(err);
          should.exist(gpi);
          gpi.should.be.an.instanceof(GrowPlanInstanceModel);
          should.exist(gpi.active);
          // Since phaseId and activePhaseDay weren't specified, they 
          // should be set to the first day of the first phase
          var today = new Date(),
              todayDateString = today.toDateString(),
              foundActivePhase = false;
          gpi.phases.forEach(function(phase, index){
            if (phase.phase.toString() == '506de3048eebf7524342cb4f'){
              phase.active.should.be.true;
              phase.startDate.toDateString().should.equal(todayDateString);
              // for Tomato Grow Plan, Vegetative phase is expected to last 28 days
              should.exist(phase.expectedEndDate);
              var daysRemaining = Math.round( (phase.expectedEndDate -  today) / 1000 / 60 / 60 / 24);
              // Started on day 3 of the phase, should should have (28-3) days remaining
              daysRemaining.should.equal(25); 
              foundActivePhase = true;
            } else {
              phase.active.should.be.false; // TODO: check falsiness instead
              should.not.exist(phase.startDate);
              should.not.exist(phase.endDate);  
            }
          });
          foundActivePhase.should.be.true;
          return done();
        });
      });


      it('activates specified device if options.device is defined', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a',
          owner : '506de30a8eebf7524342cb6c',
          device : '0006667288ae',
          active : true
        },
        function(err, gpi){
          should.not.exist(err);
          should.exist(gpi, 'gpi should be returned from create');
          gpi.should.be.an.instanceof(GrowPlanInstanceModel);
          should.exist(gpi.active);
          should.exist(gpi.device);

          Device.findById(gpi.device, function(err, device){
            should.not.exist(err);
            should.exist(device);
            device.activeGrowPlanInstance.equals(gpi._id).should.be.true;
            return done();
          });
        });
      });


      it('returns an error if GPI owner does not own the specified device', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a',
          owner : '506de30a8eebf7524342cb6c',
          device : '0006668033ae',
          active : true
        },
        function(err, gpi){
          should.exist(err);
          return done();
        });
      });      
    });


    describe('#activate', function(){
      
    }); // /#activate
    

    describe('#activatePhase', function(){
      
    }); // /#activatePhase


    describe('#deactivate', function(){
      beforeEach(function(done){
        var self = this;
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a',
          owner : '506de30a8eebf7524342cb6c',
          active : true
        }, function(err, gpi){
          self.gpi = gpi;
          self.mocks = {
            user : {
              timezone : self.gpi.tz
            }
          };

          return done();
          
        });
      });

      it('sets active to false and updates all associated documents', function(done){
        var self = this;
        should.exist(self.gpi, 'gpi should exist');
        
        NotificationModel.find({ gpi : self.gpi._id })
        .exec(function(err, notifications){
          var hasSomeActiveNotifications = notifications.some(function(notification){
            return notification.tts;
          });

          hasSomeActiveNotifications.should.equal(true, "before deactivation, should have some active notifiactions");

          self.gpi.deactivate(function(err){
            should.not.exist(err, "error deactivating");

            GrowPlanInstanceModel.findById(self.gpi._id, function(err, updatedGPI){
              should.not.exist(err);
              updatedGPI.active.should.equal(false, "gpi.active should be false after deactivation");

              NotificationModel.find(
                { 
                  gpi : self.gpi._id, 
                  'tts': {
                    $exists : true 
                  }
                })
              .exec(function(err, updatedNotifications){
                updatedNotifications.length.should.equal(0, "after deactivation, should not have any active notifications");

                done();  
              });
            });
          });
        });
      });
    });



    describe('#getPhaseDay', function(){
      it('retrieves expected day of a growPlanInstance phase, offset by phase.startedOnDay', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a', // Tomato Grow Plan
          owner : '506de30a8eebf7524342cb6c',
          active : true,
          activePhaseId : '506de3048eebf7524342cb4f', // Vegetative phase
          activePhaseDay : 3
        },
        function(err, gpi){
          should.not.exist(err);
          should.exist(gpi);
          gpi.should.be.an.instanceof(GrowPlanInstanceModel);
          should.exist(gpi.active);
        
          var today = new Date(),
              todayDateString = today.toDateString(),
              foundActivePhase = false;
        
          var gpiPhase = gpi.getPhaseByGrowPlanPhaseId("506de3048eebf7524342cb4f");

          // since we started on day 3 of the phase, getting phaseDay with today
          // as a target date should return 3
          gpi.getPhaseDay(gpiPhase, today).should.equal(3);

          return done();
        });
      });

      it('handles extended phases', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a', // Tomato Grow Plan
          owner : '506de30a8eebf7524342cb6c',
          active : true,
          activePhaseId : '506de3048eebf7524342cb4f', // Vegetative phase
          activePhaseDay : 400 // phase is only 20-something days long but users have the option to remain in a phase indefinitely. handle this.
        },
        function(err, gpi){
          should.not.exist(err);
          should.exist(gpi);
          gpi.should.be.an.instanceof(GrowPlanInstanceModel);
          should.exist(gpi.active);
        
          var today = new Date(),
              todayDateString = today.toDateString(),
              foundActivePhase = false;
        
          var gpiPhase = gpi.getPhaseByGrowPlanPhaseId("506de3048eebf7524342cb4f");

          // since we started on day 3 of the phase, getting phaseDay with today
          // as a target date should return 3
          gpi.getPhaseDay(gpiPhase, today).should.equal(400);

          return done();
        });
      });
    }); // /#getPhaseDay


    describe('#mergePhaseDaySummary', function(){
      it('adds specified phaseDaySummary to the phase data at the index corresponding to phase day', function(done){
        GrowPlanInstanceModel.create({
          growPlan : '506de2ff8eebf7524342cb3a', // Tomato Grow Plan
          owner : '506de30a8eebf7524342cb6c',
          active : true,
          activePhaseId : '506de3048eebf7524342cb4f', // Vegetative phase
          activePhaseDay : 3
        },
        function(err, gpi){
          should.not.exist(err);
          should.exist(gpi);
          gpi.should.be.an.instanceof(GrowPlanInstanceModel);
          should.exist(gpi.active);
        
          var today = new Date(),
              todayDateString = today.toDateString(),
              foundActivePhase = false;
        
          var gpiPhase = gpi.getPhaseByGrowPlanPhaseId("506de3048eebf7524342cb4f");

          // since we started on day 3 of the phase, getting phaseDay with today
          // as a target date should return 3
          var phaseDaySummary = {
            status : feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD,
            sensorSummaries : {
              'ph' : feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD,
              'ec' : feBeUtils.PHASE_DAY_SUMMARY_STATUSES.BAD,
              'air' : feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD,
              'water' : feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD,
              'hum' : feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD,
              'lux' : feBeUtils.PHASE_DAY_SUMMARY_STATUSES.GOOD
            },
            date : today
          };

          var phaseDay = gpi.getPhaseDay(gpiPhase, today);

          gpi.mergePhaseDaySummary(
          {
            growPlanInstancePhase : gpiPhase,
            daySummary : phaseDaySummary
          },
          function(err, updatedGrowPlanInstance){
            should.not.exist(err);
            should.exist(updatedGrowPlanInstance);
            gpi.should.be.an.instanceof(GrowPlanInstanceModel);

            var retrievedGpiPhase = updatedGrowPlanInstance.getPhaseByGrowPlanPhaseId("506de3048eebf7524342cb4f"),
                retrievedPhaseDaySummary = retrievedGpiPhase.daySummaries[phaseDay];
            
            should.exist(retrievedPhaseDaySummary, "phaseDaySummary for phaseDay should exist");

            retrievedPhaseDaySummary.status.should.equal(phaseDaySummary.status);
            retrievedPhaseDaySummary.sensorSummaries['ph'].should.equal(phaseDaySummary.sensorSummaries['ph']);
            retrievedPhaseDaySummary.sensorSummaries['ec'].should.equal(phaseDaySummary.sensorSummaries['ec']);
            retrievedPhaseDaySummary.sensorSummaries['air'].should.equal(phaseDaySummary.sensorSummaries['air']);
            retrievedPhaseDaySummary.sensorSummaries['water'].should.equal(phaseDaySummary.sensorSummaries['water']);
            retrievedPhaseDaySummary.sensorSummaries['hum'].should.equal(phaseDaySummary.sensorSummaries['hum']);
            retrievedPhaseDaySummary.sensorSummaries['lux'].should.equal(phaseDaySummary.sensorSummaries['lux']);

            done();
          });

        });
      });
    }); // /#getPhaseDay
});
