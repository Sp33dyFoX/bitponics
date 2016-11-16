#! /usr/bin/env node

/*
 * db_init
 * https://github.com/Bitponics/bitponics
 *
 * Copyright (c) 2012 Jack Bishop
 * Licensed under the MIT license.
 *
 *
 * Setup:
 *   1. $ cd bitponics/utils/db_init
 *   2. $ npm link
 *
 * Usage:
 *   $ cd bitponics
 *   $ db_init [local|dev|staging|test|mongodb://whatever-db-you-need] [clear]
 *   
 *   example: 
 *		$ db_init local
 *   example with clear:
 *		$ db_init dev clear
 *  
 *	 This script optionally removes all collections, then adds data from /bitponics/utils/db_init/seed_data/.
 *
 */

//TODO: separate device script

var mongoose   = require('mongoose'),
  async = require('async'),
  mongoUrls = require('../../../config/mongoose-connection').urls,
  db_url = process.argv.slice(2)[0], //gets first cmd line arg
  clear = process.argv.slice(2)[1], //gets second cmd line arg
  data = require('../seed_data'),
  appDomains = require('../../../config/app-domain-config'),
  appDomain = 'bitponics.com',
  dataType = undefined,
  savedObjectIds = {
    sensors: {},
    nutrients: {},
    deviceTypes: {},
    devices: {},
    lightBulbs: {},
    lightFixtures: {},
    lights : {},
    growSystems: {},
    plants: {},
    controls: {},
    actions: {},
    growPlans: {},
    growPlanInstances: {},
    users: {},
    sensorLogs: {},
    products: {},
    photos : {}
  },
  mongooseConnection;

switch(db_url){
  case 'local':
    mongooseConnection = require('../../../config/mongoose-connection').open("local");
    appDomain = appDomains.local;
    break;
  case 'localLocal':
    mongooseConnection = require('../../../config/mongoose-connection').open("localLocal");
    appDomain = appDomains.local;
    break;
  case 'dev':
    mongooseConnection = require('../../../config/mongoose-connection').open("development");
    appDomain = appDomains.development;
    break;
  case 'staging':
    mongooseConnection = require('../../../config/mongoose-connection').open("staging");
    appDomain = appDomains.staging;
    break;
  case 'test':
    mongooseConnection = require('../../../config/mongoose-connection').open("test");
  // don't support 'production' as a shortcut. force use to do that explicitly
  default:
    // if not one of those, assume it was a mongodb:// url, so leave it alone
    mongooseConnection = require('../../../config/mongoose-connection').open(db_url);
  
}

console.log(clear);
// console.log(data);



var models = require('../../../models');

/**
 * Run data operations in series using async lib
 */
async.series([
  function(callback){
    /**
     * clear old data in parallel if clear option
     */
    if(clear) {

      async.parallel([
        function(innerCallback){
          if (!mongooseConnection.collections['users']){ return innerCallback();}
          mongooseConnection.collections['users'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('users collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['plants']){ return innerCallback();}
          mongooseConnection.collections['plants'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('plants collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['harvestlogs']){ return innerCallback();}
          mongooseConnection.collections['harvestlogs'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('harvestlogs collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['calibrationstatuslogs']){ return innerCallback();}
          mongooseConnection.collections['calibrationstatuslogs'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('calibrationstatuslogs collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['calibrationlogs']){ return innerCallback();}
          mongooseConnection.collections['calibrationlogs'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('calibrationlogs collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['sensors']){ return innerCallback();}
          mongooseConnection.collections['sensors'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('sensors collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['nutrients']){ return innerCallback();}
          mongooseConnection.collections['nutrients'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('nutrients collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['devicetypes']){ return innerCallback();}
          mongooseConnection.collections['devicetypes'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('devicetypes collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['devices']){ return innerCallback();}
          mongooseConnection.collections['devices'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('devices collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['lightbulbs']){ return innerCallback();}
          mongooseConnection.collections['lightbulbs'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('lightbulbs collection dropped');
            innerCallback();
          });

        },
        function(innerCallback){
          if (!mongooseConnection.collections['lightfixtures']){ return innerCallback();}
          mongooseConnection.collections['lightfixtures'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('lightfixtures collection dropped');
            innerCallback();
          });

        },
        function(innerCallback){
          if (!mongooseConnection.collections['lights']){ return innerCallback();}
          mongooseConnection.collections['lights'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('lights collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['growsystems']){ return innerCallback();}
          mongooseConnection.collections['growsystems'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('growsystems collection dropped');
            innerCallback();
          });

        },
        function(innerCallback){
          if (!mongooseConnection.collections['controls']){ return innerCallback();}
          mongooseConnection.collections['controls'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('controls collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['actions']){ return innerCallback();}
          mongooseConnection.collections['actions'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('actions collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['growplans']){ return innerCallback();}
          mongooseConnection.collections['growplans'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('growplans collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['growplaninstances']){ return innerCallback();}
          mongooseConnection.collections['growplaninstances'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('growplaninstances collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['sensorlogs']){ return innerCallback();}
          mongooseConnection.collections['sensorlogs'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('sensorlogs collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['notifications']){ return innerCallback();}
          mongooseConnection.collections['notifications'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('notifications collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['immediateactions']){ return innerCallback();}
          mongooseConnection.collections['immediateactions'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('immediateactions collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['products']){ return innerCallback();}
          mongooseConnection.collections['products'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('products collection dropped');
            innerCallback();
          });
        },
        function(innerCallback){
          if (!mongooseConnection.collections['photos']){ return innerCallback();}
          mongooseConnection.collections['photos'].drop( function(err) {
            if (err){ return innerCallback(err);}
            console.log('photos collection dropped');
            innerCallback();
          });
        }
      ],
        function(err, results){
          callback(null, null);
        }
      );
    } else {
      callback();
    }
  },

  function(callback){
    /**
     * Users
     */

    var dataType = 'users',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.user.findById(_data._id, function(err, user){
        if (err) { console.log(err); return callback(err);}
        if (user){
          decrementData();
        } else {
          models.user.createUserWithPassword({
              _id : _data._id,
              email : _data.email,
              name : _data.name,
              locale: _data.locale,
              active : _data.active,
              admin :  _data.admin,
              activationToken : _data.activationToken,
              sentEmail : _data.sentEmail,
              deviceKeys : _data.deviceKeys,
              apiKey : _data.apiKey
            },
            _data.password || "8bitpass", //default password
            function(err, user){
              if (err) { console.log(err); return callback(err);}
              savedObjectIds[dataType][_data.email] = user._id;
              console.log("created user");
              decrementData();
            });
        }
      });
    });
  },

  function(callback){
    /**
     * Sensors
     */
    var dataType = 'sensors',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.sensor.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.sensor({
            _id : _data._id,
            name: _data.name,
            abbrev: _data.abbrev,
            unit: _data.unit,
            code: _data.code,
            visible : _data.visible
          });

          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.code] = doc._id;
            console.log("created sensor");
            decrementData();
          });
        }
      })
    });
  },

  function(callback){
    /**
     * Controls
     */
    var dataType = 'controls',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.control.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.control({
            _id : _data._id,
            name: _data.name,
            onAction : _data.onAction,
            offAction : _data.offAction
          });
          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.name] = doc._id;
            console.log("created control");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * Nutrients
     */
    var dataType = 'nutrients',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.nutrient.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.nutrient({
            _id : _data._id,
            name: _data.name,
            brand: _data.brand
          });

          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.name] = doc._id;
            console.log("created sensor");
            decrementData();
          });
        }
      });


    });
  },

  function(callback){
    /**
     * Device Types
     */
    var dataType = 'deviceTypes',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){

      models.deviceType.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.deviceType({
            _id : _data._id,
            name: _data.name,
            firmwareVersion: _data.firmwareVersion,
            microprocessor: _data.microprocessor,
            sensors: _data.sensors,
            outputMap : _data.outputMap
          });

          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.name] = doc._id;
            console.log("created: " + dataType);
            decrementData();
          });
        }
      });

    });
  },

  function(callback){
    /**
     * Devices
     */
    var dataType = 'devices',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){

      models.device.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.device({
            _id : _data._id,
            deviceType: _data.deviceType,
            name : _data.name,
            serial : _data.serial,
            owner: _data.owner,
            users : _data.users,
            sensors : _data.sensors,
            outputMap : _data.outputMap,
            recentSensorLogs: _data.recentSensorLogs,
            activeGrowPlanInstance : _data.activeGrowPlanInstance
          });

          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data._id] = doc._id;
            console.log("created device");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * LightBulbs
     */
    var dataType = 'lightBulbs',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.lightBulb.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.lightBulb({
            _id : _data._id,
            type: _data.type,
            watts: _data.watts,
            brand: _data.brand,
            name: _data.name
          });
          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.name] = doc._id;
            console.log("created lightBulb");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * LightFixtures
     */
    var dataType = 'lightFixtures',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.lightFixture.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.lightFixture({
            _id : _data._id,
            type: _data.type,
            watts: _data.watts,
            brand: _data.brand,
            name: _data.name,
            bulbCapacity: _data.bulbCapacity
          });
          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.name] = doc._id;
            console.log("created lightFixture");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * Lights
     */
    var dataType = 'lights',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.light.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.light({
            _id : _data._id,
            fixture : _data.fixture,
            fixtureQuantity : _data.fixtureQuantity,
            bulb : _data.bulb
          });
          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data._id] = doc._id;
            console.log("created light");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * Grow Systems
     */
    var dataType = 'growSystems',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.growSystem.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.growSystem({
            _id : _data._id,
            name: _data.name,
            description: _data.description,
            type: _data.type,
            reservoirSize: _data.reservoirSize,
            plantCapacity: _data.plantCapacity,
            overallSize : _data.overallSize,
            photos : _data.photos
          });
          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.name] = doc._id;
            console.log("created grow system");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * Plants
     */
    var dataType = 'plants',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.plant.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.plant({
            _id : _data._id,
            name: _data.name
          });
          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.name] = doc._id;
            console.log("created plant");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * Actions
     */
    var dataType = 'actions',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.action.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.action({
            _id : _data._id,
            description: _data.description,
            control: _data.control,
            cycle: _data.cycle
          });
          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.description] = doc._id;
            console.log("created action");
            decrementData();
          });
        }
      });
    });
  },




  function(callback){
    /**
     * Grow Plans
     */

    var dataType = 'growPlans',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.growPlan.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {
          var dataObj = new models.growPlan({
            _id : _data._id,
            createdBy: _data.createdBy,
            name: _data.name,
            description: _data.description,
            plants: _data.plants,
            phases: _data.phases
          });

          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][_data.name] = doc._id;
            console.log("created growPlan");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * Grow Plan Instances
     */

    var dataType = 'growPlanInstances',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.growPlanInstance.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          decrementData();
        } else {

          models.growPlanInstance.create({
              _id : _data._id,
              users: _data.users,
              owner : _data.owner,
              growPlan: _data.growPlan,
              device: _data.device,
              active : _data.active,
              startDate: _data.startDate,
              endDate: _data.endDate,
              active: _data.active,
              phases: _data.phases,
              recentSensorLogs: _data.recentSensorLogs,
              recentTagLogs: _data.recentTagLogs
            },
            function(err, doc){
              if (err) { console.log(err); return callback(err);}
              savedObjectIds[dataType][_data._id] = doc._id;
              console.log("created grow plan instance");
              decrementData();
            }
          );
          /*
           var dataObj = new models.growPlanInstance({
           _id : _data._id,
           users: _data.users,
           owner : _data.owner,
           growPlan: _data.growPlan,
           device: _data.device,
           startDate: _data.startDate,
           endDate: _data.endDate,
           active: _data.active,
           phases: _data.phases,
           recentSensorLogs: _data.recentSensorLogs,
           recentTagLogs: _data.recentTagLogs
           });

           dataObj.save(function (err, doc) {
           if (err) { console.log(err); return callback(err);}
           savedObjectIds[dataType][_data._id] = doc.id;
           console.log("created grow plan instance");

           if (dataObj.active){
           console.log('pairing grow plan instance with device');
           models.utils.activateGrowPlanInstance(doc, function(err){
           if (err) { console.log(err); return callback(err);}
           decrementData();
           });
           } else {
           decrementData();
           }

           });
           */

        }
      });
    });
  },

  function(callback){
    /**
     * Sensor Logs
     */

    var dataType = 'sensorLogs',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.sensorLog.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          return decrementData();
        } else {
          var dataObj = new models.sensorLog({
            _id : _data._id,
            gpi: _data.gpi,
            ts : _data.ts,
            logs : _data.logs
          });

          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][doc._id] = doc._id;
            console.log("created sensor log");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * Products
     */

    var dataType = 'products',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.product.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          return decrementData();
        } else {
          var dataObj = new models.product({
            _id : _data._id,
            productType: _data.productType,
            name: _data.name,
            description: _data.description,
            price: _data.price,
            billingCycle : _data.billingCycle,
            stock: _data.stock
          });

          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][doc._id] = doc._id;
            console.log("created product");
            decrementData();
          });
        }
      });
    });
  },

  function(callback){
    /**
     * Photos
     */

    var dataType = 'photos',
      dataCount = data[dataType].length,
      decrementData = function(){
        dataCount--;
        if (dataCount === 0){
          callback();
        }
      };

    console.log('####### ' + dataType + ' #######');

    data[dataType].forEach(function(_data){
      models.photo.findById(_data._id, function(err, result){
        if (err) { console.log(err); return callback(err);}
        if (result){
          return decrementData();
        } else {
          var dataObj = new models.photo({
            _id : _data._id,
            owner : _data.owner,
            originalFileName : _data.originalFileName,
            type : _data.type,
            size : _data.size,
            visibility : _data.visibility,
            date : _data.date,
            tags : _data.tags,
            ref : _data.ref
          });

          dataObj.save(function (err, doc) {
            if (err) { console.log(err); return callback(err);}
            savedObjectIds[dataType][doc._id] = doc._id;
            console.log("created photo");
            decrementData();
          });
        }
      });
    });
  }
],
  function(err, results){
    console.log('ALL DONE');
    if(err){
      console.log('FAILED');
      console.log(err);
      process.exit(1);
    } else {
      console.log('SUCCEEDED');
      process.exit(0);
    }
  }
);
