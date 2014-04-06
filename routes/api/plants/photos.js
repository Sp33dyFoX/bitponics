var PlantModel = require('../../../models/plant').model,
    ActionModel = require('../../../models/action').model,
    DeviceModel = require('../../../models/device').model,
    SensorLogModel = require('../../../models/sensorLog').model,
    PhotoModel = require('../../../models/photo').model,
    TextLogModel = require('../../../models/textLog').model,
    NotificationModel = require('../../../models/notification').model,
    ImmediateActionModel = require('../../../models/immediateAction').model,
    moment = require('moment'),
    ModelUtils = require('../../../models/utils'),
    getObjectId =  ModelUtils.getObjectId,
    getDocumentIdString = ModelUtils.getDocumentIdString,
    winston = require('winston'),
    async = require('async'),
    routeUtils = require('../../route-utils'),
    requirejs = require('../../../lib/requirejs-wrapper'),
    feBeUtils = requirejs('fe-be-utils'),
    apiUtils = require('../utils');

/**
 * module.exports : function to be immediately invoked when this file is require()'ed 
 * 
 * @param app : app instance. Will have the configs appended to a .config property. 
 */
module.exports = function(app) {
  
  /**
   * Get garden photo data
   * 
   * Request:
   * @param {Date} [req.params.start-date] (optional) Should be something parse-able by moment.js
   * @param {Date} [req.params.end-date] (optional) Should be something parse-able by moment.js
   * @param {Number} [req.params.skip]
   * @param {Number} [req.params.limit=200]
   * @param {string=} [req.params.sort]
   *
   * Response:
   * @param {Array[model]} data
   * @param {Number} count
   * @param {Number} skip
   * @param {Number} limit
   */
  app.get('/api/plants/:id/photos', apiUtils.query({
    model : PhotoModel,
    parentModel : PlantModel,
    dateFieldName : 'date',
    defaultSort : '-date'
  }));


  /**
   * Add photos to the garden
   *
   * @param {[File]} req.files
   * @param {feBeUtils.VISIBILITY_OPTIONS=} req.body.visibility
   * @param {[String]=} req.body.tags
   * @param {ObjectId=} req.body.gpi
   */
  app.post('/api/plants/:id/photos', apiUtils.photoPost({
    refModel : PlantModel,
    setPhotoIdOnRef : true
  }));

};
