/**
 * @module models/ImmediateAction
 */

var mongoose = require('mongoose'),
  mongoosePlugins = require('../lib/mongoose-plugins'),
  Schema = mongoose.Schema,
  ObjectIdSchema = Schema.ObjectId,
  mongooseConnection = require('../config/mongoose-connection').defaultConnection,
  winston = require('winston'),
  ImmediateActionModel;

/**
 * ImmediateAction
 * Actions requested that weren't part of standard phase actions.
 * Manually triggered or IdealRange-triggered actions.
 */
var ImmediateActionSchema = new Schema({
    /**
     * The GrowPlanInstance
     */
    gpi : { type: ObjectIdSchema, ref: 'GrowPlanInstance', required: true },


    /**
     * message (virtual)
     * Message is a chance to explain what triggered this action,
     * for example when actions are triggered by an IdealRange violation
     */
    m : { type : String, required: false },

    /**
     * timeRequested (virtual)
     * The time that this action was first requested, either through a sensor trigger or a manual trigger
     */
    tr: { type: Date, required: true, default: Date.now },

    /**
     * timeSent (virtual)
     * The time this action was actually sent, either to the device or user
     */
    ts: { type: Date },

    /**
     * expires (virtual)
     * This should be set at the time the record is created. Device logic will use this
     * to determine what action overrides should still be active
     */
    e : { type : Date , required : true },

    /**
     * action (virtual)
     * Reference to the action
     */
    a : {type: ObjectIdSchema, ref: 'Action', required: true },

    /**
     * done (virtual)
     * "Done" status of the action. Device actions are automatically marked as done.
     * Actions that require user action might require the user to mark it as done...but
     * that's not implemented. For now we'll just mark this as true whenever an action is sent.
     */
    d: {type : Boolean, default : false }
  },
  { id : false });

ImmediateActionSchema.plugin(mongoosePlugins.recoverableRemove);

ImmediateActionSchema.virtual('growPlanInstance')
  .get(function(){
    return this.gpi;
  })
  .set(function(growPlanInstance){
    this.gpi = growPlanInstance;
  });

ImmediateActionSchema.virtual('message')
  .get(function(){
    return this.m;
  })
  .set(function(message){
    this.m = message;
  });

ImmediateActionSchema.virtual('timeRequested')
  .get(function(){
    return this.tr;
  })
  .set(function(timeRequested){
    this.tr = timeRequested;
  });

ImmediateActionSchema.virtual('timeSent')
  .get(function(){
    return this.ts;
  })
  .set(function(timeSent){
    this.ts = timeSent;
  });

ImmediateActionSchema.virtual('expires')
  .get(function(){
    return this.e;
  })
  .set(function(expires){
    this.e = expires;
  });

ImmediateActionSchema.virtual('action')
  .get(function(){
    return this.a;
  })
  .set(function(action){
    this.a = action;
  });

ImmediateActionSchema.virtual('done')
  .get(function(){
    return this.d;
  })
  .set(function(done){
    this.d = done;
  });


/*************** SERIALIZATION *************************/

/**
 * Remove the db-only-optimized property names and expose only the friendly names
 *
 * "Transforms are applied to the document and each of its sub-documents"
 * http://mongoosejs.com/docs/api.html#document_Document-toObject
 */
ImmediateActionSchema.set('toObject', {
  getters : true,
  transform : function(doc, ret, options){
    delete ret.gpi;
    delete ret.tr;
    delete ret.ts;
    delete ret.e;
    delete ret.a;
    delete ret.d;
    delete ret.m;
  }
});
ImmediateActionSchema.set('toJSON', {
  getters : true,
  transform : ImmediateActionSchema.options.toObject.transform
});
/*************** END SERIALIZATION *************************/


/*************** STATIC METHODS *************************/
/**
 * All new instances of ImmediateAction should be created with this method.
 * This method, by default, first checks whether we already have any existing duplicate of the submitted
 * immediateAction that's active (expires is in the future).
 * If so, it returns that existing ImmediateAction.
 *
 *
 * @param {Object} options : Properties of the ImmmediateAction object. All properties are expected to be in friendly form, if a friendly form exists (virtual prop name)
 * @param {function(err, Notification)} callback
 */
ImmediateActionSchema.static('create', function(options, callback){
  var newImmediateAction = new ImmediateActionModel(options),
      now = new Date(),
      expires = newImmediateAction.expires;

  ImmediateActionModel.findOne({
    gpi : newImmediateAction.gpi,
    e : { $gte : now},
    a : newImmediateAction.action
  })
  .exec(function(err, immediateActionResult){
    if (err) { return callback(err); }
    if (immediateActionResult){
      winston.info("RETURNING EXISTING IMMEDIATE ACTION", immediateActionResult._id);
      immediateActionResult.e = newImmediateAction.expires;
      immediateActionResult.save(function(err, updatedImmediateAction){
        return callback(err, updatedImmediateAction);
      });
    } else {
      newImmediateAction.save(callback);
    }
  });
});
/*************** END STATIC METHODS *************************/

ImmediateActionSchema.index({ 'gpi': 1,  'e' : -1, 'ts': -1 });

/**
 * @type {Schema}
 */
exports.schema = ImmediateActionSchema;


/**
 * @constructor
 * @alias module:models/ImmediateAction.ImmediateActionModel
 * @type {Model}
 */
exports.model = ImmediateActionModel = mongooseConnection.model('ImmediateAction', ImmediateActionSchema);