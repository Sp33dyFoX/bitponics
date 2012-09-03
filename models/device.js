var mongoose = require('mongoose'),
	mongooseTypes = require('mongoose-types'),
  	Schema = mongoose.Schema,
  	useTimestamps = mongooseTypes.useTimestamps,
  	ObjectId = Schema.ObjectId;

var DeviceSchema = new Schema({
	id: { type: String, required: true, unique: true }, //mac address
	name : { type: String },
	users : [ { type: ObjectId, ref: 'User', required: true }],
	//sensors : [ { type: ObjectId, ref: 'Sensor', required: true }],
	sensorMap: [
	  { 
		control : { type: ObjectId, ref: 'Sensor' },
		outletId : { type: String }
	  }
	],
	controlMap : [ 
	  { 
	    control : { type: ObjectId, ref: 'Control' },
	    outletId : { type: String }
	  }
	]
});

DeviceSchema.plugin(useTimestamps);

exports.schema = DeviceSchema;
exports.model = mongoose.model('Device', DeviceSchema);