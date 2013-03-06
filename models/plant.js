var mongoose = require('mongoose'),
	mongooseTypes = require('mongoose-types'),
	Schema = mongoose.Schema,
	mongoosePlugins = require('../lib/mongoose-plugins'),
	useTimestamps = mongoosePlugins.useTimestamps,
	ObjectId = Schema.ObjectId;

var PlantSchema = new Schema({
	name: { type: String, required: true }
},
{ id : false });

PlantSchema.plugin(useTimestamps);

PlantSchema.path('name').index({ unique: true });

exports.schema = PlantSchema;
exports.model = mongoose.model('Plant', PlantSchema);
