var mongoose = require('mongoose'),
	mongooseTypes = require('mongoose-types'),
  	Schema = mongoose.Schema,
  	mongoosePlugins = require('../lib/mongoose-plugins'),
    useTimestamps = mongoosePlugins.useTimestamps,
  	ObjectId = Schema.ObjectId,
  	ActionModel,
  	ActionSchema,
  	async = require('async');

ActionSchema = new Schema({
	
	description: { type: String, required: true },
	
	control: { type: ObjectId, ref: 'Control', required: false },
	
	/**
	 * Action schedules are represented by a cycle. 
	 * Cycles have a series of states. Discreet actions are
	 * those with a "repeat" == false.
	 * 
	 * Actions trigger with phase start. They can be offset
	 * using an intial cycle state with no message or value,
	 * just a duration. 
	 *
	 * Cycles can have 1-3 states. See the pre-save hook below for validation details.
	 * 
	 * Also, all fields are optional. 
	 */
	cycle: {
	
		states: [
			{
				controlValue: { type: String },

				durationType: { type: String, enum: [
					'milliseconds',
					'seconds',
					'minutes',
					'hours',
					'days',
					'weeks',
					'months',
					'untilPhaseEnd'
				]},
				
				duration: { type: Number },
				
				message: { type: String }
			}
		],

		repeat: { type: Boolean, default: false }
	}
});

ActionSchema.plugin(useTimestamps);

ActionSchema.virtual('overallCycleTimespan')
	.get(function () {
		// default to a 1 year max duration
		var total = 1000 * 60 * 60 * 24 * 365,
			cycle = this.cycle,
			states;

		if (!cycle || !cycle.states.length){ return total; }

		states = cycle.states;
		switch(states.length){
			case 1:
				break;
			case 2:
			case 3:
				total = 0;
				states.forEach(function(state){
					total += actionUtils.convertDurationToMilliseconds(state.durationType, state.duration);
				});
				break;
				// no default; we've enforced that we have one of these values already
		}
		return total;
	});


/**
 * Now that schema is defined, add indices
 */
 // Want a sparse index on control (since it's an optional field)
ActionSchema.index({ control: 1, 'cycle.repeat': 1 }, { sparse: true});

/**
 *  Validate cycle states
 *
 *  A cycle either represents a discrete action or a pair of states.
 * 
 *  Cycles always start with the start of a phase, and 
 *  phases always start at the start of a day (at 00:00:00) local time.
 *
 *  An "offset" cycle, like a 16-hour light cycle that starts at 6am,
 *  is represented with 3 states, with the 1st and 3rd having the same value.
 */
ActionSchema.pre('save', function(next){
	var action = this,
		cycle = action.cycle,
		states;
	
	if (!cycle.states.length){ return next(); }

	states = cycle.states;
	
	if ((states.length > 3)){
		return next(new Error('Invalid number of cycle states'));
	}
	
	switch(states.length){
		case 1:
			// if a cycle has 1 state, it's considered a discrete action and must have a "repeat" of false
			// TODO : should this throw an error or just set the correct value silently?
			if (cycle.repeat){
				return next(new Error('Actions with single-state cycles are considered discrete actions and must have "repeat" set to false'))
			}
			break;
		case 2:
			break;
		case 3:
			// if a cycle has 3 states, the 1st and 3rd must have the same control value
			if (states[0].controlValue !== states[2].controlValue){
				return next(new Error('First and last control values must be equal'))
			}
			break;
		// no default; we've enforced that we have one of these values already
	}

  	next();
});

ActionModel = mongoose.model('Action', ActionSchema);


var actionUtils = {
	convertDurationToMilliseconds : function(durationType, duration){
		switch(durationType){
			case 'milliseconds':
				return duration;
			case 'seconds':
				return duration * 1000;
			case 'minutes':
				return duration * 1000 * 60;
			case'hours':
				return duration * 1000 * 60 * 60;
			case 'days':
				return duration * 1000 * 60 * 60 * 24;
			case 'weeks':
				return duration * 1000 * 60 * 60 * 24 * 7;
			case 'months':
				// TODO : Figure out a proper way to handle month-long durations. variable day spans.
				return duration * 1000 * 60 * 60 * 24 * 30;
			case 'untilPhaseEnd':
			default:
				// an infinite duration.
				return -1;
		}
	},

	/**
	 * Takes a string with the tokens {offset},{value1},{duration1},{value2},{duration2}
	 * and replaces each field with the proper values 
	 * 
	 * Assumes it's passed an action with states with controlValues.
	 *
	 * @param offset. Only a factor in a 3-state cycle, where we need to pull it back by the duration of the 3rd state
	 *                Otherwise it's just written straight to the template.
	 */
	updateCycleTemplateWithStates : function(cycleTemplate, actionCycleStates, offset){
		var //result = cycleTemplate,
			states = actionCycleStates,
			convertDurationToMilliseconds = actionUtils.convertDurationToMilliseconds,
			offset = offset || 0,
			result = {
				cycleString : '',
				offset : 0,
				value1 : 0,
				duration1 : 0,
				value2 : 0,
				duration2 : 0
			};

		switch(states.length){
			case 1:
				var infiniteStateControlValue = states[0].controlValue;
				result.offset = offset;
				result.value1 = infiniteStateControlValue;
				result.duration1 = 1;
				result.value2 = infiniteStateControlValue;
				result.duration2 = 1;
				break;
			case 2:
				var state0 = states[0],
					state1 = states[1];
				
				result.offset = offset;
				result.value1 = state0.controlValue;
				result.duration1 = convertDurationToMilliseconds(state0.durationType, state0.duration);
				result.value2 = state1.controlValue;
				result.duration2 = convertDurationToMilliseconds(state1.durationType, state1.duration);
				break;
			case 3:
				// If a 3-state cycle, the 1st and 3rd are assumed to be contiguous (have the same controlValue)

				var state0 = states[0],
					state1 = states[1],
					state2 = states[2],
					firstDuration = convertDurationToMilliseconds(state0.durationType, state0.duration),
					thirdDuration = convertDurationToMilliseconds(state2.durationType, state2.duration),
					totalFirstDuration = firstDuration + thirdDuration;
				
				// for a 3-state cycle, offset should effectively subtract 3rd state from the totalFirstDuration
				// and if we got an offset, add that os.getNetworkInterfaces();
				result.offset = offset + thirdDuration;
				result.value1 = state0.controlValue;
				result.duration1 = totalFirstDuration;
				result.value2 = state1.controlValue;
				result.duration2 = convertDurationToMilliseconds(state1.durationType, state1.duration);
				break;
			default: 
				winston.info('Serializing a blank actionCycleState');
				result.offset = 0;
				result.value1 = 0;
				result.duration1 = 0;
				result.value2 = 0;
				result.duration2 = 0;
				break;
		}

		var resultCycleString = cycleTemplate;
		resultCycleString = resultCycleString.replace(/{offset}/, result.offset);
		resultCycleString = resultCycleString.replace(/{value1}/, result.value1);
		resultCycleString = resultCycleString.replace(/{duration1}/, result.duration1);
		resultCycleString = resultCycleString.replace(/{value2}/, result.value2);
		resultCycleString = resultCycleString.replace(/{duration2}/, result.duration2);
		result.cycleString = resultCycleString;

		return result;
	}
};


exports.schema = ActionSchema;
exports.model = ActionModel;
exports.utils = actionUtils;



/**
updateDeviceCycleTemplateWithStates : function(deviceCycleTemplate, finalCallback){
		var action = this,
			states = action.cycle.states,
			resultArray = [],
			convertDurationToMilliseconds = ActionModel.convertDurationToMilliseconds;

		switch(states.length){
			case 1:
				var infiniteStateControlValue = states[0].controlValue;
				resultArray.push(infiniteStateControlValue + ',' + infiniteStateControlValue )
				//return finalCallback(new Error('Cannot convert single-state cycle to device format'));
				break;
			case 2:
				var state0 = states[0],
					state1 = states[1];
				
				async.series([
					function(callback){
						resultArray.push(state0.controlValue + ',');
						convertDurationToMilliseconds(
							state0.durationType, 
							state0.duration, 
							function(err, duration){
								if (err) { return callback(err);}
								resultArray.push(duration + ',');
								callback();		
							});
					},
					function(callback){
						resultArray.push(state1.controlValue + ',');
						convertDurationToMilliseconds(
							state1.durationType, 
							state1.duration, 
							function(err, duration){
								if (err) { return callback(err);}
								resultArray.push(duration);
								callback();		
							}
						);	
					}
					], 
					function(err, result){ 
						if (err) { return callback(err);} 
						return finalCallback(null, resultArray.join(''));
					}
				);
				
				break;
			case 3:
				var state0 = states[0],
					state1 = states[1],
					state2 = states[2],
					firstDuration;
				
				// If a 3-state cycle, the 1st and 3rd must be contiguous, so they
				async.series([
					function(callback){
						convertDurationToMilliseconds(
							state0.durationType, 
							state0.duration, 
							function(err, duration){
								if (err) { return callback(err);}
								firstDuration = duration;
								callback();		
							}
						);
					},
					function(callback){
						convertDurationToMilliseconds(
							state2.durationType, 
							state2.duration, 
							function(err, duration){
								if (err) { return callback(err);}
								firstDuration += duration;
								resultArray.push(state0.controlValue + ',');
								resultArray.push( firstDuration + ',');	
								callback();		
							}
						);
					},
					function(callback){
						resultArray.push(state1.controlValue + ',');
						convertDurationToMilliseconds(
							state1.durationType, 
							state1.duration, 
							function(err, duration){
								if (err) { return callback(err);}
								resultArray.push(duration);
								callback();		
							});	
					}
					], 
					function(err, result){ 
						if (err) { return callback(err);} 
						return finalCallback(null, resultArray.join(''));
					}
				);
				break;
		}
	}
*/