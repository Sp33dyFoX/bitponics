/**
 * Must first be require()'ed as a function, passing in the environment.
 * Subsequent requires can simply call require('mongo-connection').defaultConnection
 */

var mongoose = require('mongoose');
var winston = require('winston');
var getenv = require('getenv');

var self = {

	defaultConnection : undefined,

	connections : {},

	connectionOptions : {
		server : {
      auto_reconnect : true,
      socketOptions : {
          keepAlive : 1
      }//,
      //ssl: true
    },
    replset : {
      auto_reconnect : true,
      socketOptions : {
          keepAlive : 1
      }
    }
	},

	
	/**
	 *
	 * @param {string} environment : an environment key
	 * @param {function(err, connection)=} callback : optional
	 */
	open : function(environment, callback){
		
		var connection = self.connections[environment],
				url;
		
		if (connection){
			winston.info("DATABASE RETURNING OPEN CONNECTION TO " + environment);
			if (callback){
				callback(null, connection);
			}
			return connection;
		}

		url = getenv('BPN_MONGO_SERVER', false);

		winston.info("DATABASE OPENING CONNECTION TO " + url);

		connection = (new mongoose.Mongoose()).createConnection(
			url, 
			self.connectionOptions
		);

		connection.once("connected", function(){
			winston.info("CONNECTED TO DATABASE " + url);
			if (callback){
				callback(null, connection);
			}
		});

		connection.once("error", function(err){
			winston.error("ERROR connecting TO DATABASE " + url + " " + err.toString());
			if (callback){
				callback(err);
			}
		});

		// mongoose internally queues up DB commands before a connection is opened, so we don't 
		// need to wait for the callback to set these properties and make them available
		if (!self.defaultConnection) {
			self.defaultConnection = connection;
		}

		self.connections[environment] = connection;

		return connection;
	}
};

module.exports = self;
