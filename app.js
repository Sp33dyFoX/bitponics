
/**
 * Module dependencies.
 */

var express = require('express')
	, http = require('http')
	, app = module.exports = express.createServer()
	, net = require('net')
	, io = require('socket.io').listen(app)
	, port = (process.env.VMC_APP_PORT || 3000)
	, host = (process.env.VCAP_APP_HOST || '0.0.0.0');

var tcpGuests = [];
// Configuration
if(process.env.VCAP_SERVICES){
  var env = JSON.parse(process.env.VCAP_SERVICES);
  var mongo = env['mongodb-1.8'][0]['credentials'];
}
else{
  var mongo = {"hostname":"localhost","port":27017,"username":"",
    "password":"","name":"","db":"db"}
}

var generate_mongo_url = function(obj){
  obj.hostname = (obj.hostname || 'localhost');
  obj.port = (obj.port || 27017);
  obj.db = (obj.db || 'test');
console.log('mongodb db is:' + obj.db);

  if(obj.username && obj.password){
    return "mongodb://" + obj.username + ":" + obj.password + "@" + obj.hostname + ":" + obj.port + "/" + obj.db;
  }
  else{
    return "mongodb://" + obj.hostname + ":" + obj.port + "/" + obj.db;
  }
}

var mongourl = generate_mongo_url(mongo);

app.configure(function(){
  app.set('views', __dirname + '/views');
  app.set('view engine', 'jade');
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});

app.configure('development', function(){
  app.use(express.errorHandler({ dumpExceptions: true, showStack: true })); 
});

app.configure('production', function(){
  app.use(express.errorHandler()); 
});


// Methods
var record_visit = function(req, res){
  /* Connect to the DB and auth */
  require('mongodb').connect(mongourl, function(err, conn){
    conn.collection('ips', function(err, coll){
      /* Simple object to insert: ip address and date */
      object_to_insert = { 'ip': req.connection.remoteAddress, 'ts': new Date() };

      /* Insert the object then print in response */
      /* Note the _id has been created */
      coll.insert( object_to_insert, {safe:true}, function(err){
        if(err) { console.log(err.stack); }
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.write(JSON.stringify(object_to_insert));
        res.end('\n');
      });
    });
  });
}

var print_visits = function(req, res){
  /* Connect to the DB and auth */
  require('mongodb').connect(mongourl, function(err, conn){
    conn.collection('ips', function(err, coll){
      coll.find({}, {limit:10, sort:[['_id','desc']]}, function(err, cursor){
        cursor.toArray(function(err, items){
          res.writeHead(200, {'Content-Type': 'text/plain'});
          for(i=0; i<items.length;i++){
            res.write(JSON.stringify(items[i]) + "\n");
          }
          res.end();
        });
      });
    });
  });
}

// Routes

app.get('/dashboard', function(req, res){
	//print_visits(req, res);
	

  res.render('dashboard', {
    title: 'Express',
	locals : { temp: 1 }
  });

});

app.get('/', function(req, res){
record_visit(req, res);
/*
res.render('index', {
    title: 'Express'
  });
*/
});


app.listen(port, host, function(){
  console.log("Express server listening on port %d", app.address().port);
});



io.sockets.on('connection', function (socket) {
  socket.emit('news', { hello: 'world' });
  socket.on('sensor_event', function (data) {
    socket.broadcast.emit('sensor_event', data);
  });
});



//tcp socket server
var tcpServer = net.createServer(function (socket) {
  console.log('tcp server running on port 1337');
});

tcpServer.on('connection',function(socket){
    socket.write('connected to the tcp server\r\n');
    console.log('num of connections on port 1337: ' + tcpServer.connections);
    
    tcpGuests.push(socket);
    
    socket.on('data',function(data){
		
		console.log('received on tcp socket:', data);
        socket.write('msg received\r\n');
		socket.write(data);
		socket.write('\r\n');
		socket.write('end msg\r\n');
		
		
		try{
			var processedData = data.toString('ascii',0,data.length);
			processedData = JSON.parse(processedData);
			processedData.timestamp = new Date();
			
			require('mongodb').connect(mongourl, function(err, conn){
				console.log('connected to mongodb');
			    conn.collection('sensor_logs', function(err, coll){
					console.log('writing to sensor_logs :', processedData);
			      coll.insert( processedData, {safe:true}, function(err){
					console.log('wrote to sensor_logs');
			        if(err) { console.log(err.stack); }
					conn.close();
			      });
			    });
			  });
			
			var socks = io.sockets.sockets;
			for (s in socks) {
				if (socks[s] && socks[s].emit){
					console.log('emitting to a client');
					socks[s].emit('sensor_event', processedData); //{message:["arduino",data.toString('ascii',0,data.length)]});
				}
			}
		} catch(e){ console.log("Error parsing TCP data : ", e);}

        
        
        
		/*
		//send data to guest socket.io chat server
        for (g in io.clients) {
            var client = io.clients[g];
            client.send({message:["arduino",data.toString('ascii',0,data.length)]});
            
        }
		*/
    })
});
tcpServer.listen(1337);