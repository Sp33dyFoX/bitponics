module.exports = {

  processNewPhotos : function(PhotoModel, callback){
    var FTPClient = require('jsftp'),
    async = require('async'),
    fs = require('fs'),
    requirejs = require('../lib/requirejs-wrapper'),
    feBeUtils = requirejs('fe-be-utils'),
    ftpConfig = {
      user: 'hyatt@bitponics.host-ed.me',
      password: 'q9YM5P11mY+PW*c',
      host: 'ftp.bitponics.host-ed.me',
      port: 21
    },
    path = require('path'),
    ftpDirectory = './cam',
    tmpDirectory = path.join(__dirname, '/../tmp/'),
    fileList,
    createdPhotos = [],
    gm = require('gm').subClass({ imageMagick: true }),
    winston = require('winston');
    

    var client = new FTPClient(ftpConfig);
    

    async.waterfall(
      [
        function authConnection(innerCallback){
          winston.info("AUTHENTICATING FTP CLIENT");
          client.auth(ftpConfig.user, ftpConfig.password, function(err, res){
            return innerCallback(err, res);
          });
        },
        function setCWD(res, innerCallback){
          winston.info("FTP AUTH response", res);

          winston.info("SETTING CWD FTP CLIENT");
          client.raw.cwd(ftpDirectory, function(err, res){
            
            if (err) { return innerCallback(err); }
            winston.info("FTP CWD response", res);
            
            winston.info("PRINTING CWD FTP CLIENT");
            client.raw.pwd(function(err, res){
              return innerCallback(err, res);
            });
          });
        },
        function listFiles(pwdResponse, innerCallback){
          winston.info("FTP PWD", pwdResponse);

          winston.info("FTP LS ./");
          client.ls('./', function(err, fileList){
            winston.info("FTP LS ./", fileList);

            if (err) { return innerCallback(err); }
            
            fileList = (fileList || []).filter(
              function(responseItem){ 
                if (!responseItem) { return false; }
                
                var extension = responseItem.name.split('.');
                extension = extension[extension.length - 1].toLowerCase();
                responseItem.contentType = "image/" + extension;
                return (extension === 'jpg' || extension == 'jpeg' || extension == 'png');
              }
            );
            winston.info(fileList);
            client.keepAlive();
            return innerCallback(null, fileList);
          });
        },
        function iterateFiles(fileList, innerCallback){
          var fileIterator = function (fileMetaData, iteratorCallback){
            client.keepAlive();
            client.get("./" + fileMetaData.name, function(err, fileBuffer) {
              if (err) { return iteratorCallback(err); }

              winston.info("RETRIEVED FILE ", fileMetaData);
              

              var localFilePath = tmpDirectory + fileMetaData.name;
              winston.info("WRITING FILE TO TMP " + localFilePath);

              client.keepAlive();
              fs.writeFile(localFilePath, fileBuffer, function(err) {
                
              // https://github.com/aheckmann/gm#buffers
              //gm(fileBuffer, fileMetaData.name)
                client.keepAlive();
              
              
                //gm(localFilePath)
                //.rotate("#fff", 90)
                //.write(localFilePath, function (err) {
                  winston.info("CALLBACK FROM WRITING FILE TO TMP", localFilePath, fileMetaData);
                  if (err) { 
                    winston.error("ERROR IN CALLBACK FROM WRITING FILE TO TMP " + JSON.stringify(err)); 
                    return iteratorCallback(err); 
                  }

                  client.keepAlive();
                  PhotoModel.createAndStorePhoto(
                    {
                      owner : "506de30a8eebf7524342cb6c",//"506de30a8eebf7524342cb6c",// Amit //"51ac0117a3b04db08057e04a", // HRJC Anderson
                      gpi : "51b4e59dcda057020000000c",
                      originalFileName : fileMetaData.name,
                      name : fileMetaData.name,
                      contentType : fileMetaData.contentType,
                      date : new Date(fileMetaData.time),
                      size : fileMetaData.size,
                      visibility : feBeUtils.VISIBILITY_OPTIONS.PUBLIC,
                      filePath : localFilePath
                    },
                    function(err, photo){
                      winston.info("IN Photo creation callback");

                      if (photo) { createdPhotos.push(photo); }
                    
                      
                      //var newClient = new FTPClient(ftpConfig);
                      //newClient.auth(ftpConfig.user, ftpConfig.password, function(err){
                        client.raw.dele(fileMetaData.name, function(err, data){
                          winston.info("DELETED FILE ", data);
                          return iteratorCallback(err, photo);  
                        });
                      //});
                      //newClient.keepAlive();
                    }
                  );
                });
              //});
            });
          };

          if (fileList.length){
            var fileQueue = async.queue(fileIterator, 1);
            fileQueue.drain = function(){
              winston.info("FTP PHOTO FETCHER FINISHED PROCESSING ALL FILES");
              client.raw.quit(function(err, res) {
                return innerCallback(err, createdPhotos);
              });
            };
            fileQueue.push(fileList, function(err){
              winston.info("FTP PHOTO FETCHER FINISHED PROCESSING A FILE");
              if (err) { winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack']));}
            });
          } else {
            return innerCallback(err, []);
          }
        }
      ],
      function(err, result){
        if (err){ winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack'])); }

        return callback(err, result);
      }
    );
  }
};
