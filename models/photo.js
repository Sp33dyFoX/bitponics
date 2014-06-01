/**
 * @module models/Photo
 */

const mongoose = require('mongoose'),
  Schema = mongoose.Schema,
  ObjectIdSchema = Schema.ObjectId,
  ObjectId = mongoose.Types.ObjectId,
  requirejs = require('../lib/requirejs-wrapper'),
  feBeUtils = requirejs('fe-be-utils'),
  mongoosePlugins = require('../lib/mongoose-plugins'),
  mongooseConnection = require('../config/mongoose-connection').defaultConnection,
  async = require('async'),
  ModelUtils = require('./utils'),
  getObjectId =  ModelUtils.getObjectId,
  gm = require('gm').subClass({ imageMagick: true }),
  path = require('path'),
  tmpDirectory = path.join(__dirname, '/../tmp/'),
  fs = require('fs');

var PhotoModel;

//fs.mkdir(tmpDirectory);

/**
 * Photo
 */
var PhotoSchema = new Schema({
  
  /**
   * The GrowPlanInstance. Optional. 
   * 
   */
  //gpi : { type: ObjectIdSchema, ref: 'GrowPlanInstance', required: false},

  
  /**
   * concept of ref'ed doc should be generalized rather than just having 'gpi'
   */
  ref : 
  {
    collectionName : { type : String },
    documentId : { type : String }
  },


  tags : [ String ],

  owner : { type: ObjectIdSchema, ref: 'User', required: true },

  
  originalFileName : { type : String },

  
  /**
   * User-assignable date of creation, defaults to now
   */
  date : { type : Date, default : Date.now },


  /** 
   * The MIME-type of the file
   */
  type : { type : String },


  /**
   * User-definable name
   */
  name : { type : String },


  /**
   * Number of bytes of the original photo
   */
  size : { type : Number },

  
  /**
   * Number of bytes of the thumbnail (200x200 max)

   */
  thumbnailSize : { type : Number }
},
{ id : false });

PhotoSchema.plugin(mongoosePlugins.useTimestamps);
PhotoSchema.plugin(mongoosePlugins.visibility);
PhotoSchema.plugin(mongoosePlugins.recoverableRemove);


PhotoSchema.index({ 'ref.documentId' : 1, 'date': -1 }, { sparse : true });


PhotoSchema.virtual('gpi')
  .get(function(){
    if (this.ref && this.ref.collectionName === 'growplaninstances'){
      return this.ref.documentId;
    } else {
      return undefined;
    }
  })
  .set(function(gpi){
    this.ref = {
      'collectionName' : 'growplaninstances',
      'documentId' : getObjectId(gpi)
     }
  });


/*************** SERIALIZATION *************************/


/**
 * Remove the db-only-optimized property names and expose only the friendly names
 *
 * "Transforms are applied to the document and each of its sub-documents"
 * http://mongoosejs.com/docs/api.html#document_Document-toObject
 */
PhotoSchema.set('toObject', {
  getters : true,
  transform : function(doc, ret, options){
  }
});
PhotoSchema.set('toJSON', {
  getters : true,
  transform : PhotoSchema.options.toObject.transform
});
/*************** END SERIALIZATION *************************/






/*************** STATIC METHODS *************************/

/**
 *
 * @param options.owner
 * @param options.originalFileName
 * @param options.name
 * @param options.contentType
 * @param options.date
 * @param options.size
 * @param options.visibility
 * @param {string[]} options.tags
 * @param {ObjectId=} [options.gpi]
 * @param {string=} [options.ref.collectionName]
 * @param {string=} [options.ref.documentId]
 * @param {Stream} options.stream : optional. If set, this is used to stream to S3
 * @param {string} options.filePath: optional. Must be set if options.stream is not set. Path on the file system to stream to S3.
 * @param {bool=} options.preserveFilePath : optional. If true, file at options.filePath is left alone after upload. If omitted or false, file is deleted after uplaod.
 * @param {function} callback - passed (err, photoModels)
 */
PhotoSchema.static("createAndStorePhoto",  function(options, callback){
  if (options.contentType.indexOf("image") !== 0){
    return callback(new Error("Invalid photo content type " + options.contentType));
  }

  var s3Config = require('../config/s3-config'),
      knox = require('knox'),
      knoxClient = knox.createClient(s3Config),
      fs = require('fs'),
      requirejs = require('../lib/requirejs-wrapper'),
      feBeUtils = requirejs('fe-be-utils');

  var now = new Date(),
    photo = new PhotoModel({
      owner : options.owner,
      originalFileName : options.originalFileName,
      name : options.name,
      type : options.contentType,
      date : options.date || now,
      size : options.size,
      tags : options.tags || [],
      visibility : (options.visibility || feBeUtils.VISIBILITY_OPTIONS.PUBLIC)
    });
    
    if (options.ref){
      photo.ref = {
        collectionName : options.ref.collectionName,
        documentId : options.ref.documentId
      }  
    }

    if (options.gpi){
      photo.gpi = options.gpi;
    }

    if (!options.acl){
      options.acl = 'private';
    }

    async.parallel(
      [
        
        function uploadOriginal(innerCallback){
          var knoxMethod = ( (typeof options.stream !== 'undefined') ? 'putStream' : 'putFile'),
            knoxMethodArgument = (knoxMethod === 'putStream' ? options.stream : options.filePath),
            knoxHeaders = {
              'Content-Type': photo.type, 
              'x-amz-acl': options.acl
            };

          if (options.size){
            knoxHeaders["Content-Length"] = options.size;
          }

          knoxClient[knoxMethod](
            knoxMethodArgument,
            s3Config.photoPathPrefix + photo._id.toString(), 
            knoxHeaders, 
            function(err, result) {
              winston.info("RETURNED FROM S3, id: " + photo._id.toString() + ", err:" +  JSON.stringify(err) + ", statusCode: " + result.statusCode);

              if (err) { return innerCallback(err);  }
            
              if (result.statusCode !== 200) {
                return innerCallback(new Error("Status " + (result.statusCode || 'undefined') + " from S3"));
              }

              return innerCallback();
            }
          );
        },

        function createAndUploadThumbnail(innerCallback){

          var intermediateGM,
              thumbnailGM;


          winston.info("CREATING PHOTO THUMB, id: " + photo._id.toString());

          // Constructor is lenient in parsing stream vs path vs buffer. 2nd arg is optional and is only used for filetype inference, so it should handle undefined fine
          // https://github.com/aheckmann/gm#constructor
          if (typeof options.stream !== 'undefined'){
            intermediateGM = gm(options.stream, options.originalFileName)
          } else {
            console.log('options.filePath', options.filePath);
            // use the (stream, filename) call to make sure gm knows the filetype (from originalFileName)
            //var readStream = fs.createReadStream(options.filePath);
            //intermediateGM = gm(readStream, options.originalFileName);
            intermediateGM = gm(options.filePath);
          }

          console.log("PHOTO PROCESSING ", photo._id, "CREATED intermediateGM");
          
          var thumbnailFilePath = tmpDirectory + 'thumb-' + (Math.floor(Math.random() * 10000)) + '-' + (new Date()).valueOf() + '.jpg';

          intermediateGM
          .noProfile()
          // .thumbnail(feBeUtils.PHOTO_THUMBNAIL_SIZE.WIDTH, feBeUtils.PHOTO_THUMBNAIL_SIZE.HEIGHT)
          // .write(thumbnailFilePath, function (err) {
          .thumb(
            feBeUtils.PHOTO_THUMBNAIL_SIZE.WIDTH, 
            feBeUtils.PHOTO_THUMBNAIL_SIZE.HEIGHT, 
            thumbnailFilePath, 
            80, 
            function (err) {
            
              if (err) { 
                winston.error("PHOTO PROCESSING " + photo._id + " ERROR WRITING THUMBNAIL " + thumbnailFilePath);
                return innerCallback(err);  
              }

              knoxClient.putFile(
                thumbnailFilePath,
                s3Config.photoPathPrefix + photo._id.toString() + '/' + feBeUtils.PHOTO_THUMBNAIL_SIZE.WIDTH, 
                {
                  'Content-Type': photo.type, 
                  'x-amz-acl': options.acl
                },
                function(err, result) {
                  result = result || {};
                  
                  winston.info("PHOTO PROCESSING THUMBNAIL RETURNED FROM S3, id: " + photo._id.toString() + ", err:" +  JSON.stringify(err) + ", result: " + JSON.stringify(Object.keys(result)) + ', statusCode:' + JSON.stringify(result.statusCode));

                  fs.unlink(thumbnailFilePath);

                  if (err) { 
                    winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack']));
                    return innerCallback(err);  
                  }
                
                  if (result.statusCode !== 200) {
                    return innerCallback(new Error("Status " + (result.statusCode || 'undefined') + " from S3"));
                  }

                  return innerCallback();
                }
              );
            }
          );


          // .stream(function (err, stdout, stderr) {
          //   if (err) { 
          //     winston.error("ERROR in thumbnail stream " + JSON.stringify(err));
          //     return innerCallback(err);  
          //   }

          //   console.log("PHOTO PROCESSING ", photo._id, " CREATED THUMBNAIL STREAM");

          //   thumbnailGM = gm(stdout);
            
          //   thumbnailGM.filesize({bufferStream : true}, function(err, value){
          //     console.log("PHOTO PROCESSING ", photo._id, " INSIDE filesizeCallback, value ", value);

          //     if (err) { 
          //       winston.error("ERROR in filesizeCallback " + JSON.stringify(err));
          //       return innerCallback(err);  
          //     }

          //     // value is returned in format "724B", need to parse int to get byte number
          //     photo.thumbnailSize = parseInt(value.replace(/\D/g,''), 10);
              
          //     knoxClient.putStream(
          //       thumbnailGM.stream(),
          //       s3Config.photoPathPrefix + photo._id.toString() + '/' + feBeUtils.PHOTO_THUMBNAIL_SIZE.WIDTH, 
          //       {
          //         'Content-Type': photo.type, 
          //         'x-amz-acl': options.acl,
          //         'Content-Length' : photo.thumbnailSize
          //       },
          //       function(err, result) {
          //         winston.info("PHOTO PROCESSING THUMBNAIL RETURNED FROM S3, id: " + photo._id.toString() + ", err:" +  JSON.stringify(err) + ", result: " + JSON.stringify(Object.keys(result)) + ', statusCode:' + JSON.stringify(result.statusCode));

          //         if (err) { 
          //           winston.error(JSON.stringify(err));
          //           return innerCallback(err);  
          //         }
                
          //         if (result.statusCode !== 200) {
          //           return innerCallback(new Error("Status " + (result.statusCode || 'undefined') + " from S3"));
          //         }

          //         return innerCallback();
          //       }
          //     );
          //   });
          //   console.log("PHOTO PROCESSING ", photo._id, " SENT THUMBNAIL TO filesize stream");
          // });
          // .thumb(
          //   feBeUtils.PHOTO_THUMBNAIL_SIZE.WIDTH, 
          //   feBeUtils.PHOTO_THUMBNAIL_SIZE.HEIGHT,
          //   tmpDirectory + 'thumb-' + options.originalFileName,
          //   80,
          //   function (err, stdout, stderr, command){
          //     if (err) { 
          //       winston.error(JSON.stringify(err));
          //       return innerCallback(err);  
          //     }
          //     //innerCallback();
          //     thumbnailGM = gm(tmpDirectory + 'thumb-' + options.originalFileName);
          //     thumbnailGM.filesize({bufferStream : true}, filesizeCallback);
          //     //thumbnailGM = gm.filesize({bufferStream : true}, filesizeCallback);
          //   }
          // );
          
          // Resize to create thumbnail, but don't scale up smaller images
          // http://stackoverflow.com/questions/14705152/thumbnails-from-graphics-magick-without-upscaling
          // intermediateGM
          // .resize(feBeUtils.PHOTO_THUMBNAIL_SIZE.WIDTH, feBeUtils.PHOTO_THUMBNAIL_SIZE.HEIGHT, ">")
          // .gravity('Center')
          // // use a white background rather than transparent. If we're dealing with a jpg, transparent gets rendered as black. No thanks mister.
          // .background('#fff')
          // .extent(feBeUtils.PHOTO_THUMBNAIL_SIZE.WIDTH, feBeUtils.PHOTO_THUMBNAIL_SIZE.HEIGHT);
          
          // // Finalize the processing so that we can get the proper filesize
          // thumbnailGM = gm(intermediateGM.stream(), options.originalFileName);
          
          
        }
      ],
      function(err){
        if (typeof options.filePath !== 'undefined' && !options.preserveFilePath){
          // Delete the file from disk
          fs.unlink(options.filePath);
        }

        if (err) { 
          winston.error("ERROR PROCESSING PHOTO " + photo._id.toString() + " " + JSON.stringify(err));
          return callback(err);
        }

        // If we're here, the photo's good to go
        async.parallel([
          function(innerCallback){
            return photo.save(innerCallback);
          },
          function(innerCallback){
            if (!photo.ref.collectionName){ return innerCallback(); }
            
            var refModel = ModelUtils.getModelFromCollectionName(photo.ref.collectionName);
            console.log("refModel.schema.path('photos')", !!refModel.schema.path('photos'));
            if(!refModel.schema.path('photos')){
              return innerCallback();
            }

            refModel.findById(photo.ref.documentId, function(err, refDocumentResult){

              if (err) {
                winston.error("ERROR RETRIEVING PHOTO REFERENCE DOC " + JSON.stringify(err));
                return innerCallback();
              }
              
              if (!refDocumentResult){
                winston.error("ERROR: DID NOT RETRIEVE PHOTO REFERENCE DOC " + photo._id.toString + ", ref " + ref.documentId);
                return innerCallback();
              }
              
              refDocumentResult.photos.push(photo._id);
              return refDocumentResult.save(innerCallback);  
            });
          }
        ], function(err, results){
          return callback(err, results[0]);
        });
      }
    );
  }
);

/*************** END STATIC METHODS *************************/




/**
 * @type {Schema}
 */
exports.schema = PhotoSchema;

/**
 * @constructor
 * @alias module:models/Photo.PhotoModel
 * @type {Model}
 */
exports.model = PhotoModel = mongooseConnection.model('Photo', PhotoSchema);
