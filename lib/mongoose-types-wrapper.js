/**
 * Overrides mongoose-types' Email type with a regex that allows "+" characters
 *
 * Uses regex from http://stackoverflow.com/questions/46155/validate-email-address-in-javascript
 */
var mongoose = require('mongoose'),
 	mongooseTypes = require('./mongoose-types');

mongooseTypes.loadTypes(mongoose, 'url');


var SchemaTypes = mongoose.SchemaTypes;

function Email (path, options) {
  SchemaTypes.String.call(this, path, options);
  function validateEmail (val) {
    console.log('calling')
    return /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(val);
  }
  this.validate(validateEmail, 'email is invalid');
}
Email.prototype.__proto__ = SchemaTypes.String.prototype;
Email.prototype.cast = function (val) {
  return val.toLowerCase();
};

SchemaTypes.Email = Email;
mongoose.Types.Email = String;
