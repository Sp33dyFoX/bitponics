// var should = require('should'),
//   routeUtils = require('../../../routes/route-utils');

// describe('RouteUtils', function(){
  
//   describe('matchesHeaderLike', function(){
//     it('returns true if a close match exists', function(done){
//       var req = {
//         headers : {
//           "headerKey1" : "headerValue1",
//           "x-bn-mode" : "calib"
//         }
//       };

//       routeUtils.matchesHeaderLike(req, "x-bpn-mode", "calib").should.be.true;
//       done();
//     });

//     it('returns false if a close match does not exist', function(done){
//       var req = {
//         headers : {
//           "headerKey1" : "headerValue1"
//         }
//       };

//       routeUtils.matchesHeaderLike(req, "x-bpn-mode", "calib").should.be.false;
      
//       done();
//     });

//   });

// });
