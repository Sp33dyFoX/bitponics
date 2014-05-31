var User = require('../models/user').model,
  routeUtils = require('./route-utils'),
  winston = require('winston'),
  passport = require('passport'),
  querystring = require('querystring'),
  http = require('http'),
  verificationEmailDomain = 'bitponics.com',
  mixpanel = require('../lib/mixpanel-wrapper');

module.exports = function(app){

  // global middleware
  app.all('*', function (req, res, next){
    res.locals({
      user : req.user,
      title: 'Bitponics',
      pageDescription: 'Bitponics is your personal gardening assistant.',
      pageImage: 'http://www.bitponics.com/assets/img/home/Bitponics_social_default.png',
      pageUrl: 'http://www.bitponics.com'
    });
    next();
  });


  app.get('/', function (req, res){
    var locals = {
      title: "Bitponics",
      className: "landing-page",
      pageType: "landing-page"
    };
    res.render('index', locals);
  });

  
  app.get('/help', function (req, res){  
    mixpanel.track(req.user, "help");  
    //res.redirect('http://help.bitponics.com');
    var locals = {
      title: "Help",
      className: "app-page",
      pageType: "app-page"
    };
    res.render('help', locals);
  });

  app.get('/about', function (req, res){
    var locals = {
      title: "About",
      className: "landing-page single-page about",
      pageType: "landing-page"
    };
    res.render('about', locals);
  });

  app.get('/how-it-works', function (req, res){
    var locals = {
      title: "How It Works",
      className: "landing-page single-page how-it-works",
      pageType: "landing-page"
    };
    res.render('howitworks', locals);
  });

  app.get('/gallery', function (req, res){
    var locals = {
      title: "Gallery",
      className: "landing-page single-page gallery",
      pageType: "landing-page"
    };
    res.render('gallery', locals);
  });

  app.get('/pricing', function (req, res){
    var locals = {
      title: "Pricing",
      className: "landing-page single-page pricing",
      pageType: "landing-page"
    };
    res.render('pricing', locals);
  });

  app.get('/press', function (req, res){
    var locals = {
      title: "Press",
      className: "landing-page single-page press",
      pageType: "landing-page"
    };
    res.render('press', locals);
  });

  app.get('/contact', function (req, res){
    var locals = {
      title: "Contact",
      className: "landing-page single-page contact",
      pageType: "landing-page"
    };
    res.render('contact', locals);
  });

  app.get('/team', function (req, res){
    var locals = {
      title: "Our Team",
      className: "landing-page single-page team",
      pageType: "landing-page"
    };
    res.render('team', locals);
  });

  app.get('/get-started', function (req, res){
    var locals = {
      title: "Get Started",
      className: "landing-page single-page get-started",
      pageType: "landing-page"
    };
    //res.render('getstarted', locals);
    res.redirect('/signup');
  });

  app.get('/privacy', function (req, res){
    var locals = {
      title: "Privacy",
      className: "landing-page single-page privacy",
      pageType: "landing-page"
    };
    res.render('privacy', locals);
  });

  app.get('/returns', function (req, res){
    var locals = {
      title: "Return",
      className: "landing-page single-page returns",
      pageType: "landing-page"
    };
    res.render('returns', locals);
  });


  app.get('/installs', function (req, res) {
    var locals = {
      title: "Installs",
      className: "landing-page single-page installs",
      pageType: "landing-page"
    };
    res.render('installs', locals);
  });
  
  app.get('/install', function (req, res) {
    res.redirect('/installs');
  });

  app.get('/login', 
    routeUtils.middleware.ensureSecure, 
    function (req, res){
      var redirect = req.query.redirect,
        locals = {
          title: 'Login',
          formAction : '/login',
          className: "app-page single-page get-started",
          pageType: "app-page",
          loginErrorMessage: req.flash('loginError')
        };


      // if user is already logged in
      if (routeUtils.isUserLoggedIn(req)){
        mixpanel.increment(req.user, "logins");
        return res.redirect(req.query.redirect || '/dashboard');
      } 
      
      if (redirect){
        locals.formAction += '?redirect=' + redirect;
      }

      return res.render('login', locals);  
    }
  );

  app.post('/login', 
    routeUtils.middleware.ensureSecure, 
    function (req, res, next){
      passport.authenticate('local', function(err, user, info) {
          if (err) { return next(err); }
          if (!user) {
            winston.info(info);
            req.flash('loginError', info.message);
            return res.redirect('/login')
          }

          mixpanel.track(user, "login", { redirect: req.query.redirect });
          mixpanel.increment(user, "logins");

          req.logIn(user, function(err) {
            if (err) { return next(err); }
            return res.redirect(req.query.redirect || '/dashboard');
          });
        })(req, res, next);
    }
  );

  app.get('/signup', 
    routeUtils.middleware.ensureSecure, 
    function (req, res){
      res.render('signup', {
        title : 'Signup',
        className: "signup single-page app-page",
          pageType: "app-page"
      });
    }
  );

  app.post('/signup', 
    routeUtils.middleware.ensureSecure, 
    function (req, res, next){
      User.createUserWithPassword({
        email: req.param('email'),
        name : {
          first : req.param('firstname'),
          last : req.param('lastname')
        }
      },
      req.param('password'),
      function(err, user){
        if (err) { 
          //if already registered email address then just log in and send to register confirmation
          if(err.toString().indexOf('E11000') != -1 && err.toString().indexOf('bitponics-local.users.$email') != -1){
            req.logIn(user, function(err) {
              if (err) { return next(err); }
              return res.redirect('/register');
            });
          } else {
            //else generic error
            return next(err);
          }
          // return next(err);
        } else {

          mixpanel.track(user, "signup");


          winston.info("req.param('newsletter')" + req.param('newsletter'));
          
          if(req.param('newsletter')){
            mixpanel.track(user, "newsletter signup");
            winston.info('newsletter signup')

            /*
             * Sign user up for email newsletter if they check the checkbox
             */

            // Build the post string from an object
            var post_data = querystring.stringify({
                'EMAIL' : req.param('email'),
                'subscribe' : req.param('subscribe')
            });

            // An object of options to indicate where to post to
            var post_options = {
                host: 'bitponics.us2.list-manage1.com',
                port: '80',
                path: '/subscribe/post?u=68c690cb49ec37200919b6e55&amp;id=9b5ad31a92',
                method: 'POST',
                headers: {
                  'Host': 'bitponics.us2.list-manage1.com',
                  'Content-Type': 'application/x-www-form-urlencoded',
                  'Content-Length': post_data.length,
                  'Cache-Control':  'max-age=0',
                  'Accept': 'text/html',
                  'Origin': 'http://bitponics.com',
                  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_2) AppleWebKit/537.32 (KHTML, like Gecko) Chrome/27.0.1421.0 Safari/537.32',
                  'Referer': 'http://bitponics.com/contact',
                  // 'Accept-Encoding': 'gzip,deflate,sdch',
                  'Accept-Language': 'en-US,en;q=0.8',
                  // 'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
                  'Cookie': 'PHPSESSID=nnv0ks7p91s1hmb63e20gupj03; _AVESTA_ENVIRONMENT=prod',
                  'Pragma': 'no-cache',
                  'Cache-Control': 'no-cache'
                }
            };

            // Set up the request
            var post_req = http.request(post_options, function(res) {
                var response = '';
                res.setEncoding('utf8');
                res.on('data', function (chunk) {
                    response += chunk;
                });
                res.on('end', function(){
                  //console.log(response);
                  winston.info('newsletter signup email sent');
                });
            });

            post_req.on('error', function(e) {
              winston.error(JSON.stringify(err, ['message', 'arguments', 'type', 'name', 'stack']));
            });

            // post the data
            post_req.write(post_data);
            post_req.end();
          }




          req.logIn(user, function(err) {
            if (err) { return next(err); }
            res.redirect('/register');
          });
        }
      });
    }
  );
    
  app.get('/logout', function (req, res) {
    if (routeUtils.isUserLoggedIn(req)){
      mixpanel.track(req.user, "logout");  
    }

    req.session.regenerate(function(){
      req.logout();
      res.redirect('/')  
    });
  });

  
  /*
   * Email verification
   * 
   */
  app.get('/register', 
    routeUtils.middleware.ensureSecure, 
    function (req, res, next) {
      var UserModel = require('../models/user').model,
          locals = {
          title: 'Welcome to Bitponics!',
          header: 'Thank you.',
          message: 'Thanks for signing up. Check your email.',
          className: "landing-page single-page getstarted register",
          pageType: "landing-page"
          };

        if(req.query.verify){ //user coming back to verify account
            return UserModel.findOne({ activationToken: req.query.verify }, 
            function (err, user) {
              if (err) { return next(err); }
                if (user) {
                  mixpanel.track(user, "activate registration");
                }
              if (user && user.activationToken !== '') {
                user.active = true;
                user.sentEmail = true; //if we get here, this should be true
                user.save( function(err, user){
                  if (err) { return next(err); }
                  locals.header =  "All set!";
                          locals.message = 'Your account is now verified.';
                  locals.link = '/setup/grow-plan';
                  // locals.message = 'Your registration was successfull. Have you preordered a device yet?';
                  locals.user = user;
                  res.render('register', locals);
                });
              } else {
                locals.message = 'There was an error validating your account. Please try signing up again.';
                res.render('register', locals);
              }
            }
          );
        } else if(req.query.status == 'success') { //user preordered successfully
        locals.message = 'You\'ve successfully preordered a Bitponics device';
        //TODO: here we could also collect additional info on user (amazon setting)
        } else if(req.query.status == 'abandon') { //user cancelled preorder process mid-way
          locals.message = 'Issues preordering the device?';
      } else { //user has signed up, so tell them to check email to verify or if already verified then redirect to /gardens
          
        if (req.user.active) {
          return res.redirect('/gardens');
        } else {
            locals.header =  "Thanks for signing up!";
              locals.message = "We've sent you a welcome email. When you get a chance, click the activation link in that email.<br/><br/>In the meanwhile, let's get you growing!";
              locals.link = '/setup/grow-plan';
          }

      }
      
      return res.render('register', locals);
    }
  );

  // app.get('/robots.txt', function (req, res){
  //   res.send('User-agent: *\r\nDisallow: /');
  // });


  require('./account')(app);
  require('./admin')(app);
  require('./api')(app);
  require('./blog')(app);
  require('./dashboard')(app);
  require('./gardens')(app);
  require('./grow-plans')(app);
  require('./guides')(app);
  require('./photos')(app);
  require('./profiles')(app);
  require('./reset')(app);
  require('./setup')(app);
  require('./sockets')(app);
  require('./styleguide')(app);
  

  /*
   * Legacy PHP site routes
   */
  require('./legacy')(app);


  // The call to app.use(app.router); is to position the route handler in the middleware chain.
  // Everything afterward is assumed to have not matched a route.
  // https://github.com/visionmedia/express/blob/master/examples/error-pages/index.js
  app.use(app.router);
};
