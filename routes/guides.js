module.exports = function(app){

  app.get('/guides/water-culture-system', function (req, res){
    res.render('guides/waterculturesystem', {
      title: "Bitponics Water Culture System",
      className: "landing-page single-page guides water-culture-system",
    pageType: "landing-page"
    });
  });

  app.get('/guides/bitponics-open-hardware', function (req, res){
    res.render('guides/bitponics-open-hardware', {
      title: "Bitponics Open Hardware",
      className: "landing-page single-page guides bitponics-open-hardware",
      pageType: "landing-page"
    });
  });


  app.get('/guides', function (req, res){
    res.render('guides', {
      title: "Bitponics Guides",
      className: "landing-page single-page",
      pageType: "landing-page"
    });
  });
};
