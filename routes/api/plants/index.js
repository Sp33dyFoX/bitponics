module.exports = function(app){
    require('./plants')(app);
    require('./photos')(app);
};