var exec = require('cordova/exec');
var PLUGIN_NAME = 'nslookup';

var nslookup = {

	resolve : function (val, success, error ) {
		exec(success, error, PLUGIN_NAME, 'resolve', val);
	}
};

module.exports = nslookup;
