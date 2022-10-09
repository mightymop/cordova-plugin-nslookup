var exec = require('cordova/exec');
var PLUGIN_NAME = 'Nslookup';

var nslookup = {

	lookup : function (val, success, error ) {
		exec(success, error, 'Nslookup', 'lookup', [{value:val}]);
	}
};

module.exports = nslookup;
