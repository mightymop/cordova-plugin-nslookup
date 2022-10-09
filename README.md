# Android:

### 1. Add plugin
cordova plugin add https://github.com/mightymop/cordova-plugin-nslookup.git
### 2. For Typescript add following code to main ts file: 
/// &lt;reference types="cordova-plugin-nslookup" /&gt;<br/>
### 3. Usage:
```
var query =  [
      {query: "google.com"},
      {query: 'google.com',type: 'AAAA' },
      {query: 'www.tiste.org',type: 'CNAME'}, 
      {query: 'google.com',type: 'MX' }, 
      {query: 'google.com',type: 'NS'}, 
      {query: '192.x.x.x.in-addr.arpa',type: 'PTR'}, 
      {query: 'google.com',type: 'SOA'}, 
      {query: '_xmpp-server._tcp.gmail.com',type: 'SRV'},
      {query: 'google.com',type: 'TXT'}, 
      {query: 'google.com',type: 'AAAA'}
    ];
         
	function success(results) {
	   console.log(JSON.stringify(results));
	};
	function err(e) {
		  console.log(JSON.stringify(e));
	};

	window.nslookup.resolve(val:string,success,err);
```
