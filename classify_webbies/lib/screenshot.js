//very simple webpage screenshot
var page = require('webpage').create();
page.settings.userAgent = phantom.args[0];
var url = phantom.args[1];
var filename = phantom.args[2];

page.open(url,function (status){
	if (status != "success") {
		console.log("Failed to load "+url);
		phantom.exit(1);
	}
	else {
		window.setTimeout(function () {
			page.render(filename);
			phantom.exit(0);
		}, 2000);
	}
});
