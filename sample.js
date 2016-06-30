Interceptor.attach(Module.findExportByName('Foundation', 'NSLog'), {
	onEnter: function(args) {
		var data = new ObjC.Object(args[0]);
		sendData(data);
		data = new ObjC.Object(args[1]);
		sendData(data);
	}
});

