Interceptor.attach(Module.findExportByName('Foundation', 'NSLog'), {
	onEnter: function(args) {
		var text = new ObjC.Object(args[0]);
		var vars = new ObjC.Object(args[1]);
		text = text.toString();
		vars = vars.toString();
		var data = {'text': text, "vars": vars};
		sendData(data);
	}
});
