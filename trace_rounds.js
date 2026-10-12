Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var fnAddr = Module.findExportByName("libnib.so", "nib_85676552");
    
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        
        Interceptor.attach(fnAddr, {
            onEnter: function(args) {
                var ctx = args[0];
                this.input = args[1];
                this.output = args[2];
                
                var inp = "";
                for (var i = 0; i < 16; i++) {
                    inp += ("0" + this.input.add(i).readU8().toString(16)).slice(-2);
                }
                console.log("[R] input: " + inp);
                
                var rk_ptr_val = ctx.add(8).readU64();
                var rk_ptr = ptr(rk_ptr_val);
                
                var rk = "";
                for (var i = 0; i < 44; i++) {
                    rk += ("00000000" + rk_ptr.add(i*4).readU32().toString(16)).slice(-8) + " ";
                    if (i % 8 == 7) { console.log("[RK] " + rk); rk = ""; }
                }
            },
            onLeave: function(retval) {
                var out = "";
                for (var i = 0; i < 16; i++) {
                    out += ("0" + this.output.add(i).readU8().toString(16)).slice(-2);
                }
                console.log("[R] output: " + out);
            }
        });
        
        var result = SA.d('Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D');
        console.log("[R] result: " + result);
        console.log("[R_DONE]");
    }, 3000);
});
