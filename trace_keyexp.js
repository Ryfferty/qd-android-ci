Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[KE] base: " + BASE);
    
    // Hook key expansion函数!
    // nib_45543224 — 不是导出! 用nib_08988789(调用它的wrapper)!
    var fnAddr = Module.findExportByName("libnib.so", "nib_08988789");
    console.log("[KE] key setup @ " + fnAddr);
    
    if (fnAddr) {
        Interceptor.attach(fnAddr, {
            onEnter: function(args) {
                // 参数: (ctx, key_ptr, key_len)
                var key = "";
                for (var i = 0; i < 16; i++) {
                    key += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
                }
                console.log("[KE] KEY input: " + key);
                console.log("[KE] KEY len: " + args[2].toInt32());
            },
            onLeave: function(retval) {
                console.log("[KE] key setup done, return: " + retval);
            }
        });
    }
    
    // 也hook nib_45543224(如果导出)!
    var fn2 = Module.findExportByName("libnib.so", "nib_45543224");
    if (fn2) {
        console.log("[KE] nib_45543224 @ " + fn2);
        Interceptor.attach(fn2, {
            onEnter: function(args) {
                this.out = args[0];
                
                var key = "";
                for (var i = 0; i < 16; i++) {
                    key += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
                }
                console.log("[KE2] input KEY: " + key);
                console.log("[KE2] key_len: " + args[2].toInt32());
            },
            onLeave: function(retval) {
                // Dump output(round keys)!
                var out = "";
                for (var i = 0; i < 176; i += 4) {  // 44 words = 176 bytes
                    out += ("00000000" + this.out.add(i).readU32().toString(16)).slice(-8) + " ";
                    if ((i/4) % 8 == 7) { console.log("[KE2] " + out); out = ""; }
                }
                console.log("[KE2] return: " + retval);
            }
        });
    }
    
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        var result = SA.d('Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D');
        console.log("[KE] result: " + result);
        console.log("[KE_DONE]");
    }, 3000);
});
