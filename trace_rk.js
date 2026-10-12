Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    
    var fnAddr = Module.findExportByName("libnib.so", "nib_85676552");
    
    Interceptor.attach(fnAddr, {
        onEnter: function(args) {
            var ctx = args[0];
            var rounds = ctx.readU32();
            console.log("[RK] rounds=" + rounds);
            
            // ARM64: 尝试读指针!
            for (var off = 4; off <= 16; off += 4) {
                var val32 = ctx.add(off).readU32();
                console.log("[RK] ctx+" + off + " = 0x" + val32.toString(16));
                // 如果看起来像指针(高位非零)!
                if (val32 > 0x1000) {
                    // 读round keys!
                    try {
                        var rk_ptr = ptr(val32);
                        var rk = "";
                        for (var i = 0; i < 44; i++) {  // AES-128: 44 words
                            rk += ("00000000" + rk_ptr.add(i*4).readU32().toString(16)).slice(-8);
                            if (i % 8 == 7) rk += "\n[RK] ";
                            else rk += " ";
                        }
                        console.log("[RK] round_keys(44 words):\n[RK] " + rk);
                        break;
                    } catch(e) {}
                }
            }
            
            // 也试64位读!
            for (var off = 8; off <= 24; off += 8) {
                try {
                    var val64 = ctx.add(off).readU64();
                    var ptr_val = ptr(val64);
                    if (ptr_val.compare(BASE) > 0 && ptr_val.compare(BASE.add(0x30000)) < 0) {
                        console.log("[RK] ctx+" + off + " (64bit) = " + ptr_val);
                        // Read round keys!
                        var rk = "";
                        for (var i = 0; i < 44; i++) {
                            rk += ("00000000" + ptr_val.add(i*4).readU32().toString(16)).slice(-8) + " ";
                            if (i % 8 == 7) rk += "\n[RK] ";
                        }
                        console.log("[RK] round_keys:\n[RK] " + rk);
                        break;
                    }
                } catch(e) {}
            }
            
            // Dump input!
            var inp = "";
            for (var i = 0; i < 16; i++) {
                inp += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
            }
            console.log("[RK] input: " + inp);
        }
    });
    
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        var result = SA.d('Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D');
        console.log("[RK] result: " + result);
        console.log("[RK_DONE]");
    }, 3000);
});
