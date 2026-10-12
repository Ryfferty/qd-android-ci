Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[SA3] base: " + BASE);
    
    // ★ Hook AES解密函数(nib_54352333)和key setup(nib_08988789)!
    var fns = {
        'AES_DEC': 'nib_54352333',    // AES解密
        'KEY_SETUP': 'nib_08988789',  // key expansion
        'BASE_DEC': 'nib_63532343',   // basE91解码
        'MAIN': 'nib_67456344',       // 主解密函数
    };
    
    for (var label in fns) {
        var fnName = fns[label];
        var addr = Module.findExportByName("libnib.so", fnName);
        if (addr) {
            console.log("[SA3] " + label + " (" + fnName + ") @ " + addr);
            
            if (label === 'KEY_SETUP') {
                // key setup: (ctx, key_ptr, key_len)
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        // 读key!
                        var key = "";
                        for (var i = 0; i < 16; i++) {
                            try { key += ("0" + args[1].add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                        }
                        console.log("[KEY] " + key);
                        console.log("[KEY_LEN] " + args[2].toInt32());
                    }
                });
            }
            
            if (label === 'AES_DEC') {
                // decrypt: (ctx, mode, len, iv, input, output)
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        this.iv = args[3];
                        this.input = args[4];
                        this.output = args[5];
                        this.len = args[2].toInt32();
                        
                        // IV!
                        var iv = "";
                        for (var i = 0; i < 16; i++) {
                            try { iv += ("0" + this.iv.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                        }
                        console.log("[DEC_IV] " + iv);
                        
                        // Input!
                        var inp = "";
                        for (var i = 0; i < Math.min(this.len, 32); i++) {
                            try { inp += ("0" + this.input.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                        }
                        console.log("[DEC_IN] len=" + this.len + " " + inp);
                    },
                    onLeave: function(retval) {
                        // Output!
                        var out = "";
                        for (var i = 0; i < Math.min(this.len, 32); i++) {
                            try { out += ("0" + this.output.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                        }
                        console.log("[DEC_OUT] " + out);
                    }
                });
            }
            
            if (label === 'BASE_DEC') {
                // basE91 decode: (ctx, input_str, len, output)
                Interceptor.attach(addr, {
                    onEnter: function(args) {
                        // 读输入字符串!
                        var s = "";
                        for (var i = 0; i < 40; i++) {
                            try { 
                                var ch = args[1].add(i).readU8();
                                if (ch == 0) break;
                                s += String.fromCharCode(ch);
                            } catch(e) { break; }
                        }
                        console.log("[B91_IN] " + s);
                    },
                    onLeave: function(retval) {
                        console.log("[B91_DONE]");
                    }
                });
            }
        }
    }
    
    // 调StringArmor.d!
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        var tests = ['Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D'];
        
        for (var i = 0; i < tests.length; i++) {
            console.log("\n===== StringArmor.d =====");
            try {
                var result = SA.d(tests[i]);
                console.log("[RESULT] " + result);
            } catch(e) {
                console.log("[ERR] " + e);
            }
        }
        console.log("[SA3_DONE]");
    }, 3000);
});
