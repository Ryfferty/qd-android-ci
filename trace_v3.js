Java.perform(function() {
    // ★ 先触发libnib.so加载(调NativeWrapper的static块)!
    console.log("[V3] Triggering libnib load...");
    try {
        var NW_pre = Java.use("com.yuewen.nib.NativeWrapper");
        var dummy = NW_pre.hav();  // 调hav()触发System.loadLibrary!
        console.log("[V3] hav() = " + dummy + " (libnib loaded!)");
    } catch(e) {
        console.log("[V3] Trigger failed: " + e);
    }
    
    function waitForLib(name, cb, maxWait) {
        var start = Date.now();
        var check = function() {
            var base = Module.findBaseAddress(name);
            if (base) {
                console.log("[V3] " + name + " loaded at " + base);
                cb(base);
            } else if (Date.now() - start < (maxWait || 60000)) {
                setTimeout(check, 2000);
            } else {
                console.log("[V3] TIMEOUT waiting for " + name);
            }
        };
        check();
    }
    waitForLib("libnib.so", function(BASE) {
        console.log("[V3] Setting up hooks...");
        var MD4U_ADDR = BASE.add(0x21454);
        var C8_ADDR = BASE.add(0x7c30);
        var C16_ADDR = BASE.add(0x7b84);
        var MD4C_ADDR = BASE.add(0x20f40);
        try {
            Interceptor.attach(MD4U_ADDR, {
                onEnter: function(args) {
                    var len = args[2].toInt32();
                    if (len > 0 && len < 200) {
                        var data = "";
                        for (var i = 0; i < Math.min(len, 32); i++) {
                            data += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
                        }
                        console.log("[MD4U] len=" + len + " data=" + data);
                    }
                }
            });
            console.log("[V3] MD4U hooked!");
        } catch(e) { console.log("[V3] MD4U FAIL: " + e); }
        try {
            Interceptor.attach(C8_ADDR, {
                onEnter: function(args) {
                    this.inp = args[0]; this.len = args[1].toInt32();
                    this.key = args[2]; this.outp = args[3];
                    if (this.len > 0 && this.len < 100) {
                        var d = "";
                        for (var i = 0; i < this.len; i++) {
                            d += ("0" + this.inp.add(i).readU8().toString(16)).slice(-2);
                        }
                        console.log("[C8_IN] len=" + this.len + " data=" + d);
                    }
                    if (this.key && !this.key.isNull()) {
                        var k = "";
                        for (var i = 0; i < 16; i++) {
                            try { k += ("0" + this.key.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                        }
                        console.log("[C8_KEY] " + k);
                    }
                },
                onLeave: function(retval) {
                    if (retval && !retval.isNull()) {
                        var o = "";
                        for (var i = 0; i < 20; i++) {
                            try { o += ("0" + retval.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                        }
                        console.log("[C8_RET] " + o);
                    }
                    if (this.outp && !this.outp.isNull()) {
                        var b = "";
                        for (var i = 0; i < 16; i++) {
                            try { b += ("0" + this.outp.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                        }
                        console.log("[C8_BUF] " + b);
                    }
                }
            });
            console.log("[V3] C8 hooked!");
        } catch(e) { console.log("[V3] C8 FAIL: " + e); }
        try {
            Interceptor.attach(C16_ADDR, {
                onEnter: function(args) {
                    this.inp = args[0]; this.len = args[1].toInt32();
                    this.key = args[2];
                    if (this.len > 0 && this.len < 100) {
                        var d = "";
                        for (var i = 0; i < this.len; i++) {
                            d += ("0" + this.inp.add(i).readU8().toString(16)).slice(-2);
                        }
                        console.log("[C16_IN] len=" + this.len + " data=" + d);
                    }
                    if (this.key && !this.key.isNull()) {
                        var k = "";
                        for (var i = 0; i < 16; i++) {
                            try { k += ("0" + this.key.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                        }
                        console.log("[C16_KEY] " + k);
                    }
                },
                onLeave: function(retval) {
                    if (retval && !retval.isNull()) {
                        var o = "";
                        for (var i = 0; i < 20; i++) {
                            try { o += ("0" + retval.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                        }
                        console.log("[C16_RET] " + o);
                    }
                }
            });
            console.log("[V3] C16 hooked!");
        } catch(e) { console.log("[V3] C16 FAIL: " + e); }
        try {
            Interceptor.attach(MD4C_ADDR, {
                onEnter: function(args) {
                    this.ctx = args[0];
                    var s = [];
                    for (var i = 0; i < 4; i++) {
                        s.push(args[0].add(8 + i*4).readU32().toString(16));
                    }
                    console.log("[MD4C_IN] " + s.join(","));
                },
                onLeave: function(retval) {
                    var s = [];
                    for (var i = 0; i < 4; i++) {
                        s.push(this.ctx.add(8 + i*4).readU32().toString(16));
                    }
                    console.log("[MD4C_OUT] " + s.join(","));
                }
            });
            console.log("[V3] MD4C hooked!");
        } catch(e) { console.log("[V3] MD4C FAIL: " + e); }
        setTimeout(function() {
            var NW = Java.use("com.yuewen.nib.NativeWrapper");
            var tests = ["AB", "AA", "test", "hello"];
            for (var ti = 0; ti < tests.length; ti++) {
                console.log("\n===== lk('" + tests[ti] + "') =====");
                try {
                    var result = NW.a(tests[ti]);
                    console.log("[RESULT] " + result);
                } catch(e) {
                    console.log("[ERR] " + e);
                }
            }
            console.log("[V3_DONE]");
        }, 3000);
    }, 60000);
});
