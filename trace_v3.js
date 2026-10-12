Java.perform(function() {
    // 1. 触发libnib加载!
    console.log("[V4] Triggering libnib load...");
    try {
        var NW_pre = Java.use("com.yuewen.nib.NativeWrapper");
        var dummy = NW_pre.hav();
        console.log("[V4] hav() = " + dummy + " → libnib loaded!");
    } catch(e) {
        console.log("[V4] Trigger failed: " + e);
        return;
    }
    
    // 2. 用findExportByName找正确的ARM64地址!
    var targets = {
        'MD4U': 'nib_67453634',
        'C8': 'nib_58940238',
        'C16': 'nib_58940235',
        'MD4C': 'nib_65464522',
        'MD5C': 'nib_98632074',
    };
    
    var hooks = {};
    for (var label in targets) {
        var fnName = targets[label];
        var addr = Module.findExportByName("libnib.so", fnName);
        if (addr) {
            console.log("[V4] " + label + " (" + fnName + ") @ " + addr);
            hooks[label] = addr;
        } else {
            console.log("[V4] " + label + " NOT FOUND!");
        }
    }
    
    // 3. Hook MD4 update!
    if (hooks.MD4U) {
        try {
            Interceptor.attach(hooks.MD4U, {
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
            console.log("[V4] MD4U hooked!");
        } catch(e) { console.log("[V4] MD4U FAIL: " + e); }
    }
    
    // 4. Hook cipher8!
    if (hooks.C8) {
        try {
            Interceptor.attach(hooks.C8, {
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
            console.log("[V4] C8 hooked!");
        } catch(e) { console.log("[V4] C8 FAIL: " + e); }
    }
    
    // 5. Hook cipher16!
    if (hooks.C16) {
        try {
            Interceptor.attach(hooks.C16, {
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
            console.log("[V4] C16 hooked!");
        } catch(e) { console.log("[V4] C16 FAIL: " + e); }
    }
    
    // 6. Hook MD4 compress!
    if (hooks.MD4C) {
        try {
            Interceptor.attach(hooks.MD4C, {
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
            console.log("[V4] MD4C hooked!");
        } catch(e) { console.log("[V4] MD4C FAIL: " + e); }
    }
    
    // 7. Hook MD5 compress!
    if (hooks.MD5C) {
        try {
            Interceptor.attach(hooks.MD5C, {
                onEnter: function(args) {
                    this.ctx = args[0];
                    var s = [];
                    for (var i = 0; i < 4; i++) {
                        s.push(args[0].add(8 + i*4).readU32().toString(16));
                    }
                    console.log("[MD5C_IN] " + s.join(","));
                }
            });
            console.log("[V4] MD5C hooked!");
        } catch(e) { console.log("[V4] MD5C FAIL: " + e); }
    }
    
    // 8. 测试!
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
        console.log("[V4_DONE]");
    }, 3000);
});
