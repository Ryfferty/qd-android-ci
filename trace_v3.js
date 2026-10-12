Java.perform(function() {
    console.log("[V5] Triggering libnib load...");
    try {
        var NW_pre = Java.use("com.yuewen.nib.NativeWrapper");
        var dummy = NW_pre.hav();
        console.log("[V5] hav() = " + dummy);
    } catch(e) { console.log("[V5] Trigger failed: " + e); return; }
    
    var targets = {
        'MD4U': 'nib_67453634',
        'C8': 'nib_58940238',
        'C16': 'nib_58940235',
        'MD4C': 'nib_65464522',
        'MD5C': 'nib_98632074',
        'MD5U': 'nib_58940238',  // 同名? 查一下
    };
    
    var hooks = {};
    for (var label in targets) {
        var addr = Module.findExportByName("libnib.so", targets[label]);
        if (addr) {
            console.log("[V5] " + label + " @ " + addr);
            hooks[label] = addr;
        }
    }
    
    // MD4U — 全部数据!
    if (hooks.MD4U) {
        Interceptor.attach(hooks.MD4U, {
            onEnter: function(args) {
                var len = args[2].toInt32();
                if (len > 0 && len < 200) {
                    var data = "";
                    for (var i = 0; i < Math.min(len, 64); i++) {
                        data += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
                    }
                    console.log("[MD4U] " + len + "B: " + data);
                }
            }
        });
    }
    
    // MD5C — state + block!
    if (hooks.MD5C) {
        Interceptor.attach(hooks.MD5C, {
            onEnter: function(args) {
                var state = [];
                for (var i = 0; i < 4; i++) {
                    state.push(args[0].add(8 + i*4).readU32().toString(16));
                }
                // 读取block前32字节!
                var block = "";
                for (var i = 0; i < 32; i++) {
                    block += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
                }
                console.log("[MD5C] state=" + state.join(",") + " block=" + block);
            },
            onLeave: function(retval) {
                // 输出state!
                // 但this.ctx需要在onEnter保存!
            }
        });
    }
    
    // C8 — 完整I/O!
    if (hooks.C8) {
        Interceptor.attach(hooks.C8, {
            onEnter: function(args) {
                this.inp = args[0]; this.len = args[1].toInt32();
                this.key = args[2]; this.outp = args[3];
                this.outlen = args[4];
                if (this.len > 0 && this.len < 200) {
                    var d = "";
                    for (var i = 0; i < this.len; i++) {
                        d += ("0" + this.inp.add(i).readU8().toString(16)).slice(-2);
                    }
                    console.log("[C8_IN] " + this.len + "B: " + d);
                }
                if (this.key && !this.key.isNull()) {
                    var k = "";
                    for (var i = 0; i < 32; i++) {
                        try { k += ("0" + this.key.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                    }
                    console.log("[C8_KEY] " + k);
                }
            },
            onLeave: function(retval) {
                if (retval && !retval.isNull()) {
                    var o = "";
                    for (var i = 0; i < 32; i++) {
                        try { o += ("0" + retval.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                    }
                    console.log("[C8_RET] " + o);
                }
            }
        });
    }
    
    // C16 — 完整I/O!
    if (hooks.C16) {
        Interceptor.attach(hooks.C16, {
            onEnter: function(args) {
                this.inp = args[0]; this.len = args[1].toInt32();
                this.key = args[2];
                if (this.len > 0 && this.len < 200) {
                    var d = "";
                    for (var i = 0; i < this.len; i++) {
                        d += ("0" + this.inp.add(i).readU8().toString(16)).slice(-2);
                    }
                    console.log("[C16_IN] " + this.len + "B: " + d);
                }
                if (this.key && !this.key.isNull()) {
                    var k = "";
                    for (var i = 0; i < 32; i++) {
                        try { k += ("0" + this.key.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                    }
                    console.log("[C16_KEY] " + k);
                }
            },
            onLeave: function(retval) {
                if (retval && !retval.isNull()) {
                    var o = "";
                    for (var i = 0; i < 32; i++) {
                        try { o += ("0" + retval.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                    }
                    console.log("[C16_RET] " + o);
                }
            }
        });
    }
    
    // MD4C — 输入输出state!
    if (hooks.MD4C) {
        Interceptor.attach(hooks.MD4C, {
            onEnter: function(args) {
                this.ctx = args[0];
                var s = [];
                for (var i = 0; i < 4; i++) {
                    s.push(args[0].add(8 + i*4).readU32().toString(16));
                }
                // block!
                var b = "";
                for (var i = 0; i < 32; i++) {
                    b += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
                }
                console.log("[MD4C_IN] s=" + s.join(",") + " b=" + b);
            },
            onLeave: function(retval) {
                var s = [];
                for (var i = 0; i < 4; i++) {
                    s.push(this.ctx.add(8 + i*4).readU32().toString(16));
                }
                console.log("[MD4C_OUT] " + s.join(","));
            }
        });
    }
    
    // 测试 — 包含更多输入!
    setTimeout(function() {
        var NW = Java.use("com.yuewen.nib.NativeWrapper");
        var tests = ["test_device_id_12345", "abcdefghijklmnopqrst", "0123456789012345678901234567890123456789"];
        for (var ti = 0; ti < tests.length; ti++) {
            console.log("\n===== lk('" + tests[ti] + "') =====");
            try {
                var result = NW.a(tests[ti]);
                console.log("[RESULT] " + result);
            } catch(e) {
                console.log("[ERR] " + e);
            }
        }
        console.log("[V5_DONE]");
    }, 3000);
});
