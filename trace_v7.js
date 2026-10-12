Java.perform(function() {
    console.log("[V7] Triggering libnib load...");
    try {
        var NW_pre = Java.use("com.yuewen.nib.NativeWrapper");
        var dummy = NW_pre.hav();
        console.log("[V7] hav() = " + dummy);
    } catch(e) { console.log("[V7] Trigger failed: " + e); return; }

    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[V7] base: " + BASE);

    var targets = {
        'MD4U': 'nib_67453634',
        'C8':   'nib_58940238',
        'C16':  'nib_58940235',
        'MD4C': 'nib_65464522',
        'MD5C': 'nib_98632074',
        'CRC':  'nib_53453412',
    };

    var hooks = {};
    for (var label in targets) {
        var addr = Module.findExportByName("libnib.so", targets[label]);
        if (addr) {
            console.log("[V7] " + label + " @ " + addr);
            hooks[label] = addr;
        }
    }

    // ★ CRC32 hook — input + LR + code dump of the (runtime-decrypted) caller!
    var dumpSites = {};
    if (hooks.CRC) {
        Interceptor.attach(hooks.CRC, {
            onEnter: function(args) {
                this.len = args[1].toInt32();
                if (this.len > 0 && this.len < 200) {
                    var d = "";
                    for (var i = 0; i < Math.min(this.len, 80); i++) {
                        d += ("0" + args[0].add(i).readU8().toString(16)).slice(-2);
                    }
                    console.log("[CRC_IN] " + this.len + "B: " + d);
                }
                // capture LR (return address inside the orchestrator)
                try {
                    var lr = this.context.x30;
                    var off = lr.sub(BASE).toInt32();
                    console.log("[CRC_LR] off=0x" + off.toString(16));
                    if (!dumpSites[off]) {
                        dumpSites[off] = true;
                        console.log("[DUMP_SITE] lr_off=0x" + off.toString(16));
                        var start = lr.sub(0x1000);
                        for (var blk = 0; blk < 0x1800; blk += 0x60) {
                            var line = "";
                            for (var i = 0; i < 0x60; i++) {
                                try {
                                    line += ("0" + start.add(blk + i).readU8().toString(16)).slice(-2);
                                } catch (e) { line += "??"; }
                            }
                            console.log("[CODE " + (blk - 0x1000).toString(16) + "] " + line);
                        }
                        console.log("[DUMP_DONE] lr_off=0x" + off.toString(16));
                    }
                } catch (e) { console.log("[CRC_LR_ERR] " + e); }
            },
            onLeave: function(retval) {
                console.log("[CRC_RET] 0x" + retval.toUInt32().toString(16));
            }
        });
    }

    // MD4U — data!
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

    // MD5C — state + block
    if (hooks.MD5C) {
        Interceptor.attach(hooks.MD5C, {
            onEnter: function(args) {
                var state = [];
                for (var i = 0; i < 4; i++) {
                    state.push(args[0].add(8 + i*4).readU32().toString(16));
                }
                var block = "";
                for (var i = 0; i < 32; i++) {
                    block += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
                }
                console.log("[MD5C] state=" + state.join(",") + " block=" + block);
            }
        });
    }

    // MD4C — state + block
    if (hooks.MD4C) {
        Interceptor.attach(hooks.MD4C, {
            onEnter: function(args) {
                this.ctx = args[0];
                var b = "";
                for (var i = 0; i < 32; i++) {
                    b += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
                }
                console.log("[MD4C_IN] b=" + b);
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

    // C8 — full I/O
    if (hooks.C8) {
        Interceptor.attach(hooks.C8, {
            onEnter: function(args) {
                this.inp = args[0]; this.len = args[1].toInt32(); this.outp = args[3];
                if (this.len > 0 && this.len < 200) {
                    var d = "";
                    for (var i = 0; i < this.len; i++) {
                        d += ("0" + this.inp.add(i).readU8().toString(16)).slice(-2);
                    }
                    console.log("[C8_IN] " + this.len + "B: " + d);
                }
                if (args[2] && !args[2].isNull()) {
                    var k = "";
                    for (var i = 0; i < 32; i++) {
                        try { k += ("0" + args[2].add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                    }
                    console.log("[C8_KEY] " + k);
                }
            },
            onLeave: function(retval) {
                if (this.outp && !this.outp.isNull()) {
                    var o = "";
                    for (var i = 0; i < 60; i++) {
                        try { o += ("0" + this.outp.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                    }
                    console.log("[C8_RET] " + o);
                }
            }
        });
    }

    // C16 — full I/O
    if (hooks.C16) {
        Interceptor.attach(hooks.C16, {
            onEnter: function(args) {
                this.inp = args[0]; this.len = args[1].toInt32(); this.outp = args[3];
                if (this.len > 0 && this.len < 200) {
                    var d = "";
                    for (var i = 0; i < this.len; i++) {
                        d += ("0" + this.inp.add(i).readU8().toString(16)).slice(-2);
                    }
                    console.log("[C16_IN] " + this.len + "B: " + d);
                }
                if (args[2] && !args[2].isNull()) {
                    var k = "";
                    for (var i = 0; i < 32; i++) {
                        try { k += ("0" + args[2].add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                    }
                    console.log("[C16_KEY] " + k);
                }
            },
            onLeave: function(retval) {
                if (this.outp && !this.outp.isNull()) {
                    var o = "";
                    for (var i = 0; i < 60; i++) {
                        try { o += ("0" + this.outp.add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                    }
                    console.log("[C16_RET] " + o);
                }
            }
        });
    }

    // ★ input battery — diverse crc/length coverage
    setTimeout(function() {
        var NW = Java.use("com.yuewen.nib.NativeWrapper");
        var tests = [
            // regression (V5/V6)
            "A", "AB", "AA", "ABC", "test", "hello", "abcdefgh",
            "test_device_id_12345", "abcdefghijklmnopqrst",
            "0123456789012345678901234567890123456789",
            // single-char deltas (crc scatter)
            "B", "Z", "a", "z", "0", "9", "!", "aX", "zz", "a1",
            "ABD", "ABX", "tesu", "tesz", "hellp", "abcdefi",
            "test_device_id_12346", "test_device_id_12344",
            "abcdefghijklmnopqrstu", "abcdefghijklmnopqrstz",
            // lengths 16/20/24/32/40/48/60
            "0123456789abcdef",
            "AAAABBBBCCCCDDDD",
            "AAAAAAAAAAAAAAAAAAAA",
            "01234567890123456789abcd",
            "0123456789abcdef0123456789abcdef",
            "aaaabbbbccccddddeeeeffffgggghhhhiiii",
            "012345678901234567890123456789012345678901234567",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
            // real-world keys
            "qimei36", "guid", "platform", "ibex", "sessionKey"
        ];
        for (var ti = 0; ti < tests.length; ti++) {
            console.log("\n===== lk('" + tests[ti] + "') =====");
            try {
                var result = NW.a(tests[ti]);
                console.log("[RESULT] " + result);
            } catch(e) {
                console.log("[ERR] " + e);
            }
        }
        console.log("[V7_DONE]");
    }, 3000);
});
