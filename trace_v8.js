Java.perform(function() {
    console.log("[V8] Triggering libnib load...");
    try {
        var NW_pre = Java.use("com.yuewen.nib.NativeWrapper");
        var dummy = NW_pre.hav();
        console.log("[V8] hav() = " + dummy);
    } catch(e) { console.log("[V8] Trigger failed: " + e); return; }

    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[V8] base: " + BASE);

    var targets = {
        'MD4U': 'nib_67453634',
        'C8':   'nib_58940238',
        'C16':  'nib_58940235',
        'MD5C': 'nib_98632074',
        'CRC':  'nib_53453412',
    };

    var hooks = {};
    for (var label in targets) {
        var addr = Module.findExportByName("libnib.so", targets[label]);
        if (addr) {
            console.log("[V8] " + label + " @ " + addr);
            hooks[label] = addr;
        }
    }

    // ★ CRC32 hook — input + LR + code dump (v8: use .lr not .x30)
    var dumpSites = {};
    if (hooks.CRC) {
        Interceptor.attach(hooks.CRC, {
            onEnter: function(args) {
                this.len = args[1].toInt32();
                if (this.len > 0 && this.len < 400) {
                    var d = "";
                    for (var i = 0; i < Math.min(this.len, 64); i++) {
                        d += ("0" + args[0].add(i).readU8().toString(16)).slice(-2);
                    }
                    console.log("[CRC_IN] " + this.len + "B: " + d);
                }
                try {
                    var lr = this.context.lr || this.context.x30;
                    if (lr) {
                        var off = lr.sub(BASE).toInt32();
                        if (!dumpSites[off]) {
                            dumpSites[off] = true;
                            console.log("[DUMP_SITE] lr_off=0x" + off.toString(16));
                            var start = lr.sub(0x180);
                            for (var blk = 0; blk < 0x500; blk += 0x40) {
                                var line = "";
                                for (var i = 0; i < 0x40; i++) {
                                    try {
                                        line += ("0" + start.add(blk + i).readU8().toString(16)).slice(-2);
                                    } catch (e) { line += "??"; }
                                }
                                console.log("[CODE " + (blk - 0x180).toString(16) + "] " + line);
                            }
                            console.log("[DUMP_DONE] lr_off=0x" + off.toString(16));
                        }
                    }
                } catch (e) { console.log("[CRC_LR_ERR] " + e); }
            },
            onLeave: function(retval) {
                console.log("[CRC_RET] 0x" + retval.toUInt32().toString(16));
            }
        });
    }

    // C8/C16 order + key logging (light)
    if (hooks.C8) {
        Interceptor.attach(hooks.C8, {
            onEnter: function(args) {
                var len = args[1].toInt32();
                var d = "";
                for (var i = 0; i < Math.min(len, 16); i++) {
                    d += ("0" + args[0].add(i).readU8().toString(16)).slice(-2);
                }
                var k = "";
                for (var i = 0; i < 32; i++) {
                    try { k += ("0" + args[2].add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                }
                console.log("[C8_IN] " + len + "B: " + d + " KEY=" + k);
            }
        });
    }
    if (hooks.C16) {
        Interceptor.attach(hooks.C16, {
            onEnter: function(args) {
                var len = args[1].toInt32();
                var d = "";
                for (var i = 0; i < Math.min(len, 16); i++) {
                    d += ("0" + args[0].add(i).readU8().toString(16)).slice(-2);
                }
                var k = "";
                for (var i = 0; i < 32; i++) {
                    try { k += ("0" + args[2].add(i).readU8().toString(16)).slice(-2); } catch(e) { break; }
                }
                console.log("[C16_IN] " + len + "B: " + d + " KEY=" + k);
            }
        });
    }

    // ★ 40-input out-of-sample battery (seeded random + long, generated 2026-10-13)
    setTimeout(function() {
        var NW = Java.use("com.yuewen.nib.NativeWrapper");
        var tests = ['yP8m1gEjcCnFqz5_tfrCxPY1R88836YFNbs1Enf5i85sd2d1AVzDe9jLfBLt!6sUZslb5y6iYp5PK!S79XfJBCUKJHvTIzDPzADcpPkJ5XV4vETTrPQ0bQzkWVdj1iARtfWhRc6KFCx2nn!0ZQHvUE', '.n7IdNb1VeFi5Mu', '9-Njiiemefd6nM7UOqR-S4jWv_K-FLuxGH6PpfM2-SyXPcVNC5uZZ9vOI2pFWj84hfPbe8pNJ3.lPdWUqZF5ct.Q.lQgNDQ4YbUxi8p_Wu6KfkCCEKVilvVZ9S3J4lUXBWTSL524OHacxt8_v9frh2weYy1e8sJxbQN-Ap6r2GVa9uo8EA37W3VionU_6HxTzASqDxUe5XQ!Zpi1Qhxsl5x8JYD_Scb52bPbz8F7jgZ-QQnetVZcWHTVUUPfYs48cjL6XZs0Govb9RjoS2r8sBUOHS-HR5rb68WD_sdvZ51N', 'z2BssvMT1FvDuK3CgOG4', 'cu9jLORJem', '_c0Xsq9mvUhnAk.uh!Y2rpR', '4ky..5re-jsanZ543QfnNhL7NKTq_pJn1uMGa0K.!01QiMW', '16sKq!', 'BZyezkLL90gU9ZihpmJfegv8uL-SbsGQnPMeuMIrpnA.G5Zd', 'K1-sIp4zI4SHi6rT0QyzRHtsWXX5rZv-.hp3.PjNpFLticR7', 'ULjIbQrcL', 'A-iVYyztaG8pWNO6i8gG_rniVkNZeQskmHF6x4ITc1lvjb13h.zAIsz', 'QXhw0pxIDOe5HJ_mmiFQFpCwhU4hAaYz.pv6R.Rd', '1cU_PdbfEa.QSozr4KAWZXyV8.Y7I52KvOMVMPu3dk!WGuODJYCV.w3UXrlZaeWQN3aQCwwDvPbP.rurA!nFpdemBx8_JVm2C03ZVtSN2u6!_YcD!Ou1IGIeVWpmkaj', 'wVHrfdU9OEuasnU9V2N6', 'ep8zZbmJCii6p6ollbLm5AHeBEaQJOPeWEblfONMeRoIIu7Yz3HdaiySmFxHD.-B', '40O2jsvJIE29fynVWaYaD6WOUiYZOeq3wj_igllHmywJx6x3yJOQd8PWXO76fnwsJcecRWs3XaQM6vQzxuSw-v5QjZaIahduXbM9Y6eJl7GDQ7aKFJBjTWqQBIfWismv', 'Lk5juF03SBk1fffxL0mrVe.JUIreTTb9ti63W2z4nb9k.wcC9QfWkRh88oc7D67fVqVMvGi-Qu6gtvVJoPNFKKyiBlVD2mck4hHrWxfdXhv2zMe_tq_ZG28whQR1CjfarI9eULDh9BGi6Y..DBImZl', 'QaTjgKfzc.OpJTu7AKO-pg.8', 'h.jPv7kAMactNiUOqm_5YL4ZP0I_fophHD_VQdqTJ._gSMgj!8NYUlDw7p2k-X67C!QGV0y-Ugt3uSwN4SOaY.tZbS21Joc4z456GKDxSUYm2W.kpYGVpUxE_.HKXvA', '1hPz9OBK6-eEjTognAVtCRX', '7JHw8BdEDSxl', 'AfO7XsflRWNFbQU0wI8U6CRrT2End596iEXOwrgoeLxRVSE', 'TaBmRZOMMgYBI07dDUb6jpAv', 'r', 'S', 'TCKE6OPTRKIk_eu', 'rEDT4CVVFB0!W.gNz-tYmfMI!jFFZXW!7u6OYHO02QkmJBbM!d-W3yT7e3rDyx2fcuoayhBob2Ol0rnI', 'o!IPR', 'b6-zvK9h', 'K', 'BaAaa58O', 'oAr', 'tyE3ZCv!1FMDx464!HxJMwYvBn90Zj39ErCHmbMKOxlkFxeBTwU4Ezo65rFzC1N0mxG2lhxInQIlZJ8UOoNmNeRnLCHCqr-!TrhNBOdWYVtDlwUF1.EIPxZyt6GV4sR!4GjBg19.AsrZcNyoYIRxi0', 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX', 'YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY', 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ', '0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijk0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijk0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijk', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'test_device_id_9999999999999999999999999999999999999999'];
        for (var ti = 0; ti < tests.length; ti++) {
            console.log("\n===== lk(" + tests[ti].length + "B #" + ti + ") =====");
            try {
                var result = NW.a(tests[ti]);
                console.log("[RESULT#" + ti + "] " + result);
            } catch(e) {
                console.log("[ERR] " + e);
            }
        }
        console.log("[V8_DONE]");
    }, 3000);
});
