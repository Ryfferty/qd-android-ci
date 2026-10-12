Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[D2] base: " + BASE);
    
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        SA.d('Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D');
        
        // ★ 完整dump 3个T-table!
        // 从0x2a000开始,每个4KB页面可能有一个T-table!
        
        var offsets = [0x2a000, 0x2a458, 0x2a800, 0x2ac00,
                        0x2b000, 0x2b458, 0x2b800, 0x2bc00,
                        0x2c000, 0x2c458, 0x2c800, 0x2cc00];
        
        for (var oi = 0; oi < offsets.length; oi++) {
            var addr = BASE.add(offsets[oi]);
            try {
                var first = addr.readU32();
                if (first != 0) {
                    // 检查是否像T-table!
                    var nonZero = 0;
                    var unique = new Set();
                    for (var i = 0; i < 64; i++) {
                        var v = addr.add(i*4).readU32();
                        if (v != 0) nonZero++;
                        unique.add(v);
                    }
                    if (nonZero > 60 && unique.size > 50) {
                        // ★ 这是T-table! dump前64个值!
                        console.log("\n[D2] TABLE @ offset 0x" + offsets[oi].toString(16));
                        var dump = "";
                        for (var i = 0; i < 64; i++) {
                            dump += ("00000000" + addr.add(i*4).readU32().toString(16)).slice(-8);
                            if (i % 8 == 7) { console.log("[D2] " + dump); dump = ""; }
                            else dump += " ";
                        }
                    }
                }
            } catch(e) {}
        }
        
        // ★ 也dump S-box(256字节)!
        // S-box在key expansion中用,可能在0x2a958附近!
        for (var so = 0x29000; so < 0x2a000; so += 0x100) {
            var sAddr = BASE.add(so);
            try {
                // 检查是否像S-box(值0-255)!
                var valid = true;
                var vals = [];
                for (var i = 0; i < 16; i++) {
                    var v = sAddr.add(i).readU8();
                    vals.push(v);
                    if (v > 255) { valid = false; break; }
                }
                // 检查是否有变化(不是全零或全FF)!
                var unique = new Set(vals);
                if (valid && unique.size > 10) {
                    console.log("\n[D2] SBOX candidate @ offset 0x" + so.toString(16));
                    var sb = "";
                    for (var i = 0; i < 256; i++) {
                        sb += ("0" + sAddr.add(i).readU8().toString(16)).slice(-2);
                        if (i % 32 == 31) { console.log("[D2] " + sb); sb = ""; }
                    }
                    break;  // 只dump第一个!
                }
            } catch(e) {}
        }
        
        console.log("[D2_DONE]");
    }, 3000);
});
