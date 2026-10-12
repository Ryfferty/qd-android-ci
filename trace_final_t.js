Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        SA.d('Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D');
        
        // ★ 精确dump: 从0x2b4D8开始的完整表!
        var tableStart = BASE.add(0x2b4d8);
        console.log("[FT] table @ " + tableStart + " (offset 0x2b4d8)");
        
        // Dump 256值!
        for (var row = 0; row < 32; row++) {
            var line = "";
            for (var col = 0; col < 8; col++) {
                var v = tableStart.add((row*8+col)*4).readU32();
                line += ("00000000" + v.toString(16)).slice(-8) + " ";
            }
            console.log("[FT] " + line);
        }
        
        // 也dump前后表(可能有其他T-tables)!
        // 前一个表: 0x2b4d8 - 0x400 = 0x2b0d8
        var prevStart = BASE.add(0x2b0d8);
        console.log("\n[FT] prev table @ offset 0x2b0d8:");
        for (var row = 0; row < 32; row++) {
            var line = "";
            for (var col = 0; col < 8; col++) {
                var v = prevStart.add((row*8+col)*4).readU32();
                line += ("00000000" + v.toString(16)).slice(-8) + " ";
            }
            console.log("[FP] " + line);
        }
        
        // 下一个表: 0x2b4d8 + 0x400 = 0x2b8d8
        var nextStart = BASE.add(0x2b8d8);
        console.log("\n[FT] next table @ offset 0x2b8d8:");
        for (var row = 0; row < 32; row++) {
            var line = "";
            for (var col = 0; col < 8; col++) {
                var v = nextStart.add((row*8+col)*4).readU32();
                line += ("00000000" + v.toString(16)).slice(-8) + " ";
            }
            console.log("[FN] " + line);
        }
        
        // 第4个表: 0x2b4d8 + 0x800 = 0x2bcd8
        var t4Start = BASE.add(0x2bcd8);
        console.log("\n[FT] table4 @ offset 0x2bcd8:");
        for (var row = 0; row < 32; row++) {
            var line = "";
            for (var col = 0; col < 8; col++) {
                var v = t4Start.add((row*8+col)*4).readU32();
                line += ("00000000" + v.toString(16)).slice(-8) + " ";
            }
            console.log("[F4] " + line);
        }
        
        console.log("[FT_DONE]");
    }, 3000);
});
