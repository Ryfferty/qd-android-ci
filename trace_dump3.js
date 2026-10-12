Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[D3] base: " + BASE);
    
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        SA.d('Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D');
        
        // ★ 完整dump每个T-table(256值)!
        var offsets = [0x2a000, 0x2a458, 0x2a800, 0x2ac00,
                        0x2b000, 0x2b458, 0x2b800, 0x2bc00,
                        0x2c000, 0x2c458];
        
        for (var oi = 0; oi < offsets.length; oi++) {
            var addr = BASE.add(offsets[oi]);
            try {
                var first = addr.readU32();
                if (first != 0) {
                    console.log("\n[T_" + offsets[oi].toString(16) + "]");
                    // 256个值,每行8个!
                    for (var row = 0; row < 32; row++) {
                        var line = "";
                        for (var col = 0; col < 8; col++) {
                            var idx = row * 8 + col;
                            var v = addr.add(idx * 4).readU32();
                            line += ("00000000" + v.toString(16)).slice(-8) + " ";
                        }
                        console.log("[T] " + line);
                    }
                }
            } catch(e) {
                console.log("[D3] offset " + offsets[oi].toString(16) + " error");
            }
        }
        
        console.log("[D3_DONE]");
    }, 3000);
});
