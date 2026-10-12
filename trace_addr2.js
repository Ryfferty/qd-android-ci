Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[A2] base: " + BASE);
    
    // ★ 先调用StringArmor.d触发T-table初始化!
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        var result = SA.d('Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D');
        console.log("[A2] result: " + result);
        
        // 现在搜索!
        var searchSeq = "a5 c6 63 63 84 f8 7c 7c";  // T[32],T[33] sequence
        
        // 搜索所有RW内存!
        var ranges = Process.enumerateRanges("rw-");
        console.log("[A2] RW ranges: " + ranges.length);
        
        for (var i = 0; i < ranges.length; i++) {
            var r = ranges[i];
            if (r.size > 0x400) {
                try {
                    var results = Memory.scanSync(r.base, Math.min(r.size, 0x100000), searchSeq);
                    for (var j = 0; j < Math.min(results.length, 3); j++) {
                        var addr = results[j].address;
                        var offset = addr.sub(BASE);
                        console.log("[A2] ★ SEQUENCE @ " + addr + " (libnib offset: " + offset + ")");
                        
                        // 表的index 32在这里 → 表起点 = addr - 128!
                        var tableStart = addr.sub(128);
                        console.log("[A2] table start: " + tableStart + " (offset: " + tableStart.sub(BASE) + ")");
                        
                        // Dump完整表!
                        console.log("[A2] Full table dump:");
                        for (var row = 0; row < 32; row++) {
                            var line = "";
                            for (var col = 0; col < 8; col++) {
                                var v = tableStart.add((row*8+col)*4).readU32();
                                line += ("00000000" + v.toString(16)).slice(-8) + " ";
                            }
                            console.log("[T] " + line);
                        }
                        
                        // 也dump前后各一个表!
                        console.log("[A2] Previous table (start-1024):");
                        var prevStart = tableStart.sub(1024);
                        for (var row = 0; row < 32; row++) {
                            var line = "";
                            for (var col = 0; col < 8; col++) {
                                var v = prevStart.add((row*8+col)*4).readU32();
                                line += ("00000000" + v.toString(16)).slice(-8) + " ";
                            }
                            console.log("[P] " + line);
                        }
                        
                        console.log("[A2] Next table (start+1024):");
                        var nextStart = tableStart.add(1024);
                        for (var row = 0; row < 32; row++) {
                            var line = "";
                            for (var col = 0; col < 8; col++) {
                                var v = nextStart.add((row*8+col)*4).readU32();
                                line += ("00000000" + v.toString(16)).slice(-8) + " ";
                            }
                            console.log("[N] " + line);
                        }
                    }
                } catch(e) {}
            }
        }
        
        console.log("[A2_DONE]");
    }, 3000);
});
