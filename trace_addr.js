Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[A] base: " + BASE);
    
    var fnAddr = Module.findExportByName("libnib.so", "nib_85676552");
    console.log("[A] block cipher @ " + fnAddr + " (offset: " + fnAddr.sub(BASE) + ")");
    
    // ★ 方法: 读取块密码函数的机器码,找T-table的地址引用!
    // ARM64的ADRP+ADD指令会引用数据地址!
    
    // 读取函数前200字节的指令!
    var code = "";
    for (var i = 0; i < 200; i += 4) {
        var inst = fnAddr.add(i).readU32();
        code += ("00000000" + inst.toString(16)).slice(-8) + " ";
    }
    console.log("[A] code[0:200]: " + code);
    
    // ★ 更直接: 搜索libnib内存中的已知T-table值!
    // 标准AES T0[0]=0xc66363a5 但我们知道有字节变换!
    // 从dump中取一个唯一值搜索!
    
    // 已知: T_dump[32] = 0x6363c6a5 (这是表中的确定值!)
    // 搜索这个值在libnib的什么位置!
    
    var searchVal = "a5 c6 63 63";  // 0x6363c6a5 in LE!
    var ranges = Module.enumerateRanges("libnib.so", "rw-");
    console.log("[A] RW ranges: " + ranges.length);
    
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        if (r.size > 0x1000) {
            try {
                var results = Memory.scanSync(r.base, r.size, searchVal);
                for (var j = 0; j < Math.min(results.length, 5); j++) {
                    var addr = results[j].address;
                    console.log("[A] found 0x6363c6a5 at " + addr + " (offset: " + addr.sub(BASE) + ")");
                }
            } catch(e) {}
        }
    }
    
    // ★ 也搜索另一个确定值!
    // T_dump[33] = 0x7c7cf884
    var searchVal2 = "84 f8 7c 7c";
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        if (r.size > 0x1000) {
            try {
                var results = Memory.scanSync(r.base, r.size, searchVal2);
                for (var j = 0; j < Math.min(results.length, 5); j++) {
                    console.log("[A] found 0x7c7cf884 at " + results[j].address + " (offset: " + results[j].address.sub(BASE) + ")");
                }
            } catch(e) {}
        }
    }
    
    // ★ 搜索连续的表: 0x6363c6a5后面跟着0x7c7cf884!
    var searchSeq = "a5 c6 63 63 84 f8 7c 7c";
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        if (r.size > 0x1000) {
            try {
                var results = Memory.scanSync(r.base, r.size, searchSeq);
                for (var j = 0; j < results.length;  j++) {
                    var addr = results[j].address;
                    console.log("[A] ★ SEQUENCE found at " + addr + " (offset: " + addr.sub(BASE) + ")");
                    
                    // 这就是T-table的某个位置! 
                    // 0x6363c6a5是我们dump中index 32的值
                    // 所以实际表中这个值的位置 = 搜索到的地址
                    // 表的index 32在这里,表的起点 = addr - 32*4 = addr - 128
                    
                    var tableStart = addr.sub(128);
                    console.log("[A] table start = " + tableStart + " (offset: " + tableStart.sub(BASE) + ")");
                    
                    // Dump完整表(256值)!
                    console.log("[A] dumping table from " + tableStart + ":");
                    for (var row = 0; row < 32; row++) {
                        var line = "";
                        for (var col = 0; col < 8; col++) {
                            var v = tableStart.add((row*8+col)*4).readU32();
                            line += ("00000000" + v.toString(16)).slice(-8) + " ";
                        }
                        console.log("[T] " + line);
                    }
                }
            } catch(e) {}
        }
    }
    
    console.log("[A_DONE]");
});
