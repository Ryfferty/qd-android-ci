Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[DUMP] base: " + BASE);
    
    // ★ 方法: 扫描libnib的RW内存找T-table!
    // T-table是1024字节(256个uint32)
    // 在.bss中,base+某偏移
    
    // ARM32 T-table偏移: 0x2aa58等
    // ARM64: 用相对偏移搜索!
    // T-table特征: 非零的连续uint32值!
    
    var fnAddr = Module.findExportByName("libnib.so", "nib_85676552");
    console.log("[DUMP] block cipher @ " + fnAddr);
    console.log("[DUMP] offset = " + fnAddr.sub(BASE));
    
    // ★ 读取函数代码找T-table地址!
    // T-table地址作为立即数或从寄存器加载!
    // 更简单: 在onEnter时dump ctx周围的内存!
    
    Interceptor.attach(fnAddr, {
        onEnter: function(args) {
            var ctx = args[0];
            console.log("[DUMP] ctx @ " + ctx);
            
            // ARM64 ctx结构: [rounds(4B), pad(4B), rk_ptr(8B), ...]
            // 读取rk_ptr(64位)!
            var rk_ptr = ctx.add(8).readU64();
            console.log("[DUMP] rk_ptr = 0x" + rk_ptr.toString(16));
            
            // 检查是否在libnib范围内!
            var rk_p = ptr(rk_ptr);
            if (rk_p.compare(BASE) > 0 && rk_p.compare(BASE.add(0x100000)) < 0) {
                console.log("[DUMP] rk offset = " + rk_p.sub(BASE));
                
                // Dump round keys (44 words = 176 bytes)!
                var rk_hex = "";
                for (var i = 0; i < 44; i++) {
                    rk_hex += ("00000000" + rk_p.add(i*4).readU32().toString(16)).slice(-8) + " ";
                }
                console.log("[DUMP] RK: " + rk_hex);
            }
            
            // ★ Dump输入输出!
            this.input = args[1];
            this.output = args[2];
            var inp = "";
            for (var i = 0; i < 16; i++) {
                inp += ("0" + this.input.add(i).readU8().toString(16)).slice(-2);
            }
            console.log("[DUMP] IN: " + inp);
        },
        onLeave: function(retval) {
            var out = "";
            for (var i = 0; i < 16; i++) {
                out += ("0" + this.output.add(i).readU8().toString(16)).slice(-2);
            }
            console.log("[DUMP] OUT: " + out);
        }
    });
    
    // ★ 同时dump S-box和T-table!
    // 方法: 在hook中搜索libnib的data段!
    // S-box特征: 256字节,每个值≤255
    // T-table特征: 1024字节,uint32数组
    
    // 从ctx找更多结构!
    // ctx后面可能跟着T-table指针或T-table就在ctx附近!
    
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        var result = SA.d('Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D');
        console.log("[DUMP] result: " + result);
        
        // ★ Dump ctx周围的更多内存!
        // 搜索T-table特征(4KB连续非零数据)!
        console.log("\n[DUMP] 搜索T-table...");
        var found = [];
        var range = BASE.add(0x28000);  // .bss开始附近
        for (var page = 0; page < 20; page++) {
            var addr = range.add(page * 0x1000);
            try {
                // 读第一个uint32!
                var first = addr.readU32();
                if (first != 0) {
                    // 检查是否像T-table(所有值非零,且变化)!
                    var nonZero = 0;
                    for (var i = 0; i < 64; i++) {
                        var v = addr.add(i*4).readU32();
                        if (v != 0) nonZero++;
                    }
                    if (nonZero > 60) {
                        console.log("[DUMP] Potential T-table @ " + addr + " (offset: " + addr.sub(BASE) + ")");
                        // Dump前64个值!
                        var dump = "";
                        for (var i = 0; i < 16; i++) {
                            dump += ("00000000" + addr.add(i*4).readU32().toString(16)).slice(-8) + " ";
                        }
                        console.log("[DUMP]   " + dump);
                        found.push(addr);
                    }
                }
            } catch(e) {}
        }
        
        console.log("[DUMP] found " + found.length + " potential tables");
        console.log("[DUMP_DONE]");
    }, 3000);
});
