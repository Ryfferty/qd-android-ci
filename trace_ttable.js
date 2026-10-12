Java.perform(function() {
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[TT] base: " + BASE);
    
    // 找nib_85676552的地址(ARM64)!
    var fnAddr = Module.findExportByName("libnib.so", "nib_85676552");
    if (!fnAddr) {
        console.log("[TT] nib_85676552 not found!");
        return;
    }
    console.log("[TT] block cipher @ " + fnAddr);
    
    // Hook块密码 — 读取ctx中的T-table指针!
    Interceptor.attach(fnAddr, {
        onEnter: function(args) {
            // ctx = args[0], ctx[1] = round key pointer
            // T-tables在.data段,通过绝对地址访问!
            
            // 直接读T-tables(在.bss,base+偏移)!
            // ARM32: 0x2aa58,但ARM64偏移不同!
            // 需要从代码中提取...
            
            // 更简单: dump ctx结构!
            var ctx = args[0];
            console.log("[TT] ctx[0]=" + ctx.readU32());  // 轮数
            console.log("[TT] ctx[1]=" + ctx.add(4).readU32());  // 指针
            
            // 读round keys!
            var rk_ptr = ptr(ctx.add(4).readU32());
            var rk = "";
            for (var i = 0; i < 16; i++) {
                rk += ("00000000" + rk_ptr.add(i*4).readU32().toString(16)).slice(-8) + " ";
            }
            console.log("[TT] round_keys: " + rk);
            
            // 读input!
            var inp = "";
            for (var i = 0; i < 16; i++) {
                inp += ("0" + args[1].add(i).readU8().toString(16)).slice(-2);
            }
            console.log("[TT] input: " + inp);
        },
        onLeave: function(retval) {
            // 读output!
            // args[2]是output — 但需要在onEnter保存!
        }
    });
    
    // 也试试直接dump T-tables!
    // T-tables在data段,地址可以从反编译推断!
    // 但ARM64偏移不同...
    
    // ★ 方法: 搜索libnib的data段找AES T-table特征!
    // AES T-table的第一个值: 0xc66363a5 (T0[0])
    // 逆T-table: 0x51f4a750 (inv_T0[0])
    
    // 扫描libnib内存!
    var ranges = Module.enumerateRanges("libnib.so", "r--");
    for (var i = 0; i < ranges.length; i++) {
        var r = ranges[i];
        if (r.size > 1000) {
            // 搜索AES T-table特征!
            try {
                // 标准AES T0: c66363a5 c6...
                var search1 = Memory.scanSync(r.base, r.size, "a5 63 63 c6");
                if (search1.length > 0) {
                    console.log("[TT] AES T0 found at: " + search1[0].address);
                }
                // 标准AES inv_T0: 50 a7 f4 51
                var search2 = Memory.scanSync(r.base, r.size, "50 a7 f4 51");
                if (search2.length > 0) {
                    console.log("[TT] AES inv_T0 found at: " + search2[0].address);
                }
                // 标准AES S-box: 63 7c 77 7b
                var search3 = Memory.scanSync(r.base, r.size, "63 7c 77 7b");
                if (search3.length > 0) {
                    console.log("[TT] AES S-box found at: " + search3[0].address);
                }
            } catch(e) {}
        }
    }
    
    // 调用StringArmor.d触发!
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        console.log("\n[TT] 调StringArmor.d...");
        var result = SA.d('Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D');
        console.log("[TT] result: " + result);
        console.log("[TT_DONE]");
    }, 3000);
});
