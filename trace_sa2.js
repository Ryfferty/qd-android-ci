Java.perform(function() {
    console.log("[SA2] Triggering...");
    var NW = Java.use("com.yuewen.nib.NativeWrapper");
    NW.hav();
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[SA2] base: " + BASE);
    
    var exports = Module.enumerateExports("libnib.so");
    console.log("[SA2] " + exports.length + " exports");
    
    // ★ Hook所有nib函数 — 找StringArmor.d的调用链!
    var called = {};
    var nib_fns = exports.filter(function(e) { return e.name.indexOf("nib_") !== -1; });
    
    for (let i = 0; i < nib_fns.length; i++) {
        let exp = nib_fns[i];
        try {
            Interceptor.attach(exp.address, {
                onEnter: function(args) {
                    if (!called[exp.name]) called[exp.name] = 0;
                    called[exp.name]++;
                }
            });
        } catch(e) {}
    }
    
    // 也hook JNI函数 — GetStringUTFChars/NewByteArray!
    // JNIEnv vtable: GetStringUTFChars @ +0x2a4, NewByteArray @ +0x2c0
    // 这些通过libart调用!
    
    // Hook libart的JNI函数太复杂 — 换个思路!
    // Hook malloc追踪解密buffer!
    
    // ★ 关键: StringArmor.d的输入(密文字节)是怎么被处理的?
    // 通过hook malloc看分配的buffer!
    
    setTimeout(function() {
        var SA = Java.use("com.yuewen.nib.StringArmor");
        var tests = ['Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D'];
        
        console.log("\n[SA2] 调StringArmor.d...");
        called = {};  // 重置!
        
        for (var i = 0; i < tests.length; i++) {
            try {
                var result = SA.d(tests[i]);
                console.log("[SA2] result: " + result);
            } catch(e) {
                console.log("[SA2] err: " + e);
            }
        }
        
        // 输出被调用的函数!
        console.log("\n[SA2] 被调用的函数:");
        var fnList = Object.keys(called).sort(function(a, b) { return called[b] - called[a]; });
        for (var i = 0; i < fnList.length; i++) {
            console.log("  " + fnList[i] + ": " + called[fnList[i]] + "次");
        }
        
        console.log("[SA2_DONE]");
    }, 3000);
});
