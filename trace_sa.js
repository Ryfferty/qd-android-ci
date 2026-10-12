Java.perform(function() {
    console.log("[SA] Triggering libnib load...");
    try {
        var NW = Java.use("com.yuewen.nib.NativeWrapper");
        NW.hav();
    } catch(e) { console.log("[SA] Trigger failed: " + e); return; }
    
    var BASE = Module.findBaseAddress("libnib.so");
    console.log("[SA] base: " + BASE);
    if (!BASE) return;
    
    // ★ jniStringArmorDecrypt @ 0x17ae0 (ARM32偏移!)
    // ARM64上地址不同! 用findExportByName!
    
    
    var exports = Module.enumerateExports("libnib.so");
    console.log("[SA] " + exports.length + " exports");
    
    // 找jniStringArmorDecrypt — 不是导出!
    // 它是JNI方法,通过RegisterNatives注册!
    
    // ★ 方法: hook JNI的GetStringUTFChars和NewByteArray!
    // jniStringArmorDecrypt的流程:
    // 1. GetStringUTFChars(密文) 
    // 2. 调用解密函数(密文) → 明文bytes
    // 3. NewByteArray(长度)
    // 4. SetByteArrayRegion(明文)
    
    // Hook Java层的StringArmor.d!
    var SA = Java.use("com.yuewen.nib.StringArmor");
    var methods = SA.class.getDeclaredMethods();
    methods.forEach(function(m) {
        console.log("[SA] method: " + m.getName());
    });
    
    // Hook d方法!
    try {
        var dOverloads = SA.d.overloads;
        dOverloads.forEach(function(overload) {
            overload.implementation = function(str) {
                console.log("[SA_D] input: " + str.substring(0, 30) + "...");
                var result = overload.call(this, str);
                console.log("[SA_D] output: " + result);
                return result;
            };
        });
        console.log("[SA] d() hooked!");
    } catch(e) {
        console.log("[SA] d hook failed: " + e);
    }
    
    // ★ 也hook native层! 用JNI RegisterNatives注册的函数!
    // ARM64上jniStringArmorDecrypt的地址 = base + offset(ARM64)
    // 从ARM64 readelf获取offset!
    
    // 方法: 遍历libnib的函数,找到调用JNI vtable模式的!
    // 或者: 用Stalker追踪StringArmor.d的native执行!
    
    // ★ 最直接: hook malloc/free追踪加密数据的buffer!
    // 解密函数返回malloc的buffer!
    
    // 实际上: 直接调用StringArmor.d并hook JNI函数!
    var SA_class = Java.use("com.yuewen.nib.StringArmor");
    
    // 调几个解密!
    setTimeout(function() {
        var testCases = [
            'Y=]l"pHLk!nakZc>cW,CS9P,]NfyX$@8"d+JVl$D',      // 'Nib'
            'ew>K&:jM@rNXx{P[9XigRb7(>ZnXmn95a8r{gx9B',        // '5'
            'lg!0q^<n]G()U2!cN)=z@+ToL*AUmPm3tnoUTL2E',        // '/c'
        ];
        
        for (var i = 0; i < testCases.length; i++) {
            console.log("\n===== decrypt[" + i + "] =====");
            try {
                var result = SA_class.d(testCases[i]);
                console.log("[SA_RESULT] " + result);
            } catch(e) {
                console.log("[SA_ERR] " + e);
            }
        }
        console.log("[SA_DONE]");
    }, 3000);
});
