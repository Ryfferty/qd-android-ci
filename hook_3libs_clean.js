// hook_3libs_clean.js — 三库hook(干净版)
Java.perform(function() {
    setTimeout(function() {
        console.log("[START] Hooking 3 libraries...");
        
        // ═══ ① libnib ═══
        try {
            var NW = Java.use("com.yuewen.nib.NativeWrapper");
            console.log("[NIB] NativeWrapper found");
            var lkResult = NW.a("test_device_id_12345");
            console.log("[NIB_LK] " + lkResult);
            var havResult = NW.hav();
            console.log("[NIB_HAV] " + havResult);
        } catch(e) {
            console.log("[NIB_ERR] " + e);
        }
        
        // ═══ ② libfock ═══
        try {
            var FU = Java.use("com.qidian.QDReader.component.util.FockUtil");
            var inst = FU.INSTANCE.value;
            var RB = Java.use("okhttp3.RequestBody");
            var MT = Java.use("okhttp3.MediaType");
            var mt = MT.parse("application/x-www-form-urlencoded");
            var body = RB.create(mt, "localLabels=&gender=0");
            var url = "https://bravev6.if.qidian.com/argus/api/v1/client/getconf";
            var result = inst.getH(url, "POST", body);
            var rm = Java.cast(result, Java.use("java.util.Map"));
            var iter = rm.entrySet().iterator();
            while (iter.hasNext()) {
                var en = Java.cast(iter.next(), Java.use("java.util.Map$Entry"));
                console.log("[FOCK] " + en.getKey() + " = " + String(en.getValue()).substring(0, 80));
            }
        } catch(e) {
            console.log("[FOCK_ERR] " + e);
        }
        
        // ═══ ③ libostar ═══
        try {
            // 1. 确保libostar.so加载!
            var ostarModule = Process.findModuleByName("libostar.so");
            if (!ostarModule) {
                console.log("[OSTAR] libostar not loaded, loading...");
                var appInfo = Java.use("android.app.ActivityThread").currentApplication().getApplicationInfo();
                var nativeLibDir = appInfo.nativeLibraryDir.value;
                ostarModule = Module.load(nativeLibDir + "/libostar.so");
                console.log("[OSTAR] loaded at " + ostarModule.base);
            } else {
                console.log("[OSTAR] already loaded at " + ostarModule.base);
            }
            
            // 2. 用BeaconReport初始化!
            try {
                var BR = Java.use("com.tencent.beacon.event.open.BeaconReport");
                var report = BR.getInstance();
                console.log("[BEACON] instance: " + report);
                var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                console.log("[BEACON] ctx: " + ctx);
                report.start(ctx, "0I000JZU8B16UN21", null);
                console.log("[BEACON] started!");
            } catch(be) {
                console.log("[BEACON_START_ERR] " + be);
            }
            
            // 3. 设置U.a = true!
            var U = Java.use("com.ola.star.uin.U");
            try {
                var field = U.class.getDeclaredField("a");
                field.setAccessible(true);
                field.set(null, true);
                console.log("[OSTAR] U.a set to true");
            } catch(fe) {
                console.log("[OSTAR_FLAG_ERR] " + fe);
            }
            
            // 4. 调用U的方法!
            var ctx2 = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
            
            // z(Context) — 设备指纹!
            try {
                var zResult = U.z(ctx2);
                console.log("[★OSTAR_Z] " + zResult);
            } catch(ze) {
                console.log("[★OSTAR_Z_ERR] " + ze);
            }
            
            // z2(Context, int) — 设备指纹v2!
            try {
                var z2Result = U.z2(ctx2, 0);
                console.log("[★OSTAR_Z2] " + z2Result);
            } catch(z2e) {
                console.log("[★OSTAR_Z2_ERR] " + z2e);
            }
            
            // o() — 特征值!
            try {
                var oResult = U.o();
                console.log("[★OSTAR_O] " + oResult);
            } catch(oe) {
                console.log("[★OSTAR_O_ERR] " + oe);
            }
            
            // u() — 设备信息!
            try {
                var uResult = U.u();
                console.log("[★OSTAR_U] " + uResult);
            } catch(ue) {
                console.log("[★OSTAR_U_ERR] " + ue);
            }
            
            // p() — 特征值!
            try {
                var pResult = U.p();
                console.log("[★OSTAR_P] " + pResult);
            } catch(pe) {
                console.log("[★OSTAR_P_ERR] " + pe);
            }
            
        } catch(e) {
            console.log("[OSTAR_ERR] " + e);
        }
        
        // ═══ ③-B NativeFunction直接调用(绕过JNI注册) ═══
        try {
            var ostarBase = Module.findBaseAddress("libostar.so");
            console.log("[NF] ostar base: " + ostarBase);
            if (ostarBase) {
                var env = Java.vm.getEnv();
                var envPtr = env.handle; // 直接用handle,不readPointer!
                
                // o() — 2参数(env, thiz)
                try {
                    var oFunc = new NativeFunction(ostarBase.add(0x4cc1c), 'pointer', ['pointer', 'pointer']);
                    var oR = oFunc(envPtr, ptr(0));
                    if (!oR.isNull()) {
                        try {
                            var oS = env.getStringUtfChars(oR, null).readCString();
                            console.log("[NF_O] " + oS);
                        } catch(e) { console.log("[NF_O] ptr=" + oR); }
                    } else { console.log("[NF_O] null"); }
                } catch(e) { console.log("[NF_O_ERR] " + e); }
                
                // u() — 2参数(env, thiz)  
                try {
                    var uFunc = new NativeFunction(ostarBase.add(0x4c774), 'pointer', ['pointer', 'pointer']);
                    var uR = uFunc(envPtr, ptr(0));
                    if (!uR.isNull()) {
                        try {
                            var uS = env.getStringUtfChars(uR, null).readCString();
                            console.log("[NF_U] " + uS);
                        } catch(e) { console.log("[NF_U] ptr=" + uR); }
                    } else { console.log("[NF_U] null"); }
                } catch(e) { console.log("[NF_U_ERR] " + e); }
                
                // z() — 3参数(env, thiz, context)
                // 尝试ctx的多种获取方式!
                var ctx3 = null;
                var ctx3Ptr = ptr(0);
                try {
                    ctx3 = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                    ctx3Ptr = ctx3.$handle;
                    console.log("[NF_DBG] ctx3Ptr=" + ctx3Ptr);
                } catch(e) {
                    console.log("[NF_DBG] ctx err: " + e);
                }
                
                try {
                    var zFunc = new NativeFunction(ostarBase.add(0x4ccb8), 'pointer', ['pointer', 'pointer', 'pointer']);
                    // 先试(ctx3Ptr, ctx3Ptr), 再试(ptr(0), ctx3Ptr), 最后(ptr(0), ptr(0))!
                    var zR = null;
                    try {
                        zR = zFunc(envPtr, ctx3Ptr, ctx3Ptr);
                        console.log("[NF_Z] try1 ok");
                    } catch(e1) {
                        try {
                            zR = zFunc(envPtr, ptr(0), ctx3Ptr);
                            console.log("[NF_Z] try2 ok");
                        } catch(e2) {
                            zR = zFunc(envPtr, ptr(0), ptr(0));
                            console.log("[NF_Z] try3 (null ctx)");
                        }
                    }
                    if (zR && !zR.isNull()) {
                        try {
                            var zS = env.getStringUtfChars(zR, null).readCString();
                            console.log("[★NF_Z] " + zS);
                        } catch(e) { console.log("[★NF_Z] ptr=" + zR); }
                    } else { console.log("[★NF_Z] null"); }
                } catch(e) { console.log("[★NF_Z_ERR] " + e); }
                
                // p() — 2参数(env, thiz)
                try {
                    var pFunc = new NativeFunction(ostarBase.add(0x4c980), 'pointer', ['pointer', 'pointer']);
                    var pR = pFunc(envPtr, ptr(0));
                    if (!pR.isNull()) {
                        try {
                            var pS = env.getStringUtfChars(pR, null).readCString();
                            console.log("[★NF_P] " + pS);
                        } catch(e) { console.log("[★NF_P] ptr=" + pR); }
                    }
                } catch(e) { console.log("[★NF_P_ERR] " + e); }
                
                // z2(Context, int) — 4参数
                try {
                    var z2Func = new NativeFunction(ostarBase.add(0x4cd50), 'pointer', ['pointer', 'pointer', 'pointer', 'int']);
                    var z2R = z2Func(envPtr, ptr(0), ptr(0), 0);
                    if (!z2R.isNull()) {
                        try {
                            var z2S = env.getStringUtfChars(z2R, null).readCString();
                            console.log("[★NF_Z2] " + z2S);
                        } catch(e) { console.log("[★NF_Z2] ptr=" + z2R); }
                    }
                } catch(e) { console.log("[★NF_Z2_ERR] " + e); }
            }
        } catch(e) {
            console.log("[NF_ERR] " + e);
        }
        
        // ═══ ④ OSTAR REGISTER (纯协议!) ═══
        try {
            console.log("[REG] === Starting REGISTER ===");
            
            // 获取所有需要的头!
            var FU = Java.use("com.qidian.QDReader.component.util.FockUtil");
            var inst = FU.INSTANCE.value;
            var RB = Java.use("okhttp3.RequestBody");
            var MT = Java.use("okhttp3.MediaType");
            var mt = MT.parse("application/x-www-form-urlencoded");
            
            // 调getH获取borgus/cecelia/ibex(对ostar端点)!
            var ostarUrl = "https://druidv6.if.qidian.com/argus/api/v1/client/ostar";
            var regBody = RB.create(mt, "data=%7B%22cpt%22%3A%222%22%7D");
            var regResult = inst.getH(ostarUrl, "POST", regBody);
            var regMap = Java.cast(regResult, Java.use("java.util.Map"));
            var regIter = regMap.entrySet().iterator();
            var regHeaders = {};
            while (regIter.hasNext()) {
                var regEn = Java.cast(regIter.next(), Java.use("java.util.Map$Entry"));
                regHeaders[String(regEn.getKey())] = String(regEn.getValue());
                console.log("[REG_HDR] " + regEn.getKey() + " = " + String(regEn.getValue()).substring(0, 80));
            }
            
            // 检查是否有ibex!
            if (!regHeaders["ibex"]) {
                console.log("[REG] No ibex from getH, generating via lk...");
                var NW = Java.use("com.yuewen.nib.NativeWrapper");
                // 用设备信息生成ibex!
                var ibexInput = "register_device_test";
                var ibexVal = NW.a(ibexInput);
                regHeaders["ibex"] = ibexVal;
                console.log("[REG_IBEX] " + ibexVal.substring(0, 60));
            }
            
            // 构造REGISTER body!
            var regTs = regHeaders["tstamp"] || String(Date.now());
            var regNn = ""; 
            for (var i = 0; i < 16; i++) {
                regNn += "0123456789abcdef"[Math.floor(Math.random() * 16)];
            }
            // 简化pms(用设备信息)!
            var regPms = btoa("test_device_" + Date.now()).substring(0, 300);
            
            var regData = {
                "cpt": "2",
                "ext": "",
                "nn": regNn,
                "pms": regPms,
                "sn": "4c43851051e10785000000000000000000000000000000000000000000000000000000",
                "tm": regTs
            };
            var regBodyStr = "data=" + encodeURIComponent(JSON.stringify(regData));
            
            // 用Java发HTTP请求!
            console.log("[REG] Sending REGISTER...");
            console.log("[REG] body: " + regBodyStr.substring(0, 100));
            
            var URL2 = Java.use("java.net.URL");
            var urlObj = URL2.$new(ostarUrl);
            var conn = urlObj.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            
            // 设置所有头!
            for (var hk in regHeaders) {
                if (hk !== "Cookie") {
                    conn.setRequestProperty(hk, regHeaders[hk]);
                }
            }
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            
            // 发body!
            var os = conn.getOutputStream();
            var bytes = regBodyStr.getBytes("UTF-8");
            os.write(bytes);
            os.flush();
            os.close();
            
            // 读响应!
            var code = conn.getResponseCode();
            console.log("[REG] HTTP Status: " + code);
            
            var BufferedReader = Java.use("java.io.BufferedReader");
            var InputStreamReader = Java.use("java.io.InputStreamReader");
            var reader = BufferedReader.$new(InputStreamReader.$new(conn.getInputStream()));
            var line = reader.readLine();
            var response = "";
            while (line !== null) {
                response += String(line);
                line = reader.readLine();
            }
            reader.close();
            console.log("[REG] ★★★RESPONSE: " + response.substring(0, 300));
            
        } catch(e) {
            console.log("[REG_ERR] " + e);
        }
        
        console.log("[DONE] All 3 libraries tested!");
    }, 5000);
});
