// jni_session.js — JNIEnv 函数表全量 trace: VMP'd FockUtil.getH 的 Java 交互面
// 方法: hook libart 的 JNI 函数表条目 (FindClass/GetMethodID/GetStringUTFChars/NewStringUTF/
//       byte[] 交换/Call*Method/RegisterNatives), 只在 getH 调用窗口内记录。
// 目的: 枚举 F(device,ts) 的真实输入 + 是否走 Java crypto (MessageDigest/Cipher/Mac)。
(function() {
    var PS = Process.pointerSize;
    var JT = {active: false, n: 0, max: 9000, mainTid: 0};
    function L(s) { console.log(s); }

    // ---------- resolve JNIEnv table ----------
    var envPtr = null;
    function resolveEnv() {
        try { envPtr = Java.vm.getEnv().handle; } catch (e) { L("[E] getEnv: " + e); }
        if (envPtr === null || (envPtr.isNull && envPtr.isNull())) {
            try {
                var p = Module.findExportByName(null, "JNI_GetCreatedJavaVMs");
                if (!p) { L("[E] no JNI_GetCreatedJavaVMs"); return; }
                var fn = new NativeFunction(p, 'int32', ['pointer', 'int32', 'pointer']);
                var buf = Memory.alloc(PS), nb = Memory.alloc(4);
                fn(buf, 1, nb);
                var vm = buf.readPointer();
                var vmTable = vm.readPointer();
                var getEnvFn = new NativeFunction(vmTable.add(6 * PS).readPointer(), 'int32', ['pointer', 'pointer', 'int32']);
                var envOut = Memory.alloc(PS);
                var rc = getEnvFn(vm, envOut, 0x00010006);
                if (rc === 0) envPtr = envOut.readPointer();
            } catch (e) { L("[E] vm fallback: " + e); }
        }
    }
    resolveEnv();
    if (!envPtr) { L("[E] NO ENV — abort"); return; }
    var T = envPtr.readPointer();
    L("[T] JNIEnv table @ " + T);

    // sanity: GetVersion must be JNI 1.6 (0x00010006) => index math is right
    try {
        var gv = new NativeFunction(T.add(4 * PS).readPointer(), 'int32', ['pointer']);
        L("[VER] 0x" + (gv(envPtr) >>> 0).toString(16));
    } catch (e) { L("[E] GetVersion: " + e); }

    // ---------- helpers ----------
    var MID = {};   // jmethodID ptr -> "name sig"
    var FID = {};   // jfieldID  ptr -> "name"
    var ARRLEN = {};// array ptr  -> length
    var CLS = {};   // jclass ptr -> class name (FindClass result)
    function pk(p) { try { return p.toString(); } catch (e) { return "?"; } }
    function cs(p) { try { return p.readCString(); } catch (e) { return "<bad>"; } }
    function hex(p, n) {
        try {
            var b = new Uint8Array(p.readByteArray(Math.min(n, 96)));
            var s = "";
            for (var i = 0; i < b.length; i++) { s += ("0" + b[i].toString(16)).slice(-2); }
            return s;
        } catch (e) { return "<badhex>"; }
    }
    function gate() { return JT.active && JT.n < JT.max; }
    function ev(s) { JT.n++; L("[J" + JT.n + "] t" + Process.getCurrentThreadId() + " " + s); }

    function hook2(idx, name, h) {
        try {
            var p = T.add(idx * PS).readPointer();
            Interceptor.attach(p, {
                onEnter: function(args) {
                    this._g = gate();
                    if (!this._g) return;
                    try { if (h.onEnter) h.onEnter.call(this, args); else ev(name); } catch (e) {}
                },
                onLeave: function(ret) {
                    if (!this._g) return;
                    try { if (h.onLeave) h.onLeave.call(this, ret); } catch (e) {}
                }
            });
        } catch (e) { L("[HOOKFAIL] " + name + ": " + e); }
    }
    function hookCall(idx, label) {
        hook2(idx, label, { onEnter: function(args) {
            var m = MID[pk(args[2])];
            ev(label + " " + (m || "?mid"));
        }});
    }

    // ---------- class / method / field resolution ----------
    hook2(6, "FindClass", {
        onEnter: function(args) { this._nm = cs(args[1]); },
        onLeave: function(ret) { CLS[pk(ret)] = this._nm; ev("FindClass " + this._nm); }
    });
    hook2(31, "GetObjectClass", {
        onEnter: function(args) { this._o = pk(args[1]); },
        onLeave: function(ret) { ev("GetObjectClass -> cls " + (CLS[pk(ret)] || "?")); }
    });
    hook2(33, "GetMethodID", {
        onEnter: function(args) { this._n = cs(args[2]); this._s = cs(args[3]); },
        onLeave: function(ret) { MID[pk(ret)] = this._n + " " + this._s; ev("GetMethodID " + this._n + " " + this._s); }
    });
    hook2(113, "GetStaticMethodID", {
        onEnter: function(args) { this._n = cs(args[2]); this._s = cs(args[3]); },
        onLeave: function(ret) { MID[pk(ret)] = this._n + " " + this._s; ev("GetStaticMethodID " + this._n + " " + this._s); }
    });
    hook2(94, "GetFieldID", {
        onEnter: function(args) { this._n = cs(args[2]); },
        onLeave: function(ret) { FID[pk(ret)] = this._n; ev("GetFieldID " + this._n); }
    });
    hook2(144, "GetStaticFieldID", {
        onEnter: function(args) { this._n = cs(args[2]); },
        onLeave: function(ret) { FID[pk(ret)] = this._n; ev("GetStaticFieldID " + this._n); }
    });

    // ---------- strings: the money hooks ----------
    hook2(168, "NewStringUTF", {
        onEnter: function(args) { ev("NewStringUTF '" + cs(args[1]) + "'"); }
    });
    hook2(170, "GetStringUTFChars", {
        onLeave: function(ret) { ev("GetStringUTFChars -> '" + cs(ret) + "'"); }
    });

    // ---------- fields ----------
    function fieldHook(idx, label) {
        hook2(idx, label, { onEnter: function(args) {
            ev(label + " " + (FID[pk(args[2])] || "?fid"));
        }});
    }
    fieldHook(95, "GetObjectField");
    fieldHook(96, "GetBooleanField");
    fieldHook(100, "GetIntField");
    fieldHook(101, "GetLongField");
    fieldHook(145, "GetStaticObjectField");
    fieldHook(147, "GetStaticBooleanField");
    fieldHook(150, "GetStaticIntField");
    fieldHook(151, "GetStaticLongField");

    // ---------- arrays ----------
    hook2(172, "GetArrayLength", {
        onEnter: function(args) { this._a = pk(args[1]); },
        onLeave: function(ret) { ARRLEN[this._a] = ret.toInt32(); ev("GetArrayLength " + ret.toInt32()); }
    });
    hook2(177, "NewByteArray", {
        onEnter: function(args) { ev("NewByteArray len=" + args[1].toInt32()); }
    });
    hook2(185, "GetByteArrayElements", {
        onEnter: function(args) { this._a = pk(args[1]); },
        onLeave: function(ret) {
            var len = ARRLEN[this._a];
            ev("GetByteArrayElements len=" + (len === undefined ? "?" : len) + " " + hex(ret, len || 32));
        }
    });
    hook2(201, "GetByteArrayRegion", {
        onEnter: function(args) { this._s = args[2].toInt32(); this._l = args[3].toInt32(); this._p = args[4]; },
        onLeave: function(ret) { ev("GetByteArrayRegion start=" + this._s + " len=" + this._l + " " + hex(this._p, this._l)); }
    });
    hook2(209, "SetByteArrayRegion", {
        onEnter: function(args) {
            var l = args[3].toInt32();
            ev("SetByteArrayRegion len=" + l + " " + hex(args[4], l));
        }
    });
    hook2(223, "GetPrimitiveArrayCritical", {
        onEnter: function(args) { this._a = pk(args[1]); },
        onLeave: function(ret) {
            var len = ARRLEN[this._a];
            ev("GetPrimitiveArrayCritical len=" + (len === undefined ? "?" : len) + " " + hex(ret, len || 32));
        }
    });
    hook2(225, "GetStringCritical", {
        onLeave: function(ret) { ev("GetStringCritical (ptr only)"); }
    });

    // ---------- method calls (instance + static, plain/V/A variants) ----------
    var callSpecs = [
        [34, "CallObjectMethod"], [35, "CallObjectMethodV"], [36, "CallObjectMethodA"],
        [37, "CallBooleanMethod"], [38, "CallBooleanMethodV"], [39, "CallBooleanMethodA"],
        [40, "CallByteMethod"], [43, "CallCharMethod"], [46, "CallShortMethod"],
        [49, "CallIntMethod"], [52, "CallLongMethod"], [58, "CallDoubleMethod"],
        [61, "CallVoidMethod"], [62, "CallVoidMethodV"], [63, "CallVoidMethodA"],
        [114, "CallStaticObjectMethod"], [115, "CallStaticObjectMethodV"], [116, "CallStaticObjectMethodA"],
        [117, "CallStaticBooleanMethod"], [120, "CallStaticByteMethod"], [123, "CallStaticCharMethod"],
        [129, "CallStaticIntMethod"], [132, "CallStaticLongMethod"], [141, "CallStaticVoidMethod"],
        [142, "CallStaticVoidMethodV"], [143, "CallStaticVoidMethodA"]
    ];
    for (var ci = 0; ci < callSpecs.length; ci++) hookCall(callSpecs[ci][0], callSpecs[ci][1]);

    // ---------- RegisterNatives (lazy VMP/native registration would show here) ----------
    hook2(216, "RegisterNatives", {
        onEnter: function(args) {
            var n = args[3].toInt32();
            var out = "RegisterNatives cls=" + (CLS[pk(args[1])] || "?") + " n=" + n;
            for (var i = 0; i < n && i < 40; i++) {
                var m = args[2].add(i * 12 * (PS === 4 ? 1 : 1)); // JNINativeMethod = 3 ptrs
                out += " | " + cs(m.readPointer()) + " " + cs(m.add(PS).readPointer()) +
                       " fn=" + m.add(2 * PS).readPointer();
            }
            ev(out);
        }
    });

    // ---------- Java-level crypto observers ----------
    function jb2hex(b) {
        if (b === null) return "null";
        var s = "";
        for (var i = 0; i < b.length; i++) { var v = b[i]; if (v < 0) v += 256; s += ("0" + v.toString(16)).slice(-2); }
        return s;
    }
    Java.perform(function() {
        try {
            var MD = Java.use("java.security.MessageDigest");
            var gi = MD.getInstance.overload("java.lang.String");
            gi.implementation = function(a) {
                var r = gi.call(this, a);
                if (JT.active) console.log("[JMD] getInstance " + a);
                return r;
            };
            var up1 = MD.update.overload("[B");
            up1.implementation = function(b) {
                if (JT.active) console.log("[JMD] update " + jb2hex(b).slice(0, 256));
                return up1.call(this, b);
            };
            var up2 = MD.update.overload("[B", "int", "int");
            up2.implementation = function(b, o, l) {
                if (JT.active) console.log("[JMD] update off=" + o + " len=" + l + " " + jb2hex(b).slice(0, 256));
                return up2.call(this, b, o, l);
            };
            var dg0 = MD.digest.overload();
            dg0.implementation = function() {
                var r = dg0.call(this);
                if (JT.active) console.log("[JMD] digest() -> " + jb2hex(r) + " (this=" + this.getAlgorithm() + ")");
                return r;
            };
            var dg1 = MD.digest.overload("[B");
            dg1.implementation = function(b) {
                var r = dg1.call(this, b);
                if (JT.active) console.log("[JMD] digest(in) in=" + jb2hex(b).slice(0, 256) + " -> " + jb2hex(r) + " (this=" + this.getAlgorithm() + ")");
                return r;
            };
        } catch (e) { L("[E] MessageDigest hook: " + e); }
        try {
            var CI = Java.use("javax.crypto.Cipher");
            var cgi = CI.getInstance.overload("java.lang.String");
            cgi.implementation = function(a) {
                if (JT.active) console.log("[JCI] Cipher.getInstance " + a);
                return cgi.call(this, a);
            };
            var dfn = CI.doFinal.overload("[B");
            dfn.implementation = function(b) {
                var r = dfn.call(this, b);
                if (JT.active) console.log("[JCI] doFinal in=" + jb2hex(b).slice(0, 256) + " -> " + jb2hex(r).slice(0, 256));
                return r;
            };
        } catch (e) { L("[E] Cipher hook: " + e); }
        try {
            var MC = Java.use("javax.crypto.Mac");
            var mgi = MC.getInstance.overload("java.lang.String");
            mgi.implementation = function(a) {
                if (JT.active) console.log("[JMC] Mac.getInstance " + a);
                return mgi.call(this, a);
            };
            var mdf = MC.doFinal.overload();
            mdf.implementation = function() {
                var r = mdf.call(this);
                if (JT.active) console.log("[JMC] Mac.doFinal -> " + jb2hex(r) + " (this=" + this.getAlgorithm() + ")");
                return r;
            };
        } catch (e) { L("[E] Mac hook: " + e); }

        // module inventory (fock family loaded?)
        try {
            var mods = Process.enumerateModules();
            var names = [];
            for (var i = 0; i < mods.length; i++) {
                var n = mods[i].name;
                if (/fock|jiagu|stub|knobs|omg|nib|ostar|metasec|msaoaid/i.test(n)) names.push(n + "@" + mods[i].base);
            }
            L("[MODS] " + names.join(", "));
        } catch (e) { L("[E] mods: " + e); }

        setTimeout(function() {
            try {
                var FU = Java.use("com.qidian.QDReader.component.util.FockUtil");
                var inst = FU.INSTANCE.value;
                var RB = Java.use("okhttp3.RequestBody");
                var MT = Java.use("okhttp3.MediaType");
                var mt = MT.parse("application/x-www-form-urlencoded");
                var Map = Java.use("java.util.Map");
                var MapEntry = Java.use("java.util.Map$Entry");
                var urlA = "https://bravev6.if.qidian.com/argus/api/v1/client/getconf";
                var body = RB.create(mt, "localLabels=&gender=0");
                JT.mainTid = Process.getCurrentThreadId();
                JT.active = true;
                console.log("[GO] tid=" + JT.mainTid);
                var res = inst.getH(urlA, "POST", body);
                JT.active = false;
                console.log("[DONE] events=" + JT.n);
                var h = {};
                var it = Java.cast(res, Map).entrySet().iterator();
                while (it.hasNext()) {
                    var en = Java.cast(it.next(), MapEntry);
                    h[String(en.getKey())] = String(en.getValue());
                }
                console.log("[MAP]" + JSON.stringify(h));
                console.log("[ALLDONE]");
            } catch (e) {
                JT.active = false;
                console.log("[ERROR] " + e + " stack=" + (e.stack || ""));
            }
        }, 4000);
    });
})();
