// j2b_session.js — libart JNI 表 trace v2: 修复 v1 的三个盲区
//  1) GetStringCritical 才是 VMP 读字符串的主通道(v1只打了ptr) -> 现在 dump UTF-16 内容
//  2) NewString(164) 未hook(v1漏) -> VMP 可能用它造输出串
//  3) A变体调用的 jstring 参数/返回值按签名类型安全解析(用原表函数, 带重入保护)
//  4) 砍掉 plain variadic Call*Method hook(v1末尾 stack corruption 崩溃的头号嫌疑)
(function() {
    var PS = Process.pointerSize;
    var JT = {active: false, n: 0, max: 9000};
    function L(s) { console.log(s); }

    var envPtr = null;
    function resolveEnv() {
        try { envPtr = Java.vm.getEnv().handle; } catch (e) { L("[E] getEnv: " + e); }
        if (envPtr === null || (envPtr.isNull && envPtr.isNull())) {
            try {
                var p = Module.findExportByName(null, "JNI_GetCreatedJavaVMs");
                if (!p) return;
                var fn = new NativeFunction(p, 'int32', ['pointer', 'int32', 'pointer']);
                var buf = Memory.alloc(PS), nb = Memory.alloc(4);
                fn(buf, 1, nb);
                var vm = buf.readPointer();
                var vmTable = vm.readPointer();
                var getEnvFn = new NativeFunction(vmTable.add(6 * PS).readPointer(), 'int32', ['pointer', 'pointer', 'int32']);
                var envOut = Memory.alloc(PS);
                if (getEnvFn(vm, envOut, 0x00010006) === 0) envPtr = envOut.readPointer();
            } catch (e) { L("[E] vm fallback: " + e); }
        }
    }
    resolveEnv();
    if (!envPtr) { L("[E] NO ENV — abort"); return; }
    var T = envPtr.readPointer();
    L("[T] JNIEnv table @ " + T);
    try {
        var gv = new NativeFunction(T.add(4 * PS).readPointer(), 'int32', ['pointer']);
        L("[VER] 0x" + (gv(envPtr) >>> 0).toString(16));
    } catch (e) { L("[E] GetVersion: " + e); }

    var MID = {}, FID = {}, ARRLEN = {}, STRLEN = {}, CLS = {};
    var RES = false;   // 重入保护: resolve 期间不记日志
    var fnGSUC = null, fnRSUC = null, fnGAL = null, fnGBAE = null, fnRBAE = null;
    function initResolvers() {
        fnGSUC = new NativeFunction(T.add(170 * PS).readPointer(), 'pointer', ['pointer', 'pointer', 'pointer']);
        fnRSUC = new NativeFunction(T.add(171 * PS).readPointer(), 'void', ['pointer', 'pointer', 'pointer']);
        fnGAL = new NativeFunction(T.add(172 * PS).readPointer(), 'int32', ['pointer', 'pointer']);
        fnGBAE = new NativeFunction(T.add(185 * PS).readPointer(), 'pointer', ['pointer', 'pointer', 'pointer']);
        fnRBAE = new NativeFunction(T.add(193 * PS).readPointer(), 'void', ['pointer', 'pointer', 'pointer', 'int32']);
    }
    initResolvers();

    function pk(p) { try { return p.toString(); } catch (e) { return "?"; } }
    function cs(p) { try { return p.readCString(); } catch (e) { return "<bad>"; } }
    function hex(p, n) {
        try {
            var b = new Uint8Array(p.readByteArray(Math.min(n, 96)));
            var s = "";
            for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
            return s;
        } catch (e) { return "<badhex>"; }
    }
    function gate() { return JT.active && JT.n < JT.max && !RES; }
    function ev(s) { JT.n++; L("[J" + JT.n + "] t" + Process.getCurrentThreadId() + " " + s); }

    function resolveStr(jstr) {
        if (RES || !jstr || jstr.isNull()) return null;
        try {
            RES = true;
            var c = fnGSUC(envPtr, jstr, ptr(0));
            if (c.isNull()) return null;
            var s = c.readCString();
            fnRSUC(envPtr, jstr, c);
            return s;
        } catch (e) { return null; }
        finally { RES = false; }
    }
    function resolveBA(jarr) {
        if (RES || !jarr || jarr.isNull()) return null;
        try {
            RES = true;
            var len = fnGAL(envPtr, jarr).toInt32();
            if (len < 0 || len > 8192) return null;
            var els = fnGBAE(envPtr, jarr, ptr(0));
            if (els.isNull()) return null;
            var b = new Uint8Array(els.readByteArray(Math.min(len, 256)));
            var s = "";
            for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
            fnRBAE(envPtr, jarr, els, 0);
            return {len: len, hex: s};
        } catch (e) { return null; }
        finally { RES = false; }
    }
    function parseParams(sig) {
        var out = [];
        var i = sig.indexOf("(") + 1;
        var depth = 0;
        while (i < sig.length && sig[i] !== ")") {
            var c = sig[i];
            if (c === "L") {
                var j = sig.indexOf(";", i);
                out.push(sig.substring(i, j + 1));
                i = j + 1;
            } else if (c === "[") {
                var k = i;
                while (sig[k] === "[") k++;
                var t;
                if (sig[k] === "L") { var m = sig.indexOf(";", k); t = sig.substring(i, m + 1); i = m + 1; }
                else { t = sig.substring(i, k + 1); i = k + 1; }
                out.push(t);
            } else { out.push(c); i++; }
        }
        return out;
    }

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

    // ---- resolution hooks ----
    hook2(6, "FindClass", {
        onEnter: function(args) { this._nm = cs(args[1]); },
        onLeave: function(ret) { CLS[pk(ret)] = this._nm; ev("FindClass " + this._nm); }
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

    // ---- string creation/read (money hooks) ----
    hook2(168, "NewStringUTF", { onEnter: function(args) { ev("NewStringUTF '" + cs(args[1]) + "'"); } });
    hook2(164, "NewString", {
        onEnter: function(args) {
            var n = args[2].toInt32();
            var s = "";
            try { s = args[1].readUtf16String(Math.min(n, 200)) || ""; } catch (e) { s = "<bad>"; }
            ev("NewString len=" + n + " '" + s + "'");
        }
    });
    hook2(170, "GetStringUTFChars", { onLeave: function(ret) { ev("GetStringUTFChars -> '" + cs(ret) + "'"); } });
    hook2(165, "GetStringLength", {
        onEnter: function(args) { this._s = pk(args[1]); },
        onLeave: function(ret) { STRLEN[this._s] = ret.toInt32(); }
    });
    hook2(169, "GetStringUTFLength", {
        onEnter: function(args) { this._s = pk(args[1]); },
        onLeave: function(ret) { STRLEN[this._s] = ret.toInt32(); }
    });
    hook2(225, "GetStringCritical", {
        onEnter: function(args) { this._s = pk(args[1]); },
        onLeave: function(ret) {
            var len = STRLEN[this._s];
            var s = "";
            try { s = ret.readUtf16String(Math.min(len === undefined ? 64 : len, 200)) || "<bad>"; } catch (e) { s = "<bad>"; }
            ev("GetStringCritical len=" + (len === undefined ? "?" : len) + " '" + s + "'");
        }
    });

    // ---- byte arrays ----
    hook2(172, "GetArrayLength", {
        onEnter: function(args) { this._a = pk(args[1]); },
        onLeave: function(ret) { ARRLEN[this._a] = ret.toInt32(); ev("GetArrayLength " + ret.toInt32()); }
    });
    hook2(177, "NewByteArray", { onEnter: function(args) { ev("NewByteArray len=" + args[1].toInt32()); } });
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
        onEnter: function(args) { var l = args[3].toInt32(); ev("SetByteArrayRegion len=" + l + " " + hex(args[4], l)); }
    });
    hook2(223, "GetPrimitiveArrayCritical", {
        onEnter: function(args) { this._a = pk(args[1]); },
        onLeave: function(ret) {
            var len = ARRLEN[this._a];
            ev("GetPrimitiveArrayCritical len=" + (len === undefined ? "?" : len) + " " + hex(ret, len || 32));
        }
    });

    // ---- A-variant calls with typed string/byte[] arg+return resolution ----
    function hookCallA(idx, label, isStatic) {
        hook2(idx, label, {
            onEnter: function(args) {
                var ms = MID[pk(args[2])];
                var extra = "";
                if (ms) {
                    var parts = ms.split(" ");
                    var sig = parts.length > 1 ? parts[1] : "";
                    var params = parseParams(sig);
                    for (var i = 0; i < params.length && i < 8; i++) {
                        if (params[i] === "Ljava/lang/String;") {
                            var sv = resolveStr(args[3].add(i * 8).readPointer());
                            if (sv !== null) extra += " a" + i + "='" + sv.slice(0, 200) + "'";
                        } else if (params[i] === "[B") {
                            var bv = resolveBA(args[3].add(i * 8).readPointer());
                            if (bv !== null) extra += " a" + i + "[B len=" + bv.len + " " + bv.hex.slice(0, 256);
                        }
                    }
                    if (!isStatic && /^getBytes/.test(ms)) {
                        var rv = resolveStr(args[1]);
                        if (rv !== null) extra = " this='" + rv.slice(0, 300) + "'" + extra;
                    }
                    if (/\)Ljava\/lang\/String;/.test(sig)) this._wantRet = true;
                }
                ev(label + " " + (ms || "?mid") + extra);
            },
            onLeave: function(ret) {
                if (this._wantRet) {
                    var s = resolveStr(ret);
                    if (s !== null) ev("  RET '" + s.slice(0, 300) + "'");
                }
            }
        });
    }
    // V-variant: name only
    function hookCallV(idx, label) {
        hook2(idx, label, { onEnter: function(args) { ev(label + " " + (MID[pk(args[2])] || "?mid")); } });
    }

    hookCallA(36, "CallObjectMethodA", false);
    hookCallV(35, "CallObjectMethodV");
    hookCallA(116, "CallStaticObjectMethodA", true);
    hookCallV(115, "CallStaticObjectMethodV");
    hookCallA(39, "CallBooleanMethodA", false);
    hookCallV(38, "CallBooleanMethodV");
    hookCallA(131, "CallStaticIntMethodA", true);
    hookCallV(130, "CallStaticIntMethodV");
    hookCallA(134, "CallStaticLongMethodA", true);
    hookCallV(133, "CallStaticLongMethodV");
    hookCallA(143, "CallStaticVoidMethodA", true);
    hookCallV(142, "CallStaticVoidMethodV");

    // ---- RegisterNatives ----
    hook2(216, "RegisterNatives", {
        onEnter: function(args) {
            var n = args[3].toInt32();
            var out = "RegisterNatives cls=" + (CLS[pk(args[1])] || "?") + " n=" + n;
            for (var i = 0; i < n && i < 40; i++) {
                var m = args[2].add(i * 3 * PS);
                out += " | " + cs(m.readPointer()) + " " + cs(m.add(PS).readPointer()) + " fn=" + m.add(2 * PS).readPointer();
            }
            ev(out);
        }
    });

    // ---- Java-level crypto (worked in v1, keep) ----
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
            gi.implementation = function(a) { var r = gi.call(this, a); if (JT.active) console.log("[JMD] getInstance " + a); return r; };
            var dg0 = MD.digest.overload();
            dg0.implementation = function() { var r = dg0.call(this); if (JT.active) console.log("[JMD] digest() -> " + jb2hex(r) + " (this=" + this.getAlgorithm() + ")"); return r; };
            var dg1 = MD.digest.overload("[B");
            dg1.implementation = function(b) { var r = dg1.call(this, b); if (JT.active) console.log("[JMD] digest(in) in=" + jb2hex(b).slice(0, 512) + " -> " + jb2hex(r) + " (this=" + this.getAlgorithm() + ")"); return r; };
            var up1 = MD.update.overload("[B");
            up1.implementation = function(b) { if (JT.active) console.log("[JMD] update " + jb2hex(b).slice(0, 512)); return up1.call(this, b); };
        } catch (e) { L("[E] MessageDigest hook: " + e); }
        try {
            var CI = Java.use("javax.crypto.Cipher");
            var cgi = CI.getInstance.overload("java.lang.String");
            cgi.implementation = function(a) { if (JT.active) console.log("[JCI] Cipher.getInstance " + a); return cgi.call(this, a); };
            var dfn = CI.doFinal.overload("[B");
            dfn.implementation = function(b) { var r = dfn.call(this, b); if (JT.active) console.log("[JCI] doFinal in=" + jb2hex(b).slice(0, 512) + " -> " + jb2hex(r).slice(0, 512)); return r; };
        } catch (e) { L("[E] Cipher hook: " + e); }
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
                JT.active = true;
                console.log("[GO] tid=" + Process.getCurrentThreadId());
                var res = inst.getH(urlA, "POST", body);
                JT.active = false;
                console.log("[DONE] events=" + JT.n);
                var h = {};
                var it = Java.cast(res, Map).entrySet().iterator();
                while (it.hasNext()) { var en = Java.cast(it.next(), MapEntry); h[String(en.getKey())] = String(en.getValue()); }
                console.log("[MAP]" + JSON.stringify(h));
                console.log("[ALLDONE]");
            } catch (e) {
                JT.active = false;
                console.log("[ERROR] " + e + " stack=" + (e.stack || ""));
            }
        }, 4000);
    });
})();
