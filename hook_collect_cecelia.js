// hook_collect_cecelia.js — redroid 真机 cecelia/gorgon/r1-i-r/libknobs密钥 被动采集 v2 (子代理E, 2026-10-14)
//
// v2 新增: [0° 反检测盾] — run2/run3实证: 完全初始化的App在frida attach后1-5s内 exit(0) 自杀(logcat
//   "Process ... exited cleanly (0)", 非崩溃)。盾: ①libc exit/_exit/abort替换成吞掉 ②kill/tgkill自杀信号归零
//   ③/proc/*/maps|comm 打开重定向到假文件(剔除frida痕迹, 落app私有目录) ④Java System.exit/Runtime.exit/
//   killProcess拦截。盾在脚本最前面(attach后~100ms内生效), 之后App全自然初始化(qimei激活/r1爆发)全程被hook。
// 采集面(纯被动, 零直调):
//   [GETH]      FockUtil.getH 自然调用 (url,method,body) → 完整返回 Map
//   [OKHTTP]    okhttp3.Request$Builder.build() 出口的最终请求头+体 (qidian/yuewen/argus 域)
//   [R1REQ]     url 含 /client/r1 → i/r/o16/o36 明文表单体
//   [FORM_ADD]  FormBody$Builder.add: i/r/o16/o36/q16/q36/runMode…
//   [KNOBS_*]   libknobs.so (q480, md5=267448d2…, 符号=RECON分析件核对):
//                 knobs_45543224(0x103e0)=SetA密钥扩展  knobs_40971283(0x126c4)=SetB密钥扩展(key入参即AES密钥)
//                 knobs_58940235(0x1201c)=通用加密器  knobs_96145783(0x13db4)=CBC  knobs_12480967(0x140ac)=CFB-128
//                 knobs_29716380(0x14188)=CFB-NEON  knobs_87039164(0x1427c)=CTR  knobs_70861349(0x3159c)=192B bss
//   [APB]       AttributionParamsBuilder 只读探测
// 密钥纪律: 材料只落 console.log → collect.log(artifact), 汇总只报 hash/形态。

var STAT = { geth: 0, geth_cecelia: 0, geth_gorgon: 0, http: 0, r1: 0, form: 0, knobs: 0, bss: 0 };
var MAX = { geth: 200, http: 300, knobs: 900, form: 600 };
var SHIELD = { exit: 0, abort: 0, kill: 0, maps: 0, comm: 0, jexit: 0 };

function L(s) { console.log(s); }

// ═══ 0° 反检测盾 (最先执行) ═══
(function installShield() {
    try {
        var mypid = Process.id;
        // 假文件路径: app私有目录(同uid可写, 壳可读)
        var FAKE_MAPS_PATH = "/data/data/com.qidian.QDReader/.cfgm";
        var FAKE_COMM_PATH = "/data/data/com.qidian.QDReader/.cfgc";
        var FAKE_MAPS = Memory.allocUtf8String(FAKE_MAPS_PATH);
        var FAKE_COMM = Memory.allocUtf8String(FAKE_COMM_PATH);

        var fnc_openat = new NativeFunction(Module.findExportByName(null, "openat"), 'int', ['int', 'pointer', 'int', 'int']);
        var fnc_read = new NativeFunction(Module.findExportByName(null, "read"), 'int', ['int', 'pointer', 'int']);
        var fnc_close = new NativeFunction(Module.findExportByName(null, "close"), 'int', ['int']);

        var INREFRESH = false;
        function readReal(path) {
            var p = Memory.allocUtf8String(path);
            var fd = fnc_openat(-100, p, 0, 0);
            if (fd < 0) return "";
            var BUFSZ = 131072;
            var buf = Memory.alloc(BUFSZ);
            var parts = [], n;
            while (true) {
                n = fnc_read(fd, buf, BUFSZ);
                if (n <= 0) break;
                parts.push(buf.readUtf8String(n));
            }
            fnc_close(fd);
            return parts.join("");
        }
        function filterMaps(s) {
            return s.split("\n").filter(function(l) {
                if (l.indexOf("frida") >= 0) return false;
                if (l.indexOf("gum-js") >= 0 || l.indexOf("gmain") >= 0) return false;
                if (l.indexOf("gadget") >= 0 || l.indexOf("linjector") >= 0) return false;
                return true;
            }).join("\n");
        }
        function writeFake(path, content) {
            var f = new File(path, "w");
            f.write(content);
            f.close();
        }
        function refreshFakeMaps() {
            if (INREFRESH) return;
            INREFRESH = true;
            try { writeFake(FAKE_MAPS_PATH, filterMaps(readReal("/proc/self/maps"))); } catch (e) {}
            INREFRESH = false;
        }
        // 假comm: 遮蔽 gum-js-loop/gmain/pool-frida 线程名
        try { writeFake(FAKE_COMM_PATH, "Thread-42\n"); } catch (e) { L("[SHIELD_ERR] comm init: " + e); }
        try { refreshFakeMaps(); } catch (e) { L("[SHIELD_ERR] maps init: " + e); }
        setInterval(function() { try { refreshFakeMaps(); } catch (e) {} }, 1000);

        // ① exit/_exit/abort → 吞掉; 非主线程沉睡30s降检测线程负载, 主线程直接返回保响应
        //   (run5教训: 主线程被沉睡→ANR→ActivityManager SIGKILL; tid==pid 即主线程)
        var fnc_usleep = null, fnc_gettid = null;
        try { fnc_usleep = new NativeFunction(Module.findExportByName(null, "usleep"), 'void', ['uint64']); } catch (e) {}
        try { fnc_gettid = new NativeFunction(Module.findExportByName(null, "gettid"), 'int', []); } catch (e) {}
        ["exit", "_exit", "abort"].forEach(function(fn) {
            try {
                var p = Module.findExportByName(null, fn);
                if (!p) return;
                Interceptor.replace(p, new NativeCallback(function(a) {
                    SHIELD.exit++;
                    if (SHIELD.exit <= 10 || SHIELD.exit % 1000 === 0) L("[SHIELD] blocked " + fn + "(" + a + ") #" + SHIELD.exit);
                    try {
                        if (fnc_usleep && fnc_gettid && fnc_gettid() !== mypid) fnc_usleep(30000000);
                    } catch (e) {}
                }, 'void', ['int']));
            } catch (e) {}
        });
        // ② kill/tgkill/raise/pthread_kill 自杀信号 → 归零
        [["kill", 0, 1], ["tgkill", 2, 3], ["raise", 0, 0], ["pthread_kill", 1, 1]].forEach(function(spec) {
            try {
                var p = Module.findExportByName(null, spec[0]);
                if (!p) return;
                Interceptor.attach(p, {
                    onEnter: function(args) {
                        try {
                            var sig = args[spec[2]].toInt32();
                            if (sig === 9 || sig === 15 || sig === 6 || sig === 4 || sig === 11) {
                                args[spec[2]] = ptr(0);
                                SHIELD.kill++;
                                if (SHIELD.kill <= 10 || SHIELD.kill % 50 === 0) L("[SHIELD] neutralized " + spec[0] + " sig=" + sig + " #" + SHIELD.kill);
                            }
                        } catch (e) {}
                    }
                });
            } catch (e) {}
        });
        // ③ /proc/*/maps|comm 打开重定向 (open/openat/fopen 三入口)
        function pathHook(idx) {
            return {
                onEnter: function(args) {
                    if (INREFRESH) return;
                    try {
                        var p = args[idx].readCString();
                        if (p === null || p.indexOf("/proc/") !== 0) return;
                        if (p.indexOf("/maps") >= 0 || p.indexOf("/smaps") >= 0) {
                            args[idx] = FAKE_MAPS; SHIELD.maps++;
                        } else if (p.indexOf("/comm") >= 0) {
                            args[idx] = FAKE_COMM; SHIELD.comm++;
                        }
                    } catch (e) {}
                }
            };
        }
        [["open", 0], ["openat", 1], ["fopen", 0], ["fopen64", 0]].forEach(function(spec) {
            try {
                var p = Module.findExportByName(null, spec[0]);
                if (p) Interceptor.attach(p, pathHook(spec[1]));
            } catch (e) {}
        });
        L("[SHIELD] armed (exit/kill/procfs) pid=" + mypid);
    } catch (e) { L("[SHIELD_ERR] " + e); }
})();

function hexlify(p, n) {
    try {
        var b = new Uint8Array(Memory.readByteArray(p, Math.min(n, 4096)));
        var s = "";
        for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return "<bad>"; }
}
function asciify(p, n) {
    try {
        var b = new Uint8Array(Memory.readByteArray(p, Math.min(n, 512)));
        var s = "";
        for (var i = 0; i < b.length; i++) s += (b[i] >= 32 && b[i] < 127) ? String.fromCharCode(b[i]) : ".";
        return s;
    } catch (e) { return "<bad>"; }
}

// ═══ ① libknobs native hooks (OBS SDK 懒加载 → 轮询) ═══
var KNOBS_HOOKED = false;
var KDEDUPE = {};
function seenOnce(map, key) {
    if (map[key]) { map[key]++; return false; }
    if (Object.keys(map).length > 3000) { for (var k in map) delete map[k]; }
    map[key] = 1; return true;
}

function hookKnobs() {
    if (KNOBS_HOOKED) return;
    var mod = Process.findModuleByName("libknobs.so");
    if (!mod) return;
    KNOBS_HOOKED = true;
    L("[KNOBS] libknobs.so base=" + mod.base + " size=" + mod.size);

    // [符号名, arm64文件偏移(readelf核对), 标签, 按入参去重(仅密钥扩展)]
    var SYMS = [
        ["knobs_45543224", 0x103e0, "SETA_KEYEXP", true],
        ["knobs_40971283", 0x126c4, "SETB_KEYEXP", true],
        ["knobs_58940235", 0x1201c, "GEN_ENCRYPT", false],
        ["knobs_96145783", 0x13db4, "CBC_WRAP", false],
        ["knobs_12480967", 0x140ac, "CFB_WRAP", false],
        ["knobs_29716380", 0x14188, "CFB_NEON", false],
        ["knobs_87039164", 0x1427c, "CTR_WRAP", false]
    ];
    SYMS.forEach(function(s) {
        var addr = Module.findExportByName("libknobs.so", s[0]);
        if (!addr) { addr = mod.base.add(s[1]); L("[KNOBS] " + s[0] + " 符号缺失, 用文件偏移 " + s[1]); }
        L("[KNOBS_SYM] " + s[0] + " " + s[2] + " @ " + addr);
        try {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    if (STAT.knobs >= MAX.knobs) return;
                    var raws = [], mems = [], ascs = [];
                    for (var i = 0; i < 6; i++) {
                        raws.push(args[i].toString());
                        mems.push(hexlify(args[i], 48));
                        ascs.push(asciify(args[i], 48));
                    }
                    if (s[3]) {
                        var dkey = s[2] + "|" + mems[0].substring(0, 32) + "|" + mems[1].substring(0, 96) + "|" + mems[2].substring(0, 32);
                        if (!seenOnce(KDEDUPE, dkey)) return;
                    }
                    STAT.knobs++;
                    L("[KNOBS_ENTER] " + s[2] + " " + s[0] +
                      "\n  a0ptr=" + raws[0] + " mem=" + mems[0] +
                      "\n  a1ptr=" + raws[1] + " mem=" + mems[1] + " asc=" + ascs[1] +
                      "\n  a2ptr=" + raws[2] + " mem=" + mems[2] + " asc=" + ascs[2] +
                      "\n  a3ptr=" + raws[3] + " mem=" + mems[3] +
                      "\n  a4ptr=" + raws[4] + " mem=" + mems[4] +
                      "\n  a5ptr=" + raws[5] + " mem=" + mems[5]);
                    this._fn = s[2];
                    this._a0 = args[0];
                },
                onLeave: function(ret) {
                    if (!this._fn) return;
                    L("[KNOBS_RET] " + this._fn + " ret=" + ret + " retmem=" + hexlify(ret, 64) +
                      "\n  ctx_after_176B=" + hexlify(this._a0, 176));
                }
            });
            L("[+] hooked " + s[0] + " (" + s[2] + ")");
        } catch (e) { L("[KNOBS_HOOKFAIL] " + s[0] + ": " + e); }
    });

    // 192B .bss 密钥材料 周期dump
    try {
        var bss = Module.findExportByName("libknobs.so", "knobs_70861349");
        if (!bss) bss = mod.base.add(0x3159c);
        var BSSSEEN = {};
        var bssTick = 0;
        var bssTimer = setInterval(function() {
            bssTick++;
            var h = hexlify(bss, 192);
            if (h.indexOf("<bad>") >= 0) return;
            if (!BSSSEEN[h]) {
                BSSSEEN[h] = 1; STAT.bss++;
                L("[KNOBS_BSS] t=" + (bssTick * 10) + "s " + h);
            }
            if (bssTick >= 24) clearInterval(bssTimer);
        }, 10000);
        L("[KNOBS] bss192 poller started @ " + bss);
    } catch (e) { L("[KNOBS_BSSFAIL] " + e); }
}
var knobsPoll = setInterval(function() {
    hookKnobs();
    if (KNOBS_HOOKED) clearInterval(knobsPoll);
}, 1000);
hookKnobs();

// ═══ ② Java 层被动 hook ═══
Java.perform(function() {
    try {
        var mods = Process.enumerateModules();
        var names = [];
        for (var i = 0; i < mods.length; i++) {
            var n = mods[i].name;
            if (/fock|jiagu|knobs|ostar|nib|stub/i.test(n)) names.push(n + "@" + mods[i].base);
        }
        L("[MODS] " + names.join(", "));
    } catch (e) { L("[E] mods: " + e); }

    // Java级自杀拦截
    try {
        var Sys = Java.use("java.lang.System");
        Sys.exit.implementation = function(c) { SHIELD.jexit++; L("[SHIELD] blocked System.exit(" + c + ") #" + SHIELD.jexit); };
        var Rt = Java.use("java.lang.Runtime");
        Rt.exit.implementation = function(c) { SHIELD.jexit++; L("[SHIELD] blocked Runtime.exit(" + c + ") #" + SHIELD.jexit); };
        var AOProc = Java.use("android.os.Process");
        AOProc.killProcess.implementation = function(pid) { SHIELD.jexit++; L("[SHIELD] blocked killProcess(" + pid + ")"); };
        L("[SHIELD] java exit hooks armed");
    } catch (e) { L("[SHIELD_JAVA_ERR] " + e); }

    var JBuffer = null;
    try { JBuffer = Java.use("okio.Buffer"); } catch (e) { L("[E] okio.Buffer: " + e); }

    function bodyToStr(body) {
        if (body === null || body === undefined) return null;
        if (JBuffer === null) return "<nobuffer>";
        try {
            var buf = JBuffer.$new();
            body.writeTo(buf);
            var s = buf.readUtf8();
            buf.close();
            return s.length > 6144 ? s.substring(0, 6144) : s;
        } catch (e) { return "<unreadable:" + e + ">"; }
    }
    function headersToObj(headers) {
        var o = {};
        try {
            var sz = headers.size();
            for (var i = 0; i < sz; i++) {
                var k = String(headers.name(i));
                var v = String(headers.value(i));
                o[k] = v.length > 6144 ? v.substring(0, 6144) : v;
            }
        } catch (e) { o["<err>"] = String(e); }
        return o;
    }
    function callOrig(ov, self, argsObj) {
        switch (argsObj.length) {
            case 0: return ov.call(self);
            case 1: return ov.call(self, argsObj[0]);
            case 2: return ov.call(self, argsObj[0], argsObj[1]);
            case 3: return ov.call(self, argsObj[0], argsObj[1], argsObj[2]);
            default: return ov.call(self, argsObj[0], argsObj[1], argsObj[2], argsObj[3]);
        }
    }

    // ── FockUtil.getH 自然调用的进出口 ──
    try {
        var FockUtil = Java.use("com.qidian.QDReader.component.util.FockUtil");
        L("[+] FockUtil resolved");
        FockUtil.getH.overloads.forEach(function(ov) {
            try {
                var sig = ov.argumentTypes.map(function(t) { return t.className; }).join(",");
                ov.implementation = function() {
                    var ret = callOrig(ov, this, arguments);
                    try {
                        STAT.geth++;
                        if (STAT.geth <= MAX.geth) {
                            var inUrl = arguments.length > 0 ? String(arguments[0]) : "";
                            var inMethod = arguments.length > 1 ? String(arguments[1]) : "";
                            var inBody = arguments.length > 2 ? bodyToStr(arguments[2]) : null;
                            var out = {};
                            if (ret !== null && ret !== undefined) {
                                var rm = Java.cast(ret, Java.use("java.util.Map"));
                                var it = rm.entrySet().iterator();
                                while (it.hasNext()) {
                                    var en = Java.cast(it.next(), Java.use("java.util.Map$Entry"));
                                    var k = String(en.getKey());
                                    var v = String(en.getValue());
                                    out[k] = v.length > 6144 ? v.substring(0, 6144) : v;
                                    if (k === "cecelia" && v.length > 2) STAT.geth_cecelia++;
                                    if (k === "gorgon" && v.length > 2) STAT.geth_gorgon++;
                                }
                            }
                            L("[GETH] " + JSON.stringify({ url: inUrl, method: inMethod, body: inBody, h: out }));
                        }
                    } catch (e) { L("[GETH_DUMP_ERR] " + e); }
                    return ret;
                };
                L("[+] getH hooked sig=(" + sig + ")");
            } catch (e) { L("[E] getH overload: " + e); }
        });
        // addRetrofitH: 请求对象加头现场(第二视角)
        try {
            FockUtil.addRetrofitH.overloads.forEach(function(ov) {
                ov.implementation = function() {
                    var ret = callOrig(ov, this, arguments);
                    try {
                        if (STAT.geth <= MAX.geth) {
                            var inUrl = "";
                            try { inUrl = String(arguments[0].url().toString()); } catch (e) {}
                            var outH = {};
                            try { outH = headersToObj(ret.headers()); } catch (e) {}
                            L("[ADDRH] " + JSON.stringify({ url: inUrl, headers: outH }));
                        }
                    } catch (e) {}
                    return ret;
                };
            });
            L("[+] addRetrofitH hooked");
        } catch (e) { L("[E] addRetrofitH: " + e); }
    } catch (e) { L("[E] FockUtil: " + e); }

    // ── okhttp 最终请求 (r1 的 i/r 原文 + 全部风控头最终形态) ──
    try {
        var RQB = Java.use("okhttp3.Request$Builder");
        RQB.build.implementation = function() {
            var req = RQB.build.call(this);
            try {
                var url = String(req.url().toString());
                if (/qidian\.com|yuewen\.com|argus/i.test(url)) {
                    if (STAT.http < MAX.http) {
                        STAT.http++;
                        var hb = null;
                        try { hb = bodyToStr(req.body()); } catch (e) {}
                        var rec = { url: url, method: String(req.method()), headers: headersToObj(req.headers()), body: hb };
                        if (url.indexOf("/client/r1") >= 0 || url.indexOf("knobs") >= 0) {
                            STAT.r1++;
                            L("[R1REQ] " + JSON.stringify(rec));
                        } else {
                            L("[OKHTTP] " + JSON.stringify(rec));
                        }
                    }
                }
            } catch (e) { L("[OKHTTP_DUMP_ERR] " + e); }
            return req;
        };
        L("[+] Request$Builder.build hooked");
    } catch (e) { L("[E] Request$Builder: " + e); }

    // ── FormBody 字段构造现场 (i/r/o16/o36 兜底) ──
    try {
        var FBB = Java.use("okhttp3.FormBody$Builder");
        FBB.add.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    if (STAT.form < MAX.form) {
                        STAT.form++;
                        var k = arguments.length > 0 ? String(arguments[0]) : "";
                        var v = arguments.length > 1 ? String(arguments[1]) : "";
                        if (["i", "r", "o16", "o36", "q16", "q36", "runMode", "sora", "ibex", "cecelia", "gorgon", "borgus", "QDSign", "QDInfo", "tstamp", "cpt", "data"].indexOf(k) >= 0) {
                            L("[FORM_ADD] " + k + "=" + v);
                        }
                    }
                } catch (e) {}
                return callOrig(ov, this, arguments);
            };
        });
        L("[+] FormBody$Builder.add hooked");
    } catch (e) { L("[E] FormBody$Builder: " + e); }

    // ── AttributionParamsBuilder 只读探测 ──
    try {
        var APB = Java.use("com.qidian.QDReader.component.api.AttributionParamsBuilder");
        var ms = APB.class.getDeclaredMethods();
        var sigs = [];
        for (var i = 0; i < ms.length && i < 60; i++) sigs.push(String(ms[i].toGenericString()));
        L("[APB] reachable, declared methods=" + ms.length + "\n  " + sigs.join("\n  "));
    } catch (e) { L("[APB] not reachable: " + e); }

    setInterval(function() {
        L("[HB] geth=" + STAT.geth + " cecelia=" + STAT.geth_cecelia + " gorgon=" + STAT.geth_gorgon +
          " http=" + STAT.http + " r1=" + STAT.r1 + " form=" + STAT.form + " knobs=" + STAT.knobs + " bss=" + STAT.bss +
          " knobs_hooked=" + KNOBS_HOOKED + " shield(exit=" + SHIELD.exit + ",kill=" + SHIELD.kill + ",maps=" + SHIELD.maps +
          ",comm=" + SHIELD.comm + ",jexit=" + SHIELD.jexit + ")");
    }, 15000);
    L("[READY] passive collection armed (v2 shield)");
});
