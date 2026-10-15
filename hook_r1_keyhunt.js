// hook_r1_keyhunt.js — r1 密钥攻坚专用 frida 采集脚本 v1 (2026-10-15)
//
// 目标: 捕获 r1 i/r blob 的 AES-128-CFB-128 (key, IV/reg, 明文, 密文) 完整四元组。
// 依据 (全部 unidbg/静态实证, 见 qidian_auto/RECON/r1_key_hunt.md):
//   - libknobs SetB 原语 = 标准 AES-128 (RCON 标准), CFB-128 与 PyCryptodome segment_size=128 字节级一致
//   - keyexp 签名: (ctx x0, key x1, bits x2); ctx={rounds,ptr,sched[176B]}, sched[0:16]=原始key
//   - CFB 签名: (ctx x0, enc x1, len x2, &num x3, reg16 x4, in x5, out x6)
//       enc: 非0=加密(feedback=ct) / 0=解密(feedback=pt); reg=IV移位寄存器(跨调用续传, num=已用字节)
//   - CTR 签名: (ctx x0, enc x1, len x2, &num x3, ctr16 x4, ks16 x5, in x6, out x7) 16B大端计数器
//   - GEN_ENCRYPT(0x1201c): (in x0, len x1, key x2, &outlen x3) PKCS7+CBC, IV=key[0:16]
//   - .bss knobs_70861349 (arm64 base+0x3159c, 192B) = 疑似 VMP 侧共享 ctx; init 后为零(unidbg实证),
//     任何时刻变非零 = keyexp 已被外部调用 → sched[0:16] 即原始 key
//   - 触发链: saveKnobsEnvInfo → Fock.lock → reportR1 → l1.judian(VMP) → dlsym SetB → CFB → POST r1
//     登录态会话注入下 r1 自然发 ×10 (mitm-login 实证) → 本脚本纯被动, 零直调
//   - 反检测盾 = hook_collect_cecelia.js v2 同款 (exit/kill/procfs/Java-exit, run2-run5 实证)
// 输出纪律: 结构化行 [R1KEY] {json} 供 ci/r1_gen.py harvest 直接解析;
//   job log 只汇总计数+sha256前16; 完整材料只落 collect.log artifact。
// arm64 偏移 (q480 libknobs.so md5=267448d2…, 与 RECON 分析件同):
//   SETA_KEYEXP=0x103e0 SETB_KEYEXP=0x126c4 GEN_ENCRYPT=0x1201c CBC=0x13db4
//   CFB=0x140ac CFB_NEON=0x14188 CTR=0x1427c BSS192=0x3159c
// arm32 对照: 0x9fb0 / 0xbb80 / 0xb690 / 0xce68 / 0xd07c / 0xd118 / 0xd1cc / 0x2112c

var STAT = { keyexp: 0, cfb: 0, cfbneon: 0, ctr: 0, cbc: 0, genenc: 0, bss: 0, r1req: 0, dlsym: 0, shield: 0 };
var SHIELD = { exit: 0, kill: 0, maps: 0, comm: 0, jexit: 0 };
var MATERIAL = [];   // 汇总用: 每事件只存 sha 前缀+形态

function L(s) { console.log(s); }
function R1KEY(obj) { try { L("[R1KEY] " + JSON.stringify(obj)); } catch (e) { L("[R1KEY_ERR] " + e); } }

// ═══ 0° 反检测盾 (cecelia v2 同款, 最先执行) ═══
(function installShield() {
    try {
        var mypid = Process.id;
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
                if (l.indexOf("fs-srv") >= 0 || l.indexOf("14771") >= 0) return false;
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
        try { writeFake(FAKE_COMM_PATH, "Thread-42\n"); } catch (e) {}
        try { refreshFakeMaps(); } catch (e) {}
        setInterval(function() { try { refreshFakeMaps(); } catch (e) {} }, 1000);

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

// ═══ 工具 ═══
function hexlify(p, n) {
    try {
        var b = new Uint8Array(Memory.readByteArray(p, Math.min(n, 65536)));
        var s = "";
        for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
        return s;
    } catch (e) { return "<bad>"; }
}
function sha16(s) {  // 简易指纹(非密码学, 只为汇总去重)
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
    return ("00000000" + h.toString(16)).slice(-8);
}

// ═══ ① dlsym 观测 (VMP 何时取用 SetB 原语) ═══
try {
    var pDlsym = Module.findExportByName(null, "dlsym");
    if (pDlsym) {
        Interceptor.attach(pDlsym, {
            onEnter: function(args) { this._n = args[1]; },
            onLeave: function(ret) {
                try {
                    var nm = this._n.readCString();
                    if (nm && nm.indexOf("knobs") === 0) {
                        STAT.dlsym++;
                        R1KEY({ ev: "dlsym", sym: nm, ret: ret.toString() });
                    }
                } catch (e) {}
            }
        });
        L("[+] dlsym watcher armed");
    }
} catch (e) { L("[E] dlsym: " + e); }

// ═══ ② libknobs SetB 原语 (懒加载 → 轮询) ═══
var KNOBS_HOOKED = false;
var BSS_PTR = null;
var BSS_SEEN = {};

function dumpBss(tag) {
    if (!BSS_PTR) return;
    var h = hexlify(BSS_PTR, 192);
    if (h.indexOf("<bad>") >= 0) return;
    if (!BSS_SEEN[h]) {
        BSS_SEEN[h] = 1; STAT.bss++;
        R1KEY({ ev: "bss", tag: tag, hex: h });
    }
}

function hookKnobs() {
    if (KNOBS_HOOKED) return;
    var mod = Process.findModuleByName("libknobs.so");
    if (!mod) return;
    KNOBS_HOOKED = true;
    var is64 = Process.arch === "arm64";
    L("[KNOBS] libknobs.so base=" + mod.base + " size=" + mod.size + " arch=" + Process.arch);
    // md5 核对提示: q480 arm64 = 267448d2… (RECON 分析件同)
    var OFF = is64 ? {
        SETA_KEYEXP: 0x103e0, SETB_KEYEXP: 0x126c4, GEN_ENCRYPT: 0x1201c,
        CBC: 0x13db4, CFB: 0x140ac, CFB_NEON: 0x14188, CTR: 0x1427c, BSS: 0x3159c
    } : {
        SETA_KEYEXP: 0x9fb0, SETB_KEYEXP: 0xbb80, GEN_ENCRYPT: 0xb690,
        CBC: 0xce68, CFB: 0xd07c, CFB_NEON: 0xd118, CTR: 0xd1cc, BSS: 0x2112c
    };
    var SYMNAME = {
        SETA_KEYEXP: "knobs_45543224", SETB_KEYEXP: "knobs_40971283",
        GEN_ENCRYPT: "knobs_58940235", CBC: "knobs_96145783",
        CFB: "knobs_12480967", CFB_NEON: "knobs_29716380", CTR: "knobs_87039164",
        BSS: "knobs_70861349"
    };
    function addrOf(k) {
        var a = Module.findExportByName("libknobs.so", SYMNAME[k]);
        if (!a) { a = mod.base.add(OFF[k]); L("[KNOBS] " + k + " 符号缺失, 用偏移 0x" + OFF[k].toString(16)); }
        return a;
    }

    // --- keyexp: (ctx, key, bits) ---
    ["SETB_KEYEXP", "SETA_KEYEXP"].forEach(function(k) {
        try {
            Interceptor.attach(addrOf(k), {
                onEnter: function(args) {
                    this.ctx = args[0]; this.keyp = args[1];
                    this.bits = args[2].toInt32();
                    var nbytes = (this.bits === 128) ? 16 : (this.bits === 192 ? 24 : 32);
                    this.keyhex = hexlify(this.keyp, nbytes);
                },
                onLeave: function(ret) {
                    STAT[k === "SETB_KEYEXP" ? "keyexp" : "keyexp"]++;
                    var ctxhex = hexlify(this.ctx, 192);
                    R1KEY({ ev: "keyexp", suite: k, bits: this.bits, key: this.keyhex,
                            ctx: ctxhex, ret: ret.toInt32 ? ret.toInt32() : String(ret),
                            bt: Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 6)
                                  .map(function(a) { var m = Process.findModuleByAddress(a); return m ? m.name + "+0x" + a.sub(m.base).toString(16) : a.toString(); }) });
                    MATERIAL.push("keyexp:" + sha16(this.keyhex));
                    dumpBss("post-keyexp-" + k);
                }
            });
            L("[+] hooked " + k + " @ " + addrOf(k));
        } catch (e) { L("[HOOKFAIL] " + k + ": " + e); }
    });

    // --- CFB-128: (ctx, enc, len, &num, reg16, in, out) ---
    [["CFB", "cfb"], ["CFB_NEON", "cfbneon"]].forEach(function(spec) {
        var k = spec[0];
        try {
            Interceptor.attach(addrOf(k), {
                onEnter: function(args) {
                    this.ctx = args[0]; this.enc = args[1].toInt32();
                    this.len = args[2].toInt32 ? args[2].toInt32() : args[2].toUInt32();
                    this.pnum = args[3]; this.reg = args[4]; this.inp = args[5]; this.outp = args[6];
                    this.num0 = -1;
                    try { this.num0 = this.pnum.readU32(); } catch (e) {}
                    this.skey = hexlify(this.ctx.add(is64 ? 16 : 8), 16); // sched[0:16]=raw key (布局按unidbg arm32; arm64两偏移都抓)
                    this.skey_alt = hexlify(this.ctx.add(is64 ? 8 : 16), 16);
                    this.reghex = hexlify(this.reg, 16);
                    this.pt = hexlify(this.inp, Math.min(Math.max(this.len, 0), 8192));
                },
                onLeave: function(ret) {
                    STAT[spec[1]]++;
                    var num1 = -1; try { num1 = this.pnum.readU32(); } catch (e) {}
                    R1KEY({ ev: "cfb", variant: k, dir: this.enc ? "enc" : "dec", len: this.len,
                            num_in: this.num0, num_out: num1,
                            reg_in: this.reghex, reg_out: hexlify(this.reg, 16),
                            ctx: hexlify(this.ctx, 192),
                            ctx_key_off8: this.skey_alt, ctx_key_off16: this.skey,
                            pt: this.pt, ct: hexlify(this.outp, Math.min(Math.max(this.len, 0), 8192)) });
                    MATERIAL.push("cfb:" + this.enc + ":" + this.len + ":" + sha16(this.reghex));
                    dumpBss("post-cfb");
                }
            });
            L("[+] hooked " + k + " @ " + addrOf(k));
        } catch (e) { L("[HOOKFAIL] " + k + ": " + e); }
    });

    // --- CTR: (ctx, enc, len, &num, ctr16, ks16, in, out) ---
    try {
        Interceptor.attach(addrOf("CTR"), {
            onEnter: function(args) {
                this.ctx = args[0]; this.enc = args[1].toInt32();
                this.len = args[2].toInt32 ? args[2].toInt32() : 0;
                this.pnum = args[3]; this.ctr = args[4]; this.ks = args[5];
                this.inp = args[6]; this.outp = args[7];
                this.ctrhex = hexlify(this.ctr, 16);
                this.pt = hexlify(this.inp, Math.min(Math.max(this.len, 0), 8192));
            },
            onLeave: function(ret) {
                STAT.ctr++;
                R1KEY({ ev: "ctr", dir: this.enc ? "enc" : "dec", len: this.len,
                        ctr_in: this.ctrhex, ctr_out: hexlify(this.ctr, 16),
                        ks: hexlify(this.ks, 16), ctx: hexlify(this.ctx, 192),
                        pt: this.pt, ct: hexlify(this.outp, Math.min(Math.max(this.len, 0), 8192)) });
                dumpBss("post-ctr");
            }
        });
        L("[+] hooked CTR @ " + addrOf("CTR"));
    } catch (e) { L("[HOOKFAIL] CTR: " + e); }

    // --- CBC: 签名未定案 → 原始6参dump ---
    try {
        Interceptor.attach(addrOf("CBC"), {
            onEnter: function(args) {
                this.a = [];
                for (var i = 0; i < 6; i++) {
                    this.a.push({ p: args[i].toString(), mem: hexlify(args[i], 48),
                                  v: (function(x) { try { return x.toInt32(); } catch (e) { return null; } })(args[i]) });
                }
            },
            onLeave: function(ret) {
                STAT.cbc++;
                R1KEY({ ev: "cbc", ret: String(ret), args: this.a });
                dumpBss("post-cbc");
            }
        });
        L("[+] hooked CBC @ " + addrOf("CBC"));
    } catch (e) { L("[HOOKFAIL] CBC: " + e); }

    // --- GEN_ENCRYPT: (in, len, key, &outlen) PKCS7+CBC IV=key[:16] ---
    try {
        Interceptor.attach(addrOf("GEN_ENCRYPT"), {
            onEnter: function(args) {
                this.inp = args[0];
                this.len = args[1].toInt32 ? args[1].toInt32() : 0;
                this.keyp = args[2]; this.poutlen = args[3];
                this.keyhex = hexlify(this.keyp, 32);
                this.pt = hexlify(this.inp, Math.min(Math.max(this.len, 0), 8192));
            },
            onLeave: function(ret) {
                STAT.genenc++;
                var ol = 0; try { ol = this.poutlen.readU32(); } catch (e) {}
                R1KEY({ ev: "genenc", len: this.len, outlen: ol, key32: this.keyhex,
                        pt: this.pt, ct: hexlify(ret, Math.min(Math.max(ol, 0), 8192)), ret: String(ret) });
                MATERIAL.push("genenc:" + this.len + ":" + sha16(this.keyhex));
                dumpBss("post-genenc");
            }
        });
        L("[+] hooked GEN_ENCRYPT @ " + addrOf("GEN_ENCRYPT"));
    } catch (e) { L("[HOOKFAIL] GEN_ENCRYPT: " + e); }

    // --- .bss 192B 对象轮询 ---
    try {
        BSS_PTR = Module.findExportByName("libknobs.so", SYMNAME.BSS) || mod.base.add(OFF.BSS);
        L("[KNOBS] bss192 @ " + BSS_PTR);
        dumpBss("init");
        var tick = 0;
        var timer = setInterval(function() {
            tick++;
            dumpBss("poll" + tick);
            if (tick >= 90) clearInterval(timer);   // 5s×90 = 450s 覆盖全窗口
        }, 5000);
    } catch (e) { L("[BSSFAIL] " + e); }
}
var knobsPoll = setInterval(function() {
    hookKnobs();
    if (KNOBS_HOOKED) clearInterval(knobsPoll);
}, 500);
hookKnobs();

// ═══ ③ Java 层 (触发窗标记 + wire 对照) ═══
Java.perform(function() {
    // Java级自杀拦截
    try {
        var Sys = Java.use("java.lang.System");
        Sys.exit.implementation = function(c) { SHIELD.jexit++; L("[SHIELD] blocked System.exit(" + c + ")"); };
        var Rt = Java.use("java.lang.Runtime");
        Rt.exit.implementation = function(c) { SHIELD.jexit++; L("[SHIELD] blocked Runtime.exit(" + c + ")"); };
        var AOProc = Java.use("android.os.Process");
        AOProc.killProcess.implementation = function(pid) { SHIELD.jexit++; L("[SHIELD] blocked killProcess(" + pid + ")"); };
        L("[SHIELD] java exit hooks armed");
    } catch (e) { L("[SHIELD_JAVA_ERR] " + e); }

    var JBuffer = null;
    try { JBuffer = Java.use("okio.Buffer"); } catch (e) {}
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
    function callOrig(ov, self, argsObj) {
        switch (argsObj.length) {
            case 0: return ov.call(self);
            case 1: return ov.call(self, argsObj[0]);
            case 2: return ov.call(self, argsObj[0], argsObj[1]);
            case 3: return ov.call(self, argsObj[0], argsObj[1], argsObj[2]);
            default: return ov.call(self, argsObj[0], argsObj[1], argsObj[2], argsObj[3]);
        }
    }

    // r1 触发窗标记: QDRequestAddKnobsInterceptor (VMP 但 Java.use 可 wrap — cecelia 实证)
    try {
        var KI = Java.use("com.qidian.QDReader.component.retrofit.QDRequestAddKnobsInterceptor");
        KI.intercept.overloads.forEach(function(ov) {
            ov.implementation = function() {
                var ret = callOrig(ov, this, arguments);
                try {
                    var u = String(arguments[0].request().url().toString());
                    if (u.indexOf("/client/r1") >= 0 || u.indexOf("deeplink") >= 0 || u.indexOf("getconf") >= 0)
                        R1KEY({ ev: "ki_intercept", url: u.substring(0, 160), t: Date.now() });
                } catch (e) {}
                return ret;
            };
        });
        L("[+] KI.intercept hooked");
    } catch (e) { L("[E] KI: " + e); }

    // NativeWrapper 全量 (knobs SDK Java面; llb=lk信封, ilhc 等)
    try {
        var NWW = Java.use("com.yuewen.knobs.core.NativeWrapper");
        var nwm = NWW.class.getDeclaredMethods();
        var names = {};
        for (var i = 0; i < nwm.length; i++) names[String(nwm[i].getName())] = 1;
        Object.keys(names).forEach(function(mn) {
            try {
                NWW[mn].overloads.forEach(function(ov) {
                    ov.implementation = function() {
                        var t0 = Date.now();
                        var ret = callOrig(ov, this, arguments);
                        try {
                            var argSummary = [];
                            for (var ai = 0; ai < arguments.length; ai++) {
                                var a = arguments[ai];
                                var s = (a === null || a === undefined) ? "null" : String(a);
                                argSummary.push(s.length > 120 ? s.substring(0, 120) + "…(" + s.length + ")" : s);
                            }
                            R1KEY({ ev: "knw", m: mn, args: argSummary,
                                    ret: ret === null ? "null" : String(ret).substring(0, 200), t: t0 });
                        } catch (e) {}
                        return ret;
                    };
                });
            } catch (e) {}
        });
        L("[+] NativeWrapper hooked (" + Object.keys(names).length + " methods)");
    } catch (e) { L("[E] NativeWrapper: " + e); }

    // okhttp 最终请求体 (wire i/r 对照 + FormBody 现场)
    try {
        var RQB = Java.use("okhttp3.Request$Builder");
        RQB.build.implementation = function() {
            var req = RQB.build.call(this);
            try {
                var url = String(req.url().toString());
                if (url.indexOf("/client/r1") >= 0 || url.indexOf("deeplink") >= 0) {
                    STAT.r1req++;
                    R1KEY({ ev: "wire", url: url.substring(0, 160), body: bodyToStr(req.body()), t: Date.now() });
                }
            } catch (e) {}
            return req;
        };
        L("[+] okhttp build hooked");
    } catch (e) { L("[E] okhttp: " + e); }

    setInterval(function() {
        L("[HB] keyexp=" + STAT.keyexp + " cfb=" + STAT.cfb + " cfbneon=" + STAT.cfbneon +
          " ctr=" + STAT.ctr + " cbc=" + STAT.cbc + " genenc=" + STAT.genenc +
          " bss=" + STAT.bss + " r1wire=" + STAT.r1req + " dlsym=" + STAT.dlsym +
          " hooked=" + KNOBS_HOOKED +
          " shield(exit=" + SHIELD.exit + ",kill=" + SHIELD.kill + ",maps=" + SHIELD.maps + ",jexit=" + SHIELD.jexit + ")");
        if (MATERIAL.length) { L("[MATERIAL] " + MATERIAL.slice(-20).join(" ")); }
    }, 15000);
    L("[READY] r1 keyhunt collection armed v1");
});
