// hook_r1_keyhunt_472.js — LSPatch 472 破解版 spawn 版 (子代理B, 2026-10-18)
// 路线: 绕开 480 libjiagu_vip 注入战争 — 装 LSPatch 7.9.472 破解版(壳=libshell-superv,
//   非 libjiagu; 历史frida_attach_sora.py系全在它身上跑通), 用现有 frida-server spawn 基建拿钥。
// 骨架 = hook_r1_keyhunt_min.js (R14 极简+R15 隐形轻装) — 零syscall级钩(convoy教训),
//   只留: ②libknobs全点位(keyexp/SetB-CFB 的(key,IV,pt,ct)) + bss192 + ③SSL_write(r1 wire确认)。
// R10 (2026-10-19): jniCheck* 检测函数钩(保留); EXITGUARD2 原生 stub 已于 R13 剥除
//   检测函数钩 (472 JNI 表定案) — R9 尸检: 挂死 = libfock vfork 子进程的 _exit 被 R9
//   的 JS 回调式替换弄死 → vfork 父线程死锁; R8 对照实证检测响应 = exit(0)@+1.2s。
//
// ═══ 472 libknobs.so 偏移表 (静态分析定案, 2026-10-18) ═══
// 来源: apk/base.apk(LSPatch 0.7) → assets/lspatch/origin.apk → lib/arm64-v8a/libknobs.so
//   (md5 6ba331b04d7a348427d65f1d1acc4210, 133048B, 与外层APK同件)
// 方法: 符号名跨版本稳定(knobs_NNNNN 为源码级标识符非随机种子) — 480 表的 13 个符号名
//   在 472 里 12 个原样存在; capstone 反汇编对照 480 keyexp(0x126c4) vs 472(0x8e5c):
//   逐指令同构(0x830栈帧/tpidr_el0 canary/全局旗标门/256轮 0x1b GF域 S-box 生成循环/
//   mov x16,#0x1b;movk #0x36) ⇒ 语义同一。
// ★472 与 480 的差异: SETA 族(knobs_45543224 keyexp / knobs_54352333 CBC / knobs_67456344
//   STRARMOR)在 472 全部不存在(StringArmor 为 480 新增) — 本脚本自动跳过。
// arm64 (redroid CI 实际 ABI):
//   SETB_KEYEXP knobs_40971283=0x8e5c  GEN_ENC knobs_58940235=0x89b4  CBC knobs_96145783=0xa09c
//   CFB knobs_12480967=0xa394  CFB_NEON knobs_29716380=0xa474  CTR knobs_87039164=0xa54c
//   BSS192 knobs_70861349=0x232bc(B)  SETB_BLK knobs_61087493=0x9bdc  BLKENC=0x9750  BLKDEC=0x94e0
//   LK knobs_lk=0x8348  MW knobs_mw=0x8628
// arm32 (v7a, 备查): KEYEXP=0x6500 GEN_ENC=0x61dc CBC=0x73a4 CFB=0x75cc CFB_NEON=0x7668
//   CTR=0x76f8 BSS=0x1d2bc BLK=0x6f84 BLKENC=0x6b8c BLKDEC=0x6994 LK=0x5d2c MW=0x5f54
//
// LSPatch 装载说明: 该 APK 无内嵌 frida-gadget(实测 zip 全表无 gadget/frida 件; 其内嵌的是
//   LSPosed core 1.10.1 + QDReaderHook 3.3.6 模块) — frida 注入仍走 fs-srv + frida -f spawn
//   门控(ci/spawn_qd.sh), 与 480 线同基建。LSPatch loader 在进程内解 origin.apk 建 classloader,
//   libknobs.so 由 App System.loadLibrary 照常装载(dlopen 触发器兜底捕捉)。
// 输出同 v2/min 格式([R1KEY] ev 事件), ci/r1_gen.py harvest 兼容。
// R13(2026-10-19): 剥 THREADRENAME+EXITGUARD2(SIGSEGV 实证 stub 污染 libmsaoaidsec VM
//   寄存器; 且 R8-R12b 快挂全为僵尸装载从未执行) — 保留 jniCheck* 钩(libknobs 装载后
//   武装)+RPC ping 诊断。
// R3(2026-10-18): R2 实测 spawn+装载+READY 全通, 但 R15 存活件干扰壳 init(kill 拦截/exit 冻结)
//   → ClassNotFound QDApplication 崩; 本版撤光 R15 件, 纯业务钩判别壳敌意。

var STAT = { keyexpA: 0, keyexpB: 0, cfb: 0, ctr: 0, cbc: 0, genenc: 0, blk: 0, bss: 0,
             canary: 0, sslwire: 0, knobs_hooked: 0 };
var LIMITS = { keyexpA_dump: 40, blk_dump: 4000, sslwire: 240 };
var SEEN = { bss: {} };
var R10_KEEP = [];   // NativeCallback/NativeFunction/计数器 生命周期锚 (R10 EXITGUARD2 用,
                     // 防 JS GC 释放回调指针 — stub 字面量里只存裸地址)

function L(s) { console.log(s); }
function R1KEY(obj) { try { L("[R1KEY] " + JSON.stringify(obj)); } catch (e) { L("[R1KEY_ERR] " + e); } }
R1KEY({ ev: "script_loaded", t: Date.now(), frida: (typeof Frida !== "undefined" ? Frida.version : "?"), pid: Process.id, abi: Process.arch, v472: true });
// R13: RPC ping — daemon 侧实证脚本真的在执行(load()返回≠执行, R8-R12b 全部僵尸:
// 每轮 log 只有 CLI 首挂的 1 个 script_loaded 事件, 209 次快挂零执行)
rpc.exports.ping = function () { return 'pong-' + Process.id; };
L('[R13] script top-level executed (pid=' + Process.id + ' t=' + Date.now() + ')');
if (typeof process !== "undefined" && process.setExceptionHandler) {
  process.setExceptionHandler(function (d) { try { R1KEY({ ev: "native_exception", addr: String(d.address), type: d.type }); } catch (e) {} return false; });
}

setTimeout(function BOOT() {
  try {
  // ═══ R3 纯净版: R15 存活件全撤 ═══
  // R2实证(run 39136753310): spawn装载+[READY]+resume后100ms内 [R15] neutralized kill sig=9,
  //   随后 app 崩在 ClassNotFound QDApplication(LSPatch loader 的 classloader 替换未发生) —
  //   而 D 阶段 am start 裸启的进程正常跑通(38KB qd流量)。判决: R15 件嫌疑最大 —
  //   ① exit/abort Interceptor.replace 成"冻30s"会卡死壳init线程(R14 convoy同款死法)
  //   ② kill/raise 拦截可能挡了壳的正常生命周期信号(libshell-superv 行为未知)
  //   ③ 线程改名 dirent d_name@24 是 R16 之前的 bug(正确@19, 见480线42fae8d), 改名×0=没改
  // 本轮判别: 纯业务钩(knobs+SSL_write) — app跑通且keyexp命中=完成; 被壳杀=敌意实锤,
  //   R4 转 am start+attach(历史 472 attach 跑通)。

  // ═══ 工具 ═══
  function hexlify(p, n) {
      try {
          var b = new Uint8Array(Memory.readByteArray(p, Math.min(n, 65536)));
          var s = "";
          for (var i = 0; i < b.length; i++) s += ("0" + b[i].toString(16)).slice(-2);
          return s;
      } catch (e) { return "<bad>"; }
  }
  function hexlifyBytes(u8) {
      var s = "";
      for (var i = 0; i < u8.length; i++) s += ("0" + u8[i].toString(16)).slice(-2);
      return s;
  }
  function b64ToBytes(s) {
      var TAB = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      s = String(s).replace(/-/g, "+").replace(/_/g, "/").replace(/[^A-Za-z0-9+/=]/g, "");
      var bits = 0, nbits = 0, out = [];
      for (var i = 0; i < s.length; i++) {
          var c = s.charAt(i);
          if (c === "=") break;
          var v = TAB.indexOf(c);
          if (v < 0) continue;
          bits = (bits << 6) | v; nbits += 6;
          if (nbits >= 8) { nbits -= 8; out.push((bits >> nbits) & 0xff); }
      }
      return out;
  }

  // ═══ ② libknobs 全点位 (懒加载轮询) — 472 偏移表 ═══
  var KNOBS_HOOKED = false;
  var BSS_PTR = null;
  var KNOBS_ADDR = {};    // 名称→NativePointer (canary 用)
  var KNOBS_IS64 = Process.arch === "arm64";

  function dumpBss(tag) {
      if (!BSS_PTR) return;
      var h = hexlify(BSS_PTR, 192);
      if (h.indexOf("<bad>") >= 0) return;
      if (!SEEN.bss[h]) {
          SEEN.bss[h] = 1;
          R1KEY({ ev: "bss", tag: tag, hex: h });
      }
  }

  function hookKnobs() {
      if (KNOBS_HOOKED) return;
      var mod = Process.findModuleByName("libknobs.so");
      if (!mod) return;
      KNOBS_HOOKED = true;
      var is64 = KNOBS_IS64;
      L("[KNOBS] libknobs.so base=" + mod.base + " size=" + mod.size + " arch=" + Process.arch);
      // ═══ 472 表 (SETA 族在 472 不存在 — 见头注; 符号优先, 偏移兜底) ═══
      var OFF = is64 ? {
          SETB_KEYEXP: 0x8e5c, GEN_ENCRYPT: 0x89b4, CBC: 0xa09c,
          CFB: 0xa394, CFB_NEON: 0xa474, CTR: 0xa54c, BSS: 0x232bc,
          SETB_BLK: 0x9bdc, SETB_BLKENC: 0x9750, SETB_BLKDEC: 0x94e0,
          LK: 0x8348
      } : {
          SETB_KEYEXP: 0x6500, GEN_ENCRYPT: 0x61dc, CBC: 0x73a4,
          CFB: 0x75cc, CFB_NEON: 0x7668, CTR: 0x76f8, BSS: 0x1d2bc,
          SETB_BLK: 0x6f84, SETB_BLKENC: 0x6b8c, SETB_BLKDEC: 0x6994,
          LK: 0x5d2c
      };
      var SYMNAME = {
          SETB_KEYEXP: "knobs_40971283",
          GEN_ENCRYPT: "knobs_58940235", CBC: "knobs_96145783",
          CFB: "knobs_12480967", CFB_NEON: "knobs_29716380", CTR: "knobs_87039164",
          BSS: "knobs_70861349",
          SETB_BLK: "knobs_61087493", SETB_BLKENC: "knobs_71564283", SETB_BLKDEC: "knobs_87035146",
          LK: "knobs_lk"
      };
      function addrOf(k) {
          var a = Module.findExportByName("libknobs.so", SYMNAME[k]);
          if (!a) {
              if (OFF[k] === undefined) { L("[KNOBS] " + k + " 无符号无偏移(472缺失) — 跳过"); KNOBS_ADDR[k] = null; return null; }
              a = mod.base.add(OFF[k]); L("[KNOBS] " + k + " 符号缺失, 用偏移 0x" + OFF[k].toString(16));
          }
          KNOBS_ADDR[k] = a;
          return a;
      }

      // --- keyexp: (ctx, key, bits) — 472 只有 SetB 套件(SETA 族不存在) → 全量dump ---
      [["SETB_KEYEXP", "B"]].forEach(function(spec) {
          var k = spec[0], suite = spec[1];
          try {
              var a = addrOf(k);
              if (!a) return;
              Interceptor.attach(a, {
                  onEnter: function(args) {
                      this.ctx = args[0]; this.keyp = args[1];
                      this.bits = args[2].toInt32();
                      var nbytes = (this.bits === 128) ? 16 : (this.bits === 192 ? 24 : 32);
                      this.keyhex = hexlify(this.keyp, nbytes);
                  },
                  onLeave: function(ret) {
                      if (suite === "B") {
                          STAT.keyexpB++;
                          R1KEY({ ev: "keyexp", suite: k, bits: this.bits, key: this.keyhex,
                                  ctx: hexlify(this.ctx, 192), ret: ret.toInt32 ? ret.toInt32() : String(ret),
                                  bt: Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 8)
                                        .map(function(a) { var m = Process.findModuleByAddress(a); return m ? m.name + "+0x" + a.sub(m.base).toString(16) : a.toString(); }) });
                          dumpBss("post-keyexpB");
                      } else {
                          STAT.keyexpA++;
                          if (STAT.keyexpA <= LIMITS.keyexpA_dump) {
                              R1KEY({ ev: "keyexp", suite: k, bits: this.bits, key: this.keyhex,
                                      ctx: hexlify(this.ctx, 48), ret: 0 });
                          }
                      }
                  }
              });
              L("[+] hooked " + k + " @ " + a);
          } catch (e) { L("[HOOKFAIL] " + k + ": " + e); }
      });

      // --- CFB-128: (ctx, enc, len, &num, reg16, in, out) — reg16=IV(跨调用续传) ---
      [["CFB", "cfb"], ["CFB_NEON", "cfbneon"]].forEach(function(spec) {
          var k = spec[0];
          try {
              var a = addrOf(k);
              if (!a) return;
              Interceptor.attach(a, {
                  onEnter: function(args) {
                      this.ctx = args[0]; this.enc = args[1].toInt32();
                      this.len = args[2].toInt32 ? args[2].toInt32() : args[2].toUInt32();
                      this.pnum = args[3]; this.reg = args[4]; this.inp = args[5]; this.outp = args[6];
                      this.num0 = -1;
                      try { this.num0 = this.pnum.readU32(); } catch (e) {}
                      this.skey = hexlify(this.ctx.add(is64 ? 16 : 8), 16);
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
                              pt: this.pt, ct: hexlify(this.outp, Math.min(Math.max(this.len, 0), 8192)),
                              canary: this.pt.indexOf("52314b455948") === 0 ? 1 : 0 });
                      dumpBss("post-cfb");
                  }
              });
              L("[+] hooked " + k + " @ " + a);
          } catch (e) { L("[HOOKFAIL] " + k + ": " + e); }
      });

      // --- CTR: (ctx, enc, len, &num, ctr16, ks16, in, out) ---
      try {
          var aCtr = addrOf("CTR");
          if (aCtr) {
          Interceptor.attach(aCtr, {
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
          L("[+] hooked CTR @ " + aCtr);
          }
      } catch (e) { L("[HOOKFAIL] CTR: " + e); }

      // --- CBC: 签名未定案 → 原始6参dump (472 无 SETA_CBC — 单点) ---
      [["CBC", "cbc", 999999]].forEach(function(spec) {
          try {
              var a = addrOf(spec[0]);
              if (!a) return;
              var cnt = 0;
              Interceptor.attach(a, {
                  onEnter: function(args) {
                      this.skip = (cnt >= spec[2]);
                      if (this.skip) return;
                      this.a = [];
                      for (var i = 0; i < 6; i++) {
                          this.a.push({ p: args[i].toString(), mem: hexlify(args[i], 48),
                                        v: (function(x) { try { return x.toInt32(); } catch (e) { return null; } })(args[i]) });
                      }
                  },
                  onLeave: function(ret) {
                      cnt++;
                      if (this.skip) return;
                      STAT[spec[1]] = (STAT[spec[1]] || 0) + 1;
                      R1KEY({ ev: spec[1], ret: String(ret), args: this.a });
                  }
              });
              L("[+] hooked " + spec[0] + " @ " + a);
          } catch (e) { L("[HOOKFAIL] " + spec[0] + ": " + e); }
      });

      // --- GEN_ENCRYPT: (in, len, key, &outlen) PKCS7+CBC IV=key[:16] ---
      try {
          var aGe = addrOf("GEN_ENCRYPT");
          if (aGe) {
          Interceptor.attach(aGe, {
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
                  dumpBss("post-genenc");
              }
          });
          L("[+] hooked GEN_ENCRYPT @ " + aGe);
          }
      } catch (e) { L("[HOOKFAIL] GEN_ENCRYPT: " + e); }

      // --- 采集点e: SetB 块级原语 (VMP 手搓 CFB 的必经之路) ---
      var BLK_LAST = {};   // tid → [lastT, runCount]
      [["SETB_BLK", "blk"], ["SETB_BLKENC", "blkenc"], ["SETB_BLKDEC", "blkdec"]].forEach(function(spec) {
          try {
              var a = addrOf(spec[0]);
              if (!a) return;
              Interceptor.attach(a, {
                  onEnter: function(args) {
                      this.k = spec[1]; this.ctx = args[0];
                      this.in16 = hexlify(args[1], 16);
                      this.a2 = hexlify(args[2], 16);
                      this.a3 = hexlify(args[3], 16);
                      this.p1 = args[1]; this.p2 = args[2];
                      this.key16 = hexlify(args[0].add(is64 ? 16 : 8), 16);   // sched[0:16]=原始key
                      this.key16_alt = hexlify(args[0].add(is64 ? 8 : 16), 16);
                  },
                  onLeave: function(ret) {
                      STAT.blk++;
                      if (STAT.blk > LIMITS.blk_dump) return;
                      var tid = Process.getCurrentThreadId();
                      var now = Date.now();
                      var last = BLK_LAST[tid];
                      var run = (last && now - last[0] < 50) ? last[1] + 1 : 1;
                      BLK_LAST[tid] = [now, run];
                      R1KEY({ ev: "blockprim", fn: this.k, tid: tid, burst: run,
                              ctx_key_off8: this.key16_alt, ctx_key_off16: this.key16,
                              in16: this.in16, a2: this.a2, a3: this.a3,
                              p1_out: hexlify(this.p1, 16), p2_out: hexlify(this.p2, 16),
                              ret: String(ret), t: now });
                      if (run === 30) L("[BLK] ★同线程30连发(手搓CFB特征) tid=" + tid);
                      dumpBss("post-blk");
                  }
              });
              L("[+] hooked " + spec[0] + " @ " + a);
          } catch (e) { L("[HOOKFAIL] " + spec[0] + ": " + e); }
      });

      // --- R10: 反 frida 检测函数钩 (JNI 注册表实测定案, 472 明文名) ---
      // 472 libknobs 静态 JNI 表 (relocation addend 解码) + 反汇编复核:
      //   jniCheckFridaByTask=0x7c48 (核心 0x74d8: opendir /proc/self/task +
      //     readdir + open /proc/self/task/%s/status + grep "gum-js-loop"/"gmain"
      //     = frida 线程名扫描 → isFridaByTask)
      //   jniCheckFridaByFd=0x7c64 (核心 0x729c: /proc/self/fd 扫描)
      //   jniCheckInlineByFuncsArm=0x7c80 (核心 0x76e0: 函数序言 inline-hook 检测
      //     — 会看到我们自己的 Interceptor 钩, 必须归零)
      //   jniCheckRootByMagisk=0x7c9c (/proc/self/mountinfo grep magisk)
      //   jniCheckRootByAttr=0x7d4c
      // 策略: onLeave 强制 retval=0 (检测=假) → envJSON 的 isFrida×3/isRoot 族字段
      // 全干净, App 认为环境未被注入。472 JNI_OnLoad 无反调试(纯 RegisterNatives×10,
      // 与 480 不同), 检测全在这些 Java 可调 wrapper 里。
      if (is64) {
          var DETECT_FNS = {
              jniCheckFridaByTask: 0x7c48,
              jniCheckFridaByFd: 0x7c64,
              jniCheckInlineByFuncsArm: 0x7c80,
              jniCheckRootByMagisk: 0x7c9c,
              jniCheckRootByAttr: 0x7d4c
          };
          var DETECT_CNT = {};
          Object.keys(DETECT_FNS).forEach(function (k) {
              try {
                  var a = mod.base.add(DETECT_FNS[k]);
                  Interceptor.attach(a, {
                      onEnter: function (args) { DETECT_CNT[k] = (DETECT_CNT[k] || 0) + 1; this.n = DETECT_CNT[k]; },
                      onLeave: function (retval) {
                          var orig = retval.toInt32 ? retval.toInt32() : 0;
                          retval.replace(0);
                          if (this.n <= 3) {
                              R1KEY({ ev: 'jnicheck', fn: k, orig: orig, forced: 0 });
                          }
                      }
                  });
                  L("[+] hooked 检测函数 " + k + " @ " + a + " (返回强制 0)");
              } catch (e) { L("[HOOKFAIL] 检测 " + k + ": " + e); }
          });
      } else {
          L("[KNOBS] arm32 检测函数偏移未 RECON — 跳过 jniCheck* 钩");
      }

      // --- knobs_lk (lk信封 native 面, sora 构建路径兜底) ---
      try {
          var aLk = addrOf("LK");
          if (aLk) {
          Interceptor.attach(aLk, {
              onEnter: function(args) { this.a0 = args[0]; this.a1 = args[1]; },
              onLeave: function(ret) {
                  R1KEY({ ev: "knobs_lk", a0: String(this.a0), a1: String(this.a1), ret: String(ret),
                          retmem: hexlify(ret, 64) });
              }
          });
          L("[+] hooked LK @ " + aLk);
          }
      } catch (e) { L("[HOOKFAIL] LK: " + e); }

      // --- .bss 192B 轮询 ---
      try {
          BSS_PTR = Module.findExportByName("libknobs.so", SYMNAME.BSS) || mod.base.add(OFF.BSS);
          L("[KNOBS] bss192 @ " + BSS_PTR);
          dumpBss("init");
          var tick = 0;
          var timer = setInterval(function() {
              tick++;
              dumpBss("poll" + tick);
              if (tick >= 130) clearInterval(timer);
          }, 5000);
      } catch (e) { L("[BSSFAIL] " + e); }

      // --- canary 自检直调 (证明 Interceptor 存活 + 语义离线可判) ---
      // R6(2026-10-19): R5 实证 canary 直调=会话杀手 — run 39144212644 collect log 铁序:
      //   canary keyexp PASS(ret=0事件已发) → [CANARY_ERR] access violation 0x1f2c8f45ffc40
      //   → 0.6s 后 Process terminated — 4800s hold 活窗被砍成 1.6s, 其后 553s 流量全为
      //   系统重启的无钩裸进程(r-wire 加密从未处于被钩活窗 ⇒ cfb 事件=0 的真因, 覆盖无缺口)。
      //   死因细读: "step":"cfb" 事件从未发出 ⇒ fault 发生在 CFB 直调体内(keyexp 直调已
      //   正常返回; BLK 直调排在 CFB 之后从未执行) — 472 CFB 签名/语义与 480 表不符,
      //   直调传错参即坏指针。
      //   修复: 直调全部开关化 — keyexp 直调 R5 PASS 保留默认开(存活探针);
      //   cfb/blk 直调默认关(凡有直调风险一律加开关默认关; Interceptor 挂钩本体不受影响,
      //   事件捕获照常)。
      var CANARY_DIRECT = { keyexp: true, cfb: false, blk: false };
      setTimeout(function() {
          try {
              var ctx = Memory.alloc(256);
              var keyBuf = Memory.alloc(16);
              var KEY_HEX = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
              for (var i = 0; i < 16; i++) keyBuf.add(i).writeU8(parseInt(KEY_HEX.substr(i * 2, 2), 16));
              var ptBuf = Memory.alloc(32);
              var PT_HEX = "52314b455948554e545f43414e415259";   // "R1KEYHUNT_CANARY"
              for (var j = 0; j < 16; j++) ptBuf.add(j).writeU8(parseInt(PT_HEX.substr(j * 2, 2), 16));
              var ctBuf = Memory.alloc(32);
              var regBuf = Memory.alloc(16);   // IV=0
              var numBuf = Memory.alloc(4); numBuf.writeU32(0);
              if (CANARY_DIRECT.keyexp && KNOBS_ADDR.SETB_KEYEXP) {
                  var fKeyexp = new NativeFunction(KNOBS_ADDR.SETB_KEYEXP, 'int', ['pointer', 'pointer', 'int']);
                  var r0 = fKeyexp(ctx, keyBuf, 128);
                  STAT.canary++;
                  R1KEY({ ev: "canary", step: "keyexp", ret: r0, key: KEY_HEX,
                          ctx: hexlify(ctx, 192), pt: PT_HEX });
              }
              if (CANARY_DIRECT.cfb && KNOBS_ADDR.CFB) {
                  var fCfb = new NativeFunction(KNOBS_ADDR.CFB, 'int',
                      ['pointer', 'int', 'int', 'pointer', 'pointer', 'pointer', 'pointer']);
                  var r1 = fCfb(ctx, 1, 16, numBuf, regBuf, ptBuf, ctBuf);
                  STAT.canary++;
                  R1KEY({ ev: "canary", step: "cfb", ret: r1, ct: hexlify(ctBuf, 16),
                          reg_out: hexlify(regBuf, 16), expect: "cfb_enc(KEY,IV=0,R1KEYHUNT_CANARY)" });
              }
              if (CANARY_DIRECT.blk) {
                  try {
                      var blkIn = Memory.alloc(16);
                      blkIn.writeByteArray(Array.prototype.slice.call(new Uint8Array(Memory.readByteArray(ctBuf, 16))));
                      var blkOut = Memory.alloc(16);
                      [["SETB_BLKENC", 2], ["SETB_BLK", 2]].forEach(function(bs) {
                          try {
                              if (!KNOBS_ADDR[bs[0]]) return;
                              var fB = new NativeFunction(KNOBS_ADDR[bs[0]], 'int', ['pointer', 'pointer', 'pointer']);
                              var rb = fB(ctx, blkIn, blkOut);
                              STAT.canary++;
                              R1KEY({ ev: "canary", step: bs[0], ret: rb, in16: hexlify(blkIn, 16),
                                      out16: hexlify(blkOut, 16), inplace: hexlify(blkIn, 16) });
                          } catch (e2) { R1KEY({ ev: "canary", step: bs[0], err: String(e2) }); }
                      });
                  } catch (e) {}
              }
              L("[CANARY] 自检直调完成 (direct=" + JSON.stringify(CANARY_DIRECT) + "; r1_gen.py canary 子命令离线判定语义)");
          } catch (e) { L("[CANARY_ERR] " + e); }
      }, 800);
  }
  // hookKnobs 装载触发 — R11: dlopen Interceptor 钩全撤, 改 JS 线程轮询。
  // R10 尸检定案: 早武装进程的挂死 (2068 ANR/gathererga) 与"僵尸装载" (script.load()
  //   返回✓但零 console 输出) 都指向 init 期 frida JS 引擎楔死; 头号嫌疑 = dlopen 钩的
  //   onEnter/onLeave 在【调用者持有 linker/loader 锁】时进 JS —— JS 线程侧的模块/符号
  //   查询也拿 loader 锁 → 经典 ABBA (app线程: loader锁→JS锁 vs JS线程: JS锁→loader锁)。
  //   R8 无守卫版 209 载全通无僵尸, R9/R10 守卫版必现僵尸+挂死; R5/R6 晚挂没赶上 init 期
  //   dlopen 风暴。撤 dlopen 钩 = 斩断唯一"loader 锁→JS"边; hookKnobs 轮询化 (JS 线程
  //   自查, 无 app 线程新增 JS 入口)。r 加密 +1.3~2.2s vs 轮询 200ms — 捕获窗不受影响。
  hookKnobs();   // 立即试(attach模式兼容)
  var knobsPollCnt = 0;
  var knobsPoll = setInterval(function () {
      knobsPollCnt++;
      if (!KNOBS_HOOKED) { try { hookKnobs(); } catch (e) {} }
      if (KNOBS_HOOKED) {
          clearInterval(knobsPoll);
          L("[KNOBS] 轮询命中 (第 " + knobsPollCnt + " 轮, " + (knobsPollCnt * 0.2).toFixed(1) + "s)");
      } else if (knobsPollCnt >= 900) {
          clearInterval(knobsPoll);
          L("[KNOBS] 900 轮询(180s)未见 libknobs — 停");
      }
  }, 200);

  // ═══ ③ SSL_write 线路捕获 (r1 绕开 Java okhttp → 下移到 TLS 层; 472 wire 端点同款 /client/r1) ═══
  var SSL_ACCUM = {};      // sslPtr → {buf:[bytes], len:int}
  var LAST_R1_WIRE = null; // {i:[bytes], r:[bytes], t:ms}
  var SSL_HOST_HINT = /druidv6|if\.qidian|argus/;

  function parseFormBody(bodyStr) {
      var out = {};
      bodyStr.split("&").forEach(function(kv) {
          var ix = kv.indexOf("=");
          if (ix > 0) out[kv.substring(0, ix)] = kv.substring(ix + 1);
      });
      return out;
  }
  function onR1Wire(head, body) {
      try {
          STAT.sslwire++;
          if (STAT.sslwire > LIMITS.sslwire) return;
          var form = parseFormBody(body);
          var iB = form.i ? b64ToBytes(decodeURIComponent(form.i.replace(/\+/g, "%2B"))) : null;
          var rB = form.r ? b64ToBytes(decodeURIComponent(form.r.replace(/\+/g, "%2B"))) : null;
          var soraHdr = null;
          var m = head.match(/sora:\s*([^\r\n]+)/i);
          if (m) soraHdr = m[1].trim();
          R1KEY({ ev: "sslwire", url: head.split("\r\n")[0].substring(0, 200),
                  i_len: iB ? iB.length : 0, r_len: rB ? rB.length : 0,
                  i: iB ? hexlifyBytes(iB) : null, r: rB ? hexlifyBytes(rB) : null,
                  o16: form.o16 || "", o36: form.o36 || "", q16: form.q16 || "", q36: form.q36 || "",
                  runMode: form.runMode || "", sora: soraHdr, t: Date.now() });
          if (rB && rB.length >= 64) {
              LAST_R1_WIRE = { i: iB, r: rB, t: Date.now() };
          }
      } catch (e) { L("[SSLWIRE_ERR] " + e); }
  }
  function feedSsl(sslPtr, bufPtr, len) {
      try {
          var key = sslPtr.toString();
          var acc = SSL_ACCUM[key];
          if (!acc) { acc = SSL_ACCUM[key] = { buf: [], len: 0 }; }
          var take = Math.min(len, 16384 - acc.len);
          if (take <= 0) { return; }
          var u8 = new Uint8Array(Memory.readByteArray(bufPtr, take));
          acc.buf.push(u8); acc.len += take;
          var all = [];
          for (var i = 0; i < acc.buf.length; i++) all = all.concat(Array.prototype.slice.call(acc.buf[i]));
          var s = "";
          for (var k = 0; k < all.length; k++) s += String.fromCharCode(all[k]);
          var hix = s.indexOf("\r\n\r\n");
          if (hix < 0) return;
          var head = s.substring(0, hix);
          if (head.indexOf("POST ") !== 0 && head.indexOf("GET ") !== 0) { delete SSL_ACCUM[key]; return; }
          var isR1 = head.indexOf("/client/r1") >= 0;
          var isSora = /sora:/i.test(head);
          var cl = 0;
          var m = head.match(/Content-Length:\s*(\d+)/i);
          if (m) cl = parseInt(m[1], 10);
          var body = s.substring(hix + 4);
          var complete = (cl === 0 && body.length > 0) || body.length >= cl;
          if (!complete) return;   // 等下一个 SSL_write 分片
          delete SSL_ACCUM[key];
          if (isR1) {
              onR1Wire(head, body);
          } else if (isSora) {
              STAT.sora = (STAT.sora || 0) + 1;
              var sm = head.match(/sora:\s*([^\r\n]+)/i);
              var um = head.match(/^(?:POST|GET)\s+(\S+)/);
              R1KEY({ ev: "sora", url: um ? um[1].substring(0, 160) : "?",
                      value: sm ? sm[1].trim().substring(0, 8192) : null, t: Date.now() });
          }
      } catch (e) { delete SSL_ACCUM[sslPtr.toString()]; }
  }
  try {
      var pSslWrite = Module.findExportByName("libssl.so", "SSL_write");
      if (pSslWrite) {
          Interceptor.attach(pSslWrite, {
              onEnter: function(args) { feedSsl(args[0], args[1], args[2].toInt32()); }
          });
          L("[+] SSL_write hooked (r1/sora wire 捕获)");
      } else {
          L("[E] SSL_write 未找到 — r1 wire 触发器缺失");
      }
  } catch (e) { L("[E] SSL_write: " + e); }


      L("[READY] r1 keyhunt 472(LSPatch) armed " + Date.now());
  } catch (e) { R1KEY({ ev: "boot_error", msg: String(e), stack: String(e && e.stack || "").slice(0, 400) }); }
}, 0);
