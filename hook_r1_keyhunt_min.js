// hook_r1_keyhunt_min.js — R16 syscall-kill 封堵版 (2026-10-18)
// 判别链: R12(无钩scanonly=app活) vs R10/11/13(v2全钩=app挂死) ⇒ convoy效应(syscall级钩拖死壳init)。
//   R14 min版=app全速跑通但 spawn进程被壳120-200ms杀; R15 raise(SIGKILL)被中和但进程仍死于 signal 9
//   (logcat: "Process 3346 exited due to signal 9") ⇒ 第二杀路径=绕 libc 的 kill(裸SVC或syscall() wrapper)。
// R16 三层封堵:
//   ① libc syscall() wrapper 钩(冷门) — kill/tkill/tgkill sig→0, exit_group nr→getpid;
//   ② seccomp BPF(TSYNC) — 裸 SVC 路径: kill/tkill(sig==9)/tgkill(sig==9)与 exit_group → ERRNO(EPERM);
//   ③ 线程改名修复 — R15×0根因=arm64 dirent d_name偏移应为19(非24), 全dump comm+白名单改名中性名。
// 拿钥件不变: ②libknobs全点位(keyexp=目标) + bss192 + ③SSL_write(r1 wire) + dlopen触发挂载。
// 输出同v2格式([R1KEY] ev 事件), ci/r1_gen.py harvest 兼容。

var STAT = { keyexpA: 0, keyexpB: 0, cfb: 0, ctr: 0, cbc: 0, genenc: 0, blk: 0, bss: 0,
             canary: 0, sslwire: 0, knobs_hooked: 0 };
var LIMITS = { keyexpA_dump: 40, blk_dump: 4000, sslwire: 240 };
var SEEN = { bss: {} };

function L(s) { console.log(s); }
function R1KEY(obj) { try { L("[R1KEY] " + JSON.stringify(obj)); } catch (e) { L("[R1KEY_ERR] " + e); } }
R1KEY({ ev: "script_loaded", t: Date.now(), frida: (typeof Frida !== "undefined" ? Frida.version : "?"), pid: Process.id, abi: Process.arch, min: true });
if (typeof process !== "undefined" && process.setExceptionHandler) {
  process.setExceptionHandler(function (d) { try { R1KEY({ ev: "native_exception", addr: String(d.address), type: d.type }); } catch (e) {} return false; });
}

setTimeout(function BOOT() {
  try {
  // ═══ R16 存活件: 三层杀路径封堵 + 线程隐形(修复R15 dirent偏移bug) ═══
  // ① 直调 libc(open/read/write/opendir/readdir) 零钩枚举/proc/self/task — R15×0根因:
  //    arm64 struct dirent d_name 在偏移 19 (d_ino8+d_off8+d_reclen2+d_type1), 脚本旧值24读空。
  //    本版: 全量dump comm(诊断) + 白名单外线程改中性名(壳读comm时无frida痕迹)。
  var libc = {
      open: new NativeFunction(Module.findExportByName(null, "open"), 'int', ['pointer','int','int']),
      read: new NativeFunction(Module.findExportByName(null, "read"), 'long', ['int','pointer','long']),
      write: new NativeFunction(Module.findExportByName(null, "write"), 'long', ['int','pointer','long']),
      close: new NativeFunction(Module.findExportByName(null, "close"), 'int', ['int']),
      opendir: new NativeFunction(Module.findExportByName(null, "opendir"), 'pointer', ['pointer']),
      readdir: new NativeFunction(Module.findExportByName(null, "readdir"), 'pointer', ['pointer'])
  };
  // 白名单=任何Android app都有的线程名(缺失反而可疑); 其余(含gum-js-loop/gmain/pool-frida-*)全改Thread-9NN
  var BENIGN = /^(main|RenderThread|binder:|Thread-\d+|pool-\d+|Jit |Heap |Finalizer|Reference|queued|GLThread|RenderThread)/;
  function commPass(tag) {
      var REN = 0, SEQ = 0, report = [];
      try {
          var taskp = Memory.allocUtf8String("/proc/self/task");
          var dp = libc.opendir(taskp);
          if (dp.isNull()) { L("[R16] commPass(" + tag + "): opendir fail"); return 0; }
          var NAMEMAX = 256;
          var dent = Memory.alloc(NAMEMAX + 16);
          var NAME_OFFS = (Process.arch === "arm64") ? [19, 24] : [11, 19, 24];
          var buf = Memory.alloc(64);
          var seen = {};
          while (true) {
              var r = libc.readdir(dp);
              if (r.isNull()) break;
              Memory.copy(dent, r, NAMEMAX + 16);
              var tid = null;
              for (var oi = 0; oi < NAME_OFFS.length; oi++) {
                  var s = null;
                  try { s = Memory.readCString(dent.add(NAME_OFFS[oi])); } catch (e2) {}
                  if (s && /^\d+$/.test(s)) { tid = s; break; }
              }
              if (!tid || seen[tid]) continue;
              seen[tid] = 1;
              var commp = Memory.allocUtf8String("/proc/self/task/" + tid + "/comm");
              var fd = libc.open(commp, 0 /*O_RDONLY*/, 0);
              if (fd < 0) continue;
              var n = libc.read(fd, buf, 63);
              libc.close(fd);
              var name = (n > 0) ? String(Memory.readCString(buf)).replace(/\0.*$/,"").trim() : "";
              if (!name) name = "<empty>";
              report.push(tid + ":" + name);
              if (!BENIGN.test(name)) {
                  SEQ++;
                  var neu = "Thread-9" + ("0" + SEQ).slice(-2) + "\n";
                  var wfd = libc.open(commp, 1 /*O_WRONLY*/, 0);
                  if (wfd >= 0) {
                      var nb = Memory.allocUtf8String(neu);
                      libc.write(wfd, nb, neu.length);
                      libc.close(wfd);
                      REN++;
                      report.push("→" + neu.trim());
                  }
              }
          }
          L("[R16] comm(" + tag + ") threads=" + report.length + " renamed=" + REN + " :: " + report.join(" | "));
      } catch (e) { L("[R16_ERR] commPass: " + e); }
      return REN;
  }
  commPass("boot");

  // ② 冷门杀路径拦截(libc层: exit/kill族=正常运行期几乎不被调用, 无convoy) — 壳杀进程时被挡+留观测
  try {
      var mypid = Process.id;
      var fnc_usleep = new NativeFunction(Module.findExportByName(null, "usleep"), 'void', ['uint64']);
      var fnc_gettid = new NativeFunction(Module.findExportByName(null, "gettid"), 'int', []);
      ["exit", "_exit", "abort"].forEach(function(fn) {
          try {
              var p = Module.findExportByName(null, fn);
              if (p) Interceptor.replace(p, new NativeCallback(function(a) {
                  try { if (fnc_gettid() !== mypid) fnc_usleep(30000000); } catch (e) {}
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
                              L("[R15] neutralized " + spec[0] + " sig=" + sig);
                          }
                      } catch (e) {}
                  }
              });
          } catch (e) {}
      });
      L("[R15] kill-blockers armed");
  } catch (e) { L("[R15_ERR] blockers: " + e); }

  // ③ R16 syscall() wrapper 钩 — 第二杀路径候选A(壳经libc syscall()发kill绕过kill/raise符号):
  //    kill(pid,sig)/tkill(tid,sig): sig→0; tgkill(tgid,tid,sig): sig→0; exit_group: nr→getpid(壳继续跑)。
  //    syscall()在bionic中仅被冷门路径调用, 无convoy风险。onEnter改x0(=nr)在wrapper prologue移位前生效。
  try {
      var pSys = Module.findExportByName(null, "syscall");
      if (pSys) {
          var A64 = (Process.arch === "arm64");
          var NR = A64 ? { kill: 129, tkill: 130, tgkill: 131, exit_group: 94, getpid: 172 }
                       : { kill: 37, tkill: 268, tgkill: 269, exit_group: 248, getpid: 20 };
          Interceptor.attach(pSys, {
              onEnter: function(args) {
                  try {
                      var nr = args[0].toInt32();
                      if (nr === NR.kill || nr === NR.tkill) {
                          var sig = args[2].toInt32();
                          if (sig === 9 || sig === 6 || sig === 15 || sig === 4 || sig === 11) {
                              args[2] = ptr(0);
                              L("[R16] syscall(nr=" + nr + ") sig=" + sig + " neutralized tid=" + Process.getCurrentThreadId());
                          }
                      } else if (nr === NR.tgkill) {
                          var sig2 = args[3].toInt32();
                          if (sig2 === 9 || sig2 === 6 || sig2 === 15 || sig2 === 4 || sig2 === 11) {
                              args[3] = ptr(0);
                              L("[R16] syscall(tgkill) sig=" + sig2 + " neutralized tid=" + Process.getCurrentThreadId());
                          }
                      } else if (nr === NR.exit_group) {
                          args[0] = ptr(NR.getpid);
                          L("[R16] syscall(exit_group)→getpid tid=" + Process.getCurrentThreadId());
                      }
                  } catch (e) {}
              }
          });
          L("[R16] syscall() wrapper hook armed @ " + pSys);
      } else { L("[R16] libc syscall export 未找到"); }
  } catch (e) { L("[R16_ERR] syscall hook: " + e); }

  // ④ R16 seccomp BPF(TSYNC) — 第二杀路径候选B(壳裸SVC指令发kill, 任何用户态钩都拦不到):
  //    过滤器: kill/tkill(sig==9)/tgkill(sig==9)/exit_group → SECCOMP_RET_ERRNO|EPERM, 其余全ALLOW。
  //    仅封sig9(实证死因), 不碰frida线程suspend用的RT信号; TSYNC覆盖当前全部线程+后续fork继承。
  try {
      var prctlFn = new NativeFunction(Module.findExportByName(null, "prctl"), 'int', ['int','long','long','long','long']);
      var syscallFn = new NativeFunction(Module.findExportByName(null, "syscall"), 'long', ['long','long','long','pointer']);
      var A64s = (Process.arch === "arm64");
      var NR_KILL = A64s ? 129 : 37, NR_TKILL = A64s ? 130 : 268, NR_TGKILL = A64s ? 131 : 269, NR_EXITG = A64s ? 94 : 248;
      var NR_SECC = A64s ? 277 : 383;
      var ARCH = A64s ? 0xC00000B7 : 0x40000028;   // AUDIT_ARCH_AARCH64 / AUDIT_ARCH_ARM
      function fLD(k) { return [0x20, 0, 0, k]; }        // BPF_LD|BPF_W|BPF_ABS
      function fJEQ(k, jt, jf) { return [0x15, jt, jf, k]; } // BPF_JMP|BPF_JEQ|BPF_K
      function fRET(k) { return [0x06, 0, 0, k]; }      // BPF_RET|BPF_K
      var ALLOWK = 0x7FFF0000, ERRK = 0x00050001;       // SECCOMP_RET_ALLOW / SECCOMP_RET_ERRNO|EPERM
      var prog = [
          fLD(4),                    //  0 arch
          fJEQ(ARCH, 0, 13),         //  1 非本arch→15 ALLOW
          fLD(0),                    //  2 nr
          fJEQ(NR_EXITG, 12, 0),     //  3 exit_group→16 BLOCK
          fJEQ(NR_KILL, 0, 2),       //  4 kill→5; else→7
          fLD(24),                   //  5 sig=arg1低32
          fJEQ(9, 9, 8),             //  6 sig9→16; else→15
          fLD(0),                    //  7 nr
          fJEQ(NR_TKILL, 0, 2),      //  8 tkill→9; else→11
          fLD(24),                   //  9 sig=arg1
          fJEQ(9, 5, 4),             // 10 sig9→16; else→15
          fLD(0),                    // 11 nr
          fJEQ(NR_TGKILL, 0, 2),     // 12 tgkill→13; else→15
          fLD(32),                   // 13 sig=arg2
          fJEQ(9, 1, 0),             // 14 sig9→16; else→15
          fRET(ALLOWK),              // 15
          fRET(ERRK)                 // 16
      ];
      var filt = Memory.alloc(prog.length * 8);
      for (var i = 0; i < prog.length; i++) {
          var ins = prog[i];
          filt.add(i * 8).writeByteArray([ins[0] & 0xff, (ins[0] >> 8) & 0xff, ins[1], ins[2],
              ins[3] & 0xff, (ins[3] >> 8) & 0xff, (ins[3] >> 16) & 0xff, (ins[3] >> 24) & 0xff]);
      }
      var fprog = Memory.alloc(16);
      fprog.writeU16(prog.length);
      fprog.add(8).writePointer(filt);
      var rNnp = prctlFn(38 /*PR_SET_NO_NEW_PRIVS*/, 1, 0, 0, 0);
      var rSec = syscallFn(NR_SECC, 1 /*SECCOMP_SET_MODE_FILTER*/, 1 /*FLAG_TSYNC*/, fprog);
      L("[R16] seccomp no_new_privs=" + rNnp + " install=" + rSec +
        (rSec === 0 ? " (TSYNC OK: 裸SVC kill(sig9)/exit_group 已封)" : " FAIL errno=" + (-rSec)));
      if (rSec !== 0) {
          var rSec2 = syscallFn(NR_SECC, 1, 0, fprog);   // 退化: 仅本线程+子线程继承
          L("[R16] seccomp fallback no-TSYNC=" + rSec2);
      }
  } catch (e) { L("[R16_ERR] seccomp: " + e); }

  // ⑤ 存活时间线心跳(前80s, 2s一跳) — 若壳改判"杀不死"则进程活, JS定时器恢复工作(R10/11"饿死"实为进程早死)
  var HB = 0;
  var hbTimer = setInterval(function() {
      HB++;
      L("[R16_HB] t+" + (HB * 2) + "s keyexpB=" + STAT.keyexpB + " cfb=" + STAT.cfb + " blk=" + STAT.blk +
        " sslwire=" + STAT.sslwire + " dlopenPass=" + COMM_PASSES);
      if (HB >= 40) clearInterval(hbTimer);
  }, 2000);


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
  function sha16(s) {
      var h = 0x811c9dc5;
      for (var i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
      return ("00000000" + h.toString(16)).slice(-8);
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
      return out;   // 普通数组; hexlifyBytes 兼容
  }
  function patFromBytes(arr) {
      var s = "";
      for (var i = 0; i < arr.length; i++) s += ("0" + arr[i].toString(16)).slice(-2) + " ";
      return s.trim();
  }

  // (R7b: AES 表/SBOX/RCON/I_PREFIX_HEX/LAST_SCAN 已提升至顶层 — BOOT 开头 t0 快扫需要)

  // 校验 [w0..w(4*(nk+7)-1)] 是否为合法 AES 扩展调度 (u8 视图, off 起始)
  function schedValidAt(u8, off, nk) {
      var total = 4 * (nk + 7);
      if (off + total * 4 > u8.length) return false;
      var W = function(i) { return u8[off + i * 4]; };   // 仅取首字节做快速门
      // 快速门: 两个非RCON字的最低字节关系 (12.5% × 12.5% ≈ 1.6% 通过, 再全验)
      if ((u8[off + 5 * 4] ^ u8[off + 1 * 4] ^ u8[off + 4 * 4]) !== 0) return false;
      if ((u8[off + 6 * 4] ^ u8[off + 2 * 4] ^ u8[off + 5 * 4]) !== 0) return false;
      for (var i = nk; i < total; i++) {
          var t0, t1, t2, t3;
          if (i % nk !== 0) {
              for (var b = 0; b < 4; b++) {
                  if (u8[off + i * 4 + b] !== (u8[off + (i - nk) * 4 + b] ^ u8[off + (i - 1) * 4 + b])) return false;
              }
          } else {
              var k = i / nk;
              if (k >= RCON.length) return false;
              var a0 = u8[off + (i - 1) * 4 + 1], a1 = u8[off + (i - 1) * 4 + 2],
                  a2 = u8[off + (i - 1) * 4 + 3], a3 = u8[off + (i - 1) * 4];
              t0 = SBOX[a0] ^ RCON[k]; t1 = SBOX[a1]; t2 = SBOX[a2]; t3 = SBOX[a3];
              if (u8[off + i * 4] !== (u8[off + (i - nk) * 4] ^ t0)) return false;
              if (u8[off + i * 4 + 1] !== (u8[off + (i - nk) * 4 + 1] ^ t1)) return false;
              if (u8[off + i * 4 + 2] !== (u8[off + (i - nk) * 4 + 2] ^ t2)) return false;
              if (u8[off + i * 4 + 3] !== (u8[off + (i - nk) * 4 + 3] ^ t3)) return false;
          }
      }
      return true;
  }

  // ═══ ② libknobs 全点位 (懒加载轮询) ═══
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
      var OFF = is64 ? {
          SETA_KEYEXP: 0x103e0, SETB_KEYEXP: 0x126c4, GEN_ENCRYPT: 0x1201c,
          CBC: 0x13db4, CFB: 0x140ac, CFB_NEON: 0x14188, CTR: 0x1427c, BSS: 0x3159c,
          SETB_BLK: 0x136f0, SETB_BLKENC: 0x13064, SETB_BLKDEC: 0x12e0c,
          SETA_CBC: 0x11ac8, STRARMOR: 0x12460, LK: 0xfd10
      } : {
          SETA_KEYEXP: 0x9fb0, SETB_KEYEXP: 0xbb80, GEN_ENCRYPT: 0xb690,
          CBC: 0xce68, CFB: 0xd07c, CFB_NEON: 0xd118, CTR: 0xd1cc, BSS: 0x2112c,
          SETB_BLK: 0xc81c, SETB_BLKENC: 0xc210, SETB_BLKDEC: 0xc020,
          SETA_CBC: 0xb290, STRARMOR: 0xbd6c, LK: 0x9ab8
      };
      var SYMNAME = {
          SETA_KEYEXP: "knobs_45543224", SETB_KEYEXP: "knobs_40971283",
          GEN_ENCRYPT: "knobs_58940235", CBC: "knobs_96145783",
          CFB: "knobs_12480967", CFB_NEON: "knobs_29716380", CTR: "knobs_87039164",
          BSS: "knobs_70861349",
          SETB_BLK: "knobs_61087493", SETB_BLKENC: "knobs_71564283", SETB_BLKDEC: "knobs_87035146",
          SETA_CBC: "knobs_54352333", STRARMOR: "knobs_67456344", LK: "knobs_lk"
      };
      function addrOf(k) {
          var a = Module.findExportByName("libknobs.so", SYMNAME[k]);
          if (!a) { a = mod.base.add(OFF[k]); L("[KNOBS] " + k + " 符号缺失, 用偏移 0x" + OFF[k].toString(16)); }
          KNOBS_ADDR[k] = a;
          return a;
      }

      // --- keyexp: (ctx, key, bits) — SETB 全量dump; SETA 限额(第一轮642条纯噪声) ---
      [["SETB_KEYEXP", "B"], ["SETA_KEYEXP", "A"]].forEach(function(spec) {
          var k = spec[0], suite = spec[1];
          try {
              Interceptor.attach(addrOf(k), {
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
                              canary: this.pt.indexOf("52314b455948") === 0 ? 1 : 0 });   // "R1KEYH"前缀=canary向量
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

      // --- CBC(0x13db4)/SETA_CBC(0x11ac8): 签名未定案 → 原始6参dump (SETA_CBC=StringArmor用, 限额) ---
      [["CBC", "cbc", 999999], ["SETA_CBC", "setacbc", 20]].forEach(function(spec) {
          try {
              var cnt = 0;
              Interceptor.attach(addrOf(spec[0]), {
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
              L("[+] hooked " + spec[0] + " @ " + addrOf(spec[0]));
          } catch (e) { L("[HOOKFAIL] " + spec[0] + ": " + e); }
      });

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
                  dumpBss("post-genenc");
              }
          });
          L("[+] hooked GEN_ENCRYPT @ " + addrOf("GEN_ENCRYPT"));
      } catch (e) { L("[HOOKFAIL] GEN_ENCRYPT: " + e); }

      // --- 采集点e: SetB 块级原语 (VMP 手搓 CFB 的必经之路; arm64: x0=ctx,x1=in16,输出疑in-place/x2) ---
      // 正常流量下 SetB 块原语应静默(第一轮所有SetB包装器0命中) → 全量记录+同线程爆发检测
      var BLK_LAST = {};   // tid → [lastT, runCount]
      [["SETB_BLK", "blk"], ["SETB_BLKENC", "blkenc"], ["SETB_BLKDEC", "blkdec"]].forEach(function(spec) {
          try {
              Interceptor.attach(addrOf(spec[0]), {
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
              L("[+] hooked " + spec[0] + " @ " + addrOf(spec[0]));
          } catch (e) { L("[HOOKFAIL] " + spec[0] + ": " + e); }
      });

      // --- knobs_lk (lk信封 native 面, sora 构建路径兜底) ---
      try {
          Interceptor.attach(addrOf("LK"), {
              onEnter: function(args) { this.a0 = args[0]; this.a1 = args[1]; },
              onLeave: function(ret) {
                  R1KEY({ ev: "knobs_lk", a0: String(this.a0), a1: String(this.a1), ret: String(ret),
                          retmem: hexlify(ret, 64) });
              }
          });
          L("[+] hooked LK @ " + addrOf("LK"));
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

      // --- canary 自检直调 (一次性合成16B向量; 证明 Interceptor 存活+块原语语义离线可判) ---
      setTimeout(function() {
          try {
              var ctx = Memory.alloc(256);
              var key = Memory.allocUtf8String("");   // 占位
              var keyBuf = Memory.alloc(16);
              var KEY_HEX = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";
              for (var i = 0; i < 16; i++) keyBuf.add(i).writeU8(parseInt(KEY_HEX.substr(i * 2, 2), 16));
              var ptBuf = Memory.alloc(32);
              var PT_HEX = "52314b455948554e545f43414e415259";   // "R1KEYHUNT_CANARY"
              for (var j = 0; j < 16; j++) ptBuf.add(j).writeU8(parseInt(PT_HEX.substr(j * 2, 2), 16));
              var ctBuf = Memory.alloc(32);
              var regBuf = Memory.alloc(16);   // IV=0
              var numBuf = Memory.alloc(4); numBuf.writeU32(0);
              var fKeyexp = new NativeFunction(KNOBS_ADDR.SETB_KEYEXP, 'int', ['pointer', 'pointer', 'int']);
              var r0 = fKeyexp(ctx, keyBuf, 128);
              STAT.canary++;
              R1KEY({ ev: "canary", step: "keyexp", ret: r0, key: KEY_HEX,
                      ctx: hexlify(ctx, 192), pt: PT_HEX });
              var fCfb = new NativeFunction(KNOBS_ADDR.CFB, 'int',
                  ['pointer', 'int', 'int', 'pointer', 'pointer', 'pointer', 'pointer']);
              var r1 = fCfb(ctx, 1, 16, numBuf, regBuf, ptBuf, ctBuf);
              STAT.canary++;
              R1KEY({ ev: "canary", step: "cfb", ret: r1, ct: hexlify(ctBuf, 16),
                      reg_out: hexlify(regBuf, 16), expect: "cfb_enc(KEY,IV=0,R1KEYHUNT_CANARY)" });
              // 块原语 canary: 同一 ctx, in=ct[0:16] (若为E_k则应等于 keystream 块)
              try {
                  var blkIn = Memory.alloc(16);
                  blkIn.writeByteArray(Array.prototype.slice.call(new Uint8Array(Memory.readByteArray(ctBuf, 16))));
                  var blkOut = Memory.alloc(16);
                  [["SETB_BLKENC", 2], ["SETB_BLK", 2]].forEach(function(bs) {
                      try {
                          var fB = new NativeFunction(KNOBS_ADDR[bs[0]], 'int', ['pointer', 'pointer', 'pointer']);
                          var rb = fB(ctx, blkIn, blkOut);
                          STAT.canary++;
                          R1KEY({ ev: "canary", step: bs[0], ret: rb, in16: hexlify(blkIn, 16),
                                  out16: hexlify(blkOut, 16), inplace: hexlify(blkIn, 16) });
                      } catch (e2) { R1KEY({ ev: "canary", step: bs[0], err: String(e2) }); }
                  });
              } catch (e) {}
              L("[CANARY] 自检直调完成 (r1_gen.py canary 子命令离线判定语义)");
          } catch (e) { L("[CANARY_ERR] " + e); }
      }, 800);   // R7: 3000→800ms (壳反杀前完成自检; R5 CANARY_ERR 发生在会话中段)
  }
  // R14: dlopen 触发式挂载 — setInterval 被壳饿死(R10/11实证: 恢复后定时器全死, [KNOBS]从未出现;
  //   拦截器回调仍活=dlsym/mprotect事件可证) ⇒ 挂钩时机改挂在库加载上(dlopen低频, 无convoy风险)。
  // R16: dlopen onLeave 兼作 ①comm 再扫描(壳/app新线程浮现即改名) ②app libssl 的 SSL_write 补挂
  //   (BOOT 时 findExportByName 可能命中 agent 自带 libssl —— 地址去重后 app 的 libssl 加载时补挂)。
  var COMM_PASSES = 0;
  hookKnobs();   // 立即试(attach模式兼容)
  ["android_dlopen_ext", "dlopen", "__loader_dlopen", "__loader_android_dlopen_ext"].forEach(function(fn) {
      try {
          var p = Module.findExportByName(null, fn);
          if (!p) return;
          Interceptor.attach(p, {
              onEnter: function(args) { try { this._p = (args[0] && !args[0].isNull()) ? args[0].readCString() : null; } catch (e) { this._p = null; } },
              onLeave: function(ret) {
                  try { if (COMM_PASSES < 8) { COMM_PASSES++; commPass("dl:" + (this._p || "?").split("/").pop().slice(0, 40)); } } catch (e) {}
                  try { reArmSsl(); } catch (e) {}
                  if (KNOBS_HOOKED) return;
                  try {
                      hookKnobs();
                      if (KNOBS_HOOKED) L("[R14] knobs armed via dlopen(" + (this._p || "?") + ")");
                  } catch (e) {}
              }
          });
          L("[+] dlopen trigger armed: " + fn);
      } catch (e) {}
  });

  // ═══ ③ SSL_write 线路捕获 (第一轮硬教训: r1 绕开 Java okhttp → 下移到 TLS 层) ═══
  var SSL_ACCUM = {};      // sslPtr → {buf:[bytes], len:int}
  var LAST_R1_WIRE = null; // {i:[bytes], r:[bytes], t:ms} — memscan 动态针
  var LAST_SCHEDSCAN = 0;
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
              // 采集点c: r1 发出后 3.5s 做内存扫描 (明文窗口可能仍在堆上) + 调度扫描
              /* R14-min: doMemScan/schedScan 已随扫描节移除(min版只靠keyexp钩拿钥) */
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
          // 拼齐 head+body? 判据: 见到 \r\n\r\n 且累计 ≥ Content-Length 或 body 含 '&' 参数尾
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
              // sora 头出现在 getconf/deeplink 等请求上 — 捕获供离线 lk 解密出 envJSON
              STAT.sora++;
              var sm = head.match(/sora:\s*([^\r\n]+)/i);
              var um = head.match(/^(?:POST|GET)\s+(\S+)/);
              R1KEY({ ev: "sora", url: um ? um[1].substring(0, 160) : "?",
                      value: sm ? sm[1].trim().substring(0, 8192) : null, t: Date.now() });
          }
      } catch (e) { delete SSL_ACCUM[sslPtr.toString()]; }
  }
  var SSL_ARMED_ADDRS = {};
  function reArmSsl() {
      try {
          Process.enumerateModules().forEach(function(m) {
              if (m.name !== "libssl.so") return;
              var p = Module.findExportByName(m.path, "SSL_write");
              if (!p || SSL_ARMED_ADDRS[p.toString()]) return;
              SSL_ARMED_ADDRS[p.toString()] = 1;
              Interceptor.attach(p, {
                  onEnter: function(args) { feedSsl(args[0], args[1], args[2].toInt32()); }
              });
              L("[R16] SSL_write armed @ " + p + " (" + m.path + ")");
          });
      } catch (e) {}
  }
  try {
      var pSslWrite = Module.findExportByName("libssl.so", "SSL_write");
      if (pSslWrite) {
          SSL_ARMED_ADDRS[pSslWrite.toString()] = 1;
          Interceptor.attach(pSslWrite, {
              onEnter: function(args) { feedSsl(args[0], args[1], args[2].toInt32()); }
          });
          L("[+] SSL_write hooked (r1/sora wire 捕获 + memscan 触发器)");
      } else {
          L("[E] SSL_write 未找到 — r1 wire 触发器缺失(靠dlopen补挂+定时扫描兜底)");
      }
  } catch (e) { L("[E] SSL_write: " + e); }


      L("[READY] r1 keyhunt MIN armed (R16 syscall+seccomp 封堵) " + Date.now());
  } catch (e) { R1KEY({ ev: "boot_error", msg: String(e), stack: String(e && e.stack || "").slice(0, 400) }); }
}, 0);
