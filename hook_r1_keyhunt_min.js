// hook_r1_keyhunt_min.js — R18 真零内联钩版 (2026-10-18; R17b→R18 修订见下)
// 判别链: R12(scanonly无钩=app全速跑通) vs R14/15(有libc/linker内联钩=壳120-200ms杀) vs
//   R16(kill全封堵=活30s+但壳改"拒绝注册native"→UnsatisfiedLinkError→SIGSEGV)。
//   ⇒ 检测触发器=内联钩蹦(壳CRC libc/linker代码完整性); 阻断杀路径只换来降级响应(拒注册)。
//   ⇒ R17: 进程内零 Interceptor 钩直到 knobs/SSL 出现 — 存活件只剩 seccomp(无代码补丁, CRC不可见)。
// R17 存活件:
//   ① seccomp BPF(TSYNC): kill/tkill/tgkill(sig∈{4,6,9,11,15}) + exit_group → ERRNO(EPERM)
//     — 覆盖 libc raise/kill 内部裸SVC、syscall() wrapper、壳裸SVC 全部路径(内核层拦截);
//   ② comm 轮询改名(只改 frida 痕迹名 gum/frida/gmain/pool-frida, 不碰 main/ART 线程名);
//   ③ 定时器轮询挂 knobs/libssl(R16 心跳证 JS 定时器活着, R10/11"饿死"实为进程早死误判)。
// 拿钥件不变: libknobs全点位(keyexp=目标) + bss192 + SSL_write(r1 wire)。
// 输出同v2格式([R1KEY] ev 事件), ci/r1_gen.py harvest 兼容。
// R17b (A2复盘R16工件后修订): ①comm改名SEQ全局化(R16 logcat实锤: 被改名线程的子线程继承comm,
//   每pass重置SEQ会产生重名Thread-901=签名) ②seccomp/NNP预态诊断(读/proc/self/status, 判无痕性)
//   ③武装轮询500→200ms(无dlopen钩, libknobs出现→首次keyexp盲窗压窄), 重操作降频600ms ④TICK前移。

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
  // ═══ R17 存活件: 零内联钩(壳CRC检测触发器=钩蹦) — 只留 seccomp + comm改名 + 定时器 ═══
  // ① 直调 libc 枚举/proc/self/task(零钩): 只改 frida 痕迹线程名(gum-js-loop/gmain/pool-frida-*),
  //    不碰 main(qidian.QDReader)/ART 线程名(R16 曾把 main 改名=comm与cmdline不符=可疑特征)。
  var libc = {
      open: new NativeFunction(Module.findExportByName(null, "open"), 'int', ['pointer','int','int']),
      read: new NativeFunction(Module.findExportByName(null, "read"), 'long', ['int','pointer','long']),
      write: new NativeFunction(Module.findExportByName(null, "write"), 'long', ['int','pointer','long']),
      close: new NativeFunction(Module.findExportByName(null, "close"), 'int', ['int']),
      opendir: new NativeFunction(Module.findExportByName(null, "opendir"), 'pointer', ['pointer']),
      readdir: new NativeFunction(Module.findExportByName(null, "readdir"), 'pointer', ['pointer']),
      errno: new NativeFunction(Module.findExportByName(null, "__errno"), 'pointer', [])
  };
  var FRIDA_RE = /gum|frida|gmain|gdbus|linjector|pool-frida/i;
  var LAST_THREADS = -1;
  var REN_SEQ = 0;   // R17b: 全局序号 — 每pass重置会产生重复Thread-901(被改名线程的子线程继承comm, 重名=签名)
  function commPass(tag) {
      var REN = 0, report = [];
      try {
          var taskp = Memory.allocUtf8String("/proc/self/task");
          var dp = libc.opendir(taskp);
          if (dp.isNull()) { L("[R17] commPass(" + tag + "): opendir fail"); return 0; }
          var NAMEMAX = 256;
          var dent = Memory.alloc(NAMEMAX + 16);
          var NAME_OFFS = (Process.arch === "arm64") ? [19, 24] : [11, 19, 24];   // R16修复: d_name@19
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
              if (fd < 0) {
                  var ecode = -1; try { ecode = libc.errno().readS32(); } catch (e3) {}
                  report.push(tid + ":E" + ecode);
                  continue;
              }
              var n = libc.read(fd, buf, 63);
              libc.close(fd);
              var nn = Number(n);
              if (nn > 0) { try { buf.add(nn < 63 ? nn : 62).writeU8(0); } catch (e4) {} }   // NUL 终结(R16读脏)
              var name = (nn > 0) ? String(Memory.readCString(buf)).trim() : "";
              if (!name) name = "<empty>";
              report.push(tid + ":" + name);
              if (FRIDA_RE.test(name)) {
                  REN_SEQ++;
                  var neu = "Thread-9" + ("0" + REN_SEQ).slice(-2) + "\n";
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
          var nThreads = report.length;
          if (tag === "boot" || REN > 0 || nThreads !== LAST_THREADS) {
              L("[R17] comm(" + tag + ") threads=" + nThreads + " renamed=" + REN + " :: " + report.join(" | "));
              LAST_THREADS = nThreads;
          }
      } catch (e) { L("[R17_ERR] commPass: " + e); }
      return REN;
  }
  commPass("boot");

  // ② seccomp BPF(TSYNC) — 唯一存活防线(无代码补丁, 壳CRC不可见): 内核层封 kill/tkill/tgkill
  //    (sig∈{4,6,9,11,15}) 与 exit_group → ERRNO(EPERM)。覆盖 libc raise/kill(内部裸SVC)、
  //    syscall() wrapper、壳裸SVC 全部路径。frida 线程suspend用SIGRTMIN不受影响。
  try {
      // R17b: 预态诊断 — 装 filter 前读 /proc/self/status (Android app 由 zygote 预装 seccomp+NNP;
      // 若 NoNewPrivs 已=1, 我们的 prctl 是无痕 no-op; 若=0 则状态可观测, 需在 postmortem 里排查)
      try {
          var stp = Memory.allocUtf8String("/proc/self/status");
          var sfd = libc.open(stp, 0, 0);
          if (sfd >= 0) {
              var sbuf = Memory.alloc(4096);
              var sn = Number(libc.read(sfd, sbuf, 4095));
              libc.close(sfd);
              if (sn > 0) {
                  sbuf.add(sn < 4095 ? sn : 4094).writeU8(0);
                  var stxt = String(Memory.readCString(sbuf));
                  var secline = (stxt.match(/Seccomp:\s*\d+(?:\s+\(\w+\))?/i) || [])[0] || "Seccomp:?";
                  var nnsline = (stxt.match(/NoNewPrivs:\s*\d+/i) || [])[0] || "NoNewPrivs:?";
                  L("[R17] seccomp prestate: " + secline + " " + nnsline + " (zygote默认)");
              }
          }
      } catch (e0) {}
      var prctlFn = new NativeFunction(Module.findExportByName(null, "prctl"), 'int', ['int','long','long','long','long']);
      var syscallFn = new NativeFunction(Module.findExportByName(null, "syscall"), 'int', ['int','long','long','pointer']);
      var A64s = (Process.arch === "arm64");
      var NR_KILL = A64s ? 129 : 37, NR_TKILL = A64s ? 130 : 268, NR_TGKILL = A64s ? 131 : 269, NR_EXITG = A64s ? 94 : 248;
      var NR_SECC = A64s ? 277 : 383;
      var ARCH = A64s ? 0xC00000B7 : 0x40000028;   // AUDIT_ARCH_AARCH64 / AUDIT_ARCH_ARM
      function fLD(k) { return [0x20, 0, 0, k]; }        // BPF_LD|BPF_W|BPF_ABS
      function fJEQ(k, jt, jf) { return [0x15, jt, jf, k]; } // BPF_JMP|BPF_JEQ|BPF_K
      function fRET(k) { return [0x06, 0, 0, k]; }      // BPF_RET|BPF_K
      var ALLOWK = 0x7FFF0000, ERRK = 0x00050001;       // SECCOMP_RET_ALLOW / SECCOMP_RET_ERRNO|EPERM
      // 布局: 0 arch,1 archchk,2 nr,3 exit_group, 4 kill, 5 tkill, 6-11 kill/tkill sig块, 12 nr reload,
      //       13 tgkill, 14-19 tgkill sig块, 20 ALLOW, 21 BLOCK
      var prog = [
          fLD(4),                    //  0 arch
          fJEQ(ARCH, 0, 18),         //  1 非本arch→20 ALLOW
          fLD(0),                    //  2 nr
          fJEQ(NR_EXITG, 17, 0),     //  3 exit_group→21 BLOCK
          fJEQ(NR_KILL, 1, 0),       //  4 kill→6; else→5
          fJEQ(NR_TKILL, 0, 6),      //  5 tkill→6; else→12(跳过kill sig块)
          fLD(24),                   //  6 sig=arg1低32 (kill/tkill)
          fJEQ(9, 13, 0),            //  7 →21 BLOCK
          fJEQ(6, 12, 0),            //  8 →21
          fJEQ(15, 11, 0),           //  9 →21
          fJEQ(4, 10, 0),            // 10 →21
          fJEQ(11, 9, 8),            // 11 →21; else→20 ALLOW
          fLD(0),                    // 12 nr reload
          fJEQ(NR_TGKILL, 0, 6),     // 13 tgkill→14; else→20 ALLOW
          fLD(32),                   // 14 sig=arg2低32 (tgkill)
          fJEQ(9, 5, 0),             // 15 →21
          fJEQ(6, 4, 0),             // 16 →21
          fJEQ(15, 3, 0),            // 17 →21
          fJEQ(4, 2, 0),             // 18 →21
          fJEQ(11, 1, 0),            // 19 →21; else→20
          fRET(ALLOWK),              // 20
          fRET(ERRK)                 // 21
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
      if (rSec !== 0) {
          var rSec2 = syscallFn(NR_SECC, 1, 0, fprog);   // TSYNC失败退化: 仅本线程+子线程继承
          L("[R17] seccomp no_new_privs=" + rNnp + " tsync=" + rSec + " fallback=" + rSec2);
      } else {
          L("[R17] seccomp TSYNC OK: kill/tgkill(sig 4/6/9/11/15)/exit_group 内核层已封(裸SVC也拦)");
      }
  } catch (e) { L("[R17_ERR] seccomp: " + e); }

  // ③ 存活时间线心跳(前80s) + 统一挂载轮询(R17b: 200ms快查knobs — 无dlopen钩, 盲窗压窄;
  //    commPass/reArmSsl 是重操作(枚举/遍历线程), 每3 tick=600ms 跑一次)
  var HB = 0;
  var TICK = 0;
  var hbTimer = setInterval(function() {
      HB++;
      L("[R17_HB] t+" + (HB * 2) + "s keyexpB=" + STAT.keyexpB + " cfb=" + STAT.cfb + " blk=" + STAT.blk +
        " sslwire=" + STAT.sslwire + " tick=" + TICK);
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
  // R17: 挂载轮询 — R16 心跳已证 JS 定时器活着(R10/11 "定时器饿死"实为进程早死误判),
  //   不再钩 dlopen(壳CRC检测触发器)。R17b: 200ms 快查 libknobs.so(出现→立即挂钩, 盲窗压窄),
  //   commPass/reArmSsl 每 3 tick(600ms); 窗口 360s(覆盖 Phase D 流量窗)。
  hookKnobs();   // 立即试(attach模式兼容)
  var armTimer = setInterval(function() {
      TICK++;
      try { if (!KNOBS_HOOKED) hookKnobs(); } catch (e) {}
      if (TICK % 3 === 0) {
          try { commPass("t" + TICK); } catch (e) {}
          try { reArmSsl(); } catch (e) {}
      }
      if (TICK >= 1800) clearInterval(armTimer);   // 200ms×1800 = 360s 采集窗
  }, 200);

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
      // R18: 只挂非系统路径的 libssl(壳解包后的 app 自带 TLS 库, 出现于 unpack 之后)。
      //   R17b 教训(致命): 名字过滤 "libssl.so" 连 /system/lib64/libssl.so(boot 期已在内存)也匹配,
      //   [R17] SSL_write armed @ .../system/lib64/libssl.so 在壳武装前就打了系统库代码补丁 —
      //   这是 R14~R17b 所有被检测轮次里恒存的唯一 boot 期内联钩(R12 scanonly 零钩=唯一干净对照)。
      //   系统 libssl 概不碰(MITM 已是 wire 对照来源, 进程内 SSL 捕获纯冗余)。
      try {
          Process.enumerateModules().forEach(function(m) {
              if (m.name !== "libssl.so") return;
              if (/^\/(system|apex|vendor|product)\//.test(m.path)) return;   // 系统库=禁区
              var p = Module.findExportByName(m.path, "SSL_write");
              if (!p || SSL_ARMED_ADDRS[p.toString()]) return;
              SSL_ARMED_ADDRS[p.toString()] = 1;
              Interceptor.attach(p, {
                  onEnter: function(args) { feedSsl(args[0], args[1], args[2].toInt32()); }
              });
              L("[R18] SSL_write armed @ " + p + " (" + m.path + ")");
          });
      } catch (e) {}
  }
  try { reArmSsl(); } catch (e) { L("[E] reArmSsl: " + e); }


      L("[READY] r1 keyhunt MIN armed (R18 真零内联钩: 系统libssl禁碰+seccomp) " + Date.now());
  } catch (e) { R1KEY({ ev: "boot_error", msg: String(e), stack: String(e && e.stack || "").slice(0, 400) }); }
}, 0);
