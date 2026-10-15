// hook_r1_keyhunt_v2.js — r1 密钥攻坚第二轮采集 (2026-10-15)
//
// 第一轮(run 38712019406)硬事实 → 本轮设计依据:
//   - 642 keyexp 全是 SETA(StringArmor 字符串解密噪声); SETB keyexp/CFB/CTR/CBC/GEN_ENC 全 0 命中
//   - dlsym("knobs*") 0 命中; .bss 192B 恒零
//   - Java 层 okhttp Request$Builder.build / KI.intercept / NativeWrapper 全 0 事件
//     而 mitm 同窗看到 r1 wire ×8 (frida 已 attach) ⇒ r1 请求构建+发送+r 加密整体绕开
//     被 hook 的 Java okhttp 面与 libknobs 导出模式包装器 → 在 360 VMP(libjiagu_vip) 内部完成
//   - uh.j Timer 首次 delay=0 → r 构建可能发生在进程头几秒 (守护 attach≈T+13s 会漏) → 配套 workflow 改快 attach
//
// 本轮采集面 (嫌疑排序):
//   a. VMP Java 边界: QDRequestAddKnobsInterceptor$Companion 全部 native 方法(reportR1/
//      reportGetKnobsEnvInfo/getPrefKnobsKey/saveKnobsEnvInfo/search(JSONObject)/checkKnobsUrl/
//      saveKnobsEnvInfo$lambda-2) + 外壳静态 native(judian/search/cihai/b/a) + $intercept$1.invoke(sora头)
//      + com.yuewen.fock.Fock.lock/sign + uh.j.e/f(envJSON 分发点) + StringArmor.d(装甲词典)
//   b. pref/文件写入: getSharedPreferences 名字观测 + SharedPreferencesImpl$EditorImpl.putString
//      (knobs 相关文件全量 / 任何 ≥400B 大值=r/sora 缓存形状) + native openat/write 对
//      /data/data/com.qidian.QDReader 首次写入内容捕获 (VMP 走 native 直写也能抓到)
//   c. 内存扫描: SSL_write 拿到 r1 wire(含 i/r b64) 后 Memory.scan:
//      r 原始密文字节 / i 原始密文字节 / i[0:24] 全局不变量(21711a9a…, 跨安装恒定→随时可定位 i buffer)
//      / 明文特征("o16","o36","qimei","runMode","guid=","obs_","eth0") → VMP 解密后明文窗口
//   c2. AES 轮密钥调度全内存扫描(schedScan): VMP 若自带 cipher, 扩展调度必在可写内存中
//      (结构校验 w[i]=w[i-nk]^w[i-1] / ^SubWord(RotWord)^Rcon, 假阳性≈2^-96) → sched[0:16]=原始key
//      + AES SBOX/Te0 常量扫描(sboxScan)定位一切 AES 实现(含 VMP 解密后的私有副本)
//      + mmap/mprotect PROT_EXEC 匿名区观测(VMP 代码解密时刻)
//   d. (pt,ct) oracle 素材: envjson/sora/sslwire/memscan 事件全部结构化落 log,
//      离线 ci/r1_gen.py harvest 做 keystream=pt^ct + AES-ECB(ct[j-1],K)==ks[j] 候选钥验证
//   e. libknobs 补全: v1 全部点位保留 + SetB 块级原语(0x136f0/0x13064/0x12e0c — 若 VMP 经
//      libknobs 内部块函数手搓 CFB, 这里必炸; SetA 块原语 0x10b28=StringArmor 热路径不挂防洪)
//      + canary 自检直调(一次性 16B 合成向量): 证明 Interceptor 存活 → 0命中=硬结论而非假阴性
//
// arm64 偏移 (q480 libknobs.so md5=267448d26c43efb6cfddf269d14f865b, 本地 readelf 复核):
//   SETA_KEYEXP=0x103e0 SETB_KEYEXP=0x126c4 GEN_ENCRYPT=0x1201c CBC=0x13db4
//   CFB=0x140ac CFB_NEON=0x14188 CTR=0x1427c BSS192=0x3159c
//   SETB_BLK=0x136f0(knobs_61087493) SETB_BLKENC=0x13064(knobs_71564283) SETB_BLKDEC=0x12e0c(knobs_87035146)
//   SETA_CBC=0x11ac8(knobs_54352333) STRARMOR=0x12460(knobs_67456344) LK=0xfd10 MW=0xfff0
//   块原语 arm64 反汇编: x0=ctx(ldr [x0,#8]=schedPtr), x1=in16 → 输出疑 in-place/x2, 原始dump+onLeave回读双保险
// arm32 对照: 0x9fb0/0xbb80/0xb690/0xce68/0xd07c/0xd118/0xd1cc/0x2112c/0xc81c/0xc210/0xc020/0xb290/0x??(armor)
//
// 输出纪律: 结构化行 [R1KEY] {json} (ev 字段区分), ci/r1_gen.py harvest 解析;
//   完整材料只落 collect.log artifact; 本文件不含任何 secrets 值 (PUBLIC repo 纪律)。

var STAT = { keyexpA: 0, keyexpB: 0, cfb: 0, cfbneon: 0, ctr: 0, cbc: 0, genenc: 0,
             blk: 0, bss: 0, dlsym: 0, canary: 0,
             vmp: 0, sora: 0, envjson: 0, armor: 0, pref: 0, filewrite: 0,
             sslwire: 0, memscan: 0, schedscan: 0, sboxhit: 0, execregion: 0, r1req: 0, knw: 0 };
var SHIELD = { exit: 0, kill: 0, maps: 0, comm: 0, jexit: 0 };
var LIMITS = { keyexpA_dump: 40, blk_dump: 4000, memscan_hits: 40, sched_uniq: 96,
               sbox_uniq: 64, armor_uniq: 400, filewrite: 240, sslwire: 240, execregion: 80 };
var SEEN = { armor: {}, sched: {}, sbox: {}, memscan: {}, bss: {} };

function L(s) { console.log(s); }
function R1KEY(obj) { try { L("[R1KEY] " + JSON.stringify(obj)); } catch (e) { L("[R1KEY_ERR] " + e); } }

// R3自诊断: 脚本加载标记(区分"没装上"vs"装上没命中") + 未捕获异常上报
R1KEY({ ev: "script_loaded", t: Date.now(), frida: (typeof Frida !== "undefined" ? Frida.version : "?"), pid: Process.id, abi: Process.arch });
if (typeof process !== "undefined" && process.setExceptionHandler) {
  process.setExceptionHandler(function (d) { try { R1KEY({ ev: "native_exception", addr: String(d.address), type: d.type }); } catch (e) {} return false; });
}

// R4修正(2026-10-16): 第三轮实锤 script_loaded 打出后顶层求值>10s → "Failed to load script: timeout" ×4,
// hook 从未生效(App 存活35-72s白活)。疑点=顶层同步安装过重(openat风暴期JS回调拖垮求值)。
// 修法: 全部安装推迟到下一tick, 加载握手毫秒级完成; boot 自带错误上报。
setTimeout(function BOOT() {
  try {
  // ═══ 0° 反检测盾 (cecelia v2 / keyhunt v1 同款, 最先执行) + app数据文件 fd 观测 ═══
  var FD_PATH = {};   // fd → path (仅 /data/data|user/0/com.qidian.QDReader 下)
  var FD_DONE = {};   // fd → 已捕获首次写入
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
          function isAppData(p) {
              return p && (p.indexOf("/data/data/com.qidian.QDReader") === 0 ||
                           p.indexOf("/data/user/0/com.qidian.QDReader") === 0);
          }
          function pathHook(idx) {
              return {
                  onEnter: function(args) {
                      if (INREFRESH) return;
                      try {
                          var p = args[idx].readCString();
                          if (p === null) return;
                          if (p.indexOf("/proc/") === 0) {
                              if (p.indexOf("/maps") >= 0 || p.indexOf("/smaps") >= 0) {
                                  args[idx] = FAKE_MAPS; SHIELD.maps++;
                              } else if (p.indexOf("/comm") >= 0) {
                                  args[idx] = FAKE_COMM; SHIELD.comm++;
                              }
                              return;
                          }
                          if (isAppData(p)) this._appPath = p;   // 采集点b: fd→path 记录
                      } catch (e) {}
                  },
                  onLeave: function(ret) {
                      try {
                          if (this._appPath) {
                              var fd = ret.toInt32();
                              if (fd >= 0) FD_PATH[fd] = this._appPath;
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
          // 采集点b(native兜底): app数据文件的首次写入内容捕获 (VMP native 直写 pref/缓存也能抓)
          [["write", 1, 2], ["pwrite64", 1, 2]].forEach(function(spec) {
              try {
                  var p = Module.findExportByName(null, spec[0]);
                  if (!p) return;
                  Interceptor.attach(p, {
                      onEnter: function(args) {
                          try {
                              var fd = args[0].toInt32();
                              var path = FD_PATH[fd];
                              if (!path || FD_DONE[fd]) return;
                              if (/\.(png|jpg|ttf|otf|xlog|so)$/.test(path)) return;
                              var n = args[spec[2]].toInt32();
                              if (n <= 0 || n > 1048576) return;
                              FD_DONE[fd] = 1; STAT.filewrite++;
                              if (STAT.filewrite > LIMITS.filewrite) return;
                              R1KEY({ ev: "filewrite", fd: fd, path: path, len: n,
                                      head_hex: hexlify(args[spec[1]], Math.min(n, 8192)), t: Date.now() });
                          } catch (e) {}
                      }
                  });
              } catch (e) {}
          });
          L("[SHIELD] armed (exit/kill/procfs/fdwatch) pid=" + mypid);
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

  // ═══ AES 表 (JS侧, 供 schedScan 结构校验 / sboxScan 常量) ═══
  var SBOX = (function() {
      var p = 0, q = 0, sb = new Uint8Array(256);
      for (;;) {
          p = p ^ ((p << 1) & 0xff) ^ ((p & 0x80) ? 0x1b : 0);
          q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;
          if (q & 0x80) q ^= 0x09;
          var x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
          sb[p] = (x ^ 0x63) & 0xff;
          if (p === 1) break;
      }
      sb[0] = 0x63;
      return sb;
  })();
  var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab];
  // i[0:24] 全局不变量 (r1_ir_format.md §1.2: 两设备两安装全同) — 内存定位 i buffer 的常量针
  var I_PREFIX_HEX = "21711a9a1a4def2eeb5a4b0c5b4bd79835f6f676b79db236";

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

  // ═══ ① dlsym 观测 (放宽: 记录全部符号名, 不只 knobs 前缀 — 第一轮0命中, 需排除过滤误伤) ═══
  try {
      var pDlsym = Module.findExportByName(null, "dlsym");
      if (pDlsym) {
          var DLSYM_SEEN = {};
          Interceptor.attach(pDlsym, {
              onEnter: function(args) { this._n = args[1]; },
              onLeave: function(ret) {
                  try {
                      var nm = this._n.readCString();
                      if (!nm || DLSYM_SEEN[nm]) return;
                      DLSYM_SEEN[nm] = 1;
                      var m = Process.findModuleByAddress(ret);
                      if (nm.indexOf("knobs") === 0 || (m && /knobs|jiagu|fock|nib/.test(m.name))) {
                          STAT.dlsym++;
                          R1KEY({ ev: "dlsym", sym: nm, ret: ret.toString(),
                                  mod: m ? m.name + "+0x" + ret.sub(m.base).toString(16) : null });
                      }
                  } catch (e) {}
              }
          });
          L("[+] dlsym watcher armed (放宽过滤)");
      }
  } catch (e) { L("[E] dlsym: " + e); }

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
      }, 3000);
  }
  var knobsPoll = setInterval(function() {
      hookKnobs();
      if (KNOBS_HOOKED) clearInterval(knobsPoll);
  }, 500);
  hookKnobs();

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
              setTimeout(function() { try { doMemScan("post_r1"); } catch (e) {} }, 3500);
              setTimeout(function() { try { schedScan("post_r1"); } catch (e) {} }, 4500);
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
  try {
      var pSslWrite = Module.findExportByName("libssl.so", "SSL_write");
      if (pSslWrite) {
          Interceptor.attach(pSslWrite, {
              onEnter: function(args) { feedSsl(args[0], args[1], args[2].toInt32()); }
          });
          L("[+] SSL_write hooked (r1/sora wire 捕获 + memscan 触发器)");
      } else {
          L("[E] SSL_write 未找到 — r1 wire 触发器缺失(靠定时扫描兜底)");
      }
  } catch (e) { L("[E] SSL_write: " + e); }

  // ═══ ④ 采集点c: 内存扫描 (明文特征 + i[0:24]常量针 + 本次安装 r/i 密文针) ═══
  function scanNeedles(tag, needles) {
      var ranges = Process.enumerateRanges("r--").concat(Process.enumerateRanges("rw-"));
      var nHit = 0;
      needles.forEach(function(nd) {
          if (nHit >= LIMITS.memscan_hits * needles.length) return;
          var pat = nd.pat, label = nd.label, ctxBefore = nd.ctx || 96;
          ranges.forEach(function(rg) {
              if (rg.size > 268435456 || rg.size < 16) return;
              if (rg.file && rg.file.path && /libart|\.oat|\.vdex|\.art|boot/.test(rg.file.path)) return;
              try {
                  Memory.scanSync(rg.base, rg.size, pat).forEach(function(hit) {
                      var dk = label + "@" + rg.base.toString() + "+" + hit.address.sub(rg.base).toString(16);
                      if (SEEN.memscan[dk]) return;
                      SEEN.memscan[dk] = 1;
                      nHit++; STAT.memscan++;
                      if (STAT.memscan > 600) return;
                      var lo = rg.base;
                      try { lo = hit.address.sub(ctxBefore); if (lo.compare(rg.base) < 0) lo = rg.base; } catch (e) { lo = rg.base; }
                      var ctxHex = hexlify(lo, ctxBefore + 64);
                      var fwdHex = hexlify(hit.address, 160);
                      R1KEY({ ev: "memscan", tag: tag, needle: label,
                              range: rg.file && rg.file.path ? rg.file.path : "anon",
                              prot: rg.protection, off: "0x" + hit.address.sub(rg.base).toString(16),
                              base: rg.base.toString(),
                              ctx_before: ctxHex, at_fwd: fwdHex, t: Date.now() });
                  });
              } catch (e) {}
          });
      });
      L("[MEMSCAN] tag=" + tag + " 新命中=" + nHit);
  }
  function doMemScan(tag) {
      var needles = [
          { label: "i_prefix24_const", pat: I_PREFIX_HEX.replace(/(..)/g, "$1 ").trim() },
          { label: "o16_eq", pat: "6f 31 36 3d", ctx: 64 },          // "o16=" 表单式
          { label: "o16_json", pat: "22 6f 31 36 22", ctx: 64 },     // "o16" JSON式
          { label: "o36_eq", pat: "6f 33 36 3d", ctx: 64 },
          { label: "o36_json", pat: "22 6f 33 36 22", ctx: 64 },
          { label: "qimei", pat: "71 69 6d 65 69", ctx: 64 },
          { label: "runMode", pat: "72 75 6e 4d 6f 64 65", ctx: 64 },
          { label: "obs_", pat: "6f 62 73 5f", ctx: 64 },
          { label: "eth0", pat: "65 74 68 30", ctx: 64 },
          { label: "guid_eq", pat: "67 75 69 64 3d", ctx: 64 }
      ];
      if (LAST_R1_WIRE) {
          if (LAST_R1_WIRE.r) needles.push({ label: "r_ct_wire", pat: patFromBytes(LAST_R1_WIRE.r.slice(0, 32)) });
          if (LAST_R1_WIRE.i) needles.push({ label: "i_ct_wire", pat: patFromBytes(LAST_R1_WIRE.i.slice(0, 24)) });
      }
      scanNeedles(tag, needles);
  }

  // ═══ ⑤ 采集点c2: AES 扩展调度全内存扫描 (VMP私有cipher的钥匙必留痕) ═══
  function schedScan(tag) {
      var now = Date.now();
      if (now - LAST_SCHEDSCAN < 45000) { L("[SCHEDSCAN] 限速跳过 tag=" + tag); return; }
      LAST_SCHEDSCAN = now;
      var t0 = now, nFound = 0, nRanges = 0, bytesScanned = 0;
      var ranges = Process.enumerateRanges("rw-");
      ranges.forEach(function(rg) {
          if (rg.size > 67108864 || rg.size < 176) return;   // >64MB 跳过(单遍≤~8s, 防JS线程长阻塞)
          if (rg.file && rg.file.path && /\.(ttf|otf|png|jpg|webp|mp4|zip|apk)$/.test(rg.file.path)) return;
          nRanges++;
          var u8;
          try { u8 = new Uint8Array(Memory.readByteArray(rg.base, rg.size)); } catch (e) { return; }
          bytesScanned += u8.length;
          var end = u8.length - 240;
          for (var off = 0; off < end; off += 4) {
              var is128 = schedValidAt(u8, off, 4);
              var nk = is128 ? 4 : (schedValidAt(u8, off, 8) ? 8 : 0);
              if (!nk) continue;
              var total = 4 * (nk + 7) * 4;
              var schedHex = hexlifyBytes(u8.subarray(off, off + total));
              if (SEEN.sched[schedHex]) continue;
              SEEN.sched[schedHex] = 1;
              nFound++; STAT.schedscan++;
              if (nFound > LIMITS.sched_uniq) return;
              R1KEY({ ev: "schedscan", tag: tag, bits: nk * 32,
                      key: schedHex.substring(0, nk * 8),      // sched[0:keylen]=原始key
                      sched: schedHex,
                      range: rg.file && rg.file.path ? rg.file.path : "anon",
                      base: rg.base.toString(), off: "0x" + off.toString(16), t: Date.now() });
          }
      });
      L("[SCHEDSCAN] tag=" + tag + " ranges=" + nRanges + " MB=" + Math.round(bytesScanned / 1048576) +
        " found=" + nFound + " cost=" + (Date.now() - t0) + "ms");
  }

  // ═══ ⑥ AES 常量表扫描 (定位一切 AES 实现, 含 VMP 解密后的私有副本) ═══
  var SBOX_PAT = "63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0";
  var TE0_PAT = "c6 63 63 a5 f8 7c 7c 84 ee 77 7d c9 f4 7b 7b 8d d2 6e 6e fc b6 5b 5b ed 2a 15 15 3f 02 01 01 03";
  function sboxScan(tag) {
      var ranges = Process.enumerateRanges("r--").concat(Process.enumerateRanges("r-x"));
      var n = 0;
      [["sbox", SBOX_PAT], ["te0", TE0_PAT]].forEach(function(spec) {
          ranges.forEach(function(rg) {
              if (rg.size > 268435456) return;
              if (n >= LIMITS.sbox_uniq) return;
              try {
                  Memory.scanSync(rg.base, rg.size, spec[1]).forEach(function(hit) {
                      var m = Process.findModuleByAddress(hit.address);
                      var mn = m ? m.name + "+0x" + hit.address.sub(m.base).toString(16) : "anon";
                      var dk = spec[0] + "@" + mn;
                      if (SEEN.sbox[dk]) return;
                      SEEN.sbox[dk] = 1;
                      n++; STAT.sboxhit++;
                      R1KEY({ ev: "sboxhit", kind: spec[0], where: mn, base: rg.base.toString(),
                              prot: rg.protection,
                              file: rg.file && rg.file.path ? rg.file.path : null, t: Date.now() });
                  });
              } catch (e) {}
          });
      });
      L("[SBOXSCAN] tag=" + tag + " hits=" + n);
  }

  // ═══ ⑦ mmap/mprotect PROT_EXEC 匿名区观测 (VMP 代码解密时刻) ═══
  try {
      var PROT_EXEC = 4;
      var pMmap = Module.findExportByName(null, "mmap");
      if (pMmap) {
          Interceptor.attach(pMmap, {
              onEnter: function(args) { this.prot = args[2].toInt32(); this.len = args[1].toInt32(); },
              onLeave: function(ret) {
                  try {
                      if ((this.prot & PROT_EXEC) && this.len >= 4096 && this.len <= 8388608 &&
                          ret.compare(ptr(0)) !== 0 && STAT.execregion < LIMITS.execregion) {
                          var m = Process.findModuleByAddress(ret);
                          if (m) return;   // 常规 so 加载不记
                          STAT.execregion++;
                          R1KEY({ ev: "execregion", api: "mmap", addr: ret.toString(),
                                  len: this.len, prot: this.prot, t: Date.now() });
                      }
                  } catch (e) {}
              }
          });
      }
      var pMprotect = Module.findExportByName(null, "mprotect");
      if (pMprotect) {
          Interceptor.attach(pMprotect, {
              onEnter: function(args) {
                  try {
                      var prot = args[2].toInt32();
                      if ((prot & PROT_EXEC) && STAT.execregion < LIMITS.execregion) {
                          var m = Process.findModuleByAddress(args[0]);
                          if (m) return;
                          STAT.execregion++;
                          R1KEY({ ev: "execregion", api: "mprotect", addr: args[0].toString(),
                                  len: args[1].toInt32(), prot: prot, t: Date.now() });
                      }
                  } catch (e) {}
              }
          });
      }
      L("[+] mmap/mprotect PROT_EXEC 观测 armed");
  } catch (e) { L("[E] execregion: " + e); }

  // ═══ ⑧ Java 层 ═══
  Java.perform(function() {
      // Java级自杀拦截 (v1同款)
      try {
          var Sys = Java.use("java.lang.System");
          Sys.exit.implementation = function(c) { SHIELD.jexit++; L("[SHIELD] blocked System.exit(" + c + ")"); };
          var Rt = Java.use("java.lang.Runtime");
          Rt.exit.implementation = function(c) { SHIELD.jexit++; L("[SHIELD] blocked Runtime.exit(" + c + ")"); };
          var AOProc = Java.use("android.os.Process");
          AOProc.killProcess.implementation = function(pid) { SHIELD.jexit++; L("[SHIELD] blocked killProcess(" + pid + ")"); };
          L("[SHIELD] java exit hooks armed");
      } catch (e) { L("[SHIELD_JAVA_ERR] " + e); }

      function callOrig(ov, self, argsObj) {
          switch (argsObj.length) {
              case 0: return ov.call(self);
              case 1: return ov.call(self, argsObj[0]);
              case 2: return ov.call(self, argsObj[0], argsObj[1]);
              case 3: return ov.call(self, argsObj[0], argsObj[1], argsObj[2]);
              default: return ov.call(self, argsObj[0], argsObj[1], argsObj[2], argsObj[3]);
          }
      }
      function argSummary(arguments_) {
          var out = [];
          for (var ai = 0; ai < arguments_.length; ai++) {
              var a = arguments_[ai];
              var s = (a === null || a === undefined) ? "null" : String(a);
              out.push(s.length > 512 ? s.substring(0, 512) + "…(" + s.length + ")" : s);
          }
          return out;
      }
      // 通用 VMP 边界包装器: 进/出全记 (native stub 方法 frida 可 wrap — cecelia/v1 实证)
      function wrapVmp(cls, methodName, tag) {
          try {
              var m = cls[methodName];
              if (!m) { L("[E] vmp方法缺失 " + tag + "." + methodName); return; }
              m.overloads.forEach(function(ov) {
                  ov.implementation = function() {
                      var t0 = Date.now();
                      var args = argSummary(arguments);
                      var ret = null, err = null;
                      try { ret = callOrig(ov, this, arguments); }
                      catch (e) { err = String(e).substring(0, 200); throw e; }
                      finally {
                          try {
                              STAT.vmp++;
                              var rs = (ret === null || ret === undefined) ? null : String(ret);
                              R1KEY({ ev: "vmp", cls: tag, m: methodName, args: args,
                                      ret: rs !== null && rs.length > 8192 ? rs.substring(0, 8192) + "…(" + rs.length + ")" : rs,
                                      ret_is_null: ret === null, err: err,
                                      ms: Date.now() - t0, t: t0 });
                              // uh.j.e/f(JSONObject) 入参 = envJSON 全量 → 专事件(采集点a-5主产出)
                              if (tag === "uh.j" && args.length > 0 && args[0] && args[0].charAt(0) === "{") {
                                  STAT.envjson++;
                                  var ej = args[0];
                                  R1KEY({ ev: "envjson", via: "uh.j." + methodName,
                                          len: ej.length,
                                          json: ej.length > 16384 ? ej.substring(0, 16384) : ej, t: t0 });
                              }
                          } catch (e2) {}
                      }
                      return ret;
                  };
              });
              L("[+] vmp hooked " + tag + "." + methodName);
          } catch (e) { L("[E] vmp " + tag + "." + methodName + ": " + e); }
      }

      // 采集点a-1: QDRequestAddKnobsInterceptor$Companion (reportR1 触发链的 VMP stub 入口全集)
      try {
          var COMP = Java.use("com.qidian.QDReader.component.retrofit.QDRequestAddKnobsInterceptor$Companion");
          ["reportR1", "reportGetKnobsEnvInfo", "getPrefKnobsKey", "saveKnobsEnvInfo", "search",
           "checkKnobsUrl", "saveKnobsEnvInfo$lambda-2"].forEach(function(mn) {
              wrapVmp(COMP, mn, "KI$Companion");
          });
      } catch (e) { L("[E] KI$Companion: " + e); }

      // 采集点a-2: 外壳静态 native (judian=boolean门 / search()=String 疑缓存r/sora / cihai(String) / b())
      try {
          var KI = Java.use("com.qidian.QDReader.component.retrofit.QDRequestAddKnobsInterceptor");
          ["judian", "search", "cihai", "b"].forEach(function(mn) { wrapVmp(KI, mn, "KI"); });
          // intercept 保留 v1 wire 对照 (第一轮0命中, 留作旁证)
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
          L("[+] KI.intercept hooked (旁证保留)");
      } catch (e) { L("[E] KI: " + e); }

      // 采集点a-3: sora 头注入 lambda ($intercept$1.invoke(String) → addHeader("sora", v))
      try {
          var L1 = Java.use("com.qidian.QDReader.component.retrofit.QDRequestAddKnobsInterceptor$intercept$1");
          L1.invoke.overloads.forEach(function(ov) {
              ov.implementation = function() {
                  var ret = callOrig(ov, this, arguments);
                  try {
                      STAT.sora++;
                      var v = arguments[0] === null ? null : String(arguments[0]);
                      R1KEY({ ev: "sora_java", via: "intercept$1.invoke",
                              value: v && v.length > 8192 ? v.substring(0, 8192) : v, t: Date.now() });
                  } catch (e) {}
                  return ret;
              };
          });
          L("[+] intercept$1.invoke hooked (sora头)");
      } catch (e) { L("[E] intercept$1: " + e); }

      // 采集点a-4: Fock.lock(envJSON)=sora — lk信封已100%破(knobs_toolkit), 入参即 envJSON 明文
      try {
          var FOCK = Java.use("com.yuewen.fock.Fock");
          ["lock", "sign"].forEach(function(mn) { wrapVmp(FOCK, mn, "Fock"); });
      } catch (e) { L("[E] Fock: " + e); }

      // 采集点a-5: uh.j envJSON 构建/分发 (b=构建, e/f=分发 JSONObject)
      try {
          var UHJ = Java.use("uh.j");
          ["e", "f"].forEach(function(mn) { wrapVmp(UHJ, mn, "uh.j"); });
      } catch (e) { L("[E] uh.j: " + e); }

      // 采集点a-6: StringArmor.d 装甲→明文词典 (envJSON 字段名/o16/o36 语义; 去重限额)
      try {
          var SA = Java.use("com.yuewen.knobs.StringArmor");
          SA.d.overloads.forEach(function(ov) {
              ov.implementation = function() {
                  var ret = callOrig(ov, this, arguments);
                  try {
                      var inS = arguments[0] === null ? "" : String(arguments[0]);
                      var outS = ret === null ? "" : String(ret);
                      var dk = sha16(inS);
                      if (!SEEN.armor[dk] && STAT.armor < LIMITS.armor_uniq) {
                          SEEN.armor[dk] = 1; STAT.armor++;
                          R1KEY({ ev: "armor", in_sha16: dk,
                                  in: inS.length > 160 ? inS.substring(0, 160) : inS,
                                  out: outS.length > 240 ? outS.substring(0, 240) + "…(" + outS.length + ")" : outS });
                      }
                  } catch (e) {}
                  return ret;
              };
          });
          L("[+] StringArmor.d hooked (词典采集)");
      } catch (e) { L("[E] StringArmor: " + e); }

      // 采集点b-1: getSharedPreferences 名字观测 + EditorImpl.putString 大值/knobs文件捕获
      try {
          var CW = Java.use("android.content.ContextWrapper");
          CW.getSharedPreferences.overload("java.lang.String", "int").implementation = function(name, mode) {
              var sp = this.getSharedPreferences(name, mode);
              try {
                  if (name && /knob|KNOB|QV1|fock|leic|s_d/i.test(String(name)))
                      R1KEY({ ev: "pref_open", name: String(name), t: Date.now() });
              } catch (e) {}
              return sp;
          };
          L("[+] getSharedPreferences hooked");
      } catch (e) { L("[E] getSharedPreferences: " + e); }
      try {
          var ED = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
          ED.putString.implementation = function(k, v) {
              try {
                  var file = "?";
                  try {
                      var impl = this.this$0.value;   // EditorImpl → SharedPreferencesImpl
                      var fObj = impl.class.getDeclaredField("mFile");
                      fObj.setAccessible(true);
                      file = String(fObj.get(impl));
                  } catch (e) {}
                  var vs = v === null ? "" : String(v);
                  var interesting = /knob|KNOB|QV1/i.test(file) || vs.length >= 400;
                  if (interesting) {
                      STAT.pref++;
                      if (STAT.pref <= 400) {
                          R1KEY({ ev: "pref_write", file: file, key: String(k), vlen: vs.length,
                                  value: vs.length > 16384 ? vs.substring(0, 16384) + "…(" + vs.length + ")" : vs,
                                  t: Date.now() });
                      }
                  }
              } catch (e) {}
              return this.putString(k, v);
          };
          L("[+] EditorImpl.putString hooked");
      } catch (e) { L("[E] putString: " + e); }

      // NativeWrapper 全量 (v1同款保留; 第一轮0命中, 留作旁证)
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
                              STAT.knw++;
                              R1KEY({ ev: "knw", m: mn, args: argSummary(arguments).map(function(s) {
                                  return s.length > 120 ? s.substring(0, 120) + "…(" + s.length + ")" : s; }),
                                      ret: ret === null ? "null" : String(ret).substring(0, 200), t: t0 });
                          } catch (e) {}
                          return ret;
                      };
                  });
              } catch (e) {}
          });
          L("[+] NativeWrapper hooked (" + Object.keys(names).length + " methods)");
      } catch (e) { L("[E] NativeWrapper: " + e); }

      // okhttp build (v1同款保留; 第一轮0命中, 留作旁证)
      try {
          var JBuffer = Java.use("okio.Buffer");
          var RQB = Java.use("okhttp3.Request$Builder");
          RQB.build.implementation = function() {
              var req = this.build();
              try {
                  var url = String(req.url().toString());
                  if (url.indexOf("/client/r1") >= 0 || url.indexOf("deeplink") >= 0) {
                      STAT.r1req++;
                      var body = null;
                      try {
                          var buf = JBuffer.$new();
                          req.body().writeTo(buf);
                          body = buf.readUtf8();
                          buf.close();
                          if (body.length > 6144) body = body.substring(0, 6144);
                      } catch (e2) { body = "<unreadable>"; }
                      R1KEY({ ev: "wire", url: url.substring(0, 160), body: body, t: Date.now() });
                  }
              } catch (e) {}
              return req;
          };
          L("[+] okhttp build hooked (旁证保留)");
      } catch (e) { L("[E] okhttp: " + e); }

      // ═══ 定时采集编排 ═══
      var PHASE = 0;
      setInterval(function() {
          PHASE++;
          try {
              if (PHASE === 4) { sboxScan("t60"); doMemScan("t60"); }          // T+60s: 常量表+明文针
              if (PHASE === 6) { schedScan("t90"); }                            // T+90s: 调度扫描
              if (PHASE === 20) { doMemScan("t300"); schedScan("t300"); }        // T+300s
              if (PHASE === 38) { doMemScan("t570"); schedScan("t570"); sboxScan("t570"); }  // 收尾
          } catch (e) { L("[SCAN_ERR] phase" + PHASE + " " + e); }
      }, 15000);

      setInterval(function() {
          L("[HB] kexpA=" + STAT.keyexpA + " kexpB=" + STAT.keyexpB + " cfb=" + STAT.cfb +
            " cfbneon=" + STAT.cfbneon + " ctr=" + STAT.ctr + " cbc=" + STAT.cbc + " genenc=" + STAT.genenc +
            " blk=" + STAT.blk + " bss≠0=" + Object.keys(SEEN.bss).length + " dlsym=" + STAT.dlsym +
            " canary=" + STAT.canary +
            " | vmp=" + STAT.vmp + " sora=" + STAT.sora + " envjson=" + STAT.envjson +
            " armor=" + STAT.armor + " pref=" + STAT.pref + " filewrite=" + STAT.filewrite +
            " | sslwire=" + STAT.sslwire + " memscan=" + STAT.memscan + " sched=" + STAT.schedscan +
            " sbox=" + STAT.sboxhit + " exec=" + STAT.execregion + " knw=" + STAT.knw +
            " hooked=" + KNOBS_HOOKED +
            " shield(exit=" + SHIELD.exit + ",kill=" + SHIELD.kill + ",maps=" + SHIELD.maps + ",jexit=" + SHIELD.jexit + ")");
      }, 15000);
      L("[READY] r1 keyhunt collection armed v2");
  });

  } catch (e) { R1KEY({ ev: "boot_error", msg: String(e), stack: String(e && e.stack || "").slice(0, 400) }); }
}, 0);