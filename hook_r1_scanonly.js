// hook_r1_scanonly.js — R7f 极简扫描器(不装任何hook; 只做全内存 AES key-schedule 快照)
// 背景(R7e时间对照): r1首波在旧attach(稳判T+8-11s)之前9.5-11.5s发出 → 首建窗=T+0~8s
//   → 首个pid立即attach本脚本(T+2-3s), 连续full快照(每次≈2.3s)覆盖 attach 后 0~25s。
//   不装hook=无"武装完成"事件+最小暴露面(R7d实证[READY]后App秒被杀)。
// 输出: [R1KEY] {ev:"schedscan",...} / [SNAP-DONE] / [SCANONLY-READY] — 与主脚本同格式(harvest兼容)
var STAT = { schedscan: 0 };
var LIMITS = { sched_uniq: 96 };
var SEEN = { sched: {} };
function L(x) { console.log(x); }
function R1KEY(o) { try { L("[R1KEY] " + JSON.stringify(o)); } catch (e) { L("[R1KEY_ERR] " + e); } }
function hexlify(p, n) { try { var b = new Uint8Array(Memory.readByteArray(p, n)); var t = ""; for (var i = 0; i < b.length; i++) t += ("0" + b[i].toString(16)).slice(-2); return t; } catch (e) { return "<bad>"; } }
function hexlifyBytes(u8) { var t = ""; for (var i = 0; i < u8.length; i++) t += ("0" + u8[i].toString(16)).slice(-2); return t; }
R1KEY({ ev: "scanonly_loaded", t: Date.now(), frida: (typeof Frida !== "undefined" ? Frida.version : "?"), pid: Process.id, abi: Process.arch });

var LAST_SCAN = { full: 0, vmp: 0, medium: 0 };

// R7c: CModule scan_sched — TinyCC 目标进程内编译; 直读内存无拷贝; 本地实测 ~168MB/s (JS版450ms/MB 的 ~85x)
//   三层字节快筛(第3层 `p[o+16]==p[o]^SB[p[o+13]]^1` 拒绝全零区击穿) + 全验; 含 AES-256 i%nk==4 分支
//   本地 frida 16.7.19 验证: 编译OK / 偏移0与123命中 / 全零与随机-1 / 16MB=95ms
var CM_SRC = `
static const unsigned char SB[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const unsigned char RC[15] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x00};

long scan_sched(const unsigned char *p, long n, int nk) {
    long o;
    long need = (long)(nk + 7) * 16;
    if (n < need) return -1;
    for (o = 0; o + need <= n; o += 1) {
        int i, b, ok;
        if ((p[o+20] ^ p[o+4] ^ p[o+16]) != 0) continue;
        if ((p[o+24] ^ p[o+8] ^ p[o+20]) != 0) continue;
        if (p[o+16] != (unsigned char)(p[o] ^ SB[p[o+13]] ^ 0x01)) continue;
        ok = 1;
        for (i = nk; i < (nk + 7) * 4; i++) {
            if (i % nk != 0) {
                if (nk > 6 && i % nk == 4) {
                    for (b = 0; b < 4; b++)
                        if (p[o + i*4 + b] != (unsigned char)(p[o + (i-nk)*4 + b] ^ SB[p[o + (i-1)*4 + b]])) { ok = 0; break; }
                } else {
                    for (b = 0; b < 4; b++)
                        if (p[o + i*4 + b] != (unsigned char)(p[o + (i-nk)*4 + b] ^ p[o + (i-1)*4 + b])) { ok = 0; break; }
                }
            } else {
                int k = i / nk;
                unsigned char t0 = (unsigned char)(SB[p[o + (i-1)*4 + 1]] ^ RC[k]);
                unsigned char t1 = SB[p[o + (i-1)*4 + 2]];
                unsigned char t2 = SB[p[o + (i-1)*4 + 3]];
                unsigned char t3 = SB[p[o + (i-1)*4 + 0]];
                if (p[o + i*4 + 0] != (unsigned char)(p[o + (i-nk)*4 + 0] ^ t0)) ok = 0;
                else if (p[o + i*4 + 1] != (unsigned char)(p[o + (i-nk)*4 + 1] ^ t1)) ok = 0;
                else if (p[o + i*4 + 2] != (unsigned char)(p[o + (i-nk)*4 + 2] ^ t2)) ok = 0;
                else if (p[o + i*4 + 3] != (unsigned char)(p[o + (i-nk)*4 + 3] ^ t3)) ok = 0;
            }
            if (!ok) break;
        }
        if (ok) return o;
    }
    return -1;
}
`;
var CMSCAN = { fn: null, err: null, cm: null };
function ensureCM() {
    if (CMSCAN.fn) return true;
    if (CMSCAN.err) return false;
    try {
        CMSCAN.cm = new CModule(CM_SRC);   // ★必须保持引用: 局部cm被GC → 代码页unmap → fn野指针=access violation
        CMSCAN.fn = new NativeFunction(CMSCAN.cm.scan_sched, 'long', ['pointer', 'long', 'int']);
        L("[+] CModule scan_sched ready");
        return true;
    } catch (e) { CMSCAN.err = String(e).slice(0, 200); L("[CM_ERR] " + CMSCAN.err); return false; }
}
var SBOX = new Uint8Array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]);
if (SBOX[0] !== 0x63 || SBOX[1] !== 0x7c || SBOX[255] !== 0x16) { R1KEY({ ev: "sbox_selftest_fail" }); }
var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab];
// i[0:24] 全局不变量 (r1_ir_format.md §1.2: 两设备两安装全同) — 内存定位 i buffer 的常量针
var I_PREFIX_HEX = "21711a9a1a4def2eeb5a4b0c5b4bd79835f6f676b79db236";

// R4修正(2026-10-16): 第三轮实锤 script_loaded 打出后顶层求值>10s → "Failed to load script: timeout" ×4,
// hook 从未生效(App 存活35-72s白活)。疑点=顶层同步安装过重(openat风暴期JS回调拖垮求值)。
// 修法: 全部安装推迟到下一tick, 加载握手毫秒级完成; boot 自带错误上报。

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


  function execNeighborhoodRanges() {
      var out = [];
      try {
          var f = new File("/proc/self/maps", "r");
          var txt = "";
          try { txt = f.readText(4194304); } catch (e1) { try { txt = String(f.readAll()); } catch (e2) {} }
          f.close();
          var execs = [], rws = [];
          txt.split("\n").forEach(function(line) {
              var m = line.match(/([0-9a-f]+)-([0-9a-f]+) (....)/);
              if (!m) return;
              var b = parseInt(m[1], 16), e = parseInt(m[2], 16), perm = m[3];
              if (perm === "r-xp" && line.indexOf("/") < 0) execs.push([b, e]);
              if (perm === "rw-p") rws.push([b, e]);
          });
          var seen = {};
          execs.forEach(function(ex) {
              rws.forEach(function(rw) {
                  if (rw[0] <= ex[1] + 33554432 && rw[1] >= ex[0] - 33554432) {
                      var k = "" + rw[0] + "_" + rw[1];
                      if (seen[k]) return; seen[k] = 1;
                      out.push({ base: ptr(rw[0]), size: rw[1] - rw[0], lbl: "exec_nbhd" });
                  }
              });
          });
      } catch (e) {}
      return out;
  }
  function vmpRangeList() {
      var out = [];
      try {
          Process.enumerateModules().forEach(function(m) {
              if (/jiagu|shell|fock|knobs|nib|ostar|qidian/i.test(m.name)) {
                  try { m.enumerateRanges("rw-").forEach(function(rg) { out.push({ base: rg.base, size: rg.size, lbl: m.name }); }); } catch (e) {}
              }
          });
      } catch (e) {}
      execNeighborhoodRanges().forEach(function(rg) { out.push(rg); });
      return out;
  }

  function scanRangeForSched(base, size, tag, lbl) {
      if (size < 176 || size > 268435456) return 0;
      var nFound = 0;
      if (ensureCM()) {                                   // R7c: C 路径(直读内存, 无拷贝)
          var fn = CMSCAN.fn;
          var CH = 16777216;
          var o0 = 0;
          while (o0 < size) {
              var cs = Math.min(CH, size - o0);
              if (cs < 176) break;
              try { Memory.readByteArray(base.add(o0), 16); } catch (e0) { o0 += CH; continue; }          // R7e 块级探针
              try { Memory.readByteArray(base.add(o0 + cs - 16), 16); } catch (e0b) { o0 += CH; continue; }
              var sub = 0;
              while (sub + 176 <= cs) {
                  var off = fn(base.add(o0 + sub), cs - sub, 4);
                  if (off < 0) break;
                  var abs = o0 + sub + off;
                  nFound++; STAT.schedscan++;
                  if (nFound > LIMITS.sched_uniq) return nFound;
                  var sh = "";
                  try { sh = hexlify(base.add(abs), 176); } catch (e) { sh = "<unread>"; }
                  if (!SEEN.sched[sh]) {
                      SEEN.sched[sh] = 1;
                      R1KEY({ ev: "schedscan", tag: tag, bits: 128, key: sh.substring(0, 32), sched: sh,
                              range: lbl, base: base.toString(), off: "0x" + abs.toString(16), t: Date.now() });
                  }
                  sub = sub + off + 1;
              }
              o0 += CH;
          }
          return nFound;
      }
      return 0;
  }

  function schedScan(tag, mode, force) {
      mode = mode || "full";
      var now = Date.now();
      var minGap = (mode === "vmp") ? 2000 : 20000;
      if (!force && now - (LAST_SCAN[mode] || 0) < minGap) { L("[SCHEDSCAN] 限速跳过 tag=" + tag + " mode=" + mode); return; }
      LAST_SCAN[mode] = now;
      var t0 = now, nFound = 0, nRanges = 0, bytesScanned = 0;
      var ranges;
      if (mode === "vmp") ranges = vmpRangeList();
      else ranges = Process.enumerateRanges("rw-");
      ranges.forEach(function(rg) {
          var cap = (mode === "full") ? 2147483648 : (mode === "medium" ? 67108864 : 33554432);   // R7c: full 2GB(C直读)
          if (rg.size > cap || rg.size < 176) return;
          if (rg.file && rg.file.path && /\.(ttf|otf|png|jpg|webp|mp4|zip|apk)$/.test(rg.file.path)) return;
          // R7e: 逐区3点探针(首/中/尾) — 防 exec 邻域不可读页让 C 直读崩(R7d t0_vmp access violation)
          try { Memory.readByteArray(rg.base, 16); } catch (e1) { return; }
          try { Memory.readByteArray(rg.base.add(Math.floor(rg.size / 2)), 16); } catch (e2) { return; }
          try { Memory.readByteArray(rg.base.add(rg.size - 16), 16); } catch (e3) { return; }
          nRanges++; bytesScanned += rg.size;
          nFound += scanRangeForSched(rg.base, rg.size, tag, (rg.lbl || (rg.file && rg.file.path ? rg.file.path : "anon")));
      });
      L("[SCHEDSCAN] tag=" + tag + " mode=" + mode + " ranges=" + nRanges + " MB=" + Math.round(bytesScanned / 1048576) +
        " found=" + nFound + " cost=" + (Date.now() - t0) + "ms");
  }


// ═══ R7f 主循环: 连续全内存快照(attach优先; full≈2.3s/次 → 覆盖0~25s) ═══
setTimeout(function BOOT() {
    L("[SCANONLY-READY] " + Date.now() + " pid=" + Process.id);
    var n = 0;
    (function loop() {
        if (n > 11) { L("[SCANONLY-DONE] snapshots=" + n + " totalSched=" + STAT.schedscan); return; }
        var t0 = Date.now();
        try { schedScan("snap" + n, "full", true); } catch (e) { L("[SCAN_ERR] snap" + n + ": " + e); }
        L("[SNAP-DONE] #" + n + " ms=" + (Date.now() - t0) + " found=" + STAT.schedscan);
        n++;
        setTimeout(loop, 50);
    })();
}, 0);
