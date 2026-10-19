// hook_qqread_fock.js — QQ阅读(com.qq.reader) fock DRM 解密链 frida hook (子代理, 2026-10-19)
//
// 依据 ~/projects/qqreader/RECON-APK-CODE.md §1 (jadx13/jadx8b/jadx10 源码二次核对后的真实签名):
//   H1 com.yuewen.fock.Fock.unlockData([B, String, String, ErrorLogHandler) → FockResult{status,data,dataSize}  [static]
//      arg0=.eqct 密文(GZIP 前)  arg1=additionalKey("bid_cid_s")  arg2=userKey(fuid)  →  fock 输出(GZIP 流)
//   H2 com.yuewen.fock.Fock.addKeys(String poolB64, String skVersion, String userKey, ErrorLogHandler) [static]
//      + Fock.setup(String userKey) / addKeypool(String,String) — 密钥池/fuid 注入瞬间
//   H3 com.qq.reader.qrencrypt.fock.qdaa.search(String fuid, [B cipher, String additionalKey, cb) [static] 冗余覆盖
//   H4 com.qq.reader.cservice.onlineread.qdaf.search(String path, String bid, int cid) → byte[] [static]
//      = GZIP 解压后的最终正文明文 (100% Java)
//   四类 jadx 直读成功 ⇒ 不在 360壳(StubApp)抽取集内, Java.use 直挂。
//
// 装载方式: qqread-fock-hook.yml spawn 门控 (frida -H 127.0.0.1:14771 -f com.qq.reader -l 本脚本)
//   — 进程创建期装钩(壳武装之前), App 冷启动 → initEncryptSdk(/sk→addKeys) → 读书(unlockData) 全程在钩。
//
// 时机竞态处理: Fock 类是 /sk 响应回调里第一次才加载(加载后毫秒级就 setup+addKeys) — 1.2s 轮询必漏。
//   ⇒ 双层: ① java.lang.ClassLoader.loadClass 看门狗(命中目标类当场挂钩, 所有 loader 共用此入口)
//           ② 300ms 快轮询兜底(类已先于看门狗装好时)。qdaf/qdaa 同法。
//
// 产物(/data/data/com.qq.reader/files/fock_hook/ — app uid 可写, root adb tar 拉回):
//   events.ndjson       — 全事件流水(含 pool/additionalKey/userKey/md5/len/小 b64)
//   h1_in_<seq>.bin     — 密文(unlockData arg0 原始字节)
//   h1_out_<seq>.bin    — fock 解密输出(GZIP 流, uk() 输入输出对)
//   h4_out_<seq>.bin    — 最终正文明文(GZIP 解压后)
//   每事件同步 console.log('[FOCKEV] '+json) → frida CLI stdout → /tmp/fock_collect.log (r1_gen 同款采集通道)。
//
// 自保(360壳/腾讯系反frida惯用 exit(0), 起点项目 R6-R14 九轮定案的模式):
//   R14 出口吞噬 — 只替换 exit, 主 pid 吞掉(带计数+上报); 非 main pid(POSIX vfork 子进程)照真退
//   (vfork 子进程按 POSIX 只能 _exit, 我们不碰 _exit ⇒ 零 wedge 风险)。kill/abort 仅观察哨不拦。

var PKG = 'com.qq.reader';
var DIR = '/data/data/' + PKG + '/files/fock_hook/';

function L(s) { try { console.log(s); } catch (e) { } }

// ═══ 自保层(spawn 期即武装, 无 Java 依赖) ═══
(function GUARD() {
  var MAIN = Process.id;
  var _sc = null;
  try {
    _sc = new NativeFunction(Module.findExportByName('libc.so', 'syscall'), 'long',
      ['long', 'long', 'long', 'long']);
  } catch (e) { }
  try {
    var a = Module.findExportByName('libc.so', 'exit');
    if (a) {
      var cnt = 0;
      Interceptor.replace(a, new NativeCallback(function (code) {
        if (Process.id !== MAIN) {          // vfork 子进程违规用 exit → 让它真退
          if (_sc) { _sc(94, code); }
          return;
        }
        cnt++;
        if (cnt <= 12) L('[FOCKEV] ' + JSON.stringify({ ev: 'exit_swallowed', n: cnt, code: code }));
      }, 'void', ['int']));
      L('[GUARD] exit-swallow armed (main pid ' + MAIN + ')');
    }
  } catch (e) { L('[GUARD] exit arm fail: ' + e); }
  ['kill', 'abort', 'android_set_abort_message'].forEach(function (nm) {
    try {
      var p = Module.findExportByName(null, nm);
      if (!p) return;
      var seen = 0;
      Interceptor.attach(p, {
        onEnter: function (a) {
          if (seen++ > 15) return;
          var x = '';
          try {
            if (nm === 'kill') x = ' pid=' + a[0].toInt32() + ' sig=' + a[1].toInt32();
            else if (nm === 'android_set_abort_message') x = ' ' + a[0].readCString();
          } catch (e) { }
          L('[FOCKEV] ' + JSON.stringify({ ev: 'watchdog', fn: nm + x }));
        }
      });
    } catch (e) { }
  });
})();

L('[FOCK] script loaded pid=' + Process.id + ' abi=' + Process.arch + ' frida=' +
  (typeof Frida !== 'undefined' ? Frida.version : '?'));

// ═══ Java 层状态 ═══
var SEQ = 0;
var HITS = { h1: 0, h2: 0, h3: 0, h4: 0, setup: 0, keypool: 0 };
var DONE = { fock: false, qdaa: false, qdaf: false };
var DUMPS = { h1_in: 0, h1_out: 0, h4_out: 0 };
var MAX_DUMP = 200;          // 每类 bin 上限(防批量下载刷爆)
var _MKDIR = false;
var _CACHE = {};

function ju(n) { if (!_CACHE[n]) _CACHE[n] = Java.use(n); return _CACHE[n]; }

function ensureDir() {
  if (_MKDIR) return;
  Java.perform(function () {
    ju('java.io.File').$new(DIR).mkdirs();
    _MKDIR = true;
  });
}

// 事件: console.log 通道(r1 采集同款) + 设备 ndjson 落盘(须 Java 上下文)
function EVJ(o) {
  o.t = Date.now();
  L('[FOCKEV] ' + JSON.stringify(o));
  try {
    Java.perform(function () {
      ensureDir();
      var fos = ju('java.io.FileOutputStream').$new(DIR + 'events.ndjson', true);
      fos.write(ju('java.lang.String').$new(JSON.stringify(o) + '\n').getBytes('UTF-8'));
      fos.close();
    });
  } catch (e) { }
}

function md5hex(bArr) {
  var h = ju('java.security.MessageDigest').getInstance('MD5').digest(bArr);
  var s = '';
  for (var i = 0; i < h.length; i++) { var b = h[i] & 0xff; s += (b < 16 ? '0' : '') + b.toString(16); }
  return s;
}
function b64(bArr) { return ju('android.util.Base64').encodeToString(bArr, 2); }   // NO_WRAP
function utf8head(bArr, n) {
  try {
    var s = ju('java.lang.String').$new(bArr, 'UTF-8').toString();
    return s.substring(0, Math.min(n, s.length));
  } catch (e) { return null; }
}
function writeBin(name, bArr) {
  try {
    var fos = ju('java.io.FileOutputStream').$new(DIR + name);
    fos.write(bArr);
    fos.flush();
    fos.close();
    return DIR + name;
  } catch (e) { return null; }
}
function field(o, n) {
  try {
    var v = o[n];
    if (v === null || v === undefined) return null;
    if (typeof v === 'object' && v.value !== undefined) return v.value;
    return v;
  } catch (e) { return null; }
}

// overload 工具: 兼容 '[B'(descriptor) 与 'byte[]'(className) 两种形态
function typeNames(ov) {
  var out = [];
  try {
    var at = ov.argumentTypes;
    for (var i = 0; i < at.length; i++) out.push(String(at[i].className || at[i].name || ''));
  } catch (e) { }
  return out;
}
function isBA(t) { return t === '[B' || t === 'byte[]'; }
function isStr(t) { return t === 'java.lang.String'; }
function isInt(t) { return t === 'int'; }
function pick(overloads, matcher) {
  for (var i = 0; i < overloads.length; i++) {
    var t = typeNames(overloads[i]);
    if (matcher(t)) return overloads[i];
  }
  return null;
}

// 跨 loader 解析(360壳真实 dex 可能在 StubApp 的自定义 loader 里):
// 先默认 factory, 再 enumerateClassLoaders 逐个 ClassFactory.get 试。
function resolveCls(name) {
  try { return Java.use(name); } catch (e) { }
  var found = null;
  try {
    var loaders = (typeof Java.enumerateClassLoadersSync === 'function')
      ? Java.enumerateClassLoadersSync() : [];
    for (var i = 0; i < loaders.length && !found; i++) {
      try {
        var f = Java.ClassFactory.get(loaders[i]);
        var c = f.use(name);
        if (c) found = c;
      } catch (e2) { }
    }
  } catch (e) { }
  return found;
}

// ═══ H1: Fock.unlockData ═══
function hookFock(Fock) {
  var ov = null, types = null;
  try {
    ov = Fock.unlockData.overload('[B', 'java.lang.String', 'java.lang.String', 'com.yuewen.fock.Fock$ErrorLogHandler');
    types = 'spec';
  } catch (e) {
    ov = pick(Fock.unlockData.overloads, function (t) {
      return t.length >= 3 && isBA(t[0]) && isStr(t[1]) && isStr(t[2]);
    });
    types = 'dyn';
  }
  if (!ov) { EVJ({ ev: 'hook_fail', target: 'h1', why: 'unlockData overload not found' }); return; }
  ov.implementation = function (bArr, additionalKey, userKey, handler) {
    var seq = ++SEQ;
    var rec = { ev: 'h1', seq: seq, additionalKey: String(additionalKey), userKey: String(userKey) };
    try {
      if (bArr !== null && bArr !== undefined) {
        var len = bArr.length;
        rec.cipherLen = len;
        rec.cipherMd5 = md5hex(bArr);
        if (len <= 4096) rec.cipherB64 = b64(bArr);
        if (DUMPS.h1_in < MAX_DUMP) {
          var p = writeBin('h1_in_' + pad(seq) + '.bin', bArr);
          if (p) { rec.cipherFile = 'h1_in_' + pad(seq) + '.bin'; DUMPS.h1_in++; }
        }
      } else rec.cipherLen = -1;
    } catch (e) { rec.inErr = String(e).slice(0, 100); }
    var res = null;
    try {
      res = this.unlockData(bArr, additionalKey, userKey, handler);
    } catch (e2) {
      rec.thrown = String(e2).slice(0, 200);
      HITS.h1++;
      EVJ(rec);
      throw e2;
    }
    HITS.h1++;
    try {
      if (res !== null && res !== undefined) {
        rec.status = field(res, 'status');
        var out = field(res, 'data');
        rec.dataSize = field(res, 'dataSize');
        if (out !== null && out !== undefined && out.length !== undefined) {
          rec.outLen = out.length;
          rec.outMd5 = md5hex(out);
          var hd = utf8head(out, 80);
          if (hd && hd.charCodeAt(0) !== 0xfffd) rec.outHead = hd;   // GZIP 流首字节非法UTF-8→替换符, 过滤
          if (DUMPS.h1_out < MAX_DUMP) {
            var p2 = writeBin('h1_out_' + pad(seq) + '.bin', out);
            if (p2) { rec.outFile = 'h1_out_' + pad(seq) + '.bin'; DUMPS.h1_out++; }
          }
        } else rec.outLen = -1;
      } else rec.status = 'null';
    } catch (e3) { rec.outErr = String(e3).slice(0, 100); }
    EVJ(rec);
    return res;
  };
  EVJ({ ev: 'hooked', target: 'h1', sel: String(types) });
}

function pad(n) { return ('0000' + n).slice(-5); }

// ═══ H2: Fock.addKeys / setup / addKeypool ═══
function hookFockKeys(Fock) {
  var ov = pick(Fock.addKeys.overloads, function (t) {
    return t.length === 4 && isStr(t[0]) && isStr(t[1]) && isStr(t[2]);
  });
  if (ov) {
    ov.implementation = function (pool, skVersion, userKey, handler) {
      HITS.h2++;
      EVJ({
        ev: 'h2', poolB64: String(pool), skVersion: String(skVersion), userKey: String(userKey),
        poolLen: String(pool).length
      });
      return this.addKeys(pool, skVersion, userKey, handler);
    };
    EVJ({ ev: 'hooked', target: 'h2' });
  } else {
    EVJ({ ev: 'hook_fail', target: 'h2', why: 'addKeys overload not found' });
  }
  var ov2 = pick(Fock.setup.overloads, function (t) { return t.length === 1 && isStr(t[0]); });
  if (ov2) {
    ov2.implementation = function (userKey) {
      HITS.setup++;
      EVJ({ ev: 'setup', userKey: String(userKey) });
      return this.setup(userKey);
    };
    EVJ({ ev: 'hooked', target: 'setup' });
  }
  try {
    var ovk = pick(Fock.addKeypool.overloads, function (t) { return t.length === 2 && isStr(t[0]) && isStr(t[1]); });
    if (ovk) {
      ovk.implementation = function (a, b) {
        HITS.keypool++;
        EVJ({ ev: 'keypool', a: String(a), b: String(b) });
        return this.addKeypool(a, b);
      };
      EVJ({ ev: 'hooked', target: 'keypool' });
    }
  } catch (e) { }
}

// ═══ H3: qdaa.search(String, [B, String, cb) ═══
function hookQdaa(qdaa) {
  var ov = pick(qdaa.search.overloads, function (t) {
    return t.length === 4 && isStr(t[0]) && isBA(t[1]) && isStr(t[2]);
  });
  if (!ov) { EVJ({ ev: 'hook_fail', target: 'h3', why: 'qdaa.search overload not found' }); return; }
  ov.implementation = function (fuid, bArr, additionalKey, cb) {
    var seq = ++SEQ;
    var rec = { ev: 'h3', seq: seq, userKey: String(fuid), additionalKey: String(additionalKey) };
    try {
      if (bArr !== null && bArr !== undefined) {
        rec.cipherLen = bArr.length;
        rec.cipherMd5 = md5hex(bArr);
      } else rec.cipherLen = -1;
    } catch (e) { }
    var ret = this.search(fuid, bArr, additionalKey, cb);
    HITS.h3++;
    try {
      if (ret !== null && ret !== undefined && ret.length !== undefined) {
        rec.retLen = ret.length;
        rec.retMd5 = md5hex(ret);
      } else rec.retLen = -1;
    } catch (e2) { }
    EVJ(rec);
    return ret;
  };
  EVJ({ ev: 'hooked', target: 'h3' });
}

// ═══ H4: qdaf.search(String path, String bid, int cid) → 最终明文 ═══
function hookQdaf(qdaf) {
  var ov = pick(qdaf.search.overloads, function (t) {
    return t.length === 3 && isStr(t[0]) && isStr(t[1]) && isInt(t[2]);
  });
  if (!ov) { EVJ({ ev: 'hook_fail', target: 'h4', why: 'qdaf.search(String,String,int) not found' }); return; }
  ov.implementation = function (path, bid, cid) {
    var seq = ++SEQ;
    var rec = { ev: 'h4', seq: seq, path: String(path), bid: String(bid), cid: cid };
    var ret = null;
    try {
      ret = this.search(path, bid, cid);
    } catch (e) {
      rec.thrown = String(e).slice(0, 200);
      HITS.h4++;
      EVJ(rec);
      throw e;
    }
    HITS.h4++;
    try {
      if (ret !== null && ret !== undefined && ret.length !== undefined) {
        rec.retLen = ret.length;
        rec.retMd5 = md5hex(ret);
        var hd = utf8head(ret, 160);
        if (hd && hd.charCodeAt(0) !== 0xfffd) rec.retHead = hd;
        if (DUMPS.h4_out < MAX_DUMP) {
          var p = writeBin('h4_out_' + pad(seq) + '.bin', ret);
          if (p) { rec.retFile = 'h4_out_' + pad(seq) + '.bin'; DUMPS.h4_out++; }
        }
      } else rec.retLen = -1;
    } catch (e2) { rec.outErr = String(e2).slice(0, 100); }
    EVJ(rec);
    return ret;
  };
  EVJ({ ev: 'hooked', target: 'h4' });
}

// ═══ 安装调度 ═══
var TARGETS = {
  'com.yuewen.fock.Fock': 'fock',
  'com.qq.reader.qrencrypt.fock.qdaa': 'qdaa',
  'com.qq.reader.cservice.onlineread.qdaf': 'qdaf'
};

function install(kind) {
  if (DONE[kind]) return true;
  var hit = false;
  Java.perform(function () {
    try {
      if (kind === 'fock') {
        var Fock = resolveCls('com.yuewen.fock.Fock');
        if (Fock) { hookFock(Fock); hookFockKeys(Fock); DONE.fock = true; hit = true; }
      } else if (kind === 'qdaa') {
        var qdaa = resolveCls('com.qq.reader.qrencrypt.fock.qdaa');
        if (qdaa) { hookQdaa(qdaa); DONE.qdaa = true; hit = true; }
      } else if (kind === 'qdaf') {
        var qdaf = resolveCls('com.qq.reader.cservice.onlineread.qdaf');
        if (qdaf) { hookQdaf(qdaf); DONE.qdaf = true; hit = true; }
      }
    } catch (e) {
      L('[FOCK] install ' + kind + ' err: ' + String(e).slice(0, 120));
    }
  });
  return hit;
}

function allDone() { return DONE.fock && DONE.qdaa && DONE.qdaf; }

// ① loadClass 看门狗 — 类加载瞬间挂钩(解 Fock 类加载→addKeys 毫秒级竞态)
(function ARMWATCH() {
  Java.perform(function () {
    try {
      var CL = Java.use('java.lang.ClassLoader');
      var ov = CL.loadClass.overload('java.lang.String', 'boolean');
      ov.implementation = function (name, resolve) {
        var cls = this.loadClass(name, resolve);
        try {
          var kind = TARGETS[name];
          if (kind && !DONE[kind]) install(kind);
        } catch (e) { }
        return cls;
      };
      var ov1 = null;
      try {
        ov1 = CL.loadClass.overload('java.lang.String');
        ov1.implementation = function (name) {
          var cls = this.loadClass(name);
          try {
            var kind = TARGETS[name];
            if (kind && !DONE[kind]) install(kind);
          } catch (e) { }
          return cls;
        };
      } catch (e) { }
      L('[FOCK] classwatch armed');
    } catch (e) {
      L('[FOCK] classwatch fail: ' + String(e).slice(0, 120));
    }
  });
})();

// ② 快轮询兜底(类先于看门狗已加载时)
var ROUNDS = 0;
var TIMER = setInterval(function () {
  ROUNDS++;
  if (allDone() || ROUNDS > 3600) {   // 最长 ~18min@300ms
    clearInterval(TIMER);
    L('[FOCKHOOK_READY] all=' + JSON.stringify(DONE) + ' hits=' + JSON.stringify(HITS));
    return;
  }
  if (!DONE.fock) install('fock');
  if (!DONE.qdaa) install('qdaa');
  if (!DONE.qdaf) install('qdaf');
  if (ROUNDS % 200 === 0) {
    L('[FOCK] poll r' + ROUNDS + ' done=' + JSON.stringify(DONE) + ' hits=' + JSON.stringify(HITS));
  }
}, 300);

// RPC 自检(r1 教训: load() 返回 ≠ 执行)
rpc.exports.ping = function () { return 'pong-' + Process.id + '-' + JSON.stringify(DONE); };
