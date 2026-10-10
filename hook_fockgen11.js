// hook_fockgen11.js — 路线1(用户VMP指南): 464 VMP动态捕获, spawn模式
// ★静态已证明读不到: FockUtil.getH 464已native化(VMP), QDRequestAddKnobsInterceptor全VMP,
//   登录SDK字符串(qqwtcallback等)壳内加密 → 只能运行时抓输入输出
// ⓪ 反反调试(spawn挂起态装载, 壳初始化之前): ptrace→0 / kill·exit·abort·raise·syscall阻断+backtrace定位
//    / fork阻断(360看门狗) / strstr·strcmp frida字符串隐藏 / dlopen日志
// ① Java层: System.exit·killProcess·Runtime.exit拦截(带调用栈)
// ② 业务捕获: FockUtil.getH(VMP函数) in/out ★ + okhttp Request.Builder.build()出站全头dump ★
//    + Response$Builder(响应码+Set-Cookie) + App版本信息
// 用法: qd-vmp464.yml wrap+gadget驱动 (am start → gadget listen → load → 自动续跑)

var caps = { req: 0, geth: 0, resp: 0, kill: 0, hide: 0, dlop: 0, prop: 0, file: 0 };
var LIM = { req: 300, geth: 150, resp: 150, kill: 60, hide: 10, dlop: 20, prop: 200, file: 60 };

function S(o) { try { send(o); } catch (e) { } }
function bt(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 14).map(function (a) {
      var s = null;
      try { s = DebugSymbol.fromAddress(a); } catch (e) { }
      if (s && s.moduleName && s.moduleName !== '?') return s.moduleName + '!' + (s.name || s.address);
      // 匿名区(VMP): 报所属range的相对偏移 — 跨run可定位
      try {
        var r = Process.findRangeByAddress(a);
        if (r) return (r.file ? String(r.file.path).split('/').pop() : 'anon') + '+' + a.sub(r.base) + ' sz' + r.size;
      } catch (e) { }
      return '?' + a;
    }).join('\n      ');
  } catch (e) { return '(bt失败)'; }
}
function btNow() { return bt(null); }

// ==================== ⓪ 反反调试(native, 挂起态装载) ====================
S({ m: '⓪ 反反调试装载 pid=' + Process.id + ' arch=' + Process.arch });

// ★抹LD_PRELOAD痕迹: 只覆写键名10字节(LD_PRELOAD→QD_PRELOAD等长) — 
// v25教训: 零填充会吃掉相邻env串(BOOT_CLASSPATH等) → JNI_CreateJavaVM失败SIGSEGV
try {
  var envpp = Module.findExportByName(null, 'environ');
  var envArr = envpp.readPointer();
  var key = [0x51, 0x44, 0x5F, 0x50, 0x52, 0x45, 0x4C, 0x4F, 0x41, 0x44];   // 'QD_PRELOAD'
  for (var ei = 0; ; ei++) {
    var ep = envArr.add(ei * 8).readPointer();
    if (ep.isNull()) break;
    try {
      var es = ep.readCString(16);
      if (es && es.indexOf('LD_PRELOAD=') === 0) {
        ep.writeByteArray(key);   // 只动前10字节, '='与值与NUL原样保留
        S({ m: '✓LD_PRELOAD键名已覆写(QD_PRELOAD), 值保留' });
        break;
      }
    } catch (e2) { }
  }
} catch (e) { S({ m: '✗env覆写: ' + e }); }

// ★★seccomp内核级自杀封锁(v11终极方案): Run9b实证壳用裸svc exit_group补刀,
// libc层hook和Stalker全线程扫描都追不到(扫描还会锁死frida) — BPF过滤器在内核执行,
// 覆盖所有线程所有调用路径, 对 exit/exit_group/自杀信号syscall直接返回EPERM
// (ART正常运行不受影响: 只拦sig=9的自定向kill/tkill/tgkill和exit族)
try {
  var SPID = Process.id;
  var ALLOWK = 0x7FFF0000, EPERMK = 0x00050001, ARCHAA = 0xC00000B7;
  var BPF = [
    [0x20, 0, 0, 0x4],
    [0x15, 1, 0, 0xc00000b7],
    [0x06, 0, 0, 0x7fff0000],
    [0x20, 0, 0, 0x0],
    [0x15, 8, 0, 0x5d],
    [0x15, 7, 0, 0x5e],
    [0x15, 7, 0, 0x81],
    [0x15, 15, 0, 0x82],
    [0x15, 18, 0, 0x83],
    [0x15, 24, 0, 0x8a],
    [0x15, 32, 0, 0xf0],
    [0x15, 38, 0, 0x1a8],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x50001],
    [0x20, 0, 0, 0x18],
    [0x15, 1, 0, 0x9],
    [0x06, 0, 0, 0x7fff0000],
    [0x20, 0, 0, 0x10],
    [0x15, 3, 0, SPID],
    [0x15, 2, 0, 0x0],
    [0x15, 1, 0, 0xffffffff],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x50001],
    [0x20, 0, 0, 0x18],
    [0x15, 1, 0, 0x9],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x50001],
    [0x20, 0, 0, 0x20],
    [0x15, 1, 0, 0x9],
    [0x06, 0, 0, 0x7fff0000],
    [0x20, 0, 0, 0x10],
    [0x15, 1, 0, SPID],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x50001],
    [0x20, 0, 0, 0x18],
    [0x15, 1, 0, 0x9],
    [0x06, 0, 0, 0x7fff0000],
    [0x20, 0, 0, 0x10],
    [0x15, 3, 0, SPID],
    [0x15, 2, 0, 0x0],
    [0x15, 1, 0, 0xffffffff],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x50001],
    [0x20, 0, 0, 0x20],
    [0x15, 1, 0, 0x9],
    [0x06, 0, 0, 0x7fff0000],
    [0x20, 0, 0, 0x10],
    [0x15, 1, 0, SPID],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x50001],
    [0x20, 0, 0, 0x18],
    [0x15, 1, 0, 0x9],
    [0x06, 0, 0, 0x7fff0000],
    [0x06, 0, 0, 0x50001]
  ];
  var flt = Memory.alloc(BPF.length * 8);
  BPF.forEach(function (b, i) {
    var a = flt.add(i * 8);
    a.writeU16(b[0]); a.add(2).writeU8(b[1]); a.add(3).writeU8(b[2]); a.add(4).writeU32(b[3]);
  });
  var fprog = Memory.alloc(16);
  fprog.writeU16(BPF.length);
  fprog.add(8).writePointer(flt);
  var prctlF = new NativeFunction(Module.findExportByName(null, 'prctl'), 'int', ['int', 'long', 'pointer', 'long', 'long']);
  var r1 = prctlF(38, 1, ptr(0), 0, 0);        // PR_SET_NO_NEW_PRIVS
  var r2 = prctlF(22, 2, fprog, 0, 0);         // PR_SET_SECCOMP + MODE_FILTER
  S({ m: '✓seccomp自杀封锁: nnpriv=' + r1 + ' seccomp=' + r2 + ' (' + BPF.length + '条BPF)' });

} catch (e) { S({ m: '✗seccomp: ' + e }); }

// ptrace → 恒0 (反调试自附加/子进程附加检测全失效)
try {
  Interceptor.replace(Module.findExportByName(null, 'ptrace'),
    new NativeCallback(function (a, b, c, d) { return 0; }, 'long', ['int', 'int', 'pointer', 'pointer']));
  S({ m: '✓ ptrace→0' });
} catch (e) { S({ m: '✗ ptrace: ' + e }); }

// kill: 自杀信号拦截(360/fock检测命中后的处决路径) — backtrace定位判定点
try {
  var MYPID = Process.id;
  Interceptor.attach(Module.findExportByName(null, 'kill'), {
    onEnter: function (args) {
      try {
        var pid = args[0].toInt32(), sig = args[1].toInt32();
        if (pid === MYPID || pid === 0 || pid === -1) {
          caps.kill++;
          if (caps.kill <= LIM.kill) S({ m: '★KILL拦截 pid=' + pid + ' sig=' + sig, bt: bt(this.context) });
          dumpVmp();
          args[1] = ptr(0);   // 信号改0 = 无害探测
        }
      } catch (e) { }
    }
  });
  S({ m: '✓ kill拦截' });
} catch (e) { S({ m: '✗ kill: ' + e }); }

// fork 阻断(360看门狗子进程: fork出的child负责kill父进程)
try {
  Interceptor.replace(Module.findExportByName(null, 'fork'), new NativeCallback(function () {
    caps.kill++;
    if (caps.kill <= LIM.kill) S({ m: '★fork阻断(看门狗)', bt: btNow() });
    return -1;
  }, 'int', []));
  S({ m: '✓ fork阻断' });
} catch (e) { S({ m: '✗ fork: ' + e }); }

// exit/_exit/abort → 阻断(不调原函数) + backtrace
['exit', '_exit', 'abort'].forEach(function (n) {
  try {
    var addr = Module.findExportByName(null, n);
    Interceptor.replace(addr, new NativeCallback(function (a) {
      caps.kill++;
      if (caps.kill <= LIM.kill) S({ m: '★' + n + '阻断 arg=' + a, bt: btNow() });
      dumpVmp();
      return 0;   // 不退出
    }, 'void', ['int']));
  } catch (e) { S({ m: '✗ ' + n + ': ' + e }); }
});
S({ m: '✓ exit/_exit/abort阻断' });

// raise / pthread_kill: ★attach+参数中和(自杀信号6/9改成0, 其余原样放行)
// (v8教训: replace后用NativeFunction绑同一地址调"原函数"=自递归 → ART的GC挂起(pthread_kill+SIGUSR1)
//  触发无限递归 → frida agent锁死 → JS冻结App白屏; attach模式天然走原函数, 零递归)
try {
  var raiseA = Module.findExportByName(null, 'raise');
  Interceptor.attach(raiseA, {
    onEnter: function (args) {
      try {
        var s = args[0].toInt32();
        if (s === 6 || s === 9) {
          caps.kill++;
          if (caps.kill <= LIM.kill) S({ m: '★raise中和 sig=' + s, bt: bt(this.context) });
          dumpVmp();
          args[0] = ptr(0);   // raise(0) = 无害
        }
      } catch (e) { }
    }
  });
} catch (e) { S({ m: '✗ raise: ' + e }); }
try {
  var pkA = Module.findExportByName(null, 'pthread_kill');
  Interceptor.attach(pkA, {
    onEnter: function (args) {
      try {
        var s = args[1].toInt32();
        if (s === 6 || s === 9) {
          caps.kill++;
          if (caps.kill <= LIM.kill) S({ m: '★pthread_kill中和 sig=' + s, bt: bt(this.context) });
          dumpVmp();
          args[1] = ptr(0);   // pthread_kill(t,0) = 线程存在性探测, 无害
        }
      } catch (e) { }
    }
  });
} catch (e) { S({ m: '✗ pthread_kill: ' + e }); }

// 裸syscall: arm64 exit=93 exit_group=94 kill=129 tkill=130 tgkill=131 → 换成getpid(172)
try {
  Interceptor.attach(Module.findExportByName(null, 'syscall'), {
    onEnter: function (args) {
      try {
        var nr = args[0].toInt32();
        if (nr === 93 || nr === 94 || nr === 129 || nr === 130 || nr === 131 || nr === 138 || nr === 240 || nr === 424) {
          caps.kill++;
          if (caps.kill <= LIM.kill) S({ m: '★syscall拦截 nr=' + nr, bt: bt(this.context) });
          args[0] = ptr(172);
        }
      } catch (e) { }
    }
  });
} catch (e) { S({ m: '✗ syscall: ' + e }); }

// v3: 移除全局strcmp/strstr隐藏钩子 — v2实测零命中却让每次字符串比较都进JS回调,
// JS事件循环被饿死(心跳全丢), 干扰远大于收益. 自杀处决已由kill/exit层兜底.
// 若壳之后真用字符串扫描查frida并自杀, 会被kill拦截并带backtrace定位 → 届时再精确处置.
S({ m: '✓ (字符串钩子已移除, kill/exit层兜底)' });

// dlopen日志(看壳/风控库装载顺序) — v16: Stalker整体移除(11万svc×JS回调把引擎冲死, seccomp已兜底)
var svcCnt = {};
['dlopen', 'android_dlopen_ext'].forEach(function (n) {
  try {
    Interceptor.attach(Module.findExportByName(null, n), {
      onEnter: function (a) { try { this.p = a[0].readCString(); } catch (e) { this.p = null; } },
      onLeave: function (r) {
        if (this.p && /jiagu|fock|knob|ostar|nib|DexHelper|SecShell|exec|tupu|msaoaid/i.test(this.p)) {
          caps.dlop++;
          if (caps.dlop <= LIM.dlop) S({ m: '·dlopen ' + String(this.p).split('/').pop() });
        }
      }
    });
  } catch (e) { }
});

// ★★环境伪装(Run3实证: 无frida也130ms signal9自杀 → 360壳检测redroid环境本身)
// 真机模板: 小米11 (M2011K2C/venus, Android 11, user/release-keys)
var PROPOV = {
  'ro.build.fingerprint': 'Xiaomi/venus/venus:11/RKQ1.211022.002/V12.5.6.0.RKBCNXM:user/release-keys',
  'ro.build.flavor': 'venus-user',
  'ro.build.description': 'venus-user 11 RKQ1.211022.002 V12.5.6.0.RKBCNXM release-keys',
  'ro.build.id': 'RKQ1.211022.002',
  'ro.build.tags': 'release-keys',
  'ro.build.type': 'user',
  'ro.build.version.incremental': 'V12.5.6.0.RKBCNXM',
  'ro.build.version.codename': 'REL',
  'ro.product.brand': 'Xiaomi',
  'ro.product.device': 'venus',
  'ro.product.manufacturer': 'Xiaomi',
  'ro.product.name': 'venus',
  'ro.product.model': 'M2011K2C',
  'ro.product.marketname': 'Mi 11',
  'ro.product.system_brand': 'Xiaomi',
  'ro.product.system_device': 'venus',
  'ro.product.system_manufacturer': 'Xiaomi',
  'ro.product.system_model': 'M2011K2C',
  'ro.product.system_name': 'venus',
  'ro.hardware': 'qcom',
  'ro.boot.hardware': 'qcom',
  'ro.board.platform': 'sm8350',
  'ro.chipname': 'msmnile',
  'ro.debuggable': '0',
  'ro.secure': '1',
  'ro.boot.flash.locked': '1',
  'ro.kernel.qemu': '0',
  'qemu.hw.mainkeys': '0',
  'ro.build.selinux': '1',
  'ro.adb.secure': '1'
};
var propSeen = {};
try {
  var pga = Module.findExportByName(null, '__system_property_get');
  Interceptor.attach(pga, {
    onEnter: function (args) {
      try {
        this.nm = args[0].readCString();
        if (this.nm) this.nm = this.nm.replace(/[^A-Za-z0-9._-].*$/, '');   // VMP区名字串带密文尾巴, 截掉才匹配
        this.buf = args[1];
      } catch (e) { }
    },
    onLeave: function (ret) {
      try {
        if (!this.nm) return;
        var doLog = !propSeen[this.nm];
        if (doLog) propSeen[this.nm] = 1;
        if (PROPOV.hasOwnProperty(this.nm)) {
          var v = PROPOV[this.nm];
          var orig = ''; try { orig = this.buf.readCString() || ''; } catch (e) { }
          this.buf.writeUtf8String(v);
          ret.replace(v.length);
          if (doLog) { caps.prop++; if (caps.prop <= LIM.prop) S({ m: '·prop★ ' + this.nm + ': ' + orig + ' → ' + v }); }
        } else if (doLog) {
          var o = ''; try { o = this.buf.readCString() || ''; } catch (e) { }
          caps.prop++;
          if (caps.prop <= LIM.prop) S({ m: '·prop ' + this.nm + '=' + o });
        }
      } catch (e) { }
    }
  });
  S({ m: '✓ 属性伪装已挂(' + Object.keys(PROPOV).length + '项) + 全量查询日志' });
} catch (e) { S({ m: '✗ prop hook: ' + e }); }

// 文件探测: root/模拟器路径隐藏(返失败) + /proc探测日志(看壳查什么)
// ★全路径精确匹配($锚点): 宽松写法会把/system/bin/*全部误隐藏(linker读/etc会崩)
var SUS = /^\/(system\/(bin|xbin)\/(su|busybox|daemonsu|magisk[^\/]*)|system\/app\/(Superuser\.apk|magisk[^\/]*)|system\/etc\/(su|magisk[^\/]*)|sbin\/su|data\/local\/(tmp\/(fs|frida|qdsvc|su|magisk[^\/]*)|bin\/(su|magisk[^\/]*))|data\/adb\/magisk[^\/]*|su|magisk)$/;
// ★★maps隐藏(Run4实锤: 壳读/proc/self/maps且能看见/memfd:frida-agent-64.so → 检测源)
// 手法: fopen/open到maps时 → 读真内容滤掉frida行 → 写进memfd → 把返回值换成memfd的句柄
var MAPSRE = /^\/proc\/(self|\d+)\/maps$/;
var HIDE_LINE = /frida|linjector|qdsvc|gum-js|pool-frida/i;   // ★不藏裸memfd:(壳VMP区同是memfd)
var ioBusy = false;
var REAL = {
  fopen: new NativeFunction(Module.findExportByName(null, 'fopen'), 'pointer', ['pointer', 'pointer']),
  fgets: new NativeFunction(Module.findExportByName(null, 'fgets'), 'pointer', ['pointer', 'int', 'pointer']),
  fclose: new NativeFunction(Module.findExportByName(null, 'fclose'), 'int', ['pointer']),
  open: new NativeFunction(Module.findExportByName(null, 'open'), 'int', ['pointer', 'int']),
  close: new NativeFunction(Module.findExportByName(null, 'close'), 'int', ['int']),
  write: new NativeFunction(Module.findExportByName(null, 'write'), 'int', ['int', 'pointer', 'int']),
  lseek: new NativeFunction(Module.findExportByName(null, 'lseek'), 'int', ['int', 'int', 'int']),
  fdopen: new NativeFunction(Module.findExportByName(null, 'fdopen'), 'pointer', ['int', 'pointer']),
  memfd: new NativeFunction(Module.findExportByName(null, 'syscall'), 'int', ['int', 'int'])
};
function fakeMapsFd(realPath) {
  ioBusy = true;
  try {
    var f = REAL.fopen(Memory.allocUtf8String(realPath), Memory.allocUtf8String('r'));
    if (f.isNull()) return -1;
    var lines = [];
    var buf = Memory.alloc(4096);
    while (!REAL.fgets(buf, 4096, f).isNull()) {
      var line = buf.readCString();
      if (line && !HIDE_LINE.test(line)) lines.push(line);
    }
    REAL.fclose(f);
    var body = lines.join('\n') + '\n';
    var fd = REAL.memfd(279, 0);   // memfd_create
    if (fd < 0) return -1;
    REAL.write(fd, Memory.allocUtf8String(body), body.length);
    REAL.lseek(fd, 0, 0);
    return fd;
  } catch (e) { return -1; }
  finally { ioBusy = false; }
}

var fileSeen = {};
[['fopen', 0, 'ptr'], ['open', 0, 'int'], ['openat', 1, 'int'], ['access', 0, 'int'],
 ['stat', 0, 'int'], ['stat64', 0, 'int'], ['newfstatat', 1, 'int'], ['faccessat', 1, 'int']].forEach(function (h) {
  try {
    Interceptor.attach(Module.findExportByName(null, h[0]), {
      onEnter: function (args) {
        this.maps = false; this.p = null;
        if (ioBusy) return;   // 自己的IO重入, 不处理
        try {
          this.p = args[h[1]].readCString();
          if (this.p) {
            this.p = this.p.replace(/[\x00-\x1f\x7f].*$/, '');   // 截掉VMP密文尾巴
            if (MAPSRE.test(this.p)) this.maps = true;
          }
        } catch (e) { }
      },
      onLeave: function (ret) {
        if (ioBusy || !this.p) return;
        try {
          if (this.maps && h[0] === 'fopen') {
            if (!ret.isNull()) {
              var fd = fakeMapsFd(this.p);
              if (fd >= 0) {
                var fakeFILE = REAL.fdopen(fd, Memory.allocUtf8String('r'));
                if (!fakeFILE.isNull()) {
                  REAL.fclose(ret);
                  caps.file++;
                  if (caps.file <= LIM.file) S({ m: '·maps→滤毒fd(' + fd + ')' });
                  ret.replace(fakeFILE);
                }
              }
            }
            return;
          }
          if (this.maps && (h[0] === 'open' || h[0] === 'openat')) {
            var ofd = ret.toInt32();
            if (ofd >= 0) {
              var fd2 = fakeMapsFd(this.p);
              if (fd2 >= 0) {
                REAL.close(ofd);
                caps.file++;
                if (caps.file <= LIM.file) S({ m: '·maps→滤毒fd(' + fd2 + ')' });
                ret.replace(fd2);
              }
            }
            return;
          }
          if (SUS.test(this.p)) {
            if (h[2] === 'ptr') ret.replace(ptr(0)); else ret.replace(-1);
            if (!fileSeen[this.p]) { fileSeen[this.p] = 1; caps.file++; if (caps.file <= LIM.file) S({ m: '·file★隐 ' + this.p }); }
          } else if (/^\/proc\/(self|\d+)/.test(this.p) || /\/su$|magisk|xposed|frida|qemu/i.test(this.p)) {
            if (!fileSeen[this.p]) { fileSeen[this.p] = 1; caps.file++; if (caps.file <= LIM.file) S({ m: '·file ' + this.p }); }
          }
        } catch (e) { }
      }
    });
  } catch (e) { }
});
S({ m: '✓ 文件探测钩已挂(8族) + maps滤毒重定向' });

// ★frida线程改名(v29: dirent直读task目录, 不走frida枚举 — v28用Process.enumerateThreads崩了gadget)
var renTotal = 0, jsTid2 = Process.getCurrentThreadId();
function renameThreads() {
  try {
    var ODIR = new NativeFunction(Module.findExportByName(null, 'opendir'), 'pointer', ['pointer']);
    var RDIR = new NativeFunction(Module.findExportByName(null, 'readdir'), 'pointer', ['pointer']);
    var CDIR = new NativeFunction(Module.findExportByName(null, 'closedir'), 'int', ['pointer']);
    var WOPEN = new NativeFunction(Module.findExportByName(null, 'open'), 'int', ['pointer', 'int']);
    var WWRITE = new NativeFunction(Module.findExportByName(null, 'write'), 'int', ['int', 'pointer', 'int']);
    var WCLOSE = new NativeFunction(Module.findExportByName(null, 'close'), 'int', ['int']);
    var PRCTL = new NativeFunction(Module.findExportByName(null, 'prctl'), 'int', ['int', 'pointer', 'long', 'long', 'long']);
    var renamed = 0;
    var dir = ODIR(Memory.allocUtf8String('/proc/self/task'));
    if (dir.isNull()) return;
    var tids = [];
    var e;
    while (!(e = RDIR(dir)).isNull()) {
      try {
        var nm = e.add(19).readCString();   // bionic dirent: d_name@19
        if (nm && /^\d+$/.test(nm)) tids.push(parseInt(nm));
      } catch (e2) { }
    }
    CDIR(dir);
    tids.forEach(function (tid) {
      try {
        if (tid === jsTid2) return;   // JS线程自己用prctl
        ioBusy = true;
        var f = REAL.fopen(Memory.allocUtf8String('/proc/self/task/' + tid + '/comm'), Memory.allocUtf8String('r'));
        if (f.isNull()) { ioBusy = false; return; }
        var b = Memory.alloc(64);
        REAL.fgets(b, 64, f); REAL.fclose(f);
        ioBusy = false;
        var cn = b.readCString();
        if (cn && /gum|gmain|gdbus|frida|pool/i.test(cn)) {
          var nn = 'ArtWorker' + (renTotal % 7);
          var fd = WOPEN(Memory.allocUtf8String('/proc/self/task/' + tid + '/comm'), 1);
          if (fd >= 0) { WWRITE(fd, Memory.allocUtf8String(nn), 9); WCLOSE(fd); renamed++; renTotal++; }
        }
      } catch (e3) { ioBusy = false; }
    });
    if (renamed > 0) S({ m: '·frida线程改名 ' + renamed + '个(共' + tids.length + '线程)' });
  } catch (e) { S({ m: '✗线程改名: ' + e }); }
}
// JS自身线程名(gum-js-loop)用prctl改
try {
  var PRC = new NativeFunction(Module.findExportByName(null, 'prctl'), 'int', ['int', 'pointer', 'long', 'long', 'long']);
  PRC(15, Memory.allocUtf8String('ArtWorker9'), 0, 0, 0);
} catch (e) { }

var renN = 0;
var renT = setInterval(function () {
  renN++;
  renameThreads();
  if (renN >= 20) clearInterval(renT);
}, 5000);


// ★★VMP现场dump: 自杀被拦的瞬间(壳可能马上svc补刀) 同步抢dump:
// ①真实/proc/self/maps文本(bt里'?'地址离线对账用) ②全部匿名可执行区(VMP解释器代码)
var dumped = false;
function str2ab(s) {
  var u = new Uint8Array(s.length);
  for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i) & 0xff;
  return u.buffer;
}
function dumpVmp() {
  if (dumped) return;
  dumped = true;
  try {
    ioBusy = true;
    var f = REAL.fopen(Memory.allocUtf8String('/proc/self/maps'), Memory.allocUtf8String('r'));
    var lines = [], buf = Memory.alloc(4096);
    while (!REAL.fgets(buf, 4096, f).isNull()) { var l = buf.readCString(); if (l) lines.push(l); }
    REAL.fclose(f);
    ioBusy = false;
    send({ t: 'vmpdump', name: 'maps', part: 1, total: 1 }, str2ab(lines.join('\n')));
    var regions = Process.enumerateRanges('r-x').filter(function (r) {
      return (!r.file || /jiagu|fock|ostar|knob|nib/i.test(String(r.file && r.file.path))) &&
        r.size >= 64 * 1024 && r.size <= 20 * 1024 * 1024;
    });
    var budget = 12 * 1024 * 1024, n = 0;
    for (var i = 0; i < regions.length && budget > 0; i++) {
      var r = regions[i];
      try {
        var data = new Uint8Array(r.base.readByteArray(r.size));
        var CH = 512 * 1024, parts = Math.ceil(data.length / CH);
        for (var p = 0; p < parts; p++) {
          send({ t: 'vmpdump', name: 'r' + i + '_' + r.base + '_sz' + r.size, part: p + 1, total: parts },
            data.buffer.slice(p * CH, (p + 1) * CH));
        }
        budget -= r.size; n++;
      } catch (e) { }
    }
    S({ m: '✓VMP现场dump完成: ' + n + '区 + maps文本' });
  } catch (e) { ioBusy = false; S({ m: '✗dump: ' + e }); }
}

// 心跳
setInterval(function () { S({ t: 'hb', s: Math.floor(Date.now() / 1000) % 100000, caps: caps, svc: svcCnt }); }, 15000);
setInterval(function () { S({ t: 'svc快照', svc: svcCnt }); }, 15000);

// ==================== ①+② Java阶段(等VM起来后逐个挂) ====================
function jstack() {
  try {
    return Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new()).split('\n').slice(1, 10).join('\n');
  } catch (e) { return ''; }
}

function hookWhenReady(className, fn, triesMax) {
  var tries = 0, done = false;
  var t = setInterval(function () {
    if (done) return;
    tries++;
    try {
      Java.perform(function () {
        var C = Java.use(className);
        done = true; clearInterval(t);
        fn(C);
        S({ m: '✓ 已挂 ' + className + ' (try ' + tries + ')' });
      });
    } catch (e) {
      if (tries >= (triesMax || 90)) { done = true; clearInterval(t); S({ m: '✗ ' + className + ' ' + (triesMax || 90) + 's未加载: ' + e }); }
    }
  }, 1000);
}

var jStarted = false;
var jTimer = setInterval(function () {
  if (jStarted) return;
  if (Java.available) {
    jStarted = true; clearInterval(jTimer);
    Java.perform(function () {
      S({ m: '① Java阶段启动 android=' + Java.androidVersion });
      try {
        var at = Java.use('android.app.ActivityThread').currentApplication();
        var ctx = at.getApplicationContext();
        var pm = ctx.getPackageManager();
        var pi = pm.getPackageInfo(ctx.getPackageName(), 0);
        S({ m: 'App信息', pkg: String(ctx.getPackageName()), ver: String(pi.versionName.value), code: pi.versionCode.value });
      } catch (e) { S({ m: '✗App信息: ' + e }); }

      // Java层Build伪装(与native prop一致: 小米11)
      try {
        var B = Java.use('android.os.Build');
        B.FINGERPRINT.value = 'Xiaomi/venus/venus:11/RKQ1.211022.002/V12.5.6.0.RKBCNXM:user/release-keys';
        B.MODEL.value = 'M2011K2C';
        B.BRAND.value = 'Xiaomi'; B.MANUFACTURER.value = 'Xiaomi';
        B.DEVICE.value = 'venus'; B.PRODUCT.value = 'venus';
        B.HARDWARE.value = 'qcom'; B.BOARD.value = 'sm8350';
        B.ID.value = 'RKQ1.211022.002'; B.TAGS.value = 'release-keys'; B.TYPE.value = 'user';
        S({ m: '✓ Build字段已伪装(小米11)' });
      } catch (e) { S({ m: '✗ Build伪装: ' + e }); }

      // Java层自杀拦截
      try {
        Java.use('java.lang.System').exit.implementation = function (c) {
          S({ m: '★System.exit(' + c + ')拦截', bt: jstack() }); return;
        };
      } catch (e) { }
      try {
        Java.use('android.os.Process').killProcess.implementation = function (p) {
          S({ m: '★killProcess(' + p + ')拦截', bt: jstack() }); return;
        };
      } catch (e) { }
      try {
        Java.use('java.lang.Runtime').exit.overload('int').implementation = function (c) {
          S({ m: '★Runtime.exit(' + c + ')拦截' }); return;
        };
      } catch (e) { }
      S({ m: '✓ Java自杀拦截(System.exit/killProcess/Runtime.exit)' });
    });
  }
}, 500);

// ★主捕获1: FockUtil.getH (464已VMP native) in/out
hookWhenReady('com.qidian.QDReader.component.util.FockUtil', function (FU) {
  var ov = FU.getH.overload('java.lang.String', 'java.lang.String', 'okhttp3.RequestBody');
  ov.implementation = function (url, method, body) {
    var r = ov.call(this, url, method, body);
    try {
      caps.geth++;
      if (caps.geth <= LIM.geth) {
        var bs = '';
        try {
          if (body !== null) {
            var Buf = Java.use('okio.Buffer');
            var b = Buf.$new(); body.writeTo(b); bs = String(b.readUtf8()).slice(0, 300);
          }
        } catch (e) { }
        var hm = [];
        var it = r.entrySet().iterator();
        while (it.hasNext()) {
          var en = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
          hm.push(String(en.getKey()) + ': ' + String(en.getValue()));
        }
        S({ t: 'GETH', n: caps.geth, url: String(url), method: String(method), body: bs, out: hm });
      }
    } catch (e) { }
    return r;
  };
}, 120);

// ★主捕获2: okhttp出站请求全头dump (borgus/cecelia/gorgon/sora/QDInfo/QDSign 真实值)
hookWhenReady('okhttp3.Request$Builder', function (ReqB) {
  var ov = ReqB.build.overload();
  ov.implementation = function () {
    var r = ov.call(this);
    try {
      var url = String(r.url());
      if (/qidian\.com|yuewen\.com|qq\.com/.test(url) && !/\.(png|jpg|jpeg|webp|gif|svg|ico|mp4)(\?|$)/.test(url)) {
        caps.req++;
        if (caps.req <= LIM.req) {
          var h = r.headers();
          var it = h.names().iterator();
          var hd = [];
          while (it.hasNext()) {
            var k = String(it.next());
            hd.push(k + ': ' + String(h.get(k)));
          }
          var bodyS = '';
          try {
            var b = r.body();
            if (b !== null) {
              var Buf = Java.use('okio.Buffer');
              var buf = Buf.$new(); b.writeTo(buf); bodyS = String(buf.readUtf8());
              if (bodyS.length > 400) bodyS = bodyS.slice(0, 400) + '…';
            }
          } catch (e) { }
          S({ t: 'REQ', n: caps.req, method: String(r.method()), url: url, headers: hd, body: bodyS });
        }
      }
    } catch (e) { }
    return r;
  };
}, 120);

// 主捕获3: 响应码+响应头(Set-Cookie会话收割)
hookWhenReady('okhttp3.Response$Builder', function (RB) {
  var ov = RB.build.overload();
  ov.implementation = function () {
    var resp = ov.call(this);
    try {
      var rq = resp.request();
      if (rq !== null) {
        var url = String(rq.url());
        if (/qidian\.com|yuewen\.com|qq\.com/.test(url) && !/\.(png|jpg|jpeg|webp|gif|svg|ico|mp4)(\?|$)/.test(url)) {
          caps.resp++;
          if (caps.resp <= LIM.resp) {
            var h = resp.headers();
            var it = h.names().iterator();
            var hd = [];
            while (it.hasNext()) {
              var k = String(it.next());
              if (k.toLowerCase() === 'set-cookie' || k.toLowerCase() === 'sora' || k.toLowerCase() === 'content-type') {
                hd.push(k + ': ' + String(h.get(k)));
              }
            }
            S({ t: 'RESP', n: caps.resp, code: resp.code(), url: url, headers: hd });
          }
        }
      }
    } catch (e) { }
    return resp;
  };
}, 120);

// knobs sora原值捕获(464 native VMP, hook不成功也有REQ兜底)
hookWhenReady('com.qidian.QDReader.component.retrofit.QDRequestAddKnobsInterceptor$Companion', function (CP) {
  try {
    var ov = CP.checkKnobsUrl.overload('java.lang.String', 'com.qidian.QDReader.component.retrofit.i');
    ov.implementation = function (u, cb) {
      S({ t: 'KNOBS', url: String(u) });
      var r = ov.call(this, u, cb);
      return r;
    };
  } catch (e) { S({ m: '✗checkKnobsUrl签名: ' + e }); }
}, 60);
