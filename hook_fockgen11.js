// hook_fockgen11.js — 路线1(用户VMP指南): 464 VMP动态捕获, spawn模式
// ★静态已证明读不到: FockUtil.getH 464已native化(VMP), QDRequestAddKnobsInterceptor全VMP,
//   登录SDK字符串(qqwtcallback等)壳内加密 → 只能运行时抓输入输出
// ⓪ 反反调试(spawn挂起态装载, 壳初始化之前): ptrace→0 / kill·exit·abort·raise·syscall阻断+backtrace定位
//    / fork阻断(360看门狗) / strstr·strcmp frida字符串隐藏 / dlopen日志
// ① Java层: System.exit·killProcess·Runtime.exit拦截(带调用栈)
// ② 业务捕获: FockUtil.getH(VMP函数) in/out ★ + okhttp Request.Builder.build()出站全头dump ★
//    + Response$Builder(响应码+Set-Cookie) + App版本信息
// 用法: qd-vmp464.yml spawn驱动 (dev.spawn → attach → load → resume)

var caps = { req: 0, geth: 0, resp: 0, kill: 0, hide: 0, dlop: 0 };
var LIM = { req: 300, geth: 150, resp: 150, kill: 30, hide: 10, dlop: 20 };

function S(o) { try { send(o); } catch (e) { } }
function bt(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 14).map(function (a) {
      var s = DebugSymbol.fromAddress(a);
      return (s.moduleName || '?') + '!' + (s.name || s.address);
    }).join('\n      ');
  } catch (e) { return '(bt失败)'; }
}
function btNow() { return bt(null); }

// ==================== ⓪ 反反调试(native, 挂起态装载) ====================
S({ m: '⓪ 反反调试装载 pid=' + Process.id + ' arch=' + Process.arch });

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

// exit/_exit/abort/raise → 阻断(不调原函数) + backtrace
['exit', '_exit', 'abort', 'raise'].forEach(function (n) {
  try {
    var addr = Module.findExportByName(null, n);
    Interceptor.replace(addr, new NativeCallback(function (a) {
      caps.kill++;
      if (caps.kill <= LIM.kill) S({ m: '★' + n + '阻断 arg=' + a, bt: btNow() });
      return 0;   // 不退出
    }, 'void', ['int']));
  } catch (e) { S({ m: '✗ ' + n + ': ' + e }); }
});
S({ m: '✓ exit/_exit/abort/raise阻断' });

// pthread_kill → 拦截
try {
  Interceptor.replace(Module.findExportByName(null, 'pthread_kill'), new NativeCallback(function (t, s) {
    caps.kill++;
    if (caps.kill <= LIM.kill) S({ m: '★pthread_kill拦截 sig=' + s, bt: btNow() });
    return 0;
  }, 'int', ['pointer', 'int']));
} catch (e) { S({ m: '✗ pthread_kill: ' + e }); }

// 裸syscall: arm64 exit=93 exit_group=94 kill=129 tkill=130 tgkill=131 → 换成getpid(172)
try {
  Interceptor.attach(Module.findExportByName(null, 'syscall'), {
    onEnter: function (args) {
      try {
        var nr = args[0].toInt32();
        if (nr === 93 || nr === 94 || nr === 129 || nr === 130 || nr === 131) {
          caps.kill++;
          if (caps.kill <= LIM.kill) S({ m: '★syscall拦截 nr=' + nr, bt: bt(this.context) });
          args[0] = ptr(172);
        }
      } catch (e) { }
    }
  });
} catch (e) { S({ m: '✗ syscall: ' + e }); }

// frida字符串扫描隐藏: strstr系(返回NULL=没找到) / strcmp系(返回1=不相等)
var FRIDAMARK = /frida|gum|gmain|xinu|linjector|pool-frida|frida-agent|gadget|27042|27043/i;
['strstr', 'strcasestr'].forEach(function (n) {
  try {
    Interceptor.attach(Module.findExportByName(null, n), {
      onEnter: function (args) { try { this.nd = args[1].readCString(96); } catch (e) { this.nd = null; } },
      onLeave: function (ret) {
        try {
          if (this.nd && FRIDAMARK.test(this.nd) && !ret.isNull()) {
            ret.replace(ptr(0));
            caps.hide++;
            if (caps.hide <= LIM.hide) S({ m: '·隐藏' + n + ' needle=' + this.nd });
          }
        } catch (e) { }
      }
    });
  } catch (e) { }
});
['strcmp', 'strncmp', 'strcasecmp', 'strncasecmp'].forEach(function (n) {
  try {
    Interceptor.attach(Module.findExportByName(null, n), {
      onEnter: function (args) {
        try { this.s1 = args[0].readCString(96); this.s2 = args[1].readCString(96); } catch (e) { }
      },
      onLeave: function (ret) {
        try {
          if ((this.s1 && FRIDAMARK.test(this.s1)) || (this.s2 && FRIDAMARK.test(this.s2))) {
            ret.replace(ptr(1));
            caps.hide++;
            if (caps.hide <= LIM.hide) S({ m: '·隐藏' + n + ' ' + (this.s1 || this.s2) });
          }
        } catch (e) { }
      }
    });
  } catch (e) { }
});
S({ m: '✓ frida字符串隐藏(strstr/strcmp×6)' });

// dlopen日志(看壳/风控库装载顺序)
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

// 心跳
setInterval(function () { S({ t: 'hb', s: Math.floor(Date.now() / 1000) % 100000, caps: caps }); }, 15000);

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
