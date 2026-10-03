// hook_fockgen20.js — v20: execve围剿
// v49复盘(r49): 拓扑钉死 zygote→WrapperInit(fork)→6000(sh→exec app_process=gadget宿主)
//   死因确认=SIGILL(WrapperInit把子进程wait-status编码成exit 132回报zygote)
//   但我们的SIGILL跳过器装在6000里且rt_sigaction(4)已锁死 — 却从未触发, 日志trail停在
//   libjiagu二次dlopen后 → 唯一自洽模型: 壳在中途execve自我重启(execve抹掉全部用户态
//   武器:gadget/hook/信号处理器, 唯独seccomp内核过滤器存活) → 新镜像(无gadget)检测
//   Seccomp_filters异常(本机setenforce 0, 正常app应为0, 我们的filter让它=1) → UD自杀→132
// v20: 堵execve(221)/execveat(281) — 正常app启动期不execve, 堵掉后壳无法抹武器
//      (UD→跳过器存活→自杀失败; 若壳另有反应, 诊断器/探针会给新信号)
// v48复盘三大发现:
//   ① 死亡=完全静默(诊断器4/6/7/8/11全装却从未触发, crash缓冲0字节, tombstone空, am无kill/anr)
//      → 壳先把我们的处理器rt_sigaction重置回SIG_DFL(134不在过滤器里!), 再UD→内核默认动作→零日志死
//   ② v16 BPF其实是"全堵kill家族"(手写扁平数组24条死代码, 假条件) — 网是好的, 但rt_sigaction是大洞
//   ③ SIGILL跳过处理器的pc偏移写304(那是sp!), 真pc=312; 且诊断器后装覆盖了sig4的跳过器
//   ④ Java桥从未成功(ArtMethod偏移@CreateVM太早 + Runtime::Start符号缺) → 即使活下来也零捕获
// 本版: BPF v3(标签汇编+模拟器24/24验证) 锁rt_sigaction(4,act≠0) + 堵prctl-STRICT + pc312修正
//      + 探针×3(kill/tgkill/prctl全EPERM才算活着) + Java桥定时器重试链(script模式gadget的GLib主循环)
var caps = { req: 0, geth: 0, resp: 0, ill: 0 };
var FOPEN2 = new NativeFunction(Module.findExportByName(null, 'fopen'), 'pointer', ['pointer', 'pointer']);
var FPUTS2 = new NativeFunction(Module.findExportByName(null, 'fputs'), 'int', ['pointer', 'pointer']);
var FCLOSE2 = new NativeFunction(Module.findExportByName(null, 'fclose'), 'int', ['pointer']);
var CAPFILE = '/data/data/com.qidian.QDReader/files/cap.jsonl';
function wcap(line) {
  try {
    var f = FOPEN2(Memory.allocUtf8String(CAPFILE), Memory.allocUtf8String('a'));
    if (f.isNull()) return;
    FPUTS2(Memory.allocUtf8String(String(line) + '\n'), f);
    FCLOSE2(f);
  } catch (e) { }
}
function S(o) { try { wcap(JSON.stringify(o)); } catch (e) { } }
S({ m: '⓪ v20 pid=' + Process.id + ' t=' + new Date().toISOString() });

// ★通用syscall: arm64 syscall(nr, a, b, c, d)
var SYSC5 = new NativeFunction(Module.findExportByName(null, 'syscall'), 'int',
  ['int', 'long', 'long', 'long', 'long']);
var SYSCP = new NativeFunction(Module.findExportByName(null, 'syscall'), 'int',
  ['int', 'long', 'pointer', 'pointer', 'long']);

// ① SIGILL跳过处理器 — pc在ucontext+312(v16写304是sp的bug), 跳过UD指令继续执行
//   必须在seccomp之前装(装完过滤器就锁死sig4的rt_sigaction了)
var illHandler = null;
try {
  illHandler = new NativeCallback(function (sig, info, ctx) {
    caps.ill++;
    try {
      var pc = ctx.add(312).readU64();
      var sp = ctx.add(304).readU64();
      var mm = '?';
      try {
        var r = Process.findRangeByAddress(ptr(pc.toString()));
        if (r) mm = (r.file ? String(r.file.path).split('/').pop() : 'anon') + '+' + ptr(pc.toString()).sub(r.base);
      } catch (e) { }
      ctx.add(312).writeU64(pc.add(4));
      if (caps.ill <= 30) S({ m: '★SIGILL跳过#' + caps.ill + ' pc=' + pc + ' sp=' + sp + ' @' + mm });
    } catch (e) { }
  }, 'void', ['int', 'pointer', 'pointer']);
  var SACT = Memory.alloc(152);
  SACT.writePointer(illHandler);
  SACT.add(8).writeU64(4);          // SA_SIGINFO
  var rr = SYSCP(134, 4, SACT, ptr(0), 8);
  S({ m: '✓SIGILL跳过处理器(sig4)已装 rt_sigaction=' + rr + ' [pc@312修正]' });
} catch (e) { S({ m: '✗SIGILL装: ' + e }); }

// ② 致命信号诊断器(6/7/8/11 — sig4归跳过器, 不再覆盖!) — 死前留pc+故障地址+挂起
var dfltHandler = null;
try {
  var SIGS = { 6: 'SIGABRT', 7: 'SIGBUS', 8: 'SIGFPE', 11: 'SIGSEGV' };
  dfltHandler = new NativeCallback(function (sig, info, ctx) {
    try {
      var pc = 0, addr = 0;
      try { pc = ctx.add(312).readU64(); } catch (e) { }
      try { addr = info.add(16).readU64(); } catch (e) { }
      var mm = '?';
      try {
        var r = Process.findRangeByAddress(ptr(pc.toString()));
        if (r) mm = (r.file ? String(r.file.path).split('/').pop() : 'anon') + '+' + ptr(pc.toString()).sub(r.base);
      } catch (e) { }
      S({ m: '★致命信号 ' + (SIGS[sig] || sig) + ' pc=' + pc + ' addr=' + addr + ' @' + mm + ' tid=' + Process.getCurrentThreadId() });
    } catch (e) { }
    for (;;) { }   // 诊断写盘后挂线程
  }, 'void', ['int', 'pointer', 'pointer']);
  var SACTD = Memory.alloc(152);
  SACTD.writePointer(dfltHandler);
  SACTD.add(8).writeU64(4);
  var SYSC5c = new NativeFunction(Module.findExportByName(null, 'syscall'), 'int',
    ['int', 'long', 'pointer', 'pointer', 'long']);
  for (var sg in SIGS) {
    var r2 = SYSC5c(134, parseInt(sg), SACTD, ptr(0), 8);
    if (r2 !== 0) S({ m: '✗sig' + sg + '诊断器装: ' + r2 });
  }
  S({ m: '✓致命信号诊断器已装(6/7/8/11, 不含4)' });
} catch (e) { S({ m: '✗诊断器: ' + e }); }

// ③ seccomp BPF v4 — 标签汇编+本地模拟器28/28验证, 29insn
//    相比v16: +锁rt_sigaction(4,act≠0) +堵prctl-STRICT +★v20堵execve/execveat(壳重exec抹武器)
var secInstalled = { gum: false, main: false };
function installSeccomp(where) {
  if (secInstalled[where]) return;
  secInstalled[where] = 1;
  try {
    var BPFv19 = [
      [0x20, 0, 0, 4],
      [0x15, 1, 0, 3221225655],
      [0x06, 0, 0, 2147418112],
      [0x20, 0, 0, 0],
      [0x15, 22, 0, 93],
      [0x15, 21, 0, 94],
      [0x15, 10, 0, 129],
      [0x15, 19, 0, 130],
      [0x15, 18, 0, 131],
      [0x15, 17, 0, 138],
      [0x15, 16, 0, 240],
      [0x15, 15, 0, 424],
      [0x15, 6, 0, 134],
      [0x15, 13, 0, 221],
      [0x15, 12, 0, 281],
      [0x15, 7, 12, 167],
      [0x06, 0, 0, 2147418112],
      [0x20, 0, 0, 24],
      [0x15, 8, 9, 9],
      [0x20, 0, 0, 16],
      [0x15, 0, 7, 4],
      [0x20, 0, 0, 24],
      [0x15, 5, 4, 0],
      [0x20, 0, 0, 16],
      [0x15, 0, 3, 22],
      [0x20, 0, 0, 24],
      [0x15, 0, 1, 1],
      [0x06, 0, 0, 327681],
      [0x06, 0, 0, 2147418112]
    ];
    var flt = Memory.alloc(BPFv19.length * 8);
    BPFv19.forEach(function (b, i) {
      var a = flt.add(i * 8);
      a.writeU16(b[0]); a.add(2).writeU8(b[1]); a.add(3).writeU8(b[2]); a.add(4).writeU32(b[3]);
    });
    var fprog = Memory.alloc(16);
    fprog.writeU16(BPFv19.length);
    fprog.add(8).writePointer(flt);
    var prctlF = new NativeFunction(Module.findExportByName(null, 'prctl'), 'int', ['int', 'long', 'pointer', 'long', 'long']);
    var r1 = prctlF(38, 1, ptr(0), 0, 0);
    var r2 = prctlF(22, 2, fprog, 0, 0);
    S({ m: '✓seccomp v3@' + where + '(线程=' + Process.getCurrentThreadId() + '): ' + r1 + '/' + r2 });
  } catch (e) { S({ m: '✗seccomp@' + where + ': ' + e }); }
}
installSeccomp('gum');

// ④ 三探针 — 全EPERM=网活着(kill探针已证; tgkill/prctl是v19新增的真正致命通路探针)
try {
  var kr = SYSC5(129, Process.id, 9, 0, 0);
  S({ m: '★探针1 kill(self,9)=' + kr + (kr === -1 ? ' EPERM✓' : ' ✗✗穿了') });
  var tid = SYSC5(178, 0, 0, 0, 0);
  var tr = SYSC5(131, Process.id, tid, 9, 0);
  S({ m: '★探针2 tgkill(self,tid,9)=' + tr + (tr === -1 ? ' EPERM✓' : ' ✗✗穿了') });
  var pr = SYSC5(167, 22, 1, 0, 0);
  S({ m: '★探针3 prctl(22,STRICT)=' + pr + (pr === -1 ? ' EPERM✓(内核杀路已堵)' : ' ✗✗穿了') });
} catch (e) { S({ m: '✗探针: ' + e }); }

// ⑤ env键名10字节覆写(一次性内存写, 非钩子)
try {
  var envpp = Module.findExportByName(null, 'environ');
  var envArr = envpp.readPointer();
  var key = [0x51, 0x44, 0x5F, 0x50, 0x52, 0x45, 0x4C, 0x4F, 0x41, 0x44];
  for (var ei = 0; ; ei++) {
    var ep = envArr.add(ei * 8).readPointer();
    if (ep.isNull()) break;
    try {
      var es = ep.readCString(16);
      if (es && es.indexOf('LD_PRELOAD=') === 0) { ep.writeByteArray(key); S({ m: '✓LD_PRELOAD键名已覆写' }); break; }
    } catch (e2) { }
  }
} catch (e) { S({ m: '✗env覆写: ' + e }); }

// ⑥ 同步链 + Java桥定时器重试(v19新增: script模式gadget的GLib主循环活着,
//    v48教训: CreateVM瞬间ArtMethod偏移算不出, Runtime::Start符号缺 → 48个周期Java桥0次成功)
(function () {
  try {
    var mods = Process.enumerateModules().map(function (m) { return m.name; });
    S({ m: '·模块数=' + mods.length, art: mods.filter(function (n) { return /art|ssl|crypto|conscrypt/i.test(n); }).join(',') });
  } catch (e) { }
  var jcvm = Module.findExportByName(null, 'JNI_CreateJavaVM');
  var sslInstalled = false, sslNames = '';
  function installSSLHook(from) {
    if (sslInstalled) return;
    try {
      var sslw = Module.findExportByName(null, 'SSL_write');
      if (sslw) {
        Interceptor.attach(sslw, {
          onEnter: function (args) {
            try {
              var num = args[2].toInt32();
              if (num > 0 && num < 16384) {
                var data = args[1].readCString(Math.min(num, 2048)) || '';
                if (data.length > 0) S({ t: 'SSLW', n: (caps.resp++), len: num, head: data.slice(0, 600) });
              }
            } catch (e) { }
          }
        });
        sslInstalled = true; sslNames += 'SSL_write ';
      }
      if (sslNames) S({ m: '✓SSL钩@dlopen(' + from + '): ' + sslNames.slice(0, 200) });
    } catch (e) { S({ m: '✗SSL钩: ' + e }); }
  }
  function onDlopenLeave(path) {
    S({ m: '·dlopen: ' + String(path).slice(0, 90) });
    if (/libjiagu|conscrypt|libssl|okhttp|qidian/i.test(path)) installSSLHook(String(path).split('/').pop());
  }
  ['__loader_android_dlopen_ext', '__loader_dlopen'].forEach(function (ln) {
    try {
      var la = Module.findExportByName('linker64', ln) || Module.findExportByName(null, ln);
      if (la) {
        Interceptor.attach(la, {
          onEnter: function (args) { try { this.p = args[0].readCString(); } catch (e) { this.p = null; } },
          onLeave: function (r) { if (this.p) onDlopenLeave(this.p); }
        });
        S({ m: '✓linker!' + ln + '钩已挂' });
      } else S({ m: '·linker符号缺: ' + ln });
    } catch (e) { }
  });
  if (!jcvm) { S({ m: '✗JNI_CreateJavaVM未找到' }); return; }

  var javaStageDone = false;
  function tryJavaStage(from) {
    if (javaStageDone) return true;
    try {
      Java.perform(function () { javaStageDone = true; javaStageInner(from); });
      return true;
    } catch (e) {
      S({ m: '✗Java桥@' + from + ': ' + String(e).slice(0, 120) });
      return false;
    }
  }
  // ★定时器重试链: 每700ms试一次, 最多40次(~28s窗口) — CreateVM后运行时逐步就绪, 总有一次能过
  var jr = 0;
  function javaRetry() {
    if (javaStageDone) return;
    jr++;
    var avail = '?';
    try { avail = String(Java.available); } catch (e) { }
    S({ m: '·Java重试#' + jr + ' available=' + avail });
    if (tryJavaStage('timer' + jr)) { S({ m: '✓Java桥第' + jr + '次重试已提交' }); return; }
    if (jr < 60) setTimeout(javaRetry, 700);
    else S({ m: '✗Java桥60次重试全败' });
  }
  setTimeout(javaRetry, 300);

  Interceptor.attach(jcvm, {
    onEnter: function (a) {
      // seccomp线程级: 主线程(壳所在)必须自己装一遍
      installSeccomp('main');
    },
    onLeave: function (r) {
      try {
        S({ m: '★JNI_CreateJavaVM返回 ret=' + r });
        tryJavaStage('CreateVM');
        if (!javaStageDone) {
          try {
            var rstart = Module.findExportByName(null, '_ZN3art7Runtime5StartEv');
            if (rstart) {
              Interceptor.attach(rstart, {
                onLeave: function () { S({ m: '★art::Runtime::Start返回' }); tryJavaStage('RuntimeStart'); }
              });
              S({ m: '✓art::Runtime::Start钩已挂(第二级触发)' });
            } else S({ m: '·Runtime::Start符号缺(靠定时器重试链)' });
          } catch (e2) { }
        }
      } catch (e) { S({ m: '✗同步链: ' + e }); }
    }
  });

  function javaStageInner(from) {
    S({ m: '② Java桥OK@' + from + ', 装loadClass狙击手' });
    var sniperInstalled = 0, bizInstalled = 0;
    function installBiz() {
      if (bizInstalled) return; bizInstalled = 1;
      try {
        var ReqB = Java.use('okhttp3.Request$Builder');
        var ov = ReqB.build.overload();
        ov.implementation = function () {
          var rq = ov.call(this);
          try {
            var url = String(rq.url());
            if (/qidian\.com|yuewen\.com|qq\.com/.test(url) && !/\.(png|jpg|jpeg|webp|gif|svg|ico|mp4)(\?|$)/.test(url)) {
              caps.req++;
              if (caps.req <= 300) {
                var h = rq.headers();
                var it = h.names().iterator();
                var hd = [];
                while (it.hasNext()) { var k = String(it.next()); hd.push(k + ': ' + String(h.get(k))); }
                var bodyS = '';
                try {
                  var b = rq.body();
                  if (b !== null) { var Buf = Java.use('okio.Buffer'); var buf = Buf.$new(); b.writeTo(buf); bodyS = String(buf.readUtf8()); if (bodyS.length > 400) bodyS = bodyS.slice(0, 400) + '…'; }
                } catch (e) { }
                S({ t: 'REQ', n: caps.req, method: String(rq.method()), url: url, headers: hd, body: bodyS });
              }
            }
          } catch (e) { }
          return rq;
        };
        S({ m: '✓okhttp build钩已装' });
      } catch (e) { S({ m: '✗okhttp钩: ' + e }); }
      try {
        var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
        var ovH = FU.getH.overload('java.lang.String', 'java.lang.String', 'okhttp3.RequestBody');
        ovH.implementation = function (url, method, body) {
          var ret = ovH.call(this, url, method, body);
          try {
            caps.geth++;
            if (caps.geth <= 150) {
              var hm = [];
              var it = ret.entrySet().iterator();
              while (it.hasNext()) { var en = Java.cast(it.next(), Java.use('java.util.Map$Entry')); hm.push(String(en.getKey()) + ': ' + String(en.getValue())); }
              var bs = '';
              try { if (body !== null) { var Buf = Java.use('okio.Buffer'); var b = Buf.$new(); body.writeTo(b); bs = String(b.readUtf8()).slice(0, 300); } } catch (e) { }
              S({ t: 'GETH', n: caps.geth, url: String(url), method: String(method), body: bs, out: hm });
            }
          } catch (e) { }
          return ret;
        };
        S({ m: '✓getH(VMP native桩)钩已装' });
      } catch (e) { S({ m: '✗getH钩: ' + e }); }
    }
    function installSSL() {
      try {
        var sslw = Module.findExportByName(null, 'SSL_write');
        if (!sslw) return;
        Interceptor.attach(sslw, {
          onEnter: function (args) {
            try {
              var num = args[2].toInt32();
              if (num > 0 && num < 16384) {
                var data = args[1].readCString(Math.min(num, 2048)) || '';
                if (data.length > 0) S({ t: 'SSLW', n: (caps.resp++), len: num, head: data.slice(0, 600) });
              }
            } catch (e) { }
          }
        });
        S({ m: '✓SSL_write明文钩已装' });
      } catch (e) { S({ m: '✗SSL钩: ' + e }); }
    }
    var CL = Java.use('java.lang.ClassLoader');
    var TARGETS = /^okhttp3\.Request\$Builder$|^com\.qidian\.QDReader\.component\.util\.FockUtil$|^okhttp3\.OkHttpClient$|^com\.android\.org\.conscrypt/;
    var ovl = CL.loadClass.overload('java.lang.String', 'boolean');
    ovl.implementation = function (name, resolve) {
      var cls = ovl.call(this, name, resolve);
      try {
        if (!sniperInstalled && TARGETS.test(String(name))) {
          sniperInstalled = 1;
          S({ m: '③ 命中类加载: ' + name });
          installBiz(); installSSL();
        }
      } catch (e) { }
      return cls;
    };
    var ovs = CL.loadClass.overload('java.lang.String');
    ovs.implementation = function (name) {
      var cls = ovs.call(this, name);
      try {
        if (!sniperInstalled && TARGETS.test(String(name))) {
          sniperInstalled = 1;
          S({ m: '③ 命中类加载: ' + name });
          installBiz(); installSSL();
        }
      } catch (e) { }
      return cls;
    };
    S({ m: '✓loadClass狙击手已装' });
  }
  S({ m: '✓libart!JNI_CreateJavaVM钩已挂(pre-ART)' });
})();
