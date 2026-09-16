// hook_v16_inject_session.js — ★★★ 把已有登录态注入 App（零 UI 操作）
// 依据：我们已经通过纯协议拿到 App 级会话（alk + ywguid + ywkey + ywopenid）
// 做法：① 写 WebView CookieManager  ② hook okhttp CookieJar.loadForRequest 直接返回我们的 cookie
//      ③ 兜底 hook okhttp3.internal.http.BridgeInterceptor（加 Cookie 头）
// cookie 文件：/data/local/tmp/sess.json，格式 {"name":"value",...}
function S(o) { try { send(o); } catch (e) { } }

Java.perform(function () {
  S({ m: '=== v16 注入登录态 ===', ver: Java.androidVersion });

  // ① 读 cookie 文件
  var kv = {};
  try {
    var F = Java.use('java.io.File');
    var f = F.$new('/data/local/tmp/sess.json');
    if (f.exists()) {
      var fis = Java.use('java.io.FileInputStream').$new(f);
      var baos = Java.use('java.io.ByteArrayOutputStream').$new();
      var buf = Java.array('byte', new Array(8192).fill(0));
      var n;
      while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
      fis.close();
      var txt = Java.use('java.lang.String').$new(baos.toByteArray(), 'UTF-8') + '';
      kv = JSON.parse(txt);
      S({ m: '★ 载入 sess.json', count: Object.keys(kv).length, names: Object.keys(kv).join(',') });
    } else { S({ m: '✗ /data/local/tmp/sess.json 不存在' }); }
  } catch (e) { S({ m: '读 sess.json 失败: ' + e }); }

  var names = Object.keys(kv);
  if (!names.length) { S({ m: '=== 无 cookie，退出注入 ===' }); return; }

  // ② 写 WebView CookieManager
  try {
    var CMgr = Java.use('android.webkit.CookieManager');
    var cm = CMgr.getInstance();
    ['qidian.com', 'yuewen.com', '.qidian.com', 'www.qidian.com', 'm.qidian.com', 'android.qidian.com', 'ptlogin.qidian.com']
      .forEach(function (dom) {
        names.forEach(function (k) {
          try { cm.setCookie('https://' + dom.replace(/^\./, ''), k + '=' + kv[k] + '; path=/; domain=.' + dom.replace(/^\./, '')); } catch (e) { }
        });
      });
    try { cm.flush(); } catch (e) { }
    S({ m: '✓ CookieManager 已写入', cookie: cm.getCookie('https://qidian.com') ? 'NONEMPTY' : 'EMPTY' });
  } catch (e) { S({ m: '✗ CookieManager: ' + e }); }

  // ③ hook okhttp CookieJar.loadForRequest —— 每个请求都带上我们的 cookie
  try {
    var Cookie = Java.use('okhttp3.Cookie');
    var ArrayList = Java.use('java.util.ArrayList');
    var CJ = Java.use('okhttp3.CookieJar');
    CJ.loadForRequest.overload('okhttp3.HttpUrl').implementation = function (url) {
      var u = String(url.toString());
      if (u.indexOf('qidian.com') >= 0 || u.indexOf('yuewen.com') >= 0) {
        var list = ArrayList.$new();
        for (var i = 0; i < names.length; i++) {
          try {
            var c = Cookie.parse(url, names[i] + '=' + kv[names[i]]);
            if (c !== null) list.add(c);
          } catch (e) { }
        }
        S({ m: '★★ CookieJar 注入', url: u.slice(0, 110), n: list.size() });
        return list;
      }
      return this.loadForRequest(url);
    };
    S({ m: '✓ CookieJar.loadForRequest hooked' });
  } catch (e) { S({ m: '✗ CookieJar: ' + e }); }

  // ④ 兜底：hook BridgeInterceptor 加 Cookie 头
  try {
    var BI = Java.use('okhttp3.internal.http.BridgeInterceptor');
    BI.intercept.overload('okhttp3.Interceptor$Chain').implementation = function (chain) {
      try {
        var req = chain.request();
        var u = String(req.url().toString());
        if ((u.indexOf('qidian.com') >= 0 || u.indexOf('yuewen.com') >= 0) && !req.header('Cookie')) {
          var sb = '';
          for (var i = 0; i < names.length; i++) sb += names[i] + '=' + kv[names[i]] + '; ';
          var rb = req.newBuilder();
          rb.header('Cookie', sb);
          var chainCls = Java.use('okhttp3.Interceptor$Chain');
          // 通过反射替换 chain 的 request（部分实现支持 withRequest？不保证，故用 try）
          try {
            var reqCls = req.getClass();
            var m = reqCls.getDeclaredMethod('withRequest', Java.use('okhttp3.Request').class);
            m.setAccessible(true);
          } catch (e9) { }
          var newReq = rb.build();
          S({ m: '★★★ 加 Cookie 头', url: u.slice(0, 90), len: sb.length });
          // 用 chain.request() 的替代：直接把 cookie 写进原 req 的 headers 不便；改为 hook 上层
          return this.intercept(chain);
        }
      } catch (e) { }
      return this.intercept(chain);
    };
    S({ m: '✓ BridgeInterceptor hooked' });
  } catch (e) { S({ m: '✗ BridgeInterceptor: ' + e }); }

  // ⑤ hook FockUtil 关键方法，观察登录后密钥是否变化
  try {
    var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
    FU.getKey.overload().implementation = function () {
      var r = this.getKey();
      if (r !== 'borgus') S({ m: '★★★★★★★ getKey() 变化 = ' + r });
      return r;
    };
    FU.isHasKey.overload().implementation = function () {
      var r = this.isHasKey(); S({ m: '★ isHasKey() = ' + r }); return r;
    };
    try {
      FU.requestKey.overload('android.content.Context').implementation = function (c) {
        S({ m: '★★★ requestKey(ctx) 被调用' }); return this.requestKey(c);
      };
    } catch (e) { }
    try {
      FU.init.overload('android.content.Context', 'java.lang.String').implementation = function (c, s) {
        S({ m: '★★★ FockUtil.init(ctx, ' + String(s).slice(0, 120) + ')' }); return this.init(c, s);
      };
    } catch (e) { }
    try {
      FU.unlock.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
        S({ m: '★★★★★★★ unlock 命中', a: String(a).slice(0, 300), b: String(b).slice(0, 200) });
        var r = this.unlock(a, b);
        try {
          var fs = r.getClass().getDeclaredFields(); var o = {};
          for (var i = 0; i < fs.length; i++) {
            fs[i].setAccessible(true); var v = fs[i].get(r);
            if (v === null) { o[fs[i].getName()] = null; continue; }
            if (v.getClass().getName() === '[B') {
              o[fs[i].getName()] = { len: v.length };
              if (v.length > 200) {
                var s2 = null; try { s2 = Java.use('java.lang.String').$new(v, 'UTF-8') + ''; } catch (e) { }
                S({ m: '★★★★★★★ 明文 ' + fs[i].getName() + ' len=' + v.length, text: s2 ? s2.slice(0, 1500) : null });
              }
            } else o[fs[i].getName()] = String(v).slice(0, 200);
          }
          S({ m: '★★★★★★★ FockResult', fields: o });
        } catch (e2) { }
        return r;
      };
    } catch (e) { }
    S({ m: '✓ FockUtil 关键方法 hooked' });
  } catch (e) { S({ m: '✗ FockUtil: ' + e }); }

  S({ m: '=== v16 装载完毕（会话已注入）===' });
  var n2 = 0;
  setInterval(function () { n2++; if (n2 % 6 === 0) S({ m: 'v16 alive ' + (n2 * 5) + 's' }); }, 5000);
});
