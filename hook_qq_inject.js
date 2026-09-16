// hook_qq_inject.js — 把 QQ 域 cookie 灌进 App 的 WebView（CookieManager 写入 + getCookie 拦截双保险）
// 目的：点 QQ 登录后，内嵌 WebView 打开 imgcache.qq.com/ptlogin/... 时自动带上我们的 QQ 会话 → 自动授权
function S(o) { try { send(o); } catch (e) { } }

var DIR = '/data/data/com.qidian.QDReader/files/';
var OUT = DIR + 'qq_inject.txt';
function W(line) {
  try {
    var fo = Java.use('java.io.FileOutputStream').$new(OUT, true);
    fo.write(Java.use('java.lang.String').$new(line + '\n').getBytes('UTF-8'));
    fo.close();
  } catch (e) { }
  S({ m: line });
}

function readText(p) {
  try {
    var f = Java.use('java.io.File').$new(p);
    if (!f.exists()) return null;
    var fis = Java.use('java.io.FileInputStream').$new(f);
    var b = Java.use('java.io.ByteArrayOutputStream').$new();
    var buf = Java.array('byte', new Array(65536).fill(0)); var n;
    while ((n = fis.read(buf)) > 0) b.write(buf, 0, n);
    fis.close();
    return Java.use('java.lang.String').$new(b.toByteArray(), 'UTF-8') + '';
  } catch (e) { return null; }
}

Java.perform(function () {
  try { var f = Java.use('java.io.File').$new(OUT); if (f.exists()) f.delete(); } catch (e) { }
  W('=== QQ cookie 注入 ===');

  var kv = {};
  try {
    var txt = readText('/data/local/tmp/qq_sess.json');
    if (txt) { kv = JSON.parse(txt); W('载入 ' + Object.keys(kv).length + ' 个 QQ cookie'); }
    else W('✗ /data/local/tmp/qq_sess.json 不存在');
  } catch (e) { W('解析失败 ' + e); }
  var names = Object.keys(kv);
  if (!names.length) { W('无 cookie，退出'); return; }

  // 拼成 cookie 串（供 getCookie 拦截返回）
  var cookieStr = names.map(function (k) { return k + '=' + kv[k]; }).join('; ');
  W('cookie 串长度=' + cookieStr.length);

  // ---------- ① 写入 CookieManager（多域名 + 变体）----------
  try {
    var cm = Java.use('android.webkit.CookieManager').getInstance();
    var urls = [
      'https://imgcache.qq.com', 'https://ptlogin2.qq.com', 'https://xui.ptlogin2.qq.com',
      'https://graph.qq.com', 'https://qq.com', 'https://www.qq.com',
      'https://qzs.qq.com', 'https://ssl.ptlogin2.qq.com', 'https://tauth.qq.com'
    ];
    urls.forEach(function (u) {
      names.forEach(function (k) {
        try { cm.setCookie(u, k + '=' + kv[k] + '; path=/; domain=.qq.com'); } catch (e) { }
      });
    });
    try { cm.flush(); } catch (e) { }
    W('✓ CookieManager 写入 ' + urls.length + ' 个域名');
    W('  验证 getCookie(imgcache.qq.com)=' + (cm.getCookie('https://imgcache.qq.com') ? 'NONEMPTY' : 'EMPTY'));
  } catch (e) { W('✗ CookieManager: ' + String(e).slice(0, 120)); }

  // ---------- ② 拦截 getCookie：凡是 qq.com 域，直接返回我们的 cookie ----------
  try {
    var CM = Java.use('android.webkit.CookieManager');
    CM.getCookie.overload('java.lang.String').implementation = function (url) {
      var orig = this.getCookie(url);
      try {
        if (url && url.indexOf('qq.com') >= 0) {
          var merged = cookieStr;
          if (orig && orig.length > 0) merged = orig + '; ' + cookieStr;
          W('[getCookie 拦截] ' + url.slice(0, 70) + ' → 返回 ' + merged.length + ' 字符');
          return merged;
        }
      } catch (e) { }
      return orig;
    };
    W('✓ 已 hook CookieManager.getCookie（qq.com 域强制带我们的 cookie）');
  } catch (e) { W('✗ hook getCookie: ' + String(e).slice(0, 120)); }

  // ---------- ③ 同时 hook WebView.loadUrl，记录它打开的 QQ 登录页 ----------
  try {
    var WV = Java.use('android.webkit.WebView');
    WV.loadUrl.overload('java.lang.String').implementation = function (u) {
      W('[WebView.loadUrl] ' + String(u).slice(0, 200));
      return this.loadUrl(u);
    };
    W('✓ 已 hook WebView.loadUrl');
  } catch (e) { W('· WebView.loadUrl 未挂: ' + String(e).slice(0, 80)); }

  // ---------- ④ hook QQ SDK 的登录/授权回调，看授权结果 ----------
  try {
    var TA = Java.use('com.tencent.tauth.Tencent');
    W('· 找到 com.tencent.tauth.Tencent');
  } catch (e) { }
  try {
    var IU = Java.use('com.tencent.tauth.IUiListener');
    W('· 找到 IUiListener');
  } catch (e) { }

  W('=== 注入完成 ===');
});
