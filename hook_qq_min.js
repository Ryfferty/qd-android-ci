// hook_qq_inject_min.js — 最小侵入版：只做 CookieManager 写入，不挂任何 hook
// 上一版挂了 WebView.loadUrl / CookieManager.getCookie 后 App 退出，疑似 hook 触发问题
function S(o) { try { send(o); } catch (e) { } }

var DIR = '/data/data/com.qidian.QDReader/files/';
var OUT = DIR + 'qq_min.txt';
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
  W('=== 最小注入版（无 hook）===');

  var kv = {};
  try {
    var txt = readText('/data/local/tmp/qq_sess.json');
    if (txt) { kv = JSON.parse(txt); W('载入 ' + Object.keys(kv).length + ' 个 QQ cookie'); }
    else { W('✗ 无 qq_sess.json'); return; }
  } catch (e) { W('解析失败 ' + e); return; }
  var names = Object.keys(kv);
  if (!names.length) return;

  // 只写 CookieManager，不做任何 hook
  try {
    var cm = Java.use('android.webkit.CookieManager').getInstance();
    var urls = ['https://imgcache.qq.com', 'https://ptlogin2.qq.com', 'https://xui.ptlogin2.qq.com',
      'https://graph.qq.com', 'https://qq.com', 'https://qzs.qq.com', 'https://tauth.qq.com'];
    var ok = 0;
    urls.forEach(function (u) {
      names.forEach(function (k) {
        try { cm.setCookie(u, k + '=' + kv[k] + '; path=/; domain=.qq.com'); ok++; } catch (e) { }
      });
    });
    try { cm.flush(); } catch (e) { }
    W('✓ 写入尝试 ' + ok + ' 次');
    W('  验证 getCookie(imgcache.qq.com)=' + (cm.getCookie('https://imgcache.qq.com') ? 'NONEMPTY' : 'EMPTY'));
  } catch (e) { W('✗ CookieManager: ' + String(e).slice(0, 120)); }

  W('=== 最小注入完成（未挂任何 hook）===');
});
