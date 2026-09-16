// hook_v43_net.js — App 端协议：抓 App 自己的网络请求 + FockUtil 调用
// 目标：看清 App 自己怎么请求密钥池、响应是什么、怎么调 add/unlock
function S(o) { try { send(o); } catch (e) { } }

var DIR = '/data/data/com.qidian.QDReader/files/';
var OUT = DIR + 'v43_result.txt';
function W(line) {
  try {
    var fo = Java.use('java.io.FileOutputStream').$new(OUT, true);
    fo.write(Java.use('java.lang.String').$new(line + '\n').getBytes('UTF-8'));
    fo.close();
  } catch (e) { }
}
function clip(s, n) { try { s = String(s); return s.length > n ? s.slice(0, n) + '…[' + s.length + ']' : s; } catch (e) { return '?'; } }

function desc(r) {
  if (r === null || r === undefined) return 'null';
  try {
    var o = {};
    var fs = r.getClass().getDeclaredFields();
    for (var i = 0; i < fs.length; i++) {
      fs[i].setAccessible(true);
      var v = fs[i].get(r);
      if (v === null) { o[fs[i].getName()] = null; continue; }
      if (v.getClass().getName() === '[B') {
        var s2 = null; try { s2 = Java.use('java.lang.String').$new(v, 'UTF-8') + ''; } catch (e) { }
        o[fs[i].getName()] = 'len=' + v.length;
        if (v.length > 100) {
          var cn = 0; for (var k = 0; k < s2.length; k++) { var c = s2.charCodeAt(k); if (c >= 0x4e00 && c <= 0x9fff) cn++; }
          W('★★★★★★★ 明文！len=' + v.length + ' 中文字=' + cn);
          W('★★★ 正文: ' + s2.slice(0, 2000));
          try {
            var f2 = Java.use('java.io.FileOutputStream').$new(DIR + 'v43_plaintext.txt', false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8')); f2.close();
          } catch (e) { }
        }
      } else o[fs[i].getName()] = clip(v, 60);
    }
    return JSON.stringify(o);
  } catch (e) { return 'refErr:' + e; }
}

Java.perform(function () {
  try { var f = Java.use('java.io.File').$new(OUT); if (f.exists()) f.delete(); } catch (e) { }
  W('=== v43 App 端网络+组件观测 ===');

  // ---------- ① hook okhttp 响应（抓 App 自己的请求与响应） ----------
  try {
    var RB = Java.use('okhttp3.ResponseBody');
    RB.string.implementation = function () {
      var body = this.string();
      try {
        var resp = this; // 尝试拿请求 URL 不方便，改从 Request 侧抓
        if (body && body.length > 40) {
          W('[HTTP 响应] len=' + body.length + ' head=' + clip(body, 240));
        }
      } catch (e) { }
      return body;
    };
    W('✓ hook okhttp ResponseBody.string');
  } catch (e) { W('✗ hook ResponseBody: ' + String(e).slice(0, 120)); }

  // ---------- ② hook okhttp 请求 URL ----------
  try {
    var RC = Java.use('okhttp3.internal.http.RealInterceptorChain');
    RC.proceed.overload('okhttp3.Request').implementation = function (req) {
      try {
        var url = req.url().toString();
        var hdrs = req.headers().toString();
        if (/fock|key|content|chapter/i.test(url)) {
          W('[HTTP 请求] ' + clip(url, 220));
          W('   头: ' + clip(hdrs.replace(/\n/g, ' | '), 300));
        }
      } catch (e) { }
      return this.proceed(req);
    };
    W('✓ hook okhttp 请求');
  } catch (e) { W('✗ hook 请求: ' + String(e).slice(0, 120)); }

  // ---------- ③ hook FockUtil 的 add / unlock ----------
  try {
    var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
    FU.add.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
      W('██ App 调 FockUtil.add: key.len=' + (k || '').length + ' ver=' + v + ' key.head=' + clip(k, 200));
      return this.add(k, v);
    };
    FU.unlock.overload('java.lang.String', 'java.lang.String').implementation = function (ed, ak) {
      W('██ App 调 FockUtil.unlock: data.len=' + (ed || '').length + ' ak=' + ak + ' data.head=' + clip(ed, 160));
      var r = this.unlock(ed, ak);
      W('██ unlock 返回: ' + desc(r));
      return r;
    };
    W('✓ hook FockUtil.add / unlock');
  } catch (e) { W('✗ hook FockUtil: ' + String(e).slice(0, 120)); }

  // ---------- ④ 状态 ----------
  try {
    var fu = Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
    W('初始状态: isHasKey=' + fu.isHasKey() + ' getKey=' + clip(fu.getKey(), 60) + ' preUserKey=' + clip(fu.getPreUserKey(), 40));
  } catch (e) { W('状态查询失败 ' + String(e).slice(0, 100)); }

  W('=== v43 装载完毕（开始被动观测）===');
});
