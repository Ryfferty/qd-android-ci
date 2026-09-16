// hook_v41_oneshot.js — 单会话完成全部步骤（用 Java Handler 做延时，不依赖 frida 定时器）
function S(o) { try { send(o); } catch (e) { } }
var DIR = '/data/data/com.qidian.QDReader/files/';
var OUT = DIR + 'v41a_result.txt';
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
        o[fs[i].getName()] = { len: v.length, head: (s2 || '').slice(0, 50) };
        if (v.length > 100) {
          var cn = 0; for (var k = 0; k < s2.length; k++) { var c = s2.charCodeAt(k); if (c >= 0x4e00 && c <= 0x9fff) cn++; }
          S({ m: '★★★★★★★ 明文！len=' + v.length + ' 中文字=' + cn });
          S({ m: '★★★ 正文', text: s2.slice(0, 3000) });
          try {
            var f2 = Java.use('java.io.FileOutputStream').$new(DIR + 'v41_plaintext.txt', false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8')); f2.close();
            W('★ 明文已落盘 v41_plaintext.txt');
          } catch (e) { }
        }
      } else o[fs[i].getName()] = String(v);
    }
    return JSON.stringify(o);
  } catch (e) { return 'refErr:' + e; }
}

Java.perform(function () {
  try { var f = Java.use('java.io.File').$new(OUT); if (f.exists()) f.delete(); } catch (e) { }
  W('=== v41a 注入+init+requestKey ===');

  // ---------- ① 注入 cookie ----------
  var kv = {};
  try {
    var txt = readText('/data/local/tmp/sess.json');
    if (txt) { kv = JSON.parse(txt); W('① 载入 sess.json: ' + Object.keys(kv).length + ' 个 cookie'); }
    else W('① ✗ sess.json 不存在');
  } catch (e) { W('① 读 sess.json 失败: ' + e); }
  var names = Object.keys(kv);
  if (names.length) {
    try {
      var cm = Java.use('android.webkit.CookieManager').getInstance();
      ['qidian.com', 'yuewen.com'].forEach(function (dom) {
        names.forEach(function (k) {
          try { cm.setCookie('https://' + dom, k + '=' + kv[k] + '; path=/; domain=.' + dom); } catch (e) { }
        });
      });
      try { cm.flush(); } catch (e) { }
      W('① CookieManager: ' + (cm.getCookie('https://qidian.com') ? 'NONEMPTY' : 'EMPTY'));
    } catch (e) { W('① CookieManager 异常: ' + e); }
    // okhttp CookieJar 兜底
    try {
      var Cookie = Java.use('okhttp3.Cookie');
      var Builder = Java.use('okhttp3.Cookie$Builder');
      var jarCls = Java.use('okhttp3.CookieJar');
      var CookieJarImpl = Java.registerClass({
        name: 'com.fock.MyJar' + Date.now(),
        implements: [jarCls],
        methods: {
          loadForRequest: function (url) {
            var list = Java.use('java.util.ArrayList').$new();
            try {
              names.forEach(function (k) {
                var b = Builder.$new();
                b.name(k); b.value(kv[k]);
                b.domain(url.host()); b.path('/');
                try { list.add(b.build()); } catch (e) { }
              });
            } catch (e) { }
            return list;
          },
          saveFromResponse: function (url, list) { }
        }
      });
      W('① okhttp CookieJar 类已注册（供参考）');
    } catch (e) { W('① okhttp jar: ' + String(e).slice(0, 120)); }
  }

  // ---------- ② FockUtil ----------
  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  var ctx = null;
  try { ctx = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) { }
  W('② ctx=' + ctx + ' FockUtil=' + (FU !== null));

  var P = {};
  try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
  var keyA = P.Key || '', ver = String(P.Version || ''), blobB64 = P.blob_b64 || '';
  var chId = String(P.chapter_id || '903350205'), bookId = String(P.book_id || '1049120379');
  var ywg = String(P.ywguid || '');
  W('② params: Key=' + keyA.length + ' ver=' + ver + ' blob=' + blobB64.length + ' ch=' + chId + ' ywg=' + ywg);

  var inst = FU.INSTANCE.value;

  function phase2() {
    W('--- ④ 延时后阶段 ---');
    try { W('④ 状态: isHasKey=' + inst.isHasKey() + ' getKey=' + inst.getKey() + ' preUserKey=' + inst.getPreUserKey()); } catch (e) { }
    try { inst.add(keyA, ver); W('⑤ add(Key,' + ver + ') OK isHasKey=' + inst.isHasKey()); } catch (e) { W('⑤ add 异常 ' + String(e).slice(0, 150)); }
    if (blobB64) {
      try { W('⑥ unlock(base64密文 ' + blobB64.length + ', ak=' + chId + '): ' + desc(inst.unlock(blobB64, chId))); }
      catch (e) { W('⑥ unlock 异常 ' + String(e).slice(0, 200)); }
    }
    W('=== v41 结束 ===');
  }

  // ---------- ③ init + requestKey，然后用 Java Handler 延时 ----------
  Java.scheduleOnMainThread(function () {
    try { if (ctx && ywg) { inst.init(ctx, ywg); W('③ init(ctx,' + ywg + ') OK preUserKey=' + inst.getPreUserKey()); } }
    catch (e) { W('③ init 异常 ' + String(e).slice(0, 150)); }
    try {
      var job = inst.requestKey(ctx, Java.use('java.lang.Long').parseLong(bookId));
      W('③ requestKey(ctx,' + bookId + ') 已发起');
    } catch (e) { W('③ requestKey 异常 ' + String(e).slice(0, 200)); }

    W('③ requestKey 已发起，本会话结束（由 bash sleep 后再跑 v41b）');
  });

  W('=== v41 装载完毕 ===');
});
