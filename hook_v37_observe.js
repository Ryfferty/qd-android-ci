// hook_v37_observe.js — 决定性观测：App 自己调 unlock 到底返回什么？
// 再做：requestKey(ctx, bookId) 让 App 自己去取密钥池
function S(o) { try { send(o); } catch (e) { } }

var OUT = '/data/data/com.qidian.QDReader/files/v37_result.txt';
function W(line) {
  try {
    var fos = Java.use('java.io.FileOutputStream').$new(OUT, true);
    fos.write(Java.use('java.lang.String').$new(line + '\n').getBytes('UTF-8'));
    fos.close();
  } catch (e) { }
  S({ m: line });
}

function desc(r) {
  if (r === null || r === undefined) return 'null';
  try {
    var out = {};
    var fs = r.getClass().getDeclaredFields();
    for (var i = 0; i < fs.length; i++) {
      fs[i].setAccessible(true);
      var v = fs[i].get(r);
      if (v === null) { out[fs[i].getName()] = null; continue; }
      if (v.getClass().getName() === '[B') {
        var s2 = null; try { s2 = Java.use('java.lang.String').$new(v, 'UTF-8') + ''; } catch (e) { }
        out[fs[i].getName()] = { len: v.length, head: (s2 || '').slice(0, 50) };
        if (v.length > 100) {
          var cn = 0; for (var k = 0; k < s2.length; k++) { var c = s2.charCodeAt(k); if (c >= 0x4e00 && c <= 0x9fff) cn++; }
          W('★★★★★★★ 明文！len=' + v.length + ' 中文字=' + cn);
          W('★★★ 正文: ' + s2.slice(0, 2500));
          try {
            var f2 = Java.use('java.io.FileOutputStream').$new('/data/data/com.qidian.QDReader/files/v37_plaintext.txt', false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));
            f2.close();
            W('★ 明文落盘成功');
          } catch (e) { }
        }
      } else out[fs[i].getName()] = String(v);
    }
    return JSON.stringify(out);
  } catch (e) { return 'refErr:' + e; }
}

function readText(p) {
  try {
    var f = Java.use('java.io.File').$new(p);
    if (!f.exists()) return null;
    var fis = Java.use('java.io.FileInputStream').$new(f);
    var baos = Java.use('java.io.ByteArrayOutputStream').$new();
    var buf = Java.array('byte', new Array(65536).fill(0)); var n;
    while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
    fis.close();
    return Java.use('java.lang.String').$new(baos.toByteArray(), 'UTF-8') + '';
  } catch (e) { return null; }
}

Java.perform(function () {
  try { var f = Java.use('java.io.File').$new(OUT); if (f.exists()) f.delete(); } catch (e) { }
  W('=== v37 观测版 ===');

  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  W('✓ FockUtil 可用');

  // ★ 核心：监听 App 自己的 unlock，并抓返回值
  try {
    FU.unlock.overload('java.lang.String', 'java.lang.String').implementation = function (ed, ak) {
      W('██ App 自己调 unlock: data.len=' + (ed || '').length + ' ak=' + ak);
      var r = this.unlock(ed, ak);
      W('██ 返回: ' + desc(r));
      return r;
    };
    W('✓ 已 hook unlock');
  } catch (e) { W('✗ hook unlock: ' + e); }

  try {
    FU.add.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
      W('██ App 自己调 add: key.len=' + (k || '').length + ' ver=' + v + ' head=' + (k || '').slice(0, 80));
      return this.add(k, v);
    };
    W('✓ 已 hook add');
  } catch (e) { W('✗ hook add: ' + e); }

  try {
    FU.init.overload('android.content.Context', 'java.lang.String').implementation = function (c, u) {
      W('██ App 自己调 init: userKey=' + u);
      return this.init(c, u);
    };
    W('✓ 已 hook init');
  } catch (e) { W('✗ hook init: ' + e); }

  try {
    FU.setPreUserKey.overload('java.lang.String').implementation = function (s) {
      W('██ setPreUserKey(' + s + ')');
      return this.setPreUserKey(s);
    };
    W('✓ 已 hook setPreUserKey');
  } catch (e) { W('✗ hook setPreUserKey: ' + e); }

  var ctx = null;
  try { ctx = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) { }
  var P = {};
  try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
  var bookId = String(P.book_id || '1049120379');
  var blobB64 = P.blob_b64 || '';
  var chId = String(P.chapter_id || '903350205');

  var ran = false;
  function go() {
    if (ran) return; ran = true;
    W('--- 主动阶段 ---');
    var inst = FU.INSTANCE.value;
    try { W('状态: isHasKey=' + inst.isHasKey() + ' getKey=' + inst.getKey() + ' preUserKey=' + inst.getPreUserKey()); } catch (e) { }

    // ★ 让 App 自己去请求密钥池
    try {
      W('① requestKey(ctx, ' + bookId + ') 调用');
      var job = inst.requestKey(ctx, Java.use('java.lang.Long').parseLong(bookId));
      W('① requestKey 返回 Job=' + job);
    } catch (e) { W('① requestKey 异常: ' + String(e).slice(0, 160)); }

    // 等一会儿让它异步完成
    try {
      Java.scheduleOnMainThread(function () { });
    } catch (e) { }

    setImmediate(function () {
      try {
        W('② requestKey 后状态: isHasKey=' + inst.isHasKey() + ' getKey=' + inst.getKey());
      } catch (e) { W('② ' + e); }
      // 再试 unlock
      if (blobB64) {
        try { W('③ unlock: ' + desc(inst.unlock(blobB64, chId))); } catch (e) { W('③ 异常: ' + e); }
      }
      W('--- 主动阶段结束 ---');
    });
  }

  try { Java.scheduleOnMainThread(function () { try { go(); } catch (e) { W('go 异常 ' + e); } }); }
  catch (e) { try { setImmediate(function () { try { go(); } catch (e2) { } }); } catch (e2) { } }
  W('=== v37 装载完毕 ===');
});
