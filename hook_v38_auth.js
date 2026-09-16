// hook_v38_auth.js — 已注入登录态后：观测 + 主动 requestKey + 正确格式 unlock
// 前置：已用 v16 注入 cookie，并重启过 App（让 App 以登录态运行）
function S(o) { try { send(o); } catch (e) { } }

var OUT = '/data/data/com.qidian.QDReader/files/v38_result.txt';
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
            var f2 = Java.use('java.io.FileOutputStream').$new('/data/data/com.qidian.QDReader/files/v38_plaintext.txt', false);
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
  W('=== v38 已登录态流程 ===');

  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  W('✓ FockUtil 可用');

  // 观测 App 自身调用
  try {
    FU.unlock.overload('java.lang.String', 'java.lang.String').implementation = function (ed, ak) {
      W('██ App 调 unlock: data.len=' + (ed || '').length + ' ak=' + ak);
      var r = this.unlock(ed, ak);
      W('██ unlock 返回: ' + desc(r));
      return r;
    };
    W('✓ hook unlock');
  } catch (e) { }
  try {
    FU.add.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
      W('██ App 调 add: key.len=' + (k || '').length + ' ver=' + v);
      return this.add(k, v);
    };
    W('✓ hook add');
  } catch (e) { }
  try {
    FU.init.overload('android.content.Context', 'java.lang.String').implementation = function (c, u) {
      W('██ App 调 init: userKey=' + u);
      return this.init(c, u);
    };
    W('✓ hook init');
  } catch (e) { }

  var ctx = null;
  try { ctx = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) { }
  var P = {};
  try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
  var bookId = String(P.book_id || '1049120379');
  var blobB64 = P.blob_b64 || '';
  var chId = String(P.chapter_id || '903350205');
  var ywg = String(P.ywguid || '');
  var keyA = P.Key || '', ver = String(P.Version || '');
  W('params: Key=' + keyA.length + ' ver=' + ver + ' blob=' + blobB64.length + ' ch=' + chId + ' ywguid=' + ywg);

  var ran = false;
  function go() {
    if (ran) return; ran = true;
    W('--- 主动阶段 ---');
    var inst = FU.INSTANCE.value;

    // ① init 设 userKey（FockUtil 层）
    if (ctx && ywg) { try { inst.init(ctx, ywg); W('① init(ctx, ywguid) OK'); } catch (e) { W('① init: ' + String(e).slice(0, 120)); } }
    // ② requestKey：让 App 去取密钥池（此时已登录，应有资格）
    try {
      W('② requestKey(ctx, ' + bookId + ') 调用…');
      var job = inst.requestKey(ctx, Java.use('java.lang.Long').parseLong(bookId));
      W('② requestKey 返回 Job=' + job);
    } catch (e) { W('② requestKey 异常: ' + String(e).slice(0, 180)); }

    // 等 12 秒让异步请求完成
    setTimeout(function () {
      try {
        W('③ requestKey 后: isHasKey=' + inst.isHasKey() + ' getKey=' + inst.getKey() + ' preUserKey=' + inst.getPreUserKey());
      } catch (e) { }
      // ④ 装密钥池（argus 拿的）
      try { inst.add(keyA, ver); W('④ add(Key,' + ver + ') OK isHasKey=' + inst.isHasKey()); } catch (e) { W('④ add: ' + String(e).slice(0, 120)); }
      // ⑤ unlock（正解格式）
      if (blobB64) {
        try { W('⑤ unlock(base64密文, 章节ID): ' + desc(inst.unlock(blobB64, chId))); }
        catch (e) { W('⑤ unlock 异常: ' + String(e).slice(0, 180)); }
      }
      W('--- 主动阶段结束 ---');
    }, 12000);
  }

  try { Java.scheduleOnMainThread(function () { try { go(); } catch (e) { W('go 异常 ' + e); } }); }
  catch (e) { try { setImmediate(function () { try { go(); } catch (e2) { } }); } catch (e2) { } }
  W('=== v38 装载完毕 ===');
});
