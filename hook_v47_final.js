// hook_v47_final.js — 用 frida 直接调用（不用反射），按 App 反编译的真实序：
//  ① e.L() 拿 userKey（QIMEI）
//  ② FockUtil.init(ctx, qimei)
//  ③ FockUtil.save(ctx, key, version)     ← 关键新步骤
//  ④ FockUtil.add(key, version)
//  ⑤ FockUtil.unlock(密文b64, 章节ID)
function S(o) { try { send(o); } catch (e) { } }
var DIR = '/data/data/com.qidian.QDReader/files/';
var OUT = DIR + 'v47_result.txt';
function W(line) {
  try {
    var fo = Java.use('java.io.FileOutputStream').$new(OUT, true);
    fo.write(Java.use('java.lang.String').$new(line + '\n').getBytes('UTF-8'));
    fo.close();
  } catch (e) { }
  S({ m: line });
}
function clip(s, n) { try { s = String(s); return s.length > n ? s.slice(0, n) + '…[' + s.length + ']' : s; } catch (e) { return '?'; } }
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
        o[fs[i].getName()] = 'len=' + v.length;
        if (v.length > 100) {
          var cn = 0; for (var k = 0; k < s2.length; k++) { var c = s2.charCodeAt(k); if (c >= 0x4e00 && c <= 0x9fff) cn++; }
          W('★★★★★★★ 明文！len=' + v.length + ' 中文字=' + cn);
          W('★★★ 正文: ' + s2.slice(0, 2000));
          try {
            var f2 = Java.use('java.io.FileOutputStream').$new(DIR + 'v47_plaintext.txt', false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8')); f2.close(); W('★ 明文落盘');
          } catch (e) { }
        }
      } else o[fs[i].getName()] = clip(v, 80);
    }
    return JSON.stringify(o);
  } catch (e) { return 'refErr:' + e; }
}

Java.perform(function () {
  try { var f = Java.use('java.io.File').$new(OUT); if (f.exists()) f.delete(); } catch (e) { }
  W('=== v47 frida 直接调用版 ===');

  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  var ctx = null;
  try { ctx = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) { }
  W('ctx=' + ctx);

  var qimei = null;
  try { qimei = String(Java.use('com.qidian.QDReader.core.config.e').L()); W('★ e.L() userKey = [' + clip(qimei, 80) + ']'); }
  catch (e) { W('e.L() 失败: ' + String(e).slice(0, 120)); }

  var P = {};
  try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
  var keyA = P.Key || '', ver = String(P.Version || ''), blobB64 = P.blob_b64 || '';
  var chId = String(P.chapter_id || '903350205');
  W('params: Key=' + keyA.length + ' ver=' + ver + ' blob=' + blobB64.length + ' ch=' + chId);

  var ran = false;
  function go() {
    if (ran) return; ran = true;
    W('--- 主线程开始 ---');
    var inst = FU.INSTANCE.value;

    // ② init
    try { inst.init(ctx, qimei); W('② init(ctx, e.L()) OK → preUserKey=' + clip(inst.getPreUserKey(), 60)); }
    catch (e) { W('② init 异常: ' + String(e).slice(0, 160)); }

    // 状态
    try { W('  isHasKey=' + inst.isHasKey() + ' getKey=' + clip(inst.getKey(), 60)); } catch (e) { }

    // ③ save（关键步骤）
    try { inst.save(ctx, keyA, ver); W('③ save(ctx, Key, ' + ver + ') OK'); }
    catch (e) { W('③ save 异常: ' + String(e).slice(0, 180)); }

    // ③b 读回本地密钥池
    try { W('  getKeyMap()=' + clip(inst.getKeyMap(ctx), 200)); } catch (e) { W('  getKeyMap 异常: ' + String(e).slice(0, 100)); }
    try { W('  loadLocalKey()=' + clip(inst.loadLocalKey(ctx), 200)); } catch (e) { W('  loadLocalKey 异常: ' + String(e).slice(0, 100)); }
    try { W('  isHasKey=' + inst.isHasKey() + ' getKey=' + clip(inst.getKey(), 60)); } catch (e) { }

    // ④ add
    try { inst.add(keyA, ver); W('④ add(Key, ' + ver + ') OK → isHasKey=' + inst.isHasKey()); }
    catch (e) { W('④ add 异常: ' + String(e).slice(0, 160)); }

    // ⑤ unlock
    if (blobB64) {
      try {
        var r = inst.unlock(blobB64, chId);
        W('⑤ unlock 返回: ' + desc(r));
      } catch (e) { W('⑤ unlock 异常: ' + String(e).slice(0, 200)); }
    }
    W('--- 主线程结束 ---');
  }

  try { Java.scheduleOnMainThread(function () { try { go(); } catch (e) { W('go 异常 ' + e); } }); }
  catch (e) { try { setImmediate(function () { try { go(); } catch (e2) { } }); } catch (e2) { } }
  W('=== v47 装载完毕 ===');
});
