// hook_v49.js — 主线程里只做 native 调用，不动文件 I/O（避免 ANR 被杀）
// 顺序严格按 App 反编译：不再调 init，只 save → add → unlock
function S(o) { try { send(o); } catch (e) { } }
var DIR = '/data/data/com.qidian.QDReader/files/';
var BUF = [];                          // ★ 内存缓冲，主线程里只 push
function L(line) { BUF.push(line); S({ m: line }); }
function flushToFile(name) {
  try {
    var fo = Java.use('java.io.FileOutputStream').$new(DIR + name, false);
    fo.write(Java.use('java.lang.String').$new(BUF.join('\n')).getBytes('UTF-8'));
    fo.close();
  } catch (e) { S({ m: 'flush 失败 ' + e }); }
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
          L('★★★★★★★ 明文！len=' + v.length + ' 中文字=' + cn);
          L('★★★ 正文: ' + s2.slice(0, 3000));
          try { TESTEXT = s2; } catch (e) { }
        }
      } else o[fs[i].getName()] = clip(v, 80);
    }
    return JSON.stringify(o);
  } catch (e) { return 'refErr:' + e; }
}

var TESTEXT = null;
var RESULT = {};

Java.perform(function () {
  L('=== v49 无 I/O 主线程版 ===');
  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  var ctx = null;
  try { ctx = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) { }
  L('ctx=' + ctx);
  try { L('★ e.L() = [' + clip(Java.use('com.qidian.QDReader.core.config.e').L(), 80) + ']'); } catch (e) { }

  var P = {};
  try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
  var keyA = P.Key || '', ver = String(P.Version || ''), blobB64 = P.blob_b64 || '';
  var chId = String(P.chapter_id || '903350205');
  L('params: Key=' + keyA.length + ' ver=' + ver + ' blob=' + blobB64.length + ' ch=' + chId);

  var ran = false;
  function go() {
    if (ran) return; ran = true;
    var inst = FU.INSTANCE.value;
    L('go: 取到 INSTANCE');

    // ② 读 App 已有 userKey（不调 init）
    try { RESULT.preUserKey = String(inst.getPreUserKey()); L('② getPreUserKey=[' + clip(RESULT.preUserKey, 80) + ']'); }
    catch (e) { L('② getPreUserKey 异常 ' + String(e).slice(0, 100)); }
    try { RESULT.hasKey = String(inst.isHasKey()); L('② isHasKey=' + RESULT.hasKey + ' getKey=' + clip(inst.getKey(), 40)); }
    catch (e) { L('② 状态查询异常 ' + String(e).slice(0, 100)); }

    // ③ save
    try {
      inst.save(ctx, keyA, ver);
      RESULT.save = 'OK';
      L('③ save(ctx, Key, ' + ver + ') OK');
    } catch (e) { RESULT.save = String(e).slice(0, 120); L('③ save 异常: ' + RESULT.save); }

    // ③b 读回
    try { L('  getKeyMap=' + clip(inst.getKeyMap(ctx), 200)); } catch (e) { L('  getKeyMap 异常'); }
    try { L('  isHasKey=' + inst.isHasKey() + ' getKey=' + clip(inst.getKey(), 40)); } catch (e) { }

    // ④ add
    try { inst.add(keyA, ver); RESULT.add = 'OK'; L('④ add OK → isHasKey=' + inst.isHasKey()); }
    catch (e) { RESULT.add = String(e).slice(0, 120); L('④ add 异常: ' + RESULT.add); }

    // ⑤ unlock
    if (blobB64) {
      try {
        var r = inst.unlock(blobB64, chId);
        RESULT.unlock = desc(r);
        L('⑤ unlock: ' + RESULT.unlock);
      } catch (e) { RESULT.unlock = String(e).slice(0, 200); L('⑤ unlock 异常: ' + RESULT.unlock); }
    }
    L('go: 结束');
    // ★ 主线程末尾一次性落盘（单次写，快）
    try {
      flushToFile('v49_result.txt');
      if (TESTEXT) {
        var f2 = Java.use('java.io.FileOutputStream').$new(DIR + 'v49_plaintext.txt', false);
        f2.write(Java.use('java.lang.String').$new(TESTEXT).getBytes('UTF-8'));
        f2.close();
        L('★ 明文已落盘');
        flushToFile('v49_result.txt');
      }
    } catch (e) { S({ m: '落盘失败 ' + e }); }
    return 'done';
  }

  // ★ 用 registerClass Runnable + Handler 在【非主线程】跑？先试主线程但无 I/O
  var ok = false;
  try {
    Java.scheduleOnMainThread(function () { try { go(); } catch (e) { L('go 异常 ' + e); } });
    ok = true; L('已 scheduleOnMainThread');
  } catch (e) { L('schedule 失败 ' + e); }

  L('=== v49 装载完毕 ===');

});
