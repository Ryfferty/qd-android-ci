// hook_v46_qimei.js — 完全按 App 反编译代码复现：
//   ① 调 com.qidian.QDReader.core.config.e.L() 拿真实 userKey（QIMEI）
//   ② FockUtil.init(ctx, qimei)
//   ③ FockUtil.save(ctx, argusKey, argusVersion)   ← 之前漏掉的关键步
//   ④ FockUtil.add(...) / unlock(base64密文, 章节ID)
function S(o) { try { send(o); } catch (e) { } }

var DIR = '/data/data/com.qidian.QDReader/files/';
var OUT = DIR + 'v46_result.txt';
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
            var f2 = Java.use('java.io.FileOutputStream').$new(DIR + 'v46_plaintext.txt', false);
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
  W('=== v46 按 App 真实代码复现 ===');

  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  var ctx = null;
  try { ctx = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) { }
  W('ctx=' + ctx);

  // ---------- ① 从 App 自己的配置类拿真实 userKey ----------
  var qimei = null, qimei36 = null;
  try {
    var E = Java.use('com.qidian.QDReader.core.config.e');
    qimei = String(E.L());
    W('★ e.L()  → userKey(QIMEI) = [' + clip(qimei, 80) + ']');
  } catch (e) { W('e.L() 失败: ' + String(e).slice(0, 120)); }
  try {
    var E2 = Java.use('com.qidian.QDReader.core.config.e');
    qimei36 = String(E2.M());
    W('★ e.M()  → QIMEI_36      = [' + clip(qimei36, 80) + ']');
  } catch (e) { W('e.M() 失败: ' + String(e).slice(0, 120)); }

  // 直接从 SP 读（e.java 里就是读 BEACON_QIMEI）
  try {
    var j0 = Java.use('j0');
    W('· 找到类 j0');
  } catch (e) { W('· 类 j0 不在（可能混淆名不同）'); }
  try {
    var Prefs = Java.use('android.preference.PreferenceManager').getDefaultSharedPreferences(ctx);
    W('SP BEACON_QIMEI    = [' + clip(Prefs.getString('BEACON_QIMEI', ''), 80) + ']');
    W('SP BEACON_QIMEI_36 = [' + clip(Prefs.getString('BEACON_QIMEI_36', ''), 80) + ']');
  } catch (e) { W('读 SP 失败: ' + String(e).slice(0, 100)); }

  // ---------- 参数 ----------
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

    function findMethod(name) {
      var ms = FU.class.getDeclaredMethods();
      for (var i = 0; i < ms.length; i++) if (ms[i].getName() === name) { ms[i].setAccessible(true); return ms[i]; }
      return null;
    }
    var mInit = findMethod('init'), mSave = findMethod('save'), mAdd = findMethod('add'),
        mUnlock = findMethod('unlock'), mLoadLocal = findMethod('loadLocalKey'),
        mGetKeyMap = findMethod('getKeyMap'), mIsHasKey = findMethod('isHasKey'),
        mGetKey = findMethod('getKey'), mGetPreUserKey = findMethod('getPreUserKey');
    W('方法: init=' + !!mInit + ' save=' + !!mSave + ' add=' + !!mAdd + ' unlock=' + !!mUnlock
      + ' loadLocalKey=' + !!mLoadLocal + ' getKeyMap=' + !!mGetKeyMap);

    var cands = [];
    if (qimei) cands.push(['e.L()', qimei]);
    if (qimei36) cands.push(['e.M()', qimei36]);
    cands.push(['qimei16参数', String(P.qimei16 || '')]);
    cands.push(['ywguid', String(P.ywguid || '')]);

    for (var c = 0; c < cands.length; c++) {
      var label = cands[c][0], uk = cands[c][1];
      if (!uk) continue;
      W('===== 候选 userKey: ' + label + ' = [' + clip(uk, 60) + '] =====');
      // ② init
      try { if (mInit) { mInit.invoke(inst, ctx, uk); W('  ② init OK → preUserKey=' + clip(inst.getPreUserKey(), 40)); } }
      catch (e) { W('  ② init 异常: ' + String(e).slice(0, 120)); }
      // ③ save（关键新步骤）
      try { if (mSave) { mSave.invoke(inst, ctx, keyA, ver); W('  ③ save(ctx,key,ver) OK'); } }
      catch (e) { W('  ③ save 异常: ' + String(e).slice(0, 140)); }
      // 读本地
      try { if (mGetKeyMap) { var km = mGetKeyMap.invoke(inst, ctx); W('  ③ getKeyMap()=' + clip(km, 120)); } } catch (e) { }
      try { W('  ③ isHasKey=' + inst.isHasKey() + ' getKey=' + clip(inst.getKey(), 40)); } catch (e) { }
      // ④ add
      try { if (mAdd) { mAdd.invoke(inst, keyA, ver); W('  ④ add(key,ver) OK'); } } catch (e) { W('  ④ add 异常: ' + String(e).slice(0, 120)); }
      // ⑤ unlock
      if (blobB64 && mUnlock) {
        try {
          var r = mUnlock.invoke(inst, blobB64, chId);
          W('  ⑤ unlock 返回: ' + desc(r));
        } catch (e) { W('  ⑤ unlock 异常: ' + String(e).slice(0, 180)); }
      }
      W('----- 候选 ' + label + ' 结束 -----');
    }
    W('--- 主线程结束 ---');
  }

  try { Java.scheduleOnMainThread(function () { try { go(); } catch (e) { W('go 异常 ' + e); } }); }
  catch (e) { try { setImmediate(function () { try { go(); } catch (e2) { } }); } catch (e2) { } }
  W('=== v46 装载完毕 ===');
});
