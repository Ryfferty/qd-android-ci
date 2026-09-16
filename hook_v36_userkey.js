// hook_v36_userkey.js — 修 -3 EMPTY_USER_KEY：在 Fock 层设置内部 userKey
// 依据：v35 实测 init(ctx,userKey) 只设了 Java 层 preUserKey，unlock 仍报 -3
//       需要在 Fock 层（it/setup）设置内部 userKey
function S(o) { try { send(o); } catch (e) { } }

var OUT = '/data/data/com.qidian.QDReader/files/v36_result.txt';
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
          W('★★★★★★★ 明文！len=' + v.length + ' 中文字=' + cn);
          W('★★★ 正文: ' + s2.slice(0, 2500));
          try {
            var f2 = Java.use('java.io.FileOutputStream').$new('/data/data/com.qidian.QDReader/files/v36_plaintext.txt', false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));
            f2.close();
            W('★ 明文落盘成功');
          } catch (e) { }
        }
      } else o[fs[i].getName()] = String(v);
    }
    return JSON.stringify(o);
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
  W('=== v36 启动 ===');

  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FK = null;
  try { FK = Java.use('com.yuewen.fock.Fock'); W('✓ 类: FockUtil + Fock'); }
  catch (e) { W('✗ Fock 类不可用: ' + e); }

  var ctx = null;
  try { ctx = Java.use('android.app.ActivityThread').currentApplication(); W('✓ ctx=' + ctx); } catch (e) { W('✗ ctx: ' + e); }

  var P = {};
  try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
  var keyA = P.Key || '', ver = String(P.Version || ''), blobB64 = P.blob_b64 || '';
  var chId = String(P.chapter_id || '903350205');
  var ywg = String(P.ywguid || ''), ywk = String(P.ywkey || '');
  var ywopenid = String(P.ywopenid || '');
  W('params: Key=' + keyA.length + ' ver=' + ver + ' blob=' + blobB64.length + ' ywguid=' + ywg + ' openid=' + ywopenid);

  var ran = false;
  function go() {
    if (ran) return; ran = true;
    W('--- 主线程开始 ---');
    var inst = FU.INSTANCE.value;
    var Str = Java.use('java.lang.String');
    function bytes(s) { return Str.$new(s || '').getBytes('UTF-8'); }

    // Fock 层 native 定位
    var fSetup = null, fIt = null, fUrk = null, fAv = null, fAddKeypool = null;
    if (FK) {
      try { fSetup = FK.setup.overload('java.lang.String'); } catch (e) { }
      try { fIt = FK.it.overload('[B', 'int'); } catch (e) { }
      try { fUrk = FK.urk.overload(); } catch (e) { }
      try { fAv = FK.av.overload(); } catch (e) { }
      try { fAddKeypool = FK.addKeypool.overload('java.lang.String', 'java.lang.String'); } catch (e) { }
      W('Fock 方法: setup=' + (fSetup !== null) + ' it=' + (fIt !== null) + ' urk=' + (fUrk !== null)
          + ' av=' + (fAv !== null) + ' addKeypool=' + (fAddKeypool !== null));
    }

    var cands = [['ywguid', ywg], ['ywopenid', ywopenid], ['ywguid+ywkey', ywg + ywk], ['ywkey', ywk]];
    for (var i = 0; i < cands.length; i++) {
      var label = cands[i][0], u = cands[i][1];
      if (!u) continue;
      W('=== 候选 ' + i + ': ' + label + ' = ' + u);
      // 1) FockUtil.init
      try { if (ctx) inst.init(ctx, u); } catch (e) { W('  init 异常: ' + String(e).slice(0, 100)); }
      // 2) Fock 层设内部 userKey：先 setup 再 it
      if (fSetup) { try { fSetup.invoke(null, u); W('  Fock.setup OK'); } catch (e) { W('  Fock.setup: ' + String(e).slice(0, 110)); } }
      if (fIt) { try { var b = bytes(u); W('  Fock.it ret=' + fIt.invoke(null, b, b.length)); } catch (e) { W('  Fock.it: ' + String(e).slice(0, 110)); } }
      if (fUrk) { try { W('  Fock.urk()=' + fUrk.invoke(null)); } catch (e) { } }
      if (fAv) { try { W('  Fock.av()=[' + fAv.invoke(null) + ']'); } catch (e) { } }
      // 3) 装密钥池 —— 四种格式都试（关键是 encryptedKeys 可能是 {ver:key} 的 JSON map）
      var addForms = [
        ['裸Key', keyA],
        ['JSON{ver:key}', '{"' + ver + '":"' + keyA + '"}'],
        ['JSON{key:ver}', '{"' + keyA + '":"' + ver + '"}']
      ];
      for (var af = 0; af < addForms.length; af++) {
        try {
          inst.add(addForms[af][1], ver);
          W('  add[' + addForms[af][0] + '] OK isHasKey=' + inst.isHasKey());
        } catch (e) { W('  add[' + addForms[af][0] + ']: ' + String(e).slice(0, 110)); }
        try {
          var r0 = inst.unlock(blobB64, chId);
          W('    → 立即试 unlock: ' + desc(r0));
          var st = JSON.parse(desc(r0)).status;
          if (String(st) === '0') { W('★★★★★★★ 成功！格式=' + addForms[af][0]); return; }
        } catch (e) { W('    试 unlock 异常'); }
      }
      if (fAddKeypool) { try { fAddKeypool.invoke(null, keyA, ver); W('  Fock.addKeypool(裸Key) OK'); } catch (e) { W('  addKeypool: ' + String(e).slice(0, 110)); } }
      // 4) 解密
      if (blobB64) {
        try {
          var r = inst.unlock(blobB64, chId);
          W('  ★ unlock 返回: ' + desc(r));
        } catch (e) { W('  unlock 异常: ' + String(e).slice(0, 160)); }
      }
      W('--- 候选 ' + i + ' 结束 ---');
    }
    W('--- 全部结束 ---');
  }

  try {
    Java.scheduleOnMainThread(function () { try { go(); } catch (e) { W('go 异常 ' + e); } });
    W('✓ 已 scheduleOnMainThread');
  } catch (e) {
    W('✗ schedule 失败: ' + e);
    try { setImmediate(function () { try { go(); } catch (e2) { } }); } catch (e2) { }
  }
  recv(function (m) { var c = (m && m.cmd) ? m.cmd : String(m); if (c === 'go') { try { go(); } catch (e) { } } });
  W('=== v36 装载完毕 ===');
});
