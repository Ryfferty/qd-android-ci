// hook_v34_final.js — 按 App 的真实格式调用 FockUtil，并把结果写进设备文件（不受管道截断影响）
// App 实测格式：FockUtil.add(argusKey, argusVersion) → FockUtil.unlock(base64密文串, chapterId)
function S(o) { try { send(o); } catch (e) { } }

var OUT = '/data/local/tmp/v34_result.txt';
function W(line) {
  try {
    var F = Java.use('java.io.FileOutputStream');
    var fos = F.$new(OUT, true);
    fos.write(Java.use('java.lang.String').$new(line + '\n').getBytes('UTF-8'));
    fos.close();
  } catch (e) { try { send({ m: 'W失败 ' + e }); } catch (e2) { } }
  S({ m: line });
}

function describeResult(r) {
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
        o[fs[i].getName()] = { len: v.length, head: (s2 || '').slice(0, 60) };
        if (v.length > 100) {
          var cn = 0; for (var k = 0; k < s2.length; k++) { var c = s2.charCodeAt(k); if (c >= 0x4e00 && c <= 0x9fff) cn++; }
          W('★★★★★★★ 明文！len=' + v.length + ' 中文字=' + cn);
          W('★★★ 正文前2500字: ' + s2.slice(0, 2500));
          try {
            var FOS = Java.use('java.io.FileOutputStream');
            var f2 = FOS.$new('/data/local/tmp/v34_plaintext.txt', false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));
            f2.close();
            W('★ 明文已写入 /data/local/tmp/v34_plaintext.txt');
          } catch (e) { W('写明文失败 ' + e); }
        }
      } else o[fs[i].getName()] = String(v);
    }
    return JSON.stringify(o);
  } catch (e) { return 'refErr:' + e; }
}

function readText(p) {
  try {
    var F = Java.use('java.io.File'); var f = F.$new(p);
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
  try { var F = Java.use('java.io.File'); var f = F.$new(OUT); if (f.exists()) f.delete(); } catch (e) { }
  W('=== v34 最终版启动 ===');

  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  W('✓ FockUtil 可用，方法数 ' + FU.class.getDeclaredMethods().length);

  var P = {};
  try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
  var keyA = P.Key || '';
  var ver = String(P.Version || '');
  var blobB64 = P.blob_b64 || '';
  var chId = String(P.chapter_id || '903350205');
  W('params: Key=' + keyA.length + ' ver=' + ver + ' blob_b64=' + blobB64.length + ' chapter=' + chId);

  function go() {
    var inst = FU.INSTANCE.value;
    W('--- 开始 ---');
    try { W('① isHasKey=' + inst.isHasKey() + ' getKey=' + inst.getKey() + ' preUserKey=' + inst.getPreUserKey()); } catch (e) { W('① ' + e); }

    // 装密钥池（App 的公开 API）
    if (keyA) {
      try { inst.add(keyA, ver); W('② add(Key,' + ver + ') OK → isHasKey=' + inst.isHasKey()); }
      catch (e) { W('② add 异常: ' + String(e).slice(0, 160)); }
    }

    if (!blobB64) { W('⚠ 无密文'); return; }

    // ★ 正解：encryptedData = base64 字符串，additionalKey = 章节 ID
    var cases = [
      ['base64串/chapterId', blobB64, chId],
      ['base64串/空', blobB64, ''],
      ['base64串/ywguid', blobB64, String(P.ywguid || '')],
      ['base64串/bookId', blobB64, String(P.book_id || '')]
    ];
    for (var i = 0; i < cases.length; i++) {
      try {
        W('③ [' + cases[i][0] + '] 调用 unlock(len=' + cases[i][1].length + ', ak="' + cases[i][2] + '")');
        var r = inst.unlock(cases[i][1], cases[i][2]);
        W('③ [' + cases[i][0] + '] 返回: ' + describeResult(r));
      } catch (e) { W('③ [' + cases[i][0] + '] 异常: ' + String(e).slice(0, 160)); }
    }
    W('--- 结束 ---');
  }

  try { setImmediate(function () { try { go(); } catch (e) { W('go 异常 ' + e); } }); } catch (e) { }
  recv(function (m) { var c = (m && m.cmd) ? m.cmd : String(m); if (c === 'go') { try { go(); } catch (e) { } } });
  W('=== v34 装载完毕 ===');
});
