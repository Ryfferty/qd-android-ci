// hook_v33_capture.js — 监听 App 自己的 FockUtil 调用，抓真实参数格式
// 关键：不再猜 additionalKey / encryptedData 的格式，直接看 App 怎么传
function S(o) { try { send(o); } catch (e) { } }

function clip(s, n) { try { s = String(s); return s.length > n ? s.slice(0, n) + '…[len=' + s.length + ']' : s; } catch (e) { return '?'; } }

function describeResult(r) {
  if (r === null || r === undefined) return null;
  try {
    var o = {};
    var fs = r.getClass().getDeclaredFields();
    for (var i = 0; i < fs.length; i++) {
      fs[i].setAccessible(true);
      var v = fs[i].get(r);
      if (v === null) { o[fs[i].getName()] = null; continue; }
      if (v.getClass().getName() === '[B') {
        var s2 = null; try { s2 = Java.use('java.lang.String').$new(v, 'UTF-8') + ''; } catch (e) { }
        o[fs[i].getName()] = { len: v.length, head: clip(s2, 80) };
        if (v.length > 100) {
          var cn = 0; for (var k = 0; k < s2.length; k++) { var c = s2.charCodeAt(k); if (c >= 0x4e00 && c <= 0x9fff) cn++; }
          S({ m: '★★★★★★★ 明文！len=' + v.length + ' 中文字=' + cn });
          S({ m: '★★★★★★★ 正文', text: s2.slice(0, 2500) });
        }
      } else o[fs[i].getName()] = String(v);
    }
    return o;
  } catch (e) { return 'refErr:' + e; }
}

function readText(p) {
  try {
    var F = Java.use('java.io.File'); var f = F.$new(p);
    if (!f.exists()) return null;
    var fis = Java.use('java.io.FileInputStream').$new(f);
    var baos = Java.use('java.io.ByteArrayOutputStream').$new();
    var buf = Java.array('byte', new Array(16384).fill(0)); var n;
    while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
    fis.close();
    return Java.use('java.lang.String').$new(baos.toByteArray(), 'UTF-8') + '';
  } catch (e) { return null; }
}

Java.perform(function () {
  S({ m: '=== v33 监听 FockUtil ===' });

  var FU = null;
  try { FU = Java.use('com.qidian.QDReader.component.util.FockUtil'); S({ m: '✓ FockUtil 可用' }); }
  catch (e) { S({ m: '✗ FockUtil: ' + e }); }

  if (FU) {
    try {
      S({ m: '方法数 ' + FU.class.getDeclaredMethods().length });
      FU.class.getDeclaredMethods().forEach(function (m) {
        if ((m.getModifiers() & 0x100) !== 0) S({ m: '  native: ' + m.getName() + ' ' + m });
      });
    } catch (e) { }

    // ---- 监听 unlock（核心）----
    try {
      FU.unlock.overload('java.lang.String', 'java.lang.String').implementation = function (ed, ak) {
        S({ m: '██ FockUtil.unlock 被调用',
            encryptedData: { len: (ed || '').length, head: clip(ed, 120) },
            additionalKey: clip(ak, 120) });
        var r = this.unlock(ed, ak);
        S({ m: '██ unlock 返回', fields: describeResult(r) });
        return r;
      };
      S({ m: '✓ 已 hook unlock' });
    } catch (e) { S({ m: '✗ hook unlock: ' + e }); }

    // ---- 监听 add（装密钥池）----
    try {
      FU.add.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
        S({ m: '██ FockUtil.add 被调用', key: { len: (k || '').length, head: clip(k, 120) }, version: clip(v, 40) });
        return this.add(k, v);
      };
      S({ m: '✓ 已 hook add' });
    } catch (e) { S({ m: '✗ hook add: ' + e }); }

    // ---- 监听 init / isHasKey / getKey ----
    try {
      FU.init.overload('android.content.Context', 'java.lang.String').implementation = function (c, u) {
        S({ m: '██ FockUtil.init 被调用', userKey: clip(u, 80) + (u === null ? ' (null)' : '') });
        return this.init(c, u);
      };
      S({ m: '✓ 已 hook init' });
    } catch (e) { S({ m: '✗ hook init: ' + e }); }

    try {
      S({ m: 'isHasKey()=' + FU.INSTANCE.value.isHasKey() });
      S({ m: 'getKey()=' + clip(FU.INSTANCE.value.getKey(), 120) });
      S({ m: 'getPreUserKey()=' + clip(FU.INSTANCE.value.getPreUserKey(), 80) });
    } catch (e) { S({ m: '状态查询: ' + e }); }

    // ---- 主动调用：用 argus 数据走 FockUtil ----
    var P = {};
    try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
    S({ m: 'params keys=' + Object.keys(P).join(',') });
    var keyA = P.Key || '';
    var ver = String(P.Version || '');
    var blobB64 = P.blob_b64 || '';
    var chId = String(P.chapter_id || '903350205');

    var B64 = Java.use('android.util.Base64');
    function go() {
      S({ m: '--- 主动驱动 FockUtil（argus 数据）---' });
      var inst = FU.INSTANCE.value;
      // 1) 看当前状态
      try { S({ m: '① isHasKey=' + inst.isHasKey() + ' preUserKey=' + clip(inst.getPreUserKey(), 60) }); } catch (e) { }
      // 2) 装密钥池
      if (keyA) {
        try { inst.add(keyA, ver); S({ m: '② add(Key,' + ver + ') OK  → isHasKey=' + inst.isHasKey() }); }
        catch (e) { S({ m: '② add: ' + String(e).slice(0, 140) }); }
      }
      // 3) 密文解码
      if (!blobB64) { S({ m: '⚠ 无密文' }); return; }
      var blob = B64.decode(blobB64, 0);
      S({ m: '③ 密文 ' + blob.length + 'B' });
      var cands = [];
      try { cands.push(['base64原串', blobB64]); } catch (e) { }
      try { cands.push(['ISO8859-1(整段)', Java.use('java.lang.String').$new(blob, 'ISO-8859-1') + '']); } catch (e) { }
      try { cands.push(['去8字节后ISO', Java.use('java.lang.String').$new(Java.array('byte', (function () { var t = new Array(blob.length - 8); for (var i = 0; i < t.length; i++) t[i] = blob[i + 8]; return t; })()), 'ISO-8859-1') + '']); } catch (e) { }

      var aks = [chId, '', String(P.ywguid || ''), String(P.qimei16 || '')];
      var akl = ['chapterId', '(空)', 'ywguid', 'qimei'];
      for (var i = 0; i < cands.length; i++) {
        for (var a = 0; a < aks.length; a++) {
          try {
            var r = inst.unlock(cands[i][1], aks[a]);
            S({ m: '③ unlock[' + cands[i][0] + '/ak=' + akl[a] + ']', fields: describeResult(r) });
          } catch (e) { S({ m: '③ unlock[' + cands[i][0] + '/' + akl[a] + ']: ' + String(e).slice(0, 120) }); }
        }
      }
      S({ m: '--- 结束 ---' });
    }
    try { setImmediate(function () { try { go(); } catch (e) { S({ m: 'go 异常 ' + e }); } }); } catch (e) { }
    recv(function (m) { var c = (m && m.cmd) ? m.cmd : String(m); if (c === 'go') { try { go(); } catch (e) { } } });
  }

  S({ m: '=== v33 装载完毕（监听中）===' });
});
