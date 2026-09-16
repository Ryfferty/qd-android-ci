// hook_v32_fock_public.js — 在真 App 进程里驱动 Fock 的【公开 API】
// 目的：极简进程里 sign/setup/addKeypool/unlock 都是 UnsatisfiedLinkError（加固壳运行时才释放实现）
//       → 必须在 App 进程内（jiagu 已初始化）调用，才能走公开 API 这条正路。
// 数据来源：argus（零网页），通过 /data/local/tmp/params.json 传入
// 不碰：App 的登录/UI/任何网页接口
function S(o) { try { send(o); } catch (e) { } }

function readText(p) {
  try {
    var F = Java.use('java.io.File'); var f = F.$new(p);
    if (!f.exists()) { S({ m: '✗ 文件不存在 ' + p }); return null; }
    var fis = Java.use('java.io.FileInputStream').$new(f);
    var baos = Java.use('java.io.ByteArrayOutputStream').$new();
    var buf = Java.array('byte', new Array(16384).fill(0)); var n;
    while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
    fis.close();
    return Java.use('java.lang.String').$new(baos.toByteArray(), 'UTF-8') + '';
  } catch (e) { S({ m: '读文件失败: ' + e }); return null; }
}

function st(r) {
  if (r === null || r === undefined) return null;
  try {
    var fs = r.getClass().getDeclaredFields(); var o = {};
    for (var i = 0; i < fs.length; i++) {
      fs[i].setAccessible(true);
      var v = fs[i].get(r);
      if (v === null) { o[fs[i].getName()] = null; continue; }
      if (v.getClass().getName() === '[B') {
        var s2 = null; try { s2 = Java.use('java.lang.String').$new(v, 'UTF-8') + ''; } catch (e) { }
        o[fs[i].getName()] = { len: v.length };
        if (v.length > 50) {
          var cn = 0; for (var k = 0; k < s2.length; k++) { var c = s2.charCodeAt(k); if (c >= 0x4e00 && c <= 0x9fff) cn++; }
          S({ m: '★★★★★★ 明文 ' + fs[i].getName() + ' len=' + v.length + ' 中文字=' + cn });
          S({ m: '★★★★★★ 正文', text: s2.slice(0, 3000) });
        } else if (s2) o[fs[i].getName()].utf8 = s2;
      } else o[fs[i].getName()] = String(v);
    }
    return o;
  } catch (e) { return 'refErr:' + e; }
}

Java.perform(function () {
  S({ m: '=== v32 Fock 公开 API（App 进程内）===' });

  var Fock = null;
  try { Fock = Java.use('com.yuewen.fock.Fock'); S({ m: '✓ com.yuewen.fock.Fock 可用' }); }
  catch (e) { S({ m: '✗ Fock 类: ' + e }); return; }

  try {
    var ms = Fock.class.getDeclaredMethods();
    S({ m: '方法数 ' + ms.length });
  } catch (e) { }

  var P = {};
  try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
  S({ m: 'params keys=' + Object.keys(P).join(',') });

  var Str = Java.use('java.lang.String');
  var B64 = Java.use('android.util.Base64');
  function bytes(s) { return Str.$new(s || '').getBytes('UTF-8'); }

  var qimei = P.qimei16 || 'b3b295be58644158';
  var ver = String(P.Version || '1639985422');
  var keyA = P.Key || '';
  var blobB64 = P.blob_b64 || '';
  var ywg = String(P.ywguid || '0');
  var chId = String(P.chapter_id || '903350205');
  S({ m: 'qimei=' + qimei + ' ver=' + ver + ' keyA=' + keyA.length + ' blob=' + blobB64.length + ' ywguid=' + ywg });

  function go() {
    S({ m: '--- 开始 ---' });
    // 1) setup：公开 API 有 setup(String) / setup(Context)
    try { Fock.setup(qimei); S({ m: '① setup(qimei) OK' }); } catch (e) { S({ m: '① setup(qimei): ' + String(e).slice(0, 130) }); }
    try { S({ m: '① currentUserKey()=' + Fock.currentUserKey() }); } catch (e) { S({ m: '① currentUserKey: ' + String(e).slice(0, 110) }); }
    try { S({ m: '① av()=' + Fock.av() }); } catch (e) { }
    try { S({ m: '① urk()=' + Fock.urk() }); } catch (e) { }

    // 2) 装密钥池（公开 API）
    if (keyA) {
      try { Fock.addKeypool(keyA, ver); S({ m: '② addKeypool(Key, ' + ver + ') OK' }); }
      catch (e) { S({ m: '② addKeypool: ' + String(e).slice(0, 130) }); }
    }
    try { S({ m: '② addedKeyVersions()=' + javaArr(Fock.addedKeyVersions()) }); } catch (e) { S({ m: '② addedKeyVersions: ' + String(e).slice(0, 110) }); }

    // 3) 解密：先试公开 unlock，再试底层 uk
    if (!blobB64) { S({ m: '⚠ 无密文' }); return; }
    var blob = B64.decode(blobB64, 0);
    S({ m: '③ 密文 ' + blob.length + 'B' });

    var slices = [['完整', blob]];
    try {
      var t = new Array(blob.length - 8); for (var i = 0; i < t.length; i++) t[i] = blob[i + 8];
      slices.push(['去8头', Java.array('byte', t)]);
    } catch (e) { }

    var aks = [chId, '', qimei, ywg];
    var akl = ['chapterId', '(空)', 'qimei', 'ywguid'];

    for (var s = 0; s < slices.length; s++) {
      var inB = slices[s][1];
      var inStr = null;
      try { inStr = Str.$new(inB, 'ISO-8859-1') + ''; } catch (e) { }

      for (var a = 0; a < aks.length; a++) {
        // 公开 unlock(String,String,String,ErrorLogHandler)
        try {
          var r = Fock.unlock(inStr, aks[a], ywg, null);
          S({ m: '③ unlock[' + slices[s][0] + '/ak=' + akl[a] + ']', fields: st(r) });
          if (st(r) && String(st(r).status) === '0') return;
        } catch (e) { S({ m: '③ unlock[' + slices[s][0] + '/' + akl[a] + ']: ' + String(e).slice(0, 110) }); }

        // 底层 uk(byte[],int,byte[],int)
        try {
          var ab = bytes(aks[a]);
          var r2 = Fock.uk(inB, inB.length, ab, ab.length);
          S({ m: '③ uk[' + slices[s][0] + '/ak=' + akl[a] + ']', fields: st(r2) });
          if (st(r2) && String(st(r2).status) === '0') return;
        } catch (e) { S({ m: '③ uk[' + slices[s][0] + '/' + akl[a] + ']: ' + String(e).slice(0, 110) }); }
      }
    }
    S({ m: '--- 结束 ---' });
  }

  function javaArr(a) { try { return a === null ? 'null' : a.join(','); } catch (e) { return '?'; } }

  try { setImmediate(function () { try { go(); } catch (e) { S({ m: 'go 异常 ' + e }); } }); } catch (e) { }
  recv(function (m) { var c = (m && m.cmd) ? m.cmd : String(m); if (c === 'go') { try { go(); } catch (e) { } } });
  S({ m: '=== v32 装载完毕 ===' });
});
