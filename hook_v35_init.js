// hook_v35_init.js — 补上 init(context, userKey) + 主线程执行，再调 add/unlock
// 依据：v34 实测 unlock 在 preUserKey=null 时崩进程；且 native 从 frida 线程调用可能 JNI 环境不对
function S(o) { try { send(o); } catch (e) { } }

var OUT = '/data/data/com.qidian.QDReader/files/v35_result.txt';
function W(line) {
  try {
    var fos = Java.use('java.io.FileOutputStream').$new(OUT, true);
    fos.write(Java.use('java.lang.String').$new(line + '\n').getBytes('UTF-8'));
    fos.close();
  } catch (e) { }
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
          W('★★★ 正文: ' + s2.slice(0, 2500));
          try {
            var f2 = Java.use('java.io.FileOutputStream').$new('/data/data/com.qidian.QDReader/files/v35_plaintext.txt', false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));
            f2.close();
            W('★ 明文已落盘 v35_plaintext.txt');
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
  W('=== v35 启动 ===');

  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  W('✓ FockUtil 可用');

  // 取 Application context
  var ctx = null;
  try {
    var AT = Java.use('android.app.ActivityThread');
    ctx = AT.currentApplication();
    W('✓ context = ' + ctx);
  } catch (e) { W('✗ currentApplication: ' + e); }
  if (!ctx) {
    try {
      var Act = Java.use('android.app.ActivityThread').currentActivityThread();
      var app = Act.getApplication();
      ctx = app;
      W('✓ context(备用) = ' + ctx);
    } catch (e) { W('✗ 备用 context: ' + e); }
  }

  var P = {};
  try { P = JSON.parse(readText('/data/local/tmp/params.json') || '{}'); } catch (e) { }
  var keyA = P.Key || '';
  var ver = String(P.Version || '');
  var blobB64 = P.blob_b64 || '';
  var chId = String(P.chapter_id || '903350205');
  var ywg = String(P.ywguid || '');
  var ywk = String(P.ywkey || '');
  W('params: Key=' + keyA.length + ' ver=' + ver + ' blob=' + blobB64.length + ' ch=' + chId + ' ywguid=' + ywg);

  var ran = false;
  function go() {
    if (ran) return;
    ran = true;
    W('--- 主线程执行开始 ---');
    var inst = FU.INSTANCE.value;

    try { W('① 前: isHasKey=' + inst.isHasKey() + ' preUserKey=' + inst.getPreUserKey() + ' getKey=' + inst.getKey()); } catch (e) { W('① ' + e); }

    // ② init(context, userKey) —— 补上这一步
    var uks = [ywg, ywg + ywk, ywk, ''];
    var ukl = ['ywguid', 'ywguid+ywkey', 'ywkey', '空'];
    if (ctx) {
      for (var i = 0; i < uks.length; i++) {
        try {
          inst.init(ctx, uks[i]);
          W('② init(ctx, ' + ukl[i] + ') OK → preUserKey=' + inst.getPreUserKey() + ' isHasKey=' + inst.isHasKey());
        } catch (e) { W('② init(' + ukl[i] + ') 异常: ' + String(e).slice(0, 140)); }
      }
      // 用最后一个生效的再设一次最可能的
      try {
        inst.setPreUserKey(ywg);
        W('② setPreUserKey(ywguid) → preUserKey=' + inst.getPreUserKey());
      } catch (e) { W('② setPreUserKey: ' + String(e).slice(0, 120)); }
    } else {
      W('② 无 context，跳过 init');
    }

    // ③ 装密钥池
    if (keyA) {
      try { inst.add(keyA, ver); W('③ add(Key,' + ver + ') OK → isHasKey=' + inst.isHasKey()); }
      catch (e) { W('③ add 异常: ' + String(e).slice(0, 140)); }
    }

    if (!blobB64) { W('⚠ 无密文'); return; }

    // ④ 解密（正解格式）
    W('④ 即将 unlock(len=' + blobB64.length + ', ak="' + chId + '")');
    try {
      var r = inst.unlock(blobB64, chId);
      W('④ unlock 返回: ' + describeResult(r));
    } catch (e) { W('④ unlock 异常: ' + String(e).slice(0, 200)); }

    // ⑤ 备用：去8头 base64
    try {
      var B64 = Java.use('android.util.Base64');
      var raw = B64.decode(blobB64, 0);
      var cut = java.util.Arrays.copyOfRange(raw, 8, raw.length);
      var b64b = B64.encodeToString(cut, 0);
      W('⑤ 备用 unlock(去8头base64 len=' + b64b.length + ', ak="' + chId + '")');
      var r2 = inst.unlock(b64b, chId);
      W('⑤ 备用返回: ' + describeResult(r2));
    } catch (e) { W('⑤ 备用异常: ' + String(e).slice(0, 200)); }

    W('--- 主线程执行结束 ---');
  }

  // ★ 关键：在主线程执行（native 可能需要正确的 JNI 环境）
  try {
    Java.scheduleOnMainThread(function () {
      try { go(); } catch (e) { W('go(main) 异常 ' + e); }
    });
    W('✓ 已 scheduleOnMainThread');
  } catch (e) {
    W('✗ scheduleOnMainThread 失败，改 setImmediate: ' + e);
    try { setImmediate(function () { try { go(); } catch (e2) { W('go 异常 ' + e2); } }); } catch (e2) { }
  }
  recv(function (m) { var c = (m && m.cmd) ? m.cmd : String(m); if (c === 'go') { try { go(); } catch (e) { } } });
  W('=== v35 装载完毕 ===');
});
