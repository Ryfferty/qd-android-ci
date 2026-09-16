// hook_v45_watch.js — 全量观测 App 自己怎么用 FockUtil（不主动调用任何方法）
// 目标：抓到 App 自己请求密钥池 / 加载本地密钥 / 解密 的完整链路
function S(o) { try { send(o); } catch (e) { } }

var DIR = '/data/data/com.qidian.QDReader/files/';
var OUT = DIR + 'v45_result.txt';
function W(line) {
  try {
    var fo = Java.use('java.io.FileOutputStream').$new(OUT, true);
    fo.write(Java.use('java.lang.String').$new(line + '\n').getBytes('UTF-8'));
    fo.close();
  } catch (e) { }
}
function clip(s, n) { try { s = String(s); return s.length > n ? s.slice(0, n) + '…[' + s.length + ']' : s; } catch (e) { return '?'; } }

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
            var f2 = Java.use('java.io.FileOutputStream').$new(DIR + 'v45_plaintext.txt', false);
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
  W('=== v45 全量观测 App 对 FockUtil 的使用 ===');

  var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
  W('✓ FockUtil 可用，方法数 ' + FU.class.getDeclaredMethods().length);

  function hook(name, sigs, tag) {
    sigs.forEach(function (sig) {
      try {
        var ov = sig.length ? FU[name].overload.apply(FU[name], sig) : FU[name];
        ov.implementation = function () {
          var args = [];
          for (var i = 0; i < arguments.length; i++) {
            var a = arguments[i];
            args.push(a === null ? 'null' : (typeof a === 'string' ? ('"' + clip(a, 200) + '"') : String(a).slice(0, 80)));
          }
          W('██ App 调 ' + tag + '  args=' + JSON.stringify(args));
          var r = sig.length ? this[name].apply(this, arguments) : this[name]();
          W('   ← 返回: ' + (r === null ? 'null' : (typeof r === 'string' ? clip(r, 120) : (r && r.getClass && r.getClass().getName() === 'com.yuewen.fock.Fock$FockResult' ? desc(r) : String(r).slice(0, 100)))));
          return r;
        };
        W('✓ hook ' + tag);
      } catch (e) { W('✗ hook ' + tag + ' (' + sig.join(',') + '): ' + String(e).slice(0, 90)); }
    });
  }

  hook('requestKey', [['android.content.Context', 'long']], 'requestKey(ctx,bookId)');
  hook('requestKey', [['android.content.Context']], 'requestKey(ctx)');
  hook('loadLocalKey', [['android.content.Context']], 'loadLocalKey(ctx)');
  hook('getKeyMap', [['android.content.Context']], 'getKeyMap(ctx)');
  hook('getKey', [], 'getKey()');
  hook('isHasKey', [], 'isHasKey()');
  hook('getPreUserKey', [], 'getPreUserKey()');
  hook('setPreUserKey', [['java.lang.String']], 'setPreUserKey');
  hook('save', [['android.content.Context', 'java.lang.String', 'java.lang.String']], 'save(ctx,key,ver)');
  hook('addMap', [['java.util.Map']], 'addMap(map)');
  hook('add', [['java.lang.String', 'java.lang.String']], 'add(keys,ver)');
  hook('unlock', [['java.lang.String', 'java.lang.String']], 'unlock(data,ak)');
  hook('init', [['android.content.Context', 'java.lang.String']], 'init(ctx,userKey)');
  hook('addRetrofitH', [['okhttp3.Request']], 'addRetrofitH(req)');
  hook('getH', [['java.lang.String', 'java.lang.String', 'okhttp3.RequestBody']], 'getH()');

  try {
    W('初始状态: isHasKey=' + FU.INSTANCE.value.isHasKey()
      + ' getKey=' + clip(FU.INSTANCE.value.getKey(), 60)
      + ' preUserKey=' + clip(FU.INSTANCE.value.getPreUserKey(), 40));
  } catch (e) { W('状态查询失败 ' + String(e).slice(0, 80)); }

  W('=== v45 装载完毕（纯被动观测）===');
});
