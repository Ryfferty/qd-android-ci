// hook_ostartrig.js — ostar首启REGISTER抓包 (10-04 ZCode)
// 目标: OStarImpl.trigger(String)=ostar blob进+响应出; OStarImpl.update(q16,q36)=qimei落地
//       FockUtil.getH 被动监听(ostar URL时dump全头)
// 特性: app层类hook(480上实证可用, 壳只挡com.ola.star.uin.U); 不主动调任何ostar API
function S(o) { try { send(o); } catch (e) { } }

var hooked = false;

function tryHook() {
  Java.perform(function () {
    // ---------- ① OStarImpl 三hook ----------
    try {
      var OS = Java.use('com.qidian.QDReader.start.entity.OStarImpl');

      var trig = OS.trigger.overload('java.lang.String');
      trig.implementation = function (blob) {
        var b = '';
        try { b = (blob === null ? 'NULL' : String(blob)); } catch (e) { b = 'ERR:' + e; }
        S({ m: '★TRIGGER_ARG', len: b.length, body: b });
        var r = trig.call(this, blob);
        var rs = '';
        try { rs = (r === null ? 'NULL' : String(r)); } catch (e) { rs = 'ERR:' + e; }
        S({ m: '★TRIGGER_RET', len: rs.length, body: rs });
        return r;
      };

      try {
        var upd = OS.update.overload('java.lang.String', 'java.lang.String');
        upd.implementation = function (q16, q36) {
          S({ m: '★QIMEI_UPDATE', q16: String(q16), q36: String(q36) });
          return upd.call(this, q16, q36);
        };
      } catch (e) { S({ m: 'update hook失败: ' + e }); }

      try {
        var cih = OS.cihai.overload('java.lang.String', 'java.lang.String');
        cih.implementation = function (a, b2) {
          S({ m: '★OSTAR_FAIL', a: String(a), b: String(b2) });
          return cih.call(this, a, b2);
        };
      } catch (e) { S({ m: 'cihai hook失败: ' + e }); }

      S({ m: '✓ OStarImpl.trigger/update/cihai 已挂' });
      hooked = true;
    } catch (e) {
      // 默认loader找不到→壳类loader轮询切换(fockgen40同款, 480上实证可行)
      if (hookTry % 8 === 0) S({ m: 'wait OStarImpl(' + hookTry + '): ' + String(e).slice(0, 120) });
    }
  });
}

var hookTry = 0;
var hookedTry = 0;

Java.perform(function () {
  S({ m: '=== ostartrig v1 启动 ===', ver: Java.androidVersion });
});

// 轮询挂hook(spawn模式下等壳把dex吐出来)
var timer = setInterval(function () {
  hookTry++;
  if (hooked || hookTry > 480) { clearInterval(timer); if (!hooked) S({ m: '✗ 240s内未挂上OStarImpl' }); return; }
  tryHook();
  if (!hooked && hookTry % 20 === 10) {
    // 每10s试一次类loader枚举切换
    Java.perform(function () {
      try {
        var found = null;
        Java.enumerateClassLoaders({
          onMatch: function (loader) {
            try { loader.loadClass('com.qidian.QDReader.start.entity.OStarImpl'); if (!found) found = loader; } catch (e) { }
          }, onComplete: function () { }
        });
        if (found && found !== Java.classFactory.loader) {
          Java.classFactory.loader = found;
          S({ m: '✓ 切到含OStarImpl的loader' });
        }
      } catch (e) { }
    });
  }
}, 500);

Java.perform(function () {
  // ---------- ② FockUtil.getH 被动监听(只dump ostare URL) ----------
  try {
    var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
    var ov = FU.getH.overload('java.lang.String', 'java.lang.String', 'okhttp3.RequestBody');
    ov.implementation = function (url, method, body) {
      var r = ov.call(this, url, method, body);
      try {
        var u = String(url);
        if (u.indexOf('ostar') >= 0) {
          var it = r.entrySet().iterator();
          var hm = {};
          while (it.hasNext()) {
            var en = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
            var v = String(en.getValue());
            if (en.getKey() === 'QDInfo' || en.getKey() === 'Cookie') v = v.slice(0, 120) + '...';
            hm[String(en.getKey())] = v.slice(0, 400);
          }
          S({ m: '★OSTAR_HEADERS', url: u.slice(0, 150), method: String(method), headers: hm });
        }
      } catch (e) { }
      return r;
    };
    S({ m: '✓ getH被动监听已挂(仅ostar URL)' });
  } catch (e) { S({ m: '✗ getH: ' + String(e).slice(0, 120) }); }
});
