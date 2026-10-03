// hook_fockgen26.js — 阶段B捕获: App带注入会话重启后的启动链登录栈 + 判定三连 (10-04 ZCode)
// 前提: 阶段A已注入 MMKV pref_utils(alk/ywguid/ywkey) + SP ywlogin_share_date, App已被强杀重启
// 捕获: okhttp 全请求(稳定) — ptlogin.yuewen.com/sdk/* 即真实登录栈实弹(signature+ibex+设备)
// 判读: t+95s autoreceive/limitfreepopup/welfare
function S(o) { try { send(o); } catch (e) { } }

Java.perform(function () {
  S({ m: '=== fockgen v26: 阶段B捕获(带会话重启后) ===' });

  var okhttpCalls = 0, sdkCalls = 0;
  try {
    var OC = Java.use('okhttp3.OkHttpClient');
    OC.newCall.overload('okhttp3.Request').implementation = function (req) {
      try {
        okhttpCalls++;
        var u = String(req.url());
        if (u.indexOf('ptlogin.yuewen.com') >= 0 || u.indexOf('/sdk/') >= 0 || u.indexOf('staticlogin') >= 0) {
          sdkCalls++;
          var hb = req.headers();
          var hh = {};
          for (var i = 0; i < hb.size(); i++) {
            var n = String(hb.name(i));
            hh[n] = String(hb.value(i)).slice(0, 100);
          }
          var bodyStr = '';
          try { var b = req.body(); if (b) { var Buf = Java.use('okio.Buffer'); var bb = Buf.$new(); b.writeTo(bb); bodyStr = bb.readUtf8().slice(0, 500); } } catch (e) { }
          S({ m: '★★★SDK登录栈请求', url: u.slice(0, 140), method: String(req.method()), body: bodyStr, headers: hh });
        }
      } catch (e) { }
      return this.newCall(req);
    };
    S({ m: '✓ okhttp newCall 监听已挂(阶段B)' });
  } catch (e) { S({ m: '✗ okhttp: ' + e }); }

  // ---------- 被动: 真头dump ----------
  try {
    var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
    var ov = FU.getH.overload('java.lang.String', 'java.lang.String', 'okhttp3.RequestBody');
    ov.implementation = function (url, method, body) {
      var r = ov.call(this, url, method, body);
      try {
        var it = r.entrySet().iterator();
        var hm = {};
        while (it.hasNext()) {
          var en = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
          hm[String(en.getKey())] = String(en.getValue()).slice(0, 120);
        }
        S({ m: '★GETH', url: String(url).slice(0, 110), headers: hm });
      } catch (e) { }
      return r;
    };
  } catch (e) { S({ m: '✗ getH: ' + e }); }

  var ran = false;
  var timer = setInterval(function () {
    if (ran) { clearInterval(timer); return; }
    Java.perform(function () {
      try {
        ran = true; clearInterval(timer);
        S({ m: '=== 判读阶段 (t+25s起95s后) ===' });
        var ywguid = '', ywkey = '', alk = '';
        try {
          var F = Java.use('java.io.File');
          var f = F.$new('/data/local/tmp/sess.json');
          if (f.exists()) {
            var fis = Java.use('java.io.FileInputStream').$new(f);
            var baos = Java.use('java.io.ByteArrayOutputStream').$new();
            var buf = Java.array('byte', new Array(4096).fill(0));
            var n;
            while ((n = fis.read(buf)) > 0) baos.write(buf, 0, n);
            fis.close();
            var kv = JSON.parse(Java.use('java.lang.String').$new(baos.toByteArray(), 'UTF-8') + '');
            ywguid = String(kv.ywguid); ywkey = String(kv.ywkey); alk = String(kv.alk || '');
          }
        } catch (e) { }
        setTimeout(function () {
          Java.perform(function () {
            try {
              S({ m: ' 累计: okhttp=' + okhttpCalls + ' sdk登录栈=' + sdkCalls });
              var FU3 = Java.use('com.qidian.QDReader.component.util.FockUtil');
              var INST3 = FU3.INSTANCE.value;
              var RequestBody3 = Java.use('okhttp3.RequestBody');
              var MediaType3 = Java.use('okhttp3.MediaType');
              var OkHttpClient = Java.use('okhttp3.OkHttpClient');
              var ReqB3 = Java.use('okhttp3.Request$Builder');
              var mt3 = MediaType3.parse('application/x-www-form-urlencoded; charset=UTF-8');
              var client3 = OkHttpClient.$new();
              var ck = 'ywguid=' + ywguid + '; ywkey=' + ywkey + (alk ? '; alk=' + alk : '');
              function replay(url, method, body, tag, sliceLen) {
                try {
                  var body3 = RequestBody3.create(mt3, body || '');
                  var hm = INST3.getH(url, method, body3);
                  var it = hm.entrySet().iterator();
                  var rb3 = ReqB3.$new().url(url);
                  if (method === 'GET') { rb3.get(); } else { rb3.post(body3); }
                  while (it.hasNext()) {
                    var en = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
                    var k = String(en.getKey());
                    var v = String(en.getValue()).replace(/[\r\n]+/g, '').trim();
                    if (k === 'Cookie') { if (ck) v = ck + '; ' + v; }
                    if (k !== 'Content-Length' && k !== 'Content-Type') {
                      try { rb3.header(k, v); } catch (e) { }
                    }
                  }
                  var resp = client3.newCall(rb3.build()).execute();
                  var txt = '';
                  try { txt = resp.body().string(); } catch (e) { }
                  S({ m: '★★★判定', tag: tag, code: resp.code(), body: String(txt).slice(0, sliceLen || 400) });
                  Java.use('java.lang.Thread').sleep(2500);
                } catch (e) { S({ m: '✗ replay ' + tag + ': ' + e }); }
              }
              var H = 'https://bravev6.if.qidian.com';
              replay(H + '/argus/api/v2/freshman/autoreceive', 'POST', '', '⑧autoreceive_v2(重登后)', 400);
              replay(H + '/argus/api/v1/freshman/limitfreepopup', 'GET', '', '②limitfreepopup(重登后)', 400);
              replay(H + '/argus/api/v2/freshman/getfreshmanwelfarecenterpage', 'GET', '', '⑪welfare(重登后)', 1200);
            } catch (e) { S({ m: '✗ 判读段: ' + e }); }
          });
        }, 95000);
      } catch (e) { S({ m: '判读阶段错误: ' + e }); }
    });
  }, 25000);
});
