// hook_fockgen.js — Fock Oracle 三段式 (10-02 ZCode)
// ① 被动: 监听 FockUtil.getH 全部调用 (url/method/body/头map)
// ② 主动: 对我们的目标请求调用 getH, 输出头
// ③ 决定性实验: 用 App 自己的 OkHttpClient(全套拦截器: QDInfo/QDSign/Fock) 打 autoreceive,
//    带我们注入的会话 cookie, 抓响应 — 看罐头是否消失
// 会话写在 /data/local/tmp/sess.json (worker 由 v16 机制注入或本脚本读取)
function S(o) { try { send(o); } catch (e) { } }

Java.perform(function () {
  S({ m: '=== fockgen v1 ===', ver: Java.androidVersion });

  // ---------- ① 被动监听 getH ----------
  try {
    var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
    var ov = FU.getH.overload('java.lang.String', 'java.lang.String', 'okhttp3.RequestBody');
    ov.implementation = function (url, method, body) {
      var r = ov.call(this, url, method, body);
      try {
        var bs = '';
        try {
          if (body !== null) {
            var Buf = Java.use('okio.Buffer');
            var b = Buf.$new(); body.writeTo(b); bs = b.readUtf8().slice(0, 300);
          }
        } catch (e) { }
        var it = r.entrySet().iterator();
        var hm = {};
        while (it.hasNext()) {
          var en = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
          hm[String(en.getKey())] = String(en.getValue()).slice(0, 300);
        }
        S({ m: '★GETH', url: String(url), method: String(method), body: bs, headers: hm });
      } catch (e) { S({ m: 'getH log err: ' + e }); }
      return r;
    };
    S({ m: '✓ getH 被动监听已挂' });
  } catch (e) { S({ m: '✗ getH hook: ' + e }); }

  // ---------- ② 主动调用 getH ----------
  try {
    var FU2 = Java.use('com.qidian.QDReader.component.util.FockUtil');
    var INST = FU2.INSTANCE.value;
    var targets = [
      { url: 'https://bravev6.if.qidian.com/argus/api/v3/freshman/autoreceive', method: 'POST', body: '' },
      { url: 'https://bravev6.if.qidian.com/argus/api/v1/freshman/limitfreepopup', method: 'POST', body: '' },
      { url: 'https://bravev6.if.qidian.com/argus/api/v1/client/getconf', method: 'POST', body: 'localLabels=100&gender=m' }
    ];
    var RequestBody = Java.use('okhttp3.RequestBody');
    var MediaType = Java.use('okhttp3.MediaType');
    targets.forEach(function (t) {
      try {
        var body = null;
        if (t.body) {
          var mt = MediaType.parse('application/x-www-form-urlencoded; charset=UTF-8');
          body = RequestBody.create(mt, t.body);
        }
        var r = INST.getH(t.url, t.method, body);
        var it = r.entrySet().iterator();
        var hm = {};
        while (it.hasNext()) {
          var en = Java.cast(it.next(), Java.use('java.util.Map$Entry'));
          hm[String(en.getKey())] = String(en.getValue());
        }
        S({ m: '★★ORACLE', url: t.url, headers: hm });
      } catch (e) { S({ m: '✗ oracle ' + t.url + ': ' + e }); }
    });
  } catch (e) { S({ m: '✗ 主动调用: ' + e }); }

  // ---------- ③ App 自身客户端打 autoreceive ----------
  try {
    var Q = Java.use('com.qidian.QDReader.component.retrofit.q');
    var client = Q.f12311b.value; // App 全家桶 OkHttpClient(带 QDSign/QDInfo/Fock 拦截器)
    S({ m: '✓ App OkHttpClient 已取' });

    // 读会话
    var ck = '';
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
        Object.keys(kv).forEach(function (k) { ck += k + '=' + kv[k] + '; '; });
        S({ m: '✓ 会话已载入', names: Object.keys(kv).join(',') });
      } else { S({ m: '✗ sess.json 不存在, 用匿名' }); }
    } catch (e) { S({ m: '读 sess.json: ' + e }); }

    var ReqB = Java.use('okhttp3.Request$Builder');
    var MediaType2 = Java.use('okhttp3.MediaType');
    var RequestBody2 = Java.use('okhttp3.RequestBody');
    var mt2 = MediaType2.parse('application/x-www-form-urlencoded; charset=UTF-8');

    var urls = [
      ['https://bravev6.if.qidian.com/argus/api/v3/freshman/autoreceive', ''],
      ['https://bravev6.if.qidian.com/argus/api/v2/freshman/getfreshmanwelfarecenterpage', ''],
      ['https://bravev6.if.qidian.com/argus/api/v1/client/getconf', 'localLabels=100&gender=m']
    ];
    var CallB = Java.use('okhttp3.Callback');
    urls.forEach(function (t) {
      try {
        var rb = ReqB.$new().url(t[0]);
        if (t[1]) rb.post(RequestBody2.create(mt2, t[1]));
        else rb.post(RequestBody2.create(mt2, ''));
        if (ck) rb.header('Cookie', ck);
        rb.header('User-Agent', 'Mozilla/mobile QDReaderAndroid/7.9.200/1906/1000009');
        rb.header('Referer', 'http://android.qidian.com');
        var req = rb.build();
        client.newCall(req).enqueue(Java.registerClass({
          name: 'qd.cb' + Math.floor(Math.random() * 1e6),
          implements: [CallB],
          methods: {
            onFailure: function (call, e) { S({ m: '✗HTTP ' + t[0], err: String(e) }); },
            onResponse: function (call, resp) {
              try {
                var bd = resp.body();
                var txt = bd.string();
                S({ m: '★★HTTP ' + t[0], code: resp.code(), body: String(txt).slice(0, 800) });
              } catch (e) { S({ m: '✗HTTP读 ' + t[0] + ': ' + e }); }
            }
          }
        }).$new());
      } catch (e) { S({ m: '✗ req ' + t[0] + ': ' + e }); }
    });
    S({ m: '✓ 3 个请求已 enqueue' });
  } catch (e) { S({ m: '✗ App客户端: ' + e }); }

  // ---------- ④ Fock keyMap dump ----------
  try {
    var FU3 = Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst = FU3.INSTANCE.value;
    try { S({ m: '★getKey', key: String(inst.getKey()) }); } catch (e) { S({ m: 'getKey: ' + e }); }
    try { S({ m: '★isHasKey', has: inst.isHasKey() }); } catch (e) { }
  } catch (e) { S({ m: '✗ keydump: ' + e }); }
});
