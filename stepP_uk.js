// stepP_uk.js — 用 handler 诊断：把所有候选 userKey（含 40 字符 QIMEI 格式）逐个试
function S(o){try{send(o)}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s}catch(e){return '?'}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+''}catch(e){return null}}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}')}catch(e){}
    var blobB64=P.blob_b64||'', Key=P.Key||'', Ver=String(P.Version||'1639985422'), chId=String(P.chapter_id||'903350205');
    S({m:'=== P: userKey 候选穷举（用 handler 读 code）==='});
    // ① 从 MMKV 抓所有候选
    var mm=readText('/data/data/com.qidian.QDReader/files/mmkv/pref_utils')||'';
    var cands=[];
    function add(t,v){ if(v && String(v).length>=8){ for(var i=0;i<cands.length;i++) if(cands[i][1]===String(v)) return; cands.push([t,String(v)]) } }
    // 40 字符格式 <ts>:54:00:<mac>
    var r40=mm.match(/(\d{13,20}:54:00:[0-9a-f:]{6,})/g); if(r40) r40.forEach(function(v){ add('MMKV_40char', v) });
    var r16=mm.match(/O_STAR_Q_IMEI_16%\$([0-9a-f]{16,40})/); if(r16) add('MMKV_Q_IMEI_16', r16[1]);
    var r36=mm.match(/O_STAR_Q_IMEI_36%\$([0-9a-f]{16,40})/); if(r36) add('MMKV_Q_IMEI_36', r36[1]);
    var rb=mm.match(/BEACON_QIMEI\)\(?([^)\x00-\x1f]{10,60})/); if(rb) add('MMKV_BEACON_QIMEI', rb[1]);
    // App / 协议
    try{ var FU0=Java.use('com.qidian.QDReader.component.util.FockUtil');
      add('FockUtil.getPreUserKey', String(FU0.INSTANCE.value.getPreUserKey()||'')); }catch(e){}
    add('协议qimei16', String(P.qimei16||''));
    S({m:'候选('+cands.length+'): '+cands.map(function(c){return c[0]+'='+clip(c[1],44)}).join(' | ')});

    var FK=Java.use('com.yuewen.fock.Fock');
    var B64=Java.use('android.util.Base64'), Str=Java.use('java.lang.String');
    var lastCode='?';
    var H=Java.registerClass({
      name: 'com.example.Diag'+Date.now(),
      implements:[Java.use('com.yuewen.fock.Fock$ErrorLogHandler')],
      methods:{ onError:function(j){ try{ var s=String(j.toString());
        var m=s.match(/"code":(-?\d+)/); if(m) lastCode=m[1];
        if(s.indexOf('"code":0')>=0) S({m:'★★★★ handler: code=0 !!!'});
      }catch(e){} } }
    });
    var handler=H.$new();
    try{ FK.addKeypool(Key, Ver); }catch(e){ S({m:'addKeypool 异常 '+String(e).slice(0,80)}) }

    for(var i=0;i<cands.length;i++){
      var tag=cands[i][0], uk=cands[i][1];
      lastCode='?';
      try{ var ub=Str.$new(uk).getBytes('UTF-8'); FK.it(ub, ub.length); }catch(e){}
      var st='?';
      try{ var r=FK.unlock(blobB64, chId, uk, handler); st=String(r.status.value); }catch(e){ st='异常:'+String(e).slice(0,50) }
      S({m:'['+i+'] '+tag+' len='+uk.length+' → status='+st+'  handler.code='+lastCode});
    }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}) }
});
