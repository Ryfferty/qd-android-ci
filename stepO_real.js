// stepO_real.js — 按【真签名】调用 464 的 Fock（unlock 3/4 参、uk 4 参、it、addKeypool）
function S(o){try{send(o)}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s}catch(e){return '?'}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+''}catch(e){return null}}
function dumpRes(r,label){
  if(!r){ S({m:label+' → null'}); return }
  try{ var fs=r.getClass().getDeclaredFields(), o={};
    for(var i=0;i<fs.length;i++){ fs[i].setAccessible(true); var v=fs[i].get(r);
      if(v===null){o[fs[i].getName()]=null;continue}
      if(v.getClass().getName()==='[B'){ var s2='';try{s2=Java.use('java.lang.String').$new(v,'UTF-8')+''}catch(e){}
        o[fs[i].getName()]='len='+v.length;
        if(v.length>100){ var cn=0; for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++}
          S({m:'★★★★★★★ 明文！！！len='+v.length+' 中文字='+cn}); S({m:'★★★ 正文',text:s2.slice(0,3000)});
          try{ var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_O.txt',false); f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8')); f2.close(); S({m:'★★★ 明文已落盘'})}catch(e){} } }
      else o[fs[i].getName()]=clip(v,50) }
    S({m:label+' → '+JSON.stringify(o)});
  }catch(e){ S({m:label+' 取值失败 '+String(e).slice(0,80)}) }
}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}')}catch(e){}
    var blobB64=P.blob_b64||'', Key=P.Key||'', Ver=String(P.Version||'1639985422'), chId=String(P.chapter_id||'903350205');
    var q16=String(P.qimei16||'');
    S({m:'=== O: 真签名调用（密文 B64 len='+blobB64.length+' Key len='+Key.length+'）==='});
    var FK=Java.use('com.yuewen.fock.Fock');
    // ① ErrorLogHandler 接口方法
    try{
      var EH=Java.use('com.yuewen.fock.Fock$ErrorLogHandler');
      var ms=EH.class.getDeclaredMethods(), nm=[];
      for(var i=0;i<ms.length;i++){ var ps=ms[i].getParameterTypes(), pt=[];
        for(var j=0;j<ps.length;j++) pt.push(String(ps[j].getName()).replace('java.lang.',''));
        nm.push(String(ms[i].getName())+'('+pt.join(',')+')') }
      S({m:'ErrorLogHandler 方法: '+nm.join(' | ')});
    }catch(e){ S({m:'枚举 ErrorLogHandler 失败: '+String(e).slice(0,90)}) }
    // ② 构造 handler（Java.registerClass 实现接口）
    var handler=null;
    try{
      var H = Java.registerClass({
        name: 'com.example.MH' + Date.now(),
        implements: [Java.use('com.yuewen.fock.Fock$ErrorLogHandler')],
        methods: {
          onError: function(a, b){ try{ S({m:'[handler.onError] '+a+' '+b}) }catch(e){} },
          a: function(){}, b: function(){},
          invoke: function(){ return null }
        }
      });
      handler = H.$new();
      S({m:'✓ handler 构造成功: '+handler.getClass().getName()});
    }catch(e){ S({m:'✗ handler 构造失败 '+String(e).slice(0,140)}) }
    // ③ 装池子 + it(userKey)
    try{ FK.addKeypool(Key, Ver); S({m:'① addKeypool(String,String) OK'}) }catch(e){ S({m:'① addKeypool 异常 '+String(e).slice(0,100)}) }
    var B64=Java.use('android.util.Base64'), Str=Java.use('java.lang.String');
    try{
      var ub = Str.$new(q16).getBytes('UTF-8');
      var r=FK.it(ub, ub.length);
      S({m:'② it(userKey_bytes,'+ub.length+') → OK'});
      S({m:'② urk() = '+clip(FK.urk(),50)});
    }catch(e){ S({m:'② it 异常 '+String(e).slice(0,120)}) }
    // ④ 真 unlock（3/4 参 + handler）
    var cands=[
      ['unlock3 (密文,章节,?)', function(){ return FK.unlock(blobB64, chId, q16, handler) }],
      ['unlock4 (密文,章节,?,?)', function(){ return FK.unlock(blobB64, chId, q16, '', handler) }],
      ['unlock3b (密文,userKey,章节)', function(){ return FK.unlock(blobB64, q16, chId, handler) }],
    ];
    for(var i=0;i<cands.length;i++){
      try{ dumpRes(cands[i][1](), '③ '+cands[i][0]) }
      catch(e){ S({m:'③ '+cands[i][0]+' 异常 '+String(e).slice(0,130)}) }
    }
    // ⑤ uk（4 参 byte[]）
    try{
      var db=B64.decode(blobB64,0), ub2=Str.$new(q16).getBytes('UTF-8');
      var r2=FK.uk(db, db.length, ub2, ub2.length);
      dumpRes(r2, '④ uk(密文,密文len,userKey,userKeylen)');
    }catch(e){ S({m:'④ uk 异常 '+String(e).slice(0,130)}) }
    // ⑥ unlockData
    try{
      var db2=B64.decode(blobB64,0);
      var r3=FK.unlockData(db2, q16, '', handler);
      dumpRes(r3, '⑤ unlockData(密文字节,userKey,?,handler)');
    }catch(e){ S({m:'⑤ unlockData 异常 '+String(e).slice(0,130)}) }
    // ⑦ FockUtil 对照
    try{ var FU=Java.use('com.qidian.QDReader.component.util.FockUtil'); var inst=FU.INSTANCE.value;
      var rr=inst.unlock(blobB64, chId); S({m:'⑥ FU.unlock2 status='+rr.status.value}) }catch(e){}
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}) }
});
