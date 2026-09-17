// stepE_464fock.js — 464 上走真实 Fock 链路
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function show(r,label){
  if(r===null||r===undefined){S({m:label+' → null'});return;}
  try{
    var fs=r.getClass().getDeclaredFields(), o={};
    for(var i=0;i<fs.length;i++){ fs[i].setAccessible(true); var v=fs[i].get(r);
      if(v===null){o[fs[i].getName()]=null;continue;}
      if(v.getClass().getName()==='[B'){ var s2='';try{s2=Java.use('java.lang.String').$new(v,'UTF-8')+'';}catch(e){}
        o[fs[i].getName()]='len='+v.length+' head='+clip(s2,40); } else o[fs[i].getName()]=clip(v,60); }
    S({m:label+' → '+JSON.stringify(o)});
  }catch(e){ S({m:label+' 字段读取失败 '+String(e).slice(0,90)}); }
}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blob=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    S({m:'=== E464: 走真实 Fock 链路（密文='+blob.length+' 章节='+chId+'）==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    S({m:'FockUtil: getKey='+clip(inst.getKey(),36)+' isHasKey='+inst.isHasKey()+' preUserKey='+clip(inst.getPreUserKey(),40)});
    // ① FockUtil.init（464 的真 init）
    try{ inst.init(ctx, String(inst.getPreUserKey()||'')); S({m:'① FockUtil.init OK → getKey='+clip(inst.getKey(),50)}); }
    catch(e){ S({m:'① init 异常 '+String(e).slice(0,140)}); }
    // ② getNibKey / getRtKey（464 新增，可能是解密要素）
    try{ S({m:'② getNibKey='+clip(inst.getNibKey(),50)}); }catch(e){ S({m:'② getNibKey 异常 '+String(e).slice(0,90)}); }
    try{ S({m:'② getRtKey='+clip(inst.getRtKey(),50)}); }catch(e){ S({m:'② getRtKey 异常 '+String(e).slice(0,90)}); }
    try{ S({m:'② checkEnvTraits 相关：checkSign='+clip(inst.checkSign(),80)}); }catch(e){}
    // ③ Fock 真类
    var FK=null;
    try{ FK=Java.use('com.yuewen.fock.Fock'); S({m:'③ com.yuewen.fock.Fock 可用'}); }
    catch(e){ S({m:'③ Fock 不可用 '+String(e).slice(0,110)}); }
    if(FK){
      try{ S({m:'③ currentUserKey='+clip(FK.currentUserKey(),50)}); }catch(e){ S({m:'③ currentUserKey 异常 '+String(e).slice(0,90)}); }
      try{ S({m:'③ addedKeyVersions='+clip(FK.addedKeyVersions(),80)}); }catch(e){ S({m:'③ addedKeyVersions 异常 '+String(e).slice(0,90)}); }
      // addKeys / addKeypool：把 MMKV 里的密钥池装进真引擎
      var pool=null;
      try{ var m=inst.loadLocalKey(ctx); if(m){ var it=Java.cast(m,Java.use('java.util.Map')).keySet().iterator();
            if(it.hasNext()){ var ver=String(it.next()); pool=String(Java.cast(m,Java.use('java.util.Map')).get(ver)); S({m:'③ 池子: ver='+ver+' key='+clip(pool,40)}); } } }catch(e){ S({m:'③ 读池子失败 '+String(e).slice(0,90)}); }
      if(pool){
        try{ FK.addKeys(pool, '1639985422'); S({m:'③ Fock.addKeys(pool,ver) OK'}); }catch(e){ S({m:'③ addKeys 异常 '+String(e).slice(0,140)}); }
        try{ S({m:'③ 之后 addedKeyVersions='+clip(FK.addedKeyVersions(),80)}); }catch(e){}
      }
      // ④ 真 unlock
      if(blob){
        try{ var r=FK.unlock(blob, chId); show(r,'④ Fock.unlock(密文,章节ID)'); }
        catch(e){ S({m:'④ Fock.unlock 异常 '+String(e).slice(0,150)}); }
        try{ var r2=FK.unlock(blob, String(inst.getPreUserKey()||'')); show(r2,'④ Fock.unlock(密文,QIMEI)'); }
        catch(e){}
      }
    }
    // ⑤ FockUtil.unlock（对照）
    if(blob){ try{ var r3=inst.unlock(blob, chId); show(r3,'⑤ FockUtil.unlock(密文,章节ID)'); }catch(e){ S({m:'⑤ 异常 '+String(e).slice(0,120)}); } }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}); }
});
