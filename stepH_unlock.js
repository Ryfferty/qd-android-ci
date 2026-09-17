// stepH_unlock.js — 464 决战：用 App 自己的 preUserKey 走完整链路并解锁
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function dump(r,label){
  if(!r){ S({m:label+' → null'}); return; }
  try{ var fs=r.getClass().getDeclaredFields(), o={}; var got=false;
    for(var i=0;i<fs.length;i++){ fs[i].setAccessible(true); var v=fs[i].get(r);
      if(v===null){o[fs[i].getName()]=null;continue;}
      if(v.getClass().getName()==='[B'){ var s2='';try{s2=Java.use('java.lang.String').$new(v,'UTF-8')+'';}catch(e){}
        o[fs[i].getName()]='len='+v.length;
        if(v.length>100){
          var cn=0; for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
          S({m:'★★★★★★★ 明文！！！len='+v.length+' 中文字='+cn});
          S({m:'★★★ 正文',text:s2.slice(0,3000)});
          try{ var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_464_FINAL.txt',false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8')); f2.close(); S({m:'★★★ 明文已落盘 plain_464_FINAL.txt'}); got=true;}catch(e){}
        }
      } else o[fs[i].getName()]=clip(v,60); }
    S({m:label+' → '+JSON.stringify(o)});
  }catch(e){ S({m:label+' 读字段失败 '+String(e).slice(0,90)}); }
}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blob=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    S({m:'=== H: 464 决战（密文='+blob.length+' 章节='+chId+'）==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var uk=String(inst.getPreUserKey()||'');
    S({m:'★★ App 自带 userKey='+clip(uk,60)});
    S({m:'调用前 getKey='+clip(inst.getKey(),36)+' isHasKey='+inst.isHasKey()});
    // ① init（App 自己的 userKey）
    try{ inst.init(ctx, uk); S({m:'① init(ctx, userKey) OK → getKey='+clip(inst.getKey(),50)}); }
    catch(e){ S({m:'① init 异常 '+String(e).slice(0,120)}); }
    // ② 装池子
    try{ var m=inst.loadLocalKey(ctx); if(m){ inst.addMap(Java.cast(m,Java.use('java.util.Map')));
      S({m:'② loadLocalKey + addMap OK'}); } else S({m:'② loadLocalKey=null'}); }
    catch(e){ S({m:'② 装载异常 '+String(e).slice(0,120)}); }
    // ③ Fock 真类状态
    try{ var FK=Java.use('com.yuewen.fock.Fock');
      try{ S({m:'③ currentUserKey='+clip(FK.currentUserKey(),50)}); }catch(e){}
      try{ S({m:'③ addedKeyVersions='+clip(FK.addedKeyVersions(),70)}); }catch(e){}
      try{ S({m:'③ av='+clip(FK.av(),50)+' urk='+clip(FK.urk(),50)+' rmdk='+clip(FK.rmdk(),50)}); }catch(e){ S({m:'③ av/urk/rmdk 不可读'}); }
    }catch(e){ S({m:'③ Fock 不可用 '+String(e).slice(0,90)}); }
    // ④ unlock 矩阵（第二参数用章节ID / userKey / 空串）
    if(blob){
      var cands=[['章节ID',chId],['userKey',uk],['空串','']];
      for(var i=0;i<cands.length;i++){
        try{ var r=inst.unlock(blob, cands[i][1]); dump(r,'④ FockUtil.unlock['+cands[i][0]+']'); }
        catch(e){ S({m:'④ unlock['+cands[i][0]+'] 异常 '+String(e).slice(0,120)}); }
      }
    } else S({m:'④ 无密文'});
    // ⑤ Fock.unlock 对照
    try{ var FK2=Java.use('com.yuewen.fock.Fock'); var r2=FK2.unlock(blob, chId); dump(r2,'⑤ Fock.unlock(密文,章节ID)'); }
    catch(e){ S({m:'⑤ Fock.unlock 异常 '+String(e).slice(0,110)}); }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}); }
});
