// stepF_userkey.js — 464：取真实 userKey → setPreUserKey → init → unlock
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function show(r,label){
  if(r===null||r===undefined){S({m:label+' → null'});return;}
  try{ var fs=r.getClass().getDeclaredFields(), o={};
    for(var i=0;i<fs.length;i++){ fs[i].setAccessible(true); var v=fs[i].get(r);
      if(v===null){o[fs[i].getName()]=null;continue;}
      if(v.getClass().getName()==='[B'){ var s2='';try{s2=Java.use('java.lang.String').$new(v,'UTF-8')+'';}catch(e){}
        o[fs[i].getName()]='len='+v.length;
        if(v.length>100){
          var cn=0; for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
          S({m:'★★★★★★★ 明文！len='+v.length+' 中文字='+cn});
          S({m:'★★★ 正文',text:s2.slice(0,3000)});
          try{ var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_464.txt',false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8')); f2.close(); S({m:'★★ 明文已落盘'});}catch(e){}
        }
      } else o[fs[i].getName()]=clip(v,60); }
    S({m:label+' → '+JSON.stringify(o)});
  }catch(e){ S({m:label+' 读字段失败 '+String(e).slice(0,90)}); }
}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blob=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    S({m:'=== F: 取 userKey → set → unlock（密文='+blob.length+'）==='});
    // ① 从 App 配置取 QIMEI（= 200 版验证过的 userKey 来源）
    var qm='';
    try{
      var E=Java.use('com.qidian.QDReader.core.config.e');
      var inst=E.$new();
      try{ qm=String(inst.L()); }catch(e1){
        try{ qm=String(E.L()); }catch(e2){ qm=''; }
      }
      S({m:'① core.config.e.L() = '+clip(qm,60)});
    }catch(e){ S({m:'① 取 e.L() 失败 '+String(e).slice(0,120)}); }
    // 兜底：从 MMKV BEACON_QIMEI 附近扫
    if(!qm){
      try{
        var t=readText('/data/data/com.qidian.QDReader/files/mmkv/pref_utils')||'';
        var m=t.match(/(\d{15,20}:54:00:[0-9a-f:]+)/);
        if(m){ qm=m[1]; S({m:'①(兜底 MMKV) QIMEI='+clip(qm,60)}); }
      }catch(e){}
    }
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    // ② setPreUserKey + init
    if(qm){
      try{ inst.setPreUserKey(qm); S({m:'② setPreUserKey OK → getPreUserKey='+clip(inst.getPreUserKey(),50)}); }
      catch(e){ S({m:'② setPreUserKey 异常 '+String(e).slice(0,120)}); }
    } else S({m:'② 无 QIMEI，跳过 setPreUserKey'});
    try{ inst.init(ctx, qm||String(inst.getPreUserKey()||'')); S({m:'② init OK'}); }catch(e){ S({m:'② init 异常 '+String(e).slice(0,110)}); }
    // ③ 装池子（MMKV → 引擎）
    try{ var m2=inst.loadLocalKey(ctx); if(m2) inst.addMap(Java.cast(m2,Java.use('java.util.Map'))); S({m:'③ loadLocalKey+addMap OK'}); }
    catch(e){ S({m:'③ 装载异常 '+String(e).slice(0,110)}); }
    // ④ 真 unlock（多种第二参数）
    var cands=[['章节ID',chId],['QIMEI',qm],['空串','']];
    for(var i=0;i<cands.length;i++){
      if(!blob) break;
      try{ var r=inst.unlock(blob, cands[i][1]); show(r,'④ unlock['+cands[i][0]+']'); }
      catch(e){ S({m:'④ unlock['+cands[i][0]+'] 异常 '+String(e).slice(0,120)}); }
    }
    // ⑤ Fock 真类对照
    try{ var FK=Java.use('com.yuewen.fock.Fock');
      try{ S({m:'⑤ Fock.currentUserKey='+clip(FK.currentUserKey(),40)+' addedKeyVersions='+clip(FK.addedKeyVersions(),60)}); }catch(e){}
      try{ var r2=FK.unlock(blob, chId); show(r2,'⑤ Fock.unlock(密文,章节ID)'); }catch(e){ S({m:'⑤ Fock.unlock 异常 '+String(e).slice(0,120)}); }
    }catch(e){}
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}); }
});
