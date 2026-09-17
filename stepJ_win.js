// stepJ_win.js — 统一身份：setPreUserKey(X) → 装池子 → unlock
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function dump(r,label){
  if(!r){ S({m:label+' → null'}); return; }
  try{ var fs=r.getClass().getDeclaredFields(), o={};
    for(var i=0;i<fs.length;i++){ fs[i].setAccessible(true); var v=fs[i].get(r);
      if(v===null){o[fs[i].getName()]=null;continue;}
      if(v.getClass().getName()==='[B'){ var s2='';try{s2=Java.use('java.lang.String').$new(v,'UTF-8')+'';}catch(e){}
        o[fs[i].getName()]='len='+v.length;
        if(v.length>100){
          var cn=0; for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
          S({m:'★★★★★★★ 明文！！！len='+v.length+' 中文字='+cn});
          S({m:'★★★ 正文',text:s2.slice(0,3000)});
          try{ var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_WIN.txt',false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8')); f2.close(); S({m:'★★★ 明文已落盘 plain_WIN.txt'});}catch(e){}
        }
      } else o[fs[i].getName()]=clip(v,60); }
    S({m:label+' → '+JSON.stringify(o)});
  }catch(e){ S({m:label+' 读字段失败 '+String(e).slice(0,90)}); }
}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blob=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    var FIXED=readText(DIR+'fixeduk.txt')||'';
    S({m:'=== J: 统一身份决胜 ==='});
    S({m:'指定 userKey='+clip(FIXED,50)+'  密文='+blob.length});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    S({m:'设备原 userKey='+clip(inst.getPreUserKey(),50)});
    // ① 把设备 userKey 设成与 argus 相同的值
    if(FIXED){
      try{ inst.setPreUserKey(FIXED); S({m:'① setPreUserKey OK → 复查='+clip(inst.getPreUserKey(),50)}); }
      catch(e){ S({m:'① setPreUserKey 异常 '+String(e).slice(0,120)}); }
    }
    // ② init + 装池子
    try{ inst.init(ctx, FIXED); S({m:'② init OK'}); }catch(e){ S({m:'② init 异常 '+String(e).slice(0,110)}); }
    try{ var m=inst.loadLocalKey(ctx); if(m) inst.addMap(Java.cast(m,Java.use('java.util.Map'))); S({m:'② loadLocalKey+addMap OK'}); }
    catch(e){ S({m:'② 装载异常 '+String(e).slice(0,110)}); }
    try{ var FK=Java.use('com.yuewen.fock.Fock');
      try{ S({m:'② currentUserKey='+clip(FK.currentUserKey(),50)+' addedKeyVersions='+clip(FK.addedKeyVersions(),50)}); }catch(e){}
      try{ FK.setup(FIXED); S({m:'② Fock.setup(userKey) OK'}); }catch(e){ S({m:'② Fock.setup 异常 '+String(e).slice(0,90)}); }
    }catch(e){}
    // ③ unlock 矩阵
    if(blob){
      var cands=[['章节ID',chId],['指定userKey',FIXED],['空串','']];
      for(var i=0;i<cands.length;i++){
        try{ dump(inst.unlock(blob, cands[i][1]), '③ FU.unlock['+cands[i][0]+']'); }
        catch(e){ S({m:'③ ['+cands[i][0]+'] 异常 '+String(e).slice(0,110)}); }
      }
      // Fock 3 参
      try{ var FK2=Java.use('com.yuewen.fock.Fock'); var ms=FK2.class.getDeclaredMethods();
        for(var j=0;j<ms.length;j++){
          var nm=String(ms[j].getName()); if(nm!=='unlock'&&nm!=='unlockData') continue;
          var ps=ms[j].getParameterTypes(), pt=[]; for(var q=0;q<ps.length;q++) pt.push(String(ps[q].getName()).split('.').pop());
          if(pt.length===3 && pt.join(',')==='String,String,String'){
            var combos=[[blob,FIXED,chId],[blob,chId,FIXED]];
            for(var c=0;c<combos.length;c++){
              try{ dump(ms[j].invoke(null, Java.array('java.lang.Object',combos[c])), '④ Fock3['+c+']'); }
              catch(e){ S({m:'④ Fock3['+c+'] 异常 '+String(e).slice(0,90)}); }
            }
          }
        }
      }catch(e){}
    }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}); }
});
