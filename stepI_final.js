// stepI_final.js — 464：3 参重载 unlock + 同源密文
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
          try{ var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_464_WIN.txt',false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8')); f2.close(); S({m:'★★★ 明文已落盘 plain_464_WIN.txt'});}catch(e){}
        }
      } else o[fs[i].getName()]=clip(v,60); }
    S({m:label+' → '+JSON.stringify(o)});
  }catch(e){ S({m:label+' 读字段失败 '+String(e).slice(0,90)}); }
}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blob=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    var uk2=readText(DIR+'userkey.txt')||'';   // 由上一阶段写入（同源身份）
    S({m:'=== I: 464 终局（密文='+blob.length+' 同源userKey='+clip(uk2,40)+'）==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var uk=String(inst.getPreUserKey()||'');
    S({m:'App userKey='+clip(uk,50)});
    try{ inst.init(ctx, uk); }catch(e){}
    try{ var m=inst.loadLocalKey(ctx); if(m) inst.addMap(Java.cast(m,Java.use('java.util.Map'))); }catch(e){}
    // ① FockUtil.unlock 2 参（矩阵）
    var cands=[['章节ID',chId],['AppUserKey',uk],['空串','']];
    for(var i=0;i<cands.length;i++){
      try{ dump(inst.unlock(blob, cands[i][1]), '① FU.unlock2['+cands[i][0]+']'); }catch(e){ S({m:'① ['+cands[i][0]+'] 异常 '+String(e).slice(0,110)}); }
    }
    // ② Fock 真类：列出 unlock 重载并逐个试
    try{
      var FK=Java.use('com.yuewen.fock.Fock');
      var ms=FK.class.getDeclaredMethods();
      for(var j=0;j<ms.length;j++){
        var nm=String(ms[j].getName());
        if(nm!=='unlock' && nm!=='unlockData') continue;
        var ps=ms[j].getParameterTypes(), pt=[];
        for(var q=0;q<ps.length;q++) pt.push(String(ps[q].getName()).split('.').pop());
        S({m:'② Fock.'+nm+'('+pt.join(',')+')'});
        // 3 参 String 重载：试 (密文, userKey, 章节ID) 与 (密文, 章节ID, userKey)
        if(pt.length===3 && pt.join(',')==='String,String,String'){
          var combos=[[blob,uk,chId],[blob,chId,uk],[blob,uk2,chId],[blob,chId,uk2],[blob,uk,'']];
          for(var c=0;c<combos.length;c++){
            try{
              var r=ms[j].invoke(null, Java.array('java.lang.Object', combos[c]));
              dump(r, '② Fock.'+nm+'3['+c+']');
            }catch(e){ S({m:'   3参组合'+c+' 异常 '+String(e).slice(0,100)}); }
          }
        }
      }
    }catch(e){ S({m:'② Fock 反射失败 '+String(e).slice(0,120)}); }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}); }
});
