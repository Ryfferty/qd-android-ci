// stepG_qimei.js — 在 464 上猎取 userKey(QIMEI) → setPreUserKey → unlock
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function readRaw(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return b.toByteArray();}catch(e){return null;}}
function readText(p){try{var b=readRaw(p); if(!b) return null;
 return Java.use('java.lang.String').$new(b,'UTF-8')+'';}catch(e){return null;}}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blob=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    S({m:'=== G: 猎取 QIMEI（464）==='});

    // ① MMKV 全文扫描 QIMEI 痕迹
    try{
      var t=readText('/data/data/com.qidian.QDReader/files/mmkv/pref_utils')||'';
      S({m:'MMKV 长度='+t.length});
      var cands=[];
      var re1=/(\d{13,20}:54:00:[0-9a-f:]{6,})/g, m1;
      while((m1=re1.exec(t))!==null) cands.push(m1[1]);
      var re2=/([0-9a-f]{16})/g, m2, c2=0;
      while((m2=re2.exec(t))!==null && c2<6){ cands.push('hex16:'+m2[1]); c2++; }
      S({m:'★ MMKV 里的候选: '+cands.slice(0,8).join(' | ')});
      var i=t.indexOf('QIMEI');
      if(i>=0) S({m:'★ MMKV QIMEI 上下文: '+clip(t.slice(Math.max(0,i-30), i+120).replace(/[^\x20-\x7e]/g,'.'),160)});
      else S({m:'MMKV 里没有 QIMEI 字样'});
    }catch(e){ S({m:'MMKV 扫描失败 '+String(e).slice(0,90)}); }

    // ② App 侧 API 逐个试
    var apis=[
      ['core.config.e.L()',      function(){ var E=Java.use('com.qidian.QDReader.core.config.e');
                                  try{ return String(E.INSTANCE.value.L()); }catch(e){ return String(E.L()); } }],
      ['config.e$L via 反射',     function(){ var E=Java.use('com.qidian.QDReader.core.config.e');
                                  var ms=E.class.getDeclaredMethods();
                                  for(var i=0;i<ms.length;i++){ if(String(ms[i].getName())==='L'){ ms[i].setAccessible(true);
                                    try{ return String(ms[i].invoke(E.INSTANCE.value||null, Java.array('java.lang.Object',[]))); }catch(e){} } }
                                  return ''; }],
      ['UserAction.getQIMEI',     function(){ var U=Java.use('com.qidian.QDReader.core.user.UserAction');
                                  try{ return String(U.getQIMEI()); }catch(e){ return ''; } }],
      ['FockUtil.getPreUserKey',  function(){ var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
                                  return String(FU.INSTANCE.value.getPreUserKey()||''); }],
    ];
    var found='';
    for(var i=0;i<apis.length;i++){
      try{ var v=apis[i][1](); S({m:'  '+(i+1)+') '+apis[i][0]+' = '+clip(v,60)});
           if(v && v!=='null' && v.length>5 && !found) found=v; }
      catch(e){ S({m:'  '+(i+1)+') '+apis[i][0]+' 异常 '+String(e).slice(0,80)}); }
    }
    // ③ 兜底：MMKV 里形如 <ts>:54:00:<mac> 的串
    if(!found){
      try{ var t2=readText('/data/data/com.qidian.QDReader/files/mmkv/pref_utils')||'';
        var m=t2.match(/(\d{13,20}:54:00:[0-9a-f:]{6,})/); if(m) found=m[1]; }catch(e){}
    }
    S({m:'★★ 最终采用 userKey='+clip(found,70)});

    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    if(found){
      try{ inst.setPreUserKey(found); S({m:'③ setPreUserKey OK → 复查='+clip(inst.getPreUserKey(),50)}); }
      catch(e){ S({m:'③ setPreUserKey 异常 '+String(e).slice(0,120)}); }
      try{ var FK0=Java.use('com.yuewen.fock.Fock'); FK0.setup(found); S({m:'③ Fock.setup(userKey) OK'}); }catch(e){ S({m:'③ Fock.setup 异常 '+String(e).slice(0,100)}); }
    } else S({m:'③ 仍无 userKey'});
    try{ inst.init(ctx, found||''); S({m:'③ init OK'}); }catch(e){}
    try{ var m3=inst.loadLocalKey(ctx); if(m3) inst.addMap(Java.cast(m3,Java.use('java.util.Map'))); S({m:'③ 装池子 OK'}); }catch(e){}

    // ④ unlock 矩阵
    if(blob){
      var cands2=[['章节ID',chId],['userKey',found],['空串','']];
      for(var j=0;j<cands2.length;j++){
        try{
          var r=inst.unlock(blob, cands2[j][1]);
          var fs=r.getClass().getDeclaredFields(), o={};
          for(var q=0;q<fs.length;q++){ fs[q].setAccessible(true); var v2=fs[q].get(r);
            if(v2===null){o[fs[q].getName()]=null;continue;}
            if(v2.getClass().getName()==='[B'){ var s3='';try{s3=Java.use('java.lang.String').$new(v2,'UTF-8')+'';}catch(e){}
              o[fs[q].getName()]='len='+v2.length;
              if(v2.length>100){ var cn=0; for(var k=0;k<s3.length;k++){var c=s3.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
                S({m:'★★★★★★★ 明文！len='+v2.length+' 中文字='+cn}); S({m:'★★★ 正文',text:s3.slice(0,3000)});
                try{ var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_G.txt',false);
                  f2.write(Java.use('java.lang.String').$new(s3).getBytes('UTF-8')); f2.close(); S({m:'★★ 明文已落盘'});}catch(e){} }
            } else o[fs[q].getName()]=clip(v2,50); }
          S({m:'④ unlock['+cands2[j][0]+'] → '+JSON.stringify(o)});
        }catch(e){ S({m:'④ unlock['+cands2[j][0]+'] 异常 '+String(e).slice(0,110)}); }
      }
    }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}); }
});
