// stepM_fockchain.js — 464 真引擎链路：逐个候选 userKey 试 it/urk/addKeypool/uk
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function callAny(obj, name, args){
  // 反射找到匹配的重载并调用（Java 层），返回结果或错误串
  try{
    var cl = obj ? obj.getClass() : Java.use('com.yuewen.fock.Fock').class;
    var ms = cl.getDeclaredMethods();
    for(var i=0;i<ms.length;i++){
      if(String(ms[i].getName())!==name) continue;
      var ps=ms[i].getParameterTypes();
      if(ps.length!==args.length) continue;
      try{
        ms[i].setAccessible(true);
        return { ok:true, ret: ms[i].invoke(obj, Java.array('java.lang.Object', args)) };
      }catch(e){ /* 试下一个重载 */ }
    }
    return { err:'无匹配重载 '+name+'/'+args.length };
  }catch(e){ return { err:String(e).slice(0,100) }; }
}
function show(r,label){
  if(r===null||r===undefined){ S({m:label+' → null'}); return; }
  try{ var fs=r.getClass().getDeclaredFields(), o={};
    for(var i=0;i<fs.length;i++){ fs[i].setAccessible(true); var v=fs[i].get(r);
      if(v===null){o[fs[i].getName()]=null;continue;}
      if(v.getClass().getName()==='[B'){ var s2='';try{s2=Java.use('java.lang.String').$new(v,'UTF-8')+'';}catch(e){}
        o[fs[i].getName()]='len='+v.length;
        if(v.length>100){ var cn=0; for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
          S({m:'★★★★★★★ 明文！！！len='+v.length+' 中文字='+cn}); S({m:'★★★ 正文',text:s2.slice(0,3000)});
          try{ var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_M.txt',false);
            f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8')); f2.close(); S({m:'★★★ 明文已落盘 plain_M.txt'});}catch(e){} } }
      else o[fs[i].getName()]=clip(v,60); }
    S({m:label+' → '+JSON.stringify(o)});
  }catch(e){ S({m:label+' 读字段失败 '+String(e).slice(0,80)}); }
}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blob=P.blob_b64||'', Key=P.Key||'', Ver=String(P.Version||'1639985422'), chId=String(P.chapter_id||'903350205');
    var q16=(P.qimei16||'');
    S({m:'=== M: 464 真引擎链路（Key len='+Key.length+' 密文='+blob.length+'）==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var fuInst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    // 候选 userKey 集合
    var cands=[];
    function add(tag,v){ if(v && String(v).length>5) cands.push([tag, String(v)]); }
    add('App.getPreUserKey', String(fuInst.getPreUserKey()||''));
    add('协议qimei16', q16);
    // MMKV 里的 QIMEI16/36
    try{ var mm=readText('/data/data/com.qidian.QDReader/files/mmkv/pref_utils')||'';
      var m1=mm.match(/O_STAR_Q_IMEI_16%\$([0-9a-f]{16,40})/); if(m1) add('MMKV_QIMEI16', m1[1]);
      var m2=mm.match(/O_STAR_Q_IMEI_36%\$([0-9a-f]{16,40})/); if(m2) add('MMKV_QIMEI36', m2[1]);
      var m3=mm.match(/BEACON_QIMEI\)\(([^)\x00-\x1f]+)/); if(m3) add('MMKV_BEACON_QIMEI', m3[1]);
    }catch(e){}
    S({m:'候选 userKey: '+cands.map(function(c){return c[0]+'='+clip(c[1],30);}).join(' | ')});

    var FK=Java.use('com.yuewen.fock.Fock');
    // ① 先看 Fock 当前状态
    var r1=callAny(null,'urk',[]); S({m:'urk() 初始 = '+(r1.ok?clip(r1.ret,50):r1.err)});
    var r2=callAny(null,'currentUserKey',[]); S({m:'currentUserKey() 初始 = '+(r2.ok?clip(r2.ret,50):r2.err)});
    var r3=callAny(null,'addedKeyVersions',[]); S({m:'addedKeyVersions() 初始 = '+(r3.ok?clip(r3.ret,50):r3.err)});

    // ② 装池子（真 API）
    var rAdd=callAny(null,'addKeypool',[Key, Ver]);
    S({m:'② addKeypool(Key,Ver) → '+(rAdd.ok?'OK ret='+clip(rAdd.ret,40):rAdd.err)});
    var rKeys=callAny(null,'addKeys',[Key, Ver]);
    S({m:'② addKeys(Key,Ver) → '+(rKeys.ok?'OK ret='+clip(rKeys.ret,40):rKeys.err)});
    var r3b=callAny(null,'addedKeyVersions',[]); S({m:'② 之后 addedKeyVersions = '+(r3b.ok?clip(r3b.ret,50):r3b.err)});

    // ③ 逐个候选 userKey：it(userKey) → urk 校验 → unlock
    for(var i=0;i<cands.length;i++){
      var tag=cands[i][0], uk=cands[i][1];
      S({m:'—— 候选['+i+'] '+tag+' = '+clip(uk,40)+' ——'});
      var ri=callAny(null,'it',[uk]);
      S({m:'   it(userKey) → '+(ri.ok?'OK ret='+clip(ri.ret,40):ri.err)});
      var ru=callAny(null,'urk',[]);
      S({m:'   urk() → '+(ru.ok?clip(ru.ret,50):ru.err)});
      // 用 FockUtil 解密（设备正常入口）
      try{ show(fuInst.unlock(blob, chId), '   FU.unlock(密文,章节ID)'); }catch(e){ S({m:'   FU.unlock 异常 '+String(e).slice(0,90)}); }
      // 真 API uk
      var ruk=callAny(null,'uk',[blob, chId]);
      if(ruk.ok) show(ruk.ret, '   Fock.uk(密文,章节ID)'); else S({m:'   Fock.uk → '+ruk.err});
      var ruk2=callAny(null,'uk',[blob, uk]);
      if(ruk2.ok) show(ruk2.ret, '   Fock.uk(密文,userKey)'); else S({m:'   Fock.uk(密文,userKey) → '+ruk2.err});
    }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}); }
});
