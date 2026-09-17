// stepN_sig.js — dump Fock 真签名 + 用 byte[] 调用真链路
function S(o){try{send(o)}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s}catch(e){return '?'}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+''}catch(e){return null}}
function sigs(cl,name){
  var out=[], ms=cl.getDeclaredMethods();
  for(var i=0;i<ms.length;i++){ if(String(ms[i].getName())!==name) continue;
    var ps=ms[i].getParameterTypes(), pt=[];
    for(var j=0;j<ps.length;j++) pt.push(String(ps[j].getName()).replace('java.lang.',''));
    out.push(name+'('+pt.join(',')+')'); }
  return out;
}
function callBytes(name, args){
  var FK=Java.use('com.yuewen.fock.Fock'), ms=FK.class.getDeclaredMethods();
  for(var i=0;i<ms.length;i++){
    if(String(ms[i].getName())!==name) continue;
    var ps=ms[i].getParameterTypes(); if(ps.length!==args.length) continue;
    try{ ms[i].setAccessible(true); return {ok:true, ret:ms[i].invoke(null, Java.array('java.lang.Object',args))} }
    catch(e){ return {err:String(e).slice(0,110)} }
  }
  return {err:'无匹配 '+name+'/'+args.length};
}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}')}catch(e){}
    var blobP=P.blob_b64||'', Key=P.Key||'', Ver=String(P.Version||'1639985422'), chId=String(P.chapter_id||'903350205');
    var FK=Java.use('com.yuewen.fock.Fock');
    S({m:'=== N: 真签名 ==='});
    ['it','uk','urk','addKeypool','addKeys','setup','sn','av','lk','rmdk','unlock','unlockData','dataForLog','checkEnvTraits'].forEach(function(nm){
      var s2=sigs(FK.class, nm);
      if(s2.length) S({m:'  '+s2.join('  |  ')});
    });
    // 恢复显示被截断的签名（分段打印）
    var all=sigs(FK.class,'it').concat(sigs(FK.class,'uk'),sigs(FK.class,'addKeypool'));
    S({m:'★ 重点: '+all.join('  |  ')});

    var B64=Java.use('android.util.Base64');
    var Str=Java.use('java.lang.String');
    var kb=B64.decode(Key, 0);            // 密钥池字节
    var ub=Str.$new(String(P.qimei16||'')).getBytes('UTF-8');   // userKey 字节
    var db=B64.decode(blobP, 0);          // 密文字节
    S({m:'字节长度: key='+kb.length+' userKey='+ub.length+' cipher='+db.length});

    // ① setup(userKey) = it([B I)
    var r1=callBytes('it',[ub, 0]); S({m:'① it(userKey,0) → '+(r1.ok?'OK':r1.err)});
    var r2=callBytes('urk',[]);     S({m:'① urk() = '+(r2.ok?clip(r2.ret,50):r2.err)});
    // ② addKeypool(byte[] key, int/String ver?)
    var rk1=callBytes('addKeypool',[kb, 1639985422]); S({m:'② addKeypool(key,ver:int) → '+(rk1.ok?'OK':rk1.err)});
    var rk2=callBytes('addKeypool',[kb, Ver]);        S({m:'② addKeypool(key,ver:String) → '+(rk2.ok?'OK':rk2.err)});
    var rk3=callBytes('addKeypool',[Key, Ver]);       S({m:'② addKeypool(key:String,ver:String) → '+(rk3.ok?'OK':rk3.err)});
    var rv=callBytes('addedKeyVersions',[]);
    if(rv.ok){
      try{ S({m:'② addedKeyVersions='+Java.use('java.util.Arrays').toString(rv.ret)}); }
      catch(e){ S({m:'② addedKeyVersions(数组,无法打印)'}); }
    }
    // ③ uk：真签名全试
    var cand=[['uk',[db, chId]],['uk',[db, ub]],['uk',[db, 903350205]],['uk',[db, ub, 0]],['uk',[db, 903350205, 0]]];
    for(var i=0;i<cand.length;i++){
      var r=callBytes(cand[i][0], cand[i][1]);
      if(r.ok){
        try{ var fr=r.ret, fs=fr.getClass().getDeclaredFields(), o={};
          for(var q=0;q<fs.length;q++){ fs[q].setAccessible(true); var v=fs[q].get(fr);
            if(v===null){o[fs[q].getName()]=null;continue}
            if(v.getClass().getName()==='[B'){ var s3='';try{s3=Java.use('java.lang.String').$new(v,'UTF-8')+''}catch(e){}
              o[fs[q].getName()]='len='+v.length;
              if(v.length>100){ var cn=0; for(var k=0;k<s3.length;k++){var c=s3.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++}
                S({m:'★★★★★★★ 明文！！！len='+v.length+' 中文字='+cn}); S({m:'★★★ 正文',text:s3.slice(0,3000)});
                try{ var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_N.txt',false); f2.write(Java.use('java.lang.String').$new(s3).getBytes('UTF-8')); f2.close(); S({m:'★★★ 明文已落盘'})}catch(e){} } }
            else o[fs[q].getName()]=clip(v,50) }
          S({m:'③ uk['+i+'] → '+JSON.stringify(o)});
        }catch(e){ S({m:'③ uk['+i+'] 取值失败'}) }
      } else S({m:'③ uk['+i+'] → '+r.err});
    }
    // ④ FockUtil.unlock 对照（String 入口）
    try{ var FU=Java.use('com.qidian.QDReader.component.util.FockUtil'); var inst=FU.INSTANCE.value;
      var rr=inst.unlock(blobP, chId);
      S({m:'④ FU.unlock(String) status='+rr.status.value});
    }catch(e){}
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}) }
});
