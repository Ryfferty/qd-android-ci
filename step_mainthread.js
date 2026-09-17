// step_mainthread.js — ★ 用 Java.scheduleOnMainThread 在主线程调用 native（MUST）
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…['+s.length+']':s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function desc(r){ if(r===null||r===undefined)return 'null';
 try{var o={};var fs=r.getClass().getDeclaredFields();
  for(var i=0;i<fs.length;i++){fs[i].setAccessible(true);var v=fs[i].get(r);
   if(v===null){o[fs[i].getName()]=null;continue;}
   if(v.getClass().getName()==='[B'){var s2=null;try{s2=Java.use('java.lang.String').$new(v,'UTF-8')+'';}catch(e){}
    o[fs[i].getName()]='len='+v.length;
    if(v.length>100){var cn=0;for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
     S({m:'★★★★★★★ 明文！len='+v.length+' 中文字='+cn});
     S({m:'★★★ 正文',text:s2.slice(0,3000)});
     try{var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_mainthread.txt',false);
      f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));f2.close();S({m:'★ 明文已落盘'});}catch(e){}}
   } else o[fs[i].getName()]=clip(v,60);}
  return JSON.stringify(o);}catch(e){return 'refErr:'+e;}}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blobB64=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    S({m:'=== mainthread: 主线程调用 init → 载入 → unlock ==='});
    Java.scheduleOnMainThread(function(){
      try{
        var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
        var inst=FU.INSTANCE.value;
        var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        var uk=String(inst.getPreUserKey()||'');
        S({m:'[主线程] 进入 OK，userKey='+clip(uk,45)});
        S({m:'[主线程] 调用前 getKey='+clip(inst.getKey(),40)+' isHasKey='+inst.isHasKey()});
        // ① init（App 启动时就是这么做的）
        try{ inst.init(ctx, uk); S({m:'[主线程] ✓ init 后 getKey='+clip(inst.getKey(),50)+' isHasKey='+inst.isHasKey()}); }
        catch(e){ S({m:'[主线程] ✗ init 异常 '+String(e).slice(0,160)}); }
        // ② loadLocalKey 反射找
        try{
          var cl=FU.class, ms=cl.getDeclaredMethods(), found=null;
          for(var i=0;i<ms.length;i++){ if(String(ms[i].getName())==='loadLocalKey'){ found=ms[i]; break; } }
          if(found){
            S({m:'[主线程] loadLocalKey 签名='+found.toString().slice(0,140)});
            var lk=found.invoke(inst, Java.array('java.lang.Object',[ctx]));
            S({m:'[主线程] loadLocalKey → '+clip(lk,100)});
          } else S({m:'[主线程] 没有 loadLocalKey 方法'});
        }catch(e){ S({m:'[主线程] loadLocalKey 反射调用失败 '+String(e).slice(0,140)}); }
        // ③ getKeyMap 反射
        try{
          var ms2=FU.class.getDeclaredMethods(), f2=null;
          for(var j=0;j<ms2.length;j++){ if(String(ms2[j].getName())==='getKeyMap'){ f2=ms2[j]; break; } }
          if(f2){ var km=f2.invoke(inst, Java.array('java.lang.Object',[ctx])); S({m:'[主线程] getKeyMap → '+clip(km,140)}); }
          else S({m:'[主线程] 没有 getKeyMap 方法'});
        }catch(e){ S({m:'[主线程] getKeyMap 失败 '+String(e).slice(0,120)}); }
        S({m:'[主线程] 载入后 getKey='+clip(inst.getKey(),60)});
        // ④ unlock（additionalKey = 章节ID）
        if(blobB64){
          try{ var r=inst.unlock(blobB64, chId); S({m:'[主线程] unlock: '+desc(r)}); }
          catch(e){ S({m:'[主线程] unlock 异常 '+String(e).slice(0,160)}); }
        } else S({m:'[主线程] 无密文'});
      }catch(e){ S({m:'[主线程] ✗ 顶层异常 '+String(e).slice(0,200)}); }
    });
    S({m:'已排入主线程队列'});
  }catch(e){ S({m:'✗ 顶层异常 '+String(e).slice(0,200)}); }
});
