// step_initload.js — 让 Fock 引擎从 MMKV 载入密钥（init），随后立刻解锁
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
     try{var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_initload.txt',false);
      f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));f2.close();S({m:'★ 明文已落盘'});}catch(e){}}
   } else o[fs[i].getName()]=clip(v,60);}
  return JSON.stringify(o);}catch(e){return 'refErr:'+e;}}
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blobB64=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    S({m:'=== initload: init → 校验 → unlock ==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var uk=String(inst.getPreUserKey()||'');
    S({m:'userKey='+clip(uk,50)+'  调用前 getKey='+clip(inst.getKey(),40)});
    // ★ init(context, userKey)：App 启动时就是这么调的，应从 MMKV 载入 pref_fock_key
    try{ inst.init(ctx, uk); S({m:'✓ init 返回，getKey='+clip(inst.getKey(),40)+' isHasKey='+inst.isHasKey()}); }
    catch(e){ S({m:'✗ init 异常 '+String(e).slice(0,180)}); }
    // 再试 loadLocalKey（双写法）
    try{ var lk=inst.loadLocalKey(ctx); S({m:'loadLocalKey → '+clip(lk,80)}); }catch(e1){
      try{ var lk2=inst.loadLocalKey.overload('android.content.Context').call(inst, ctx); S({m:'loadLocalKey(overload) → '+clip(lk2,80)}); }
      catch(e2){ S({m:'loadLocalKey 两种写法都失败: '+String(e1).slice(0,60)+' / '+String(e2).slice(0,60)}); }
    }
    try{ var km=inst.getKeyMap(ctx); S({m:'getKeyMap → '+clip(km,120)}); }catch(e){ S({m:'getKeyMap 异常 '+String(e).slice(0,80)}); }
    S({m:'init 后 getKey='+clip(inst.getKey(),60)});
    // 立刻解锁：additionalKey 用章节 ID
    if(blobB64){
      try{ var r=inst.unlock(blobB64, chId); S({m:'unlock: '+desc(r)}); }
      catch(e){ S({m:'unlock 异常 '+String(e).slice(0,180)}); }
    } else S({m:'无密文，跳过 unlock'});
  }catch(e){ S({m:'✗ 顶层异常 '+String(e).slice(0,200)}); }
});
