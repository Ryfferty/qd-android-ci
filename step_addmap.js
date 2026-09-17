// step_addmap.js — ★ 决定性一步：loadLocalKey → addMap → unlock
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
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
     try{var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_addmap.txt',false);
      f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));f2.close();S({m:'★★ 明文已落盘 plain_addmap.txt'});}catch(e){}}
   } else o[fs[i].getName()]=clip(v,60);}
  return JSON.stringify(o);}catch(e){return 'refErr:'+e;}}
function walk(o,label){ try{ var M=Java.cast(o,Java.use('java.util.Map'));
  var sz=M.size(), it=M.keySet().iterator(), n=0, arr=[];
  while(it.hasNext()&&n<6){ var k=it.next(); arr.push(String(k)+'='+clip(M.get(k),40)); n++; }
  S({m:label+' size='+sz+' → '+arr.join(' | ')}); }catch(e){ S({m:label+' 遍历失败 '+String(e).slice(0,90)}); } }
Java.perform(function(){
  try{
    var P={}; try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blobB64=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    S({m:'=== addmap: loadLocalKey → addMap → unlock ==='});
    S({m:'密文长度='+blobB64.length+' 章节ID='+chId});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    S({m:'前置 getKey='+clip(inst.getKey(),36)+' isHasKey='+inst.isHasKey()});
    // ① 从 MMKV 读出密钥 Map
    var m=null;
    try{ m=inst.loadLocalKey(ctx); walk(m,'① loadLocalKey'); }
    catch(e){ S({m:'① loadLocalKey 直接调用失败 '+String(e).slice(0,110)}); }
    if(!m){
      try{ var ms=FU.class.getDeclaredMethods();
        for(var i=0;i<ms.length;i++){ if(String(ms[i].getName())==='loadLocalKey'){ ms[i].setAccessible(true);
          m=ms[i].invoke(inst, Java.array('java.lang.Object',[ctx])); break; } } 
        walk(m,'①(反射) loadLocalKey');
      }catch(e){ S({m:'① 反射也失败 '+String(e).slice(0,110)}); }
    }
    // ② ★ addMap：把 Map 装进引擎
    if(m){
      try{ inst.addMap(Java.cast(m, Java.use('java.util.Map'))); S({m:'② ✓ addMap 调用成功 → getKey='+clip(inst.getKey(),50)}); }
      catch(e){ S({m:'② addMap 异常 '+String(e).slice(0,160)}); }
    } else S({m:'② 无 Map，跳过 addMap'});
    S({m:'② 后 getKey='+clip(inst.getKey(),60)+' isHasKey='+inst.isHasKey()});
    // ③ 解锁（第二参数矩阵）
    var cands=[['章节ID',chId],['QIMEI',String(inst.getPreUserKey()||'')],['空串','']];
    for(var j=0;j<cands.length;j++){
      try{ var r=inst.unlock(blobB64, cands[j][1]); S({m:'③ unlock['+cands[j][0]+']: '+desc(r)}); }
      catch(e){ S({m:'③ unlock['+cands[j][0]+'] 异常 '+String(e).slice(0,140)}); }
    }
  }catch(e){ S({m:'✗ 顶层异常 '+String(e).slice(0,200)}); }
});
