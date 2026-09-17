function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…['+s.length+']':s;}catch(e){return '?';}}
function desc(r){ if(r===null||r===undefined)return 'null';
 try{var o={};var fs=r.getClass().getDeclaredFields();
  for(var i=0;i<fs.length;i++){fs[i].setAccessible(true);var v=fs[i].get(r);
   if(v===null){o[fs[i].getName()]=null;continue;}
   if(v.getClass().getName()==='[B'){var s2=null;try{s2=Java.use('java.lang.String').$new(v,'UTF-8')+'';}catch(e){}
    o[fs[i].getName()]='len='+v.length;
    if(v.length>100){var cn=0;for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
     S({m:'★★★★★★★ 明文！len='+v.length+' 中文字='+cn});
     S({m:'★★★ 正文',text:s2.slice(0,3000)});
     try{var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_afterkey.txt',false);
      f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));f2.close();S({m:'★ 明文已落盘'});}catch(e){}}
   } else o[fs[i].getName()]=clip(v,60);}
  return JSON.stringify(o);}catch(e){return 'refErr:'+e;}}
Java.perform(function(){
  try{
    var P={};
    try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var blobB64=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
    S({m:'=== afterkey: 看 App 自己请求后的状态 ==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    if(!inst){S({m:'✗ INSTANCE null'});return;}
    try{S({m:'getKey='+clip(inst.getKey(),60)});}catch(e){S({m:'getKey 异常 '+e});}
    try{S({m:'isHasKey='+inst.isHasKey()});}catch(e){}
    try{S({m:'getPreUserKey='+clip(inst.getPreUserKey(),60)});}catch(e){}
    var ctx=null;
    try{ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();}catch(e){}
    try{
      var km=inst.getKeyMap(ctx);
      if(km){var it=km.entrySet().iterator(),arr=[],c=0;
        while(it.hasNext()&&c<8){var en=it.next();arr.push(String(en.getKey())+'='+clip(en.getValue(),24));c++;}
        S({m:'★ getKeyMap 条目='+c+' → '+arr.join(' | ')});} else S({m:'getKeyMap=null'});
    }catch(e){ S({m:'getKeyMap 异常 '+String(e).slice(0,120)}); }
    var uk=inst.getPreUserKey();
    try{ var r=inst.unlock(blobB64, uk); S({m:'unlock: '+desc(r)}); }
    catch(e){ S({m:'unlock 异常 '+String(e).slice(0,200)}); }
  }catch(e){ S({m:'✗ 顶层异常 '+String(e).slice(0,200)}); }
});
