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
     S({m:'★★★★★★★ 明文！len='+v.length+' 中文字='+cn});S({m:'★★★ 正文',text:s2.slice(0,3000)});
     try{var f2=Java.use('java.io.FileOutputStream').$new(DIR+'plain_add.txt',false);
      f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));f2.close();S({m:'★ 明文已落盘 /data/local/tmp/plain_add.txt'});}catch(e){}}
   } else o[fs[i].getName()]=clip(v,80);}
  return JSON.stringify(o);}catch(e){return 'refErr:'+e;}}
Java.perform(function(){
 var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
 var ctx=null; try{ctx=Java.use('android.app.ActivityThread').currentApplication();}catch(e){}
 var P={}; try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
 var keyA=P.Key||'', ver=String(P.Version||''), blobB64=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
 S({m:'=== 单步 add ==='});
 try{FU.INSTANCE.value.add(keyA,ver);S({m:'add OK → isHasKey='+FU.INSTANCE.value.isHasKey()});}catch(e){S({m:'add 异常 '+String(e).slice(0,160)});}
});
