// hook_v41b.js — 密钥池应已就绪：add + unlock（不再注入/init）
function S(o){try{send(o);}catch(e){}}
var DIR='/data/data/com.qidian.QDReader/files/', OUT=DIR+'v41b_result.txt';
function W(s){try{var fo=Java.use('java.io.FileOutputStream').$new(OUT,true);
 fo.write(Java.use('java.lang.String').$new(s+'\n').getBytes('UTF-8'));fo.close();}catch(e){}S({m:s});}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function desc(r){
 if(r===null||r===undefined)return 'null';
 try{var o={};var fs=r.getClass().getDeclaredFields();
  for(var i=0;i<fs.length;i++){fs[i].setAccessible(true);var v=fs[i].get(r);
   if(v===null){o[fs[i].getName()]=null;continue;}
   if(v.getClass().getName()==='[B'){var s2=null;try{s2=Java.use('java.lang.String').$new(v,'UTF-8')+'';}catch(e){}
    o[fs[i].getName()]={len:v.length,head:(s2||'').slice(0,50)};
    if(v.length>100){var cn=0;for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
     S({m:'★★★★★★★ 明文！len='+v.length+' 中文字='+cn});S({m:'★★★ 正文',text:s2.slice(0,3000)});
     try{var f2=Java.use('java.io.FileOutputStream').$new(DIR+'v41b_plaintext.txt',false);
      f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));f2.close();W('★ 明文落盘');}catch(e){}}
   } else o[fs[i].getName()]=String(v);}
  return JSON.stringify(o);}catch(e){return 'refErr:'+e;}}
Java.perform(function(){
 try{var f=Java.use('java.io.File').$new(OUT);if(f.exists())f.delete();}catch(e){}
 W('=== v41b add+unlock ===');
 var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
 var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
 var keyA=P.Key||'',ver=String(P.Version||''),blobB64=P.blob_b64||'',chId=String(P.chapter_id||'903350205');
 var inst=FU.INSTANCE.value;
 Java.scheduleOnMainThread(function(){
  try{W('前: isHasKey='+inst.isHasKey()+' getKey='+inst.getKey()+' preUserKey='+inst.getPreUserKey());}catch(e){}
  try{inst.add(keyA,ver);W('① add(Key,'+ver+') OK isHasKey='+inst.isHasKey());}catch(e){W('① add 异常 '+String(e).slice(0,150));}
  if(blobB64){try{W('② unlock: '+desc(inst.unlock(blobB64,chId)));}catch(e){W('② unlock 异常 '+String(e).slice(0,200));}}
  W('=== v41b 结束 ===');
 });
});
