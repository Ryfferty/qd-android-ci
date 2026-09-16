// hook_v40_unlock.js — 密钥池应已就绪：add(argusKey,ver) + unlock(base64密文, 章节ID)
function S(o){try{send(o);}catch(e){}}
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
        S({m:'★★★★★★★ 明文！len='+v.length+' 中文字='+cn}); S({m:'★★★ 正文',text:s2.slice(0,3000)});
        try{var f2=Java.use('java.io.FileOutputStream').$new('/data/data/com.qidian.QDReader/files/v40_plaintext.txt',false);
          f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));f2.close();W2('★ 明文落盘');}catch(e){}}
    } else o[fs[i].getName()]=String(v);}
   return JSON.stringify(o);}catch(e){return 'refErr:'+e;}
}
var OUTF='/data/data/com.qidian.QDReader/files/v40_result.txt';
function W2(s){try{var fo=Java.use('java.io.FileOutputStream').$new(OUTF,true);
  fo.write(Java.use('java.lang.String').$new(s+'\n').getBytes('UTF-8'));fo.close();}catch(e){}S({m:s});}
Java.perform(function(){
  try{var f=Java.use('java.io.File').$new(OUTF);if(f.exists())f.delete();}catch(e){}
  W2('=== v40 unlock 阶段 ===');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var P={}; try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var keyA=P.Key||'', ver=String(P.Version||''), blobB64=P.blob_b64||'', chId=String(P.chapter_id||'903350205');
  var inst=FU.INSTANCE.value;
  Java.scheduleOnMainThread(function(){
    try{W2('前: isHasKey='+inst.isHasKey()+' getKey='+inst.getKey()+' preUserKey='+inst.getPreUserKey());}catch(e){}
    try{inst.add(keyA,ver);W2('① add(Key,'+ver+') OK isHasKey='+inst.isHasKey());}catch(e){W2('① add 异常 '+String(e).slice(0,150));}
    if(blobB64){
      try{W2('② unlock(base64密文 '+blobB64.length+', ak='+chId+'): '+desc(inst.unlock(blobB64,chId)));}
      catch(e){W2('② unlock 异常 '+String(e).slice(0,200));}
    }
    W2('=== v40 结束 ===');
  });
});
