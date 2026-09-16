// hook_v42_matrix.js — 密钥池装载矩阵：4 种策略各自试 unlock
function S(o){try{send(o);}catch(e){}}
var DIR='/data/data/com.qidian.QDReader/files/', OUT=DIR+'v42_result.txt';
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
    o[fs[i].getName()]={len:v.length};
    if(v.length>100){var cn=0;for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
     S({m:'★★★★★★★ 明文！len='+v.length+' 中文字='+cn});S({m:'★★★ 正文',text:s2.slice(0,3000)});
     try{var f2=Java.use('java.io.FileOutputStream').$new(DIR+'v42_plaintext.txt',false);
      f2.write(Java.use('java.lang.String').$new(s2).getBytes('UTF-8'));f2.close();W('★ 明文落盘');}catch(e){}}
   } else o[fs[i].getName()]=String(v);}
  return JSON.stringify(o);}catch(e){return 'refErr:'+e;}}
function st(r){try{return String(JSON.parse(desc(r)).status);}catch(e){return '?';}}
Java.perform(function(){
 try{var f=Java.use('java.io.File').$new(OUT);if(f.exists())f.delete();}catch(e){}
 W('=== v42 密钥池矩阵 ===');
 var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
 var ctx=null;try{ctx=Java.use('android.app.ActivityThread').currentApplication();}catch(e){}
 var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
 var k0=P.Key||'', k1=P.key_ui1||'', ver=String(P.Version||''), blob=P.blob_b64||'';
 var chId=String(P.chapter_id||'903350205'), ywg=String(P.ywguid||'');
 W('账号 ywguid='+ywg+'  k0='+k0.length+'  k1='+k1.length+'  ver='+ver);
 var inst=FU.INSTANCE.value;
 Java.scheduleOnMainThread(function(){
  try{ if(ctx&&ywg){ inst.init(ctx,ywg); W('init OK preUserKey='+inst.getPreUserKey()); } }catch(e){W('init 异常 '+String(e).slice(0,90));}
  var strategies=[
   ['k0裸串', k0],
   ['k1裸串', k1],
   ['JSON{k0}', '{"'+ver+'":"'+k0+'"}'],
   ['JSON{k1}', '{"'+ver+'":"'+k1+'"}'],
   ['JSON{两把}', k1? '{"'+ver+'":"'+k0+'","'+(Number(ver)+1)+'":"'+k1+'"}' : '']
  ];
  for(var i=0;i<strategies.length;i++){
   if(!strategies[i][1]){W('['+strategies[i][0]+'] 跳过（空）');continue;}
   try{ inst.add(strategies[i][1], ver); }catch(e){ W('['+strategies[i][0]+'] add 异常 '+String(e).slice(0,80)); continue; }
   if(!blob){ W('['+strategies[i][0]+'] 无密文'); continue; }
   var r=null;
   try{ r=inst.unlock(blob, chId); }catch(e){ W('['+strategies[i][0]+'] unlock 异常 '+String(e).slice(0,90)); continue; }
   W('['+strategies[i][0]+'] add OK → unlock status='+st(r)+'  '+desc(r));
   if(st(r)==='0'){ W('★★★★★★★ 成功！策略='+strategies[i][0]); return; }
  }
  W('=== v42 结束 ===');
 });
});
