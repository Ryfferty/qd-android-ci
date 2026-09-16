// hook_v39_req.js — 只做：init(ctx,userKey) + requestKey(ctx,bookId)，让 App 去取密钥池
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
Java.perform(function(){
  var Out='/data/data/com.qidian.QDReader/files/v39_req.txt';
  try{var f=Java.use('java.io.File').$new(Out);if(f.exists())f.delete();}catch(e){}
  function W(s){try{var fo=Java.use('java.io.FileOutputStream').$new(Out,true);
    fo.write(Java.use('java.lang.String').$new(s+'\n').getBytes('UTF-8'));fo.close();}catch(e){}S({m:s});}
  W('=== v39 requestKey 阶段 ===');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var ctx=null; try{ctx=Java.use('android.app.ActivityThread').currentApplication();}catch(e){}
  W('ctx='+ctx);
  var P={}; try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var bookId=String(P.book_id||'1049120379'), ywg=String(P.ywguid||'');
  var inst=FU.INSTANCE.value;
  try{W('前: isHasKey='+inst.isHasKey()+' getKey='+inst.getKey()+' preUserKey='+inst.getPreUserKey());}catch(e){W('前 '+e);}
  Java.scheduleOnMainThread(function(){
    try{ if(ctx&&ywg){ inst.init(ctx,ywg); W('① init(ctx,'+ywg+') OK → preUserKey='+inst.getPreUserKey()); } }catch(e){W('① init 异常 '+e);}
    try{ var job=inst.requestKey(ctx, Java.use('java.lang.Long').parseLong(bookId));
         W('② requestKey(ctx,'+bookId+') 已发起 Job='+job); }catch(e){W('② requestKey 异常 '+String(e).slice(0,200));}
    W('=== v39 结束（异步请求由其自行完成）===');
  });
});
