function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…['+s.length+']':s;}catch(e){return '?';}}
Java.perform(function(){
  try{
    var P={};
    try{P=JSON.parse(readText(DIR+'params.json')||'{}');}catch(e){}
    var bookId=P.book_id||'1040025277';
    S({m:'=== appreqkey: 让 App 自己请求密钥 ==='});
    S({m:'bookId='+bookId+'  argusKey.len='+((P.Key||'').length)+' ver='+(P.Version||'')});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    if(!inst){S({m:'✗ INSTANCE null'});return;}
    try{S({m:'前置 getKey='+clip(inst.getKey(),40)+' isHasKey='+inst.isHasKey()+' preUserKey='+clip(inst.getPreUserKey(),40)});}catch(e){S({m:'前置异常 '+e});}
    var ctx=null;
    try{ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();}catch(e){}
    if(!ctx){S({m:'✗ ctx null'});return;}
    // ★ 调 App 自己的公开 API：内部 getH(HTTP) → save → add
    try{
      var job=inst.requestKey(ctx, Java.use('java.lang.Long').parseLong(String(bookId)));
      S({m:'✓ requestKey 已发起 job='+clip(job,80)});
    }catch(e){ S({m:'✗ requestKey 异常 '+String(e).slice(0,200)}); }
    // 顺带看一眼 getKeyMap（App 自己的池子视图）
    try{
      var km=inst.getKeyMap(ctx);
      if(km){
        var it=km.entrySet().iterator(), arr=[], c=0;
        while(it.hasNext() && c<6){ var en=it.next(); arr.push(String(en.getKey())+'='+clip(en.getValue(),20)); c++; }
        S({m:'getKeyMap 条目='+c+' → '+arr.join(' | ')});
      } else S({m:'getKeyMap=null'});
    }catch(e){ S({m:'getKeyMap 异常 '+String(e).slice(0,120)}); }
  }catch(e){ S({m:'✗ 顶层异常 '+String(e).slice(0,200)}); }
});
