// stepT_qdinfo.js — 专门抓 App 请求的 QDInfo 头原文（与协议逐字段对照用）
function S(o){try{send(o)}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s}catch(e){return '?'}}
function save(t){try{var f=Java.use('java.io.FileOutputStream').$new(DIR+'QDIFF.txt',true);
 f.write(Java.use('java.lang.String').$new(t+'\n').getBytes('UTF-8'));f.close();}catch(e){}}
Java.perform(function(){
  try{
    S({m:'=== T: 抓 QDInfo / 签名相关头 ==='});
    var C=Java.use('okhttp3.RealCall');
    var seen={};
    try{
      C.execute.implementation=function(){
        try{ dump(this.request()); }catch(e){}
        return this.execute();
      };
      C.enqueue.implementation=function(cb){
        try{ dump(this.request()); }catch(e){}
        return this.enqueue(cb);
      };
      S({m:'✓ hook RealCall'});
    }catch(e){ S({m:'✗ RealCall hook 失败 '+String(e).slice(0,90)}) }
    function dump(req){
      try{
        var url=String(req.url().toString());
        if(url.indexOf('qidian')<0 && url.indexOf('yuewen')<0) return;
        var hs=req.headers(), n=hs.size(), lines=['### '+clip(url,150)];
        for(var i=0;i<n;i++){
          var name=String(hs.name(i)), val=String(hs.value(i));
          if(/qdinfo|qdsign|sign|tstamp|user-agent|cookie|token|imei|device/i.test(name)){
            if(name.toLowerCase()==='cookie'){ continue; }   // cookie 太长且已单独处理
            lines.push('    '+name+': '+val);
          }
        }
        var key=lines.join('\n');
        if(!seen[key]){ seen[key]=1; S({m:key}); save(key); }
      }catch(e){}
    }
    // 触发一次请求
    try{
      var app=Java.use('android.app.ActivityThread').currentApplication();
      var ctx=app.getApplicationContext();
      var Intent=Java.use('android.content.Intent'), Uri=Java.use('android.net.Uri');
      var it=Intent.$new('android.intent.action.VIEW', Uri.parse('QDReader://OpenBook/1049120379/903350205'));
      it.addFlags(268435456); ctx.startActivity(it);
      S({m:'✓ deeplink 已发'});
    }catch(e){}
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}) }
});
