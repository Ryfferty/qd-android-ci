// stepL_reqdump.js — 只做一件事：把 App 真实发出的请求（URL + 全部头 + body）原样打印
// 目的：拿它当"协议复刻的对照样本"，之后所有取数走纯协议
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function save(name, txt){ try{
  var f=Java.use('java.io.FileOutputStream').$new(DIR+name,true);
  f.write(Java.use('java.lang.String').$new(txt+'\n').getBytes('UTF-8')); f.close();
}catch(e){} }
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function dumpReq(req){
  try{
    var url=String(req.url().toString());
    if(!/argus|qidian|bookcontent|getkey|content|chapter/i.test(url)) return;
    var lines=[];
    lines.push('### URL: '+url);
    lines.push('### METHOD: '+req.method());
    try{
      var hd=req.headers(), names=hd.names().toArray();
      for(var i=0;i<names.length;i++){
        var k=String(names[i]);
        lines.push('### HDR '+k+': '+String(hd.get(k)));
      }
    }catch(e){ lines.push('### HDR 读取失败 '+e); }
    try{
      var b=req.body();
      if(b){ var Buf=Java.use('okio.Buffer').$new(); b.writeTo(Buf);
             var s=String(Buf.readUtf8());
             lines.push('### BODY: '+clip(s,600)); }
    }catch(e){}
    S({m:lines.join('\n')});
    save('REQDUMP.txt', lines.join('\n'));
  }catch(e){ S({m:'dumpReq 异常 '+String(e).slice(0,120)}); }
}
Java.perform(function(){
  try{
    S({m:'=== L: 请求全貌抓取（协议复刻对照用）==='});
    var dumped=0;
    // ① RealCall.execute / enqueue
    try{
      var RC=Java.use('okhttp3.RealCall');
      RC.execute.implementation=function(){
        try{ dumpReq(this.request()); dumped++; }catch(e){}
        return this.execute();
      };
      RC.enqueue.implementation=function(cb){
        try{ dumpReq(this.request()); dumped++; }catch(e){}
        return this.enqueue(cb);
      };
      S({m:'✓ hook RealCall.execute/enqueue'});
    }catch(e){ S({m:'✗ RealCall hook 失败 '+String(e).slice(0,110)}); }
    // ② BridgeInterceptor（兜底，App 自己加的 Cookie/UA 也在这层）
    try{
      var BI=Java.use('okhttp3.internal.http.BridgeInterceptor');
      BI.intercept.implementation=function(chain){
        try{ dumpReq(chain.request()); }catch(e){}
        return this.intercept(chain);
      };
      S({m:'✓ hook BridgeInterceptor'});
    }catch(e){ S({m:'✗ BridgeInterceptor hook 失败 '+String(e).slice(0,90)}); }
    // ③ 响应：只记 status 与前 200 字节
    try{
      var R=Java.use('okhttp3.Response');
      R.body.implementation=function(){
        var b=this.body();
        try{
          var u=String(this.request().url().toString());
          if(/argus|bookcontent|getkey|content/i.test(u)){
            var s=String(b.string());
            S({m:'### RESP '+clip(u,100)+' len='+s.length+' head='+clip(s,200)});
            save('RESPDUMP.txt', '### '+u+'\n'+clip(s,800));
          }
        }catch(e){}
        return b;
      };
      S({m:'✓ hook Response.body'});
    }catch(e){}
    // ④ 记录当前可用身份字段（供对照）
    try{
      var SB=Java.use('java.lang.StringBuilder').$new();
      ['ro.product.model','ro.product.brand','ro.build.fingerprint','ro.serialno'].forEach(function(k){
        try{ var c=Java.use('android.os.SystemProperties'); }catch(e){}
      });
      S({m:'（身份字段对照：见 REQDUMP 里的 QDInfo）'});
    }catch(e){}
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}); }
});
