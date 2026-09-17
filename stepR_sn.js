// stepR_sn.js — 捕获 sn() 的输入+返回值 + 与之配对的 HTTP 请求
function S(o){try{send(o)}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s}catch(e){return '?'}}
function bytesToStr(b, len){
  try{ var n = (len && len>0 && len<=b.length) ? len : b.length;
       var arr=[]; for(var i=0;i<n && i<2000;i++) arr.push(b[i]&0xff);
       var s=''; for(var j=0;j<arr.length;j++) s += String.fromCharCode(arr[j]);
       return s; }catch(e){ return '(解码失败)' }
}
function save(name,txt){ try{ var f=Java.use('java.io.FileOutputStream').$new(DIR+name,true);
  f.write(Java.use('java.lang.String').$new(txt+'\n').getBytes('UTF-8')); f.close(); }catch(e){} }
Java.perform(function(){
  try{
    S({m:'=== R: sn() 输入+输出 + URL 配对 ==='});
    var FK=Java.use('com.yuewen.fock.Fock');
    var lastUrl='';
    // ① hook okhttp，记录当前请求 URL（用于与 sn 配对）
    try{
      var RC=Java.use('okhttp3.RealCall');
      RC.execute.implementation=function(){ try{ lastUrl=String(this.request().url().toString()) }catch(e){}; return this.execute() };
      RC.enqueue.implementation=function(cb){ try{ lastUrl=String(this.request().url().toString()) }catch(e){}; return this.enqueue(cb) };
      S({m:'✓ hook RealCall（记录 URL）'});
    }catch(e){ S({m:'✗ RealCall '+String(e).slice(0,80)}) }
    // ② hook sn([B,int)：打印输入串 + 返回值
    var snMs=FK.class.getDeclaredMethods(), done=false;
    for(var i=0;i<snMs.length;i++){
      if(String(snMs[i].getName())!=='sn') continue;
      (function(){
        try{
          var o=FK.sn.overload('[B','int');
          o.implementation=function(b, l){
            var inp=bytesToStr(b, l);
            var ret=o.call(this, b, l);
            var out='';
            try{
              if(ret===null) out='null';
              else if(ret.getClass().getName()==='[B') out=bytesToStr(ret, ret.length);
              else if(ret.getClass().getName()==='java.lang.String') out=String(ret);
              else out=String(ret);
            }catch(e){ out='(取值失败)' }
            var line='### URL='+clip(lastUrl,110)+'\n### IN ['+l+'] '+clip(inp,600)+'\n### OUT '+clip(out,300);
            S({m:line});
            save('SN_DUMP.txt', line);
            return ret;
          };
          S({m:'✓ hook sn([B,int)'}); done=true;
        }catch(e){ S({m:'✗ sn hook 失败 '+String(e).slice(0,90)}) }
      })();
      break;
    }
    if(!done) S({m:'未找到 sn([B,int)'});
    // ③ 触发一次带签名的请求：打开章节
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
