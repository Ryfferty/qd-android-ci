// stepS_snpair.js — 抓 sn 的完整输入+输出样本（用于本地验证 SHA-256 假设）
function S(o){try{send(o)}catch(e){}}
var DIR='/data/local/tmp/';
function b2s(b,len){
  try{ var n=(len&&len>0&&len<=b.length)?len:b.length; var s='';
    for(var i=0;i<n;i++) s+=String.fromCharCode(b[i]&0xff); return s;
  }catch(e){ return '(解码失败)' }
}
function save(t){ try{ var f=Java.use('java.io.FileOutputStream').$new(DIR+'SN_PAIRS.txt',true);
  f.write(Java.use('java.lang.String').$new(t+'\n').getBytes('UTF-8')); f.close(); }catch(e){} }
Java.perform(function(){
  try{
    S({m:'=== S: 抓 sn 输入输出对 ==='});
    var FK=Java.use('com.yuewen.fock.Fock');
    var cnt=0;
    try{
      var o=FK.sn.overload('[B','int');
      o.implementation=function(b,l){
        var inp=b2s(b,l);
        var ret=o.call(this,b,l);
        var out='';
        try{
          if(ret===null) out='null';
          else if(ret.getClass().getName()==='[B') out=b2s(ret, ret.length);
          else if(ret.getClass().getName()==='java.lang.String') out=String(ret);
          else out=String(ret);
        }catch(e){ out='(取值失败)' }
        cnt++;
        if(cnt<=20){
          var line='PAIR#'+cnt+' IN['+inp.length+']='+inp+'\nOUT['+out.length+']='+out;
          S({m:line});
          save(line);
        }
        return ret;
      };
      S({m:'✓ hook sn([B,int)'});
    }catch(e){ S({m:'✗ sn hook 失败 '+String(e).slice(0,110)}) }
    // 触发请求
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
