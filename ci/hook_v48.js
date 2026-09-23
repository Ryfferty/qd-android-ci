// hook_v48.js — v8: 同一辆车抓三个真值, 解出 dk 公式的最后缺口
//  A) okhttp 抓 App 自己的 getkey 响应 (它的池子原文 vs 我们协议 Key 是否同物)
//  B) hook Fock.addKeypool/addKeys Java 入口 (App 自装载现场: 内容+userKey 态)
//  C) DES/GCM 引擎现场 dk (已知可挂)
//  然后 unlockData(协议blob) + unlockData(App 深链自取的 blob 若有) 全对照
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function hexAt(addr,n){try{var b=new Uint8Array(Memory.readByteArray(addr,n));var s='';for(var i=0;i<b.length;i++)s+=('0'+b[i].toString(16)).slice(-2);return s;}catch(e){return 'ERR';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
Java.perform(function(){
  S({m:'=== v8 start ==='});
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var BLOB=String(P.blob_b64||'');
  S({m:'协议 Key=' + clip(String(P.Key||''),40)});
  S({m:'协议 userKey=' + clip(String(P.userKey||''),40)});

  // ---- A) okhttp 响应旁听 (纯读) ----
  try{
    var RS=Java.use('okhttp3.Response');
    var RB=Java.use('okhttp3.ResponseBody');
    // peek body 只针对 argus URL, 其他放过
    var Inter=Java.use('okhttp3.Interceptor');
    // 简单方案: hook RealResponseBody.string()/bytes()
    var RRB=null; try{RRB=Java.use('okhttp3.internal.http.RealResponseBody');}catch(e){ try{RRB=Java.use('okhttp3.internal.connection.RealResponseBody');}catch(e2){} }
    if(RRB){
      try{
        RRB.string.implementation=function(){
          var s=this.string();
          try{ if(/"Key"|encryptedKey|Version/i.test(s)) S({m:'◆RESP.body: '+clip(s,300)}); }catch(e){}
          return s;
        };
        RRB.bytes.implementation=function(){
          var r=this.bytes();
          try{ var t=Java.use('java.lang.String').$new(r,'UTF-8')+''; if(/"Key"|Version/i.test(t)) S({m:'◆RESP.bytes: '+clip(t,300)}); }catch(e){}
          return r;
        };
        S({m:'+ okhttp body 旁听已挂'});
      }catch(e){S({m:'- body hook: '+String(e).slice(0,100)});}
    } else S({m:'- RealResponseBody 类未找到'});
  }catch(e){S({m:'- okhttp: '+String(e).slice(0,110)});}

  // ---- B) addKeypool / addKeys Java 入口 (App 自己装载池子的现场) ----
  try{
    var FK=Java.use('com.yuewen.fock.Fock');
    try{
      FK.addKeypool.overload('java.lang.String','java.lang.String').implementation=function(k,v){
        S({m:'★★★ addKeypool 现场: userKey态='+clip(FK.currentUserKey(),40)});
        S({m:'   Key='+clip(k,80)});
        S({m:'   Ver='+clip(v,20)});
        S({m:'   === 与协议Key相等? '+(String(k)===String(P.Key))});
        return this.addKeypool(k,v);
      };
      S({m:'+ addKeypool hooked'});
    }catch(e){S({m:'- addKeypool: '+String(e).slice(0,90)});}
    try{
      FK.addKeys.overloads.forEach(function(o){
        o.implementation=function(){
          var a=Array.prototype.slice.call(arguments);
          S({m:'★★★ addKeys('+a.length+'p): a0='+clip(String(a[0]),80)+' a1='+clip(String(a[1]),20)});
          S({m:'   === a0 与协议Key相等? '+(String(a[0])===String(P.Key))});
          return o.apply(this, a);
        };
      });
      S({m:'+ addKeys hooked'});
    }catch(e){S({m:'- addKeys: '+String(e).slice(0,90)});}
    try{
      FK.setup.overload('java.lang.String').implementation=function(x){
        S({m:'★★ setup(x) x='+clip(x,50)+' (currentUserKey 前='+clip(FK.currentUserKey(),40)+')'});
        return this.setup(x);
      };
      S({m:'+ setup hooked'});
    }catch(e){}
  }catch(e){S({m:'✗ Fock: '+String(e).slice(0,110)});}

  // ---- C) 引擎 dk ----
  try{
    var fm=null; Process.enumerateModules().forEach(function(m){if(/libfock\.so$/.test(m.path))fm=m;});
    if(fm){
      Interceptor.attach(fm.base.add(0xc098),{onEnter:function(a){
        S({m:'◆DES len='+a[1].toUInt32()+' key8='+hexAt(a[3],8)});
      }});
      Interceptor.attach(fm.base.add(0xc214),{onEnter:function(a){
        S({m:'◆GCM key32='+hexAt(a[3],32)+' iv12='+hexAt(a[2],12)+' len='+a[1].toUInt32()});
      }});
      S({m:'+ DES/GCM hooked'});
    }
  }catch(e){S({m:'- native hook: '+String(e).slice(0,90)});}

  // ---- 触发: 我们的 unlockData (协议同轮 blob) ----
  try{
    var B64=Java.use('android.util.Base64');
    var bb=B64.decode(BLOB,0);
    var r=FK.unlockData(bb,'1049120379','1049120379_903350205',null);
    S({m:'★unlockData(协议blob) status='+r.status.value+' len='+(r.data.value?r.data.value.length:0)});
    if(r.data.value&&r.data.value.length){
      var t=Java.use('java.lang.String').$new(r.data.value,'UTF-8')+'';
      S({m:'★明文: '+clip(t,200)});
    }
  }catch(e){S({m:'触发失败 '+String(e).slice(0,130)});}
  S({m:'=== v8 done ==='});
});
