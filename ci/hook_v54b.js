// hook_v54b.js — v13: 引擎三段全量现场 (DES-IN / DES-OUT / FINAL) → XOR 反推真机 GCM keystream
// 只用 v9 参数(blob), dk 已证==引擎值; 差异必在 ①DES-OUT≠我们s1[128:] 或 ②ks 块8+ 计数器结构
function S(o){try{send(o);}catch(e){}}
function hx(p,n){try{var b=new Uint8Array(Memory.readByteArray(p,n));var s='';for(var i=0;i<b.length;i++)s+=('0'+b[i].toString(16)).slice(-2);return s;}catch(e){return 'ERR';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
Java.perform(function(){
  S({m:'=== v13 start ==='});
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var BLOB=String(P.blob_b64||'');
  var fm=null;Process.enumerateModules().forEach(function(m){if(/libfock\.so$/.test(m.path))fm=m;});
  if(!fm){S({m:'✗ libfock 未加载'});return;}
  var B=fm.base;
  // ① bl 0x75c0 (DEC1 入口): x0=in x1=len x2=iv8 x3=key8
  Interceptor.attach(B.add(0xb984),{onEnter:function(){
    var c=this.context;var len=parseInt(c.x1)&0xffff;
    S({m:'① DES-IN len='+len+' key='+hx(c.x3,8)+' iv='+hx(c.x2,8)});
    S({m:'① HEX='+hx(c.x0,len>4096?4096:len)});
  }});
  // ② 0xb988 (DEC1 返回)
  Interceptor.attach(B.add(0xb988),{onEnter:function(){
    var c=this.context;
    S({m:'② DES-OUT@x0='+hx(c.x0,392)});
    S({m:'② DES-OUT@x19='+hx(c.x19,392)});
  }});
  // 触发 (同 v12: attach 稳定后立即打)
  try{
    var B64=Java.use('android.util.Base64');
    var FK=Java.use('com.yuewen.fock.Fock');
    var r=FK.unlockData(B64.decode(BLOB,0),'1049120379','1049120379_903350205',null);
    S({m:'★ status='+r.status.value+' len='+(r.data.value?r.data.value.length:0)});
    if(r.data.value){
      var v=r.data.value;var s2='';
      for(var i=0;i<v.length;i++){var x=v[i]&0xff;s2+=('0'+x.toString(16)).slice(-2);}
      S({m:'★ FINAL_HEX='+s2});
    }
  }catch(e){S({m:'触发 '+String(e).slice(0,120)});}
  S({m:'=== v13 done ==='});
});
