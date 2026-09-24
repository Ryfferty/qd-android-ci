// hook_v53.js — v12 终结版: attach 稳定 App, BP fock+0xbbf4 直读 SHA 输入 concat_buf = dk 公式原材料
// 输出: sel16(引擎自池) + userKey + addKey 拼接现场 (48-96B) → 公式当场看
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function hexAt(addr,n){try{var b=new Uint8Array(Memory.readByteArray(addr,n));var s='';for(var i=0;i<b.length;i++)s+=('0'+b[i].toString(16)).slice(-2);return s;}catch(e){return 'ERR';}}
function ascAt(addr,n){try{var b=new Uint8Array(Memory.readByteArray(addr,n));var s='';for(var i=0;i<b.length;i++){var c=b[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
var N=0;
Java.perform(function(){
  S({m:'=== v12 start ==='});
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var BLOB=String(P.blob_b64||'');
  var book='1049120379', cid='1049120379_903350205';
  var fm=null; Process.enumerateModules().forEach(function(m){if(/libfock\.so$/.test(m.path))fm=m;});
  if(!fm){S({m:'✗ libfock 未加载'});return;}
  S({m:'fock @'+fm.base});
  // ★ 0xbbf4: SHA-256 返回点 (unidbg BP 实证: x24=concat_buf 消息, x23=decrypted_kp96, x22=1st_sha, x19=finalkey)
  Interceptor.attach(fm.base.add(0xbbf4),{onEnter:function(a){
    var ctx=this.context;
    var x19=ctx.x19, x22=ctx.x22, x23=ctx.x23, x24=ctx.x24;
    N++;
    S({m:'◆#'+N+' bbf4: x22(1stsha)='+hexAt(x22,32)});
    S({m:'   x23(decKP96)='+hexAt(x23,96)});
    S({m:'   x24(concat80)hex='+hexAt(x24,80)});
    S({m:'   x24(concat80)asc='+ascAt(x24,80)});
    S({m:'   x19(finalkey)='+hexAt(x19,32)});
  }});
  // 触发
  try{
    var B64=Java.use('android.util.Base64');
    var bb=B64.decode(BLOB,0);
    var FK=Java.use('com.yuewen.fock.Fock');
    var r=FK.unlockData(bb,book,cid,null);
    S({m:'★unlockData status='+r.status.value+' len='+(r.data.value?r.data.value.length:0)});
    if(r.data.value){var t=Java.use('java.lang.String').$new(r.data.value,'UTF-8')+'';S({m:'★明文: '+clip(t,200)});}
  }catch(e){S({m:'触发 '+String(e).slice(0,120)});}
  S({m:'bbf4 命中次数='+N});
  S({m:'=== v12 done ==='});
});
