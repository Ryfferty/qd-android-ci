// hook_v46.js — v6: 引擎直读答案. Native hook libfock 内部 3 个枢纽, 抓"引擎实际用的值"
//   fock_34497762@0x7530 (AES set_key: x0=ctx,x1=key,len=x2) — 抓 keypool_key 与 final_key(dk)
//   fock_43538120@0x143f0 (DES crypt: x0=key?, x1=ctx) 前后
//   fock_25045543@0xc098 (DES-CBC 封装: x0=in,x1=len,x2=iv,x3=key,x4=out)
//   fock_43195364@0xc214 (GCM 封装: x0=in,x1=len,x2=iv12,x3=key,x4=out)
// 同车先跑 v45 的 unlockData(命中过) 触发这些函数, 抓现场值 → 反推协议差在哪
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function hexAt(addr,n){try{var b=new Uint8Array(Memory.readByteArray(addr,n));var s='';for(var i=0;i<b.length;i++)s+=('0'+b[i].toString(16)).slice(-2);return s;}catch(e){return 'ERR';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
var REC=[];
Java.perform(function(){
  S({m:'=== v6 start ==='});
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var BLOB=String(P.blob_b64||''), book='1049120379', cid='903350205';
  var base=null, mod=null;
  Process.enumerateModules().forEach(function(m){ if(/libfock\.so$/.test(m.path)){mod=m;base=m.base;} });
  if(!mod){S({m:'✗ libfock.so 未加载'});return;}
  S({m:'libfock @'+base+' size='+mod.size});
  function hookAt(off,name,fn){
    try{
      Interceptor.attach(base.add(off),{onEnter:fn});
      S({m:'+ hook '+name+' @'+off.toString(16)});
    }catch(e){S({m:'- '+name+' '+String(e).slice(0,80)});}
  }
  // set_key: x0=ctx x1=key x2=len (0x7530 = fock_34497762)
  hookAt(0x7530,'AES-setkey',function(){
    var len=this.context.x2.toUInt32?this.context.x2.toUInt32():0;
    var r={f:'setkey',keyLen:len,key:hexAt(this.context.x1, Math.min(len,32))};
    REC.push(r); if(len===32||len===16) S({m:'★setkey len='+len+' key='+r.key});
  });
  // DES-CBC 封装 0xc098 (fock_25045543): x0=in x1=len x2=iv x3=key x4=out
  hookAt(0xc098,'DES-CBC',function(){
    var r={f:'des',in:hexAt(this.context.x0,16),len:this.context.x1.toUInt32(),iv:hexAt(this.context.x2,8),key:hexAt(this.context.x3,8)};
    REC.push(r); S({m:'★DES len='+r.len+' key='+r.key+' iv='+r.iv+' in16='+r.in});
  });
  // GCM 封装 0xc214 (fock_43195364): x0=in x1=len x2=iv(12) x3=key x4=out
  hookAt(0xc214,'GCM',function(){
    var r={f:'gcm',len:this.context.x1.toUInt32(),iv:hexAt(this.context.x2,12),key:hexAt(this.context.x3,32),in16:hexAt(this.context.x0,16)};
    REC.push(r); S({m:'★GCM len='+r.len+' key='+r.key+' iv='+r.iv});
  });
  // 触发命中过的 unlockData
  try{
    var B64=Java.use('android.util.Base64');
    var bb=B64.decode(BLOB,0);
    var FK=Java.use('com.yuewen.fock.Fock');
    var r=FK.unlockData(bb, book, book+'_'+cid, null);
    S({m:'unlockData status='+r.status.value+' len='+(r.data.value?r.data.value.length:0)});
  }catch(e){S({m:'触发失败 '+String(e).slice(0,140)});}
  var out=JSON.stringify(REC,null,1);
  S({m:'=== REC ==='});
  try{var f2=Java.use('java.io.FileOutputStream').$new('/data/local/tmp/ORACLE6.txt',false);
    f2.write(Java.use('java.lang.String').$new(out).getBytes('UTF-8'));f2.close();S({m:'ORACLE6 written'});}catch(e){S({m:'write fail '+e});}
  S(out.length<6000?out:'too big');
});
