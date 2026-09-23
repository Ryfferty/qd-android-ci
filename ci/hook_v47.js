// hook_v47.js — v7: 决定性测量 — SHA-256 输入消息 + keypool AES set_key 现场
// 手法: ①hook libcrypto SHA256_Update, 记录每轮流(≤8轮=一次SHA256)完整消息 ②等 dk 目标出现 → 打印公式
//       ②dlopen("libfock.so") 拿真实 base 后补 hook fock 0x7530(setkey) 现场 key
//       ③Fock.addedKeyVersions + 引擎内 map dump: 找 App 池子明文存哪
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function hexAt(addr,n){try{var b=new Uint8Array(Memory.readByteArray(addr,n));var s='';for(var i=0;i<b.length;i++)s+=('0'+b[i].toString(16)).slice(-2);return s;}catch(e){return 'ERR';}}
function ascAt(addr,n){try{var b=new Uint8Array(Memory.readByteArray(addr,n));var s='';for(var i=0;i<b.length;i++){var c=b[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
var DK_HEX='2a60160c93dd70a77060290c7b6be05a0cd372844aa5a34b615d25104e398ebf';
var CUR=null; var SHAS=[];
Java.perform(function(){
  S({m:'=== v7 start ==='});
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var BLOB=String(P.blob_b64||''), book='1049120379', cid='903350205';
  // ① SHA256 hooks (BoringSSL: SHA256_Update(ctx, data, len); SHA256_final(ctx, md))
  var lc=null;
  try{ lc = Process.findModuleByName('libcrypto.so'); }catch(e){}
  if(!lc){ ['libssl.so','libc.so'].forEach(function(mn){try{var m=Process.findModuleByName(mn); if(m&&!lc)lc=m;}catch(e){}}); }
  var hooked=0;
  ['SHA256_Update','SHA256_Final','SHA256'].forEach(function(fn){
    var addr=null;
    try{ addr = Module.findExportByName(lc?lc.name:null, fn) || Module.findExportByName(null, fn); }catch(e){}
    if(!addr) return;
    try{
      if(fn==='SHA256_Update'){
        Interceptor.attach(addr,{onEnter:function(a){
          var len=a[2].toUInt32();
          if(!CUR) CUR={upd:[],fns:[]};
          CUR.upd.push({len:len, hex:hexAt(a[1],Math.min(len,200)), asc:ascAt(a[1],Math.min(len,120))});
        }});
      } else if(fn==='SHA256_Final'){
        Interceptor.attach(addr,{onEnter:function(a){
          if(!CUR){CUR={upd:[],fns:[]};}
          var out=hexAt(a[1],32);
          CUR.digest=out;
          if(out===DK_HEX){ CUR.MATCH='***DK***'; }
          SHAS.push(CUR);
          S({m:'◆SHA256 final='+out+(out===DK_HEX?' ★★DK命中':'')+' upd='+CUR.upd.map(function(u){return '['+u.len+']'+u.hex.slice(0,140);}).join(' + ')});
          if(out===DK_HEX){ S({m:'★★★DK 消息全文: '+CUR.upd.map(function(u){return 'len='+u.len+' hex='+u.hex+' asc='+u.asc;}).join(' || ')}); }
          CUR=null;
        }});
      } else {
        Interceptor.attach(addr,{onEnter:function(a){
          var len=a[1].toUInt32();
          var out={one:true,len:len,hex:hexAt(a[0],Math.min(len,400)),asc:ascAt(a[0],Math.min(len,200))};
          SHAS.push(out);
          S({m:'◆SHA256(1shot) len='+len+' hex='+out.hex.slice(0,200)});
        },onLeave:function(r){ try{ /* md 指针参数3 */ }catch(e){} }});
      }
      hooked++; S({m:'+ hook '+fn});
    }catch(e){S({m:'- '+fn+': '+String(e).slice(0,80)});}
  });
  if(!hooked) S({m:'✗ 没挂上任何 SHA256 (找符号: '+Object.keys(lc||{}).join(',')+')'});
  // ② dlopen fock 真实 base 补 setkey
  try{
    var h=Module.findBaseAddress('libfock.so')||Module.ensureInitialized('libfock.so');
    var mm=Process.findModuleByAddress(h);
    if(mm){
      try{
        Interceptor.attach(mm.base.add(0x7530),{onEnter:function(a){
          var len=a[2].toUInt32();
          var kh=hexAt(a[1],Math.min(len,32));
          S({m:'◆fock-setkey len='+len+' key='+kh});
          if(kh===DK_HEX.slice(0,32)) S({m:'  (setkey=DK前32 ✓)'});
        }});
        S({m:'+ hook fock0x7530 @'+mm.base});
      }catch(e){S({m:'- fock0x7530: '+String(e).slice(0,80)});}
    } else S({m:'✗ fock module by addr 失败'});
  }catch(e){S({m:'- dlopen/base: '+String(e).slice(0,100)});}
  // ③ DES/GCM 现场 (v6 已知可用, 再挂一遍拿本轮 in16=st1 头部对照)
  try{
    var fm=null; Process.enumerateModules().forEach(function(m){if(/libfock\.so$/.test(m.path))fm=m;});
    if(fm){
      Interceptor.attach(fm.base.add(0xc098),{onEnter:function(a){
        S({m:'◆DES len='+a[1].toUInt32()+' key='+hexAt(a[3],8)+' in16='+hexAt(a[0],16)});
      }});
      Interceptor.attach(fm.base.add(0xc214),{onEnter:function(a){
        S({m:'◆GCM len='+a[1].toUInt32()+' key='+hexAt(a[3],32)+' iv='+hexAt(a[2],12)});
      }});
      S({m:'+ DES/GCM rehooked'});
    }
  }catch(e){S({m:'- rehook: '+String(e).slice(0,80)});}
  // ④ Java 层池子 dump: getKey() map 内容
  try{
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var m=inst.getKeyMap ? inst.getKeyMap() : null;
    if(m){ var it=m.entrySet().iterator(); while(it.hasNext()){ var en=it.next(); S({m:'◆KeyMap['+clip(String(en.getKey()),24)+']='+clip(String(en.getValue()),120)}); } }
    S({m:'◆getKey()='+clip(inst.getKey(),60)});
  }catch(e){S({m:'- KeyMap: '+String(e).slice(0,110)});}
  // 触发
  try{
    var B64=Java.use('android.util.Base64');
    var bb=B64.decode(BLOB,0);
    var FK=Java.use('com.yuewen.fock.Fock');
    var r=FK.unlockData(bb, book, book+'_'+cid, null);
    S({m:'unlockData status='+r.status.value+' len='+(r.data.value?r.data.value.length:0)});
  }catch(e){S({m:'触发失败 '+String(e).slice(0,140)});}
  // 兜底: 扫描所有 SHA256 记录
  S({m:'=== SHA 流汇总 ==='});
  SHAS.forEach(function(rec,i){
    if(rec.MATCH) S({m:'#'+i+' ★★★DK: '+JSON.stringify(rec.upd)});
    else if(rec.one) S({m:'#'+i+' 1shot len='+rec.len+' '+rec.hex.slice(0,120)});
    else S({m:'#'+i+' digest='+rec.digest+' upds='+rec.upd.map(function(u){return u.len+':'+u.hex.slice(0,80);}).join('+')});
  });
  S({m:'=== v7 done ==='});
});
