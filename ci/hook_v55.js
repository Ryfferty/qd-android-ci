// hook_v55.js — v15: 从 URL 容器一路打到正文 — unlockData→设备侧下载zip→提取.qd→正文解密矩阵
// 正文矩阵: Fock.uk(byte,int,byte,int) × key 候选(K16/batchKey全/dk/md5) × addKey 候选; FockUtil.unlock(3参String)
function S(o){try{send(o);}catch(e){}}
function hx(b,n){try{var x=new Uint8Array(b);var s='';var m=n;if(!m)m=x.length;for(var i=0;i<m;i++){var v=x[i].toString(16);if(v.length<2)v='0'+v;s+=v;}return s;}catch(e){return 'ERR';}}
function asc(a,n){
  try{
    var s='';var m=n;if(!m)m=80;if(a.length<m)m=a.length;
    for(var i=0;i<m;i=i+1){var c=a[i]&255;if(c>=32&&c<127){s+=String.fromCharCode(c);}else{s+='.';}}
    return s;
  }catch(e){return '?';}
}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
Java.perform(function(){
  S({m:'=== v15 start ==='});
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var BLOB=String(P.blob_b64||''), BK=String(P.batch_key||''), MD5=String(P.md5||'');
  var book='1049120379', cid='903350205';
  var FM=null;Process.enumerateModules().forEach(function(m){if(/libfock\.so$/.test(m.path))FM=m;});
  var B64=Java.use('android.util.Base64');
  var FK=Java.use('com.yuewen.fock.Fock');

  // ① URL 容器 → COS 直链
  var url=null;
  try{
    var r=FK.unlockData(B64.decode(BLOB,0),book,book+'_'+cid,null);
    S({m:'① unlockData status='+r.status.value+' len='+(r.data.value?r.data.value.length:0)});
    if(r.status.value===0&&r.data.value){
      var t=Java.use('java.lang.String').$new(r.data.value,'UTF-8')+'';
      url=t.substring(t.indexOf('http'));
      S({m:'① URL头80: '+url.substring(0,80)});
    }
  }catch(e){S({m:'① err '+String(e).slice(0,90)});}
  if(!url){S({m:'无URL, 终止'});return;}

  // ② 设备侧下载 zip (HttpURLConnection + gunzip)
  var qd=null;
  try{
    var URLc=Java.use('java.net.URL'); var conn=URLc.$new(url).openConnection();
    conn.setConnectTimeout(15000); conn.setReadTimeout(20000);
    conn.setRequestProperty('User-Agent','Mozilla/5.0');
    var ins=conn.getInputStream();
    try{ins=Java.use('java.util.zip.GZIPInputStream').$new(ins);S({m:'② (gzipped)'});}catch(e0){S({m:'② (raw)'})}
    var bos=Java.use('java.io.ByteArrayOutputStream').$new();
    var abuf=Java.array('byte',new Array(65536).fill(0));var rn;
    while((rn=ins.read(abuf))>0) bos.write(abuf,0,rn);
    var zipBytes=bos.toByteArray();
    S({m:'② 下载 '+zipBytes.length+'B magic='+hx(zipBytes,4)});
    // ZIP 提取
    var ZIS=Java.use('java.util.zip.ZipInputStream');
    var zis=ZIS.$new(Java.use('java.io.ByteArrayInputStream').$new(zipBytes));
    var ent;
    while((ent=zis.getNextEntry())!==null){
      S({m:'② 条目: '+ent.getName()+' ('+ent.getSize()+')'});
      var eb=Java.use('java.io.ByteArrayOutputStream').$new(); var x;
      while((x=zis.read(abuf))>0) eb.write(abuf,0,x);
      qd=eb.toByteArray();
    }
    if(qd) S({m:'② .qd len='+qd.length+' head='+hx(qd,16)+' tail='+hx(qd.slice(qd.length-16),16)});
  }catch(e){S({m:'② 下载/解压失败 '+String(e).slice(0,140)});}
  if(!qd){S({m:'无 .qd, 终止'});return;}

  // ③ 正文解密矩阵
  var nP=(qd[4]&255)|((qd[5]&255)<<8)|((qd[6]&255)<<16)|((qd[7]&255)<<24);
  if(nP<=0||nP>qd.length)nP=qd.length-24;
  var payload=qd.slice(8,8+nP); // 头 8B (u32 len)
  var K16=[];try{var h=BK.replace(/-/g,'');for(var i=0;i<32;i++)K16.push(parseInt(h.substr(i*2,2),16));}catch(e){}
  var Kfull=[];try{var h2=BK.replace(/-/g,'');for(var j=0;j<h2.length/2;j++)Kfull.push(parseInt(h2.substr(j*2,2),16));}catch(e){}
  var MD5b=[];try{for(var k=0;k<16;k++)MD5b.push(parseInt(MD5.substr(k*2,2),16));}catch(e){}
  var keysets={'K16':Java.array('byte',K16.map(x=>x>127?x-256:x)),
               'Kfull':Java.array('byte',Kfull.map(x=>x>127?x-256:x)),
               'MD5':Java.array('byte',MD5b.map(x=>x>127?x-256:x))};
  var addsets={'empty':null,'book':Java.array('byte',Array.from(Java.use('java.lang.String').$new(book).getBytes()))};
  function bArr(jstr){var s=jstr.getBytes();var a=new Array(s.length);for(var i=0;i<s.length;i++)a[i]=s[i];return Java.array('byte',a);}
  addsets['book']=Java.array('byte',Array.from(bArr(book)));
  var PAY=Java.array('byte',Array.from(payload).map(function(x){return x>127?x-256:x;}));
  S({m:'③ payload len='+payload.length+' %16='+(payload.length%16)});
  // 私有 native: m67572uk([B I [B I)→FockResult / uksf([B I [B I [B)→FockResult
  function dumpR(tag,r){
    if(r===null){S({m:tag+' → null'});return;}
    try{
      var st=r.status.value, d=r.data.value, ln=r.len!==undefined?r.len.value:'?';
      if(d&&d.length>0){var arr=Array.from(d);
        var pr=arr.slice(0,200).filter(function(c){c=c&0xff;return (c>=32&&c<127)||c===9||c===10||c===13;}).length/Math.min(200,d.length);
        S({m:'★ '+tag+' status='+st+' len='+d.length+' print='+pr.toFixed(2)+' : '+asc(arr,90)});
      } else S({m:tag+' status='+st+' len=0'});
    }catch(e){S({m:tag+' 解析失败 '+String(e).slice(0,70)});}
  }
  try{
    var UK=FK.m67572uk.overload('[B','int','[B','int');
    var E=Java.array('byte',[]);
    for(var kn2 in keysets){ for(var an2 in addsets){
      var add2=addsets[an2]; var alen2=add2?add2.length:0;
      try{ dumpR('uk['+kn2+'|'+an2+']', UK(PAY,payload.length,add2||E,alen2)); }
      catch(e){S({m:'uk['+kn2+'|'+an2+'] err '+String(e).slice(0,70)});}
    }}
    // 无 addKey 纯数据版 (addKey=K 自身变体: 换 PAY=各 key 材料? 不, data=payload 固定, addKey=K 逐一试)
    try{ dumpR('uk[空|K16]', UK(PAY,payload.length,keysets['K16'],16)); }catch(e){}
    try{ dumpR('uk[空|MD5]', UK(PAY,payload.length,keysets['MD5'],16)); }catch(e){}
    try{ dumpR('uk[空|Kfull]', UK(PAY,payload.length,keysets['Kfull'],36)); }catch(e){}
  }catch(e){S({m:'m67572uk 拿不到: '+String(e).slice(0,80)});}
  try{
    var UKSF=FK.uksf.overload('[B','int','[B','int','[B');
    var E2=Java.array('byte',[]);
    for(var kn3 in keysets){
      try{ dumpR('uksf[|'+kn3+']', UKSF(PAY,payload.length,E2,0,keysets[kn3])); }catch(e){}
      try{ dumpR('uksf['+kn3+'|空]', UKSF(PAY,payload.length,keysets[kn3],(keysets[kn3]||E2).length,E2)); }catch(e){}
    }
  }catch(e){S({m:'uksf 拿不到: '+String(e).slice(0,80)});}
  // FockUtil.unlock(3参 String): base64 版
  try{
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
    var b64url=B64.encodeToString(payload,2); // NO_WRAP
    var st=FU.unlock(b64url,book,book+'_'+cid);
    S({m:'FU.unlock(3参) status='+st});
  }catch(e){S({m:'FU.unlock err '+String(e).slice(0,90)});}
  S({m:'=== v15 done ==='});
});
