// hook_v59.js — v19: 同车 unlockData 成功后 → addKeys 注册变体 → uk/resf/lk/sn/restoreShufflingText 全打
function S(o){try{send(o);}catch(e){}}
function asc(a,n){try{var s='';var m=n;if(!m)m=100;if(a.length<m)m=a.length;for(var i=0;i<m;i=i+1){var c=a[i]&255;if(c>=32&&c<127){s+=String.fromCharCode(c);}else{s+='.';}}return s;}catch(e){try{var s2='';var x=new Uint8Array(a);for(var j=0;j<Math.min(x.length,n||100);j++){var cc=x[j];s2+=(cc>=32&&cc<127)?String.fromCharCode(cc):'.';}return s2;}catch(e2){return '?';}}}
function hx(b,n){try{var x=new Uint8Array(b);var s='';var m=n;if(!m)m=x.length;for(var i=0;i<m;i=i+1){var v=x[i].toString(16);if(v.length<2)v='0'+v;s+=v;}return s;}catch(e){return 'ERR';}}
function bArr(str){return Java.use('java.lang.String').$new(str).getBytes();}
Java.perform(function(){
  var C=Java.use('com.yuewen.fock.Fock');
  var Cc=C.class;
  function mRef(n){try{return Cc.getDeclaredMethod(n,Cc.getClassLoader?null:null);}catch(e){return null;}}
  // 用反射拿所有方法(绕过 Java 名字混淆)
  var methods=Cc.getDeclaredMethods();
  function byName(n){for(var i=0;i<methods.length;i++){if(methods[i].getName()===n)return methods[i];}return null;}
  // 私有方法名是 m67567ak 等——按签名找
  function bySig(ret,params){var res=[];for(var i=0;i<methods.length;i++){var mm=methods[i];if(ret&&mm.getReturnType().getName()!==ret)continue;var ps=mm.getParameterTypes();if(ps.length!==params.length)continue;var ok=1;for(var k=0;k<ps.length;k++){if(ps[k].getName()!==params[k])ok=0;}if(ok)res.push(mm);}return res;}
  var UK   = bySig('com.yuewen.fock.Fock$FockResult',['[B','int','[B','int'])[0];
  var UKSF = bySig('com.yuewen.fock.Fock$FockResult',['[B','int','[B','int','[B'])[0];
  var RESF = bySig('[B',['[B','int','[B'])[0];
  var LKM  = bySig('[B',['[B','int'])[0];
  var SNM  = bySig('java.lang.String',['[B','int'])[0];
  var AKM  = bySig(void 0,['[B','int','[B'])[0];
  S({m:'签名定位: uk='+!!UK+' uksf='+!!UKSF+' resf='+!!RESF+' lk='+!!LKM+' sn='+!!SNM+' ak='+!!AKM});
  UK.setAccessible(true); if(UKSF)UKSF.setAccessible(true);
  if(RESF)RESF.setAccessible(true); if(LKM)LKM.setAccessible(true);
  if(SNM)SNM.setAccessible(true); if(AKM)AKM.setAccessible(true);
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  S({m:'params: blob='+((P.blob_b64||'').length)+' payload预取='+((P.payload_b64||'').length)+' book='+P.book});
  var book=P.book+'', cid=P.cid+'';
  var PAY=null;
  function bytesFromJava(jb){var a=[];for(var i=0;i<jb.length;i++)a.push(jb[i]);return Java.array('byte',a);}
  // ★ payload 优先设备侧自取 (runner 到不了 COS 时 blob_b64 仍在 params 里)
  try{
    var UD=C.unlockData.overload('[B','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
    var blobb=Java.use('android.util.Base64').decode(P.blob_b64,2);
    var r0=UD.call(C,bytesFromJava(blobb),book,book+'_'+cid,null);
    S({m:'⓪ unlockData(blob) st='+r0.status.value+' len='+r0.length.value});
    if(r0.status.value===0){
      var urlS=(''+r0.data.value)+'';  // data 是 byte[]? .value 返回 Java 对象 → toString 不可靠, 直接按字节转 String
      var urlB=r0.data.value, urlLen=r0.length.value;
      var us='';for(var q=0;q<urlLen;q++){us+=String.fromCharCode(urlB[q]&255);}
      S({m:'⓪ URL='+us.slice(0,70)});
      var con=Java.use('java.net.URL').$new(us).openConnection();
      con.setConnectTimeout(15000);con.setReadTimeout(25000);
      con.setRequestProperty('User-Agent','okhttp/4.9.0');
      var is=con.getInputStream();
      var bo=Java.use('java.io.ByteArrayOutputStream').$new();
      var buf=Java.array('byte',new Array(8192).fill(0));var rd;
      while((rd=is.read(buf,0,8192))>0)bo.write(buf,0,rd);
      var zbytes=bo.toByteArray();
      S({m:'⓪ zip='+zbytes.length+'B'});
      // 存文件 → ZipFile 解 (byte 精确)
      var fos=Java.use('java.io.FileOutputStream').$new('/data/data/com.qidian.QDReader/cache/ch.zip');
      fos.write(zbytes);fos.close();
      var zf=Java.use('java.util.zip.ZipFile').$new('/data/data/com.qidian.QDReader/cache/ch.zip');
      var en=zf.entries();var qdBytes=null;
      while(en.hasMoreElements()){
        var ent=en.nextElement();
        if((''+ent.getName()).endsWith('.qd')){
          var eis=zf.getInputStream(ent);var eb=Java.use('java.io.ByteArrayOutputStream').$new();var er;
          while((er=eis.read(buf,0,8192))>0)eb.write(buf,0,er);
          qdBytes=eb.toByteArray();
        }
      }
      zf.close();
      if(qdBytes){
        // u32 nP at [4..8)
        var nPv=(qdBytes[4]&255)|((qdBytes[5]&255)<<8)|((qdBytes[6]&255)<<16)|((qdBytes[7]&255)<<24);
        if(nPv<=0||nPv>qdBytes.length-8)nPv=qdBytes.length-24;
        var carr=[];for(var g=8;g<8+nPv;g++)carr.push(qdBytes[g]);
        PAY=Java.array('byte',carr);
        S({m:'⓪★ PAY 设备侧自取='+PAY.length+'B head='+asc(carr,16)});
      } else S({m:'⓪ zip 无 .qd 条目'});
    }
  }catch(e){S({m:'⓪ 设备侧取 payload 失败: '+String(e).slice(0,120)});}
  if(!PAY){ // 回退 runner 预取
    PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);return Array.from(Array.from({length:raw.length},function(_,i){return raw[i];}));})());
    S({m:'⓪ 回退 runner payload='+PAY.length+'B'});
  }
  var bkno=(P.batch_key||'').replace(/-/g,'');
  // 候选第3参 keys
  var Ks={'book':bArr(book),'pair':bArr(book+'_'+cid),'bkUUID':bArr(P.batch_key||''),
          'md5':bArr(P.md5||''),'empty':Java.array('byte',[])};
  function fr(tag,r){
    if(r===null||r===undefined){S({m:tag+' → null'});return;}
    try{
      var st=r.status.value, d=r.data.value, dl=r.length.value;
      if(st===0){S({m:'████ '+tag+' status=0 len='+dl+' asc='+asc(d,140)});S({m:'★PLAIN_B64='+Java.use('android.util.Base64').encodeToString(d.length>4096?Java.array('byte',Array.from(d).slice(0,4096)):d,2)});return 1;}
      S({m:tag+' st='+st+' len='+dl+(dl>0?' head='+asc(d,42):'')});
    }catch(e){S({m:tag+' 读异常 '+String(e).slice(0,80)});}
    return 0;
  }
  // 真 unlockData 用 blob (params 里有 blob_b64 则跑一次注册池)
  if(P.blob_b64){
    try{
      var blobb=Java.use('android.util.Base64').decode(P.blob_b64,2);
      var barr=[];for(var i2=0;i2<blobb.length;i2++)barr.push(blobb[i2]);
      var UD2=C.unlockData.overload('[B','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
      var rr=UD2.call(C,Java.array('byte',barr),book,book+'_'+cid,null);
      S({m:'⓪b unlockData(blob) st='+rr.status.value+' len='+rr.length.value});
    }catch(e){S({m:'⓪b '+String(e).slice(0,100)});}
  }
  // ① addKeys String3+handler 注册变体 (App 下载后可能调它注册 body key)
  try{
    var AK=C.addKeys.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
    var trips=[[book+'_'+cid,book,book+'_'+cid],[book,book+'_'+cid,book],[P.Version||'',book,book+'_'+cid],[(P.md5||''),book,book+'_'+cid],['',book,book+'_'+cid]];
    for(var t=0;t<trips.length;t++){
      try{AK.call(C,trips[t][0],trips[t][1],trips[t][2],null);S({m:'① addKeys('+trips[t].join('|').slice(0,40)+') OK'});}catch(e2){S({m:'① addKeys err '+String(e2).slice(0,60)});}
    }
  }catch(e){S({m:'① addKeys 定位失败 '+String(e).slice(0,70)});}
  // ② uk × 全 keys (addKeys 之后可能翻正)
  var hit=0;
  for(var kn in Ks){
    try{ if(fr('② uk(PAY|'+kn+')',UK.invoke(null,PAY,PAY.length,Ks[kn],Ks[kn].length)))hit=1; }catch(e){S({m:'② uk|'+kn+' 异常 '+String(e).slice(0,90)});}
  }
  // ③ resf / lk / sn (直接返回体, 无 FockResult)
  var kn3=0;
  for(var kn2 in Ks){
    if(!RESF||kn3++>3)break;
    try{var out=RESF.invoke(null,PAY,PAY.length,Ks[kn2]);
      if(out&&out.length>0)S({m:'③ resf|'+kn2+' len='+out.length+' asc='+asc(out,80)});
      else S({m:'③ resf|'+kn2+' 空/null'});
    }catch(e){S({m:'③ resf|'+kn2+' ex '+String(e).slice(0,70)});}
  }
  if(LKM){try{var o2=LKM.invoke(null,PAY,PAY.length);S({m:'④ lk len='+(o2?o2.length:'null')+' asc='+asc(o2,80)});}catch(e){S({m:'④ lk ex '+String(e).slice(0,80)});}}
  if(SNM){try{var o3=SNM.invoke(null,PAY,PAY.length);S({m:'⑤ sn='+(o3?(''+o3).slice(0,120):'null')});}catch(e){S({m:'⑤ sn ex '+String(e).slice(0,80)});}}
  // ⑥ unlock(String,String,String,null) b64 正文
  try{
    var b64s=Java.use('android.util.Base64').encodeToString(PAY,2)+'';
    var U4=C.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
    var combos=[[b64s,book,book+'_'+cid],[b64s,book+'_'+cid,book]];
    for(var c2=0;c2<combos.length;c2++){
      try{ if(fr('⑥ unlock4['+c2+']',U4.call(C,combos[c2][0],combos[c2][1],combos[c2][2],null)))hit=1; }catch(e){S({m:'⑥['+c2+'] ex '+String(e).slice(0,80)});}
    }
  }catch(e){S({m:'⑥ 定位失败 '+String(e).slice(0,70)});}
  S({m:'v19 done hit='+hit});
});
