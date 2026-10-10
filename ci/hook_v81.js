// hook_v81.js — v42: ★收官验证: ① 事件流全串不截断 dump ② 主动复算链 (key=uk[:36] vs "0"+uk[:36] 双假说) 与 a.b.b 直调三向比对
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function hexp(b,n){if(!b)return 'null';var s='';for(var i=0;i<Math.min(n||16,b.length);i++){var v=b[i]&0xff;s+=(v<16?'0':'')+v.toString(16);}return s;}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<raw.length;i++)a.push(raw[i]);return a;})());
  var uk=P.userKey, book=P.book, cid=P.cid;
  var SALT='2EEE1433A152E84B3756301D8FA3E69A';
  var A=Java.use('java.lang.String');
  var B64=Java.use('android.util.Base64');
  var JAR=Java.use('java.util.Arrays');
  S({m:'v42 开跑 uk全='+uk+' len='+uk.length});
  var INB=false; var ev=[];
  try{
    var Ci=Java.use('javax.crypto.Cipher');
    var i3=Ci.init.overload('int','java.security.Key','java.security.spec.AlgorithmParameterSpec');
    i3.implementation=function(mode,key,spec){
      if(INB){try{var kb=key.getEncoded();var ivb=spec&&spec.getIV?spec.getIV():null;
        ev.push({t:'ck3',keyStr:A.$new(kb,'UTF-8')+'',ivH:ivb?hexp(ivb,16):'null'});
      }catch(e){ev.push({t:'ck3',err:''+e});}}
      return i3.call(this,mode,key,spec);
    };
    var i2=Ci.init.overload('int','java.security.Key');
    i2.implementation=function(mode,key){
      if(INB){try{var kb=key.getEncoded();ev.push({t:'ck2',keyStr:A.$new(kb,'UTF-8')+'',iv:'NO-SPEC'});}catch(e){ev.push({t:'ck2',err:''+e});}}
      return i2.call(this,mode,key);
    };
    var dF=Ci.doFinal.overload('[B');
    dF.implementation=function(d){
      var r=dF.call(this,d);
      if(INB){try{ev.push({t:'fin',inLen:d.length,outLen:r?r.length:0,inH:hexp(d,8),outH:r?hexp(r,8):'null'});}catch(e){}}
      return r;
    };
    var Ma=Java.use('javax.crypto.Mac');
    var mi=Ma.init.overload('java.security.Key');
    mi.implementation=function(k){
      if(INB){try{var kb=k.getEncoded();ev.push({t:'mk',keyStr:A.$new(kb,'UTF-8')+'',keyH:hexp(kb,40)});}catch(e){ev.push({t:'mk',err:''+e});}}
      return mi.call(this,k);
    };
    var mdf=Ma.doFinal.overload('[B');
    mdf.implementation=function(d){
      var r=mdf.call(this,d);
      if(INB){try{ev.push({t:'mfin',alg:this.getAlgorithm()+'',dataStr:A.$new(d,'UTF-8')+'',outB64:B64.encodeToString(r,2)+'',outLen:r.length});}catch(e){}}
      return r;
    };
    var mi2=Ma.init.overload('javax.crypto.SecretKey');
    mi2.implementation=function(k){
      if(INB){try{var kb=k.getEncoded();ev.push({t:'mk',keyStr:A.$new(kb,'UTF-8')+'',keyH:hexp(kb,40)});}catch(e){}}
      return mi2.call(this,k);
    };
    S({m:'钩 OK'});
  }catch(e){S({m:'钩失败 '+String(e).slice(0,90)});}
  // ① 直调 b 拿基准
  var bR=null;
  try{
    var AB=Java.use('a.b'); var ABi=AB.$new();
    INB=true;
    bR=AB.b.overload('long','long','[B','long','java.lang.String').call(ABi,parseInt(book),parseInt(cid),PAY,0,A.$new(uk));
    INB=false;
    S({m:'★b基准 len='+(bR?bR.length:0)});
  }catch(e){S({m:'b失败 '+String(e).slice(0,100)});}
  for(var i=0;i<ev.length;i++){var e2=ev[i];S({m:'◆['+i+']'+e2.t+' key='+(''+e2.keyStr)+' kh='+e2.keyH+' data='+(''+e2.dataStr)+' outB64='+e2.outB64+' iv='+e2.ivH+'|'+e2.iv+' in/out='+'/'+e2.inLen+'/'+e2.outLen});}
  // ② 主动复算 (从事件流取 mk#0 key 串 = 真值, 双假说自动消解)
  try{
    var mk0='', mfin0='';
    for(var j=0;j<ev.length;j++){ if(ev[j].t==='mk'&&!mk0){mk0=ev[j].keyStr;} if(ev[j].t==='mfin'&&ev[j].alg.indexOf('SHA1')>=0&&!mfin0){mfin0=ev[j].outB64;} }
    S({m:'◇复算基准: Mac#1key='+mk0+' 输出b64全='+mfin0});
    // k1=mfin0[:24]; Mac#2 key=k1 已捕获(ck2#2)... 用 Cipher 手动重放两遍
    var k2str='';
    for(var j2=0;j2<ev.length;j2++){ if(ev[j2].t==='mfin'&&ev[j2].alg.indexOf('MD5')>=0){ var ob=ev[j2].outB64; k2str=ob.slice(0,24); } }
    S({m:'◇k2(算)='+k2str+' (捕获对比见 ◆ck)'});
    // 手动 3DES 双遍 (key=第一次ck2捕获串)
    var kk=''; for(var j3=0;j3<ev.length;j3++){ if(ev[j3].t==='ck2'){kk=ev[j3].keyStr;break;} }
    var SKS=Java.use('javax.crypto.spec.SecretKeySpec');
    var Ci2=Java.use('javax.crypto.Cipher');
    var c=Ci2.getInstance('DESede/CBC/PKCS5Padding');
    c.init(2, SKS.$new(A.$new(kk,'UTF-8').getBytes(),'DESede'));
    var p1=c.doFinal(PAY);
    var p2=c.doFinal(p1);
    var same=p2.length===bR.length; var diffAt=-1;
    for(var x2=0;x2<p2.length;x2++){ if(p2[x2]!==bR[x2]){diffAt=x2;break;} }
    S({m: same&&diffAt<0 ? '████全链复算与b逐字节一致!! 公式100%闭环' : '复算不一致 same='+same+' diffAt='+diffAt+' p2len='+p2.length});
    if(same&&diffAt<0){var js=B64.encodeToString(p2,0)+'';for(var z2=0;z2<js.length;z2+=3000){S({m:'PJSON|'+z2+'|'+js.slice(z2,z2+3000)});}}
  }catch(e3){S({m:'复算失败 '+String(e3).slice(0,120)});}
  S({m:'v42 完成'});
});
