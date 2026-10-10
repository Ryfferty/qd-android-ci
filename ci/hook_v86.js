// hook_v86.js — v47: 自实现 s/m 替换(不回调原方法,链路不断) → 记录 C 层真实入参; Cipher 抓同轮 ISM8 样本#2
// v45 铁证: C 在 b 内 JNI 回调 s/m/d (打坏→sha1key1=null)。v37 已证 s/m = 纯 HMAC → 我们替身直接算等价结果
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
(function(){
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var imei=P.userKey, cid=P.cid, book=P.book;
  var A=Java.use('java.lang.String'), B64=Java.use('android.util.Base64');
  var SELF=0, CAP=[], EVS=[];
  function by2s(b){var ch='',hx='';for(var z=0;z<b.length&&z<48;z++){var v=b[z]&0xff;ch+=(v>=32&&v<127?String.fromCharCode(v):'.');hx+=(v<16?'0':'')+v.toString(16);}return ch+'|'+hx;}
  function hmac(alg,keyB64ish,data){ // 双向都算
    var Mac=Java.use('javax.crypto.Mac'); var SK=Java.use('javax.crypto.spec.SecretKeySpec');
    var mk=Mac.getInstance(A.$new(alg)); mk.init(SK.$new(keyB64ish,A.$new(alg)));
    return B64.encodeToString(mk.doFinal(data),2)+'';
  }
  // ① Cipher 消费旁观 (只记录不干预)
  try{
    var Ci=Java.use('javax.crypto.Cipher');
    var oi=Ci.init.overload('int','java.security.Key');
    oi.implementation=function(op,k){
      try{ if(!SELF) CAP.push('CIPH'+op+' '+k.getAlgorithm()+' '+by2s(k.getEncoded())); }catch(e){}
      return oi.call(this,op,k);
    };
  }catch(e){S({m:'钩Cipher 败 '+String(e).slice(0,60)});}
  // ② s/m 自实现替换 (语义=v37 测试向量字节级验证过的方向; 若 logcat sha1key1 对不上则方向反了, 反正入参照常打印)
  var AB=Java.use('a.b'), ABi=AB.$new();
  try{
    var sOv=AB.s.overload('java.lang.String','java.lang.String');
    sOv.implementation=function(a,b){
      var r1='',r2='';
      SELF++; try{ r1=hmac('HmacSHA1',A.$new(b).getBytes(),A.$new(a).getBytes()); r2=hmac('HmacSHA1',A.$new(a).getBytes(),A.$new(b).getBytes()); }finally{ SELF--; }
      EVS.push('s(a.len='+a.length+',b='+(''+b).slice(0,46)+') k=b:'+r1+' k=a:'+r2);
      return A.$new(r1);
    };
    var mOv=AB.m.overload('java.lang.String','java.lang.String');
    mOv.implementation=function(a,b){
      var r1='',r2='';
      SELF++; try{ r1=hmac('HmacMD5',A.$new(a).getBytes(),A.$new(b).getBytes()); r2=hmac('HmacMD5',A.$new(b).getBytes(),A.$new(a).getBytes()); }finally{ SELF--; }
      EVS.push('m(a='+(''+a).slice(0,46)+',b.len='+b.length+') k=a:'+r1+' k=b:'+r2);
      return A.$new(r1);
    };
    S({m:'替身 s/m 装好 (d/Cipher 不碰)'});
  }catch(e){S({m:'装替身败 '+String(e).slice(0,90)});}
  // ③ 触发 b 两次
  var d=B64.decode(P.payload_b64,2);
  try{
    var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
    var j=bOv.call(ABi, parseInt(book), parseInt(cid), d, 0, A.$new(imei));
    var js=A.$new(j,'UTF-8')+'';
    S({m:'b#0 len='+j.length+' head='+js.slice(0,50)});
  }catch(e){S({m:'b#0 败 '+String(e).slice(0,120)});}
  // ④ 吐现场
  for(var i=0;i<EVS.length;i++) S({m:'◆E'+i+' '+EVS[i]});
  for(var i2=0;i2<CAP.length;i2++) S({m:'◆C'+i2+' '+CAP[i2]});
  S({m:'◆nE='+EVS.length+' nC='+CAP.length+' 身份 imei='+imei+' cid='+cid+' ver='+P.Version});
  S({m:'v47 END'});
});
})();
