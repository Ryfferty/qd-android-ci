// hook_v89.js — v49: ★决定性: m 替身全参打印 + Cipher旁观同轮抓 ISM8 → 对号即公式; s 也全参
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
(function(){
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var imei=P.userKey, cid=P.cid, book=P.book;
  var A=Java.use('java.lang.String'), B64=Java.use('android.util.Base64');
  var EVS=[], CAP=[];
  function bys(b){var ch='',hx='';for(var z=0;z<b.length&&z<100;z++){var v=b[z]&0xff;ch+=(v>=32&&v<127?String.fromCharCode(v):'.');hx+=(v<16?'0':'')+v.toString(16);}return ch+'|'+hx;}
  function hmac(alg,keyStr,dataStr){
    var Mac=Java.use('javax.crypto.Mac'); var SK=Java.use('javax.crypto.spec.SecretKeySpec');
    var mk=Mac.getInstance(A.$new(alg)); mk.init(SK.$new(A.$new(keyStr).getBytes(),A.$new(alg)));
    return B64.encodeToString(mk.doFinal(A.$new(dataStr).getBytes()),2)+'';
  }
  // ① Cipher 旁观 (抓同轮 ISM8 + 第二遍 key)
  try{
    var Ci=Java.use('javax.crypto.Cipher');
    var oi=Ci.init.overload('int','java.security.Key');
    oi.implementation=function(op,k){
      try{ var kb=k.getEncoded(); CAP.push(bys(kb)); }catch(e){ CAP.push('ERR'); }
      return oi.call(this,op,k);
    };
    S({m:'钩Cipher OK'});
  }catch(e){S({m:'钩Cipher 败 '+String(e).slice(0,60)});}
  var AB=Java.use('a.b'), ABi=AB.$new();
  // ② m 替身: 两向都算, 全参打印; 若与本轮 Cipher CAP 匹配则打印 MATCH
  try{
    var mOv=AB.m.overload('java.lang.String','java.lang.String');
    mOv.implementation=function(a,b){
      var ra=hmac('HmacMD5',''+a,''+b);   // key=a (v37向量方向)
      var rb=hmac('HmacMD5',''+b,''+a);
      EVS.push('m|A=['+a+']|B=['+b+']|ka='+ra+'|kb='+rb);
      return A.$new(ra);
    };
    var sOv=AB.s.overload('java.lang.String','java.lang.String');
    sOv.implementation=function(a,b){
      var ra=hmac('HmacSHA1',''+a,''+b);
      var rb=hmac('HmacSHA1',''+b,''+a);
      EVS.push('s|A.len='+a.length+'|B.len='+b.length+'|B=['+(b+'').slice(0,90)+']|ka='+ra+'|kb='+rb);
      return A.$new(rb); // v47 证明 rb(key=b,data=a) 走通链路
    };
    S({m:'替身 m/s 装好'});
  }catch(e){S({m:'替身败 '+String(e).slice(0,90)});}
  // ③ 触发 b
  var d=B64.decode(P.payload_b64,2);
  try{
    var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
    var j=bOv.call(ABi, parseInt(book), parseInt(cid), d, 0, A.$new(imei));
    S({m:'b#0 OK len='+j.length});
  }catch(e){S({m:'b#0 败 '+String(e).slice(0,140)});}
  for(var i=0;i<EVS.length;i++) S({m:'◆E'+i+' '+EVS[i]});
  for(var i2=0;i2<CAP.length;i2++) S({m:'◆C'+i2+' '+CAP[i2]});
  S({m:'◆nE='+EVS.length+' nC='+CAP.length+' imei='+imei});
  S({m:'v49 END'});
});
})();
