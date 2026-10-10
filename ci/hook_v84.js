// hook_v84.js — v45: ★决定性: 包 a.b.s/m/d 记录 C 层每次调用的入参+出参 + Cipher key → ISM8 来源当场现形
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
(function(){
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var imei=P.userKey, cid=P.cid, book=P.book, ver=P.Version;
  var SALT='2EEE1433A152E84B3756301D8FA3E69A';
  var A=Java.use('java.lang.String'), B64=Java.use('android.util.Base64');
  var LOG=[], CAP=[];
  function by2s(kb){ var ch='',hx=''; for(var z=0;z<kb.length&&z<48;z++){ var v=kb[z]&0xff; ch+=(v>=32&&v<127?String.fromCharCode(v):'.'); hx+=(v<16?'0':'')+v.toString(16);} return ch+'|'+hx; }
  // ① Cipher key 现场
  try{
    var Ci=Java.use('javax.crypto.Cipher');
    var oi=Ci.init.overload('int','java.security.Key');
    oi.implementation=function(op,k){
      try{ CAP.push('CIPH '+op+' '+by2s(k.getEncoded())); }catch(e){}
      return oi.call(this,op,k);
    };
    S({m:'钩Cipher OK'});
  }catch(e){S({m:'钩Cipher 败 '+String(e).slice(0,60)});}
  // ② 包 a.b 三方法: 记录 C 传了什么
  var AB=Java.use('a.b'), ABi=AB.$new();
  try{
    var sOv=AB.s.overload('java.lang.String','java.lang.String');
    var mOv=AB.m.overload('java.lang.String','java.lang.String');
    var sOrig=sOv.implementation; var mOrig=mOv.implementation;
    sOv.implementation=function(a,b){ var r=sOrig.call(this,a,b); LOG.push('s('+a+','+b+')='+r); return r; };
    mOv.implementation=function(a,b){ var r=mOrig.call(this,a,b); LOG.push('m('+a+','+b+')='+r); return r; };
    var dOv=AB.d.overload('[B','java.lang.String');
    var dOrig=dOv.implementation;
    dOv.implementation=function(da,kk){ LOG.push('d(len='+da.length+',key='+kk+')'); var r=dOrig.call(this,da,kk); return r; };
    S({m:'包s/m/d OK'});
  }catch(e){S({m:'包s/m/d 败 '+String(e).slice(0,90)});}
  // ③ 触发 b (两次, 第一次可能走包后的路径)
  var d=B64.decode(P.payload_b64,2);
  var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
  var j=bOv.call(ABi, parseInt(book), parseInt(cid), d, 0, A.$new(imei));
  S({m:'b#0 OK len='+j.length});
  // ④ 全量吐现场
  for(var i=0;i<LOG.length;i++) S({m:'◆L'+i+' '+(''+LOG[i]).slice(0,220)});
  for(var i2=0;i2<CAP.length;i2++) S({m:'◆C'+i2+' '+CAP[i2]});
  S({m:'v45 END M1轮=?'});
});
})();
