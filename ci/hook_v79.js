// hook_v79.js — v40: ★INB门控抓 a.b.b 执行期间的 javax.crypto 现场 (Cipher=3DES / Mac=HMAC / MD)
// v39实锤: b 不回调 Java s/m/d → 若走 Java 加密只能是 javax.crypto; 若全无现场=native C 自包含(转 unidbg 追 libload-jni)
// 写法: 保存原方法引用 orig.call(this,...) 防重入; 只观察不改值
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function hexp(b,n){if(!b)return 'null';var s='';for(var i=0;i<Math.min(n||24,b.length);i++){var v=b[i]&0xff;s+=(v<16?'0':'')+v.toString(16);}return s;}
function u8s(b){if(!b)return 'null';try{return String(Java.use('java.lang.String').$new(b,'UTF-8'));}catch(e){return hexp(b,16);}}
function clip(s,n){s=''+s;return s.length<(n||80)?s:s.slice(0,n||80)+'…';}
Java.perform(function(){
  var INB=false, CSUM=0, MSUM=0;
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<raw.length;i++)a.push(raw[i]);return a;})());
  var uk=P.userKey, book=P.book, cid=P.cid;
  S({m:'v40 开跑 PAY='+PAY.length});
  // ① Cipher 三形态
  try{
    var Ci=Java.use('javax.crypto.Cipher');
    var i3=Ci.init.overload('int','java.security.Key','java.security.spec.AlgorithmParameterSpec');
    i3.implementation=function(mode,key,spec){
      if(INB&&CSUM<10){CSUM++;try{var kb=key.getEncoded();var iv='?';try{iv=spec.getIV?hexp(spec.getIV(),16):'noIV';}catch(e){iv='n/a';}S({m:'▷Ci.init#'+CSUM+' m='+mode+' 3p alg='+this.getAlgorithm()+' key'+(kb?kb.length:0)+'B='+clip(u8s(kb),64)+' iv='+iv});}catch(e){S({m:'Ci钩异常 '+String(e).slice(0,60)});}}
      return i3.call(this,mode,key,spec);
    };
    var i2=Ci.init.overload('int','java.security.Key');
    i2.implementation=function(mode,key){
      if(INB&&CSUM<10){CSUM++;try{var kb=key.getEncoded();S({m:'▷Ci.init#'+CSUM+' m='+mode+' 2p alg='+this.getAlgorithm()+' key'+(kb?kb.length:0)+'B='+clip(u8s(kb),64)});}catch(e){}}
      return i2.call(this,mode,key);
    };
    var dF=Ci.doFinal.overload('[B');
    dF.implementation=function(d){
      var r=dF.call(this,d);
      if(INB&&CSUM<18){CSUM++;try{S({m:'▷Ci.fin#'+CSUM+' alg='+this.getAlgorithm()+' in'+d.length+'='+hexp(d,10)+' out'+(r?r.length:0)+'='+hexp(r,10)+' outU='+clip(u8s(r),24)});}catch(e){}}
      return r;
    };
    S({m:'钩Cipher OK'});
  }catch(e){S({m:'钩Cipher失败 '+String(e).slice(0,90)});}
  // ② Mac
  try{
    var Ma=Java.use('javax.crypto.Mac');
    var mi=Ma.init.overload('java.security.Key');
    mi.implementation=function(k){
      if(INB&&MSUM<8){MSUM++;try{this.__kk=clip(u8s(k.getEncoded()),64);}catch(e){this.__kk='?';}}
      return mi.call(this,k);
    };
    var mdf=Ma.doFinal.overload('[B');
    mdf.implementation=function(d){
      var r=mdf.call(this,d);
      if(INB&&MSUM<14){MSUM++;try{S({m:'▷Mac#'+MSUM+' key='+clip(this.__kk,64)+' data='+clip(u8s(d),64)+' → '+hexp(r,10)});}catch(e){}}
      return r;
    };
    S({m:'钩Mac OK'});
  }catch(e){S({m:'钩Mac失败 '+String(e).slice(0,90)});}
  // ③ MessageDigest
  try{
    var Md=Java.use('java.security.MessageDigest');
    var mdd=Md.digest.overload('[B');
    mdd.implementation=function(d){
      var r=mdd.call(this,d);
      if(INB&&MSUM<20){MSUM++;try{S({m:'▷MD#'+MSUM+' in='+clip(u8s(d),64)+' → '+hexp(r,10)});}catch(e){}}
      return r;
    };
    var mdfn=Md.doFinal.overload('[B');
    mdfn.implementation=function(d){
      var r=mdfn.call(this,d);
      if(INB&&MSUM<24){MSUM++;try{S({m:'▷MDf#'+MSUM+' in='+clip(u8s(d),64)+' → '+hexp(r,10)});}catch(e){}}
      return r;
    };
    S({m:'钩MD OK'});
  }catch(e){}
  // ④ 触发 b (实例绑定, ABi; v36 实证实例调用才通)
  try{
    var AB=Java.use('a.b'); var ABi=AB.$new();
    var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
    var A=Java.use('java.lang.String');
    INB=true;
    var bR=bOv.call(ABi,parseInt(book),parseInt(cid),PAY,0,A.$new(uk));
    INB=false;
    S({m:'★b len='+(bR?bR.length:0)+' head='+hexp(bR,12)});
    if(bR){var B64=Java.use('android.util.Base64');var js=B64.encodeToString(bR,0)+'';for(var z=0;z<js.length;z+=3000){S({m:'BJSON|'+z+'|'+js.slice(z,z+3000)});}}
  }catch(e){S({m:'b 失败 '+String(e).slice(0,120)});}
  S({m:'v40 完成 CSUM='+CSUM+' MSUM='+MSUM});
});
