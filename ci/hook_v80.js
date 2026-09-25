// hook_v80.js — v41: ★INB门控捕获 a.b.b 内部 Mac/Cipher 真 key 全串(闭包共享,修 frida wrapper 属性不持久坑) → 本地公式一次对齐
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function hexp(b,n){if(!b)return 'null';var s='';for(var i=0;i<Math.min(n||32,b.length);i++){var v=b[i]&0xff;s+=(v<16?'0':'')+v.toString(16);}return s;}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<raw.length;i++)a.push(raw[i]);return a;})());
  var uk=P.userKey, book=P.book, cid=P.cid;
  var A=Java.use('java.lang.String');
  var B64=Java.use('android.util.Base64');
  var INB=false;
  var ev=[]; // 事件流: {t:'mk'|'mdata'|'ck'|'fin', ...} 全带序号
  S({m:'v41 开跑 ukLen='+uk.length});
  try{
    var Ci=Java.use('javax.crypto.Cipher');
    var i3=Ci.init.overload('int','java.security.Key','java.security.spec.AlgorithmParameterSpec');
    i3.implementation=function(mode,key,spec){
      if(INB){try{var kb=key.getEncoded();
        ev.push({t:'ck',str:A.$new(kb,'UTF-8')+'',b64:B64.encodeToString(kb,2)+'',h:hexp(kb,10),len:kb.length});
      }catch(e){ev.push({t:'ck',err:''+e});}}
      return i3.call(this,mode,key,spec);
    };
    var i2=Ci.init.overload('int','java.security.Key');
    i2.implementation=function(mode,key){
      if(INB){try{var kb=key.getEncoded();
        ev.push({t:'ck2p',str:A.$new(kb,'UTF-8')+'',h:hexp(kb,10),len:kb.length});
      }catch(e){ev.push({t:'ck2p',err:''+e});}}
      return i2.call(this,mode,key);
    };
    var dF=Ci.doFinal.overload('[B');
    dF.implementation=function(d){
      var r=dF.call(this,d);
      if(INB){try{ev.push({t:'fin',inLen:d.length,inH:hexp(d,10),outLen:r?r.length:0,outH:r?hexp(r,10):'null'});}catch(e){}}
      return r;
    };
    var Ma=Java.use('javax.crypto.Mac');
    var mi=Ma.init.overload('java.security.Key');
    mi.implementation=function(k){
      if(INB){try{var kb=k.getEncoded();
        ev.push({t:'mk',str:A.$new(kb,'UTF-8')+'',b64:B64.encodeToString(kb,2)+'',h:hexp(kb,10),len:kb.length,alg:this.getAlgorithm()+''});
      }catch(e){ev.push({t:'mk',err:''+e});}}
      return mi.call(this,k);
    };
    // 补齐 init 所有重载 (Mac.init() 用 init 前的 key 无从取 → 只记事件)
    try{
      var mi0=Ma.init.overload();
      mi0.implementation=function(){
        if(INB){try{ev.push({t:'mk0',alg:this.getAlgorithm()+'',cls:''+this.getClass().getName()});}catch(e){}}
        return mi0.call(this);
      };
    }catch(e){S({m:'无 init() 重载'});}
    var mdf=Ma.doFinal.overload('[B');
    mdf.implementation=function(d){
      var r=mdf.call(this,d);
      if(INB){try{ev.push({t:'mfin',dataH:hexp(d,90),dataStr:A.$new(d,'UTF-8')+'',outH:hexp(r,20),outB64:B64.encodeToString(r,2)+'',alg:this.getAlgorithm()+''});}catch(e){}}
      return r;
    };
    S({m:'门控钩 OK'});
  }catch(e){S({m:'钩失败 '+String(e).slice(0,100)});}
  // 触发 b
  try{
    var AB=Java.use('a.b'); var ABi=AB.$new();
    var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
    INB=true;
    var bR=bOv.call(ABi,parseInt(book),parseInt(cid),PAY,0,A.$new(uk));
    INB=false;
    S({m:'★b len='+(bR?bR.length:0)});
    if(bR){var js=B64.encodeToString(bR,0)+'';for(var z=0;z<js.length;z+=3000){S({m:'BJSON|'+z+'|'+js.slice(z,z+3000)});}}
  }catch(e){S({m:'b 失败 '+String(e).slice(0,110)});}
  // dump 事件流 (全量)
  for(var i=0;i<ev.length;i++){
    var e=ev[i];
    if(e.t==='mk'||e.t==='ck'||e.t==='ck2p'){S({m:'◆'+e.t+'#'+i+' len='+e.len+' b64='+e.b64+' str='+e.str.slice(0,64)+' h='+e.h+(e.alg?' alg='+e.alg:'')});}
    else if(e.t==='mfin'){S({m:'◆mfin#'+i+' alg='+e.alg+' dataH='+e.dataH+' outB64='+e.outB64});}
    else if(e.t==='fin'){S({m:'◆fin#'+i+' in'+e.inLen+':'+e.inH+' → out'+e.outLen+':'+e.outH});}
  }
  S({m:'v41 完成 ev='+ev.length});
});
