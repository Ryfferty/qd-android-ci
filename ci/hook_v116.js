// hook_v116.js — v76: ★门控旁观 unlock 期间 javax.crypto 现场 (购章路径第一次看穿: 走不走Java加密/什么钥比对)
// 前置 setup(IMEI)+addKeypool(VER,K128); INB 期间 unlock(CT)/(K128)/lock环测; 事件流全 dump
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT, K128=BD.K128, VER=''+BD.VER, imei=''+BD.imei;
  var B64=Java.use('android.util.Base64');
  var cidS='799920041', book='1040025277', pairU=book+'_'+cidS;
  var Fock=Java.use('com.yuewen.fock.Fock');
  function a2s(ba){try{var s='';for(var i=0;i<ba.length&&i<56;i++){var v=ba[i]&0xff;s+=(v>=32&&v<127?String.fromCharCode(v):'.');}return s;}catch(e){return 'ERR';}}
  function a2h(ba){try{var s='';for(var i=0;i<ba.length&&i<40;i++){var v=ba[i]&0xff;s+=(v<16?'0':'')+v.toString(16);}return s;}catch(e){return 'ERR';}}

  var EV=[], INB=false;
  // ① Mac.init(key)
  try{
    var Mac=Java.use('javax.crypto.Mac');
    var mi=Mac.init.overload('java.security.Key');
    mi.implementation=function(k){ if(INB){try{var kb=k.getEncoded();EV.push('MK:'+(kb?a2s(kb):'?')+'|'+(kb?a2h(kb):'?'));}catch(e){EV.push('MK:ERR');}} return mi.call(this,k); };
    var mf=Mac.doFinal.overload('[B');
    mf.implementation=function(d){ if(INB){try{EV.push('MDin:'+a2h(d));}catch(e){}} return mf.call(this,d); };
    var mfn=Mac.doFinal.overload();
    mfn.implementation=function(){ var o=mfn.call(this); if(INB){try{EV.push('MDout:'+a2h(o));}catch(e){}} return o; };
    S({m:'钩Mac OK'});
  }catch(e){S({m:'钩Mac 败 '+String(e).slice(0,70)});}
  // ② SecretKeySpec 构造 (拿 alg+key)
  try{
    var SKS=Java.use('javax.crypto.spec.SecretKeySpec');
    var sk=SKS.$init.overload('[B','java.lang.String');
    sk.implementation=function(k,alg){ if(INB){try{EV.push('SK:'+alg+'|'+a2s(k)+'|'+a2h(k));}catch(e){}} return sk.call(this,k,alg); };
    S({m:'钩SK OK'});
  }catch(e){S({m:'钩SK 败 '+String(e).slice(0,70)});}
  // ③ Cipher.init(op,key) + doFinal([B)
  try{
    var Ci=Java.use('javax.crypto.Cipher');
    var i3=Ci.init.overload('int','java.security.Key');
    i3.implementation=function(op,k){ if(INB){try{var kb=k.getEncoded();EV.push('Ci.init op='+op+' '+(kb?a2s(kb):'?')+'|'+(kb?a2h(kb):'?'));}catch(e){}} return i3.call(this,op,k); };
    var i4=Ci.init.overload('int','java.security.Key','java.security.spec.AlgorithmParameterSpec');
    i4.implementation=function(op,k,ps){ if(INB){try{var kb=k.getEncoded();EV.push('Ci.initIV op='+op+' '+(kb?a2s(kb):'?')+'|'+(kb?a2h(kb):'?')+' ps='+(''+ps).slice(0,40));}catch(e){}} return i4.call(this,op,k,ps); };
    var df=Ci.doFinal.overload('[B');
    df.implementation=function(d){ var o=df.call(this,d); if(INB){try{EV.push('Ci.fin in='+d.length+':'+a2h(d).slice(0,24)+' out='+(''+a2h(o)).slice(0,24));}catch(e){}} return o; };
    var df0=Ci.doFinal.overload();
    df0.implementation=function(){ var o=df0.call(this); if(INB){try{EV.push('Ci.fin0 out='+(''+a2h(o)).slice(0,24));}catch(e){}} return o; };
    S({m:'钩Ci OK'});
  }catch(e){S({m:'钩Ci 败 '+String(e).slice(0,70)});}

  try{ Fock.setup(imei); S({m:'uk='+(''+Fock.currentUserKey()).slice(0,40)}); }catch(e){}
  try{ Fock.addKeypool(VER,K128); S({m:'akp OK'}); }catch(e){S({m:'akp败 '+String(e).slice(0,50)});}

  // A. unlock(CT) 门控
  INB=true; EV=[];
  try{ var r=Fock.unlock(CTs,cidS,pairU,null); S({m:'◆U st='+r.status.value}); }catch(e){S({m:'U败 '+String(e).slice(0,50)});}
  INB=false;
  S({m:'◆EV_U('+EV.length+')='+EV.slice(0,14).join(' ;; ')});

  // B. unlock(K128) 门控
  INB=true; EV=[];
  try{ var r2=Fock.unlock(K128,cidS,pairU,null); S({m:'◆UK st='+r2.status.value}); }catch(e){S({m:'UK败 '+String(e).slice(0,50)});}
  INB=false;
  S({m:'◆EV_K('+EV.length+')='+EV.slice(0,10).join(' ;; ')});

  // C. lock 环测门控 (lock 用什么钥 — 对照 unlock 找的钥)
  INB=true; EV=[];
  try{ var lc=''+Fock.lock('验证环测试123456'); S({m:'◆lock='+lc.slice(0,40)}); }catch(e){S({m:'lock败 '+String(e).slice(0,50)});}
  INB=false;
  S({m:'◆EV_L('+EV.length+')='+EV.slice(0,10).join(' ;; ')});

  // D. 环测 unlock(lock输出修b64)
  INB=true; EV=[];
  try{
    var lc2=lc.replace(/-/g,'+').replace(/_/g,'/'); while(lc2.length%4!==0) lc2+='=';
    var r4=Fock.unlock(lc2,cidS,pairU,null);
    S({m:'◆环 st='+r4.status.value+' out='+(''+B64.encodeToString(r4.data,0)).slice(0,30)});
  }catch(e){S({m:'环败 '+String(e).slice(0,50)});}
  INB=false;
  S({m:'◆EV_R('+EV.length+')='+EV.slice(0,10).join(' ;; ')});
  S({m:'v76 出'});
});
})();
