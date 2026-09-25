// hook_v109.js — v69: ★真名修正: addKeypool(str,str)/addKeys(s,s,s,h)/currentUserKey()/addedKeyVersions() 全试
// v68 三败因: getCurrentUserKey→真名 currentUserKey; resf private→反射; add→正主是 addKeypool
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT, K128=BD.K128, VER=''+BD.VER;
  var B64=Java.use('android.util.Base64');
  var CTb=B64.decode(CTs,0), Kraw=B64.decode(K128,0);
  var cidS='799920041', pair='1040025277|799920041', book='1040025277';
  var Fock=Java.use('com.yuewen.fock.Fock');
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0&&r.data){ var d=r.data; var as=''; try{as=''+Java.use('java.lang.String').$new(d);}catch(e){} S({m:'█'+tag+' '+as.slice(0,150)}); } return st; }catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});return -9;} }
  // ① 当前注册表
  try{ S({m:'◆versions='+JSON.stringify(Fock.addedKeyVersions())}); }catch(e){S({m:'ver 败 '+String(e).slice(0,60)});}
  try{ S({m:'◆uk='+(''+Fock.currentUserKey()).slice(0,50)}); }catch(e){S({m:'uk 败 '+String(e).slice(0,60)});}
  // ② addKeypool(VER, K128) → unlock
  try{ Fock.addKeypool(VER,K128); S({m:'◆addKeypool(VER,K128) OK'}); FR(Fock.unlock(CTs,cidS,pair,null),'U ak1'); }
  catch(e){ S({m:'ak1 败 '+String(e).slice(0,80)}); }
  // ③ addKeypool(cid, K128) / addKeypool(pair, K128)
  try{ Fock.addKeypool(cidS,K128); S({m:'◆addKeypool(cid,K128) OK'}); FR(Fock.unlock(CTs,cidS,pair,null),'U ak2'); }
  catch(e){ S({m:'ak2 败 '+String(e).slice(0,80)}); }
  try{ Fock.addKeypool(pair,K128); FR(Fock.unlock(CTs,cidS,pair,null),'U ak3'); }
  catch(e){ S({m:'ak3 败 '+String(e).slice(0,80)}); }
  // ④ addKeys(VER, cid, K128) 3参形态 (源: addKeys(s,s,s,handler))
  try{ Fock.addKeys(VER,cidS,K128,null); S({m:'◆addKeys(VER,cid,K) OK'}); FR(Fock.unlock(CTs,cidS,pair,null),'U aks1'); }
  catch(e){ S({m:'aks1 败 '+String(e).slice(0,80)}); }
  try{ Fock.addKeys(VER,pair,K128,null); FR(Fock.unlock(CTs,cidS,pair,null),'U aks2'); }
  catch(e){ S({m:'aks2 败 '+String(e).slice(0,80)}); }
  // ⑤ unlockData 干净字节版
  try{ FR(Fock.unlockData(CTb,cidS,pair,null),'UD'); }catch(e){S({m:'UD 败 '+String(e).slice(0,70)});}
  // ⑥ 反射私有 resf/uk 拿池语义
  try{
    var JC=Java.use('java.lang.Class').forName('com.yuewen.fock.Fock',true,Fock.class.getClassLoader());
    var ms=JC.getDeclaredMethods();
    var want={};
    for(var i=0;i<ms.length;i++){ var nm=''+ms[i].getName(); if(nm==='resf'||nm==='tsf'||nm==='uk'||nm==='uksf'||nm==='ak'||nm==='lk'||nm==='sn'||nm==='it'||nm==='av') want[nm]=ms[i]; }
    S({m:'◆私有到手 '+Object.keys(want).join(',')});
    function rv(nm,args,types){ try{ var m=want[nm]; m.setAccessible(true);
      // 构造类型数组
      var CL={byte:'[B',int:'I'};
      return m.invoke(null,args); }catch(e){ return 'E:'+String(e.message||e).slice(0,60); } }
    if(want.resf){
      var r=rv('resf',[Kraw,0,Kraw],'');
      if(typeof r==='string') S({m:'resf '+r}); else { var b=''+B64.encodeToString(r,2); S({m:'◆resf(Kraw,0,Kraw)='+b.slice(0,60)});
        try{ Fock.addKeypool(VER,b); FR(Fock.unlock(CTs,cidS,pair,null),'U resfAK'); }catch(e){} } }
    if(want.uk){ var r2=rv('uk',[CTb,CTb.length,Kraw,Kraw.length],'');
      if(typeof r2==='string') S({m:'uk '+r2}); else { try{ FR(r2,'uk直调'); }catch(e){S({m:'uk读败 '+String(e).slice(0,60)});} } }
    if(want.av){ var r3=rv('av',[],''); S({m:'◆av='+(''+r3).slice(0,80)}); }
  }catch(e){S({m:'反射 败 '+String(e).slice(0,90)});}
  try{ S({m:'◆versions2='+JSON.stringify(Fock.addedKeyVersions())}); }catch(e){}
  S({m:'v69 出'});
});
})();
