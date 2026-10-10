// hook_v105.js — v65: ★修解码污染(flag10→0!)+setup 基线 — v60-64 全部字节数组都喂错了!
// 证据: v64 报 CTb=287(应296) Kraw=92(应96) → URL_SAFE 解标准b64 吞 +/ 字符
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT, K128s=BD.K128;
  var B64=Java.use('android.util.Base64');
  var CTb=B64.decode(CTs,0), Kraw=B64.decode(K128s,0);   // DEFAULT 保真
  S({m:'v65 CTb='+CTb.length+'(应296) Kraw='+Kraw.length+'(应96)'});
  var cidS='799920041', pair='1040025277|799920041';
  var Fock=Java.use('com.yuewen.fock.Fock');
  // ① setup 对齐 (v54 auto 姿势)
  try{ Fock.setup('5a271be5da434be'); S({m:'setup OK uk='+Fock.getCurrentUserKey()}); }catch(e){S({m:'setup 败 '+String(e).slice(0,80)});}
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0){ var t=''+Java.use('java.lang.String').$new(r.data); S({m:'█'+tag+' '+t.slice(0,150)}); } }catch(e){S({m:'◆'+tag+' 读败 '+String(e).slice(0,60)});} }
  // ② 基线 U4 (应回 -4, 证身份+数据干净)
  try{ FR(Fock.unlock(CTs,cidS,pair,null),'U4base'); }catch(e){S({m:'U4base 败 '+String(e).slice(0,70)});}
  // ③ 干净字节版底层: uksf/uk 反射直调
  try{
    var JC=Java.use('java.lang.Class').forName('com.yuewen.fock.Fock');
    var ms=JC.getDeclaredMethods();
    for(var i=0;i<ms.length;i++){ var nm=''+ms[i].getName(); if(nm==='uksf'||nm==='uk'||nm==='resf'||nm==='rmdk'||nm==='urk'){
      ms[i].setAccessible(true);
      S({m:'◆发现 '+nm+' 参数数='+ms[i].getParameterTypes().length});
    }}
    // uk([B,I,[B,I) — 猜测: data,len,key,len → Kraw 切 24/32 段当 key
    var b24=Kraw.slice(0,24), b32=Kraw.slice(0,32);
    var mks={};
    for(var i2=0;i2<ms.length;i2++){ var nm2=''+ms[i2].getName(); if(!mks[nm2])mks[nm2]=ms[i2]; }
    function inv(nm,args){ try{ if(!mks[nm])return 'NOMETH'; mks[nm].setAccessible(true); return mks[nm].invoke(null,args); }catch(e){ return 'ERR:'+String(e.message||e).slice(0,70); } }
    var rr=inv('uk',[CTb,CTb.length,b24,b24.length]);
    S({m:'◆uk(CT,24key) '+(''+rr).slice(0,60)});
    if(rr && ''+rr !== 'NOMETH' && (''+rr).indexOf('ERR:')!==0){ var FRC=Java.cast(rr,Java.use('com.yuewen.fock.Fock$FockResult')); FR(FRC,'uk24'); }
    var rr2=inv('uk',[CTb,CTb.length,b32,b32.length]);
    if(rr2 && (''+rr2).indexOf('ERR:')!==0 && rr2!==null){ try{FR(Java.cast(rr2,Java.use('com.yuewen.fock.Fock$FockResult')),'uk32');}catch(e3){} } else S({m:'◆uk32 '+(''+rr2).slice(0,60)});
  }catch(e){S({m:'底层反射 败 '+String(e).slice(0,90)});}
  // ④ addKeys 注册(正确 K128 串本就是 b64, v62 姿势)→ 再 U4
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FUinst=FU.INSTANCE.value;
  var regs=[
    ['book|cid|K128', [book0(),cidS,K128s]],
    ['cid|book|K128', [cidS,book0(),K128s]],
    ['VER|cid|K128', [''+BD.VER,cidS,K128s]]
  ];
  function book0(){return '1040025277';}
  for(var ri=0;ri<regs.length;ri++){
    try{
      var ak=FU.addKeys? (FU.addKeys.overload? FU.addKeys.overload('java.lang.String','java.lang.String','java.lang.String'):null) : null;
      if(ak) ak.call(FUinst, regs[ri][1][0],regs[ri][1][1],regs[ri][1][2]); else FU.addKeys(FUinst, regs[ri][1][0],regs[ri][1][1],regs[ri][1][2]);
      S({m:'◆AK['+regs[ri][0]+'] OK'});
      FR(Fock.unlock(CTs,cidS,pair,null),'U4postAK'+ri);
    }catch(e){S({m:'◆AK['+regs[ri][0]+'] 败 '+String(e).slice(0,70)});}
  }
  // ⑤ unlockData 干净字节版
  try{ FR(Fock.unlockData(CTb,cidS,pair,null),'ud.clean'); }catch(e){S({m:'ud 败 '+String(e).slice(0,80)});}
  S({m:'v65 出'});
});
})();
