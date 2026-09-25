// hook_v110.js — v70: ★收官: setup(IMEI)注入身份 → addKeypool(VER,K128) → unlock (v69差的就是没setup: -5身份不一致)
// 雷区: addKeys 会阻塞 → 全砍; addKeypool 安全 (v69 三次都 OK 返回)
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT, K128=BD.K128, VER=''+BD.VER, imei=''+BD.imei;
  var B64=Java.use('android.util.Base64');
  var CTb=B64.decode(CTs,0);
  var cidS='799920041', pair='1040025277|799920041', book='1040025277';
  var Fock=Java.use('com.yuewen.fock.Fock');
  function uk(){ try{ return ''+Fock.currentUserKey(); }catch(e){ return 'E'; } }
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0&&r.data){ var d=r.data; var as=''+Java.use('java.lang.String').$new(d); S({m:'█'+tag+' len='+d.length}); var b=B64.encodeToString(d,0); S({m:'█B64='+(''+b).slice(0,900)}); } return st; }catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});return -9;} }
  S({m:'v70 uk前='+uk().slice(0,44)+' VER='+VER+' imei='+imei});
  // ① 注入身份 (v54 auto 姿势已证可用)
  try{ Fock.setup(imei); S({m:'◆setup('+imei.slice(0,16)+') 调用完 uk='+uk().slice(0,44)}); }
  catch(e){ S({m:'setup 败 '+String(e).slice(0,80)}); }
  // ② 注册章钥池
  try{ Fock.addKeypool(VER,K128); S({m:'◆addKeypool OK versions='+JSON.stringify(Fock.addedKeyVersions())}); }
  catch(e){ S({m:'akp 败 '+String(e).slice(0,80)}); }
  // ③ unlock 三连 (参数序全试)
  try{ FR(Fock.unlock(CTs,cidS,pair,null),'U1'); }catch(e){S({m:'U1 败 '+String(e).slice(0,70)});}
  try{ FR(Fock.unlock(CTs,pair,book,null),'U2'); }catch(e){}
  try{ FR(Fock.unlockData(CTb,cidS,pair,null),'UD'); }catch(e){S({m:'UD 败 '+String(e).slice(0,70)});}
  // ④ 若 -5 仍在: setup(Context) 姿势对比 (引擎要求 ctx 版初始化)
  try{
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    Fock.setup(ctx);   // 自动匹配 (v54 姿势; call(null) 会 $borrowClassHandle 崩)
    S({m:'◆setup(ctx) 完 uk='+uk().slice(0,44)});
    try{ Fock.addKeypool(VER,K128); }catch(e){}
    FR(Fock.unlock(CTs,cidS,pair,null),'U3');
  }catch(e){ S({m:'setup ctx 败 '+String(e).slice(0,80)}); }
  // ⑤ 双参 setup(ctx, imei)
  try{
    Fock.setup(ctx,imei); S({m:'◆setup(ctx,imei) uk='+uk().slice(0,44)});
    try{ Fock.addKeypool(VER,K128); }catch(e){}
    FR(Fock.unlock(CTs,cidS,pair,null),'U4');
  }catch(e){ S({m:'setup2 败 '+String(e).slice(0,80)}); }
  S({m:'v70 出'});
});
})();
