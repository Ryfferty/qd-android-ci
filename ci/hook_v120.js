// hook_v120.js — v80: ★双序列定位车: A组(无ctx: setup(imei)+akp 基线复证) → B组(setup(ctx)→setup(ui) UUID身份→akp双钥→unlock)
// v79线索: setup(ctx) 后 uk 变真UUID格式(9b0636d7-…) 且 keep×ui0 的 addKeypool 无输出(疑挂) → 每动作前打印定位
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f),'UTF-8'));var s='',l;while((l=r.readLine())!=null)s+=l;r.close();return s;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v80_bundle.json'));
  var Fock=Java.use('com.yuewen.fock.Fock');
  var pair=BD.book+'_'+BD.cid;
  var uk=function(){try{return ''+Fock.currentUserKey();}catch(e){return 'ERR';}};
  var U=function(tag){try{var R=Fock.unlock(BD.CT,BD.cid,pair,null);S({m:'◆'+tag+' st='+R.status.value});return R.status.value;}catch(e){S({m:'◆'+tag+' 败 '+String(e).slice(0,50)});return -99;}};
  var AK=function(ver,key,tag){S({m:'→akp('+tag+') 前'});try{Fock.addKeypool(ver,key);S({m:'→akp('+tag+') OK'});}catch(e){S({m:'→akp('+tag+') 败 '+String(e).slice(0,60)});}};
  S({m:'v80 起 uk0='+uk().slice(0,40)});

  // ══ A组 基线复证 (v78 实证路: 无ctx, setup(imei)) ══
  try{ Fock.setup(BD.imei); }catch(e){ S({m:'A setup(imei) 败 '+String(e).slice(0,50)}); }
  S({m:'◆A uk='+uk().slice(0,40)});
  AK(BD.VER,BD.K128,'A ui0');
  U('A imei×ui0');

  // ══ B组 ctx-init + ui-UUID 身份 ══
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  S({m:'→B setup(ctx) 前'});
  try{ Fock.setup(ctx); S({m:'◆B1 setup(ctx) OK uk='+uk().slice(0,40)}); }catch(e){ S({m:'◆B setup(ctx) 败 '+String(e).slice(0,60)}); }
  S({m:'→B akp@ctx身份 ui0 前'});
  AK(BD.VER,BD.K128,'B ctx×ui0');
  U('B ctx×ui0');
  S({m:'→B akp ui1 前'});
  if(BD.K128_ui1){ AK(BD.VER,BD.K128_ui1,'B ctx×ui1'); U('B ctx×ui1'); }

  // ══ C组 ctx-init 后再切会话 ui 身份 (大写/小写/去横线) ══
  var cands=[['ui',BD.ui],['ui_lc',(BD.ui||'').toLowerCase()],['ui_nohy',(BD.ui||'').replace(/-/g,'')]];
  for(var ci=0;ci<cands.length;ci++){
    if(!cands[ci][1]) continue;
    S({m:'→C setup('+cands[ci][0]+') 前'});
    try{ Fock.setup(cands[ci][1]); }catch(e){ S({m:'◆C '+cands[ci][0]+' setup 败 '+String(e).slice(0,50)}); continue; }
    S({m:'◆C uk='+uk().slice(0,40)});
    AK(BD.VER,BD.K128,'C '+cands[ci][0]+'×ui0'); U('C '+cands[ci][0]+'×ui0');
    if(BD.K128_ui1){ AK(BD.VER,BD.K128_ui1,'C '+cands[ci][0]+'×ui1'); U('C '+cands[ci][0]+'×ui1'); }
  }
  // ══ D组 登录态申领 (rks 走 App 当前会话身份拉章钥进池) ══
  S({m:'→D rks 前 uk='+uk().slice(0,40)});
  try{
    var r1=Fock.requestKeySync(ctx, Java.use('java.lang.Long').$new(BD.cid));
    S({m:'◆D rks(cid)='+r1});
    if((''+r1)==='true'){ U('D rks×ui0'); if(BD.K128_ui1){AK(BD.VER,BD.K128_ui1,'D ui1'); U('D rks×ui1');} }
  }catch(e){ S({m:'◆D rks 败 '+String(e).slice(0,70)}); }
  S({m:'v80 出'});
});
})();