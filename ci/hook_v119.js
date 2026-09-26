// hook_v119.js — v79: ★ctx-init×身份矩阵 (v78 疑点: setup(String) 在未 setup(Context) 时全被拒)
// 序列: Fock.setup(Context) → setup(ui小写/ui去横线/imei) → currentUserKey 验证 → addKeypool(ui0/ui1) → unlock
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f),'UTF-8'));var s='',l;while((l=r.readLine())!=null)s+=l;r.close();return s;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v79_bundle.json'));
  var Fock=Java.use('com.yuewen.fock.Fock');
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var uk=function(){try{return ''+Fock.currentUserKey();}catch(e){return 'ERR';}};
  var pair=BD.book+'_'+BD.cid;
  var U=function(data){try{var R=Fock.unlock(data,BD.cid,pair,null);return {st:R.status.value,data:R.data.value};}catch(e){return {st:'E',data:String(e).slice(0,40)};}};
  S({m:'v79 起 uk0='+uk().slice(0,44)});
  var HIT=null;
  // ① 先 ctx 初始化
  try{ Fock.setup(ctx); S({m:'◆setup(ctx) OK uk='+uk().slice(0,40)}); }catch(e){ S({m:'◆setup(ctx) 败 '+String(e).slice(0,80)}); }
  // ② 身份候选 (全部在 ctx-init 之后)
  var ids=[['keep',null],[BD.imei,'imei'],[BD.ui,'ui'],[(BD.ui||'').toLowerCase(),'ui_lc'],[(BD.ui||'').replace(/-/g,''),'ui_nohy'],[BD.qimei_full,'qimei36']];
  for(var ii=0;ii<ids.length&&HIT==null;ii++){
    if(ids[ii][1]){ try{ Fock.setup(ids[ii][1]); }catch(e){ S({m:'◆setup('+ids[ii][0]+') 败 '+String(e).slice(0,60)}); continue; } }
    var u=uk();
    S({m:'◆['+ids[ii][0]+'] uk='+u.slice(0,44)});
    // ③ 双钥×注册
    var ks=[[BD.K128,'ui0'],[BD.K128_ui1,'ui1']];
    for(var ki=0;ki<ks.length&&HIT==null;ki++){
      if(!ks[ki][0]) continue;
      try{ Fock.addKeypool(BD.VER,ks[ki][0]); }catch(e){ continue; }
      var r=U(BD.CT);
      S({m:'◆'+ids[ii][0]+'×'+ks[ki][1]+' st='+r.st});
      if(r.st===0){ HIT=['body',ids[ii][0],ks[ki][1],r.data]; }
    }
  }
  // ④ 命中回传
  if(HIT && HIT[3]){
    var b=HIT[3];
    S({m:'█HIT='+HIT[0]+'/'+HIT[1]+'/'+HIT[2]+' len='+b.length});
    var Base64=Java.use('android.util.Base64');
    var sb=Base64.encodeToString(b,2);
    S({m:'█B64='+(''+sb).slice(0,3000)});
  }
  // ⑤ 独家备采: requestKeySync(ctx,cid) 登录态申领 (v68 姿势=直接调)
  try{ var ok=Fock.requestKeySync(ctx,Java.use('java.lang.Long').$new(BD.cid)); S({m:'◆rks登录态='+ok});
    if(ok){ var r2=U(BD.CT); S({m:'◆rks后 st='+r2.st}); if(r2.st===0)HIT=['rks','',null,r2.data]; } }catch(e){ S({m:'◆rks 败 '+String(e).slice(0,70)}); }
  S({m:'v79 出'});
});
})();