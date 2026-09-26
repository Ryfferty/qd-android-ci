// hook_v118.js — v78: ★修 v77 双 bug(矩阵短路 return + bundle 字段名) — 4身份×2钥全矩阵, 每格完整跑
// 官方签名(v77对照确认): addKeypool(VER,K128) / setup(String) / unlock(data,cid,pair,handler)
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v78_bundle.json'));
  var CTs=''+BD.CT, K0=''+BD.K128, VER=''+BD.VER;
  var imei=''+BD.imei, ui=''+BD.ui, uikey=''+BD.uikey, q=''+BD.qimei_full;
  var cidS=''+BD.cid, book=''+BD.book, pair=book+'_'+cidS;
  var B64=Java.use('android.util.Base64');
  var Fock=Java.use('com.yuewen.fock.Fock');
  function uk(){try{return ''+Fock.currentUserKey();}catch(e){return 'E';}}
  var HIT=false;
  function FR(r,tag){try{var st=r.status.value;S({m:'◆'+tag+' st='+st});
    if(st===0&&r.data){HIT=true;var d=r.data;S({m:'█'+tag+' len='+d.length});S({m:'█B64='+(''+B64.encodeToString(d,0))});}
    return st;}catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});return -9;}}
  function U(tag){try{return FR(Fock.unlock(CTs,cidS,pair,null),tag);}catch(e){S({m:tag+' 败 '+String(e).slice(0,60)});return -99;}}
  // 矩阵 (ui1 钥缺失 → K0 双试位: 保留 K1 若 bundle 有)
  var K1 = BD.K128_ui1 ? ''+BD.K128_ui1 : null;
  var ids=[['imei',imei],['ui',ui],['uikey',uikey],['q',q]];
  for(var ii=0;ii<ids.length && !HIT;ii++){
    if(!ids[ii][1]){S({m:'跳过空身份 '+ids[ii][0]});continue;}
    try{ Fock.setup(ids[ii][1]); }catch(e){S({m:'setup '+ids[ii][0]+' 败 '+String(e).slice(0,50)});continue;}
    S({m:'◆['+ids[ii][0]+'] uk='+uk().slice(0,40)});
    var ks=K1?[[K1,'ui1'],[K0,'ui0']]:[[K0,'ui0']];
    for(var ki=0;ki<ks.length && !HIT;ki++){
      try{ Fock.addKeypool(VER,ks[ki][0]); }catch(e){S({m:'akp '+ks[ki][1]+' 败 '+String(e).slice(0,60)});}
      U(ids[ii][0]+'×'+ks[ki][1]);
    }
  }
  if(!HIT){ // 收尾独家: unlockData 字节版 + ui1 直喂(池外临时)
    var CTb=B64.decode(CTs,0);
    try{ var r=Fock.unlockData(CTb,cidS,pair,null); FR(r,'UD'); }catch(e){S({m:'UD 败 '+String(e).slice(0,60)});}
  }
  S({m:HIT?'★★★ 命中':'v78 全灭, 身份×钥矩阵无 0'});
});
})();
