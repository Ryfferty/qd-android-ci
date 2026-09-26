// hook_v117.js — v77: ★ui=1 Key (服务端按身份发的另一把!) × setup 身份交叉矩阵
// 本地新证: getkey ui=0→Eocb… ui=1→vdk5… 完全不同 → App rks 用登录身份,我们之前全喂 ui=0 的
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v77_bundle.json'));
  var CTs=BD.CT, K0=BD.K128_ui0, K1=BD.K128_ui1, VER=''+BD.VER;
  var imei=BD.imei, ui=BD.ui, uikey=BD.uikey, qfull=BD.qimei_full;
  var cidS='799920041', book='1040025277', pairU=book+'_'+cidS;
  var B64=Java.use('android.util.Base64');
  var Fock=Java.use('com.yuewen.fock.Fock');
  function uk(){try{return ''+Fock.currentUserKey();}catch(e){return 'E';}}
  function FR(r,tag){try{var st=r.status.value;S({m:'◆'+tag+' st='+st});if(st===0&&r.data){var d=r.data;S({m:'█'+tag+' len='+d.length});S({m:'█B64='+(''+B64.encodeToString(d,0)).slice(0,1500)});}return st;}catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});return -9;}}
  function U(tag){try{FR(Fock.unlock(CTs,cidS,pairU,null),tag);return true;}catch(e){S({m:tag+' 败 '+String(e).slice(0,50)});return false;}}
  // 矩阵: 身份 × 池钥
  var ids=[['imei16',imei],['ui',ui],['uikey',uikey],['qfull',qfull]];
  var keys=[['ui1',K1],['ui0',K0]];
  for(var ii=0;ii<ids.length;ii++){
    try{ Fock.setup(ids[ii][1]); }catch(e){S({m:'setup '+ids[ii][0]+' 败 '+String(e).slice(0,40)});}
    S({m:'◆'+ids[ii][0]+' uk='+uk().slice(0,36)});
    for(var ki=0;ki<keys.length;ki++){
      try{ Fock.addKeypool(VER,keys[ki][1]); }catch(e){S({m:'akp败 '+String(e).slice(0,40)});}
      var hit=U(ids[ii][0]+'×'+keys[ki][0]);
      if(hit){ii=99;ki=99;}
    }
  }
  S({m:'v77 出'});
});
})();
