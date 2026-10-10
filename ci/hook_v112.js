// hook_v112.js — v72: ★pair 分隔符修正: "_" 非 "|"; 身份姿势矩阵 (setup qimei16/ctx)
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT, K128=BD.K128, VER=''+BD.VER, imei=''+BD.imei, qimei16=BD.qimei16||'b3b295be58644158';
  var B64=Java.use('android.util.Base64');
  var cidS='799920041', book='1040025277', pairU=book+'_'+cidS, pairV=book+'|'+cidS;
  var Fock=Java.use('com.yuewen.fock.Fock');
  function uk(){ try{ return ''+Fock.currentUserKey(); }catch(e){ return 'E'; } }
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0&&r.data){ var d=r.data; S({m:'█'+tag+' len='+d.length}); var b=''+B64.encodeToString(d,0); S({m:'█B64='+b.slice(0,1200)}); } return st; }catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});return -9;} }
  S({m:'v72 uk='+uk().slice(0,40)});
  // ① 下划线 pair 直打 (App 原生状态)
  try{ FR(Fock.unlock(CTs,cidS,pairU,null),'U_原生'); }catch(e){S({m:'a '+String(e).slice(0,60)});}
  // ② setup(qimei16) 对照
  try{ Fock.setup(qimei16); S({m:'◆setupQ uk='+uk().slice(0,40)}); }catch(e){S({m:'sq败 '+String(e).slice(0,60)});}
  try{ FR(Fock.unlock(CTs,cidS,pairU,null),'U_setupQ'); }catch(e){}
  // ③ setup(ctx)
  try{ var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    Fock.setup(ctx); S({m:'◆setupC uk='+uk().slice(0,40)});
    FR(Fock.unlock(CTs,cidS,pairU,null),'U_setupC');
  }catch(e){S({m:'sc败 '+String(e).slice(0,60)});}
  // ④ setup(imei) + 下划线 pair
  try{ Fock.setup(imei); FR(Fock.unlock(CTs,cidS,pairU,null),'U_setupI_'); }catch(e){}
  // ⑤ setup(imei) + addKeypool + 下划线
  try{ Fock.addKeypool(VER,K128); FR(Fock.unlock(CTs,cidS,pairU,null),'U_akp_');
       FR(Fock.unlock(CTs,pairU,VER,null),'U_akp_2');
  }catch(e){S({m:'e '+String(e).slice(0,60)});}
  // ⑥ 实例 FU unlock 下划线 (其内部可能拼 ctx)
  try{ var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var FUinst=FU.INSTANCE.value;
    var u4=FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
    FR(u4.call(FUinst,CTs,cidS,pairU,null),'FU_下划线');
  }catch(e){S({m:'f '+String(e).slice(0,70)});}
  // ⑦ unlockData 下划线
  try{ FR(Fock.unlockData(B64.decode(CTs,0),cidS,pairU,null),'UD_'); }catch(e){}
  S({m:'v72 出'});
});
})();
