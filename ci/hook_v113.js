// hook_v113.js — v73: ★App 原生解密链: FockUtil.cihai(judian,..)/judian()/search()/EnvResult + rks 全码 + lock 环测假说
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT, K128=BD.K128, VER=''+BD.VER, imei=''+BD.imei;
  var B64=Java.use('android.util.Base64');
  var cidS='799920041', book='1040025277', pairU=book+'_'+cidS;
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FUinst=FU.INSTANCE.value;
  function uk(){ try{ return ''+Fock.currentUserKey(); }catch(e){ return 'E'; } }
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0&&r.data){ var d=r.data; S({m:'█'+tag+' len='+d.length}); var b=''+B64.encodeToString(d,0); S({m:'█B64='+b.slice(0,1200)}); } return st; }catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});return -9;} }
  try{ Fock.setup(imei); }catch(e){}
  S({m:'v73 uk='+uk().slice(0,40)});
  // ① EnvResult / cihai / judian / search 探路
  try{
    S({m:'◆FU methods: '+FU.class.getDeclaredMethods().length});
    var mlist=FU.class.getDeclaredMethods(); var names={};
    for(var i=0;i<mlist.length;i++){ var nm=''+mlist[i].getName(); names[nm]=1; }
    S({m:'◆env/cihai/judian/search 在? '+JSON.stringify({env:!!names.env||!!names.getEnv, cihai:!!names.cihai, judian:!!names.judian, search:!!names.search})});
  }catch(e){S({m:'①探败 '+String(e).slice(0,80)});}
  // ② requestKey(ctx) 异步申领 + 轮询 unlock (最长 20s)
  try{
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    FU.requestKey.call(FUinst,ctx);
    S({m:'◆requestKey(ctx) 已发'});
    for(var w=0;w<10;w++){
      java.lang.Thread.sleep(2000);
      try{ var st=FR(Fock.unlock(CTs,cidS,pairU,null),'轮'+w); if(st===0)break; }catch(e){}
    }
  }catch(e){S({m:'②败 '+String(e).slice(0,80)});}
  // ③ rks 真参 (book / cid / pair / uid) + 立即 unlock
  try{
    var rks=FU.requestKeySync.overload('android.content.Context','long');
    var ids=[[parseInt(cidS),'cid'],[parseInt(book),'book'],[parseInt('0'),'uid0']];
    for(var k=0;k<ids.length;k++){
      try{ var ok=rks.call(FUinst,ctx,ids[k][0]); S({m:'◆rks('+ids[k][1]+')='+ok});
        for(var w2=0;w2<3;w2++){ java.lang.Thread.sleep(1500);
          var st2=FR(Fock.unlock(CTs,cidS,pairU,null),'后'+ids[k][1]+w2); if(st2===0){w2=99;k=99;} }
      }catch(e){S({m:'rks'+ids[k][1]+' 败 '+String(e).slice(0,60)});}
    }
  }catch(e){S({m:'③败 '+String(e).slice(0,90)});}
  // ④ lock 环测: 注册 K128 后 lock(x) → unlock(lockout) 环=1 证钥方向可用
  try{
    Fock.addKeypool(VER,K128);
    var lck=Fock.lock('验证环测试123456');
    S({m:'◆lock头='+(''+lck).slice(0,40)});
    var rr=Fock.unlock(''+lck,cidS,pairU,null);
    S({m:'◆环 st='+rr.status.value+' out='+(''+Java.use('java.lang.String').$new(rr.data||Java.array('byte',[0]))).slice(0,30)});
  }catch(e){S({m:'④败 '+String(e).slice(0,80)});}
  S({m:'v73 出'});
});
})();
