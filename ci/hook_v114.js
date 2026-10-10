// hook_v114.js — v74: ①修 sleep(Java.use) ②rks/requestKey 后真轮询 unlock ③lock环测 urlsafe→std ④cihai/judian/search 公开解密口调用 ⑤addKeypool 全6字段JSON
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  function sleep(ms){ Java.use('java.lang.Thread').sleep(ms); }
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT, K128=BD.K128, VER=''+BD.VER, imei=''+BD.imei;
  var B64=Java.use('android.util.Base64');
  var cidS='799920041', book='1040025277', pairU=book+'_'+cidS, pairV=book+'|'+cidS;
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FUinst=FU.INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0&&r.data){ var d=r.data; S({m:'█'+tag+' len='+d.length}); S({m:'█B64='+(''+B64.encodeToString(d,0)).slice(0,1200)}); } return st; }catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});return -9;} }
  function unlockX(data,nm,ch,tag){ try{ FR(Fock.unlock(data,nm,ch,null),tag); return true; }catch(e){ S({m:tag+' 败 '+String(e).slice(0,60)}); return false; } }
  try{ Fock.setup(imei); }catch(e){}
  S({m:'v74 uk='+(''+Fock.currentUserKey()).slice(0,40)});
  // ① cihai/judian/search 签名 dump + 直调
  try{
    var mlist=FU.class.getDeclaredMethods();
    for(var i=0;i<mlist.length;i++){
      var mth=mlist[i]; var nm=''+mth.getName();
      if(nm==='cihai'||nm==='judian'||nm==='search'){
        S({m:'◆SIG '+nm+' → '+(''+mth).replace('public ','').replace('static ','')});
      }
    }
  }catch(e){S({m:'①dump败 '+String(e).slice(0,70)});}
  try{
    // 逐个试: 各重载直调 (String,String,String) / (String) / ([B,..])
    var cands=[
      ['cihai', ['java.lang.String','java.lang.String','java.lang.String'], [CTs,cidS,pairU]],
      ['cihai', ['java.lang.String','java.lang.String','java.lang.String'], [CTs,pairU,VER]],
      ['judian',['java.lang.String','java.lang.String','java.lang.String'], [CTs,cidS,pairU]],
      ['search',['java.lang.String','java.lang.String','java.lang.String'], [CTs,cidS,pairU]],
      ['cihai', ['java.lang.String'], [CTs]],
      ['judian',['java.lang.String'], [CTs]],
      ['search',['java.lang.String'], [CTs]],
      ['cihai', ['java.lang.String','java.lang.String'], [CTs,pairU]],
      ['cihai', ['java.lang.String','java.lang.String'], [K128,pairU]]
    ];
    for(var ci=0;ci<cands.length;ci++){
      try{
        var ov=FU[cands[ci][0]].overload.apply(FU[cands[ci][0]],cands[ci][1]);
        var ret=ov.apply(FUinst,cands[ci][2]);
        var rs=ret===null?'null':(''+ret);
        S({m:'◆CALL'+ci+' '+cands[ci][0]+'→ '+rs.slice(0,80)+(rs.length>20?' len='+rs.length:'')});
      }catch(e2){ S({m:'◆CALL'+ci+' '+cands[ci][0]+' 败 '+String(e2).slice(0,70)}); }
    }
  }catch(e){S({m:'①调败 '+String(e).slice(0,80)});}
  // ② requestKey(ctx) 异步 → 轮询 unlock 10×2s
  try{
    FU.requestKey.call(FUinst,ctx);
    for(var w=0;w<10;w++){ sleep(2000);
      var hit=unlockX(CTs,cidS,pairU,'轮q'+w); if(hit) w=99;
    }
  }catch(e){S({m:'②败 '+String(e).slice(0,80)});}
  // ③ rks + 轮询
  try{
    var rks=FU.requestKeySync.overload('android.content.Context','long');
    rks.call(FUinst,ctx,parseInt(cidS));
    for(var w3=0;w3<8;w3++){ sleep(2000);
      var hit3=unlockX(CTs,cidS,pairU,'轮r'+w3); if(hit3) w3=99;
    }
  }catch(e){S({m:'③败 '+String(e).slice(0,80)});}
  // ④ lock 环测 urlsafe→std
  try{
    var lc=''+Fock.lock('验证环测试123456');
    var lc2=lc.replace(/-/g,'+').replace(/_/g,'/');
    while(lc2.length%4!==0) lc2+='=';
    unlockX(lc2,cidS,pairU,'环std');
    unlockX(lc,cidS,pairU,'环raw');
  }catch(e){S({m:'④败 '+String(e).slice(0,70)});}
  // ⑤ addKeypool 全 6 字段 JSON (从 files.xml 学结构, d=K128) + 键名 "1"
  try{
    var j6='{\"d\":\"'+K128+'\",\"id\":\"'+pairU+'\",\"st\":0,\"et\":0,\"dt\":0,\"to\":0}';
    Fock.addKeypool(VER,j6); S({m:'◆akp6 OK'});
    unlockX(CTs,cidS,pairU,'U_akp6');
    Fock.addKeypool('1',K128); S({m:'◆akp1 OK'});
    unlockX(CTs,cidS,pairU,'U_akp1');
  }catch(e){S({m:'⑤败 '+String(e).slice(0,70)});}
  S({m:'v74 出'});
});
})();
