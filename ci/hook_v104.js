// hook_v104.js — v64: 修正 CT 保真(v63的b64url解码链把串毁了→-1) — 直接用 bundle.CT 原串喂 unlock
// 目标: 回到 -4 的正确数据基线 → unlockData(byte[]真296B) + U4(CT原串) + uksf 底层直通
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT;                       // 标准b64原串(396字符) — 不转码!
  var CTb=Java.use('android.util.Base64').decode(CTs,10);  // 真 296B
  var Kraw=Java.use('android.util.Base64').decode(BD.K128,10);
  var env='{"code":0,"content":"'+CTs+'","type":1}';
  S({m:'v64 CTs='+CTs.length+' CTb='+CTb.length+' Kraw='+Kraw.length});
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FUinst=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var cidS='799920041', pair='1040025277|799920041';
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0){ var d=r.data; var t=Java.use('java.lang.String').$new(d); S({m:'█'+tag+' '+(''+t).slice(0,120)}); } }catch(e){S({m:'◆'+tag+' 读败 '+String(e).slice(0,60)});} }
  // ① Fock.unlock(String...) 静态自动直调 (v58 同款) — CT原串/env全文 双形态
  try{ FR(Fock.unlock(CTs,cidS,pair,null),'U4(CTs,cid,pair)'); }catch(e){S({m:'U4a 败 '+String(e).slice(0,70)});}
  try{ FR(Fock.unlock(env,cidS,pair,null),'U4(env,cid,pair)'); }catch(e){S({m:'U4b 败 '+String(e).slice(0,70)});}
  try{ FR(Fock.unlock(CTs,pair,cidS,null),'U4(CTs,pair,cid)'); }catch(e){}
  // ② unlockData(byte[] 真296B, str, str, handler) — 实例调用 (v63 call(null) 崩)
  try{
    var udOv=Fock.unlockData.overload('[B','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
    FR(udOv(FUinst,[CTb,cidS,pair,null]),'ud(CTb,cid,pair)');
  }catch(e){ try{ FR(Fock.unlockData(CTb,cidS,pair,null),'ud.auto'); }catch(e2){ S({m:'ud 败 '+String(e2).slice(0,90)}); } }
  // ③ uksf 底层直通: byte[] data + byte[] key (Kraw 切段全形态)
  try{
    var uksf=Fock['uk'];
    if(uksf){
      var ks=[Kraw.slice(0,24),Kraw.slice(0,32),Kraw.slice(24,48),Kraw.slice(72,96),Kraw.slice(0,16),Kraw.slice(80,96)];
      var kns=['K0:24','K0:32','K24:48','K72:96','K0:16','K80:96'];
      for(var ki=0;ki<ks.length;ki++){
        try{
          var r=uksf(CTb,CTb.length,ks[ki],ks[ki].length,null);
          FR(r,'uksf('+kns[ki]+')');
        }catch(e){ S({m:'uksf '+kns[ki]+' 败 '+String(e).slice(0,60)}); break; }
      }
    }
  }catch(e){S({m:'uksf 探败 '+String(e).slice(0,80)});}
  // ④ 实例 2参/4参 (v63 同款但 CT 保真)
  try{
    var u2=Java.use('com.qidian.QDReader.component.util.FockUtil').unlock.overload('java.lang.String','java.lang.String');
    FR(u2.call(FUinst,CTs,pair),'instU2(CTs,pair)');
    FR(u2.call(FUinst,CTs,cidS),'instU2(CTs,cid)');
    var u4=Java.use('com.qidian.QDReader.component.util.FockUtil').unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
    FR(u4.call(FUinst,CTs,cidS,pair,null),'instU4(CTs)');
    FR(u4.call(FUinst,env,cidS,pair,null),'instU4(env)');
  }catch(e){S({m:'inst 败 '+String(e).slice(0,90)});}
  S({m:'v64 出'});
});
})();
