// hook_v103.js — v63: unlockData(byte[],str,str,handler) 从未试过(直喂byte!绕base64层) + uksf/uk 底层直通 + FockUtil实例2参unlock
// 钥: v60 bundle K128(96B池) 切段全形态 / batchKey 三形态
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f),'UTF-8'));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json'));
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json')||readText('/data/local/tmp/v16_params.json'));
  var CTb=Java.use('android.util.Base64').decode(BD.CT,10); // URL_SAFE
  var Kraw=Java.use('android.util.Base64').decode(BD.K128,0);
  var bkBytes=Java.use('java.lang.String').$new(BD.batchKey,'UTF-8').getBytes('UTF-8');
  S({m:'v63 载 CT='+CTb.length+'B Kraw='+Kraw.length+'B'});
  var Fock=Java.use('com.yuewen.fock.Fock');
  var cidS='799920041', pair='1040025277|799920041';
  var CTs=''+Java.use('java.lang.String').$new(CTb,'UTF-8');
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0){ var d=r.data; var sb=[]; for(var z=0;z<Math.min(120,d.length);z++){ sb.push(String.fromCharCode(d[z]&0xff)); } S({m:'█'+tag+' DATA='+sb.join('').replace(/[\r\n]+/g,' ').slice(0,110)}); } }catch(e){S({m:'◆'+tag+' 读败 '+String(e).slice(0,60)});} }
  // ① unlockData 静态: (byte[] data, String cid, String pair, handler) — 直喂字节绕开 bad-base64 层!
  try{ S({m:'ud4 overload: '+(!!Fock.unlockData.overload)}); }catch(e){}
  var udOv;
  try{ udOv=Fock.unlockData.overload('[B','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler'); }catch(e){ S({m:'ud ov 败 '+String(e).slice(0,90)}); }
  if(udOv){
    try{ FR(udOv.call(null,CTb,cidS,pair,null),'ud(CT,cid,pair)'); }catch(e){S({m:'ud(CT,cid,pair) 败 '+String(e).slice(0,90)});}
    try{ FR(udOv.call(null,CTb,pair,cidS,null),'ud(CT,pair,cid)'); }catch(e){S({m:'ud(CT,pair,cid) 败 '+String(e).slice(0,90)});}
  }
  // ② FockUtil 实例 2参 unlock(str,str)
  var FU=null;
  try{ FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value; }catch(e){ S({m:'FU inst 败 '+String(e).slice(0,60)}); }
  try{
    var u2ov=Java.use('com.qidian.QDReader.component.util.FockUtil').unlock.overload('java.lang.String','java.lang.String');
    FR(u2ov.call(FU,CTs,pair),'instU2(CT,pair)');
    FR(u2ov.call(FU,CTs,cidS),'instU2(CT,cid)');
  }catch(e){S({m:'instU2 败 '+String(e).slice(0,90)});}
  // ③ 私有底层 uk/uksf (byte[] 直通)
  try{
    var uksf=Fock['uksf.overload']?null:null;
    var uk=Fock.uk||Fock.m67572uk;
    S({m:'uk 存在? '+(!!uk)});
  }catch(e){S({m:'uk 探败 '+String(e).slice(0,60)});}
  // ④ 常规 4/5 参 unlock 换 unlockData 语义下的 b64url-CT (对照)
  try{ FR(Fock.unlock(CTs,cidS,pair,null),'U4(CTb64url)'); }catch(e){}
  S({m:'v63 出'});
  java.lang.Thread.sleep(3000);
});
})();
