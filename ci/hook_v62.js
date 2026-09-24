// hook_v62.js — v22: 先注册键池(add/addMap/requestKeySync) → 读 App 内部密钥 getter → 再打 unlock
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);}catch(e){try{s=s.toString();}catch(e2){return '[bytes]';}}return s.length>n?s.slice(0,n)+'…':s;}
function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||60);i++){var c=a[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
function bArr(jstr){var s=jstr.getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
function fr(tag,r){
  if(r===null){S({m:tag+' → null'});return;}
  try{
    var st=r.status.value; var d=r.data.value; var msg=''; try{msg=r.message.value+'';}catch(e){}
    if(d!==null&&d!==undefined&&d.length>=0){var a=[];for(var i=0;i<Math.min(d.length,64);i++)a.push(d[i]&255);
      var pr=0;for(var i=0;i<a.length;i++){if(a[i]>=32&&a[i]<127)pr++;}
      S({m:'★'+tag+' status='+st+' len='+d.length+' print='+(a.length?(pr/a.length).toFixed(2):'-')+' asc='+asc(a,48)+((a.length&&pr/a.length>0.85)?' ██命中!!':'')});
    } else S({m:'·'+tag+' status='+st+' data=null '+clip(msg,24)});
  }catch(e){S({m:tag+' 读结果异常 '+String(e).slice(0,60)});}
}
(function(){
  var P={};
  try{
    var f=Java.use('java.io.File').$new('/data/local/tmp/v16_params.json');
    var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));
    var sb=Java.use('java.lang.StringBuilder').$new(); var ln;
    while((ln=br.readLine())!==null) sb.append(ln);
    br.close();
    P=JSON.parse(sb.toString()+'');
  }catch(e1){S({m:'params 读取失败 '+String(e1).slice(0,90)});}
  if(!P.payload_b64){S({m:'无 payload, 退出'});return;}
  var book=P.book+'',cid=P.cid+'';
  var b64=Java.use('android.util.Base64').encodeToString(Java.array('byte',(function(){var d=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<d.length;i++)a.push(d[i]);return a;})()),2)+'';
  var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FU=FUc.INSTANCE.value;
  var FK=Java.use('com.yuewen.fock.Fock');
  var app=Java.use('android.app.ActivityThread').currentApplication();
  var ctx=app.getApplicationContext();

  // ⓪ 引擎内部密钥 getter — App 自己有什么钥匙
  var getters=['get3DesKey','getNibKey','getRtKey','getCloudConfigKey','getAudioAesKey','getKey','getPreUserKey','isHasKey','currentThreatLevel','getCanReportNormalResult'];
  for(var g=0;g<getters.length;g++){
    try{ var val=getters[g]==='getCanReportNormalResult'||getters[g]==='isHasKey'||getters[g]==='currentThreatLevel'? FU[getters[g]](): FU[getters[g]].call(FU);
      S({m:'◆ '+getters[g]+'() = '+clip(String(val),48)});}catch(e){S({m:'◆ '+getters[g]+' 异常 '+String(e).slice(0,60)});}
  }
  // ① 键池注册三连 (n0.search 模式: -5→setup→重试; 键池靠 requestKeySync/add)
  var R1=null;
  try{ R1=FK.currentUserKey?null:null; }catch(e){}
  try{ S({m:'① setup(S) 重试通道: '+clip(String(FK.setup(P.userKey)),20)});}catch(e){S({m:'① setup 异常 '+String(e).slice(0,80)});}
  try{ FU.add(book, book+'_'+cid); S({m:'① add(book,pair) OK'});}catch(e){S({m:'① add 异常 '+String(e).slice(0,80)});}
  try{ var m=Java.use('java.util.HashMap').$new(); m.put(book+'', (P.batch_key||'')+''); m.put(book+'_'+cid+'', (P.batch_key||'')+''); FU.addMap(m); S({m:'① addMap{book→bk,pair→bk} OK'});}catch(e){S({m:'① addMap 异常 '+String(e).slice(0,80)});}
  // ② 重打 unlock 全形态
  function fr(tag,r){
    if(r===null){S({m:tag+' → null'});return;}
    var st=r.status.value; var d=r.data.value;
    var msg=''; try{msg=r.message.value+'';}catch(e){}
    if(d!==null&&d!==undefined){var a=[];for(var i=0;i<Math.min(d.length,64);i++)a.push(d[i]&255);
      var pr=0;for(var i=0;i<a.length;i++){if(a[i]>=32&&a[i]<127)pr++;}
      S({m:'★'+tag+' status='+st+' len='+d.length+' print='+(a.length?(pr/a.length).toFixed(2):'-')+' asc='+asc(a,48)+(pr/a.length>0.85?' ██命中!!':'')});
    } else S({m:'·'+tag+' status='+st+' data=null '+clip(msg,24)});}
  function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||60);i++){var c=a[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
  try{ fr('② unlock2(b64,book)', FU.unlock(b64, book)); }catch(e){S({m:'② u2 异常 '+String(e).slice(0,70)});}
  try{ fr('② unlock4(b64,book,pair,null)', FU.unlock(b64, book, book+'_'+cid, null)); }catch(e){S({m:'② u4 异常 '+String(e).slice(0,70)});}
  try{ fr('② unlock$default', FUc.unlock$default(FU, b64, book, book+'_'+cid, null, 8, null)); }catch(e){S({m:'② ud 异常 '+String(e).slice(0,70)});}
  // ③ requestKeySync 网络拉键 (App 真拉键路径) → 再 unlock
  try{ var ok=FU.requestKeySync(ctx, parseInt(book)); S({m:'③ requestKeySync='+ok}); }catch(e){S({m:'③ rks 异常 '+String(e).slice(0,80)});}
  try{ fr('③ afterRKS unlock4', FU.unlock(b64, book, book+'_'+cid, null)); }catch(e){}
  try{ FU.add(book, book+'_'+cid); fr('③ afterAdd unlock4', FU.unlock(b64, book, book+'_'+cid, null)); }catch(e){}
  // ④ getKeyMap 看池子
  try{ var km=FU.getKeyMap(ctx); S({m:'④ getKeyMap size='+km.size()+' keys='+clip(String(km.keySet()),120)});}catch(e){S({m:'④ gkm 异常 '+String(e).slice(0,70)});}
  // ⑤ Fock.uk 直调 (池注册后可能通)
  try{ var d=Java.use('android.util.Base64').decode(P.payload_b64,2);
    var UK=FK.uk.overload('[B','int','[B','int');
    var adds={'book':bArr(book),'pair':bArr(book+'_'+cid),'bk':bArr(P.batch_key||''),'md5':bArr(P.md5||''),'ver':bArr(String(P.Version))};
    for(var k in adds){ try{ fr('⑤ uk|'+k, UK.call(FK,d,d.length,adds[k],adds[k].length)); }catch(e){S({m:'⑤ uk|'+k+' 异常 '+String(e).slice(0,60)});} }
  }catch(e){S({m:'⑤ setup 异常 '+String(e).slice(0,60)});}
  S({m:'v22 done'});
  Java.perform(function(){});
})();
