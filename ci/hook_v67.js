// hook_v67.js — v28: ★引擎内建钥匙(ibex/cecelia/borgus/cloudcfg/audioAesKey/preUserKey) × unlock 全形态矩阵
// v27 教训: FU.add() native 阻塞挂死脚本 → 本轮矩阵先跑, add/rks 挪最后且包线程
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function fget(obj,name){try{var f=obj.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(obj);}catch(e){return null;}}
function jint(v){if(v===null||v===undefined)return null;try{return v.intValue();}catch(e){try{return parseInt(''+v,10);}catch(e2){return null;}}}
function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||60);i++){var c=a[i]&255;s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
function report(tag,r){
  if(r===null||r===undefined){S({m:tag+' → null'});return true;}
  try{
    var st=jint(fget(r,'status')); if(st===null)st=jint(fget(r,'errCode'));
    var data=fget(r,'data'); var msg=''+(fget(r,'message')||'');
    if(st===0&&data){
      var jb=Java.cast(data,Java.use('[B'));
      var a=[];for(var i=0;i<Math.min(jb.length,80);i++)a.push(jb[i]&255);
      var pr=0;for(var i=0;i<a.length;i++){if(a[i]>=32&&a[i]<127)pr++;}
      var full=[];for(var i=0;i<Math.min(jb.length,6000);i++)full.push(jb[i]);
      S({m:'███命中!! '+tag+' status=0 len='+jb.length+' print='+(a.length?(pr/a.length).toFixed(2):'-')+' asc='+asc(a,60)});
      S({m:'█PLAIN_B64='+Java.use('android.util.Base64').encodeToString(Java.array('byte',full),2)+''});
      return true;
    }
    S({m:'·'+tag+' status='+st+(data?' len='+Java.cast(data,Java.use('[B')).length:' data=null')+(msg?' msg='+String(msg).slice(0,20):'')});
    return false;
  }catch(e){S({m:tag+' 读结果异常 '+String(e).slice(0,60)});return false;}
}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  if(!P.payload_b64){S({m:'无 payload'});return;}
  var book=P.book+'', cid=P.cid+'';
  var d=Java.use('android.util.Base64').decode(P.payload_b64,2);
  var b64=Java.use('android.util.Base64').encodeToString(d,2)+'';
  var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FU=FUc.INSTANCE.value;
  S({m:'v28 矩阵开跑 payload='+d.length+'B b64='+b64.length});

  // 引擎内建钥匙 (v27 getter 实测值; 重新现取防硬编漂移)
  var K={};
  K.ibex='ibex'; K.cecelia='cecelia'; K.borgus='borgus'; K.cloud='01*&^%JKldm23876';
  K.audio='OkTpW1VKUVvNoEVUjMI+eROv9keoqR8bzEPAEly92Uk='; K.pre='a069a3419236265bd01436d410001bc1a918';
  K.cur=P.userKey; K.pair=book+'_'+cid; K.bk=P.batch_key; K.md5=P.md5; K.ver=''+P.Version;
  try{ K.d3des=''+FU.get3DesKey.call(FU);}catch(e){K.d3des=null;S({m:'3DesKey 取失败(它可能就是答案,在报错里)'});}
  try{ K.cloud2=''+FU.getCloudConfigKey.call(FU);}catch(e){}
  try{ K.audio2=''+FU.getAudioAesKey.call(FU);}catch(e){}
  try{ K.key2=''+FU.getKey.call(FU);}catch(e){}

  var hit=false, tried=0;
  // 主矩阵: unlock2(b64,k)
  var ks={};
  for(var kk in K) if(K[kk]) ks[kk]=K[kk];
  for(var kk in ks){
    if(hit)break;
    try{ hit=report('U2(b64,'+kk+')', FU.unlock.call(FU, b64, ks[kk])); }catch(e){S({m:'U2 '+kk+' 异常 '+String(e).slice(0,50)});}
    tried++;
  }
  S({m:'U2 轮完 hit='+hit+' tried='+tried});
  // 主矩阵: unlock4(b64, book, k, null)
  if(!hit)for(var kk in ks){
    if(hit)break;
    try{ hit=report('U4(b64,book,'+kk+')', FU.unlock.call(FU, b64, book, ks[kk], null)); }catch(e){}
    tried++;
  }
  S({m:'U4a 轮完 hit='+hit});
  // 主矩阵: unlock4(b64, k, pair, null)
  if(!hit)for(var kk in ks){
    if(hit)break;
    try{ hit=report('U4(b64,'+kk+',pair)', FU.unlock.call(FU, b64, ks[kk], book+'_'+cid, null)); }catch(e){}
  }
  S({m:'U4b 轮完 hit='+hit+' tried='+tried});
  // FockUtil 视角的 3DesKey 若拿到了, 用 Fock.uk 以它为 key
  if(!hit){
    var FK=Java.use('com.yuewen.fock.Fock');
    function bArr(jstr){var s=jstr.getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
    var UK=FK.uk.overload('[B','int','[B','int');
    for(var kk in ks){
      if(hit)break;
      try{ hit=report('UK|'+kk, UK.call(FK,d,d.length,bArr(ks[kk]),ks[kk].length)); }catch(e){S({m:'UK '+kk+' 异常 '+String(e).slice(0,40)});break;}
    }
  }
  S({m:'全矩阵完 hit='+hit});

  // ── 阻塞件挪最后: 后台线程里跑 add/requestKeySync, 完成后写标记文件 (下轮车若存在标记则先 unlock)
  try{
    var TH=Java.use('java.lang.Thread');
    var R=Java.use('java.lang.Runnable').$new(function(){
      try{ FU.add.call(FU, book, book+'_'+cid); }catch(e){}
      try{ var hm=Java.use('java.util.HashMap').$new(); hm.put(book+'', (P.batch_key||'')+''); FU.addMap.call(FU,hm); }catch(e){}
      try{ var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext(); FU.requestKeySync.call(FU, ctx, parseInt(book)); }catch(e){}
      try{ Java.use('java.io.File').$new('/data/local/tmp/v28_registered').createNewFile(); }catch(e){}
    });
    TH.$new(R).start();
    S({m:'后台注册线程已发 (add/addMap/rks 不再卡矩阵)'});
  }catch(e){S({m:'后台线程异常 '+String(e).slice(0,60)});}
  S({m:'v28 done'});
});
