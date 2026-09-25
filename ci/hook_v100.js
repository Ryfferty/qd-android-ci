// hook_v100.js — v60: ★新攻击面: getEncrypt(str1,str2)/lock(s)/restoreShufflingText(s,long,long) 三 native 全形态
// + add 异常打全栈(native 帧暴露 base64 解码位置) + unlock data 三形态(CT/env全文/qd整段b64)
// 素材: v60_bundle.json = 同轮 K128+VER+batchKey+CT (getkey/batch/下载全一轮拉齐)
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb='',ln;while((ln=r.readLine())!==null){sb+=ln;}r.close();return sb;}catch(e){return null;}}
  var B=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CT=B.CT, K128=B.K128, BK=B.batchKey, VER=B.VER;
  var book=B.book, cid=B.cid, imei=B.imei;
  var A=Java.use('java.lang.String');
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var B64=Java.use('android.util.Base64');
  var LOG=Java.use('android.util.Log');
  function fget(o,n){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===n){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  function hit(r,tag){try{var s=st(r);var dt=dataOf(r);S({m:tag+' st='+s+' dlen='+dt.length});
    if(s===0&&dt.length>4){S({m:'█████ 命中!!'});
      var pb=B64.encodeToString(A.$new(dt).getBytes(),2)+'';
      for(var q=0;q<Math.min(8,Math.ceil(pb.length/4800));q++)S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
      return true;}
    if(dt!=='null'&&dt!=='err'&&dt.length>1)S({m:'   d='+dt.slice(0,120)});
    return false;}catch(e){S({m:tag+' EX '+String(e).slice(0,70)});return false;}}
  var envJson='{"code":0,"content":"'+CT+'","type":1}';
  try{ Fock.setup(A.$new(imei)); S({m:'v60 uk='+Fock.currentUserKey()}); }catch(e){ S({m:'setup败'}); }
  try{ FU.requestKeySync.overload('android.content.Context','long').call(FU,ctx,parseInt(cid)); S({m:'rks ok'}); }catch(e){}
  var pair=book+'_'+cid;
  // ① getEncrypt 双形态 (假说: 内层再解密口)
  var ges=[['(null,CT)',function(){return FU.getEncrypt(null,CT);}],['(CT,null)',function(){return FU.getEncrypt(CT,null);}],
    ['(null,env)',function(){return FU.getEncrypt(null,envJson);}],['(CT,pair)',function(){return FU.getEncrypt(CT,pair);}]];
  for(var gi=0;gi<ges.length;gi++){
    try{ var v=ges[gi][1](); S({m:'◆getEncrypt'+ges[gi][0]+' = '+((''+v).length>60?(''+v).slice(0,60)+'…(len'+(''+v).length+')':''+v)}); }
    catch(e){ S({m:'◆getEncrypt'+ges[gi][0]+' 败 '+String(e).slice(0,60)}); }
  }
  // ② lock(CT) — 若 lock=加扰对函数, 解出的东西即正文
  try{ var lv=''+FU.lock(CT); S({m:'◆lock = '+(lv.length>80?lv.slice(0,80)+'…(len'+lv.length+')':lv)}); }
  catch(e){ S({m:'◆lock 败 '+String(e).slice(0,60)}); }
  // ③ restoreShufflingText(s, long, long) — (text, bookId, cid)?
  var rs=FU.restoreShufflingText.overload('java.lang.String','long','long');
  var rsc=[[CT,book,cid],[CT,cid,book],[envJson,book,cid]];
  for(var ri=0;ri<rsc.length;ri++){
    try{ var rv=rs.call(FU,A.$new(rsc[ri][0]),parseInt(rsc[ri][1]),parseInt(rsc[ri][2]));
      S({m:'◆rst['+ri+'] = '+(''+rv).slice(0,100)}); }catch(e){ S({m:'◆rst['+ri+'] 败 '+String(e).slice(0,60)}); }
  }
  // ④ add 全栈定位 (native 帧暴露解码器)
  function addProbe(tag,n,v){
    try{ FU.add.overload('java.lang.String','java.lang.String').call(FU,A.$new(n),A.$new(v)); S({m:'add('+tag+') OK'}); return true; }
    catch(e){ var tr=LOG.getStackTraceString(e); var lines=tr.split('\n').slice(0,12);
      S({m:'add('+tag+')栈: '+lines.map(function(x){return x.trim().replace('at ','');}).slice(0,9).join(' ← ')}); return false; }
  }
  var done=addProbe('cid|K128',cid,K128); if(done){ if(hit(FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(cid)),'postadd')) return; }
  addProbe('VER|K128',VER,K128);
  S({m:'v60 END'});
});
})();
