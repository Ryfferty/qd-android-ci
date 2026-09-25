// hook_v107.js — v67: ★dump 引擎持久化文件 + rks 真钥流 + unlock
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln+'\n';r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT;
  var cidS='799920041', pair='1040025277|799920041';
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FUinst=FU.INSTANCE.value;
  var DD='/data/user/0/com.qidian.QDReader';
  // ① dump fockrt 持久化 (键池/userKey 落盘)
  var p1=readText(DD+'/shared_prefs/com.yuewen.fockrt.xml');
  var p2=readText(DD+'/shared_prefs/com.yuewen.fockrt.files.xml');
  S({m:'◆fockrt.xml='+(p1||'null').slice(0,700)});
  S({m:'◆fockrt.files='+(p2||'null').slice(0,1400)});
  // ② 当前引擎 userKey
  var uk='';try{uk=''+Fock.getCurrentUserKey();}catch(e){uk='ERR';}
  S({m:'◆引擎 uk='+uk.slice(0,40)});
  // ③ rks book + rks cid 各 6s (让真实响应入池)
  try{
    var rksOv=FU.requestKeySync.overload('android.content.Context','long');
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var r1=rksOv.call(FUinst,ctx,parseInt(pair)); S({m:'◆rks(pair)='+r1});
    java.lang.Thread.sleep(6000);
    var r2=rksOv.call(FUinst,ctx,parseInt(cidS)); S({m:'◆rks(cid)='+r2});
    java.lang.Thread.sleep(6000);
  }catch(e){S({m:'rks 败 '+String(e).slice(0,90)});}
  // ④ 池再 dump (对比新增)
  var p3=readText(DD+'/shared_prefs/com.yuewen.fockrt.files.xml');
  S({m:'◆files_after='+(p3||'null').slice(0,1400)});
  try{ var km=FU.getKeyMap.overload('android.content.Context').call(FUinst,ctx);
    var e1=km.entrySet().iterator(); var n=0;
    while(e1.hasNext()&&n<12){ var en=e1.next(); var v=en.getValue();
      S({m:'◆池'+n+' k='+en.getKey()+' v.name='+(v.name?''+v.name:'?')+' v.key='+(''+v.key).slice(0,56)}); n++; }
    S({m:'◆池总 '+km.size()});
  }catch(e){S({m:'池败 '+String(e).slice(0,80)});}
  // ⑤ unlock 基线 + 全 CT 形态
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0){ var d=r.data; var t=''+Java.use('java.lang.String').$new(d); S({m:'█'+tag+' '+t.slice(0,150)}); } }catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});} }
  try{ FR(Fock.unlock(CTs,cidS,pair,null),'U(CT)'); }catch(e){S({m:'U 败 '+String(e).slice(0,70)});}
  try{ FR(Fock.unlock(CTs,pair,'1040025277',null),'U(CT)反序'); }catch(e){}
  // ⑥ loadLocalKey(ctx) 触发本地钥加载
  try{ var llk=FU.loadLocalKey; if(llk){ var lr=llk.overload?llk.overload('android.content.Context').call(FUinst,ctx):llk.call(FUinst,ctx); S({m:'◆loadLocalKey='+(''+lr).slice(0,60)}); } }catch(e){S({m:'llk 败 '+String(e).slice(0,80)});}
  try{ FR(Fock.unlock(CTs,cidS,pair,null),'U(CT)post-llk'); }catch(e){}
  S({m:'v67 出'});
});
})();
