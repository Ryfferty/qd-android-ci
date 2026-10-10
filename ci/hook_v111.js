// hook_v111.js — v71: ★池值格式假说: fockrt.files.xml 里池条目是 {"d":"…"} JSON 包装 → addKeypool 喂包装体而非裸K128
// v70: setup(IMEI)✓ uk=5a27…✓ addKeypool(VER,K128)✓ 但 -4 → 值格式错(数据层)
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln+'\n';r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT, K128=BD.K128, VER=''+BD.VER, imei=''+BD.imei;
  var B64=Java.use('android.util.Base64');
  var cidS='799920041', pair='1040025277|799920041', book='1040025277';
  var Fock=Java.use('com.yuewen.fock.Fock');
  function uk(){ try{ return ''+Fock.currentUserKey(); }catch(e){ return 'E'; } }
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0&&r.data){ var d=r.data; S({m:'█'+tag+' len='+d.length}); var b=''+B64.encodeToString(d,0); S({m:'█B64='+b.slice(0,900)}); } return st; }catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});return -9;} }
  // ① 真池文件全结构 (看 JSON 字段名)
  var pf=readText('/data/user/0/com.qidian.QDReader/shared_prefs/com.yuewen.fockrt.files.xml')||'';
  S({m:'◆filesxml len='+pf.length});
  // 提取 set 里第一个 string 完整 JSON (找 {"d": 开头)
  var m1=pf.match(/\{[^<]{20,}/);
  if(m1){ var j=m1[0].replace(/&quot;/g,'"').replace(/\\\\\//g,'/'); S({m:'◆池JSON头='+j.slice(0,120)});
    var kk=j.match(/"([a-zA-Z_]+)"\s*:/g); S({m:'◆池字段='+JSON.stringify((kk||[]).slice(0,8))}); }
  // ② setup 对齐身份
  try{ Fock.setup(imei); S({m:'◆uk='+uk().slice(0,40)}); }catch(e){S({m:'setup败 '+String(e).slice(0,60)});}
  // ③ addKeypool 包装形态全试
  var JO=Java.use('org.json.JSONObject');
  function tryPool(val,tag){
    try{ Fock.addKeypool(VER,val); var st=FR(Fock.unlock(CTs,cidS,pair,null),tag); if(st===0)return true; }
    catch(e){ S({m:tag+' 败 '+String(e).slice(0,70)}); }
    return false;
  }
  var done=false;
  if(!done) done=tryPool('{"d":"'+K128+'"}','P-d');
  if(!done){ try{ var o=JO.$new(); o.put('d',K128); done=tryPool(''+o.toString(),'P-d2'); }catch(e){} }
  if(!done){ try{ var o2=JO.$new(); o2.put('k',K128); done=tryPool(''+o2.toString(),'P-k'); }catch(e){} }
  if(!done){ try{ var o3=JO.$new(); o3.put('key',K128); done=tryPool(''+o3.toString(),'P-key'); }catch(e){} }
  if(!done){ try{ var o4=JO.$new(); o4.put('data',K128); o4.put('v',1); done=tryPool(''+o4.toString(),'P-data-v'); }catch(e){} }
  if(!done) done=tryPool('{"d":"'+K128+'","v":1}','P-dv');
  if(!done) done=tryPool('{"1":"'+K128+'"}','P-1');
  // ④ unlock data 形态对比: env 全文 (带包装)
  if(!done){ var env='{"code":0,"content":"'+CTs+'","type":1}';
    try{ FR(Fock.unlock(env,cidS,pair,null),'U-env'); }catch(e){} }
  // ⑤ 池文件里的 d 值直接抄出来喂 (引擎自己的池条目格式最权威)
  if(!done && m1){ try{
    var dval=(m1[0].replace(/&quot;/g,'"').match(/"d"\s*:\s*"([^"]{40,})"/)||[])[1];
    if(dval){ var unesc=dval.replace(/\\\//g,'/'); S({m:'◆真池d len='+unesc.length});
      done=tryPool(unesc,'P-reald'); if(!done) done=tryPool('{"d":"'+unesc+'"}','P-reald-w'); }
  }catch(e){S({m:'reald 败 '+String(e).slice(0,60)});} }
  S({m:'v71 出 done='+done});
});
})();
