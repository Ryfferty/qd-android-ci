// hook_v106.js — v66: ★方案2: unlock(K128)=用引擎用户钥反解章钥 (lock实证用户钥可用→K128是它加密的章钥容器)
//           + 方案1侦察: 找 App 存用户会话的 SharedPreferences 文件 (注入购章身份用)
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var K128=BD.K128, CTs=BD.CT;
  var B64=Java.use('android.util.Base64');
  var Kbytes=B64.decode(K128,0);        // 96B
  var CTb=B64.decode(CTs,0);            // 296B
  S({m:'v66 K128='+Kbytes.length+'B CT='+CTb.length+'B'});
  var Fock=Java.use('com.yuewen.fock.Fock');
  var cidS='799920041', pair='1040025277|799920041', book='1040025277';
  function dump(r,tag){ try{ var st=r.status.value; var d=r.data; var n=d?d.length:-1;
    var hx=''; if(d&&st===0){for(var z=0;z<Math.min(64,n);z++){var v=d[z]&0xff;hx+=(v<16?'0':'')+v.toString(16);} }
    var as=''; if(d&&st===0){try{as=''+Java.use('java.lang.String').$new(d);}catch(e){}}
    S({m:'◆'+tag+' st='+st+' len='+n+(st===0?' hex='+hx.slice(0,64)+' ascii='+as.slice(0,40).replace(/[\r\n]/g,'.'):'')});
    return st===0;
  }catch(e){S({m:'◆'+tag+' 读败 '+String(e).slice(0,60)});return false;} }
  // ★ 核心: K128 反解 (String 版走 b64 自解码; byte[] 版直喂)
  try{ dump(Fock.unlock(K128,cidS,pair,null),'U(K128,cid,pair)'); }catch(e){S({m:'a败 '+String(e).slice(0,80)});}
  try{ dump(Fock.unlock(K128,pair,cidS,null),'U(K128,pair,cid)'); }catch(e){}
  try{ dump(Fock.unlock(K128,book,cidS,null),'U(K128,book,cid)'); }catch(e){}
  try{ dump(Fock.unlockData(Kbytes,cidS,pair,null),'UD(Kb,cid,pair)'); }catch(e){S({m:'b败 '+String(e).slice(0,80)});}
  try{ dump(Fock.unlockData(Kbytes,pair,book,null),'UD(Kb,pair,book)'); }catch(e){}
  // K128 反解出的 key 立刻用: 若上面任一 st=0 会打印, 这里再做 二段: 拿到 key 后 unlock(CTs) 
  // 对照: CT 正常喂 (基线 -4 复现)
  try{ dump(Fock.unlock(CTs,cidS,pair,null),'U(CT) 基线'); }catch(e){}
  // ★方案1侦察: App 数据目录里的 xml/db (购章会话注入点)
  try{
    var RU=Java.use('android.app.ActivityThread').currentApplication();
    var ctx=RU.getApplicationContext();
    var dd=''+ctx.getApplicationInfo().dataDir.value;
    S({m:'dataDir='+dd});
    var File=Java.use('java.io.File');
    function walk(path,depth){ if(depth>2)return; try{
      var f=File.$new(path); var ls=f.listFiles(); if(!ls)return;
      for(var i=0;i<ls.length&&i<40;i++){ var nm=''+ls[i].getName(); var full=path+'/'+nm;
        if(ls[i].isDirectory()){ S({m:'  D '+full.slice(dd.length)}); walk(full,depth+1); }
        else if(/\.(xml|db|sqlite|sharedpreferences|sp)$|pref|user|account|login/i.test(nm)){ S({m:'  F '+full.slice(dd.length)+' '+ls[i].length()+'B'}); }
      }}catch(e){} }
    walk(dd,0);
    // shared_prefs 里的当前用户键 (找到注入点)
    var spNames=['user','account','login','fock','reader','pref'];
    for(var si=0;si<spNames.length;si++){
      try{ var sp=ctx.getSharedPreferences(spNames[si],4); var all=sp.getAll(); var it=all.entrySet().iterator(); var cnt=0;
        while(it.hasNext()&&cnt<6){ var en=it.next(); var k=''+en.getKey(); var v=''+en.getValue();
          if(/key|user|uid|imei|qimei|token|sess/i.test(k)){ S({m:'◆SP['+spNames[si]+'] '+k+'='+v.slice(0,30)}); } cnt++; }
        if(all.size()>0) S({m:'◆SP '+spNames[si]+' 共'+all.size()+'键'});
      }catch(e){}
    }
  }catch(e){S({m:'侦察败 '+String(e).slice(0,90)});}
  S({m:'v66 出'});
});
})();
