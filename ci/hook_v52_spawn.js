// hook_v52.js — v11: spawn 全程抓池子出生. 目标 = App 启动时装进引擎的 addKeypool/addKeys 原始入参
// 记录: 每次 addKeypool/addKeys/setup 的入参+返回+装载后 addedKeyVersions
//       以及 unlockData 命中时 GCM dk 现场 → 拿 (池子原文, dk) 同车对拍
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function hexAt(addr,n){try{var b=new Uint8Array(Memory.readByteArray(addr,n));var s='';for(var i=0;i<b.length;i++)s+=('0'+b[i].toString(16)).slice(-2);return s;}catch(e){return 'ERR';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
var DK=null, POOL_LOG=[];
Java.perform(function(){
  S({m:'=== v11 spawn start ==='});
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var BLOB=String(P.blob_b64||''), PROTK=String(P.Key||'');
  var book='1049120379', cid='1049120379_903350205';

  // native dk hook 尽早挂 (等 libfock 加载)
  function tryNative(){
    var fm=null; Process.enumerateModules().forEach(function(m){if(/libfock\.so$/.test(m.path))fm=m;});
    if(!fm) return false;
    try{
      Interceptor.attach(fm.base.add(0xc214),{onEnter:function(a){ DK=hexAt(a[3],32); }});
      Interceptor.attach(fm.base.add(0xc098),{onEnter:function(a){ S({m:'◆DES key8='+hexAt(a[3],8)}); }});
      S({m:'+ native dk hooks @'+fm.base});
      return true;
    }catch(e){S({m:'- native: '+String(e).slice(0,90)});return true;}
  }
  if(!tryNative()){
    var mtd=Module.findExportByName(null,'android_dlopen_ext')||Module.findExportByName(null,'dlopen');
    if(mtd) Interceptor.attach(mtd,{onLeave:function(){ if(tryNative()) Interceptor.detachAll&&0; }});
  }

  // 核心: Fock 池子装载入口全签名 hook (从进程出生就在线)
  function hookFock(){
    var FK; try{ FK=Java.use('com.yuewen.fock.Fock'); }catch(e){ return false; }
    ['addKeypool','addKeys','setup'].forEach(function(fn){
      try{
        FK[fn].overloads.forEach(function(o){
          var sig=o.argumentTypes.map(function(t){return t.className;});
          o.implementation=function(){
            var a=Array.prototype.slice.call(arguments);
            var strs=a.map(function(x){return typeof x==='object'&&x!==null&&x.toString?clip(String(x),200):String(x);});
            var r=o.apply(this,a);
            var vers=''; try{ vers=JSON.stringify(FK.addedKeyVersions()); }catch(e){}
            var rec={f:fn+'('+sig.join(',')+')', args:strs, ret:(r===undefined?'void':clip(String(r),60)), versions:vers, userKey:clip(safeCur(),40)};
            POOL_LOG.push(rec); S({m:'★★★ 装载: '+JSON.stringify(rec).slice(0,420)});
            return r;
          };
        });
        S({m:'+ hooked '+fn});
      }catch(e){S({m:'- '+fn+': '+String(e).slice(0,90)});}
    });
    tryNative();
    return true;
  }
  function safeCur(){try{return Java.use('com.yuewen.fock.Fock').currentUserKey();}catch(e){return '?';}}
  // Fock 类可能延迟加载(加固), 轮询直到挂上
  var tries=0;
  var iv=setInterval(function(){
    tries++;
    if(hookFock()||tries>40){ clearInterval(iv); S({m:'hook 轮询结束 tries='+tries}); }
  }, 250);

  // 深链/主动触发放在后面
  setTimeout(function(){
    try{
      var B64=Java.use('android.util.Base64');
      var bb=B64.decode(BLOB,0);
      var FK=Java.use('com.yuewen.fock.Fock');
      DK=null;
      var r=FK.unlockData(bb,book,cid,null);
      S({m:'▲协议blob unlockData status='+r.status.value+' dk='+clip(DK,24)+' len='+(r.data.value?r.data.value.length:0)});
      if(r.data.value){var t=Java.use('java.lang.String').$new(r.data.value,'UTF-8')+'';S({m:'★明文: '+clip(t,180)});}
    }catch(e){S({m:'触发: '+String(e).slice(0,120)});}
    S({m:'★池子装载全记录: '+JSON.stringify(POOL_LOG).slice(0,1200)});
    S({m:'userKey(终)='+clip(safeCur(),40)+' versions='+clip(JSON.stringify(Java.use('com.yuewen.fock.Fock').addedKeyVersions()),60)});
    S({m:'=== v11 done ==='});
  }, 45000);
});
