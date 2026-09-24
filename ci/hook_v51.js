// hook_v51.js — v10: 同车三点闭环 — ①App池密文(从 tar dump 落地文件读) ②引擎 dk 现场 ③协议params
//   + 因果矩阵: addKeypool(App值,verX)→dk变? / addKeypool(协议值,verX)→dk变? 
//   目标: 拿 (uk, pool96cipher, dk) 三元组反推纯 Python dk 公式
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function hexAt(addr,n){try{var b=new Uint8Array(Memory.readByteArray(addr,n));var s='';for(var i=0;i<b.length;i++)s+=('0'+b[i].toString(16)).slice(-2);return s;}catch(e){return 'ERR';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
var DK=null;
Java.perform(function(){
  S({m:'=== v10 start ==='});
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var BLOB=String(P.blob_b64||''), PROTK=String(P.Key||'');
  var book='1049120379', cid='1049120379_903350205';
  var FK=Java.use('com.yuewen.fock.Fock');

  var fm=null; Process.enumerateModules().forEach(function(m){if(/libfock\.so$/.test(m.path))fm=m;});
  if(fm){
    Interceptor.attach(fm.base.add(0xc214),{onEnter:function(a){ DK=hexAt(a[3],32); S({m:'◆GCM dk32='+DK}); }});
    Interceptor.attach(fm.base.add(0xc098),{onEnter:function(a){ S({m:'◆DES key8='+hexAt(a[3],8)}); }});
  }
  function tu(tag){
    try{
      var B64=Java.use('android.util.Base64');
      var bb=B64.decode(BLOB,0); DK=null;
      var r=FK.unlockData(bb,book,cid,null);
      var st=r.status.value;
      S({m:'▲'+tag+' status='+st+' dk='+clip(DK,20)+' len='+(r.data.value?r.data.value.length:0)});
      if(st===0&&r.data.value){var t=Java.use('java.lang.String').$new(r.data.value,'UTF-8')+'';S({m:'★明文: '+clip(t,150)});}
      return DK;
    }catch(e){S({m:'×'+tag+' '+String(e).slice(0,110)});return null;}
  }
  S({m:'userKey='+clip(FK.currentUserKey(),40)});

  // ① App 池子原文: 多路径找 pref_fock_key*
  var APPK=null;
  var cands=['/data/data/com.qidian.QDReader/shared_prefs/pref_fock_key.xml',
             '/data/data/com.qidian.QDReader/shared_prefs/pref_fock_key',
             '/data/data/com.qidian.QDReader/files/pref_fock_key.xml',
             '/data/data/com.qidian.QDReader/files/mmkv/pref_fock_key'];
  for(var i=0;i<cands.length && !APPK;i++){
    var t=readText(cands[i]);
    if(t){ var m=t.match(/"(\d{6,})":"([A-Za-z0-9+\/=]{60,})"/);
      if(m){ APPK=m[2]; S({m:'◆池子['+cands[i].split('/').pop()+'] ver='+m[1]+' val='+clip(APPK,60)}); }
      else S({m:'◆'+cands[i]+' 内容(无匹配): '+clip(t,120)});
    }
  }
  if(!APPK){ // 目录列举兜底
    try{var sp=Java.use('java.io.File').$new('/data/data/com.qidian.QDReader/shared_prefs');
      var ls=sp.list();var arr=[];for(var j2=0;j2<ls.length;j2++)arr.push(String(ls[j2]));S({m:'shared_prefs: '+clip(arr.join(','),260)});}catch(e){}
  }

  // 基线
  var dk0=tu('baseline');

  // ② 因果A: 装 App 自存值到新版本号 (若 App 值已在 1639985422, 换新 ver 看 dk 是否"跟随池子内容")
  if(APPK){ try{ FK.addKeypool(APPK,'16399854220002'); S({m:'② addKeypool(App值,ver0002) vers='+clip(JSON.stringify(FK.addedKeyVersions()),140)}); }catch(e){S({m:'② fail '+String(e).slice(0,100)});} }
  var dkA=tu('after-AppPool');

  // ③ 因果B: 装协议值到同 ver0002 (覆盖) → dk 应回到协议材料?
  try{ FK.addKeypool(PROTK,'16399854220002'); S({m:'③ addKeypool(协议值,ver0002) vers='+clip(JSON.stringify(FK.addedKeyVersions()),140)});}catch(e){S({m:'③ fail '+String(e).slice(0,100)});}
  var dkB=tu('after-ProtoPool');
  S({m:'★★ 因果: base='+clip(dk0,16)+' App池='+clip(dkA,16)+' 协议池='+clip(dkB,16)+' | base==App? '+(dk0===dkA)+' 协议==base? '+(dk0===dkB)});
  S({m:'=== v10 done ==='});
});
