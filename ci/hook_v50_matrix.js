// hook_v50_matrix.js — v9: 池子因果实验 + App 池子原文 dump + 双 dk 现场
//  ① DES/GCM hook 拿 dk (引擎现场)
//  ② App 池子原文: FockUtil.getKey() map + pref_fock_key 存储 dump
//  ③ addKeypool(协议Key, 新ver) 强制装载 → dk 变不变? (池子因验证)
//  ④ 每次装载后各试一次 unlockData(协议blob), 明文=终极判据
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function hexAt(addr,n){try{var b=new Uint8Array(Memory.readByteArray(addr,n));var s='';for(var i=0;i<b.length;i++)s+=('0'+b[i].toString(16)).slice(-2);return s;}catch(e){return 'ERR';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
var LAST_KEY32=null;
Java.perform(function(){
  S({m:'=== v9 start ==='});
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){}
  var BLOB=String(P.blob_b64||''), PROTK=String(P.Key||'');
  var book='1049120379', cid='1049120379_903350205';
  var FK=Java.use('com.yuewen.fock.Fock');

  var fm=null; Process.enumerateModules().forEach(function(m){if(/libfock\.so$/.test(m.path))fm=m;});
  if(fm){
    Interceptor.attach(fm.base.add(0xc214),{onEnter:function(a){
      LAST_KEY32=hexAt(a[3],32);
      S({m:'◆GCM dk32='+LAST_KEY32+' iv12='+hexAt(a[2],12)+' len='+a[1].toUInt32()});
    }});
    Interceptor.attach(fm.base.add(0xc098),{onEnter:function(a){
      S({m:'◆DES key8='+hexAt(a[3],8)+' in16='+hexAt(a[0],16)+' len='+a[1].toUInt32()});
    }});
    S({m:'+ DES/GCM hooks ok'});
  } else S({m:'✗ libfock 未找到'});

  function tryUnlock(tag){
    try{
      var B64=Java.use('android.util.Base64');
      var bb=B64.decode(BLOB,0);
      LAST_KEY32=null;
      var r=FK.unlockData(bb,book,cid,null);
      var st=r.status.value, dl=r.data.value?r.data.value.length:0;
      S({m:'▲unlockData['+tag+'] status='+st+' len='+dl+' dkhead='+(LAST_KEY32?LAST_KEY32.slice(0,16):'-')});
      if(st===0&&r.data.value){
        var t=Java.use('java.lang.String').$new(r.data.value,'UTF-8')+'';
        S({m:'★★★明文['+tag+']: '+clip(t,230)});
      }
      return LAST_KEY32;
    }catch(e){S({m:'×unlock['+tag+']: '+String(e).slice(0,120)});return null;}
  }

  S({m:'curUserKey='+clip(FK.currentUserKey(),40)+' versions='+clip(JSON.stringify(FK.addedKeyVersions()),60)});
  var dk0=tryUnlock('baseline');

  try{
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var m=inst.getKeyMap();
    var it=m.entrySet().iterator();
    while(it.hasNext()){var en=it.next();S({m:'◆KeyMap['+clip(String(en.getKey()),24)+']='+clip(String(en.getValue()),200)});}
  }catch(e){S({m:'- getKeyMap: '+String(e).slice(0,110)});}
  var t2=readText('/data/data/com.qidian.QDReader/shared_prefs/pref_fock_key.xml');
  if(t2)S({m:'◆pref_fock_key.xml: '+clip(t2,420)});
  var dk1=tryUnlock('after-mapread');

  try{ FK.addKeypool(PROTK,'16399854229991'); S({m:'③ addKeypool(协议Key,新ver) versions='+clip(JSON.stringify(FK.addedKeyVersions()),140)}); }
  catch(e){S({m:'③ fail '+String(e).slice(0,110)});}
  var dk2=tryUnlock('protocol-pool');
  S({m:'★因果: dk(0)='+(dk0||'-')+' dk(2)='+(dk2||'-')+' 相同?='+(dk0===dk2)});

  // 协议池 blob 若用新ver装不命中, 换"替换同ver"打法: 直接改 App 池子值再 reload
  try{
    var mm=null;
    if(t2){ var g=t2.match(/1639985422":"([^"]+)/); if(g)mm=g[1]; }
    if(mm){ FK.addKeypool(mm,'1639985422'); S({m:'④ App自存值 reload OK'}); tryUnlock('apppool-reload'); }
    else S({m:'④ 没抓到 App 自存池值'});
  }catch(e){S({m:'④ '+String(e).slice(0,110)});}
  S({m:'=== v9 done ==='});
});
