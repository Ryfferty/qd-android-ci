// hook_v45.js — v5: 不动 App 池子/userKey, 只用它的引擎解"同设备身份抓的 blob"
// handler 传 null (§9.39 实证法). 判据: status=0 且 data 可读 (URL 或正文都算破口)
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
var OUT=[];
function L(m){OUT.push(m);S({m:m});}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function wr(p,s){try{var f2=Java.use('java.io.FileOutputStream').$new(p,true);
 f2.write(Java.use('java.lang.String').$new(s).getBytes('UTF-8'));f2.close();}catch(e){}}
function dumpRes(r,label){
  if(!r){L(label+' -> null');return;}
  try{
    var st=r.status.value, dt=r.data.value;
    var e={label:label,status:st,len:dt?dt.length:0};
    if(dt&&dt.length){
      var s2=Java.use('java.lang.String').$new(dt,'UTF-8')+'';
      var cn=0,pr=0;for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;if(c>=32&&c<127)pr++;}
      e.cn=cn; e.head=s2.slice(0,240);
      L(label+' ★status='+st+' len='+dt.length+' cn='+cn+' print='+(pr/s2.length).toFixed(2));
      L('   text[:240]='+clip(s2,240));
      wr('/data/local/tmp/ORACLE5.txt', JSON.stringify(e)+'\n');
    } else L(label+' status='+st+' data=null');
    OUT.push(e);
  }catch(x){L(label+' 读字段失败 '+String(x).slice(0,110));}
}
Java.perform(function(){
  L('=== v5 start ===');
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){L('params fail '+e);}
  var BLOB=String(P.blob_b64||'');
  var ADDKS=P.addks||[];
  L('BLOB.len='+BLOB.length+' addks#='+ADDKS.length+' userKey(协议)='+clip(String(P.userKey||''),40));
  var FK=Java.use('com.yuewen.fock.Fock');
  // 现状只读
  try{L('App currentUserKey='+clip(FK.currentUserKey(),40));}catch(e){}
  try{L('App addedKeyVersions='+clip(JSON.stringify(FK.addedKeyVersions()),80));}catch(e){}
  // 可选: 若 params.forceKey 非空才装载我们的池(用假版本号避免撞车), 默认完全不碰
  if(P.forceKey){
    try{ FK.addKeypool(String(P.forceKey), String(P.forceVer||'9999999991')); L('forceKey addKeypool OK versions='+clip(JSON.stringify(FK.addedKeyVersions()),120)); }
    catch(e){ L('forceKey fail '+String(e).slice(0,100)); }
  }
  // 找可用 unlock 重载
  var overloads=FK.unlock.overloads, sigs=[];
  for(var i=0;i<overloads.length;i++) sigs.push(overloads[i].argumentTypes.map(function(t){return t.className;}).join(','));
  L('unlock sigs: '+sigs.join(' || '));
  function callFor(idx,a2,a3){
    var o=overloads[idx];
    var wantSig=o.argumentTypes.map(function(t){return t.className;});
    var args=[BLOB,String(a2||''),String(a3||'')];
    if(wantSig.length===4) args.push(null);                    // handler 可空 §9.39
    else if(wantSig.length===5) args.push('',null);            // 5参: 第4参猜测空
    try{ dumpRes(o.apply(null,args), 'unlock'+wantSig.length+'p['+idx+'|'+clip(String(a2),22)+','+clip(String(a3),30)+']'); }
    catch(ex){ L('  call fail '+String(ex).slice(0,130)); }
  }
  // 优先 4 参 (n0.search 实证签名); 没中则 5 参对照
  var i4=-1,i5=-1;
  for(var s2=0;s2<sigs.length;s2++){ if(sigs[s2].split(',').length===4&&sigs[s2].indexOf('ErrorLog')>=0) i4=s2; if(sigs[s2].split(',').length===5) i5=s2; }
  L('i4='+i4+' i5='+i5);
  for(var q=0;q<ADDKS.length;q++){
    L('--- add['+q+']='+JSON.stringify(ADDKS[q]));
    if(i4>=0) callFor(i4,ADDKS[q][0],ADDKS[q][1]);
    if(i5>=0) callFor(i5,ADDKS[q][0],ADDKS[q][1]);
  }
  // unlockData 字节路径 (handler null)
  try{
    var B64=Java.use('android.util.Base64');
    var bb=B64.decode(BLOB,0);
    var ovs=FK.unlockData.overloads;
    for(var u=0;u<ovs.length;u++){
      var npar=ovs[u].argumentTypes.length;
      for(var q2=0;q2<Math.min(ADDKS.length,4);q2++){
        var ar=[bb,String(ADDKS[q2][0]||''),String(ADDKS[q2][1]||'')];
        if(npar>=4) ar.push(null);
        try{ dumpRes(ovs[u].apply(FK,ar),'uD'+npar+'p['+q2+']'); }catch(ex){ L('uD'+npar+'['+q2+'] fail '+String(ex).slice(0,120)); }
      }
    }
  }catch(e){L('- unlockData: '+String(e).slice(0,100));}
  L('=== v5 done ===');
});
