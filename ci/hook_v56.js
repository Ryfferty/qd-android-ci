// hook_v56.js — v16: 只跑 .qd 正文解密矩阵 (payload/keys 全从 params 本地喂入, 无设备侧下载)
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);}catch(e){try{s=s.toString();}catch(e2){return '[bytes]';}}return s.length>n?s.slice(0,n)+'…':s;}
function hx(b,n){try{var x=new Uint8Array(b);var s='';var m=n;if(!m)m=x.length;for(var i=0;i<m;i=i+1){var v=x[i].toString(16);if(v.length<2)v='0'+v;s+=v;}return s;}catch(e){return 'ERR';}}
function asc(a,n){try{var s='';var m=n;if(!m)m=80;if(a.length<m)m=a.length;for(var i=0;i<m;i=i+1){var c=a[i]&255;if(c>=32&&c<127){s+=String.fromCharCode(c);}else{s+='.';}}return s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var fis=Java.use('java.io.FileInputStream').$new(f);var bos=Java.use('java.io.ByteArrayOutputStream').$new();var buf=Java.array('byte',new Array(8192).fill(0));var r;while((r=fis.read(buf))>0)bos.write(buf,0,r);fis.close();return Java.use('java.lang.String').$new(bos.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
var TAG='com.yuewen.fock.Fock';
Java.perform(function(){
  Java.choose('java.lang.ApplicationLoaders',{
    onMatch:function(al){
      try{ var cl=al.getClassLoader(Java.use('android.app.ActivityThread').currentApplication().getPackageName());
        if(cl){ Java.classFactory.loader=cl; } }catch(e){}
    },onComplete:function(){}
  });
  var FK;try{FK=Java.use(TAG);}catch(e){S({m:'✗ Fock: '+String(e).slice(0,100)});return;}
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  S({m:'=== v16 正文矩阵 start nP='+P.nP+' ==='});
  function hex2arr(h){var a=[];for(var i=0;i<h.length;i=i+2)a.push(parseInt(h.substr(i,2),16));return a;}
  function s2arr(s){var out=[];for(var i=0;i<s.length;i++){var c=s.charCodeAt(i);out.push(c&255);}return out;}
  var B64=Java.use('android.util.Base64');
  // payload: base64 → java byte[]
  var PAY=B64.decode(P.payload_b64,0);
  S({m:'① PAY len='+PAY.length+' head='+hx(PAY,16)});
  var bkraw=(P.batch_key||P.bk||'')+'';
  var book=(P.book||'1049120379')+'', cid=(P.cid||'903350205')+'';
  var K16=Java.array('byte',hex2arr(bkraw.replace(/-/g,'').slice(0,32)));
  var KF  =Java.array('byte',hex2arr(bkraw.replace(/-/g,'')));
  var MD5 =Java.array('byte',hex2arr(P.md5||''));
  var DK  =Java.array('byte',hex2arr(P.dk));
  var EMPTY=Java.array('byte',[]);
  var EMPTYS='';
  function dumpR(tag,r){
    if(r===null){S({m:tag+' → null'});return;}
    try{
      var st=r.status.value, d=r.data.value;
      if(d&&d.length>0){var arr=Array.from(d);
        var pr=arr.slice(0,200).filter(function(c){c=c&0xff;return (c>=32&&c<127)||c===9||c===10||c===13;}).length/Math.min(200,d.length);
        S({m:'★ '+tag+' status='+st+' len='+d.length+' print='+pr.toFixed(2)+' : '+asc(arr,100)});
        if(pr>0.85){
          var fpath='/data/user/0/com.qidian.QDReader/cache/body_plain.bin';
          try{var cdir=Java.use('android.app.ActivityThread').currentApplication().getCacheDir();fpath=cdir.getAbsolutePath().toString()+'/body_plain.bin';}catch(e0){}
          var fs=Java.use('java.io.FileOutputStream').$new(fpath);fs.write(d);fs.close();
          S({m:'████ 命中! 已存 '+fpath});
          // 同时直传前 2KB base64 (防 pull 不到)
          var part = d.length>2048 ? Java.array('byte', Array.from(d).slice(0,2048).map(function(c){return c>127?c-256:c;})) : d;
          S({m:'★PLAIN_B64='+Java.use('android.util.Base64').encodeToString(part,2)+''});
        }
      } else S({m:tag+' status='+st+' len=0'});
    }catch(e){S({m:tag+' 解析失败 '+String(e).slice(0,70)});}
  }
  // ② 安全优先: Fock.unlock 4参 String(b64) — App 正常路径, 不会崩
  function dumpR2(tag,r){
    if(r===null){S({m:tag+' → null'});return;}
    try{
      var st=r.status.value, d=r.data.value;
      if(d&&d.length>0){var arr=Array.from(d);
        var pr=arr.slice(0,200).filter(function(c){c=c&0xff;return (c>=32&&c<127)||c===9||c===10||c===13;}).length/Math.min(200,d.length);
        S({m:'★ '+tag+' status='+st+' len='+d.length+' print='+pr.toFixed(2)+' : '+asc(arr,100)});
        save(pr,d);
      } else S({m:tag+' status='+st+' len=0'});
    }catch(e){S({m:tag+' 解析失败 '+String(e).slice(0,70)});}
  }
  function save(pr,d){
    if(pr>0.85){
      var fpath='body_plain.bin';
      try{fpath=Java.use('android.app.ActivityThread').currentApplication().getCacheDir().getAbsolutePath().toString()+'/body_plain.bin';}catch(e0){}
      try{var fs=Java.use('java.io.FileOutputStream').$new(fpath);fs.write(d);fs.close();S({m:'████ 命中! 已存 '+fpath});}catch(e1){}
      var part = d.length>2048 ? Java.array('byte', Array.from(d).slice(0,2048).map(function(c){return c>127?c-256:c;})) : d;
      S({m:'★PLAIN_B64='+Java.use('android.util.Base64').encodeToString(part,2)+''});
    }
  }
  try{
    var b64str=B64.encodeToString(PAY,2)+'';
    var U4=FK.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
    var U3=FK.unlock.overload('java.lang.String','java.lang.String','java.lang.String');
    var pairs=[[book,book+'_'+cid],[cid,''],[book,''],[book+'_'+cid,''],['','']];
    for(var i4=0;i4<pairs.length;i4++){
      S({m:'~ pre F4p['+i4+']'});
      try{ dumpR2('F4p['+pairs[i4][0].slice(0,12)+'|'+pairs[i4][1].slice(0,12)+']', U4(b64str,pairs[i4][0],pairs[i4][1],null)); }catch(e){S({m:'F4p['+i4+'] err '+String(e).slice(0,60)});}
      if(U3){ S({m:'~ pre F3p['+i4+']'});
        try{ dumpR2('F3p['+pairs[i4][0].slice(0,12)+'|'+pairs[i4][1].slice(0,12)+']', U3(b64str,pairs[i4][0],pairs[i4][1])); }catch(e){S({m:'F3p['+i4+'] err '+String(e).slice(0,60)});}
      }
    }
  }catch(e){S({m:'② unlock String 重载: '+String(e).slice(0,90)});}
  // ③ 私有 native m67572uk([B I [B I) — 可能崩进程, 放最后, 预打 tag
  try{
    var UK=FK.m67572uk.overload('[B','int','[B','int');
    var named={'K16':K16,'Kfull':KF,'MD5':MD5,'dk':DK,'EMPTY':EMPTY};
    var seq=[];
    for(var kn in named){ for(var an in named){ if(!(an==='EMPTY'&&kn==='EMPTY'))seq.push([kn,an]); } }
    for(var q=0;q<seq.length;q++){
      var k=seq[q][0], a=seq[q][1];
      S({m:'~ pre uk['+k+'|'+a+'] '+q+'/'+seq.length});
      try{ dumpR2('uk['+k+'|'+a+']', UK(PAY,PAY.length,named[a],named[a].length)); }catch(e){S({m:'uk err '+String(e).slice(0,60)});}
    }
    S({m:'~ uk 全轮完成'});
  }catch(e){S({m:'③ uk 拿不到: '+String(e).slice(0,90)});}
  // ③ uksf([B I [B I [B)
  try{
    var UKSF=FK.uksf.overload('[B','int','[B','int','[B');
    var named2={'K16':K16,'MD5':MD5,'dk':DK,'Kfull':KF};
    for(var k2 in named2){
      try{ dumpR2('uksf[空|'+k2+']', UKSF(PAY,PAY.length,EMPTY,0,named2[k2])); }catch(e){}
      try{ dumpR2('uksf['+k2+'|空]', UKSF(PAY,PAY.length,named2[k2],named2[k2].length,EMPTY)); }catch(e){}
    }
  }catch(e){S({m:'③ uksf 拿不到: '+String(e).slice(0,90)});}
  // ⑤ FockUtil.unlock(String,String) 2参 (v10 签名表: 2参 String,String)
  try{
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
    var U2=FU.unlock.overload('java.lang.String','java.lang.String');
    try{ dumpR2('FU2[book]', U2(b64str,'1049120379')); }catch(e){S({m:'FU2 err '+String(e).slice(0,80)});}
  }catch(e){S({m:'⑤ FU2 '+String(e).slice(0,80)});}
  S({m:'=== v16 done ==='});
});