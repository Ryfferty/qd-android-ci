// hook_v44_matrix.js — v4 主动矩阵: 同一存活窗口内 setup(协议身份) → addKeys(协议同轮池子) → unlock 矩阵(协议同轮blob)
// 目标: 解 addKey 真值谜 + 拿到 ground-truth 明文; 同时对照 App 自己的池子值
// params 从 /data/local/tmp/params.json 读: {Key,Version,blob_b64,userKey,addks:[{a,b},...]}
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
var OUT=[];
function L(m){OUT.push(m);S({m:m});}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function wr(p,s){try{var f2=Java.use('java.io.FileOutputStream').$new(p,false);
 f2.write(Java.use('java.lang.String').$new(s).getBytes('UTF-8'));f2.close();}catch(e){}}
function dumpRes(r,label){
  if(!r){L(label+' -> null');return null;}
  try{
    var st=r.status.value, dt=r.data.value;
    var entry={label:label,status:st,len:dt?dt.length:0,text:null,diag:null};
    if(dt&&dt.length){
      var s2=Java.use('java.lang.String').$new(dt,'UTF-8')+'';
      var cn=0,pr=0;for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;if(c>=32&&c<127)pr++;}
      entry.text=s2.slice(0,400);entry.cn=cn;entry.print=(s2.length?pr/s2.length:0);
      L(label+' status='+st+' len='+dt.length+' cn='+cn+' print='+(entry.print.toFixed?entry.print.toFixed(2):entry.print));
      L('   text[:200]='+clip(s2,200));
    } else L(label+' status='+st+' data=null');
    OUT.push(entry);
    return entry;
  }catch(e){L(label+' 读字段失败 '+String(e).slice(0,110));return null;}
}
Java.perform(function(){
  L('=== v4 matrix start ===');
  var P={};try{P=JSON.parse(readText('/data/local/tmp/params.json')||'{}');}catch(e){L('params parse fail '+e);}
  var KEY=String(P.Key||''),VER=String(P.Version||''),BLOB=String(P.blob_b64||''),UK=String(P.userKey||'');
  var ADDKS=P.addks||[];
  L('KEY='+clip(KEY,24)+' VER='+VER+' BLOB.len='+BLOB.length+' UK='+UK+' addks#='+ADDKS.length);
  var FK=Java.use('com.yuewen.fock.Fock');
  var H=Java.use('com.yuewen.fock.Fock$ErrorLogHandler');

  // 捕获 handler (接口实现): 收 onError 诊断 JSON
  var CapCls=Java.registerClass({
    name:'com.example.Cap44H',
    implements:[H],
    methods:{ onError:function(j){
      var o={};
      try{var it=j.keys();while(it.hasNext()){var k=it.next()+'';o[k]=String(j.get(k)).slice(0,300);}}
      catch(e){o._raw=String(j).slice(0,600);}
      L('████ onError 诊断: '+JSON.stringify(o));
      OUT.push({diag:o});
    }}
  });

  // 基线状态
  try{L('baseline currentUserKey='+clip(FK.currentUserKey(),40));}catch(e){L('currentUserKey fail '+String(e).slice(0,80));}
  try{L('baseline addedKeyVersions='+clip(JSON.stringify(FK.addedKeyVersions()),120));}catch(e){}
  try{
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    try{L('App自有 getKey='+clip(inst.getKey(),40));}catch(e){L('getKey fail '+String(e).slice(0,80));}
    try{L('App自有 preUserKey='+clip(inst.getPreUserKey(),40));}catch(e){}
  }catch(e){L('FockUtil 不可用 '+String(e).slice(0,110));}

  // ① setup 协议身份
  try{FK.setup(UK);L('① setup(UK) OK currentUserKey='+clip(FK.currentUserKey(),40));}
  catch(e){L('① setup fail '+String(e).slice(0,120));}

  // ② addKeys 装载协议同轮池子 (3种签名轮试)
  var hnd=CapCls.$new();
  var loaded=false;
  try{ FK.addKeypool(KEY,VER); L('② addKeypool(2参) OK'); loaded=true; }
  catch(e){ L('② addKeypool fail '+String(e).slice(0,100)); }
  if(!loaded){ try{ FK.addKeys(KEY,VER,'',hnd); L('② addKeys(4参) OK'); loaded=true; }
  catch(e){ L('② addKeys4 fail '+String(e).slice(0,100)); } }
  if(!loaded){ try{ FK.addKeys(KEY,VER,''); L('② addKeys(3参) OK'); loaded=true; }
  catch(e){ L('② addKeys3 fail '+String(e).slice(0,100)); } }
  try{L('② after addedKeyVersions='+clip(JSON.stringify(FK.addedKeyVersions()),160));}catch(e){}

  // ③ unlock 矩阵 (4参主签名; 5参对照)
  var m4=null,m5=null;
  try{m4=FK.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');}catch(e){L('- m4: '+String(e).slice(0,80));}
  try{m5=FK.unlock.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');}catch(e){L('- m5: '+String(e).slice(0,80));}
  for(var i=0;i<ADDKS.length;i++){
    var a=String(ADDKS[i][0]||''), b=String(ADDKS[i][1]||'');
    L('--- ③['+i+'] add=(' +clip(a,26)+','+clip(b,34)+')');
    if(m4){ try{ dumpRes(m4.invoke? m4(BLOB,a,b,hnd): null, 'unlock4['+i+']'); }catch(e){ L('  m4 异常 '+String(e).slice(0,110)); } }
    else if(m5){ try{ dumpRes(m5(BLOB,a,b,'',hnd), 'unlock5['+i+']'); }catch(e){ L('  m5 异常 '+String(e).slice(0,110)); } }
  }
  // ④ FockUtil.unlock 3参对照 (cipher, str2, str3)
  try{
    var FU2=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var in2=FU2.INSTANCE.value;
    var mu=in2.unlock.overload('java.lang.String','java.lang.String','java.lang.String');
    for(var q2=0;q2<Math.min(ADDKS.length,4);q2++){
      try{ dumpRes(mu.call(in2,BLOB,String(ADDKS[q2][0]||''),String(ADDKS[q2][1]||'')),'FU3['+q2+']'); }
      catch(e){ L('FU3['+q2+'] 异常 '+String(e).slice(0,100)); }
    }
  }catch(e){L('- FU3: '+String(e).slice(0,100));}

  wr('/data/local/tmp/ORACLE4.txt',JSON.stringify(OUT,null,1));
  L('=== v4 done, ORACLE4.txt 已写 ===');
});
