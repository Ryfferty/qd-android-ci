// hook_v70.js — v31: 键池 dump 用 overload('android.content.Context') 正确拿法 → map 键值全喂 U2/U4/UK
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function fget(obj,name){try{var f=obj.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(obj);}catch(e){return null;}}
function jint(v){if(v===null||v===undefined)return null;try{return v.intValue();}catch(e){try{return parseInt(''+v,10);}catch(e2){return null;}}}
function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||60);i++){var c=a[i]&255;s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
function bArr(jstr){var s=Java.use('java.lang.String').$new(''+jstr).getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
function report(tag,r){
  if(r===null||r===undefined){S({m:tag+' → null'});return false;}
  try{
    var st=jint(fget(r,'status')); if(st===null)st=jint(fget(r,'errCode'));
    var data=fget(r,'data'); var msg=''+(fget(r,'message')||'');
    if(st===0&&data){
      var jb=Java.cast(data,Java.use('[B'));
      var a=[];for(var i=0;i<Math.min(jb.length,80);i++)a.push(jb[i]&255);
      var pr=0;for(var i=0;i<a.length;i++){if(a[i]>=32&&a[i]<127)pr++;}
      var full=[];for(var i=0;i<Math.min(jb.length,6000);i++)full.push(jb[i]);
      S({m:'███命中!! '+tag+' status=0 len='+jb.length+' print='+(a.length?(pr/a.length).toFixed(2):'-')+' asc='+asc(a,60)});
      S({m:'█PLAIN_B64='+Java.use('android.util.Base64').encodeToString(Java.array('byte',full),2)+''});
      return true;
    }
    S({m:'·'+tag+' status='+st+(msg?' msg='+String(msg).slice(0,24):'')});
    return false;
  }catch(e){S({m:tag+' 读异常 '+String(e).slice(0,60)});return false;}
}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  if(!P.payload_b64){S({m:'无 payload'});return;}
  var book=P.book+'', cid=P.cid+'';
  var d=Java.use('android.util.Base64').decode(P.payload_b64,2);
  var b64=Java.use('android.util.Base64').encodeToString(d,2)+'';
  var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FU=FUc.INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  S({m:'v31 开跑 payload='+d.length+'B'});

  // ⓪ 键池: overload 正确拿法
  var mapKeys={};
  function getMap(tag,ovtypes){
    try{
      var mm=FUc.getKeyMap; // static-ish? 用 FU 实例 overload
      var m=ovtypes==='load'? FU.loadLocalKey.overload('android.content.Context') : FU.getKeyMap.overload('android.content.Context');
      var r=m.call(FU, ctx);
      if(r===null){S({m:'◇'+tag+' → null'});return;}
      var mp=Java.cast(r,Java.use('java.util.Map'));
      var en=mp.entrySet().iterator(); var n=0;
      while(en.hasNext()&&n<30){
        var e=Java.cast(en.next(),Java.use('java.util.Map$Entry'));
        var k=''+e.getKey(); var v=''+e.getValue();
        S({m:'◇'+tag+' ['+(k.length>26?k.slice(0,26)+'…':k)+'] = '+(v.length>80?v.slice(0,80)+'…':v)});
        mapKeys[k]=v; n++;
      }
      S({m:'◇'+tag+' 共 '+mp.size()+' 项'});
    }catch(e){S({m:tag+' 异常 '+String(e).slice(0,90)});}
  }
  getMap('getKeyMap',0);
  getMap('loadLocalKey',1);
  try{ S({m:'◆isHasKey='+FU.isHasKey.overload().call(FU)});}catch(e){S({m:'isHasKey 异常 '+String(e).slice(0,60)});}

  // ① map 键值 × String 面矩阵
  var hit=false;
  for(var k in mapKeys){
    if(hit)break;
    var v=mapKeys[k];
    try{ hit=report('U2(b64,mapK)'+k.slice(0,12), FU.unlock.overload('java.lang.String','java.lang.String').call(FU, b64, k)); }catch(e){S({m:'U2K 异常 '+String(e).slice(0,50)});}
    if(!hit){try{ hit=report('U2(b64,mapV)'+k.slice(0,12), FU.unlock.overload('java.lang.String','java.lang.String').call(FU, b64, v)); }catch(e){}}
    if(!hit){try{ hit=report('U4(b64,K,V)'+k.slice(0,12), FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler').call(FU, b64, k, v, null)); }catch(e){}}
    if(!hit){try{ hit=report('U4(b64,book,V)'+k.slice(0,12), FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler').call(FU, b64, book, v, null)); }catch(e){}}
  }
  S({m:'① map矩阵完 hit='+hit+' N='+Object.keys(mapKeys).length});

  // ② byte[] 面: Fock.uk (v18c 成功形态)
  if(!hit){
    var FK=Java.use('com.yuewen.fock.Fock');
    try{
      var UK=FK.uk.overload('[B','int','[B','int');
      for(var k2 in mapKeys){
        if(hit)break;
        try{ var kb=bArr(k2); hit=report('UK|mapK '+k2.slice(0,12), UK.call(FK,d,d.length,kb,kb.length)); }catch(e){S({m:'UKk 异常 '+String(e).slice(0,40)});break;}
        if(!hit){try{ var vb=bArr(mapKeys[k2]); hit=report('UK|mapV '+k2.slice(0,12), UK.call(FK,d,d.length,vb,vb.length)); }catch(e){}}
      }
    }catch(e){S({m:'② UK 装配异常 '+String(e).slice(0,60)});}
  }
  // ③ resf/tsf byte[] 面 (v18c 材料 = map 值)
  if(!hit){
    var FK2=Java.use('com.yuewen.fock.Fock');
    function byteRet(tag,r){
      try{
        if(r===null){S({m:'·'+tag+' null'});return false;}
        var jb=Java.cast(r,Java.use('[B'));
        var a=[];for(var i=0;i<Math.min(jb.length,64);i++)a.push(jb[i]&255);
        var pr=0;for(var i=0;i<a.length;i++){if(a[i]>=32&&a[i]<127)pr++;}
        var same=(jb.length===d.length);
        var head=asc(a,32);
        S({m:(pr/(a.length||1)>0.8&&!same)?'★★'+tag:'·'+tag+' len='+jb.length+' print='+(pr/(a.length||1)).toFixed(2)+' head='+head+(same?' (透传)':'')});
        if(pr/(a.length||1)>0.8&&!same){var full=[];for(var i=0;i<Math.min(jb.length,6000);i++)full.push(jb[i]);S({m:'█RESF_B64='+Java.use('android.util.Base64').encodeToString(Java.array('byte',full),2)+''});return true;}
      }catch(e){S({m:tag+' 读异常 '+String(e).slice(0,50)});}
      return false;
    }
    try{
      var RESF=FK2.resf.overload('[B','int','[B');
      var TSF=FK2.tsf.overload('[B','int','[B');
      for(var k3 in mapKeys){
        if(hit)break;
        try{ var mb=bArr(mapKeys[k3]); hit=byteRet('resf|mapV '+k3.slice(0,12), RESF.call(FK2,d,d.length,mb)); }catch(e){S({m:'resf 异常 '+String(e).slice(0,40)});break;}
        if(!hit){try{ var nb=bArr(k3); hit=byteRet('tsf|mapK '+k3.slice(0,12), TSF.call(FK2,d,d.length,nb)); }catch(e){}}
      }
    }catch(e){S({m:'③ 装配异常 '+String(e).slice(0,60)});}
  }
  S({m:'v31 done hit='+hit});
});
