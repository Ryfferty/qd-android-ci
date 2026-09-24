// hook_v68.js — v29: ★同步 dump getKeyMap/loadLocalKey 全键值 (isHasKey=true 的真键就在这) + map键喂unlock + uk重载修正
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function fget(obj,name){try{var f=obj.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(obj);}catch(e){return null;}}
function jint(v){if(v===null||v===undefined)return null;try{return v.intValue();}catch(e){try{return parseInt(''+v,10);}catch(e2){return null;}}}
function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||60);i++){var c=a[i]&255;s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
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
    S({m:'·'+tag+' status='+st+(msg?' msg='+msg.slice(0,24):'')});
    return false;
  }catch(e){S({m:tag+' 读异常 '+String(e).slice(0,60)});return false;}
}
function bArr(jstr){var s=Java.cast(jstr,Java.use('java.lang.String')).getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  if(!P.payload_b64){S({m:'无 payload'});return;}
  var book=P.book+'', cid=P.cid+'';
  var d=Java.use('android.util.Base64').decode(P.payload_b64,2);
  var b64=Java.use('android.util.Base64').encodeToString(d,2)+'';
  var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FU=FUc.INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  S({m:'v29 开跑 payload='+d.length+'B'});

  // ⓪ ★ 键池全 dump (真键就在这)
  var mapKeys={};
  function dumpMap(tag,m){
    try{
      if(m===null){S({m:tag+' → null'});return;}
      var en=m.entrySet().iterator(); var n=0;
      while(en.hasNext()&&n<30){
        var e=en.next(); var k=''+e.getKey(); var v=''+e.getValue();
        S({m:'◇'+tag+' ['+k+'] = '+(v.length>70?v.slice(0,70)+'…':v)});
        mapKeys[k]=v; n++;
      }
      S({m:'◇'+tag+' 共 '+m.size()+' 项'});
    }catch(e){S({m:tag+' dump 异常 '+String(e).slice(0,80)});}
  }
  try{ dumpMap('getKeyMap(ctx)', FU.getKeyMap.call(FU, ctx)); }catch(e){S({m:'getKeyMap 异常 '+String(e).slice(0,80)});}
  try{ dumpMap('loadLocalKey(ctx)', FU.loadLocalKey.call(FU, ctx)); }catch(e){S({m:'loadLocalKey 异常 '+String(e).slice(0,80)});}
  // 3DesKey 反射正确拿 (枚举方法找)
  try{
    var mds=FU.getClass().getDeclaredMethods();
    for(var i=0;i<mds.length;i++){
      if(''+mds[i].getName()=== 'get3DesKey'){ mds[i].setAccessible(true);
        try{ S({m:'◆3DesKey(refl)='+mds[i].call(FU)});}catch(e1){S({m:'3DesKey invoke 异常 '+String(e1).slice(0,70)});} }
    }
  }catch(e){}

  // ① map 键值双喂 unlock 矩阵
  var hit=false;
  for(var k in mapKeys){
    if(hit)break;
    var v=mapKeys[k];
    try{ hit=report('U2(b64,mapK) '+k.slice(0,18), FU.unlock.call(FU, b64, k)); }catch(e){}
    if(!hit){try{ hit=report('U2(b64,mapV) '+k.slice(0,18), FU.unlock.call(FU, b64, v)); }catch(e){}}
    if(!hit){try{ hit=report('U4(b64,mapK,mapV) '+k.slice(0,14), FU.unlock.call(FU, b64, k, v, null)); }catch(e){}}
    if(!hit){try{ hit=report('U4(b64,book,mapV) '+k.slice(0,14), FU.unlock.call(FU, b64, book, v, null)); }catch(e){}}
  }
  S({m:'① map矩阵完 hit='+hit});

  // ② uk 重载修正 + map键扫
  var FK=Java.use('com.yuewen.fock.Fock');
  try{
    var mUk=FK.class.getDeclaredMethods(); var sigs=[];
    for(var i=0;i<mUk.length;i++){ if(''+mUk[i].getName()==='uk'){ var ps=[]; for(var t=0;t<mUk[i].getParameterTypes().length;t++)ps.push(''+mUk[i].getParameterTypes()[t].getName()); sigs.push(ps.join(',')); } }
    S({m:'② Fock.uk 真实重载: '+sigs.join(' | ')});
  }catch(e){S({m:'②枚举uk异常 '+String(e).slice(0,60)});}
  try{
    var UK=null; var ov=FK.uk.getOverloads();
    for(var i=0;i<ov.length;i++){ if(ov[i].argumentTypes.length===4){UK=ov[i];S({m:'② 用重载 '+ov[i].signature});} }
    if(UK){
      function kB(jstr){var s=Java.cast(jstr,Java.use('java.lang.String')).getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
      for(var k in mapKeys){
        if(hit)break;
        try{ hit=report('UK|mapK '+k.slice(0,16), UK.call(FK,d,d.length,kB(k),kB(k).length)); }catch(e){}
        if(!hit){try{ hit=report('UK|mapV '+k.slice(0,16), UK.call(FK,d,d.length,kB(mapKeys[k]),kB(mapKeys[k]).length)); }catch(e){}}
      }
    }
  }catch(e){S({m:'② uk 矩阵异常 '+String(e).slice(0,70)});}
  S({m:'v29 done hit='+hit});
});
