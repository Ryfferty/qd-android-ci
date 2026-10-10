// hook_v69.js — v30: 修 v29 三 bug (bArr 用 v18c 版/getOverloads→overload/键池 getter 反射 invoke)
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
  S({m:'v30 开跑 payload='+d.length+'B'});

  // ⓪ 键池全 dump —— 反射 invoke (方法可能是 private/synthetic, 直 .call 不行)
  var mapKeys={};
  function reflCall(name,ctxNeeded){
    try{
      var mds=FU.getClass().getDeclaredMethods();
      for(var i=0;i<mds.length;i++){
        var m=mds[i];
        if(''+m.getName()!==name)continue;
        m.setAccessible(true);
        var pt=m.getParameterTypes();
        var args=[];
        for(var t=0;t<pt.length;t++){
          var tn=''+pt[t].getName();
          if(tn.indexOf('Context')>=0)args.push(ctx);
          else if(tn==='long')args.push(Java.use('java.lang.Long').$new(0));
          else if(tn==='int')args.push(0);
          else if(tn==='java.lang.String')args.push(null);
          else args.push(null);
        }
        var r=m.invoke.apply(m,[FU].concat(args));
        S({m:'◆'+name+'('+pt.length+'参) → '+(r===null?'null':(''+r).slice(0,80))});
        return r;
      }
      S({m:'◆'+name+' 方法不存在'});
    }catch(e){S({m:'◆'+name+' 反射异常 '+String(e).slice(0,90)});}
    return null;
  }
  function dumpMap(tag,m){
    try{
      if(m===null){S({m:tag+' null'});return;}
      var mm=Java.cast(m,Java.use('java.util.Map'));
      var en=mm.entrySet().iterator(); var n=0;
      while(en.hasNext()&&n<30){
        var e=Java.cast(en.next(),Java.use('java.util.Map$Entry'));
        var k=''+e.getKey(); var v=''+e.getValue();
        S({m:'◇'+tag+' ['+(k.length>24?k.slice(0,24)+'…':k)+'] = '+(v.length>70?v.slice(0,70)+'…':v)});
        mapKeys[k]=v; n++;
      }
      S({m:'◇'+tag+' 共 '+mm.size()+' 项'});
    }catch(e){S({m:tag+' dump 异常 '+String(e).slice(0,80)});}
  }
  var km1=reflCall('getKeyMap',true); if(km1)dumpMap('getKeyMap',km1);
  var km2=reflCall('loadLocalKey',true); if(km2&&km2!==km1)dumpMap('loadLocalKey',km2);
  reflCall('get3DesKey',false);
  reflCall('isHasKey',false);

  // ① map 键值矩阵 (String 面)
  var hit=false;
  for(var k in mapKeys){
    if(hit)break;
    var v=mapKeys[k];
    try{ hit=report('U2(b64,mapK)'+k.slice(0,14), FU.unlock.call(FU, b64, k)); }catch(e){}
    if(!hit){try{ hit=report('U2(b64,mapV)'+k.slice(0,14), FU.unlock.call(FU, b64, v)); }catch(e){}}
    if(!hit){try{ hit=report('U4(b64,K,V)'+k.slice(0,14), FU.unlock.call(FU, b64, k, v, null)); }catch(e){}}
    if(!hit){try{ hit=report('U4(b64,book,V)'+k.slice(0,14), FU.unlock.call(FU, b64, book, v, null)); }catch(e){}}
  }
  // ② uk byte[] 面 (v18c 成功形态: overload + .call(FK,...))
  var FK=Java.use('com.yuewen.fock.Fock');
  var UK=null;
  try{ UK=FK.uk.overload('[B','int','[B','int'); S({m:'② UK overload OK'}); }catch(e){S({m:'② overload 异常 '+String(e).slice(0,60)});}
  if(UK){
    var mats={'mapK-first':null};
    for(var k2 in mapKeys){ mats['mk='+k2.slice(0,10)]=k2; mats['mv='+k2.slice(0,10)]=mapKeys[k2]; }
    for(var mn in mats){
      if(hit)break; if(mn==='mapK-first')continue;
      try{ var kb=bArr(mats[mn]); hit=report('UK|'+mn, UK.call(FK,d,d.length,kb,kb.length)); }catch(e){S({m:'UK '+mn+' 异常 '+String(e).slice(0,50)});}
    }
  }
  S({m:'v30 done hit='+hit+' mapN='+Object.keys(mapKeys).length});
});
