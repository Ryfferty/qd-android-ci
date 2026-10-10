// hook_v99.js — v59: ① 静态自动直调 Fock.unlock 4/5参 (v54 setup(auto) 同款姿势) ② add 异常打全栈定位解码点 ③ get3DesKey 反射拿
// s4 假说: 5参 unlock 第4参 = 章钥槽 (batch Key)
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var CT='Ro7U5gdjpGA4RrdJ3JxFBUKO40NVTjdc0vfKiOmxMA20SGnD6/Kcg/hNOE0MV8e206wgzG6o4RkgB0Kiw/maay5bDhkR8jhnbMtEqalbEgr1b7lyPXutY1lYn87pB6PEVHbqxiASYptxsLxQYkQvsxVprapvF4+wuCzfei5Wu5db6pJ5Z1cHOvcOrEXBFHXDs2ilSO4T29/JvwiR3g+gZ3efy5pkoS91UcWQhanHu3kzap+uRTdLuAsV+8D6UbEl7syKsD0t7Ded1GkSEySPFO0Yv/TmfFnrzzeFzrqjYDyWsmLtVAFofseGh1ktePBRgoonbgMwdQtadt1X9zXX7NRwpf6qLf1fbYmQ26aC21oJ0kFD6/FkQ6MTsb9Ukldl05WZy+Cv/hc=';
  var KEYV='9f5e9bac-6ed1-4526-9fab-e1f63c0d1a09-6ab680a535a1881881710ce7';
  var book='1040025277', cid='799920041';
  var A=Java.use('java.lang.String');
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var B64=Java.use('android.util.Base64');
  var LOG=Java.use('android.util.Log');
  function fget(o,n){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===n){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  try{ Fock.setup(A.$new('5a271be5da434be')); }catch(e){}
  S({m:'v59 uk='+Fock.currentUserKey()});
  function hit(r,tag){ try{ var s=st(r); var dt=dataOf(r); S({m:tag+' st='+s+' dlen='+dt.length});
    if(s===0&&dt.length>4){ S({m:'█████ 命中!!'});
      var pb=B64.encodeToString(A.$new(dt).getBytes(),2)+'';
      for(var q=0;q<Math.min(6,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
      return true; }
    if(dt!=='null'&&dt!=='err'&&dt.length>1) S({m:'   d='+dt.slice(0,110)});
    return false; }catch(e){ S({m:tag+' EX '+String(e).slice(0,70)}); return false; } }
  // ① get3DesKey 反射 (private final native 可能藏在类层级)
  var G3='';
  try{
    var cls=FU.getClass();
    while(cls!==null && !G3){
      try{ var ms=cls.getDeclaredMethods();
        for(var mi=0;mi<ms.length;mi++){ var mn=''+ms[mi].getName();
          if(/3Des|desKey/i.test(mn)){ ms[mi].setAccessible(true);
            try{ G3=''+ms[mi].invoke(FU); S({m:'◆反射 '+mn+' = '+(G3.length>50?G3.slice(0,50)+'…':G3)}); }catch(e){ S({m:'◆'+mn+' invoke败 '+String(e).slice(0,50)}); }
            if(G3)break; } }
      }catch(e){}
      cls=cls.getSuperclass();
    }
    if(!G3) S({m:'◆无 3Des 方法'});
  }catch(e){ S({m:'反射扫败 '+String(e).slice(0,60)}); }
  // ② 静态自动直调: 5参 Fock.unlock(data,s2,s3,s4,handler=null)
  var hx=KEYV.replace(/-/g,'');
  var ub=[]; for(var i2=0;i2<hx.length;i2+=2)ub.push(parseInt(hx.substr(i2,2),16));
  var v_b64bin=B64.encodeToString(Java.array('byte',ub),2)+'';
  var s4s=[['raw',KEYV],['hex56',hx],['b64bin',v_b64bin],['tail24',KEYV.split('-')[5]]];
  if(G3)s4s.push(['g3',G3]);
  var pair=book+'_'+cid;
  var done=false;
  for(var ki=0;ki<s4s.length&&!done;ki++){
    try{ var r=Fock.unlock(CT,cid,pair,s4s[ki][1],null); done=hit(r,'U5auto('+s4s[ki][0]+')'); }
    catch(e){ S({m:'U5auto('+s4s[ki][0]+') EX '+String(e).slice(0,70)}); }
  }
  // ③ 4参静态版 (无 s4, 纯池键路径)
  if(!done){ try{ done=hit(Fock.unlock(CT,cid,pair,null),'U4auto'); }catch(e){ S({m:'U4auto EX '+String(e).slice(0,60)}); } }
  // ④ add 定位实验: 异常全栈 (放最后, 可能炸引擎)
  function addProbe(tag,n,v){
    try{ FU.add(n,v); S({m:'add('+tag+') OK'}); return true; }
    catch(e){ var tr=LOG.getStackTraceString(e);
      var frs=tr.split('\n'); var core=[];
      for(var fi=0;fi<frs.length&&core.length<6;fi++){ if(/fock|Base64|FockUtil|qidian|yuewen/i.test(frs[fi])) core.push(frs[fi].trim()); }
      S({m:'add('+tag+') 败 '+core.join(' ← ')}); return false; }
  }
  if(!done){
    addProbe('pair|hex56',pair,hx);
    addProbe('cid|hex56',cid,hx);
    addProbe('pair|b64bin',pair,v_b64bin);
    addProbe('uid|hex56','5a271be5da434be',hx);
  }
  S({m:'v59 END'});
});
})();
