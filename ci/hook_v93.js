// hook_v93.js — v53: ★修正静态调用(overload()(args) 直调,v52的.call(null)是崩因) + 动态枚举签名 + fresh CT(同轮,本地外层公式已验)
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var CT='Ro7U5gdjpGA4RrdJ3JxFBUKO40NVTjdc0vfKiOmxMA20SGnD6/Kcg/hNOE0MV8e206wgzG6o4RkgB0Kiw/maay5bDhkR8jhnbMtEqalbEgr1b7lyPXutY1lYn87pB6PEVHbqxiASYptxsLxQYkQvsxVprapvF4+wuCzfei5Wu5db6pJ5Z1cHOvcOrEXBFHXDs2ilSO4T29/JvwiR3g+gZ3efy5pkoS91UcWQhanHu3kzap+uRTdLuAsV+8D6UbEl7syKsD0t7Ded1GkSEySPFO0Yv/TmfFnrzzeFzrqjYDyWsmLtVAFofseGh1ktePBRgoonbgMwdQtadt1X9zXX7NRwpf6qLf1fbYmQ26aC21oJ0kFD6/FkQ6MTsb9Ukldl05WZy+Cv/hc=';
  var book='1040025277', cid='799920041';
  var IMEI='5a271be5da434be';
  var A=Java.use('java.lang.String');
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  function fget(o,n){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===n){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  // ① 枚举关键方法真实重载表 (只报签名不猜)
  function enumOv(obj,name){try{var f=obj[name]; if(!f) return name+':无'; var ovs=f.overloads||null; if(ovs){return name+': '+ovs.map(function(x){return '('+x.argumentTypes.map(function(t){return t.className;}).join(',')+')→'+x.returnType.className;}).join(' | ');} }catch(e){return name+' 枚举败 '+String(e).slice(0,50);} return name+':?';}
  S({m:enumOv(Fock,'setup')});
  S({m:enumOv(FU,'requestKeySync')});
  S({m:enumOv(FU,'getKeyMap')});
  S({m:enumOv(FU,'add')});
  S({m:enumOv(FU,'unlock')});
  S({m:'v53 前 uk='+Fock.currentUserKey()});
  // ② setup(IMEI) 静态直调 (修正版)
  try{ Fock.setup.overload('java.lang.String')(IMEI); S({m:'setup(IMEI) OK → uk='+Fock.currentUserKey()}); }
  catch(e){ S({m:'setup 败 '+String(e).slice(0,110)}); }
  // ③ requestKeySync 注册 (按枚举出的第一个 String 重载调)
  try{
    var rks=FU.requestKeySync;
    var used='';
    if(rks.overload('android.content.Context','java.lang.String')){ rks.overload('android.content.Context','java.lang.String')(ctx, book+'_'+cid); used='(ctx,pair)'; }
    else if(rks.overload('java.lang.String')){ rks.overload('java.lang.String')(book+'_'+cid); used='(pair)'; }
    S({m:'rks 走 '+used});
  }catch(e){ S({m:'rks 败 '+String(e).slice(0,110)}); }
  // ④ keyMap dump
  try{
    var gm=FU.getKeyMap.overload('android.content.Context')(ctx);
    var it=gm.entrySet().iterator(); var got={}; var n=0;
    while(it.hasNext()){var e2=it.next(); var k=''+e2.getKey(); var v=''+e2.getValue();
      S({m:'◇['+k.slice(0,30)+'] len='+v.length+' = '+(v.length>130?v.slice(0,130)+'…':v)}); got[k]=v; n++;}
    S({m:'池 n='+n});
    // 池里新键试 unlock(CT, 键) / unlock(键值,...)
    for(var kk in got){
      try{ var r4=FU.unlock.overload('java.lang.String','java.lang.String')(CT,kk);
        if(st(r4)!==-5) S({m:'U2(CT,'+kk.slice(0,14)+') st='+st(r4)}); }catch(e3){}
    }
  }catch(e){ S({m:'dump败 '+String(e).slice(0,90)}); }
  // ⑤ unlock 矩阵 (setup 后身份应已一致)
  var seq=[
    ['U2(CT,cid)', function(){return FU.unlock.overload('java.lang.String','java.lang.String')(CT,cid);}],
    ['U2(CT,pair)', function(){return FU.unlock.overload('java.lang.String','java.lang.String')(CT,book+'_'+cid);}],
    ['U4(CT,cid,pair)', function(){return FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler')(CT,cid,book+'_'+cid,null);}]
  ];
  for(var i=0;i<seq.length;i++){
    try{ var r=seq[i][1](); var s=st(r); var dt=dataOf(r);
      S({m:'['+i+']'+seq[i][0]+' st='+s+' dlen='+dt.length});
      if(s===0&&dt.length>4){ S({m:'█████ 购章命中!!'});
        var pb=Java.use('android.util.Base64').encodeToString(A.$new(dt).getBytes(),2)+'';
        for(var q=0;q<Math.min(6,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
        break; }
      else if(dt!=='null'&&dt!=='err'&&dt.length>1) S({m:'   data='+dt.slice(0,110)});
    }catch(e){ S({m:'['+i+'] EX '+String(e).slice(0,70)}); }
  }
  S({m:'v53 END uk='+Fock.currentUserKey()});
});
})();
