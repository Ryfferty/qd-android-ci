// hook_v97.js — v57: ★B态身份对齐(v56实锤 -4=身份已过) → batch Key 注册变体全矩阵
// v56: setup(af.IMEI)=CT同轮身份 → st=-4; add(cid,Key原文) 抛 bad base-64 → Key 需 b64 化注册
// Key=uuid(16B)+ts尾段(12B) 形态 → hex解码28B → b64 = 章钥本钥假说
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var CT='Ro7U5gdjpGA4RrdJ3JxFBUKO40NVTjdc0vfKiOmxMA20SGnD6/Kcg/hNOE0MV8e206wgzG6o4RkgB0Kiw/maay5bDhkR8jhnbMtEqalbEgr1b7lyPXutY1lYn87pB6PEVHbqxiASYptxsLxQYkQvsxVprapvF4+wuCzfei5Wu5db6pJ5Z1cHOvcOrEXBFHXDs2ilSO4T29/JvwiR3g+gZ3efy5pkoS91UcWQhanHu3kzap+uRTdLuAsV+8D6UbEl7syKsD0t7Ded1GkSEySPFO0Yv/TmfFnrzzeFzrqjYDyWsmLtVAFofseGh1ktePBRgoonbgMwdQtadt1X9zXX7NRwpf6qLf1fbYmQ26aC21oJ0kFD6/FkQ6MTsb9Ukldl05WZy+Cv/hc=';
  var KEYV='86550dad-8e8f-4795-baee-f563e00e227d-6ab6784835a1881881709023';
  var book='1040025277', cid='799920041';
  var A=Java.use('java.lang.String');
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  function fget(o,n){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===n){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  var U2=FU.unlock.overload('java.lang.String','java.lang.String');
  var ADD=FU.add.overload('java.lang.String','java.lang.String');
  var RKS=FU.requestKeySync.overload('android.content.Context','long');
  // Key 变体库
  var hx=KEYV.replace(/-/g,'');
  var rawB=[]; for(var i=0;i<hx.length;i+=2)rawB.push(parseInt(hx.substr(i,2),16));
  var raw=Java.array('byte',rawB);
  var B64=Java.use('android.util.Base64');
  var v_b64hex=B64.encodeToString(raw,2)+'';                 // 28B→38字符
  var v_b64hex_nopad=v_b64hex.replace(/=+$/,'');
  var v_d1=b64d(KEYV.replace(/-/g,''));                       // 若 hex 本身当 ASCII b64 解(小概率) 保底
  function b64d(s){try{return B64.decode(s,11);}catch(e){return null;}}
  function b64e(str){ return B64.encodeToString(A.$new(str).getBytes(),2)+''; }
  S({m:'v57 前 uk='+Fock.currentUserKey()});
  try{ Fock.setup(A.$new('5a271be5da434be')); }catch(e){S({m:'setup败'});}
  S({m:'setup→'+Fock.currentUserKey()+' KEYb64hex='+v_b64hex.slice(0,20)+'… len='+v_b64hex.length});
  try{ RKS.call(FU,ctx,parseInt(cid)); S({m:'rks true'}); }catch(e){}
  function probe(tag){
    var pairs=[[cid,'cid'],[book+'_'+cid,'pair']];
    for(var i=0;i<2;i++){
      try{ var r=U2.call(FU,A.$new(CT),A.$new(pairs[i][1])); var s=st(r); var dt=dataOf(r);
        S({m:tag+' → st='+s+' dlen='+dt.length});
        if(s===0&&dt.length>4){ S({m:'█████ 命中!! head='+dt.slice(0,120)});
          var pb=B64.encodeToString(A.$new(dt).getBytes(),2)+'';
          for(var q=0;q<Math.min(6,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
          return true; }
      }catch(e){ S({m:tag+' EX '+String(e).slice(0,50)}); }
    }
    return false;
  }
  // 注册变体矩阵
  var regs=[
    ['b64hex|cid', function(){ADD.call(FU,A.$new(cid),A.$new(v_b64hex));}],
    ['b64hex|pair', function(){ADD.call(FU,A.$new(book+'_'+cid),A.$new(v_b64hex));}],
    ['b64hex nopad|cid', function(){ADD.call(FU,A.$new(cid),A.$new(v_b64hex_nopad));}],
    ['rawkey|cid', function(){ADD.call(FU,A.$new(cid),A.$new(KEYV));}],
    ['b64(KeyASCII)|cid', function(){ADD.call(FU,A.$new(cid),A.$new(b64e(KEYV)));}],
    ['b64hex|ts尾24', function(){ADD.call(FU,A.$new(cid),A.$new(KEYV.split('-')[5]));}],
    ['uuid段|b64hex', function(){ADD.call(FU,A.$new(KEYV.slice(0,36)),A.$new(v_b64hex));}]
  ];
  for(var ri=0;ri<regs.length;ri++){
    try{ regs[ri][1](); S({m:'add('+regs[ri][0]+') OK'}); if(probe('reg'+ri)) break; }
    catch(e){ S({m:'add('+regs[ri][0]+') 败 '+String(e).slice(0,60)}); }
  }
  S({m:'v57 END'});
});
})();
