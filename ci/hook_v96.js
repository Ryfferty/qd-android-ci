// hook_v96.js — v56: ★身份修正实验组: setup(36全串)/setup(qimei16) × 原生uk 三态各跑 unlock(CT)
// v55判读: setup('5a271be5da434be') 把 uk 截成 15 字符(错格式!) → currentUserKey 正常态=36字符
// CT: 本地 a3264757074 会话拉的 fresh (同 Key 轮), 但 App 原生身份≠该 batch 身份 → 也试设备自拉 batch 拿真同轮 CT
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var CT='Ro7U5gdjpGA4RrdJ3JxFBUKO40NVTjdc0vfKiOmxMA20SGnD6/Kcg/hNOE0MV8e206wgzG6o4RkgB0Kiw/maay5bDhkR8jhnbMtEqalbEgr1b7lyPXutY1lYn87pB6PEVHbqxiASYptxsLxQYkQvsxVprapvF4+wuCzfei5Wu5db6pJ5Z1cHOvcOrEXBFHXDs2ilSO4T29/JvwiR3g+gZ3efy5pkoS91UcWQhanHu3kzap+uRTdLuAsV+8D6UbEl7syKsD0t7Ded1GkSEySPFO0Yv/TmfFnrzzeFzrqjYDyWsmLtVAFofseGh1ktePBRgoonbgMwdQtadt1X9zXX7NRwpf6qLf1fbYmQ26aC21oJ0kFD6/FkQ6MTsb9Ukldl05WZy+Cv/hc=';
  var KEYV='7422ea79-5d66-40ab-981f-95794ac95697-6ab6735f35a1881881704a20';
  var book='1040025277', cid='799920041';
  var A=Java.use('java.lang.String');
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  function fget(o,n){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===n){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  var U2=FU.unlock.overload('java.lang.String','java.lang.String');
  var RKS=FU.requestKeySync.overload('android.content.Context','long');
  function tryUnlock(tag){
    var pairs=[['cid',cid],['pair',book+'_'+cid]];
    for(var i=0;i<2;i++){
      try{ var r=U2.call(FU,A.$new(CT),A.$new(pairs[i][1])); var s=st(r); var dt=dataOf(r);
        S({m:tag+' U2('+pairs[i][0]+') st='+s+' dlen='+dt.length});
        if(s===0&&dt.length>4){ S({m:'█████ 命中!!'});
          var pb=Java.use('android.util.Base64').encodeToString(A.$new(dt).getBytes(),2)+'';
          for(var q=0;q<Math.min(6,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
          return true; }
        else if(dt!=='null'&&dt!=='err'&&dt.length>1) S({m:'   data='+dt.slice(0,110)});
      }catch(e){ S({m:tag+' EX '+String(e).slice(0,60)}); }
    }
    return false;
  }
  // A. 原生身份 (不动 setup)
  var uk0=''+Fock.currentUserKey();
  S({m:'A 原生 uk='+uk0+' len='+uk0.length});
  try{ S({m:'A rks '+RKS.call(FU,ctx,parseInt(cid))}); }catch(e){}
  if(tryUnlock('A')) return;
  // B. setup(全 36 串) = 本地 batch 请求那个身份串
  var FULL='5a271be5da434be';
  // 注: af.IMEI 就是 15 字符? 打印本地 params 里 userKey 供比对
  try{ Fock.setup(A.$new(FULL)); }catch(e){ S({m:'B setup 败'}); }
  S({m:'B uk→'+Fock.currentUserKey()});
  try{ RKS.call(FU,ctx,parseInt(cid)); }catch(e){}
  if(tryUnlock('B')) return;
  // C. setup(qimei16) —— App 自愈路径用 qimei
  try{ Fock.setup(A.$new('b3b295be58644158')); }catch(e){ S({m:'C setup 败'}); }
  S({m:'C uk→'+Fock.currentUserKey()});
  try{ RKS.call(FU,ctx,parseInt(cid)); }catch(e){}
  tryUnlock('C');
  // D. batch Key 直接注册进池再试 (add(key,value) 两态)
  var ADD=FU.add.overload('java.lang.String','java.lang.String');
  var dnames=[cid, book+'_'+cid, ''+cid];
  for(var di=0;di<2;di++){
    try{ ADD.call(FU,A.$new(dnames[di]),A.$new(KEYV)); S({m:'D add('+dnames[di]+',Key) OK'}); }catch(e){ S({m:'D add败 '+String(e).slice(0,60)}); break; }
  }
  try{ Fock.uksf ? null : null; }catch(e){}
  tryUnlock('D');
  // D2: rmdk 清掉重注册版 (unlock$addMap 形态)
  try{ var AM=Fock.addKeypool; if(AM){ AM.overload('java.lang.String','java.lang.String').call(null,A.$new(cid),A.$new(KEYV)); S({m:'D2 addKeypool OK'});} }catch(e){ S({m:'D2 败 '+String(e).slice(0,60)}); }
  tryUnlock('D2');
  S({m:'v56 END'});
});
})();
