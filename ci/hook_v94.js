// hook_v94.js — v54: 按 v53 真签名表修正一切:
//  ① setup 三连试 (静态 String 参: $new 包裹直调 / invoke(null,[..]) / 自动匹配)
//  ② requestKeySync(ctx, LONG) —— bookId 和 cid 各调一次 (这是章键申领口!)
//  ③ 实例方法全回 .call(FU,...) 姿势 (v50 已证可行)
//  ④ keyMap 申领前后对比 dump
//  ⑤ unlock 矩阵 (fresh CT 嵌入)
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
  S({m:'v54 前 uk='+Fock.currentUserKey()});
  // ① setup 三连
  var st_ok='';
  try{ Fock.setup.overload('java.lang.String')(A.$new(IMEI)); st_ok='ov+new'; }catch(e){ S({m:'s1 '+String(e).slice(0,70)}); }
  if(!st_ok){ try{ Fock.setup.overload('java.lang.String').invoke(null,[A.$new(IMEI)]); st_ok='invoke'; }catch(e){ S({m:'s2 '+String(e).slice(0,70)}); } }
  if(!st_ok){ try{ Fock.setup(A.$new(IMEI)); st_ok='auto'; }catch(e){ S({m:'s3 '+String(e).slice(0,70)}); } }
  if(!st_ok){ try{ Fock.setup.overload('android.content.Context','java.lang.String')(ctx,A.$new(IMEI)); st_ok='ctx+str'; }catch(e){ S({m:'s4 '+String(e).slice(0,70)}); } }
  S({m:'setup 走 '+st_ok+' → uk='+Fock.currentUserKey()});
  function dump(tag){
    try{
      var gm=FU.getKeyMap.overload('android.content.Context').call(FU,ctx);
      var it=gm.entrySet().iterator(); var n=0;
      while(it.hasNext()){var e2=it.next(); var k=''+e2.getKey(); var v=''+e2.getValue();
        S({m:'◇'+tag+' ['+k.slice(0,30)+'] len='+v.length+' = '+(v.length>130?v.slice(0,130)+'…':v)}); n++;}
      S({m:tag+' n='+n}); return gm;
    }catch(e){ S({m:tag+' 败 '+String(e).slice(0,70)}); return null; }
  }
  dump('申领前');
  // ② requestKeySync(ctx, long) ×2
  try{ var r1=FU.requestKeySync.overload('android.content.Context','long').call(FU,ctx,parseInt(cid)); S({m:'rks(cid) → '+r1}); }catch(e){ S({m:'rks1 败 '+String(e).slice(0,80)}); }
  try{ var r2=FU.requestKeySync.overload('android.content.Context','long').call(FU,ctx,parseInt(book)); S({m:'rks(book) → '+r2}); }catch(e){ S({m:'rks2 败 '+String(e).slice(0,80)}); }
  dump('申领后');
  // ③ unlock 矩阵 (call(FU) 姿势)
  var U2=FU.unlock.overload('java.lang.String','java.lang.String');
  var U4=FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
  var seq=[
    ['U2(CT,cid)', function(){return U2.call(FU,A.$new(CT),A.$new(cid));}],
    ['U2(CT,pair)', function(){return U2.call(FU,A.$new(CT),A.$new(book+'_'+cid));}],
    ['U4(CT,cid,pair)', function(){return U4.call(FU,A.$new(CT),A.$new(cid),A.$new(book+'_'+cid),null);}],
    ['U4(CT,pair,book)', function(){return U4.call(FU,A.$new(CT),A.$new(book+'_'+cid),A.$new(book),null);}]
  ];
  for(var i=0;i<seq.length;i++){
    try{ var r=seq[i][1](); var s=st(r); var dt=dataOf(r);
      S({m:'['+i+']'+seq[i][0]+' st='+s+' dlen='+dt.length});
      if(s===0&&dt.length>4){ S({m:'█████ 购章正文命中!!'});
        var pb=Java.use('android.util.Base64').encodeToString(A.$new(dt).getBytes(),2)+'';
        for(var q=0;q<Math.min(6,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
        break; }
      else if(dt!=='null'&&dt!=='err'&&dt.length>1) S({m:'   data='+dt.slice(0,110)});
    }catch(e){ S({m:'['+i+'] EX '+String(e).slice(0,70)}); }
  }
  S({m:'v54 END uk='+Fock.currentUserKey()});
});
})();
