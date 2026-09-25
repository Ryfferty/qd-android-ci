// hook_v92.js — v52: ★App 自愈序列复刻: setup(IMEI)(修正静态调用) → requestKeySync(按v51抓到的真URL形态) → keyMap dump → unlock(CT)
// v51 logcat 金矿: App 真身会 GET /argus/api/v2/userconfig/requestkey?userid=<引擎uk>&noncestr=<book_cid> → 服务端回章键
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var CT='Ro7U5gdjpGA4RrdJ3JxFBUKO40NVTjdc0vfKiOmxMA20SGnD6/Kcg/hNOE0MV8e206wgzG6o4RkgB0Kiw/maay5bDhkR8jhnbMtEqalbEgr1b7lyPXutY1lYn87pB6PEVHbqxiASYptxsLxQYkQvsxVprapvF4+wuCzfei5Wu5db6pJ5Z1cHOvcOrEXBFHXDs2ilSO4T29/JvwiR3g+gZ3efy5pkoS91UcWQhanHu3kzap+uRTdLuAsV+8D6UbEl7syKsD0t7Ded1GkSEySPFO0Yv/TmfFnrzzeFzrqjYDyWsmLtVAFofseGh1ktePBRgoonbgMwdQtadt1X9zXX7NRwpf6qLf1fbYmQ26aC21oJ0kFD6/FkQ6MTsb9Ukldl05WZy+Cv/hc=';
  var book='1040025277', cid='799920041';
  var IMEI='5a271be5da434be';           // batch 加密身份
  var A=Java.use('java.lang.String');
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  function fget(o,n){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===n){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  S({m:'v52 前 uk='+Fock.currentUserKey()});
  // ① setup(IMEI) —— 静态 native: overload.call(null,str) [v51教训: $new 是构造器]
  var ok1=false;
  try{ Fock.setup.overload('java.lang.String').call(null,A.$new(IMEI)); ok1=true; }catch(e){ S({m:'setup1败 '+String(e).slice(0,80)}); }
  if(!ok1){ try{ Fock.setup.overload('android.content.Context','java.lang.String').call(null,ctx,A.$new(IMEI)); ok1=true; S({m:'setup(ctx,IMEI) OK'});}catch(e2){S({m:'setup2败 '+String(e2).slice(0,80)});} }
  if(ok1) S({m:'setup(IMEI) OK → uk='+Fock.currentUserKey()});
  // ② requestKeySync 注册章键 (FockUtil 真签名反射兜底)
  var MK=Java.use('java.util.HashMap');
  var got={};
  function dumpMap(tag){
    try{
      var m=FU.getKeyMap.overload('android.content.Context').call(FU,ctx);
      var it=m.entrySet().iterator(); var n=0;
      while(it.hasNext()){ var e=it.next(); var k=''+e.getKey(); var v=''+e.getValue();
        S({m:'◇'+tag+' ['+k.slice(0,28)+'] len='+v.length+' = '+(v.length>120?v.slice(0,120)+'…':v)}); got[k]=v; n++; }
      S({m:tag+' 池 n='+n});
    }catch(e){S({m:tag+' dump败 '+String(e).slice(0,70)});}
  }
  dumpMap('注册前');
  var done=false;
  try{
    var RKS=FU.requestKeySync;
    // 枚举真签名逐个试 (v27 实证 FU.add 阻塞主线程 → requestKeySync 也危险: 放最后, 拿完就跑)
    var ovs=RKS.getOverloads ? null : null;
    var tried=[];
    var cands=[
      ['ctx+pair', function(){ return RKS.overload('android.content.Context','java.lang.String').call(FU,ctx,A.$new(book+'_'+cid)); }],
      ['pair', function(){ return RKS.overload('java.lang.String').call(FU,A.$new(book+'_'+cid)); }],
      ['book', function(){ return RKS.overload('java.lang.String').call(FU,A.$new(book)); }],
      ['pair+map', function(){ var mp=MK.$new(); return RKS.overload('java.lang.String','java.util.Map').call(FU,A.$new(book+'_'+cid),mp); }]
    ];
    for(var ci=0;ci<cands.length;ci++){
      try{ var rr=cands[ci][1](); S({m:'rks('+cands[ci][0]+') → '+(rr===undefined?'void':(''+rr).slice(0,60))}); tried.push(cands[ci][0]); }
      catch(e){ /* 无此重载 */ }
    }
    S({m:'rks 尝试: '+tried.join(',')});
  }catch(e){ S({m:'rks 外层败 '+String(e).slice(0,90)}); }
  dumpMap('注册后');
  // ③ unlock(CT) 矩阵 + 池内新键再试
  var U2=FU.unlock.overload('java.lang.String','java.lang.String');
  var seq=[
    ['U2(CT,cid)', function(){return U2.call(FU,A.$new(CT),A.$new(cid));}],
    ['U2(CT,pair)', function(){return U2.call(FU,A.$new(CT),A.$new(book+'_'+cid));}]
  ];
  for(var i=0;i<seq.length;i++){
    try{ var r=seq[i][1](); var s=st(r); var dt=dataOf(r);
      S({m:'['+i+']'+seq[i][0]+' st='+s+' dlen='+dt.length});
      if(s===0&&dt.length>4){ S({m:'█████ 购章正文命中!! '+dt.slice(0,120)}); done=true;
        var pb=Java.use('android.util.Base64').encodeToString(A.$new(dt).getBytes(),2)+'';
        for(var q=0;q<Math.min(6,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)}); break; }
      else if(dt!=='null'&&dt!=='err'&&dt.length>1) S({m:'   data='+dt.slice(0,100)});
    }catch(e){ S({m:'['+i+'] EX '+String(e).slice(0,60)}); }
  }
  if(!done){
    // 池里所有新增值再当 data/或 key 试一轮
    for(var k in got){
      if(k==='1639985422') continue;
      try{ var r3=U2.call(FU,A.$new(got[k].length>64?got[k]:CT),A.$new(k.length>64?CT:k));
        S({m:'池外键 '+k.slice(0,20)+' → st='+st(r3)}); }catch(e){}
    }
  }
  S({m:'v52 END'});
});
})();
