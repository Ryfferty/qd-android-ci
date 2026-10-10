// hook_v91.js — v51: setup(IMEI) 对齐引擎身份 → 解锁购章信封 unlock(CT,cid,pair)
// v50判读: 喂参已对(数据层过关), -5 是字面义——引擎键14351f12… ≠ batch加密键 af.IMEI
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var CT='Ro7U5gdjpGA4RrdJ3JxFBUKO40NVTjdc0vfKiOmxMA20SGnD6/Kcg/hNOE0MV8e206wgzG6o4RkgB0Kiw/maay5bDhkR8jhnbMtEqalbEgr1b7lyPXutY1lYn87pB6PEVHbqxiASYptxsLxQYkQvsxVprapvF4+wuCzfei5Wu5db6pJ5Z1cHOvcOrEXBFHXDs2ilSO4T29/JvwiR3g+gZ3efy5pkoS91UcWQhanHu3kzap+uRTdLuAsV+8D6UbEl7syKsD0t7Ded1GkSEySPFO0Yv/TmfFnrzzeFzrqjYDyWsmLtVAFofseGh1ktePBRgoonbgMwdQtadt1X9zXX7NRwpf6qLf1fbYmQ26aC21oJ0kFD6/FkQ6MTsb9Ukldl05WZy+Cv/hc=';
  var book='1040025277', cid='799920041';
  var IMEI='5a271be5da434be';  // af.IMEI (batch 请求用的设备身份)
  var BK=''; // batch Key 后补 (见 P_KEY 常量注入位)
  var A=Java.use('java.lang.String');
  var FK=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  function fget(o,name){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===name){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  S({m:'v51 前 uk='+FK.currentUserKey()});
  // ① setup 对齐
  try{
    FK.setup.overload('java.lang.String').call(null,A.$new(IMEI));
    S({m:'setup(IMEI) OK, 后 uk='+FK.currentUserKey()});
  }catch(e){ S({m:'setup(String) 败 '+String(e).slice(0,90)});
    try{
      var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
      FK.setup.overload('android.content.Context','java.lang.String').call(null,ctx,A.$new(IMEI));
      S({m:'setup(ctx,IMEI) OK, 后 uk='+FK.currentUserKey()});
    }catch(e2){ S({m:'setup(ctx) 也败 '+String(e2).slice(0,80)}); }
  }
  var pair=book+'_'+cid;
  var U2=FU.unlock.overload('java.lang.String','java.lang.String');
  var U4=FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
  // ② unlock 形态组
  var seq=[
    ['U2(CT,cid)', function(){return U2.call(FU,A.$new(CT),A.$new(cid));}],
    ['U2(CT,pair)', function(){return U2.call(FU,A.$new(CT),A.$new(pair));}],
    ['U4(CT,cid,pair)', function(){return U4.call(FU,A.$new(CT),A.$new(cid),A.$new(pair),null);}],
    ['U4(CT,pair,book)', function(){return U4.call(FU,A.$new(CT),A.$new(pair),A.$new(book),null);}]
  ];
  for(var i=0;i<seq.length;i++){
    try{
      var r=seq[i][1]();
      var s=st(r), dt=dataOf(r);
      S({m:'['+i+']'+seq[i][0]+' status='+s+' dlen='+dt.length});
      if(s===0&&dt.length>4){
        S({m:'██████ VIP正文命中!! head='+dt.slice(0,150)});
        var pb=Java.use('android.util.Base64').encodeToString(A.$new(dt).getBytes(),2)+'';
        for(var q=0;q<Math.min(8,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
        break;
      } else if(dt!=='null'&&dt!=='err'&&dt.length>1) S({m:'   data='+dt.slice(0,120)});
    }catch(e){ S({m:'['+i+'] EX '+String(e).slice(0,80)}); }
  }
  // ③ 若仍 -5: 用 batch Key 注册再试一次
  if(BK.length>4){
    try{
      var ctx2=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
      FU.add.overload('java.lang.String','java.lang.String').call(FU,A.$new(cid),A.$new(BK));
      var r2=seq[0][1]();
      S({m:'add后 U2 status='+st(r2)});
    }catch(e){S({m:'add 败 '+String(e).slice(0,70)});}
  }
  S({m:'v51 END'});
});
})();
