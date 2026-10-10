// hook_v98.js — v58: ★getter 拿真钥 + Fock 5参 unlock(带key槽) + add 只留最后一格(防雷)
// v57c教训: FU.add 抛 bad base-64 后引擎死 → 排最后
// v27遗留: get3DesKey() 取法 TypeError → 用直调(不 overload)+ 反射 invoke 双姿势
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var CT='Ro7U5gdjpGA4RrdJ3JxFBUKO40NVTjdc0vfKiOmxMA20SGnD6/Kcg/hNOE0MV8e206wgzG6o4RkgB0Kiw/maay5bDhkR8jhnbMtEqalbEgr1b7lyPXutY1lYn87pB6PEVHbqxiASYptxsLxQYkQvsxVprapvF4+wuCzfei5Wu5db6pJ5Z1cHOvcOrEXBFHXDs2ilSO4T29/JvwiR3g+gZ3efy5pkoS91UcWQhanHu3kzap+uRTdLuAsV+8D6UbEl7syKsD0t7Ded1GkSEySPFO0Yv/TmfFnrzzeFzrqjYDyWsmLtVAFofseGh1ktePBRgoonbgMwdQtadt1X9zXX7NRwpf6qLf1fbYmQ26aC21oJ0kFD6/FkQ6MTsb9Ukldl05WZy+Cv/hc=';
  var KEYV='834a531a-1eef-418b-8a2e-5c39601fce5e-6ab67ec735ec6d09ce9f7ca9';
  var book='1040025277', cid='799920041';
  var A=Java.use('java.lang.String');
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var B64=Java.use('android.util.Base64');
  function fget(o,n){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===n){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  try{ Fock.setup(A.$new('5a271be5da434be')); S({m:'setup→'+Fock.currentUserKey()}); }catch(e){ S({m:'setup败'}); }
  try{ FU.requestKeySync.overload('android.content.Context','long').call(FU,ctx,parseInt(cid)); }catch(e){}
  // ① getters (直调, 拿 3DES 真钥)
  var G3='';
  var gnames=['get3DesKey','getNibKey','getRtKey','getKey','getCloudConfigKey','getAudioAesKey','getPreUserKey'];
  for(var gi=0;gi<gnames.length;gi++){
    try{ var v=''+FU[gnames[gi]](); S({m:'◆'+gnames[gi]+' = '+(v.length>60?v.slice(0,60)+'…(len'+v.length+')':v)});
      if(gnames[gi]==='get3DesKey') G3=v;
    }catch(e){ S({m:'◆'+gnames[gi]+' 败 '+String(e).slice(0,50)}); }
  }
  // ② Fock 5参 unlock(data,s2,s3,s4,handler): s4=密钥槽假说 (KEYV 三形态 + G3)
  var k4s=[];
  k4s.push(['raw',KEYV]);
  k4s.push(['tail24',KEYV.split('-')[5]]);
  var hx=KEYV.replace(/-/g,'');
  var ub=[]; for(var i2=0;i2<hx.length;i2+=2)ub.push(parseInt(hx.substr(i2,2),16));
  k4s.push(['b64hex',B64.encodeToString(Java.array('byte',ub),2)+'']);
  if(G3.length>6) k4s.push(['g3',G3]);
  var U5=null;
  try{ U5=Fock.unlock.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler'); S({m:'5参在手'}); }
  catch(e){ S({m:'5参无 '+String(e).slice(0,60)}); }
  if(U5){
    for(var ki=0;ki<k4s.length;ki++){
      try{
        var r=U5.call(null,A.$new(CT),A.$new(cid),A.$new(book+'_'+cid),A.$new(k4s[ki][1]),null);
        var s=st(r); var dt=dataOf(r);
        S({m:'U5(k='+k4s[ki][0]+') st='+s+' dlen='+dt.length});
        if(s===0&&dt.length>4){ S({m:'█████ 命中!!'});
          var pb=B64.encodeToString(A.$new(dt).getBytes(),2)+'';
          for(var q=0;q<Math.min(6,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
          return; }
      }catch(e){ S({m:'U5('+k4s[ki][0]+') EX '+String(e).slice(0,60)}); }
    }
  }
  // ③ G3 直接当第二遍 key 本地不可行 → 喂 U2 键名槽 (cid→G3)
  if(G3.length>6){
    try{ var r2=FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(G3));
      S({m:'U2(CT,G3) st='+st(r2)}); if(st(r2)===0) S({m:'   d='+dataOf(r2).slice(0,100)}); }catch(e){}
  }
  // ④ 最后一格才 add (防炸): 最信形态 b64hex
  try{ FU.add.overload('java.lang.String','java.lang.String').call(FU,A.$new(cid),A.$new(k4s[2][1])); S({m:'add(b64hex) OK'});
    var r3=FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(cid));
    S({m:'add后 U2 st='+st(r3)+' dlen='+dataOf(r3).length});
    if(st(r3)===0) S({m:'   d='+dataOf(r3).slice(0,150)});
  }catch(e){ S({m:'add 败(预期末位) '+String(e).slice(0,60)}); }
  S({m:'v58 END'});
});
})();
