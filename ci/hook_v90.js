// hook_v90.js — v50: ★已购章信封 content 字段喂 unlock(正解用法, 此前30轮数据全喂错)
// 数据: 书1040025277 章799920041 已购(a3264757074 账号); 外层3DES已本地解出 {code:0,content:CT,type:1}
// CT = 服务端发的内层密文 → App 正是把它喂 unlock → 期望 status=0 + 正文
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var CT='Ro7U5gdjpGA4RrdJ3JxFBUKO40NVTjdc0vfKiOmxMA20SGnD6/Kcg/hNOE0MV8e206wgzG6o4RkgB0Kiw/maay5bDhkR8jhnbMtEqalbEgr1b7lyPXutY1lYn87pB6PEVHbqxiASYptxsLxQYkQvsxVprapvF4+wuCzfei5Wu5db6pJ5Z1cHOvcOrEXBFHXDs2ilSO4T29/JvwiR3g+gZ3efy5pkoS91UcWQhanHu3kzap+uRTdLuAsV+8D6UbEl7syKsD0t7Ded1GkSEySPFO0Yv/TmfFnrzzeFzrqjYDyWsmLtVAFofseGh1ktePBRgoonbgMwdQtadt1X9zXX7NRwpf6qLf1fbYmQ26aC21oJ0kFD6/FkQ6MTsb9Ukldl05WZy+Cv/hc=';
  var book='1040025277', cid='799920041';
  var A=Java.use('java.lang.String'), B64=Java.use('android.util.Base64');
  function fget(o,name){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===name){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');return d?(''+A.$new(d)):'null';}catch(e){return 'err';}}
  var FK=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var uk=FK.currentUserKey();
  S({m:'v50 开跑 uk='+uk});
  var pair=book+'_'+cid;
  var tries=[
    ['U2(CT,cid)', function(){ return FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(cid)); }],
    ['U2(CT,pair)', function(){ return FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(pair)); }],
    ['U4(CT,cid,pair)', function(){ return FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler').call(FU,A.$new(CT),A.$new(cid),A.$new(pair),null); }],
    ['U4(CT,pair,cid)', function(){ return FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler').call(FU,A.$new(CT),A.$new(pair),A.$new(cid),null); }],
    ['FK.unl4(CT,cid,pair)', function(){ return FK.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler').call(FK?null:FK,A.$new(CT),A.$new(cid),A.$new(pair),null); }],
    ['FK.unl5(CT,cid,pair,ver)', function(){ return FK.unlock.overload('java.lang.String','java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler').call(null,A.$new(CT),A.$new(cid),A.$new(pair),A.$new('1639985422'),null); }],
    ['U2(b64(CT),cid)', function(){ var b=B64.encodeToString(A.$new(CT).getBytes(),2)+''; return FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(b),A.$new(cid)); }]
  ];
  for(var i=0;i<tries.length;i++){
    try{
      var r=tries[i][1]();
      if(r===null||r===undefined){ S({m:'['+i+']'+tries[i][0]+' → null'}); continue; }
      var s=st(r), dt=dataOf(r);
      S({m:'['+i+']'+tries[i][0]+' status='+s+' len='+dt.length+(s===0?'  ██████命中!!':'')});
      if(s===0&&dt.length>4){
        S({m:'PLAIN_HEAD='+dt.slice(0,120)});
        // 全量回传 (分片)
        var pb=B64.encodeToString(A.$new(dt).getBytes(),2)+'';
        for(var q=0;q<Math.min(6,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
        break;
      } else if(dt.length>2&&dt.length<200){ S({m:'  data预览='+dt.slice(0,140)}); }
    }catch(e){ S({m:'['+i+']'+tries[i][0]+' EX '+String(e).slice(0,90)}); }
  }
  S({m:'v50 END'});
});
})();
