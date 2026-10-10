// hook_v95.js — v55: ★钩 okhttp 抓 requestKeySync 真实请求+响应(章键来源) + setup→rks→unlock 全链一台车
// v54: setup(auto)✓ rks→true ✓ unlock=-4(DATA_NOT_MATCH) → 缺"键响应"这块拼图
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
  var seen=[];
  // ① okhttp 旁观: Builder.url 记录每次请求 URL; Response body 抓含 key/content 的响应
  try{
    var B=Java.use('okhttp3.Request$Builder');
    var uOv=B.url.overload('java.lang.String');
    uOv.implementation=function(u){ try{ var s=''+u; if(/key|fock|content|cipher/i.test(s)) seen.push(s); }catch(e){} return uOv.call(this,u); };
    S({m:'钩Builder OK'});
  }catch(e){ S({m:'钩Builder 败 '+String(e).slice(0,80)}); }
  try{
    var RC=Java.use('okhttp3.internal.http.CallServerInterceptor');
    var interp=RC.intercept.overload('okhttp3.Interceptor$Chain');
    interp.implementation=function(chain){
      var resp=interp.call(this,chain);
      try{
        var url=''+chain.request().url();
        if(/key|fock|cipher/i.test(url)){
          S({m:'▷REQ '+url.slice(0,180)});
          S({m:'▷HDR '+JSON.stringify(chain.request().headers().toMultimap()).slice(0,300)});
          var body=resp.body();
          var clone=resp.peekBody ? resp.peekBody(2048) : null;
          if(clone) S({m:'▷RESP '+url.slice(0,80)+' → '+(''+clone.string()).slice(0,600)});
        }
      }catch(e2){ S({m:'RESP读败 '+String(e2).slice(0,60)}); }
      return resp;
    };
    S({m:'钩CallServer OK'});
  }catch(e){ S({m:'钩CallServer 败 '+String(e).slice(0,80)}); }
  // ② setup + rks 触发
  S({m:'v55 前 uk='+Fock.currentUserKey()});
  try{ Fock.setup(A.$new(IMEI)); S({m:'setup OK → uk='+Fock.currentUserKey()}); }catch(e){ S({m:'setup 败 '+String(e).slice(0,80)}); }
  try{ var r1=FU.requestKeySync.overload('android.content.Context','long').call(FU,ctx,parseInt(cid)); S({m:'rks(cid) '+r1}); }catch(e){ S({m:'rks1 败 '+String(e).slice(0,80)}); }
  S({m:'seen URL: '+(seen.join(' || ')||'(无)')});
  // ③ keyMap dump (三姿势轮试)
  function dump(tag){
    var gm=null;
    try{ gm=FU.getKeyMap.overload('android.content.Context').call(FU,ctx); }catch(e){ try{ gm=Java.cast(FU,Java.use('com.qidian.QDReader.component.util.FockUtil')).getKeyMap(ctx); }catch(e2){ S({m:tag+' 两姿势皆败'}); return; } }
    try{
      var it=gm.entrySet().iterator(); var n=0;
      while(it.hasNext()){var e2=it.next(); var k=''+e2.getKey(); var v=''+e2.getValue();
        S({m:'◇'+tag+' ['+k.slice(0,30)+'] len='+v.length+' = '+(v.length>150?v.slice(0,150)+'…':v)}); n++;}
      S({m:tag+' n='+n});
    }catch(e){ S({m:tag+' 迭代败 '+String(e).slice(0,70)}); }
  }
  dump('rks后');
  // ④ unlock 矩阵
  var U2=FU.unlock.overload('java.lang.String','java.lang.String');
  var seq=[
    ['U2(CT,cid)', function(){return U2.call(FU,A.$new(CT),A.$new(cid));}],
    ['U2(CT,pair)', function(){return U2.call(FU,A.$new(CT),A.$new(book+'_'+cid));}]
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
  S({m:'v55 END seen='+seen.length});
});
})();
