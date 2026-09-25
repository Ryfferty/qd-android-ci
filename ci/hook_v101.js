// hook_v101.js — v61: ★add/addKeys 双参必b64(v60栈证) → 全矩阵: name=b64(cid/pair), value=K128系; Fock.addKeys 4参(bookId,cid,keyB64)形态直打; getEncrypt 反射调
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb='',ln;while((ln=r.readLine())!==null){sb+=ln;}r.close();return sb;}catch(e){return null;}}
  var B=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CT=B.CT, K128=B.K128, BK=B.batchKey, VER=B.VER;
  var book=B.book, cid=B.cid, imei=B.imei;
  var A=Java.use('java.lang.String');
  var Fock=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var B64=Java.use('android.util.Base64');
  var LOG=Java.use('android.util.Log');
  function fget(o,n){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===n){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  function b64e(s){return B64.encodeToString(A.$new(s).getBytes(),2)+'';}
  var pair=book+'_'+cid;
  try{ Fock.setup(A.$new(imei)); S({m:'v61 uk='+Fock.currentUserKey()}); }catch(e){}
  try{ FU.requestKeySync.overload('android.content.Context','long').call(FU,ctx,parseInt(cid)); }catch(e){}
  function probe(tag){
    try{ var r=FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(cid)); var s=st(r);
      var r2=FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(pair)); var s2=st(r2);
      S({m:tag+' → U2(cid) st='+s+' | U2(pair) st='+s2});
      var best=(s===0)?r:(s2===0?r2:null);
      if(best){ var dt=dataOf(best); S({m:'█████ 命中!! dlen='+dt.length});
        var pb=B64.encodeToString(A.$new(dt).getBytes(),2)+'';
        for(var q=0;q<Math.min(8,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
        return true; }
      return false;
    }catch(e){ S({m:tag+' probeEX '+String(e).slice(0,60)}); return false; }
  }
  // ① getEncrypt 反射 (直调报 not a function → 从声明方法里 invoke)
  try{
    var ms=FU.getClass().getDeclaredMethods(); var names=[];
    for(var i=0;i<ms.length;i++){ var mn=''+ms[i].getName(); if(/Encrypt|addKey|Key|lock|shuffle/i.test(mn)) names.push(mn+'('+ms[i].getParameterTypes().length+')'); }
    S({m:'◆方法表: '+names.slice(0,20).join(', ')});
  }catch(e){ S({m:'枚举败 '+String(e).slice(0,50)}); }
  try{
    var m2=FU.getClass().getDeclaredMethod('getEncrypt', Java.use('java.lang.String').class, Java.use('java.lang.String').class);
    m2.setAccessible(true);
    var gv=''+m2.invoke(FU, null, A.$new(CT)); S({m:'◆getEncrypt(null,CT)='+ (gv.length>70?gv.slice(0,70)+'…':gv)});
  }catch(e){ S({m:'◆getEncrypt 反射败 '+String(e).slice(0,80)}); }
  // ② Fock.addKeys 4参 (String,String,String,handler) 形态直打
  var AK4=null;
  try{ AK4=Fock.addKeys.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler'); }catch(e){ S({m:'无AK4 '+String(e).slice(0,50)}); }
  var ak4s=[
    ['book|cid|K128', [book,cid,K128]],
    ['cid|book|K128', [cid,book,K128]],
    ['book|cid|K24', [book,cid,K128.slice(0,24)]],
    ['pair||K128', [pair,'',K128]],
    ['book|cid|CT', [book,cid,CT]]
  ];
  if(AK4){ for(var ai=0;ai<ak4s.length;ai++){
    try{ AK4.call(null,A.$new(ak4s[ai][1][0]),A.$new(ak4s[ai][1][1]),A.$new(ak4s[ai][1][2]),null); S({m:'AK4('+ak4s[ai][0]+') OK'}); if(probe('AK4:'+ak4s[ai][0])) return; }
    catch(e){ S({m:'AK4('+ak4s[ai][0]+') 败 '+String(e).slice(0,60)}); }
  } }
  // ③ FU.add 双 b64 矩阵
  var ADD=FU.add.overload('java.lang.String','java.lang.String');
  var vals=[['K128',K128],['K128_24',K128.slice(0,24)],['K128_40',K128.slice(0,40)],['CT',CT],['b64BK',b64e(BK)],['b64BK48',b64e(BK.slice(0,48))]];
  var names=[['b64cid',b64e(cid)],['b64pair',b64e(pair)],['b64VER',b64e(VER)]];
  outer: for(var ni=0;ni<names.length;ni++){
    for(var vi=0;vi<vals.length;vi++){
      try{ ADD.call(FU,A.$new(names[ni][1]),A.$new(vals[vi][1])); S({m:'add('+names[ni][0]+'|'+vals[vi][0]+') OK'});
        if(probe('add:'+names[ni][0]+'|'+vals[vi][0])) return; break; }
      catch(e){ var tr=LOG.getStackTraceString(e).split('\n').slice(0,6).join('←').replace(/at /g,'');
        S({m:'add('+names[ni][0]+'|'+vals[vi][0]+') 败 '+tr.slice(0,140)}); }
      if(/bad base-64/.test(''+e)) continue; // 值非法, 换值
    }
  }
  S({m:'v61 END'});
});
})();
