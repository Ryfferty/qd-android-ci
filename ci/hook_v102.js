// hook_v102.js — v62: AK4 自动直调(v54姿势) + add 后台线程(v27雷) + loadLocalKey/encryptionMD5 侦察 + probe
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
  function fget(o,n){try{var fs=o.getClass().getDeclaredFields();for(var i=0;i<fs.length;i++){if((''+fs[i].getName())===n){fs[i].setAccessible(true);return fs[i].get(o);}}return undefined;}catch(e){return undefined;}}
  function st(r){return r?parseInt(''+fget(r,'status')):-999;}
  function dataOf(r){try{var d=fget(r,'data');if(d===null||d===undefined)return 'null';return ''+A.$new(d);}catch(e){return 'err';}}
  function b64e(s){return B64.encodeToString(A.$new(s).getBytes(),2)+'';}
  try{ Fock.setup(A.$new(imei)); }catch(e){}
  try{ FU.requestKeySync.overload('android.content.Context','long').call(FU,ctx,parseInt(cid)); }catch(e){}
  S({m:'v62 uk='+Fock.currentUserKey()});
  // ① 侦察: encryptionMD5(1) / loadLocalKey(1) / isHasKey
  try{ S({m:'◆isHasKey='+FU.isHasKey()}); }catch(e){ S({m:'isHasKey败'}); }
  try{ var em=''+FU.encryptionMD5(K128.slice(0,40)); S({m:'◆MD5(K128[:40]) = '+em}); }catch(e){ S({m:'◆MD5败 '+String(e).slice(0,50)}); }
  try{ var ll=FU.loadLocalKey.overload('android.content.Context').call(FU,ctx);
    if(ll){ var it=ll.entrySet().iterator(); var n=0;
      while(it.hasNext()&&n<8){var e2=it.next(); var k=''+e2.getKey(); var v=''+e2.getValue();
        S({m:'◆local ['+k.slice(0,28)+'] = '+(v.length>90?v.slice(0,90)+'…(len'+v.length+')':v)}); n++;}
      S({m:'◆localKey n='+n}); }
    else S({m:'◆localKey null'});
  }catch(e){ S({m:'◆loadLocalKey败 '+String(e).slice(0,60)}); }
  function probe(tag){
    try{ var s1=st(FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(cid)));
      var r2=FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(book+'_'+cid)); var s2=st(r2);
      S({m:tag+' → U2 st='+s1+'/'+s2});
      if(s2===0||s1===0){ var best=(s1===0)?FU.unlock.overload('java.lang.String','java.lang.String').call(FU,A.$new(CT),A.$new(cid)):r2;
        var dt=dataOf(best); S({m:'█████ 命中!! dlen='+dt.length});
        var pb=B64.encodeToString(A.$new(dt).getBytes(),2)+'';
        for(var q=0;q<Math.min(8,Math.ceil(pb.length/4800));q++) S({m:'P'+q+':'+pb.slice(q*4800,(q+1)*4800)});
        return true; }
      return false;
    }catch(e){ S({m:tag+' EX '+String(e).slice(0,60)}); return false; }
  }
  // ② Fock.addKeys 自动直调 (静态方法: Fock.addKeys(a,b,c,d) 自动匹配)
  var akq=[
    ['book,cid,K128', function(){ Fock.addKeys(book,cid,K128,null); }],
    ['book,cid,b64BK', function(){ Fock.addKeys(book,cid,b64e(BK),null); }],
    ['cid,book,K128', function(){ Fock.addKeys(cid,book,K128,null); }],
    ['VER,cid,K128', function(){ Fock.addKeys(VER,cid,K128,null); }]
  ];
  for(var ai=0;ai<akq.length;ai++){
    try{ akq[ai][1](); S({m:'AK4('+akq[ai][0]+') OK'}); if(probe('AK4:'+akq[ai][0])) return; }
    catch(e){ S({m:'AK4('+akq[ai][0]+') 败 '+String(e).slice(0,70)}); }
  }
  // ③ FU.add 后台线程 (name=b64(cid), value=K128) → 3s 后主线程 probe
  var RK=Java.registerClass({ name:'BgAdd$1', implements:[Java.use('java.lang.Runnable')],
    methods:{ run:function(){ try{ FU.add.overload('java.lang.String','java.lang.String').call(FU,A.$new(b64e(cid)),A.$new(K128)); }catch(e){} } } });
  try{ var th=Java.use('java.lang.Thread').$new(RK.$new()); th.start(); S({m:'BgAdd 已启动'}); }catch(e){ S({m:'BgAdd败 '+String(e).slice(0,60)}); }
  setTimeout(function(){
    try{ Java.perform(function(){
      if(probe('add3s')) return;
      // 仍未中 → 再后台 add (name=pair) 后 5s probe 终轮
      var RK2=Java.registerClass({ name:'BgAdd2$1', implements:[Java.use('java.lang.Runnable')],
        methods:{ run:function(){ try{ FU.add.overload('java.lang.String','java.lang.String').call(FU,A.$new(b64e(book+'_'+cid)),A.$new(K128)); }catch(e){} } } });
      try{ Java.use('java.lang.Thread').$new(RK2.$new()).start(); }catch(e){}
      setTimeout(function(){ try{ Java.perform(function(){ probe('add8s'); S({m:'v62 END'}); }); }catch(e){} }, 5000);
    }); }catch(e){ S({m:'T1败 '+String(e).slice(0,60)}); }
  }, 3000);
  S({m:'v62 主段出'});
});
})();
