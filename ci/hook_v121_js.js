// hook_v121_js.js — 截获 fockrt 喂进 QuickJS 的全部 JS 载荷，落盘 /data/local/tmp/jsdump/
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var File=Java.use('java.io.File'), FIS=Java.use('java.io.FileInputStream'), FOS=Java.use('java.io.FileOutputStream');
  var DIR='/data/local/tmp/jsdump';
  var d=File.$new(DIR); if(!d.exists()) d.mkdirs();
  function b64(bytes){ var V=Java.use('android.util.Base64'); return ''+V.encodeToString(bytes,2); }
  function wr(name, text){ try{ var f=FOS.$new(File.$new(DIR,name)); var bs=Java.array('byte', Array.prototype.map.call((''+text).split(''),function(c){return c.charCodeAt(0)&0xff;})); f.write(bs); f.close(); S({m:'★SAVED '+name+' len='+(''+text).length}); }catch(e){ S({m:'save败 '+String(e).slice(0,40)}); } }
  var Q=Java.use('com.yuewen.fockrt.vm.QuickJS');
  // evaluate(J, String source, String name, I)
  Q.evaluate.overloads.forEach(function(ov){
    ov.implementation=function(){ var a=arguments;
      try{
        if(a.length>=3 && typeof a[1]==='string' && a[1].length>50){ S({m:'◆evaluate('+a[1].length+'B) name='+a[2]}); wr('eval_'+a[1].length+'_'+a[2].replace(/[^a-zA-Z0-9]/g,'_')+'.js', a[1]); }
      }catch(e){S({m:'e败'+String(e).slice(0,40)});}
      return ov.apply(this,a); };
  });
  // evaluate2(J, byte[] bArr, String, I, String, String) — 字节码/字节源
  Q.evaluate2.overloads.forEach(function(ov){
    ov.implementation=function(){ var a=arguments;
      try{ if(a[1]){ S({m:'◆evaluate2 bytes='+a[1].length}); wr('eval2_'+a[1].length+'.bin', b64(a[1])); } }catch(e){}
      return ov.apply(this,a); };
  });
  // loadScript 若存在
  try{ Q.loadScript.overloads.forEach(function(ov){ ov.implementation=function(){ var a=arguments;
      try{ if(typeof a[1]==='string') { S({m:'◆loadScript '+a[1].length+'B'}); wr('load_'+a[1].length+'.js', a[1]); } }catch(e){}
      return ov.apply(this,a); }; }); }catch(e){ S({m:'no loadScript'}); }
  // NativeBinding.d 入口也记录
  try{ var NB=Java.use('com.yuewen.fockrt.NativeBinding');
    NB.d.overloads.forEach(function(ov){ ov.implementation=function(){ var a=arguments;
      try{ if(a[0]) S({m:'◆NB.d inlen='+a[0].length}); }catch(e){}
      var r=ov.apply(this,a); return r; }; }); }catch(e){}
  // ★ 主动触发：直接调 FockRT.setup + eval 走一遍
  var F=Java.use('com.yuewen.fockrt.FockRT');
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  try{ F.setup(ctx,'probe',false); S({m:'◆FockRT.setup 完成'}); }catch(e){ S({m:'setup败 '+String(e).slice(0,60)}); }
  S({m:'v121 hook 就绪，静候 120s 采 JS'});
});
})();
// —— v121b: setup 后直读 libfock .bss 槽（设备内存里 JS 已执行过，槽应为真编码值）——
(function(){ Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function dumpSlots(tag){
    try{
      var m = Process.findModuleByName('libfock.so');
      if(!m){ S({m:'no libfock module'}); return; }
      var hex='';
      for(var off=0x1b000; off<0x1b040; off+=4){
        var w = Memory.readU32(m.base.add(off));
        hex += ('00000000'+w.toString(16)).slice(-8)+' ';
      }
      S({m:'★SLOTS['+tag+'] base='+m.base+' @1b000: '+hex});
      // 顺带解出 0x1b00c/0x1b010 的 target
      var s0c = Memory.readU32(m.base.add(0x1b00c));
      var s10 = Memory.readU32(m.base.add(0x1b010));
      var d0c = (s0c ^ m.base.add(0x1b00c).toUInt32? (s0c ^ (m.base.toUInt32()+0x1b00c)))>>>0;
      S({m:'★DEC 1b00c enc='+s0c.toString(16)+' dec=0x'+d0c.toString(16)});
    }catch(e){ S({m:'dump败 '+String(e).slice(0,60)}); }
  }
  var F=Java.use('com.yuewen.fock.Fock');
  var FR=Java.use('com.yuewen.fockrt.FockRT');
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  dumpSlots('before');
  try{ F.setup(ctx); }catch(e){ S({m:'F.setup(ctx)败'}); }
  try{ FR.setup(ctx,'probe',false); }catch(e){ S({m:'FR.setup败 '+String(e).slice(0,50)}); }
  Java.use('java.lang.Thread').sleep(4000);
  dumpSlots('after-setup');
  // 再试触发一次解锁评估（打开过书才有池，至少 setup 链走完）
  S({m:'v121b 完成，继续采 evaluate 60s'});
  setTimeout(function(){ dumpSlots('t+60s'); }, 60000);
}); })();
