// v83: 真机抓 NativeBinding.s()/d() 的返回值 = 明文 JS/结果，绕过 native 逆向
// 思路：设备运行时 XOR 表已填好，app 自己会调 s() 解密脚本；我们 pass-through 记录 return
(function(){ Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var FOS=Java.use('java.io.FileOutputStream'), File=Java.use('java.io.File');
  var DIR='/data/local/tmp/jsout'; var d=File.$new(DIR); if(!d.exists()) d.mkdirs();
  function save(name, text){ try{ var f=FOS.$new(File.$new(DIR,name)); var s=''+text; var arr=[]; for(var i=0;i<s.length&&i<200000;i++)arr.push(s.charCodeAt(i)&0xff); f.write(Java.array('byte',arr)); f.close(); S({m:'★SAVED '+name+' '+arr.length+'B'});}catch(e){S({m:'save败 '+String(e).slice(0,50)});} }
  function b64save(name, bytes){ try{ var V=Java.use('android.util.Base64'); var enc=''+V.encodeToString(bytes,2); save(name+'.b64', enc); }catch(e){} }
  var NB=Java.use('com.yuewen.fockrt.NativeBinding');
  var cls=NB.class, ms=cls.getDeclaredMethods();
  S({m:'NativeBinding 方法数='+ms.length});
  // 遍历 static native 方法，按名+参型包 hook
  for(var k=0;k<ms.length;k++){
    (function(mm){
      var name=mm.getName();
      var pt=mm.getParameterTypes(); var ret=mm.getReturnType().getName();
      var ptdesc=[]; for(var p=0;p<pt.length;p++) ptdesc.push(pt[p].getName());
      S({m:'NB方法 '+name+'('+ptdesc.join(',')+')→'+ret});
      try{
        NB[name].overloads.forEach(function(ov){
          ov.implementation=function(){
            var args=arguments, tag='NB.'+name;
            var arginfo=[]; for(var a=0;a<args.length;a++){ var x=args[a];
              if(x && x.length!==undefined && typeof x!=='string') arginfo.push('bytes['+x.length+']'); else arginfo.push(''+x);
            }
            S({m:'◆'+tag+' 入参: '+arginfo.join(' | ')});
            var r=ov.apply(this,args);
            if(r===null||r===undefined){ S({m:'◇'+tag+' 返回 null'}); }
            else if(typeof r==='string'){ S({m:'◇'+tag+' 返回String '+r.length+'B head='+r.substring(0,60)}); save(tag.replace(/\W/g,'_')+'_ret.txt', r); }
            else if(r.length!==undefined && typeof r!=='string'){ S({m:'◇'+tag+' 返回bytes '+r.length}); b64save(tag.replace(/\W/g,'_')+'_ret', r); }
            else { var rs=''+r; S({m:'◇'+tag+' 返回 '+rs.substring(0,80)}); }
            return r;
          };
        });
      }catch(e){ S({m:'hook '+name+'败 '+String(e).slice(0,40)}); }
    })(ms[k]);
  }
  // 主动触发：调 FockRT.eval / 打开文件管理，促使真机自己调 s()
  var FRT=Java.use('com.yuewen.fockrt.FockRT');
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  try{ FRT.setup(ctx, 'x', false); S({m:'FRT.setup 已调'});}catch(e){S({m:'setup败 '+String(e).slice(0,50)});}
  // 读 SP 看 cfg 现值
  try{ var sp=ctx.getSharedPreferences('com.yuewen.fockrt',0); var all=sp.getAll(); var it=all.entrySet().iterator(); while(it.hasNext()){var e2=it.next(); S({m:'SPfock '+e2.getKey()+'='+(''+e2.getValue()).substring(0,40)});} }catch(e){}
  S({m:'v83 就绪，等待/触发 s() 调用 90s'});
});
})();
