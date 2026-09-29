// v85: 纯枚举+被动捕获+轻量主动（禁 registerClass/d.loadClass）
(function(){ Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var FOS=Java.use('java.io.FileOutputStream'), File=Java.use('java.io.File');
  var DIR='/data/local/tmp/jsout'; var d=File.$new(DIR); if(!d.exists()) d.mkdirs();
  function save(name, s){ try{ var f=FOS.$new(File.$new(DIR,name)); var arr=[]; s=''+s; for(var i=0;i<s.length&&i<400000;i++)arr.push(s.charCodeAt(i)&0xff); f.write(Java.array('byte',arr)); f.close(); S({m:'★SAVED '+name+' '+arr.length+'B'});}catch(e){S({m:'save败 '+String(e).slice(0,60)});} }

  // ① 被动 hook：NB.s/d 返回值捕获（App 自调时抓明文）
  var NB=Java.use('com.yuewen.fockrt.NativeBinding');
  NB.s.overloads.forEach(function(ov){ ov.implementation=function(){
    var r=ov.apply(this,arguments);
    var arg0=arguments[0]?arguments[0].length:-1;
    S({m:'◆NB.s(自调) arg0='+arg0+'B arg1='+arguments[1]+' → '+(r===null?'null':(''+r).length+'B head='+(''+r).substring(0,50))});
    if(r && (''+r).length>50) save('sn_passive.js', r);
    return r;
  };});
  S({m:'NB.s 被动 hook 就绪'});

  // ② 枚举 FRT 运行时真方法名
  try{
    var dm = Java.use('com.yuewen.fockrt.FockRT').class.getDeclaredMethods();
    var ns=[]; for(var z=0;z<dm.length;z++){ var ps=dm[z].getParameterTypes(); var p1=ps.length?('('+ps[0].getSimpleName()+')'):''; ns.push(dm[z].getName()+p1+':'+dm[z].getReturnType().getSimpleName()); }
    S({m:'FRT方法: '+ns.join(' , ')});
  }catch(e){ S({m:'FRT枚举败 '+String(e).slice(0,60)}); }

  // ③ 枚举 fileManager 实例类方法
  try{
    var fm = Java.use('com.yuewen.fockrt.FockRT').fileManager.value;
    if(fm){ var fc=fm.getClass(); S({m:'fm类='+fc.getName()});
      var fm2=fc.getDeclaredMethods(); var g=[]; for(var y=0;y<fm2.length;y++){ g.push(fm2[y].getName()+':'+fm2[y].getReturnType().getSimpleName()); }
      S({m:'fm方法: '+g.join(' , ')});
    } else S({m:'fm=null'});
  }catch(e){ S({m:'fm枚举败 '+String(e).slice(0,60)}); }

  // ④ 枚举 QuickJS 类（evaluate 相关）与 enums 包真实名
  try{ var qj=Java.use('com.yuewen.fockrt.vm.QuickJS'); S({m:'QuickJS类存在'}); }catch(e){ S({m:'QuickJS类败 '+String(e).slice(0,40)}); }

  // ⑤ 轻量主动：setup + 调 sn 真名（枚举结果里挑 sn/含sn的短名；先试 m67574sn 再试 sn）
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  try{ Java.use('com.yuewen.fockrt.FockRT').setup(ctx,'qjsprobe',false); S({m:'★setup ok'});}catch(e){S({m:'setup败 '+String(e).slice(0,50)});}
  ['m67574sn','sn'].forEach(function(m){
    try{ var out=Java.use('com.yuewen.fockrt.FockRT')[m]('probe_ui'); S({m:'◆'+m+' → '+(out===null?'null':(''+out).length+'B:'+(''+out).substring(0,60))}); if(out&&(''+out).length>50)save('sn_'+m+'.js',out); }
    catch(e){ S({m:m+' 败 '+String(e).slice(0,60)}); }
  });
  S({m:'v85 完成'});
});
})();
