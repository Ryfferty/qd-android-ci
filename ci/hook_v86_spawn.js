// v86: spawn 模式抓 Fock 全部 native 方法的输入/输出字节（含启动期 it() 的槽填充载荷）
(function(){ Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var FOS=Java.use('java.io.FileOutputStream'), File=Java.use('java.io.File');
  var B64=Java.use('android.util.Base64');
  var DIR='/data/local/tmp/jsout'; var d=File.$new(DIR); if(!d.exists()) d.mkdirs();
  function wtxt(name, text){ try{ var f=FOS.$new(File.$new(DIR,name)); var s=''+text; var arr=[]; for(var i=0;i<s.length&&i<800000;i++)arr.push(s.charCodeAt(i)&0xff); f.write(Java.array('byte',arr)); f.close(); S({m:'★W '+name+' '+arr.length+'B'});}catch(e){S({m:'W败 '+name+' '+String(e).slice(0,50)});} }
  function wb64(name, bytes){ try{ wtxt(name, ''+B64.encodeToString(bytes, 2)); }catch(e){} }

  var TARGETS=['it','ak','uk','av','sn','wnid','urk','lk','uksf','resf','rmdk','ets','ide','lock','sign','setup'];
  var Fock=Java.use('com.yuewen.fock.Fock');
  // 先枚举运行时真名
  try{ var dm=Fock.class.getDeclaredMethods(); var ns=[]; for(var z=0;z<dm.length;z++){ var ps=dm[z].getParameterTypes(); var pd=[]; for(var p=0;p<ps.length;p++)pd.push(ps[p].getSimpleName()); ns.push(dm[z].getName()+'('+pd.join(')(')+'):'+dm[z].getReturnType().getSimpleName()); } S({m:'Fock方法: '+ns.join(' , ')});}catch(e){S({m:'枚举败 '+String(e).slice(0,60)});}

  TARGETS.forEach(function(nm){
    try{
      Fock[nm].overloads.forEach(function(ov){
        ov.implementation=function(){
          var args=arguments, tag='Fock.'+nm;
          var info=[];
          for(var a=0;a<args.length;a++){ var x=args[a];
            if(x===null||x===undefined) info.push('null');
            else if(typeof x==='object' && x.length!==undefined && typeof x!=='string'){ info.push('bytes['+x.length+']'); wb64(tag.replace(/\W/g,'_')+'_in'+a+'.b64', x); }
            else info.push((''+x).substring(0,40));
          }
          var r=ov.apply(this,args);
          var rinfo;
          if(r===null||r===undefined) rinfo='null';
          else if(typeof r==='object' && r.length!==undefined){ rinfo='bytes['+r.length+']'; wb64(tag.replace(/\W/g,'_')+'_out.b64', r); }
          else if('' + r === '[object Object]'){ // FockResult
            try{ rinfo='Result{'+r.result+','+r.status+'}'; if(r.value && r.value.value){ var vv=r.value.value; wb64(tag.replace(/\W/g,'_')+'_res.b64', vv); } }catch(e2){ rinfo='Result{?}'; }
            try{ var RF=Java.cast(r, Java.use('com.yuewen.fock.Fock$FockResult')); if(RF.value.value) { wb64(tag.replace(/\W/g,'_')+'_res.b64', RF.value.value); rinfo+=' vbytes='+RF.value.value.length; } if(RF.status.value!==undefined) rinfo+=' status='+RF.status.value; }catch(e3){}
          }
          else { rinfo=''+r; if(rinfo.length>50) wtxt(tag.replace(/\W/g,'_')+'_out.txt', rinfo); rinfo=rinfo.substring(0,60); }
          S({m:'◆'+tag+' ('+info.join('|')+') → '+rinfo});
          return r;
        };
      });
    }catch(e){ /* 名字不存在静默跳 */ }
  });
  // NB.s/d 被动（与 v85 同）
  try{ var NB=Java.use('com.yuewen.fockrt.NativeBinding');
    NB.s.overloads.forEach(function(ov){ ov.implementation=function(){
      var r=ov.apply(this,arguments);
      var arg0=(arguments[0]&&arguments[0].length!==undefined)?arguments[0].length:'-';
      S({m:'◆NB.s arg0='+arg0+'B arg1='+arguments[1]+' → '+(r===null?'null':(''+r).length+'B')});
      if(r && (''+r).length>50){ wtxt('NB_s_out.js', r); }
      if(arguments[0] && arguments[0].length) wb64('NB_s_in0.b64', arguments[0]);
      return r; };});
    S({m:'NB.s hook 就绪'});
  }catch(e){ S({m:'NB hook败'}); }
  // FRT.sn/de 被动
  try{ var FRT=Java.use('com.yuewen.fockrt.FockRT');
    FRT.sn.overloads.forEach(function(ov){ ov.implementation=function(){ var r=ov.apply(this,arguments); S({m:'◆FRT.sn('+(''+arguments[0]).substring(0,30)+') → '+(r? (''+r).length+'B':'null')}); if(r&&(''+r).length>50)wtxt('FRTSn_out.js',r); return r; };});
    S({m:'FRT.sn hook 就绪'});
  }catch(e){ S({m:'FRT.sn败 '+String(e).slice(0,50)}); }
  S({m:'v86 hook 全就绪（spawn 早挂，等启动流量）'});
});
})();
