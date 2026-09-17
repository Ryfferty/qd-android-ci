// stepD_antikill.js — spawn 后立刻挂钩自杀点，抓 abort 原因
function S(o){try{send(o);}catch(e){}}
setImmediate(function(){
  try{
    S({m:'=== D: 抓自杀原因 ==='});
    // ① android_set_abort_message —— 直接读出 abort 原因
    var fns=['android_set_abort_message','__android_log_assert','abort','exit','_exit','kill','pthread_kill','raise','syscall'];
    for(var i=0;i<fns.length;i++){
      var n=fns[i];
      try{
        var p=Module.getExportByName(null,n);
        if(!p) continue;
        (function(nm){
          Interceptor.attach(Module.getExportByName(null,nm),{
            onEnter:function(a){
              var extra='';
              try{
                if(nm==='android_set_abort_message'||nm==='__android_log_assert'){
                  extra=' msg='+a[0].readCString();
                } else if(nm==='kill'||nm==='pthread_kill'||nm==='raise'){
                  extra=' sig='+(nm==='kill'?a[1].toInt32():a[0].toInt32());
                } else if(nm==='syscall'){
                  extra=' nr='+a[0].toInt32()+' arg0='+a[1];
                }
              }catch(e){ extra=' (读取失败)'; }
              S({m:'★★ ['+nm+'] 被调用'+extra});
            }
          });
          S({m:'✓ 已挂 '+n});
        })(n);
      }catch(e){}
    }
    // ② 相关模块（稍后轮询）
    var t=setInterval(function(){
      try{
        var mods=Process.enumerateModules(), hit=[];
        for(var k=0;k<mods.length;k++){
          if(/fock|nib|knobs|shell|jiagu|omg|stub/i.test(mods[k].name)) hit.push(mods[k].name);
        }
        if(hit.length) S({m:'★ 已加载相关模块: '+hit.join(', ')});
      }catch(e){}
    }, 2000);
    // ③ 30 秒后总结
    setTimeout(function(){
      try{
        var mods=Process.enumerateModules();
        S({m:'模块总数='+mods.length});
        clearInterval(t);
        S({m:'=== D 结束（进程仍存活='+ (Process.id>0) +'）==='});
      }catch(e){}
    }, 30000);
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,180)}); }
});
