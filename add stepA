// stepA_native.js — 只做 native 层：枚举模块 + hook RegisterNatives/JNI_OnLoad
function S(o){try{send(o);}catch(e){}}
setImmediate(function(){
  try{
    S({m:'=== A: native 层探测 ==='});
    var mods=Process.enumerateModules(), fock=[];
    for(var i=0;i<mods.length;i++){
      var n=mods[i].name;
      if(/fock|nib|knobs|shell|jiagu|omg/i.test(n)) fock.push(n+'@'+mods[i].base);
    }
    S({m:'相关模块: '+(fock.join(' | ')||'（暂无）')});
    // hook RegisterNatives（libart 导出）
    var rn=null;
    try{ rn=Module.getExportByName(null,'RegisterNatives'); }catch(e){}
    if(rn){
      S({m:'✓ 找到 RegisterNatives @ '+rn});
      Interceptor.attach(rn,{
        onEnter:function(a){
          try{
            var clazz=a[0], methods=a[1], count=a[2].toInt32();
            var name='?';
            try{
              var jn=Java.vm.getEnv();
              // 仅记录数量与首方法名，避免深挖触发自检
              name='methods='+count;
            }catch(e){}
            S({m:'[RegisterNatives] '+name});
          }catch(e){ S({m:'[RegisterNatives] 读取异常 '+e}); }
        }
      });
      S({m:'✓ RegisterNatives 已挂钩'});
    } else S({m:'✗ 找不到 RegisterNatives'});
    // 轮询 libfock 是否出现
    var tries=0;
    var t=setInterval(function(){
      tries++;
      var m=Process.findModuleByName('libfock.so');
      if(m){ S({m:'★ libfock.so 已加载 base='+m.base+' size='+m.size}); clearInterval(t); }
      if(tries>20){ S({m:'轮询结束：libfock.so 未出现'}); clearInterval(t); }
    }, 3000);
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,180)}); }
});
