// step_probe464.js — 在 464 上探 FockUtil / Fock 的真实行为
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
Java.perform(function(){
  try{
    S({m:'=== probe464 ==='});
    // ① FockUtil
    try{
      var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
      var inst=FU.INSTANCE.value;
      S({m:'✓ FockUtil 存在'});
      try{ S({m:'getKey='+clip(inst.getKey(),50)}); }catch(e){ S({m:'getKey 异常 '+String(e).slice(0,90)}); }
      try{ S({m:'isHasKey='+inst.isHasKey()}); }catch(e){}
      try{ S({m:'preUserKey='+clip(inst.getPreUserKey(),50)}); }catch(e){}
      var ms=FU.class.getDeclaredMethods(), names=[];
      for(var i=0;i<ms.length;i++) names.push(String(ms[i].getName()));
      S({m:'FockUtil 方法('+names.length+'): '+names.sort().join(',')});
    }catch(e){ S({m:'✗ FockUtil 不存在/异常 '+String(e).slice(0,140)}); }
    // ② com.yuewen.fock.Fock（464 里有真 class_data）
    try{
      var FK=Java.use('com.yuewen.fock.Fock');
      S({m:'✓ com.yuewen.fock.Fock 存在'});
      var ms2=FK.class.getDeclaredMethods(), nm2=[];
      for(var j=0;j<ms2.length;j++) nm2.push(String(ms2[j].getName()));
      S({m:'Fock 方法('+nm2.length+'): '+nm2.sort().slice(0,40).join(',')});
    }catch(e){ S({m:'com.yuewen.fock.Fock 不可用 '+String(e).slice(0,120)}); }
    // ③ 装了哪些 fock 库
    try{
      var Runtime=Java.use('java.lang.Runtime');
      var pro=Runtime.getRuntime().exec(['sh','-c','ls -la /data/app/*/com.qidian.QDReader*/lib/arm64/ 2>/dev/null | grep -iE "fock|nib|knobs"']);
      pro.waitFor();
      var is=pro.getInputStream();
      var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(is));
      var line, out=[];
      while((line=br.readLine())!==null && out.length<10) out.push(String(line));
      S({m:'★ 已加载的 so 文件: '+out.join(' | ')});
    }catch(e){ S({m:'ls 失败 '+String(e).slice(0,90)}); }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,180)}); }
});
