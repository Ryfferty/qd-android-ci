// v84: 主动用真机 NB.s() 解 dblob（设备运行时表已填好）→ 拿明文 JS 落盘
(function(){ Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var FOS=Java.use('java.io.FileOutputStream'), File=Java.use('java.io.File');
  var DIR='/data/local/tmp/jsout'; var d=File.$new(DIR); if(!d.exists()) d.mkdirs();
  function save(name, s){ try{ var f=FOS.$new(File.$new(DIR,name)); var arr=[]; s=''+s; for(var i=0;i<s.length&&i<400000;i++)arr.push(s.charCodeAt(i)&0xff); f.write(Java.array('byte',arr)); f.close(); S({m:'★SAVED '+name+' '+arr.length+'B'});}catch(e){S({m:'save败 '+String(e).slice(0,60)});} }
  function rdBytes(p){
    try{
      var n = parseInt('' + File.$new(p).length(), 10);
      var zeroArr = []; for(var i=0;i<n;i++) zeroArr.push(0);
      var BA = Java.array('byte', zeroArr);
      var FIS=Java.use('java.io.FileInputStream'); var f=FIS.$new(p);
      var got=f.read(BA); f.close();
      S({m:'rd '+p+' n='+n+' got='+got});
      return BA;
    }catch(e){ S({m:'read败 '+p+' '+String(e).slice(0,60)}); return null; }
  }
  var NB=Java.use('com.yuewen.fockrt.NativeBinding');
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  // ★ 先跑 FRT.setup：建 fileManager/executor + 触发 libfockrt 全局表填充（表不填 s 必崩）
  try{ var FRT=Java.use('com.yuewen.fockrt.FockRT'); FRT.setup(ctx,'qjsprobe',false); S({m:'★FRT.setup ok'}); }catch(e){ S({m:'setup败 '+String(e).slice(0,70)}); }
  Java.use('java.lang.Thread').sleep(5000);
  // cfg 候选：C18706g.f72914a 当前值（setup 第2参喂入的业务串）
  var cfgNow = '';
  try{ var G=Java.use('com.yuewen.fockrt.C18706g'); cfgNow = G.f72914a.value; S({m:'f72914a 现值=['+(cfgNow===null?'null':cfgNow)+']'}); }catch(e){ S({m:'g类名混淆，试别的 '+String(e).slice(0,40)}); }
  try{ var G2=Java.use('com.yuewen.fockrt.g'); cfgNow = G2.f72914a.value; S({m:'g.f72914a=['+(cfgNow===null?'null':(''+cfgNow).substring(0,40))+']'}); }catch(e){}
  var blob = rdBytes('/data/local/tmp/dblob.bin');
  var ui   = rdBytes('/data/local/tmp/ui.bin');
  if(blob){ S({m:'blob='+blob.length+'B ui='+(ui?ui.length:'null')}); }
  // s([B, long, [B, String) → String：多 cfg 组合
  // setup 已把 f72914a='qjsprobe'；s 第4参须与之一致。primitive 直传（勿 valueOf）
  var cfgs = ['qjsprobe', cfgNow, ''];
  for(var i=0;i<cfgs.length;i++){
    (function(cfgv, i){
      try{
        var r = NB.s(blob, 2, ui, cfgv===null?null:cfgv);
        S({m:'◆s#'+i+' cfg=['+cfgv+'] → '+(r===null?'null':(''+r).substring(0,70)+' ('+(''+r).length+'B)')});
        if(r && (''+r).length>50) save('script_s_'+i+'.js', r);
      }catch(e){ S({m:'s#'+i+' 败 '+String(e).slice(0,90)}); }
    })(cfgs[i], i);
  }
  // desc.e 可能不是2：试 fileManager 路径拿真 desc
  try{
    var FRT2=Java.use('com.yuewen.fockrt.FockRT');
    var fm=FRT2.fileManager.value;
    if(fm){
      var list=fm.m67608b(Java.use('com.yuewen.fockrt.enums.EnumC18704c').MANUAL.value, false);
      S({m:'fileManager MANUAL scripts='+list.size()});
    }
  }catch(e){ S({m:'fm 探测败 '+String(e).slice(0,50)}); }
  // d([B, String, String) → FockRT$Result 探测（解锁评估入口）
  try{ var r2 = NB.d(blob, '2', cfgNow||''); S({m:'◆d → '+(r2===null?'null':JSON.stringify(''+r2).substring(0,80))}); }catch(e){ S({m:'d 败 '+String(e).slice(0,60)}); }
  // ① 枚举 FRT 运行时真方法名（jadx 改名≠dex真名）
  try{
    var dm = Java.use('com.yuewen.fockrt.FockRT').class.getDeclaredMethods();
    var ns=[]; for(var z=0;z<dm.length;z++) ns.push(dm[z].getName()+'/'+dm[z].getParameterTypes().length);
    S({m:'FRT方法: '+ns.join(',')});
  }catch(e){ S({m:'枚举败 '+String(e).slice(0,50)}); }
  // ② 后台线程调 sn（m67608b 会同步等网络，主线程直调会挂死 frida）
  try{
    var Runnable=Java.use('java.lang.Runnable');
    var Impl=Java.registerClass({
      name:'com.probe.Sn84', implements:[Runnable],
      methods:{ run: function(){
        try{
          var out = Java.use('com.yuewen.fockrt.FockRT').m67574sn('probe_ui');
          send({m:'◆m67574sn → '+(out===null?'null':(''+out).substring(0,80)+' ('+(''+out).length+'B)')});
          if(out && (''+out).length>50){
            var f=Java.use('java.io.FileOutputStream').$new(Java.use('java.io.File').$new('/data/local/tmp/jsout/sn_out.js'));
            var st=''+out; var arr=[]; for(var i=0;i<st.length;i++)arr.push(st.charCodeAt(i)&0xff);
            f.write(Java.array('byte',arr)); f.close(); send({m:'★SAVED sn_out.js '+arr.length+'B'});
          }
        }catch(e){ send({m:'sn败 '+String(e).slice(0,80)}); }
      }}
    });
    Java.use('java.lang.Thread').$new(Impl.$new()).start();
    S({m:'sn 线程已派'});
  }catch(e){ S({m:'线程派生败 '+String(e).slice(0,60)}); }
  S({m:'v84c 完成'});

});
})();
