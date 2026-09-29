// v84: 主动用真机 NB.s() 解 dblob（设备运行时表已填好）→ 拿明文 JS 落盘
(function(){ Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var FOS=Java.use('java.io.FileOutputStream'), File=Java.use('java.io.File');
  var DIR='/data/local/tmp/jsout'; var d=File.$new(DIR); if(!d.exists()) d.mkdirs();
  function save(name, s){ try{ var f=FOS.$new(File.$new(DIR,name)); var arr=[]; s=''+s; for(var i=0;i<s.length&&i<400000;i++)arr.push(s.charCodeAt(i)&0xff); f.write(Java.array('byte',arr)); f.close(); S({m:'★SAVED '+name+' '+arr.length+'B'});}catch(e){S({m:'save败 '+String(e).slice(0,60)});} }
  function rdBytes(p){
    try{
      var FIS=Java.use('java.io.FileInputStream'); var f=FIS.$new(p); var n=File.$new(p).length();
      var buf=Java.array('byte', new Array(n)); f.read(buf); f.close(); return buf;
    }catch(e){ S({m:'read败 '+p+' '+String(e).slice(0,40)}); return null; }
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
  var cfgs = [cfgNow, '', 'x', null];
  for(var i=0;i<cfgs.length;i++){
    (function(cfgv, i){
      try{
        var r = NB.s(blob, Java.use('java.lang.Long').valueOf(2), ui, cfgv===null?null:Java.use('java.lang.String').valueOf(''+cfgv));
        if(cfgv===null) r = NB.s(blob, 2, ui, null);
        S({m:'◆s#'+i+' cfg=['+(cfgv===null?'null':cfgv)+'] → '+(r===null?'null':(''+r).substring(0,70)+' ('+(''+r).length+'B)')});
        if(r && (''+r).length>50) save('script_s_'+i+'.js', r);
      }catch(e){ S({m:'s#'+i+' 败 '+String(e).slice(0,70)}); }
    })(cfgs[i], i);
  }
  // d([B, String, String) → FockRT$Result 探测（解锁评估入口）
  try{ var r2 = NB.d(blob, '2', cfgNow||''); S({m:'◆d → '+(r2===null?'null':JSON.stringify(''+r2).substring(0,80))}); }catch(e){ S({m:'d 败 '+String(e).slice(0,60)}); }
  S({m:'v84 完成，观察 jsout'});
});
})();
