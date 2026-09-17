// stepQ_hookall.js — 挂上全部真方法名，抓 App 自己的调用参数（尤其 addk）
function S(o){try{send(o)}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s}catch(e){return '?'}}
function save(name,txt){ try{ var f=Java.use('java.io.FileOutputStream').$new(DIR+name,false);
  f.write(Java.use('java.lang.String').$new(txt).getBytes('UTF-8')); f.close(); S({m:'★ 落盘 '+name+' ('+txt.length+'B)'}); }catch(e){} }
function W(l){ S({m:l}) }
Java.perform(function(){
  try{
    W('=== Q: 挂全真方法名，抓 App 自己的调用 ===');
    var FK=Java.use('com.yuewen.fock.Fock');
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    // ① FockUtil.unlock 的所有重载
    var fuMs=FU.class.getDeclaredMethods(), hooked=0;
    for(var i=0;i<fuMs.length;i++){
      (function(m){
        var nm=String(m.getName());
        if(nm!=='unlock' && nm!=='unlockData' && nm!=='add' && nm!=='save' && nm!=='requestKey' && nm!=='init') return;
        try{
          var ps=m.getParameterTypes(), pt=[];
          for(var j=0;j<ps.length;j++) pt.push(String(ps[j].getName()).replace('java.lang.',''));
          var ov=FU[nm];
          if(!ov || !ov.overload) return;
          var o=ov.overload.apply(ov, pt);
          o.implementation=function(){
            var args=[]; for(var a=0;a<arguments.length;a++){ try{ args.push(clip(arguments[a],80)) }catch(e){ args.push('?') } }
            W('★★★ FockUtil.'+nm+'('+pt.join(',')+') ← '+args.join(' ‖ '));
            if(nm==='unlock'||nm==='unlockData'){ try{ save('CAP_unlock_args.txt', nm+'('+pt.join(',')+')\n'+args.join('\n')) }catch(e){} }
            return o.apply(this, arguments);
          };
          hooked++; W('  ✓ hook FockUtil.'+nm+'('+pt.join(',')+')');
        }catch(e){}
      })(fuMs[i]);
    }
    // ② Fock 真类的关键方法
    var fkMs=FK.class.getDeclaredMethods();
    ['unlock','unlockData','uk','it','addKeypool','addKeys','setup','sn','lk'].forEach(function(nm){
      try{
        var ov=FK[nm]; if(!ov||!ov.overload) return;
        var variants=[];
        for(var k=0;k<fkMs.length;k++){
          if(String(fkMs[k].getName())!==nm) continue;
          var ps=fkMs[k].getParameterTypes(), pt=[];
          for(var j=0;j<ps.length;j++) pt.push(String(ps[j].getName()).replace('java.lang.',''));
          variants.push(pt);
        }
        variants.forEach(function(pt){
          (function(pt2){
            try{
              var o=ov.overload.apply(ov, pt2);
              o.implementation=function(){
                var args=[]; for(var a=0;a<arguments.length;a++){ try{ args.push(clip(arguments[a],90)) }catch(e){ args.push('?') } }
                W('★★★ Fock.'+nm+'('+pt2.join(',')+') ← '+args.join(' ‖ '));
                try{ save('CAP_fock_'+nm+'.txt', nm+'('+pt2.join(',')+')\n'+args.join('\n')) }catch(e){}
                return o.apply(this, arguments);
              };
              W('  ✓ hook Fock.'+nm+'('+pt2.join(',')+')');
            }catch(e){}
          })(pt);
        });
      }catch(e){}
    });
    W('共挂上 '+hooked+' 个 FockUtil 重载');
    // ③ 触发：deeplink 打开免费章
    try{
      var app=Java.use('android.app.ActivityThread').currentApplication();
      var ctx=app.getApplicationContext();
      var Intent=Java.use('android.content.Intent'), Uri=Java.use('android.net.Uri');
      var it=Intent.$new('android.intent.action.VIEW', Uri.parse('QDReader://OpenBook/1049120379/903350205'));
      it.addFlags(268435456);
      ctx.startActivity(it);
      W('✓ 已发 deeplink OpenBook/1049120379/903350205');
    }catch(e){ W('✗ deeplink 失败 '+String(e).slice(0,110)) }
    // ④ 15 秒后再补发一次（有时首次被吞）
    setTimeout(function(){
      try{
        var app2=Java.use('android.app.ActivityThread').currentApplication();
        var ctx2=app2.getApplicationContext();
        var Intent2=Java.use('android.content.Intent'), Uri2=Java.use('android.net.Uri');
        var it2=Intent2.$new('android.intent.action.VIEW', Uri2.parse('QDReader://OpenBook/1040025277/794290414'));
        it2.addFlags(268435456);
        ctx2.startActivity(it2);
        W('✓ 补发 deeplink OpenBook/1040025277/794290414');
      }catch(e){}
    }, 15000);
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}) }
});
