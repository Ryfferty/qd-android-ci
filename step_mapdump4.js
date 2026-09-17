// step_mapdump4.js — 直接用 frida wrapper 调 private 方法 + Java.cast 遍历
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function walk(o,label){
  if(o===null||o===undefined){ S({m:label+' = null'}); return; }
  var M=null;
  try{ M=Java.cast(o, Java.use('java.util.Map')); }
  catch(e){ S({m:label+' cast 成 Map 失败 '+String(e).slice(0,90)+' class='+o.getClass().getName()}); return; }
  try{
    var sz=M.size(); S({m:'★ '+label+' size='+sz});
    if(sz===0){ S({m:'   （空）'}); return; }
    var it=M.keySet().iterator(), n=0;
    while(it.hasNext() && n<15){
      var k=it.next(); var v=null;
      try{ v=M.get(k); }catch(e){ v='<err>'; }
      S({m:'   ['+n+'] '+clip(k,36)+' ⇒ '+clip(v,60)});
      n++;
    }
  }catch(e){ S({m:label+' 遍历失败 '+String(e).slice(0,110)}); }
}
Java.perform(function(){
  try{
    S({m:'=== mapdump4 ==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    S({m:'getKey='+clip(inst.getKey(),36)+' isHasKey='+inst.isHasKey()+' preUserKey='+clip(inst.getPreUserKey(),36)});
    // ① 直接调用（frida wrapper 能进 private）
    try{ var km=inst.getKeyMap(ctx); walk(km,'getKeyMap(直接)'); }
    catch(e){ S({m:'getKeyMap 直接调用失败 '+String(e).slice(0,110)}); }
    try{ var lk=inst.loadLocalKey(ctx); walk(lk,'loadLocalKey(直接)'); }
    catch(e){ S({m:'loadLocalKey 直接调用失败 '+String(e).slice(0,110)}); }
    // ② setAccessible 后反射
    try{
      var ms=FU.class.getDeclaredMethods();
      for(var i=0;i<ms.length;i++){
        var nm=String(ms[i].getName());
        if(nm!=='getKeyMap' && nm!=='loadLocalKey') continue;
        try{
          ms[i].setAccessible(true);
          var r=ms[i].invoke(inst, Java.array('java.lang.Object',[ctx]));
          walk(r, nm+'(setAccessible)');
        }catch(e){ S({m:nm+' setAccessible 后仍失败 '+String(e).slice(0,110)}); }
      }
    }catch(e){ S({m:'setAccessible 分支异常 '+String(e).slice(0,110)}); }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,180)}); }
});
