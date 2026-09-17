// step_mapdump3.js — 可靠遍历 Java Map（cast + iterator），并把内容落盘
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function dumpMap(o,label){
  if(o===null||o===undefined){ S({m:label+' = null'}); return; }
  var M=null;
  try{ M=Java.cast(o, Java.use('java.util.Map')); }catch(e){ S({m:label+' cast 失败 '+String(e).slice(0,100)}); return; }
  try{
    var sz=M.size();
    S({m:'★ '+label+': size='+sz+' class='+M.getClass().getName()});
    if(sz===0){ S({m:'   （空 Map）'}); return; }
    var it=M.keySet().iterator(), n=0;
    while(it.hasNext() && n<15){
      var k=it.next(); var v=null;
      try{ v=M.get(k); }catch(e){ v='<get err>'; }
      S({m:'   ['+n+'] '+clip(k,40)+' ⇒ '+clip(v,60)});
      n++;
    }
  }catch(e){ S({m:label+' 遍历失败 '+String(e).slice(0,120)}); }
}
Java.perform(function(){
  try{
    S({m:'=== mapdump3 ==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    S({m:'getKey='+clip(inst.getKey(),40)+' isHasKey='+inst.isHasKey()});
    // 反射调用 private 方法（更稳）
    var ms=FU.class.getDeclaredMethods();
    for(var i=0;i<ms.length;i++){
      var nm=String(ms[i].getName());
      if(nm==='getKeyMap'||nm==='loadLocalKey'){
        try{
          var r=ms[i].invoke(inst, Java.array('java.lang.Object',[ctx]));
          dumpMap(r, nm+'()');
        }catch(e){ S({m:nm+' 反射调用失败 '+String(e).slice(0,140)}); }
      }
    }
    // 顺带看 add 之后 getKey 变化
    S({m:'（只读，不改状态）'});
  }catch(e){ S({m:'✗ 顶层异常 '+String(e).slice(0,200)}); }
});
