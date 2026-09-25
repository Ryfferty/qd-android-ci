// hook_v78.js — v39: ★旁观 a.b.d 内部现场: b 执行时 native 回调 d 的真实入参(seg1边界+真key)一次拿全
// 原理: a.b=libload-jni 注入类(非libfock, 无自检; v37 直调不死已证) → implementation 只观察放行
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function hexp(b,n){var s='';for(var i=0;i<Math.min(n||24,b.length);i++){var v=b[i]&0xff;s+=(v<16?'0':'')+v.toString(16);}return s;}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<raw.length;i++)a.push(raw[i]);return a;})());
  var uk=P.userKey, book=P.book, cid=P.cid;
  var AB=Java.use('a.b');
  S({m:'v39 开跑 PAY='+PAY.length});
  // ① 观察钩 s/m/d (调用即 dump, 原样放行)
  var nS=0,nM=0,nD=0;
  try{
    AB.s.implementation=function(a1,b1){
      var r=this.s(a1,b1);
      if(nS<6){nS=nS+1;S({m:'▷s#'+nS+' key='+(''+b1).slice(0,66)+' data='+(''+a1).slice(0,66)+' → '+(''+r).slice(0,40)});}
      return r;
    };
    S({m:'钩s OK'});
  }catch(e){S({m:'钩s 失败 '+String(e).slice(0,80)});}
  try{
    AB.m.implementation=function(a1,b1){
      var r=this.m(a1,b1);
      if(nM<6){nM=nM+1;S({m:'▷m#'+nM+' ['+(''+a1).slice(0,40)+', '+(''+b1).slice(0,40)+'] → '+(''+r).slice(0,40)});}
      return r;
    };
    S({m:'钩m OK'});
  }catch(e){S({m:'钩m 失败 '+String(e).slice(0,80)});}
  try{
    AB.d.implementation=function(barr,kstr){
      var r=this.d(barr,kstr);
      if(nD<10){nD=nD+1;
        var ih=(barr?hexp(barr,20):'null')+' len='+(barr?barr.length:0);
        var oh=(r?hexp(r,20):'null')+' len='+(r?r.length:0);
        S({m:'▷d#'+nD+' in['+ih+'] key='+(''+kstr)+' out['+oh+']'});
      }
      return r;
    };
    S({m:'钩d OK'});
  }catch(e){S({m:'钩d 失败 '+String(e).slice(0,80)});}
  // ② 触发 b → 上面钩子记录全部现场
  try{
    var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
    var A=Java.use('java.lang.String');
    var bR=bOv.call(null,parseInt(book),parseInt(cid),PAY,0,A.$new(uk));
    if(bR){
      S({m:'★b len='+bR.length+' head='+hexp(bR,16)});
      var B64=Java.use('android.util.Base64');
      var js=B64.encodeToString(bR,0)+'';
      for(var z=0;z<js.length;z+=3000){S({m:'BJSON|'+z+'|'+js.slice(z,z+3000)});}
    } else S({m:'b=null'});
  }catch(e){S({m:'b 失败 '+String(e).slice(0,110)});}
  // ③ uid 变体再触发 (确认 s 的 data 里 uid 从哪来)
  try{
    var bOv2=AB.b.overload('long','long','[B','long','java.lang.String');
    var A2=Java.use('java.lang.String');
    var bR2=bOv2.call(null,parseInt(book),parseInt(cid),PAY,parseInt(uk.length>8?0:0),A2.$new(uk));
    S({m:'(二次触发 len='+(bR2?bR2.length:0)+')'});
  }catch(e2){}
  S({m:'v39 完成'});
});
