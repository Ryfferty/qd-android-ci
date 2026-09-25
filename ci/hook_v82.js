// hook_v82.js — v43: 触发 a.b.b (让 native 自打印 sha1key1/sha1key2 到 logcat) + 回传本轮全部身份参数供公式对账
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
(function(){
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var d=Java.use('android.util.Base64').decode(P.payload_b64,2);
  S({m:'v43 payload='+d.length});
  // 回传本轮身份参数全量 (logcat 里 imei/userid 要与此对账)
  var FK=Java.use('com.yuewen.fock.Fock');
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  try{
    var g=function(n){try{var m=FU.getClass().getDeclaredMethod(n);m.setAccessible(true);return ''+m.invoke(FU);}catch(e){return 'X';}};
    S({m:'◆IMEI(getPreUserKey)='+g('getPreUserKey')});
    S({m:'◆userKey(cur)='+FK.currentUserKey()});
    S({m:'◆book='+P.book+' cid='+P.cid+' uk='+P.userKey+' ver='+P.Version});
  }catch(e){S({m:'身份读取 '+String(e).slice(0,80)});}
  // 触发 b (native 会打 logcat)
  try{
    var AB=Java.use('a.b'); var ABi=AB.$new();
    var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
    for(var i=0;i<2;i++){
      var t0=Date.now();
      var out=bOv.call(ABi, parseInt(P.book), parseInt(P.cid), d, 0, Java.use('java.lang.String').$new(P.userKey));
      var s=Java.use('java.lang.String').$new(out, 'UTF-8')+'';
      S({m:'▷b#'+i+' len='+out.length+' head='+s.slice(0,60)+' 用时'+(Date.now()-t0)});
    }
    // 再试 userid=真userId 形态 (logcat 里 userid 可能≠0)
    S({m:'完成, 等 logcat flush'});
    var T=Java.use('java.lang.Thread'); T.sleep(6000);
    S({m:'v43 END'});
  }catch(e){S({m:'b 失败 '+String(e).slice(0,140)});}
});
})();
