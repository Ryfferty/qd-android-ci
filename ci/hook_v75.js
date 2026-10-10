// hook_v75.js — v36: dump a.b 全方法签名 → 主动调 s/m/d (native 胶水回调的三个 Java 方法) 拿真实密钥链
// 安全打法: 全部 .call(obj,...) 主动调用 (v34b 实证可用), 不做 implementation 替换 (避自检)
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function bts(a,n){try{var u=new Uint8Array(a);var m=n&&n<u.length?n:u.length;var s='';for(var i=0;i<m;i++){var c=u[i]&0xff;s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}catch(e){return '?';}}
function hx(a,n){try{var u=new Uint8Array(a);var m=n&&n<u.length?n:u.length;var s='';for(var i=0;i<m;i++)s+=('0'+(u[i]&0xff).toString(16)).slice(-2);return s;}catch(e){return '?';}}
function bArr(jstr){var s=Java.use('java.lang.String').$new(''+jstr).getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
(function(){
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<raw.length;i++)a.push(raw[i]);return a;})());
  var book=P.book+'', cid=P.cid+'', uk=P.userKey+'';
  var SALT='2EEE1433A152E84B3756301D8FA3E69A';
  S({m:'v36 开跑 payload='+PAY.length+'B'});

  var AB=Java.use('a.b'); var inst=AB.$new();
  // ① dump a.b 所有方法签名
  try{
    var ms=AB.class.getDeclaredMethods();
    for(var mi=0;mi<ms.length;mi++) S({m:'◆a.b.'+(''+ms[mi])});
  }catch(e){S({m:'dump 失败 '+String(e).slice(0,60)});}

  function callOvl(name, argsArr){
    try{
      var ovl=AB[name].apply(AB, []);
    }catch(e){}
    try{
      // 直接找匹配重载
      var meth=AB[name];
      var r=meth.apply(inst,argsArr.map(function(x){return x;}));
      S({m:'◇'+name+' apply → '+bts(r,80)});
      return r;
    }catch(e){
      S({m:'◇'+name+' apply 异常 '+String(e).slice(0,80)});
      return null;
    }
  }

  // ② 主动调 a.b.s (还原: HmacSHA1(key,msg)→b64[:24])
  //    猜测签名: (String key, String msg) 或 ([B,[B) — 全重载试
  ['s','m','d'].forEach(function(fn){
    try{
      var ovs=AB[fn].overloads;
      S({m:'◆'+fn+' 重载数='+ovs.length});
      for(var oi=0;oi<ovs.length;oi++){
        var types=ovs[oi].argumentTypes.map(function(t){return t.className;}).join(',');
        S({m:'  '+fn+'#'+oi+' ('+types+') → '+ovs[oi].returnType.className});
      }
    }catch(e){S({m:fn+' 枚举失败 '+String(e).slice(0,60)});}
  });

  // ③ 用真实语义参数调 (按还原文档: s(qimei, uid+SALT+cid)→b64; m(k1, cid+SALT)→b64; d(data,key)→解密)
  var k1=null,k2=null;
  try{
    k1=AB.s.overload('java.lang.String','java.lang.String').call(inst, uk, '0'+SALT+cid);
    S({m:'★s1(String,String)="'+(''+k1)+'"'});
  }catch(e){S({m:'s1 失败 '+String(e).slice(0,70)});}
  if(k1){
    try{ k2=AB.m.overload('java.lang.String','java.lang.String').call(inst, ''+k1, cid+SALT); S({m:'★m1="'+(''+k2)+'"'}); }catch(e){S({m:'m1 失败 '+String(e).slice(0,70)});}
  }
  // byte[] 形态变体
  try{
    var r2=AB.s.overload('[B','[B').call(inst, bArr(uk), bArr('0'+SALT+cid));
    S({m:'★s2([B,[B)="'+bts(r2,60)+'"'});
  }catch(e){S({m:'s2 失败 '+String(e).slice(0,70)});}
  // ④ d: 3DES 回调 — 若 k2 拿到, 喂 PAY 与 seg1 起点变体
  if(k2){
    try{
      var o3=AB.d.overload('[B','[B').call(inst, PAY, bArr(''+k2));
      S({m:'★d(PAY,k2) len='+(o3?o3.length:'null')+' head='+bts(o3,60)});
      if(o3&&o3.length>10){var a2=[];for(var j=0;j<o3.length&&j<20000;j++)a2.push(o3[j]);S({m:'★DOUT_B64',json:Java.use('android.util.Base64').encodeToString(Java.array('byte',a2),2)+''});}
    }catch(e){S({m:'d 失败 '+String(e).slice(0,70)});}
  }
  // ⑤ a.b.b 完整触发 + JSON 全量回传 (v34b 已验证链, 再拿一次)
  try{
    var ab=AB.b.overload('long','long','[B','long','java.lang.String');
    var out=ab.call(inst, parseInt(book), parseInt(cid), PAY, 0, uk);
    S({m:'a.b.b out len='+(out?out.length:'null')+' head='+bts(out,70)});
    if(out&&out.length>10){var a3=[];for(var jj=0;jj<out.length&&jj<20000;jj++)a3.push(out[jj]);S({m:'★JSON_FULL',json:Java.use('android.util.Base64').encodeToString(Java.array('byte',a3),2)+''});}
  }catch(e){S({m:'a.b.b 异常 '+String(e).slice(0,90)});}
  S({m:'v36 done'});
});
})();