// hook_v83.js — v44: ★先抓本轮 ISM8(Cipher.init现场) → 设备端自爆破 m/s/md5 组合命中它 → 公式当场现形
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
(function(){
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var imei=P.userKey, cid=P.cid, book=P.book, ver=P.Version;
  var SALT='2EEE1433A152E84B3756301D8FA3E69A';
  var A=Java.use('java.lang.String');
  var B64=Java.use('android.util.Base64');
  // ① Cipher.init 抓本轮真 ISM8
  var CAP=[];
  try{
    var Ci=Java.use('javax.crypto.Cipher');
    var oi=Ci.init.overload('int','java.security.Key');
    oi.implementation=function(op,k){
      try{ var kb=k.getEncoded(); var s=A.$new(kb).toString(); if(/^[A-Za-z0-9+\/=]{20,28}$/.test(s+'')) CAP.push(''+s);}catch(e){}
      return oi.call(this,op,k);
    };
    S({m:'钩Cipher OK'});
  }catch(e){S({m:'钩Cipher 失败 '+String(e).slice(0,80)});}
  // ② a.b 方法句柄
  var AB=Java.use('a.b'), ABi=AB.$new();
  var sOv=AB.s.overload('java.lang.String','java.lang.String');
  var mOv=AB.m.overload('java.lang.String','java.lang.String');
  // ③ 触发 b 一次拿 ISM8
  var d=B64.decode(P.payload_b64,2);
  var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
  var j=bOv.call(ABi, parseInt(book), parseInt(cid), d, 0, A.$new(imei));
  S({m:'b OK len='+j.length+' CAP='+CAP.join(',')});
  var ISM8=CAP.length?CAP[0]:null;
  if(!ISM8){S({m:'✗ 没抓到 ISM8'});return;}
  // ④ 串池
  var M1=null; // HmacSHA1 已知, key1 截24
  try{
    var Mac=Java.use('javax.crypto.Mac'); var mk=Mac.getInstance(A.$new('HmacSHA1'));
    var SK=Java.use('javax.crypto.spec.SecretKeySpec');
    mk.init(SK.$new(A.$new(imei).getBytes(),A.$new('HmacSHA1')));
    var raw=mk.doFinal(A.$new('0'+imei+cid+SALT).getBytes());
    M1=B64.encodeToString(raw,2)+'';
  }catch(e){S({m:'M1 算败 '+String(e).slice(0,60)});}
  var pool={'imei':imei,'0imei':'0'+imei,'imei8':imei.slice(32),'imei20':imei.slice(0,20),
   'cid':cid,'book':book,'pair':book+'_'+cid,'ver':ver,'SALT':SALT,'M1':M1,'k2':M1?M1.slice(0,24):'?',
   'S':('0'+imei+cid+SALT),'0':'0','empty':'','uid0':'0','sha1id':'-1209242176','magic':'825709325',
   'cidS':cid+SALT,'Scid':SALT+cid,'bookcid':book+cid,'imeicid':imei+cid};
  // ⑤ 爆破 m/s 双向 + 拼接
  var hit=false, tried=0;
  var kn=Object.keys(pool);
  for(var i=0;i<kn.length && !hit;i++)for(var j2=0;j2<kn.length && !hit;j2++){
    var k1=pool[kn[i]], k2v=pool[kn[j2]]; if(k1===null||k2v===null)continue;
    tried++;
    try{ var vm=''+mOv.call(ABi, A.$new(k1), A.$new(k2v)); if(vm===ISM8){S({m:'★★★ m('+kn[i]+','+kn[j2]+') = ISM8 !'});hit=true;} }catch(e){}
    tried++;
    try{ var vs=''+sOv.call(ABi, A.$new(k1), A.$new(k2v)); if(vs===ISM8){S({m:'★★★ s('+kn[i]+','+kn[j2]+') = ISM8 !'});hit=true;} }catch(e){}
    tried++;
    try{ var vm2=''+mOv.call(ABi, A.$new(k2v), A.$new(k1)); if(vm2===ISM8){S({m:'★★★ m(反'+kn[j2]+','+kn[i]+') = ISM8 !'});hit=true;} }catch(e){}
  }
  S({m:'◇爆破完成 tried='+tried+(hit?' 命中★':' 未中')});
  S({m:'v44 END'});
});
})();
