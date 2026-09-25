// hook_v77.js — v38: 钉死 k1 真值(s全输出hex+len) + d(单遍3DES) 解 seg1 + s/m 与 native 内部一致性
// 现场(v37): s(uk,"0"+SALT+cid)=87HT96qSEbKl+TqJJULKXJ+5xtI= 但设备内部 k1=ziEyqVIYLPM17ns8qjiinH(截24)
// 假说: native 拼 key 时用了不同顺序/额外字段, 或 key1 全输出=28B→截24
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<raw.length;i++)a.push(raw[i]);return a;})());
  var uk=P.userKey, book=P.book, cid=P.cid, q=P.imei16||P.qimei16||uk;
  var SALT='2EEE1433A152E84B3756301D8FA3E69A';
  var AB=Java.use('a.b'); var ABi=null; try{ABi=AB.$new();}catch(e){}
  var A=Java.use('java.lang.String');
  S({m:'v38 开跑'});
  function hexpb(jb,n){var s='';for(var i=0;i<Math.min(n||40,jb.length);i++){var v=jb[i]&0xff;s+=(v<16?'0':'')+v.toString(16);}return s;}
  // ① s(uk, "0"+SALT+cid) 完整输出 + 长度 + hex
  try{
    var sOv=AB.s.overload('java.lang.String','java.lang.String');
    var k1=(sOv.call(ABi,A.$new(uk),A.$new('0'+SALT+cid))+'');
    S({m:'k1='+k1+' len='+k1.length});
    // ② m 输入 key1 → key2
    var mOv=AB.m.overload('java.lang.String','java.lang.String');
    var k2=(mOv.call(ABi,A.$new(k1),A.$new(cid+SALT+cid))+'');
    S({m:'k2='+k2+' len='+k2.length});
    // ③ d(data,key2) 一次 → 期望是 3DES 一遍的结果
    var dOv=AB.d.overload('[B','java.lang.String');
    var d1=dOv.call(ABi,PAY,A.$new(k2));
    if(d1){
      S({m:'★d(整PAY,k2) len='+d1.length+' head='+hexpb(d1,32)});
      var d2=dOv.call(ABi,d1,A.$new(k2));
      if(d2){ S({m:'★★d(d1,k2) len='+d2.length+' head='+hexpb(d2,40)});
        var B64=Java.use('android.util.Base64');
        var js=B64.encodeToString(d2,0)+'';
        for(var z=0;z<Math.min(9000,js.length);z+=3000){S({m:'DJSON|'+z+'|'+js.slice(z,z+3000)});}
      }
    } else S({m:'d(整PAY,k2)=null'});
    // ④ 对照: 设备内部真实链 = a.b.b — 若 d 双遍=JSON 则公式全对
    var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
    var bR=bOv.call(ABi,parseInt(book),parseInt(cid),PAY,0,A.$new(q));
    if(bR){ S({m:'★b len='+bR.length+' head='+hexpb(bR,20)}); }
    // ⑤ s 变体扫: 找与 v36 现场 k1=ziEyq... 一致的输入
    var cands=[
      [q,'0'+SALT+cid], [uk,SALT+cid+uk], [uk+'0',SALT+cid], [q,SALT+cid],
      ['0'+uk,SALT+cid], [uk,'0'+SALT+cid], [q,'0'+SALT+cid]
    ];
    for(var ci=0;ci<cands.length;ci++){
      var r=(sOv.call(ABi,A.$new(cands[ci][0]),A.$new(cands[ci][1]))+'');
      if(r.indexOf('ziEyq')===0) S({m:'★★★k1现场复现! s('+cands[ci][0].slice(0,8)+'…,'+cands[ci][1].slice(0,20)+'…) = '+r});
    }
    // 也测 (data,key) 互换方向
    for(var cj=0;cj<2;cj++){
      var a1=cj===0?q:uk, b1='0'+SALT+cid;
      var r2=(sOv.call(ABi,A.$new(b1),A.$new(a1))+'');
      if(r2.indexOf('ziEyq')===0) S({m:'★★★k1复现(反序)! s('+b1.slice(0,16)+'…,'+a1.slice(0,8)+'…) = '+r2});
    }
  }catch(e){S({m:'失败 '+String(e).slice(0,130)});}
  S({m:'v38 完成'});
});
