// hook_v76.js — v37: ★黑盒钉死 a.b 三函数: s/m/d 用固定测试向量主动调用 + b 喂整段PAY边界验证
// a.b 类 = libload-jni 运行时注入, jadx 无静态源码 → 行为定案
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<raw.length;i++)a.push(raw[i]);return a;})());
  var uk=P.userKey, book=P.book, cid=P.cid, q=P.imei16||P.qimei16||uk;
  var AB=Java.use('a.b'); var ABi=null; try{ABi=AB.$new();}catch(e){}
  S({m:'v37 开跑 PAY='+PAY.length+'B'});

  function call(ov,name,args){
    try{ var r=ov.call.apply(ov,[ABi].concat(args)); return String(r); }
    catch(e){ try{ var r2=ov.call.apply(ov,[null].concat(args)); return String(r2); }catch(e2){ return 'ERR:'+String(e2).slice(0,120); } }
  }
  // ① s: (String,String) 测试向量 + 真参复现 (对照 v36 现场 ziEyq…)
  try{
    var sOv=AB.s.overload('java.lang.String','java.lang.String');
    var A=Java.use('java.lang.String');
    S({m:'s("a","b") = '+call(sOv,'s',[A.$new('a'),A.$new('b')])});
    S({m:'s("a","a") = '+call(sOv,'s',[A.$new('a'),A.$new('a')])});
    S({m:'s("",b) = '+call(sOv,'s',[A.$new(''),A.$new('b')])});
    // 真参方向探测: 现场 k1=ziEyq… (28B) —— 试 (uk, 0+SALT+cid) 各序
    var SALT='2EEE1433A152E84B3756301D8FA3E69A';
    S({m:'s(uk,0+SALT+cid)= '+call(sOv,'s',[A.$new(uk),A.$new('0'+SALT+cid)])});
    S({m:'s(q,0+SALT+cid)= '+call(sOv,'s',[A.$new(q),A.$new('0'+SALT+cid)])});
    S({m:'s(uk,SALT+cid)= '+call(sOv,'s',[A.$new(uk),A.$new(SALT+cid)])});
    S({m:'s(q,uid+SALT+cid)= '+call(sOv,'s',[A.$new(q),A.$new('0'+SALT+cid)])});
  }catch(e){S({m:'s 拿不到 '+String(e).slice(0,100)});}
  // ② m: (String,String) 测试向量 + 真参 (key 用 s 的全输出/截断)
  try{
    var mOv=AB.m.overload('java.lang.String','java.lang.String');
    var A2=Java.use('java.lang.String');
    S({m:'m("a","b") = '+call(mOv,'m',[A2.$new('a'),A2.$new('b')])});
    var k1f=call(mOv,'m',[A2.$new('ziEyqVIYLPM17ns8qjiinHCc'),A2.$new(cid+SALT+cid)])!=='' ? '' : '';
  }catch(e){S({m:'m 拿不到 '+String(e).slice(0,100)});}
  // ③ m 真参全序试 (v36: m=k2=QE8K7353Z573922915628690+8字符)
  try{
    var mOv2=AB.m.overload('java.lang.String','java.lang.String'); var A3=Java.use('java.lang.String');
    var K1F='ziEyqVIYLPM17ns8qjiinHCc'; // v36 现场 (截24版)
    var K1FULL=call(AB.s.overload('java.lang.String','java.lang.String'),'s',[A3.$new(uk),A3.$new('0'+SALT+cid)]); // 若匹配则=28全
    var cands=[
      [K1F, cid+SALT+cid], [K1F.slice(0,24), cid+SALT+cid],
      ['ziEyqVIYLPM17ns8qjiinHCc', cid+'2EEE1433A152E84B3756301D8FA3E69A'+cid],
      [K1F, cid+SALT], [K1F, SALT+cid], [K1F, cid], ['0'+SALT+cid, K1F]
    ];
    for(var ci=0;ci<cands.length;ci++){
      S({m:'m['+ci+']('+cands[ci][0].slice(0,10)+'…,'+cands[ci][1].slice(0,14)+'…) = '+call(mOv2,'m',[A3.$new(cands[ci][0]),A3.$new(cands[ci][1])])});
    }
  }catch(e){S({m:'m 序试失败 '+String(e).slice(0,90)});}
  // ④ d 边界验证: 整段 PAY + 现场 k2 → JSON? (若成功=密钥链全对,只差派生公式)
  try{
    var dOv=AB.d.overload('[B','java.lang.String'); var A4=Java.use('java.lang.String');
    var K2='QE8K7353Z573922915628690';
    var dR=ABi===null ? dOv.call(null,PAY,A4.$new(K2)) : dOv.call(ABi,PAY,A4.$new(K2));
    if(dR!==null){ var da=[]; for(var x=0;x<Math.min(48,dR.length);x++)da.push((dR[x]&0xff).toString(16)); S({m:'★d(PAY全,'+K2+') len='+dR.length+' head='+da.join('')}); }
    else S({m:'d(PAY全,k2)=null'});
  }catch(e){S({m:'d 失败 '+String(e).slice(0,110)});}
  // ⑤ b 直调真参终验 + JSON 分段回传
  try{
    var bOv=AB.b.overload('long','long','[B','long','java.lang.String');
    var A5=Java.use('java.lang.String');
    var bR=(ABi===null?bOv.call(null,parseInt(book),parseInt(cid),PAY,0,A5.$new(q)):bOv.call(ABi,parseInt(book),parseInt(cid),PAY,0,A5.$new(q)));
    if(bR){ var B64=Java.use('android.util.Base64'); var js=B64.encodeToString(bR,0)+''; for(var z=0;z<js.length;z+=3000){S({m:'BJSON|'+z+'|'+js.slice(z,z+3000)});} }
  }catch(e){S({m:'b 失败 '+String(e).slice(0,100)});}
  S({m:'v37 完成'});
});
