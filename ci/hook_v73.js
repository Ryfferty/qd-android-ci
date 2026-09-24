// hook_v73.js — v34: ★a.b.b 直调真链: X类反射扫真 uid/qimei → seg1(payload) → a.b.b→JSON→content→unlock(cid,pair)
// 前情: unlock -5 因 data 喂错层; 真 data = a.b.b(book,cid,payload,uid,qimei) 的 JSON.content
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function toB64(bb){var s=Java.use('android.util.Base64').encodeToString(bb,2);return Java.use('java.lang.String').$new(s).toString();}
function bArr(jstr){var s=Java.use('java.lang.String').$new(''+jstr).getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
function printable(bb,n){var L=Math.min(n||60,bb.length);var s='';for(var i=0;i<L;i++){var c=bb[i]&0xff;s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
(function(){
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<raw.length;i++)a.push(raw[i]);return a;})());
  var book=P.book+'', cid=P.cid+'';
  S({m:'v34 开跑 payload='+PAY.length});

  // ① X.c17122q 静态字段全扫 (真 qimei/uid 存这里)
  var uids={'0':'0','1':'1','1M':'1000000'}, qimeis={};
  try{
    var XC=Java.use('X.c17122q');
    XC.$clinit();
    var fs=XC.class.getDeclaredFields();
    S({m:'X 静态字段数='+fs.length});
    for(var fi=0;fi<fs.length;fi++){
      try{
        var fd=fs[fi]; fd.setAccessible(true);
        var nm=''+fd.getName(); if(nm==='toString')continue;
        var tn=''+fd.getType().getName();
        if(tn==='long'||tn==='java.lang.Long'){ var v=fd.getLong(null); if(v>0){uids['X.'+nm]=''+v;} S({m:'◆X.'+nm+'(J)='+v}); }
        else if(tn==='int'){ var iv=fd.getInt(null); if(iv>0)uids['X.'+nm]=''+iv; }
        else if(tn==='java.lang.String'){ var sv=fd.get(null); if(sv!==null){ var t=''+sv; S({m:'◆X.'+nm+'(S) len='+t.length+' h='+t.slice(0,10)}); qimeis['X.'+nm]=t; } }
      }catch(ef){}
    }
  }catch(e){S({m:'X 扫描失败 '+String(e).slice(0,90)});}
  if(P.qimei16)qimeis['P.q16']=P.qimei16+'';
  if(P.userKey){qimeis['uk36']=P.userKey+'';qimeis['uk16']=P.userKey.slice(0,16);}
  try{var ctx0=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();qimeis['AD']=Java.use('android.provider.Settings$Secure').getString(ctx0.getContentResolver(),'android_id')+'';}catch(e2){}
  S({m:'uid候选='+Object.keys(uids).length+' qimei候选='+Object.keys(qimeis).join(',')});

  // ② a.b.b 直调 (libload-jni; 不碰 libfock 自检面)
  var AB=null,ab=null;
  try{ AB=Java.use('a.b'); ab=AB.b.overload('long','long','[B','long','java.lang.String'); S({m:'★a.b.b 拿到了'}); }catch(e){S({m:'a.b.b 拿不到 '+String(e).slice(0,90)});}
  var jsonHit=false, content=null;
  if(ab){
    var us=Object.keys(uids), qs=Object.keys(qimeis);
    for(var qi=0;qi<qs.length&&!jsonHit;qi++){
      for(var ui=0;ui<us.length&&!jsonHit;ui++){
        try{
          var out=ab.call(null, parseInt(book), parseInt(cid), PAY, parseInt(uids[us[ui]]), qimeis[qs[qi]]);
          if(out!==null&&out.length>8){
            var pr=printable(out,40);
            S({m:'▷a.b.b['+qs[qi]+'|'+us[ui]+'] len='+out.length+' '+pr});
            if(pr.charAt(0)==='{'){ jsonHit=true; content=out; S({m:'★★★ JSON 到手! len='+out.length+' head='+pr}); }
          }
        }catch(e){ if(ui+qi<3)S({m:'a.b.b 异常('+us[ui]+'/'+qs[qi]+'): '+String(e).slice(0,110)}); }
        Java.use('java.lang.Thread').sleep(30);
      }
    }
  }
  // ③ 若有 JSON → content → unlock(cid, pair) 真形态
  if(jsonHit&&content){
    try{
      var jstr=Java.use('java.lang.String').$new(content,'UTF-8')+'';
      var JO=Java.use('org.json.JSONObject').$new(jstr);
      var cstr=JO.optString('content','');
      var typ=JO.optString('type','');
      S({m:'◆JSON.type='+typ+' content len='+(''+cstr).length+' head='+clipX(''+cstr,48)});
      var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
      var U4=FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
      var combos=[[cid+'',book+'_'+cid],[book+'',book+'_'+cid],[cid+'',book],['','']];
      for(var m=0;m<combos.length;m++){
        var r=U4.call(FU,cstr,combos[m][0],combos[m][1],null);
        var st=r.status.value, sz=r.dataSize.value;
        S({m:'⟨正文⟩unlock('+combos[m][0].slice(0,14)+','+combos[m][1].slice(0,20)+') status='+st+' sz='+sz});
        if(st===0){ var d=r.data; var a2=[];for(var k=0;k<sz&&k<60000;k++)a2.push(d[k]); S({m:'████████ 正文命中!!',b64:toB64(Java.array('byte',a2)),ascii:printable(a2,150)}); break; }
        Java.use('java.lang.Thread').sleep(40);
      }
    }catch(e){S({m:'JSON/unlock 段异常 '+String(e).slice(0,140)});}
  }
  function clipX(s,n){return s.length>n?s.slice(0,n)+'…':s;}
  S({m:'v34 done jsonHit='+jsonHit});
});
setTimeout(function(){try{Java.perform(function(){S({m:'hb'});});}catch(e){}},15000);
})();