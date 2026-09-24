// hook_v74.js — v35: a.b.b→JSON 全字段遍历 + 每个大字符串字段 × unlock(cid,pair)
// v34b: JSON 到手(AuthorComments…), content 键名取空 → 遍历真键名
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function bArr(jstr){var s=Java.use('java.lang.String').$new(''+jstr).getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
function clipX(s,n){s=''+s;return s.length>n?s.slice(0,n)+'…':s;}
(function(){
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var PAY=Java.array('byte',(function(){var raw=Java.use('android.util.Base64').decode(P.payload_b64,2);var a=[];for(var i=0;i<raw.length;i++)a.push(raw[i]);return a;})());
  var book=P.book+'', cid=P.cid+'', uk=P.userKey+'';
  S({m:'v35 开跑'});
  var AB=Java.use('a.b'); var ab=AB.b.overload('long','long','[B','long','java.lang.String'); var ABi=AB.$new();
  var out=ab.call(ABi, parseInt(book), parseInt(cid), PAY, 0, uk);
  if(out===null||out.length<10){S({m:'a.b.b 失败 len='+(out?out.length:'null')});return;}
  var jstr=Java.use('java.lang.String').$new(out,'UTF-8')+'';
  S({m:'JSON='+jstr.length+'B'});
  var JO;
  try{ JO=Java.use('org.json.JSONObject').$new(jstr); }catch(e){ S({m:'JSON parse 失败 '+String(e).slice(0,80)+' head='+clipX(jstr,80)}); return; }
  // ① 全顶层字段
  var keys=[];
  var it=JO.keys();
  while(it.hasNext()){ var k=''+it.next(); keys.push(k); }
  S({m:'顶层字段: '+keys.join(' | ')});
  var strs=[];
  for(var ki=0;ki<keys.length;ki++){
    try{
      var v=JO.get(keys[ki]);
      var vs=''+v;
      S({m:'◆['+keys[ki]+'] type='+(typeof v)+' len='+vs.length+' head='+clipX(vs,60)});
      if(typeof v==='string'||v.$className==='java.lang.String'){ if(vs.length>50) strs.push([keys[ki],vs]); }
      // 嵌套一层 (AuthorComments 是对象)
      try{
        if(vs.charAt(0)==='{'){
          var J2=Java.use('org.json.JSONObject').$new(vs); var it2=J2.keys();
          while(it2.hasNext()){ var k2=''+it2.next(); try{var v2=''+J2.get(k2); if(v2.length>50){strs.push([keys[ki]+'.'+k2,v2]); S({m:'  ·['+keys[ki]+'.'+k2+'] len='+v2.length+' head='+clipX(v2,60)});} }catch(e3){} }
        }
      }catch(e4){}
    }catch(e){S({m:'['+keys[ki]+'] 读失败'});}
  }
  // ② 每个大字符串 × unlock 形态
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var U4=FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
  S({m:'★候选字符串字段 '+strs.length+' 个'});
  for(var si=0;si<strs.length;si++){
    var tag=strs[si][0], val=strs[si][1];
    var combos=[[cid+'',book+'_'+cid],[book+'',book+'_'+cid]];
    for(var m=0;m<2;m++){
      try{
        var r=U4.call(FU,val,combos[m][0],combos[m][1],null);
        var st=r.status.value, sz=r.dataSize.value;
        S({m:'⟨'+tag+'|'+m+'⟩status='+st+(sz>0?' sz='+sz+' head='+clipX(''+Java.use('java.lang.String').$new(r.data,'UTF-8'),50):'')});
        if(st===0){
          var d=r.data, a2=[]; for(var j2=0;j2<sz&&j2<80000;j2++)a2.push(d[j2]);
          var b64=Java.use('android.util.Base64').encodeToString(Java.array('byte',a2),2)+'';
          S({m:'████████ 正文命中!! field='+tag+' combo='+m, b64:b64});
          return;
        }
      }catch(e){S({m:'⟨'+tag+'|'+m+'⟩异常 '+String(e).slice(0,70)});}
      Java.use('java.lang.Thread').sleep(30);
    }
  }
  // ③ 整串 JSON 也喂一次
  try{
    var r3=U4.call(FU,jstr,cid,book+'_'+cid,null);
    S({m:'⟨whole⟩status='+r3.status.value+' sz='+r3.dataSize.value});
  }catch(e){}
  S({m:'v35 done'});
});
})();