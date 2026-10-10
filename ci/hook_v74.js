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
  // ① 递归收集所有叶子字符串 (Content/Blocks/Resources 可能是嵌套 object/array!)
  var keys=[];
  var it=JO.keys();
  while(it.hasNext()){ var k=''+it.next(); keys.push(k); }
  S({m:'顶层字段: '+keys.join(' | ')});
  var strs=[];
  function walk(v,path,depth){
    try{
      var t=typeof v; var cls=(v&&v.$className)||'';
      if(t==='string'||cls==='java.lang.String'){ if((''+v).length>50){ strs.push([path,''+v]); S({m:'◆叶子['+path+'] len='+(''+v).length+' head='+clipX(''+v,70)}); } return; }
      if(cls==='[B'||cls==='byte[]'){ S({m:'◆bytes['+path+'] len='+v.length}); return; }
      var vs=''+v;
      if(vs.charAt(0)==='['){
        var JA=Java.cast(v,Java.use('org.json.JSONArray'));
        S({m:'·数组['+path+'] n='+JA.length()});
        for(var i=0;i<Math.min(JA.length(),12);i++) walk(JA.get(i),path+'['+i+']',depth+1);
        return;
      }
      if(vs.charAt(0)==='{'){
        var J2=Java.cast(v,Java.use('org.json.JSONObject'));
        var it2=J2.keys(); var ks2=[];
        while(it2.hasNext())ks2.push(''+it2.next());
        S({m:'·对象['+path+'] {'+ks2.join(', ')+'}'});
        if(depth<4)for(var j=0;j<ks2.length;j++) walk(J2.get(ks2[j]),path+'.'+ks2[j],depth+1);
        return;
      }
      S({m:'·值['+path+'] = '+clipX(vs,60)});
    }catch(e){ S({m:'['+path+'] walk异常 '+String(e).slice(0,50)}); }
  }
  for(var ki=0;ki<keys.length;ki++){
    try{ walk(JO.get(keys[ki]),keys[ki],0); }catch(e){S({m:'['+keys[ki]+'] 读失败'});}
  }
  // ② 每个大字符串 × unlock 形态; ★bad base-64 证明 unlock 内部先 b64 解码 data → 同时试 原串/b64(原串)
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil').INSTANCE.value;
  var U4=FU.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
  S({m:'★候选字符串字段 '+strs.length+' 个'});
  function b64e(sv){ try{ return Java.use('android.util.Base64').encodeToString(Java.use('java.lang.String').$new(sv).getBytes('UTF-8'),2)+''; }catch(e){ return sv; } }
  for(var si=0;si<strs.length;si++){
    var tag=strs[si][0], val=strs[si][1];
    var datas=[[val+'',0],[b64e(val),1]];
    var combos=[[cid+'',book+'_'+cid],[book+'',book+'_'+cid]];
    for(var di=0;di<2;di++)for(var m=0;m<2;m++){
      try{
        var r=U4.call(FU,datas[di][0],combos[m][0],combos[m][1],null);
        var st=r.status.value, sz=r.dataSize.value;
        S({m:'⟨'+tag+'|d'+di+'|c'+m+'⟩status='+st+(sz>0?' sz='+sz+' head='+clipX(''+Java.use('java.lang.String').$new(r.data,'UTF-8'),60):'')});
        if(st===0){
          var d=r.data, a2=[]; for(var j2=0;j2<sz&&j2<80000;j2++)a2.push(d[j2]);
          var b64=Java.use('android.util.Base64').encodeToString(Java.array('byte',a2),2)+'';
          S({m:'████████ 正文命中!! field='+tag+' data'+di+' combo'+m, b64:b64});
          return;
        }
      }catch(e){ if(di+m<2)S({m:'⟨'+tag+'|d'+di+'|c'+m+'⟩异常 '+String(e).slice(0,60)}); }
      Java.use('java.lang.Thread').sleep(25);
    }
  }
  // ★②.5 全量 Content/JSON 回传 (定局件: Content 已是明文正文)
  for(var fi=0;fi<strs.length;fi++){
    if(strs[fi][0]==='Content'||strs[fi][0]==='AuthorComments.AuthorComments'){
      try{
        var cb=Java.use('java.lang.String').$new(strs[fi][1]).getBytes('UTF-8');
        var ab2=[];for(var ci=0;ci<cb.length;ci++)ab2.push(cb[ci]);
        S({m:'★FULL['+strs[fi][0]+'] len='+cb.length, b64:Java.use('android.util.Base64').encodeToString(Java.array('byte',ab2),2)+''});
      }catch(e){S({m:'FULL 失败 '+String(e).slice(0,60)});}
    }
  }
  try{ var jb=[];for(var jj=0;jj<out.length;jj++)jb.push(out[jj]);
    S({m:'★FULL[JSON]', b64:Java.use('android.util.Base64').encodeToString(Java.array('byte',Java.array('byte',jb)),2)+''}); }catch(e){}
  // ③ 整串 JSON 也喂一次
  try{
    var r3=U4.call(FU,jstr,cid,book+'_'+cid,null);
    S({m:'⟨whole⟩status='+r3.status.value+' sz='+r3.dataSize.value});
  }catch(e){}
  S({m:'v35 done'});
});
})();