// hook_v61.js — v21: FockUtil 反射枚举 + unlock/unlockBytes/unlock$default 矩阵
// FockResult 真字段 errCode/data/message (v20d 用 .status/.length 全 TypeError)
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function bytesFromJava(jb){var a=[];for(var i=0;i<jb.length;i++)a.push(jb[i]);return Java.array('byte',a);}
function headAscii(jb,n){
  var s='',m=n||120,tot=0,pr=0;
  try{tot=jb.length;if(tot<m)m=tot;}catch(e){return {s:'?',tot:0,pr:0};}
  for(var i=0;i<tot;i++){
    var c=jb[i]&255;
    var ok=(c>=0x20&&c<0x7f);
    if(!ok&&i+2<tot){var cp=((c&0x0f)<<12)|((jb[i+1]&0x3f)<<6)|(jb[i+2]&0x3f);if((c&0xe0)===0xe0&&cp>0x2000)ok=1;}
    if(ok)pr++;
    if(i<m)s+=(c>=0x20&&c<0x7f)?String.fromCharCode(c):'.';
  }
  return {s:s,tot:tot,pr:tot?pr/tot:0};
}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  S({m:'params: payload='+((P.payload_b64||'').length)+' book='+P.book+' cid='+P.cid});
  var book=P.book+'', cid=P.cid+'', md5=P.md5||'', bk=P.batch_key||'';
  var B64=Java.use('android.util.Base64');
  var payloadArr=bytesFromJava(B64.decode(P.payload_b64,2));
  var b64=B64.encodeToString(payloadArr,2)+'';
  S({m:'payload bytes='+payloadArr.length+' b64='+b64.length});
  // ★ FockResult 真字段名
  var fields=[];
  try{
    var frs=Java.use('com.yuewen.fock.Fock$FockResult').class.getDeclaredFields();
    for(var i=0;i<frs.length;i++)fields.push(frs[i].getName()+':'+frs[i].getType().getName());
  }catch(e){S({m:'FockResult 字段枚举失败 '+String(e).slice(0,100)});}
  S({m:'◆FR字段 '+fields.join(' | ')});
  function fget(obj,name){try{var f=obj.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(obj);}catch(e){return null;}}
  function jint(v){if(v===null||v===undefined)return null;try{return v.intValue();}catch(e){try{return parseInt(''+v,10);}catch(e2){return null;}}}
  function report(tag,r){
    if(r===null||r===undefined){S({m:tag+' → null'});return;}
    try{
      var st=jint(fget(r,'status')); if(st===null)st=jint(fget(r,'errCode'));
      var data=fget(r,'data');
      var ds=jint(fget(r,'dataSize'));
      var msg=fget(r,'message');
      var stN=(st===null)?'?':(''+st);
      if(!data){S({m:tag+' status='+stN+' dataSize='+ds+' data=null msg='+(''+(msg||'')).slice(0,60)});return;}
      var jb;
      try{jb=Java.cast(data,Java.use('[B'));}catch(e1){jb=data;}
      var h=headAscii(jb,120);
      var star=(stN==='0'||h.pr>0.8)?'★ ':'';
      S({m:star+tag+' status='+stN+' dataSize='+ds+' len='+h.tot+' print='+h.pr.toFixed(2)+' asc='+h.s+' msg='+(''+(msg||'')).slice(0,40)});
      if(star){
        var n=h.tot>4096?4096:h.tot, arr=[];
        for(var k=0;k<n;k++)arr.push(jb[k]);
        S({m:'★PLAIN_B64='+B64.encodeToString(Java.array('byte',arr),2)});
      }
    }catch(e){S({m:tag+' 读异常 '+String(e).slice(0,110)});try{S({m:tag+' raw='+(''+r).slice(0,150)});}catch(e2){}}
  }
  // 反射枚举 FockUtil
  var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var meths=FU.class.getDeclaredMethods();
  var table=[];
  for(var j=0;j<meths.length;j++){
    var mm=meths[j];
    var ps=mm.getParameterTypes(), pn=[];
    for(var k=0;k<ps.length;k++)pn.push(ps[k].getName());
    var line=mm.getName()+'('+pn.join(',')+')->'+mm.getReturnType().getName();
    table.push(line);
    if(/nlock|ytes|ey/.test(mm.getName())){try{mm.setAccessible(true);}catch(e){}}
  }
  S({m:'◆FU表 n='+table.length});
  for(var t=0;t<table.length;t++)S({m:'◆FU|'+table[t]});
  var inst=null;
  try{inst=FU.INSTANCE.value;}catch(e){S({m:'INSTANCE 取失败 '+String(e).slice(0,80)});}
  S({m:'INSTANCE='+(inst===null?'NULL':'ok')});
  function findM(name,npar){var r=[];for(var i=0;i<meths.length;i++){if(meths[i].getName()===name&&meths[i].getParameterTypes().length===npar)r.push(meths[i]);}return r;}
  function isHandler(tn){return /ErrorLogHandler|Handler/.test(tn);}
  var idx=0;
  function callM(m,args,tag){
    var my=idx++;
    S({m:'pre|'+my+'|'+tag});
    try{var r=m.invoke(inst,args);report(tag,r);}
    catch(e){S({m:tag+' EX '+String(e).slice(0,140)});}
  }
  // unlock(String,String)
  var u2=findM('unlock',2);
  var pairs=[[b64,book],[b64,book+'_'+cid],[b64,md5],[b64,bk],[book+'_'+cid,b64],[b64,'']];
  for(var a=0;a<u2.length;a++){
    var ps=u2[a].getParameterTypes();
    if(ps[0].getName()!=='java.lang.String'||ps[1].getName()!=='java.lang.String'){S({m:'unlock2 跳过非String签名 '+ps[0].getName()});continue;}
    for(var p=0;p<pairs.length;p++)callM(u2[a],[pairs[p][0],pairs[p][1]],'unlock2['+p+'] '+(p<4?'k'+(p):'alt'+p));
  }
  if(!u2.length)S({m:'无 unlock(2参)'});
  // unlock(String,String,String,ErrorLogHandler)
  var u4=findM('unlock',4);
  var triples=[[b64,book,book+'_'+cid],[b64,book+'_'+cid,book]];
  for(var b=0;b<u4.length;b++){
    var ps4=u4[b].getParameterTypes();
    if(ps4[0].getName()!=='java.lang.String'){S({m:'unlock4 跳过签名 '+ps4[0].getName()});continue;}
    for(var q=0;q<triples.length;q++)callM(u4[b],[triples[q][0],triples[q][1],triples[q][2],null],'unlock4['+q+']');
  }
  if(!u4.length)S({m:'无 unlock(4参)'});
  // unlockBytes: 按反射签名动态构参
  var ub=[];
  for(var c=0;c<meths.length;c++){if(meths[c].getName().indexOf('unlockBytes')===0&&meths[c].getName().indexOf('$')<0)ub.push(meths[c]);}
  S({m:'unlockBytes 重载数='+ub.length});
  var Str=Java.use('java.lang.String');
  var b64bytes=Str.$new(b64).getBytes();
  for(var d=0;d<ub.length;d++){
    var psp=ub[d].getParameterTypes();
    var built=null,skip=0,desc=[];
    var args=[];
    for(var e=0;e<psp.length;e++){
      var tn=psp[e].getName();
      if(tn==='[B'){args.push(e===0?payloadArr:b64bytes);desc.push('byte[]');}
      else if(tn==='java.lang.String'){args.push(e===0?b64:(e%2?book:book+'_'+cid));desc.push('String');}
      else if(tn==='int'||tn==='java.lang.Integer'){args.push(Java.use('java.lang.Integer').$new(payloadArr.length));desc.push('int');}
      else if(isHandler(tn)||tn==='java.lang.Object'){args.push(null);desc.push('null');}
      else {skip=1;desc.push('SKIP:'+tn);break;}
    }
    if(skip){S({m:'unlockBytes['+d+'] 跳过 '+desc.join(',')});continue;}
    callM(ub[d],args,'unlockBytes['+d+']('+desc.join(',')+')');
  }
  // unlock$default 7参
  var udef=findM('unlock$default',7);
  if(!udef.length)udef=findM('unlock$default',6);
  S({m:'unlock$default 命中='+udef.length+(udef.length?' 参='+udef[0].getParameterTypes().length:'')});
  for(var f=0;f<udef.length;f++){
    var pd=udef[f].getParameterTypes(), ad=[], dd=[], sk2=0;
    for(var g=0;g<pd.length;g++){
      var tn2=pd[g].getName();
      if(tn2.indexOf('FockUtil')>=0){ad.push(inst);dd.push('inst');}
      else if(tn2==='java.lang.String'){ad.push(dd.filter(function(x){return x==='String';}).length===0?b64:(dd.filter(function(x){return x==='String';}).length===1?book:book+'_'+cid));dd.push('String');}
      else if(isHandler(tn2)||tn2==='java.lang.Object'){ad.push(null);dd.push('null');}
      else if(tn2==='int'||tn2==='java.lang.Integer'){ad.push(Java.use('java.lang.Integer').$new(0));dd.push('int');}
      else {sk2=1;dd.push('SKIP:'+tn2);break;}
    }
    if(sk2){S({m:'unlock$default['+f+'] 跳过 '+dd.join(',')});continue;}
    callM(udef[f],ad,'unlock$default['+f+']('+dd.join(',')+')');
    // 第2组: 交换两个 key 串
    var ad2=ad.slice(), n=0;
    for(var h=0;h<pd.length;h++){if(pd[h].getName()==='java.lang.String'){n++;if(n===2)ad2[h]=book+'_'+cid;if(n===3)ad2[h]=book;}}
    callM(udef[f],ad2,'unlock$default['+f+']b(keys swapped)');
  }
  // addMap 是否存在 (只报签名, 不调用)
  for(var z=0;z<table.length;z++){if(/addMap|requestKey/.test(table[z]))S({m:'◇可注册 '+table[z]});}
  S({m:'v21 done'});
});
