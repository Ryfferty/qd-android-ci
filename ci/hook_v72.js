// hook_v72.js — v33: 全链收官车 seg1→(3DES双遍)→JSON→content→unlock(cid,pair)
// 算法=SEG1_JSON_FINDINGS: k1=b64(HmacSHA1(qimei, uid+SALT+cid))[:24]; k2=b64(HMAC-MD5(k1, cid+SALT))[:24]; 3DES-CBC(iv0,PKCS5)×2
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function fget(obj,name){try{var f=obj.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(obj);}catch(e){return null;}}
function jint(v){if(v===null||v===undefined)return null;try{return v.intValue();}catch(e){try{return parseInt(''+v,10);}catch(e2){return null;}}}
function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||100);i++){var c=a[i]&255;s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var book=P.book+'', cid=P.cid+'';
  var SALT='2EEE1433A152E84B3756301D8FA3E69A';
  var q16=P.imei16+'';
  S({m:'v33 开跑; qimei16='+(q16?q16.slice(0,6)+'…':'缺!')+' payload='+(P.payload_b64?Math.floor(P.payload_b64.length*3/4):0)});

  function b64enc(bytes){return Java.use('android.util.Base64').encodeToString(bytes,0)+'';} // flag0=标准带padding
  function hmac(alg,keyStr,msgStr){
    var K=Java.use('javax.crypto.spec.SecretKeySpec');
    var M=Java.use('javax.crypto.Mac');
    var mac=M.getInstance(alg);
    mac.init(K.$new(Java.use('java.lang.String').$new(keyStr).getBytes('UTF-8'),alg==='HmacSHA1'?'HmacSHA1':'HmacMD5'));
    return mac.doFinal(Java.use('java.lang.String').$new(msgStr).getBytes('UTF-8'));
  }
  function des3dec(data,keyStr){
    var C=Java.use('javax.crypto.Cipher');
    var K=Java.use('javax.crypto.spec.SecretKeySpec');
    var IV=Java.use('javax.crypto.spec.IvParameterSpec');
    var kb=Java.use('java.lang.String').$new(keyStr).getBytes('UTF-8');
    var k24=kb.length===16?Java.array('byte',(function(){var a=[];for(var i=0;i<16;i++)a.push(kb[i]);for(var i=0;i<8;i++)a.push(kb[i]);return a;})()):kb;
    var c=C.getInstance('DESede/CBC/PKCS5Padding');
    c.init(2,K.$new(k24,'DESede'),IV.$new(Java.array('byte',[0,0,0,0,0,0,0,0])));
    return c.doFinal(data);
  }
  function u64(arr,o){return ((arr[o]&255)+((arr[o+1]&255)<<8)+((arr[o+2]&255)<<16)+((arr[o+3]&255)*16777216));}

  // ── userId 候选: 反射 QDUserManager + 常量
  var uids=['0','1','1000000'];
  try{
    var QM=Java.use('com.qidian.QDReader.model.manager.user.UserManagerImpl');
    S({m:'QM loaded'});
  }catch(e){}
  try{
    // 常见: 静态单例 .k() / getInstance().getUserId()
    var cands=['com.qidian.QDReader.model.manager.user.UserManagerImpl','com.qidian.QDReader.model.user.UserManagerImpl','com.qidian.QDReader.manager.user.UserManagerImpl'];
    for(var ci=0;ci<cands.length;ci++){
      try{
        var U=Java.use(cands[ci]);
        try{ var inst=U.g.value; }catch(e0){}
        try{ var inst=U.e.value; }catch(e1){}
        var mm=U.class.getDeclaredMethods();
        for(var mi=0;mi<mm.length;mi++){
          var nm=''+mm[mi].getName();
          if(nm==='k'||nm==='getUserId'||nm==='f'){
            try{
              mm[mi].setAccessible(true);
              if(mm[mi].isStatic()){var v=''+mm[mi].invoke(null);}
              else if(inst){var v=''+mm[mi].invoke(inst);}
              if(v&&/^[0-9]{3,}$/.test(v)&&uids.indexOf(v)<0){uids.unshift(v);S({m:'◆反射 userId='+v.slice(0,6)+'… from '+cands[ci]+'.'+nm});}
            }catch(ei){}
          }
        }
        break;
      }catch(eu){}
    }
  }catch(e){S({m:'uid 反射总异常 '+String(e).slice(0,60)});}
  // currentUserKey 派生? userId 可能就是 0 (未登录)
  S({m:'uid 候选: '+uids.join(', ')});

  // ── seg1 提取: payload 整块 + 头跳 4/8/12
  var payRaw=Java.use('android.util.Base64').decode(P.payload_b64,2);
  var payB=[];for(var i=0;i<payRaw.length;i++)payB.push(payRaw[i]);
  S({m:'payload='+payB.length+'B u32[0]='+u64(payB,0)+' u32[4]='+u64(payB,4)+' u32[8]='+u64(payB,8)});
  var segs={};
  function slice(a,s,l){var r=[];for(var i=0;i<l&&s+i<a.length;i++)r.push(a[s+i]);return Java.array('byte',r);}
  segs['full']=payRaw;
  var L0=u64(payB,0), L4=u64(payB,4), L8=u64(payB,8);
  if(L4>0&&L4<payB.length-8)segs['[8:+u32_4]']=slice(payB,8,Math.min(L4,payB.length-8));
  if(L8>0&&L8<payB.length-12)segs['[12:+u32_8]']=slice(payB,12,Math.min(L8,payB.length-12));
  if(L0>0&&L0<payB.length-4)segs['[4:+u32_0]']=slice(payB,4,Math.min(L0,payB.length-4));

  // ── 主矩阵: seg × uid × qimei(q16/userKey) → JSON → unlock
  var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FU=FUc.INSTANCE.value;
  var U4=FUc.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
  var qimes={}; if(q16&&q16.length>=12)qimes['q16']=q16; if(P.userKey)qimes['uk']=P.userKey;
  var hit=false, jsonHit=false;
  for(var sn in segs){
    if(jsonHit)break;
    var sd=segs[sn];
    if(sd.length%8!==0){continue;}
    for(var uidI=0;uidI<uids.length&&!jsonHit;uidI++){
      for(var qn in qimes){
        if(jsonHit)break;
        try{
          var uid=''+uids[uidI], qm=''+qimes[qn];
          var k1=b64enc(hmac('HmacSHA1',qm,uid+SALT+cid)).substring(0,24);
          var k2=b64enc(hmac('HmacMD5',k1,cid+SALT)).substring(0,24);
          var r1=null,r2=null;
          try{ r1=des3dec(sd,k2); }catch(e1){ continue; }
          try{ r2=des3dec(r1,k2); }catch(e2){ r2=null; }
          var out=r2||r1;
          var strOut=Java.use('java.lang.String').$new(out,'UTF-8')+'';
          var printable=strOut.substring(0,Math.min(60,out.length));
          S({m:'▷'+sn+'|uid='+uid+'|'+qn+' →'+(r2?'2遍':'1遍')+' head='+printable.slice(0,50)});
          if(strOut.charAt(0)==='{'||strOut.indexOf('content')>=0){
            jsonHit=true;
            S({m:'★★★ JSON 到手! seg='+sn+' uid='+uid+' qm='+qn});
            try{
              var JO=Java.use('org.json.JSONObject').$new(strOut);
              var content=JO.optString('content')+'';
              var ctype=JO.optInt('type',-1);
              S({m:'★JSON type='+ctype+' contentLen='+content.length+' raw head='+strOut.slice(0,160)});
              if(content.length>10){
                var rr=U4.call(FU,content,cid,book+'_'+cid,null);
                var st=jint(fget(rr,'status')); var dd=fget(rr,'data');
                if(st===0&&dd){
                  var jb=Java.cast(dd,Java.use('[B'));
                  var a=[];for(var i=0;i<jb.length;i++)a.push(jb[i]&255);
                  S({m:'█████ 正文!! len='+a.length});
                  S({m:'█BODY_B64='+Java.use('android.util.Base64').encodeToString(Java.array('byte',a.slice(0,Math.min(a.length,9000))),2)+''});
                  hit=true;
                } else S({m:'█unlock status='+st});
              }
            }catch(ej){S({m:'JSON parse 异常 '+String(ej).slice(0,80)});}
          }
        }catch(e){}
      }
    }
  }
  S({m:'v33 done jsonHit='+jsonHit+' bodyHit='+hit});
});
