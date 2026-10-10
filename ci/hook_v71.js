// hook_v71.js — v32: ★真参数(字节码实锤) unlock(content, str(chapterId), book_cid, handler)
// 关键修正: 之前30轮 str2 全用 bookId(书签形态), 正文形态 str2=chapterId 从未试过!
// 自愈链: -3→setup(qimei16)重试 / -4|-5→setup+requestKeySync(bookId)重试
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function fget(obj,name){try{var f=obj.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(obj);}catch(e){return null;}}
function jint(v){if(v===null||v===undefined)return null;try{return v.intValue();}catch(e){try{return parseInt(''+v,10);}catch(e2){return null;}}}
function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||100);i++){var c=a[i]&255;s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
function bArr(jstr){var s=Java.use('java.lang.String').$new(''+jstr).getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
function plain(tag,r,enc){
  if(r===null||r===undefined){S({m:tag+' → null'});return false;}
  try{
    var st=jint(fget(r,'status'));
    var data=fget(r,'data');
    if(st===0&&data){
      var jb=Java.cast(data,Java.use('[B'));
      var a=[];for(var i=0;i<jb.length;i++)a.push(jb[i]&255);
      var pr=0;for(var i=0;i<Math.min(a.length,200);i++){var c=a[i];if(c>=32&&c<127||c>127)pr++;}
      S({m:'█████命中!! '+tag+' status=0 len='+a.length});
      S({m:'█HEAD='+asc(a.slice(0,120),120)});
      var b64=Java.use('android.util.Base64').encodeToString(Java.array('byte',a.slice(0,Math.min(a.length,8000))),2)+'';
      S({m:'█PLAIN_B64='+b64});
      return true;
    }
    S({m:'·'+tag+' status='+st});
    return st;
  }catch(e){S({m:tag+' 读异常 '+String(e).slice(0,60)});return false;}
}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  var book=P.book+'', cid=P.cid+'';
  var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FU=FUc.INSTANCE.value;
  var FK=Java.use('com.yuewen.fock.Fock');
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var qimei16=''+P.imei16;
  S({m:'v32 开跑; qimei16='+qimei16.slice(0,6)+'… pair='+book+'_'+cid});

  var U4=FUc.unlock.overload('java.lang.String','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler');
  var U2=FUc.unlock.overload('java.lang.String','java.lang.String');

  function tryUnlock(tag,content){
    var r=null;
    try{ r=U4.call(FU,content,cid,book+'_'+cid,null); }          // ★正文形态 str2=cid
    catch(e){ S({m:tag+' U4异常 '+String(e).slice(0,50)}); return false; }
    var st=plain(tag+'(cid,pair)',r);
    if(st===true)return true;
    // -5/-4/-2 → 自愈链: setup(qimei16) + requestKeySync(bookId) 再原参重试
    if(st===-5||st===-4||st===-2){
      try{ FK.setup.overload('java.lang.String').call(null,qimei16); S({m:tag+' ↻ setup(qimei16) OK'}); }catch(e){S({m:tag+' setup异常 '+String(e).slice(0,60)});}
      try{ var rks=FUc.requestKeySync.overload('android.content.Context','long'); rks.call(FU,ctx,Java.use('java.lang.Long').$new(book)); S({m:tag+' ↻ requestKeySync OK'}); }catch(e){S({m:tag+' rks异常 '+String(e).slice(0,70)});}
      try{ var r2=U4.call(FU,content,cid,book+'_'+cid,null); if(plain(tag+'-retry',r2)===true)return true; }catch(e){}
      // 书签形态兜底 (str2=book)
      try{ var r3=U4.call(FU,content,book,book+'_'+cid,null); if(plain(tag+'(book,pair)',r3)===true)return true; }catch(e){}
    }
    if(st===-3){
      try{ FK.setup.overload('java.lang.String').call(null,qimei16); }catch(e){}
      try{ var r4=U4.call(FU,content,cid,book+'_'+cid,null); if(plain(tag+'-r3',r4)===true)return true; }catch(e){}
    }
    return false;
  }

  var hit=false;
  // ═ 素材 1: 设备侧 URL→下载→.qd→x.n0 五段切分 (JSON.content 送 unlock)
  var payload=null, segs=[];
  try{
    if(P.payload_b64){
      payload=Java.use('android.util.Base64').decode(P.payload_b64,2);
    } else if(P.blob_b64){
      var bb=Java.use('android.util.Base64').decode(P.blob_b64,2);
      var r0=FK.unlockData.overload('[B','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler').call(FK,bb,book,book+'_'+cid,null);
      var st0=jint(fget(r0,'status'));
      if(st0===0){
        var db=Java.cast(fget(r0,'data'),Java.use('[B'));
        var s='';for(var q=0;q<db.length;q++){var c=db[q]&255;if(c>=33&&c<=126)s+=String.fromCharCode(c);}
        var si=s.indexOf('https://'); var url=si>=0?s.slice(si):'';
        if(url){
          var zipPath='/data/data/com.qidian.QDReader/cache/ch32.zip';
          var con=Java.use('java.net.URL').$new(url+'').openConnection();
          con.setConnectTimeout(20000);con.setReadTimeout(30000);con.setRequestProperty('User-Agent','okhttp/4.9.0');
          var ins=con.getInputStream();
          var fos=Java.use('java.io.FileOutputStream').$new(zipPath);
          var buf=Java.array('byte',new Array(8192));var n;
          while((n=ins.read(buf))>0)fos.write(buf,0,n);
          fos.close();ins.close();
          var ZF=Java.use('java.util.zip.ZipFile').$new(zipPath);
          var en=ZF.entries();var e0=null;
          while(en.hasMoreElements()){var e=en.nextElement();if((''+e.getName()).indexOf('.qd')>=0)e0=e;}
          if(!e0){var en2=ZF.entries();while(en2.hasMoreElements())e0=en2.nextElement();}
          var is=ZF.getInputStream(e0);
          var zbuf=Java.array('byte',new Array(65536));var zout=Java.use('java.io.ByteArrayOutputStream').$new();var zn;
          while((zn=is.read(zbuf))>0)zout.write(zbuf,0,zn);
          is.close();ZF.close();
          var qdB=zout.toByteArray();
          function u32(idx){return ((qdB[idx]&255)|((qdB[idx+1]&255)<<8)|((qdB[idx+2]&255)<<16)|((qdB[idx+3]&255)<<24))>>>0;}
          var off=0;var nPv=0;
          for(var g=0;g<5;g++){
            if(off+4>qdB.length)break;
            var L=u32(off);off+=4;
            if(L===0||L>qdB.length-off){off-=4;break;}
            var seg=[];for(var k=0;k<L;k++)seg.push(qdB[off+k]);
            segs.push(seg);off+=L;
            S({m:'#seg'+g+' len='+L+' head='+asc(seg,48)});
          }
          if(segs.length===0){
            var nP2=u32(4);var carr=[];for(var g8=8;g8<8+nP2;g8++)carr.push(qdB[g8]);
            payload=Java.array('byte',carr);
          }
          S({m:'# 切分段数='+segs.length+' payload='+(payload?payload.length:0)});
        }
      }
    }
  }catch(e1){S({m:'# 素材链异常 '+String(e1).slice(0,100)});}

  // ═ 素材 2: 各段/变体 → tryUnlock
  function segB64(seg){return Java.use('android.util.Base64').encodeToString(Java.array('byte',seg.slice()),2)+'';}
  // 5 段结构下: seg1=VIP密文块→x.B 前还有 a.b.b; 直接尝试把各段作为 content
  var mats=[];
  if(segs.length>=2){
    mats.push(['seg1-b64',segB64(segs[1])]);
    mats.push(['seg1-raw',Java.use('java.lang.String').$new(Java.array('byte',segs[1].slice()),'UTF-8')+'']);
  }
  if(payload){
    mats.push(['pay-b64',Java.use('android.util.Base64').encodeToString(payload,2)+'']);
    // payload 前 8B 可能是头
    var tail=[];for(var i2=8;i2<payload.length;i2++)tail.push(payload[i2]);
    mats.push(['pay[8:]-b64',Java.use('android.util.Base64').encodeToString(Java.array('byte',tail),2)+'']);
    mats.push(['pay-raw',Java.use('java.lang.String').$new(payload,'UTF-8')+'']);
  }
  for(var mi=0;mi<mats.length;mi++){
    if(hit)break;
    var mt=mats[mi];
    var c=mt[1];
    if(c.length>4000){ c=c.slice(0,0)+mt[1]; }  // 原样
    S({m:'▷素材 '+mt[0]+' len='+mt[1].length});
    hit=tryUnlock(mt[0],mt[1]);
  }
  // ═ 若 JSON 假说: content 字段可能在某段里是 JSON —— 尝试把可打印段 parse JSON 取 content
  if(!hit&&segs.length){
    for(var gs=0;gs<segs.length;gs++){
      if(hit)break;
      try{
        var strG=Java.use('java.lang.String').$new(Java.array('byte',segs[gs].slice()),'UTF-8')+'';
        if(strG.indexOf('content')>=0||strG.charAt(0)==='{'){
          var JO=Java.use('org.json.JSONObject').$new(strG);
          var content=JO.optString('content')+'';
          var ctype=JO.optInt('type',-1);
          S({m:'▷seg'+gs+' 是JSON type='+ctype+' content len='+content.length});
          if(content.length>10){ hit=tryUnlock('json'+gs,content); }
        }
      }catch(ej){}
    }
  }
  S({m:'v32 done hit='+hit});
});
