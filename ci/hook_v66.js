// hook_v66.js — v27: v61 成功骨架 + [设备侧 unlockData→下载→取payload] + getter + 注册流(add/addMap/rks) + 注册后重打
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function fget(obj,name){try{var f=obj.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(obj);}catch(e){return null;}}
function jint(v){if(v===null||v===undefined)return null;try{return v.intValue();}catch(e){try{return parseInt(''+v,10);}catch(e2){return null;}}}
function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||60);i++){var c=a[i]&255;s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
function report(tag,r){
  if(r===null||r===undefined){S({m:tag+' → null'});return;}
  try{
    var st=jint(fget(r,'status')); if(st===null)st=jint(fget(r,'errCode'));
    var data=fget(r,'data'); var msg=''+(fget(r,'message')||'');
    if(!data){S({m:'·'+tag+' status='+st+' data=null '+String(msg).slice(0,20)});return;}
    var jb=Java.cast(data,Java.use('[B'));
    var a=[];for(var i=0;i<Math.min(jb.length,80);i++)a.push(jb[i]&255);
    var pr=0;for(var i=0;i<a.length;i++){if(a[i]>=32&&a[i]<127)pr++;}
    var line='★'+tag+' status='+st+' len='+jb.length+' print='+(a.length?(pr/a.length).toFixed(2):'-')+' asc='+asc(a,60);
    if(a.length&&pr/a.length>0.85){line+=' ██命中!!';
      var full=[];for(var i=0;i<Math.min(jb.length,4000);i++)full.push(jb[i]);
      S({m:'█PLAIN_B64='+Java.use('android.util.Base64').encodeToString(Java.array('byte',full),2)+''});}
    S({m:line});
  }catch(e){S({m:tag+' 读结果异常 '+String(e).slice(0,70)});}
}
Java.perform(function(){
  var P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');
  S({m:'params blob='+(P.blob_b64||'').length+' pre_payload='+((P.payload_b64||'').length)});
  if(!P.blob_b64)return;
  var book=P.book+'', cid=P.cid+'';
  var FK=Java.use('com.yuewen.fock.Fock');
  var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FU=FUc.INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();

  // ⓪ 拿 payload: 设备侧自解 blob → 新 URL → 下载 → ZipFile(path) 提取 (v15d 全 Java 路径)
  var PAY=null;
  try{
    var blobB=Java.use('android.util.Base64').decode(P.blob_b64,2);
    var r0=FK.unlockData.overload('[B','java.lang.String','java.lang.String','com.yuewen.fock.Fock$ErrorLogHandler').call(FK,blobB,book+'',book+'_'+cid,null);
    var st0=jint(fget(r0,'status')); var url=null;
    if(st0===0){
      var db=fget(r0,'data'); var dj=Java.cast(db,Java.use('[B'));
      var uas=[];for(var i=0;i<dj.length;i++){var c=dj[i]&255;if(c>=32&&c<127)uas.push(c);}
      url=String.fromCharCode.apply(null,uas.slice(0,uas.length-1).concat([])); // 去尾 \x00 类垃圾: 截到最后一个合法字符
      // 更稳: 找 https:// 起点 + 逐字符合法集截断
      var s='';for(var i=0;i<dj.length;i++){var c=dj[i]&255;if(c>=33&&c<=126)s+=String.fromCharCode(c);else if(s.length>10)break;}
      var si=s.indexOf('https://'); url=si>=0?s.slice(si):s;
      S({m:'⓪ unlockData=0 url len='+url.length+' head='+url.slice(0,60)});
    } else S({m:'⓪ unlockData status='+st0});
    if(url&&url.indexOf('https://')===0){
      var zipPath='/data/data/com.qidian.QDReader/cache/ch.zip';
      var URL=Java.use('java.net.URL'), con=URL.$new(url+'').openConnection();
      con.setConnectTimeout(20000); con.setReadTimeout(25000);
      con.setRequestProperty('User-Agent','okhttp/4.9.0');
      var ins=con.getInputStream();
      var fos=Java.use('java.io.FileOutputStream').$new(zipPath);
      var buf=Java.array('byte',new Array(8192)); var n, tot=0;
      while((n=ins.read(buf))>0){fos.write(buf,0,n);tot+=n;}
      fos.close(); ins.close();
      S({m:'⓪ zip 落盘='+tot+'B'});
      var ZF=Java.use('java.util.zip.ZipFile').$new(zipPath);
      var en=ZF.entries(); var e0=null;
      while(en.hasMoreElements()){var e=en.nextElement(); if((''+e.getName()).indexOf('.qd')>=0)e0=e;}
      if(!e0){var en2=ZF.entries(); while(en2.hasMoreElements())e0=en2.nextElement();}
      S({m:'⓪ 条目='+e0.getName()+' comp='+e0.getMethod()+' size='+e0.getSize()});
      var is=ZF.getInputStream(e0);
      var zbuf=Java.array('byte',new Array(65536)); var zout=Java.use('java.io.ByteArrayOutputStream').$new(); var zn;
      while((zn=is.read(zbuf))>0)zout.write(zbuf,0,zn);
      is.close(); ZF.close();
      var qdBytes=Java.cast(zout.toByteArray(),Java.use('[B'));
      // .qd 头: [u32=0][u32=nP][payload]  (Java byte → int 手工小端)
      function u32(idx){return ((qdBytes[idx]&255)|((qdBytes[idx+1]&255)<<8)|((qdBytes[idx+2]&255)<<16)|((qdBytes[idx+3]&255)<<24))>>>0;}
      var nPv=u32(4);
      var carr=[];for(var g=8;g<8+nPv;g++)carr.push(qdBytes[g]);
      PAY=Java.array('byte',carr);
      S({m:'⓪★ PAY 设备侧自取='+PAY.length+'B nP='+nPv});
    }
  }catch(e){S({m:'⓪ 设备侧链异常 '+String(e).slice(0,90)});}
  if(!PAY&&P.payload_b64){
    var dd=Java.use('android.util.Base64').decode(P.payload_b64,2);
    var arr=[];for(var i=0;i<dd.length;i++)arr.push(dd[i]);
    PAY=Java.array('byte',arr);
    S({m:'⓪ fallback runner payload='+PAY.length+'B'});
  }
  if(!PAY){S({m:'无 payload, 退出'});return;}
  var b64=Java.use('android.util.Base64').encodeToString(PAY,2)+'';

  // ① getter 直读 (App 钥匙)
  var gs=['get3DesKey','getNibKey','getRtKey','getCloudConfigKey','getAudioAesKey','getKey','getPreUserKey'];
  for(var g=0;g<gs.length;g++){
    try{ S({m:'◆ '+gs[g]+'() = '+String(FU[gs[g]].call(FU)).slice(0,44)});}catch(e){S({m:'◆ '+gs[g]+' 异常 '+String(e).slice(0,40)});}
  }
  try{ S({m:'◆ isHasKey()='+FU.isHasKey.call(FU)});}catch(e){}

  // ② 注册流 add/addMap (键池写入者)
  try{ FU.add.call(FU, book, book+'_'+cid); S({m:'② add(book,pair) OK'});}catch(e){S({m:'② add 异常 '+String(e).slice(0,60)});}
  try{ var hm=Java.use('java.util.HashMap').$new(); hm.put(book+'', (P.batch_key||'')+''); hm.put(book+'_'+cid+'', (P.batch_key||'')+''); FU.addMap.call(FU,hm); S({m:'② addMap OK'});}catch(e){S({m:'② addMap 异常 '+String(e).slice(0,60)});}
  report('②后 u4', FU.unlock.call(FU, b64, book, book+'_'+cid, null));

  // ③ requestKeySync (网络拉键) → 重打 + keyMap
  try{ S({m:'③ requestKeySync='+FU.requestKeySync.call(FU, ctx, parseInt(book))});}catch(e){S({m:'③ rks 异常 '+String(e).slice(0,60)});}
  report('③后 u4', FU.unlock.call(FU, b64, book, book+'_'+cid, null));
  try{ var km=FU.getKeyMap.call(FU, ctx); S({m:'③ keyMap size='+km.size()+' keys='+String(km.keySet()).slice(0,140)});}catch(e){}
  // ④ Fock 视角注册态
  try{ S({m:'④ currentUserKey='+String(FK.currentUserKey()).slice(0,44)});}catch(e){}
  try{ S({m:'④ addedKeyVersions='+String(FK.addedKeyVersions()).slice(0,120)});}catch(e){}
  // ⑤ 键位型变体重打
  report('⑤ u4(pair,book)', FU.unlock.call(FU, b64, book+'_'+cid, book, null));
  report('⑤ u4(md5,cid)', FU.unlock.call(FU, b64, P.md5||'', cid, null));
  report('⑤ u2(b64,book)', FU.unlock.call(FU, b64, book));
  S({m:'v27 done'});
});
