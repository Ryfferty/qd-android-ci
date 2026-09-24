// hook_v65.js — v26: 在 v61 成功骨架上只加 3 件事: getter直读 + add/addMap/requestKeySync 注册流 + 注册后重打 unlock
// 教训: v23/v25 秒死 0 输出 = 顶层 setTimeout/native Interceptor/重试包装 引入; 回归 v61 裸 Java.perform 结构
function S(o){try{send(o);}catch(e){}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));var sb=Java.use('java.lang.StringBuilder').$new();var ln;while((ln=br.readLine())!==null)sb.append(ln);br.close();return sb.toString()+'';}catch(e){return null;}}
function bArr(jstr){var s=jstr.getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
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
  S({m:'params: payload='+((P.payload_b64||'').length)+' book='+P.book});
  if(!P.payload_b64)return;
  var book=P.book+'', cid=P.cid+'';
  var d=Java.use('android.util.Base64').decode(P.payload_b64,2);
  var b64=Java.use('android.util.Base64').encodeToString(d,2)+'';
  var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
  var FU=FUc.INSTANCE.value;
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();

  // ⓪ getter 直读 (App 自己的钥匙)
  var gs=['get3DesKey','getNibKey','getRtKey','getCloudConfigKey','getAudioAesKey','getKey','getPreUserKey'];
  for(var g=0;g<gs.length;g++){
    try{ S({m:'◆ '+gs[g]+'() = '+String(FU[gs[g]].call(FU)).slice(0,44)});}catch(e){S({m:'◆ '+gs[g]+' 异常 '+String(e).slice(0,46)});}
  }
  try{ S({m:'◆ isHasKey() = '+FU.isHasKey.call(FU)});}catch(e){}

  // ① 注册流: add(str,str) / addMap(map) — 键池写入者
  try{ FU.add.call(FU, book, book+'_'+cid); S({m:'① add(book,pair) OK'});}catch(e){S({m:'① add 异常 '+String(e).slice(0,60)});}
  try{ var hm=Java.use('java.util.HashMap').$new(); hm.put(bArr(book), bArr(P.batch_key||'')); hm.put(bArr(book+'_'+cid), bArr(P.batch_key||'')); FU.addMap.call(FU,hm); S({m:'① addMap(byte[] 键?) OK'});}catch(e){S({m:'① addMap 字节键异常 '+String(e).slice(0,50)});}
  try{ var hm2=Java.use('java.util.HashMap').$new(); hm2.put(book+'', (P.batch_key||'')+''); hm2.put(book+'_'+cid+'', (P.batch_key||'')+''); FU.addMap.call(FU,hm2); S({m:'① addMap(String 键) OK'});}catch(e){S({m:'① addMap 字符串键异常 '+String(e).slice(0,50)});}
  report('①后 u4', FU.unlock.call(FU, b64, book, book+'_'+cid, null));

  // ② requestKeySync 拉键 (App 真网络键路径) → 重打
  try{ S({m:'② requestKeySync='+FU.requestKeySync.call(FU, ctx, parseInt(book))});}catch(e){S({m:'② rks 异常 '+String(e).slice(0,60)});}
  report('②后 u4', FU.unlock.call(FU, b64, book, book+'_'+cid, null));
  try{ S({m:'② 再 isHasKey() = '+FU.isHasKey.call(FU)});}catch(e){}
  try{ var km=FU.getKeyMap.call(FU, ctx); S({m:'② keyMap size='+km.size()+' keys='+String(km.keySet()).slice(0,140)});}catch(e){S({m:'② gkm 异常 '+String(e).slice(0,50)});}

  // ③ 换 payload 形态重打 (raw .qd / 头8B去掉 / trailer)
  var raw=Java.use('android.util.Base64').encodeToString(d,0)+''; // 带换行版
  report('③ u4(无pair第二键)', FU.unlock.call(FU, b64, book+'_'+cid, book, null));
  report('③ u4(单book_cid键)', FU.unlock.call(FU, b64, book+'_'+cid, '', null));
  // ④ 引擎内部 Fock 面直读(注册后): currentUserKey / addedKeyVersions
  var FK=Java.use('com.yuewen.fock.Fock');
  try{ S({m:'④ currentUserKey='+String(FK.currentUserKey()).slice(0,44)});}catch(e){}
  try{ S({m:'④ addedKeyVersions='+String(FK.addedKeyVersions()).slice(0,120)});}catch(e){}
  S({m:'v26 done'});
});
