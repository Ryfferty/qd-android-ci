// hook_v63.js — v23: 旁观钩子(App 自调现场) + 键池注册流 + getter 直读
// v22b 教训: 顶层括号错位→evaluate 崩(Process terminated); FockResult 字段必须反射 fget
var TRIES=0;
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);}catch(e){return '[bytes]';}return s.length>n?s.slice(0,n)+'…':s;}
function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||60);i++){var c=a[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
function bArr(jstr){var s=jstr.getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
function fget(obj,name){try{var f=obj.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(obj);}catch(e){return null;}}
function jint(v){if(v===null||v===undefined)return null;try{return v.intValue();}catch(e){try{return parseInt(''+v,10);}catch(e2){return null;}}}
function report(tag,r){
  if(r===null||r===undefined){S({m:tag+' → null'});return;}
  try{
    var st=jint(fget(r,'status')); if(st===null)st=jint(fget(r,'errCode'));
    var data=fget(r,'data'); var msg=''+(fget(r,'message')||'');
    if(!data){S({m:'·'+tag+' status='+st+' data=null '+clip(msg,20)});return;}
    var jb=Java.cast(data,Java.use('[B'));
    var a=[];for(var i=0;i<Math.min(jb.length,80);i++)a.push(jb[i]&255);
    var pr=0;for(var i=0;i<a.length;i++){if(a[i]>=32&&a[i]<127)pr++;}
    var line='★'+tag+' status='+st+' len='+jb.length+' print='+(a.length?(pr/a.length).toFixed(2):'-')+' asc='+asc(a,60);
    if(a.length&&pr/a.length>0.85){
      line+=' ██命中!!';
      var full=[];for(var i=0;i<Math.min(jb.length,4000);i++)full.push(jb[i]);
      S({m:'█PLAIN_B64='+Java.use('android.util.Base64').encodeToString(Java.array('byte',full),2)+''});
    }
    S({m:line});
  }catch(e){S({m:tag+' 读结果异常 '+String(e).slice(0,70)});}
}
function loadP(){
  var f=Java.use('java.io.File').$new('/data/local/tmp/v16_params.json');
  if(!f.exists()) throw new Error('no params file');
  var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));
  var sb=Java.use('java.lang.StringBuilder').$new(); var ln;
  while((ln=br.readLine())!==null) sb.append(ln);
  br.close();
  return JSON.parse(sb.toString()+'');
}
function hookAll(FK,FUc,FU){
  var seen=0;
  function note(s){ if(seen<60){seen++; S({m:'👁 '+s});} }
  try{
    FUc.unlock.overload('java.lang.String','java.lang.String').implementation=function(a,b){
      note('FU.unlock2(str1 len='+(''+a).length+' head='+clip(''+a,36)+' | str2='+clip(''+b,24)+')');
      var r=this.unlock(a,b); report('👁u2ret',r); return r;
    };
  }catch(e){note('hook u2 失败');}
  try{
    var H=Java.use('com.yuewen.fock.Fock$ErrorLogHandler');
    FUc.unlock.overload('java.lang.String','java.lang.String','java.lang.String',H).implementation=function(a,b,c,d){
      note('FU.unlock4(s1 len='+(''+a).length+' head='+clip(''+a,36)+' | s2='+clip(''+b,24)+' | s3='+clip(''+c,28)+')');
      var r=this.unlock(a,b,c,d); report('👁u4ret',r); return r;
    };
  }catch(e){note('hook u4 失败');}
  try{
    FK.uk.overload('[B','int','[B','int').implementation=function(a,al,b,bl){
      var bv=[]; if(b!==null){for(var j=0;j<Math.min(bl,32);j++)bv.push(b[j]&255);}
      note('Fock.uk(in='+al+'B key='+bl+'B ['+asc(bv,32)+'])');
      var r=this.uk(a,al,b,bl); note(' → status='+jint(fget(r,'status'))); return r;
    };
  }catch(e){note('hook uk 失败');}
  try{ FK.setup.overload('java.lang.String').implementation=function(s){ note('Fock.setup("'+clip(''+s,40)+'")'); return this.setup(s); }; }catch(e){}
  try{ FUc.add.overload('java.lang.String','java.lang.String').implementation=function(a,b){ note('FU.add("'+clip(''+a,26)+'","'+clip(''+b,26)+'")'); return this.add(a,b); }; }catch(e){}
  try{ FUc.addMap.overload('java.util.Map').implementation=function(m){ note('FU.addMap(size='+m.size()+' keys='+clip(''+m.keySet(),100)+')'); return this.addMap(m); }; }catch(e){}
  S({m:'👁 旁观钩子挂好'});
}
function main(){
  TRIES=TRIES+1;
  Java.perform(function(){
    try{
      var P=loadP();
      if(!P.payload_b64){ if(TRIES<25){S({m:'⏳ retry '+TRIES}); setTimeout(main,4000);} return; }
      var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
      var FK=Java.use('com.yuewen.fock.Fock');
      var FU=FUc.INSTANCE.value;
      var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
      var book=P.book+'', cid=P.cid+'';
      var d=Java.use('android.util.Base64').decode(P.payload_b64,2);
      var b64=Java.use('android.util.Base64').encodeToString(d,2)+'';
      S({m:'v23 开跑 book='+book+' payload='+d.length+'B b64len='+b64.length});
      hookAll(FK,FUc,FU);
      // ⓪ getter
      var gs=['get3DesKey','getNibKey','getRtKey','getCloudConfigKey','getAudioAesKey','getKey','getPreUserKey','isHasKey'];
      for(var g=0;g<gs.length;g++){
        try{ S({m:'◆ '+gs[g]+'() = '+clip(''+FU[gs[g]].call(FU),44)});}catch(e){S({m:'◆ '+gs[g]+' 异常 '+String(e).slice(0,46)});}
      }
      // ① 注册流
      try{ FU.add(book, book+'_'+cid); }catch(e){}
      try{ var hm=Java.use('java.util.HashMap').$new(); hm.put(book+'', (P.batch_key||'')+''); hm.put(book+'_'+cid+'', (P.batch_key||'')+''); FU.addMap(hm); }catch(e){}
      // ② 主动打一轮
      report('② u4', FU.unlock(b64, book, book+'_'+cid, null));
      // ③ requestKeySync
      try{ S({m:'③ requestKeySync='+FU.requestKeySync(ctx, parseInt(book))});}catch(e){S({m:'③ rks 异常 '+String(e).slice(0,60)});}
      report('③后 u4', FU.unlock(b64, book, book+'_'+cid, null));
      // ④ 池
      try{ var km=FU.getKeyMap(ctx); S({m:'④ keyMap size='+km.size()+' keys='+clip(''+km.keySet(),140)});}catch(e){}
      // ⑤ 深链驱动 App 真开书 → 旁观钩子抓现场
      try{
        var it=Java.use('android.content.Intent').parseUri('QDReader://OpenBook/'+book+'/'+cid, 0);
        it.setFlags(0x10000000);
        ctx.startActivity(it);
        S({m:'⑤ 深链已发 (App 自解正文中, 旁观…)'});
      }catch(e){S({m:'⑤ 深链异常 '+String(e).slice(0,80)});}
      S({m:'v23 armed'});
    }catch(e){
      var es=String(e);
      if((es.indexOf('ClassNotFound')>=0||es.indexOf('no params')>=0||es.indexOf('not found')>=0)&&TRIES<25){
        S({m:'⏳ retry '+TRIES+' ('+es.slice(0,50)+')'}); setTimeout(main,4000);
      } else S({m:'FATAL '+es.slice(0,130)});
    }
  });
}
setTimeout(main,3000);
