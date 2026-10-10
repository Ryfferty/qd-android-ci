// hook_v64.js — v24: 旁观改用 native Interceptor (不碰 Java implementation — v23 App 秒死疑因方法体被改触发自检)
// 深链改由 runner adb 并发改 (本脚本不 startActivity)
// native 入口: ak@0x8d24 (注册现场!) uk@0x8e30 resf@0x9490 uksf@0x92d4 tsf@0x9548 lk@0x920c sn@0x9094 wnid@0x9150 it@0x8c3c
// JNI 约定: x0=env x1=clazz x2=arrayA x3=lenA x4=arrayK x5=lenK — dump jobject 原始头(ART Array: class+mon+len+data)
var TRIES=0;
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);}catch(e){return '[bytes]';}return s.length>n?s.slice(0,n)+'…':s;}
function asc(a,n){var s='';for(var i=0;i<Math.min(a.length,n||60);i++){var c=a[i];s+=(c>=32&&c<127)?String.fromCharCode(c):'.';}return s;}
function fget(obj,name){try{var f=obj.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(obj);}catch(e){return null;}}
function jint(v){if(v===null||v===undefined)return null;try{return v.intValue();}catch(e){try{return parseInt(''+v,10);}catch(e2){return null;}}}
function bArr(jstr){var s=jstr.getBytes();var a=[];for(var i=0;i<s.length;i++)a.push(s[i]);return Java.array('byte',a);}
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
function dumpJobj(p,tag){ // 读 ART Array 对象原始头 (class ptr + monitor + len + data), offset 未知→raw dump 判读
  try{
    if(p.isNull()){S({m:tag+' obj=null'});return;}
    var raw=p.readByteArray(96); var a=new Uint8Array(raw); var arr=[];
    for(var i=0;i<96;i++)arr.push(a[i]);
    // len 猜 offset 8 或 12 (u32 LE)
    var L8=arr[8]|(arr[9]<<16)|(arr[10]<<24); var uL8=arr[8]|(arr[9]<<8)|(arr[10]<<16)|(arr[11]<<24);
    var uL12=arr[12]|(arr[13]<<8)|(arr[14]<<16)|(arr[15]<<24);
    S({m:'◆'+tag+' raw='+arr.map(function(x){return ('0'+x.toString(16)).slice(-2);}).join('').slice(0,80)+' | L8='+uL8+' L12='+uL12+' data@16:'+asc(arr.slice(16,48),32)+' data@20:'+asc(arr.slice(20,52),32)});
  }catch(e){S({m:'◆'+tag+' dump异常 '+String(e).slice(0,50)});}
}
function attachNative(FK,base){
  var offs={'it':0x8c3c,'ak':0x8d24,'uk':0x8e30,'lk':0x920c,'sn':0x9094,'wnid':0x9150,'uksf':0x92d4,'resf':0x9490,'tsf':0x9548};
  var cnt={};
  for(var k in offs){
    (function(name,off){
      cnt[name]=0;
      try{
        Interceptor.attach(base.add(off),{
          onEnter:function(a){
            cnt[name]++;
            if(cnt[name]>8)return;
            S({m:'⚡'+name+'#'+cnt[name]+' x2='+a[2]+' x3='+a[2].toUInt32()+' x4='+a[4]});
            dumpJobj(a[2],name+'.A');
            if(name!=='it')dumpJobj(a[4],name+'.K');
            this.nm=name; this.n=cnt[name];
          },
          onLeave:function(r){
            if(cnt[this.nm]>8)return;
            // uk/uksf 返回 FockResult 引用; sn/wnid 返回 String ref; it 返回 int
            if(this.nm==='it'||this.nm==='ak')S({m:'⚡'+this.nm+'#'+this.n+' ret='+r});
            else S({m:'⚡'+this.nm+'#'+this.n+' ret='+r+' obj dump:'});
            if(this.nm!=='it'&&this.nm!=='ak'&&!r.isNull()){try{dumpJobj(r,this.nm+'.R');}catch(e){}}
          }
        });
      }catch(e){S({m:'attach '+name+' 失败 '+String(e).slice(0,40)});}
    })(k,offs[k]);
  }
  S({m:'⚡ native 旁观已挂 (9 入口, raw dump 判读 ART Array offset)'});
}
function main(){
  TRIES=TRIES+1;
  Java.perform(function(){
    try{
      var f=Java.use('java.io.File').$new('/data/local/tmp/v16_params.json');
      if(!f.exists()){ if(TRIES<25){S({m:'⏳ retry '+TRIES+' (params)'}); setTimeout(main,4000);} return; }
      var br=Java.use('java.io.BufferedReader').$new(Java.use('java.io.FileReader').$new(f));
      var sb=Java.use('java.lang.StringBuilder').$new(); var ln;
      while((ln=br.readLine())!==null) sb.append(ln);
      br.close();
      var P=JSON.parse(sb.toString()+'');
      if(!P.payload_b64){ if(TRIES<25){setTimeout(main,4000);} return; }
      var FUc=Java.use('com.qidian.QDReader.component.util.FockUtil');
      var FK=Java.use('com.yuewen.fock.Fock');
      var mod=Process.findModuleByName('libfock.so');
      if(!mod){ if(TRIES<25){S({m:'⏳ retry '+TRIES+' (libfock 未加载)'}); setTimeout(main,4000);} return; }
      var FU=FUc.INSTANCE.value;
      var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
      var book=P.book+'', cid=P.cid+'';
      var d=Java.use('android.util.Base64').decode(P.payload_b64,2);
      var b64=Java.use('android.util.Base64').encodeToString(d,2)+'';
      S({m:'v24 开跑 base='+mod.base+' book='+book});
      attachNative(FK,mod.base);
      // ⓪ getter (只调用不替换)
      var gs=['get3DesKey','getNibKey','getRtKey','getCloudConfigKey','getAudioAesKey','getKey','getPreUserKey','isHasKey'];
      for(var g=0;g<gs.length;g++){
        try{ S({m:'◆ '+gs[g]+'() = '+clip(''+FU[gs[g]].call(FU),44)});}catch(e){S({m:'◆ '+gs[g]+' 异常 '+String(e).slice(0,46)});}
      }
      // ① 注册流 (add/addMap 调用本身会被 ak 旁观钩子抓到注册现场!)
      try{ FU.add(book, book+'_'+cid); S({m:'① add 已调'});}catch(e){S({m:'① add 异常 '+String(e).slice(0,60)});}
      try{ var hm=Java.use('java.util.HashMap').$new(); hm.put(book+'', (P.batch_key||'')+''); hm.put(book+'_'+cid+'', (P.batch_key||'')+''); FU.addMap(hm); S({m:'① addMap 已调'});}catch(e){S({m:'① addMap 异常 '+String(e).slice(0,60)});}
      // ② 主动打一轮
      report('② u4', FU.unlock(b64, book, book+'_'+cid, null));
      // ③ requestKeySync
      try{ S({m:'③ requestKeySync='+FU.requestKeySync(ctx, parseInt(book))});}catch(e){S({m:'③ rks 异常 '+String(e).slice(0,60)});}
      report('③后 u4', FU.unlock(b64, book, book+'_'+cid, null));
      // ④ 池
      try{ var km=FU.getKeyMap(ctx); S({m:'④ keyMap size='+km.size()+' keys='+clip(''+km.keySet(),140)});}catch(e){}
      S({m:'v24 armed (等 runner 深链)'});
    }catch(e){
      var es=String(e);
      if((es.indexOf('ClassNotFound')>=0||es.indexOf('not found')>=0)&&TRIES<25){
        S({m:'⏳ retry '+TRIES+' ('+es.slice(0,50)+')'}); setTimeout(main,4000);
      } else S({m:'FATAL '+es.slice(0,130)});
    }
  });
}
setTimeout(main,2000);
