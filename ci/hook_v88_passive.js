// v88: 纯被动 URL 抓取（绝不主动调用 native，防主线程卡死）
(function(){ Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var FOS=Java.use('java.io.FileOutputStream'), File=Java.use('java.io.File');
  var DIR='/data/local/tmp/jsout'; var d=File.$new(DIR); if(!d.exists()) d.mkdirs();
  function wtxt(name, text){ try{ var f=FOS.$new(File.$new(DIR,name)); var s=''+text; var arr=[]; for(var i=0;i<s.length&&i<900000;i++)arr.push(s.charCodeAt(i)&0xff); f.write(Java.array('byte',arr)); f.close(); }catch(e){} }
  var cnt=0;

  // ① HttpURLConnection 连接时全量抓
  try{
    var HUC=Java.use('java.net.HttpURLConnection');
    HUC.connect.implementation=function(){
      var u=''; try{ u=''+this.getURL(); }catch(e){}
      if(u.indexOf('fock')>=0 || u.indexOf('yuewen')>=0 || u.indexOf('script')>=0 || u.indexOf('ability')>=0){
        cnt++; var info='URL='+u+' M='+this.getRequestMethod()+'\n';
        var keys=['User-Agent','Content-Type','Accept','Cookie','qdsign','sign','app-version','oaid','imei','android-device-id','device-id','Authorization','x-','Version','AppKey','AppID','guid','mac','net','os','client'];
        for(var k=0;k<keys.length;k++){ try{ var v=this.getRequestProperty(keys[k]); if(v) info+='H:'+keys[k]+'='+(''+v).substring(0,200)+'\n'; }catch(e2){} }
        S({m:'◆CONN '+u}); wtxt('conn'+cnt+'.txt', info);
      }
      return this.connect();
    };
    S({m:'HUC.connect ok'});
  }catch(e){ S({m:'HUC败 '+String(e).slice(0,60)}); }

  // ② 输出流抓 POST body（BufferedOutputStream.write 过滤大 body）
  try{
    var BOS=Java.use('java.io.BufferedOutputStream');
    BOS.write.overload('[B','int','int').implementation=function(b,off,len){
      try{ if(len>20 && len<60000){
        var s=''; for(var i=off;i<off+len && i<800;i++){ var c=b[i]&0xff; s+=(c>=32&&c<127)?String.fromCharCode(c):'.'; }
        if(s.indexOf('script')>=0||s.indexOf('fock')>=0||s.indexOf('appId')>=0||s.indexOf('userId')>=0||s.indexOf('sign')>=0){ S({m:'◆BODY '+len+'B: '+s.substring(0,260)}); wtxt('body'+cnt+'_'+len+'.txt', s);} }
      }catch(e){}
      return this.write(b,off,len);
    };
    S({m:'BOS.write ok'});
  }catch(e){ S({m:'BOS败 '+String(e).slice(0,60)}); }

  // ③ OkHttp 兜底
  try{
    var RB=Java.use('okhttp3.Request$Builder');
    RB.build.overload().implementation=function(){
      try{ var r=this.build(); var u=''+r.url();
        if(u.indexOf('fock')>=0||u.indexOf('yuewen')>=0||u.indexOf('script')>=0||u.indexOf('ability')>=0){
          cnt++; var h='OKURL='+u+' M='+r.method()+'\n'; var hs=r.headers();
          for(var i=0;i<hs.size();i++) h+=hs.name(i)+'='+(''+hs.value(i)).substring(0,180)+'\n';
          S({m:'◆OK '+u}); wtxt('ok'+cnt+'.txt', h);
        }
      }catch(e){}
      return this.build();
    };
    S({m:'okhttp ok'});
  }catch(e){ S({m:'okhttp败 '+String(e).slice(0,50)}); }

  // ④ NB.s 被动（App 自调解脚本时截明文）
  try{ var NB=Java.use('com.yuewen.fockrt.NativeBinding');
    NB.s.overloads.forEach(function(ov){ ov.implementation=function(){ var r=ov.apply(this,arguments);
      var a0=(arguments[0]&&arguments[0].length!==undefined)?arguments[0].length:'-';
      S({m:'◆NB.s a0='+a0+' a1='+arguments[1]+' → '+(r? (''+r).length+'B head='+(''+r).substring(0,60):'null')});
      if(r&&(''+r).length>50) wtxt('NB_s_out.js', r);
      return r; };});
    S({m:'NB.s ok'});
  }catch(e){}
  S({m:'v88 就绪（纯被动）'});
});
})();
