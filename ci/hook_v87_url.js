// v87: spawn hook 抓 fockrt 下载 URL（HttpURLConnection 层）+ 全 native I/O
(function(){ Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  var FOS=Java.use('java.io.FileOutputStream'), File=Java.use('java.io.File');
  var B64=Java.use('android.util.Base64');
  var DIR='/data/local/tmp/jsout'; var d=File.$new(DIR); if(!d.exists()) d.mkdirs();
  function wtxt(name, text){ try{ var f=FOS.$new(File.$new(DIR,name)); var s=''+text; var arr=[]; for(var i=0;i<s.length&&i<800000;i++)arr.push(s.charCodeAt(i)&0xff); f.write(Java.array('byte',arr)); f.close(); S({m:'★W '+name+' '+arr.length+'B'});}catch(e){S({m:'W败 '+name+' '+String(e).slice(0,50)});} }

  // ★ 核心：hook URL/连接层抓 fockrt.yuewen.com 请求
  var URL=Java.use('java.net.URL');
  var HUC=Java.use('java.net.HttpURLConnection');
  var OS=Java.use('java.io.OutputStream');
  // URL.openConnection 无法直接 hook 构造（太热）；改 hook 请求体写出 + getURL 读取
  var seen={};
  function noteUrl(u, body){
    try{
      var s=''+u;
      if(seen[s+(body?'#':'')]&&(!body)) return; 
      seen[s+(body?'#':'')]=1;
      S({m:'◆URL '+s+(body?' BODY:'+(''+body).substring(0,200):'')});
    }catch(e){}
  }
  // hook connect 时刻读 getURL
  try{
    HUC.connect.implementation=function(){ try{ noteUrl(this.getURL(), null);}catch(e){} return this.connect(); };
    S({m:'HUC.connect hook ok'});
  }catch(e){ S({m:'connect败 '+String(e).slice(0,50)}); }
  // hook 输出流写入（POST body）：装饰 OutputStream.write(byte[])
  try{
    var PS=Java.use('java.io.PrintStream'); // 不相关，跳过
  }catch(x){}
  // 更稳：hook java.net.HttpURLConnection#getOutputStream + write 抓不到体；用 DataOutputStream 兜
  try{
    var DOS=Java.use('java.io.DataOutputStream');
    S({m:'DOS ready'});
  }catch(e){}
  // OkHttp（若起点主网络栈用 okhttp，也兜上）
  try{
    var Intc=Java.use('okhttp3.Interceptor$Chain'); S({m:'okhttp存在'});
  }catch(e){ S({m:'no okhttp iface'}); }
  try{
    var RealCall=Java.use('okhttp3.internal.connection.RealCall');
    S({m:'RealCall ok'});
  }catch(e){}

  // ★ 网络线程抓栈：hook Thread.start 过滤含 fockrt 的？太重。改为 hook HUC.getInputStream（响应时刻）+ 记录 header
  try{
    HUC.getInputStream.implementation=function(){
      try{ var u=''+this.getURL(); noteUrl(u, null);
        // 尝试抓请求头里的 sign/cookie
        var keys=['qdsign','sign','cookie','user-key','x-','app-version','oaid','imei','deviceid','qimei'];
        var hdrs='';
        for(var k=0;k<keys.length;k++){ try{ var v=this.getRequestProperty(keys[k]); if(v) hdrs+=keys[k]+'='+(''+v).substring(0,80)+';'; }catch(e2){} }
        S({m:'◆GET-IO '+u+' HDR{'+hdrs+'}'});
        wtxt('last_req.txt', u+'\n'+hdrs+'\n');
      }catch(e){}
      return this.getInputStream();
    };
    S({m:'HUC.getIn hook ok'});
  }catch(e){ S({m:'getIn败 '+String(e).slice(0,50)}); }

  // 主动触发 fileManager 拉列表：App 进程内起线程调 FRT.setup+sn
  var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  try{ Java.use('com.yuewen.fockrt.FockRT').setup(ctx,'qjsprobe',false); S({m:'★setup ok'});}catch(e){S({m:'setup败 '+String(e).slice(0,60)});}
  try{ var out=Java.use('com.yuewen.fockrt.FockRT').sn('probe_ui'); S({m:'◆sn → '+(out? (''+out).length+'B':'null')}); }catch(e){ S({m:'sn败 '+String(e).slice(0,60)}); }

  // NB.s/d 被动
  try{ var NB=Java.use('com.yuewen.fockrt.NativeBinding');
    NB.s.overloads.forEach(function(ov){ ov.implementation=function(){ var r=ov.apply(this,arguments);
      var a0=(arguments[0]&&arguments[0].length!==undefined)?arguments[0].length:'-';
      S({m:'◆NB.s a0='+a0+' a1='+arguments[1]+' → '+(r? (''+r).length+'B':'null')});
      if(r&&(''+r).length>50){ wtxt('NB_s_out.js', r); } return r; };});
  }catch(e){}
  // ★ 触发重试：10s 后再 setup+sn（等网络初始化）
  setTimeout(function(){
    Java.perform(function(){
      try{ Java.use('com.yuewen.fockrt.FockRT').setup(Java.use('android.app.ActivityThread').currentApplication().getApplicationContext(),'qjsprobe',false); }catch(e){}
      try{ var o2=Java.use('com.yuewen.fockrt.FockRT').sn('probe_ui'); S({m:'◆sn2 → '+(o2?(''+o2).length+'B':'null')}); if(o2&&(''+o2).length>50)wtxt('sn2_out.js',o2); }catch(e){S({m:'sn2败 '+String(e).slice(0,50)});}
    });
  }, 15000);
  S({m:'v87 hook 就绪'});
});
})();
