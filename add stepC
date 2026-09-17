// stepC_okhttp.js — hook okhttp 抓正文/密钥响应体（同源密文的来源）
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function save(name, txt){ try{
  var f=Java.use('java.io.FileOutputStream').$new(DIR+name,false);
  f.write(Java.use('java.lang.String').$new(txt).getBytes('UTF-8')); f.close(); S({m:'★ 已落盘 '+name+' ('+txt.length+'B)'});
}catch(e){ S({m:'落盘失败 '+name+' '+e}); } }
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
Java.perform(function(){
  try{
    S({m:'=== C: hook okhttp 响应 ==='});
    var Resp=Java.use('okhttp3.Response');
    Resp.body.implementation=function(){
      var b=this.body();
      try{
        var req=this.request(), url=String(req.url().toString());
        if(/getkey|safegetcontent|getvipcontent|bookcontent|chapter/i.test(url)){
          S({m:'★ 响应 URL: '+clip(url,140)});
          var s=String(b.string());
          S({m:'   body len='+s.length+' 前 200: '+clip(s,200)});
          try{ var req2=this.request(); save('http_body_'+Date.now()+'.txt', url+'\n'+s); }catch(e){}
        }
      }catch(e){ S({m:'body 读取异常 '+String(e).slice(0,110)}); }
      return b;
    };
    S({m:'✓ Response.body 已挂钩'});
    // 同时挂 request 侧，便于看请求参数
    try{
      var RB=Java.use('okhttp3.RequestBody');
      var R=Java.use('okhttp3.Request');
      R.url.implementation=function(){
        var u=this.url();
        try{ var s=String(u.toString()); if(/getkey|content|chapter/i.test(s)) S({m:'→ 请求: '+clip(s,140)}); }catch(e){}
        return u;
      };
      S({m:'✓ Request.url 已挂钩'});
    }catch(e){}
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,180)}); }
});
