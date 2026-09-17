// stepK_capture.js — 抓 App 自己的 unlock 调用（同源密文）
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
var TRACE=[];
function W(line){ TRACE.push(line); S({m:line}); }
function save(name, txt){ try{
  var f=Java.use('java.io.FileOutputStream').$new(DIR+name,false);
  f.write(Java.use('java.lang.String').$new(txt).getBytes('UTF-8')); f.close();
  W('★★ 已落盘 '+name+' ('+txt.length+'B)');
}catch(e){ W('落盘失败 '+name+' '+e); } }
Java.perform(function(){
  try{
    W('=== K: 捕获 App 自己的 unlock ===');
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    W('preUserKey='+clip(inst.getPreUserKey(),50)+' getKey='+clip(inst.getKey(),30)+' isHasKey='+inst.isHasKey());
    // ① hook unlock(String,String)
    try{
      FU.unlock.overload('java.lang.String','java.lang.String').implementation=function(a,b){
        W('★★★ App 调 unlock: data='+clip(a,60)+'  additionalKey='+clip(b,60));
        save('CAPTURED_unlock_data.txt', String(a));
        save('CAPTURED_unlock_ak.txt', String(b));
        try{ var f=Java.use('java.io.FileOutputStream').$new(DIR+'CAPTURED_uk.txt',false);
             f.write(Java.use('java.lang.String').$new(String(inst.getPreUserKey()||'')).getBytes('UTF-8')); f.close(); }catch(e){}
        var r=null; try{ r=this.unlock(a,b); }catch(e){ W('  unlock 内部异常 '+String(e).slice(0,140)); }
        if(r){ try{ W('  → status='+r.status.value+' dataLen='+(r.data.value?r.data.value.length:'null'));
                      if(r.data.value && r.data.value.length>100){
                        var s2=Java.use('java.lang.String').$new(r.data.value,'UTF-8')+''; var cn=0;
                        for(var k=0;k<s2.length;k++){var c=s2.charCodeAt(k);if(c>=0x4e00&&c<=0x9fff)cn++;}
                        W('★★★★★★★ 明文！len='+r.data.value.length+' 中文字='+cn);
                        W('★★★ 正文',{}); S({m:'★★★ 正文', text:s2.slice(0,3000)});
                        save('plain_K.txt', s2);
                      } }catch(e){ W('  → 取值失败'); } }
        return r;
      };
      W('✓ hook unlock(String,String)');
    }catch(e){ W('✗ hook unlock 失败 '+String(e).slice(0,110)); }
    // ② hook requestKey(Context,long)
    try{
      FU.requestKey.overload('android.content.Context','long').implementation=function(c,bid){
        W('★ App 调 requestKey(bookId='+bid+')');
        var j=null; try{ j=this.requestKey(c,bid); }catch(e){ W('  requestKey 异常 '+String(e).slice(0,120)); }
        return j;
      };
      W('✓ hook requestKey');
    }catch(e){ W('✗ hook requestKey 失败 '+String(e).slice(0,100)); }
    // ③ hook save / add
    try{
      FU.save.overload('android.content.Context','java.lang.String','java.lang.String').implementation=function(c,k,v){
        W('★ App 调 save(key='+clip(k,40)+' ver='+clip(v,30)+')'); return this.save(c,k,v);
      };
      W('✓ hook save');
    }catch(e){ W('✗ hook save 失败 '+String(e).slice(0,90)); }
    try{
      FU.add.overload('java.lang.String','java.lang.String').implementation=function(a,b){
        W('★ App 调 add(arg1='+clip(a,40)+' ver='+clip(b,30)+')'); return this.add(a,b);
      };
      W('✓ hook add');
    }catch(e){ W('✗ hook add 失败 '+String(e).slice(0,90)); }
    // ④ hook okhttp 响应（正文）
    try{
      var R=Java.use('okhttp3.Response');
      R.body.implementation=function(){
        var b=this.body();
        try{
          var u=String(this.request().url().toString());
          if(/content|chapter|getkey/i.test(u)){
            var s=String(b.string());
            W('★ HTTP 响应 '+clip(u,110)+' len='+s.length);
            save('CAPTURED_http_'+Date.now()+'.txt', u+'\n'+s);
          }
        }catch(e){}
        return b;
      };
      W('✓ hook okhttp Response.body');
    }catch(e){ W('✗ hook okhttp 失败 '+String(e).slice(0,90)); }
    // ⑤ 触发 App 去读章（deeplink）
    try{
      var app=Java.use('android.app.ActivityThread').currentApplication();
      var ctx=app.getApplicationContext();
      var Intent=Java.use('android.content.Intent');
      var Uri=Java.use('android.net.Uri');
      var it=Intent.$new('android.intent.action.VIEW', Uri.parse('QDReader://OpenBook/1049120379/903350205'));
      it.addFlags(268435456);
      ctx.startActivity(it);
      W('✓ 已发 deeplink: OpenBook/1049120379/903350205');
    }catch(e){ W('✗ deeplink 失败 '+String(e).slice(0,120)); }
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,200)}); }
});
