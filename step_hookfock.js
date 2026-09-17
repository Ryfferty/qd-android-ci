// step_hookfock.js — hook FockUtil 的写/解密入口，捕获 App 自己调用时的真实参数
function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function dumpFile(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function W(line){ try{ var fos=Java.use('java.io.FileOutputStream').$new(DIR+'fock_trace.txt',true);
  fos.write(Java.use('java.lang.String').$new(line+'\n').getBytes('UTF-8')); fos.close(); }catch(e){} S({m:line}); }
Java.perform(function(){
  try{
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    W('=== hookfock 启动 isHasKey='+(inst?inst.isHasKey():'null')+' getKey='+(inst?clip(inst.getKey(),30):'-'));
    // ① hook unlock(String,String)
    try{
      FU.unlock.overload('java.lang.String','java.lang.String').implementation = function(a,b){
        W('★★ App 调 unlock: data='+clip(a,80)+'  additionalKey='+clip(b,80));
        try{ var f2=Java.use('java.io.FileOutputStream').$new(DIR+'captured_unlock_data.txt',false);
             f2.write(Java.use('java.lang.String').$new(String(a)).getBytes('UTF-8')); f2.close();
             W('   → 密文已落盘 captured_unlock_data.txt'); }catch(e){}
        var r=null; try{ r=this.unlock(a,b); }catch(e){ W('   unlock 内部异常 '+String(e).slice(0,150)); }
        if(r){ try{ W('   → 返回 status='+r.status.value+' dataLen='+(r.data.value?r.data.value.length:'null')); }catch(e){ W('   → 返回(取值失败)'); } }
        return r;
      };
      W('✓ hook unlock 装上');
    }catch(e){ W('✗ hook unlock 失败 '+String(e).slice(0,150)); }
    // ② hook save(Context,String,String)
    try{
      FU.save.overload('android.content.Context','java.lang.String','java.lang.String').implementation = function(c,k,v){
        W('★★ App 调 save: key='+clip(k,60)+' version='+clip(v,40));
        return this.save(c,k,v);
      };
      W('✓ hook save 装上');
    }catch(e){ W('✗ hook save 失败 '+String(e).slice(0,120)); }
    // ③ hook add(String,String)
    try{
      FU.add.overload('java.lang.String','java.lang.String').implementation = function(a,b){
        W('★★ App 调 add: arg1='+clip(a,80)+' version='+clip(b,40));
        return this.add(a,b);
      };
      W('✓ hook add 装上');
    }catch(e){ W('✗ hook add 失败 '+String(e).slice(0,120)); }
    // ④ hook requestKey(Context,long)
    try{
      FU.requestKey.overload('android.content.Context','long').implementation = function(c,bid){
        W('★★ App 调 requestKey: bookId='+bid);
        var j=null; try{ j=this.requestKey(c,bid); }catch(e){ W('   requestKey 内部异常 '+String(e).slice(0,150)); }
        return j;
      };
      W('✓ hook requestKey 装上');
    }catch(e){ W('✗ hook requestKey 失败 '+String(e).slice(0,120)); }
    // ⑤ 触发 App 去读一章（用它自己的 deeplink）
    try{
      var app=Java.use('android.app.ActivityThread').currentApplication();
      var ctx=app.getApplicationContext();
      var Intent=Java.use('android.content.Intent');
      var Uri=Java.use('android.net.Uri');
      var it=Intent.$new('android.intent.action.VIEW', Uri.parse('QDReader://OpenBook/1049120379/903350205'));
      it.addFlags(268435456);
      ctx.startActivity(it);
      W('✓ 已发 deeplink: QDReader://OpenBook/1049120379/903350205');
    }catch(e){ W('✗ deeplink 失败 '+String(e).slice(0,150)); }
  }catch(e){ W('✗ 顶层异常 '+String(e).slice(0,200)); }
});
