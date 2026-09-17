// step_qdfind.js — 找 App 自己缓存的章节密文（.qd 等），同源才能解开
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…['+s.length+']':s;}catch(e){return '?';}}
function walkDir(dir,depth,out){
  if(depth>3||out.length>120) return;
  try{
    var F=Java.use('java.io.File'), d=F.$new(dir);
    var arr=d.listFiles(); if(!arr) return;
    for(var i=0;i<arr.length;i++){
      var f=arr[i];
      var name=String(f.getName());
      if(f.isDirectory()){ walkDir(String(f.getAbsolutePath()),depth+1,out); }
      else{
        var sz=f.length();
        if(sz>2000) out.push(String(f.getAbsolutePath())+'  '+sz+'B');
      }
    }
  }catch(e){}
}
Java.perform(function(){
  try{
    S({m:'=== qdfind: 找 App 缓存的大文件 ==='});
    var roots=['/data/data/com.qidian.QDReader/files','/data/data/com.qidian.QDReader/cache','/sdcard/Android/data/com.qidian.QDReader','/data/user/0/com.qidian.QDReader/files'];
    for(var r=0;r<roots.length;r++){
      var out=[];
      walkDir(roots[r],0,out);
      S({m:'■ '+roots[r]+' → '+out.length+' 个 >2KB 文件'});
      for(var k=0;k<out.length && k<25;k++) S({m:'   '+out[k]});
    }
    // 特别找 .qd
    try{
      var F=Java.use('java.io.File');
      var d=F.$new('/data/data/com.qidian.QDReader');
      S({m:'■ App 根目录列表:'});
      var arr=d.listFiles();
      for(var j=0;j<arr.length && j<25;j++) S({m:'   '+String(arr[j].getName())+(arr[j].isDirectory()?'/':'  '+arr[j].length()+'B')});
    }catch(e){}
  }catch(e){ S({m:'✗ 顶层 '+String(e).slice(0,180)}); }
});
