// step_methods.js — 反射列出 FockUtil 的真实方法，并读 MMKV 里的密钥
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…['+s.length+']':s;}catch(e){return '?';}}
var DIR='/data/local/tmp/';
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
Java.perform(function(){
  try{
    S({m:'=== methods: 反射 FockUtil ==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var cl=Java.use('java.lang.Class');
    var ms=FU.class.getDeclaredMethods();
    S({m:'FockUtil 声明方法数 = '+ms.length});
    var out=[];
    for(var i=0;i<ms.length;i++){
      try{
        var m=ms[i];
        var nm=m.getName();
        var ps=m.getParameterTypes();
        var pt=[]; for(var j=0;j<ps.length;j++) pt.push(ps[j].getName());
        out.push(nm+'('+pt.join(',')+')');
      }catch(e){}
    }
    out.sort();
    for(var k=0;k<out.length;k++) S({m:'  '+out[k]});
    // 读 MMKV 原始文本
    var raw=readText('/data/data/com.qidian.QDReader/files/mmkv/pref_utils');
    if(raw){
      var i=raw.indexOf('pref_fock_key');
      if(i>=0) S({m:'★★ MMKV pref_fock_key 附近: '+clip(raw.slice(i,i+350).replace(/[^\x20-\x7e]/g,'.'),340)});
      else S({m:'MMKV 里没有 pref_fock_key'});
    } else S({m:'MMKV 读不到（可能非文本）'});
    if(inst){ try{ S({m:'现状 getKey='+clip(inst.getKey(),40)+' isHasKey='+inst.isHasKey()}); }catch(e){} }
  }catch(e){ S({m:'✗ 顶层异常 '+String(e).slice(0,200)}); }
});
