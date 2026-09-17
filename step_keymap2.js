function S(o){try{send(o);}catch(e){}}
var DIR='/data/local/tmp/';
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;
 var fis=Java.use('java.io.FileInputStream').$new(f);var b=Java.use('java.io.ByteArrayOutputStream').$new();
 var buf=Java.array('byte',new Array(65536).fill(0));var n;while((n=fis.read(buf))>0)b.write(buf,0,n);fis.close();
 return Java.use('java.lang.String').$new(b.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…['+s.length+']':s;}catch(e){return '?';}}
Java.perform(function(){
  try{
    S({m:'=== keymap2: 展开 App 的密钥映射 ==='});
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ctx=null; try{ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();}catch(e){}
    if(!inst){S({m:'✗ INSTANCE null'});return;}
    S({m:'getKey='+clip(inst.getKey(),40)+' isHasKey='+inst.isHasKey()});
    // ① getKeyMap
    try{
      var km=null;
      try{ km=inst.getKeyMap.overload('android.content.Context').call(inst, ctx); }
      catch(e1){ try{ km=inst.getKeyMap(ctx); }catch(e2){ S({m:'getKeyMap 解析失败 overload='+String(e1).slice(0,80)+' 直调='+String(e2).slice(0,80)}); } }
      if(km===null){S({m:'getKeyMap = null'});}
      else{
        var sz=km.size();
        S({m:'★ getKeyMap: size='+sz+' class='+km.getClass().getName()});
        var ks=km.keySet().toArray();
        for(var i=0;i<ks.length && i<10;i++){
          var k=String(ks[i]);
          var v=null; try{v=String(km.get(ks[i]));}catch(e){v='<get err>';}
          S({m:'  ['+i+'] '+clip(k,50)+' ⇒ '+clip(v,50)});
        }
      }
    }catch(e){ S({m:'getKeyMap 异常 '+String(e).slice(0,150)}); }
    // ② loadLocalKey
    try{
      var lk=null;
      try{ lk=inst.loadLocalKey.overload('android.content.Context').call(inst, ctx); }
      catch(e1){ try{ lk=inst.loadLocalKey(ctx); }catch(e2){} }
      if(lk===null){S({m:'loadLocalKey = null'});}
      else{
        var sz2=lk.size(); S({m:'★ loadLocalKey: size='+sz2+' class='+lk.getClass().getName()});
        var ks2=lk.keySet().toArray();
        for(var j=0;j<ks2.length && j<10;j++){
          var k2=String(ks2[j]); var v2=null; try{v2=String(lk.get(ks2[j]));}catch(e){}
          S({m:'  ['+j+'] '+clip(k2,50)+' ⇒ '+clip(v2,50)});
        }
      }
    }catch(e){ S({m:'loadLocalKey 异常 '+String(e).slice(0,150)}); }
    // ③ MMKV 原始内容
    try{
      var t=readText('/data/data/com.qidian.QDReader/files/mmkv/pref_utils');
      if(t){S({m:'MMKV pref_utils 文本片段: '+clip(t.replace(/[^\x20-\x7e]/g,'.'),300)});}
      else S({m:'MMKV 读不到（二进制）'});
    }catch(e){}
  }catch(e){ S({m:'✗ 顶层异常 '+String(e).slice(0,200)}); }
});
