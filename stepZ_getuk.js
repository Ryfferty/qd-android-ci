function S(o){try{send(o);}catch(e){}}
Java.perform(function(){
  try{
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var inst=FU.INSTANCE.value;
    var ku=String(inst.getPreUserKey()||'');
    S({m:'USERKEY='+ku});
    try{ var f=Java.use('java.io.FileOutputStream').$new('/data/local/tmp/userkey.txt',false);
      f.write(Java.use('java.lang.String').$new(ku).getBytes('UTF-8')); f.close(); }catch(e){}
  }catch(e){ S({m:'提取失败 '+String(e).slice(0,120)}); }
});
