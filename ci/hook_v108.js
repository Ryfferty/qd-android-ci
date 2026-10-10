// hook_v108.js — v68: 非阻塞实验(resf/tsf池原语+uk真值+setup)在前, 可能阻塞的 add 放最后
(function(){
Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var r=Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(Java.use('java.io.FileInputStream').$new(f)));var sb='',ln;while((ln=r.readLine())!==null)sb+=ln;r.close();return sb;}catch(e){return null;}}
  var BD=JSON.parse(readText('/data/local/tmp/v60_bundle.json'));
  var CTs=BD.CT, K128=BD.K128;
  var B64=Java.use('android.util.Base64');
  var CTb=B64.decode(CTs,0), Kraw=B64.decode(K128,0);
  var cidS='799920041', pair='1040025277|799920041';
  var Fock=Java.use('com.yuewen.fock.Fock');
  S({m:'v68 CT='+CTb.length+' K='+Kraw.length});
  function FR(r,tag){ try{ var st=r.status.value; S({m:'◆'+tag+' st='+st}); if(st===0&&r.data){ var d=r.data,hx='',n=Math.min(32,d.length); for(var z=0;z<n;z++){var v=d[z]&0xff;hx+=(v<16?'0':'')+v.toString(16);} var as=''; try{as=''+Java.use('java.lang.String').$new(d);}catch(e){} S({m:'█'+tag+' hx='+hx+' as='+as.slice(0,60).replace(/[\r\n]/g,'.')}); } return st; }catch(e){S({m:tag+' 读败 '+String(e).slice(0,50)});return -9;} }
  // ① uk 真值 + setup(bundle.imei)
  var uk0=''; try{ uk0=''+Fock.getCurrentUserKey(); }catch(e){ uk0='E:'+String(e).slice(0,40); }
  S({m:'◆uk原生='+uk0.slice(0,50)});
  try{ Fock.setup(''+BD.imei); }catch(e){ S({m:'setup 败 '+String(e).slice(0,70)}); }
  var uk1=''; try{ uk1=''+Fock.getCurrentUserKey(); }catch(e){ uk1='E'; }
  S({m:'◆uk后='+uk1.slice(0,50)});
  // ② resf/tsf 池原语滑窗 (private static native, 无网络风险)
  try{
    var resf=Fock.resf.overload('[B','int','[B');
    var tsf=Fock.tsf.overload('[B','int','[B');
    var out=[];
    for(var i=0;i<5;i++){
      try{ var r1=resf(CTb,i,Kraw); var hx='';
        for(var z=0;z<Math.min(12,r1.length);z++){var v=r1[z]&0xff;hx+=(v<16?'0':'')+v.toString(16);}
        out.push('r'+i+':'+hx); }catch(e){ out.push('r'+i+'E'); break; }
    }
    for(var i2=0;i2<3;i2++){
      try{ var r2=tsf(CTb,i2,Kraw); var hx2='';
        for(var z2=0;z2<Math.min(12,r2.length);z2++){var v2=r2[z2]&0xff;hx2+=(v2<16?'0':'')+v2.toString(12+4);}
        out.push('t'+i2+':'+hx2); }catch(e){ out.push('t'+i2+'E'); break; }
    }
    S({m:'◆池原语 '+out.join(' | ')});
    // resf(K128) 变换→ b64 → 可能是真池钥, 喂 unlock 前的对照: 直接看可否当 add 值
    try{ var r3=resf(Kraw,0,Kraw); var b3=''+B64.encodeToString(r3,2); S({m:'◆resf(K,0,K)='+b3.slice(0,56)}); }catch(e){}
  }catch(e){S({m:'池原语败 '+String(e).slice(0,90)});}
  // ③ unlock 基线 (post-setup)
  try{ FR(Fock.unlock(CTs,cidS,pair,null),'U base'); }catch(e){S({m:'U 败 '+String(e).slice(0,70)});}
  // ④ 最后才 add (v27 阻塞雷区) → 立刻 unlock
  try{
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    var FUinst=FU.INSTANCE.value;
    FU.add.call(FUinst,''+BD.VER,K128);
    S({m:'◆add(VER,K128) 返回'});
    FR(Fock.unlock(CTs,cidS,pair,null),'U postADD');
  }catch(e){ S({m:'add 败 '+String(e).slice(0,80)}); }
  S({m:'v68 出'});
});
})();
