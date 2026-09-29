// v90: 活体抄槽——dump libfockrt RW 表区（NB.s 死表 0xd3080±）与 libfock 对照区
(function(){ Java.perform(function(){
  function S(o){try{send(o);}catch(e){}}
  function dumpMod(mname, ranges, tag){
    var m = Process.findModuleByName(mname);
    if(!m){ S({m:'★NO-MODULE '+mname}); return; }
    S({m:'★BASE '+mname+' = '+m.base+' size=0x'+m.size.toString(16)});
    ranges.forEach(function(rg){
      var h='';
      for(var off=rg[0]; off<rg[1]; off+=8){
        try{ var w=Memory.readU32(m.base.add(off)); var w2=Memory.readU32(m.base.add(off+4));
          h += ('0000000'+(w>>>0).toString(16)).slice(-8)+('0000000'+(w2>>>0).toString(16)).slice(-8)+' ';
        }catch(e){ h+='XXXXXXXXXXXXXXXX '; }
      }
      S({m:'★SLOTS['+tag+' 0x'+rg[0].toString(16)+'-0x'+rg[1].toString(16)+'] '+h});
    });
  }
  // libfockrt: s()死表区 0xd3080（v7a布局同版本arm64偏移需确认，双区都扫）
  dumpMod('libfockrt.so', [[0xd3060,0xd30c0],[0x271c60,0x271cc0]], 'rt');
  // libfock 对照（arm64 27020 区，v82 曾成功）
  dumpMod('libfock.so', [[0x26fe0,0x270c0]], 'fk');
  // 被动 NB.s 钩子：确认自调时机（证明表活）
  try{ var NB=Java.use('com.yuewen.fockrt.NativeBinding');
    NB.s.overloads.forEach(function(ov){ ov.implementation=function(){ var r=ov.apply(this,arguments);
      var a0=(arguments[0]&&arguments[0].length!==undefined)?arguments[0].length:'-';
      S({m:'◆NB.s(自调) a0='+a0+' a1='+arguments[1]+' a2len='+(arguments[2]?arguments[2].length:'?')+' → '+(r?(''+r).length+'B':'null')});
      return r; };});
    S({m:'NB.s pass ok'});
  }catch(e){ S({m:'NB pass败 '+String(e).slice(0,50)}); }
  // 延迟再 dump 一次（等 App 完成 fockrt init 后表值变化）
  setTimeout(function(){ dumpMod('libfockrt.so', [[0xd3060,0xd30c0],[0x271c60,0x271cc0]], 'rt-late'); }, 30000);
  S({m:'v90 就绪'});
});
})();
