// hook_oracle_final.js — 被动抓 App 自己成功解密的 ground-truth 配对 (200/464 通用)
// 覆盖 Fock.unlock 2/3/4 参全部重载 + uk/it/addKeys/setup + FockUtil.unlock
// 纯被动: 全部原样转发并返回原结果, 不改 App 行为
function S(o){try{send(o);}catch(e){}}
function clip(s,n){try{s=String(s);return s.length>n?s.slice(0,n)+'…[len='+s.length+']':s;}catch(e){return '?';}}
function hexOf(arr,n){try{var s='';var m=Math.min(arr.length,n||96);for(var i=0;i<m;i++){var b=(arr[i]+256)%256;s+=(b<16?'0':'')+b.toString(16);}return s;}catch(e){return 'ERR';}}
function dumpRes(tag,r){
  if(!r){S({m:'  '+tag+' 返回 null'});return;}
  try{
    var st=r.status.value, dt=r.data.value;
    S({m:'  '+tag+' → status='+st+' dataLen='+(dt?dt.length:0)});
    if(dt&&dt.length){
      var s='';
      for(var i=0;i<Math.min(dt.length,6000);i++){var b=(dt[i]+256)%256;s+=(b>=32&&b<127)?String.fromCharCode(b):((b===10||b===13)?'\n':'.');}
      S({m:'  ---- '+tag+' 明文前6000 ----\n'+s});
    }
  }catch(e){S({m:'  读结果失败 '+String(e).slice(0,100)});}
}

Java.perform(function(){
  S({m:'=== oracle_final loaded ==='});

  try{
    var F=Java.use('com.yuewen.fock.Fock');
    S({m:'✓ Fock class'});

    // unlock 全部重载
    try{
      var ov=F.unlock.overloads;
      for(var oi=0;oi<ov.length;oi++){
        (function(o){
          var sig=o.argumentTypes.map(function(t){return t.className;}).join(',');
          if(sig.indexOf('ErrorLogHandler')>=0){
            o.implementation=function(){
              var args=Array.prototype.slice.call(arguments);
              S({m:'★★★★★ Fock.unlock('+sig+') 被调用!'});
              S({m:'  cipher='+clip(args[0],110)});
              for(var j=1;j<args.length-1;j++){ if(args[j]!==undefined&&args[j]!==null) S({m:'  arg'+j+'='+clip(String(args[j]),60)}); }
              // ★ 换入自己的捕获 handler (skill 9.17): 保留原 handler 转发, 再收诊断
              try{
                var origH=args[args.length-1];
                var Cap=Java.registerClass({ name:'com.example.CapH'+Date.now(),
                  implements:[Java.use('com.yuewen.fock.Fock$ErrorLogHandler')],
                  methods:{ onError:function(j){
                    S({m:'███████ 捕获 onError 诊断 ███████'});
                    try{var o=JSON.parse(String(j));for(var k in o){S({m:'  ['+k+']='+clip(String(o[k]),300)});}}
                    catch(e2){S({m:'  raw='+clip(String(j),900)});}
                    // 原样转发给 App 自己的 handler
                    try{ if(origH) Java.cast(origH, Java.use('com.yuewen.fock.Fock$ErrorLogHandler')).onError(j);}catch(e3){}
                  }}});
                args[args.length-1]=Cap.$new();
              }catch(e){ S({m:'  造 handler 失败 '+String(e).slice(0,90)}); }
              var r=this.unlock.apply(this,args);
              dumpRes('unlock('+args.length+'p)',r);
              return r;
            };
          } else {
            o.implementation=function(){
              var args=Array.prototype.slice.call(arguments);
              S({m:'★★★★★ Fock.unlock('+sig+')'});
              S({m:'  cipher='+clip(args[0],110)});
              S({m:'  addKey="'+clip(args[1],80)+'"'+(args.length>2?' arg2='+clip(String(args[2]),40):'')});
              var r=this.unlock.apply(this,args);
              dumpRes('unlock',r);
              return r;
            };
          }
          S({m:'+ hooked '+sig});
        })(ov[oi]);
      }
    }catch(e){S({m:'- unlock overloads: '+String(e).slice(0,140)});}

    // unlockData([B,...)
    try{
      F.unlockData.overloads.forEach(function(o){
        o.implementation=function(){
          var a=Array.prototype.slice.call(arguments);
          S({m:'★★★ unlockData over='+o.argumentTypes.map(function(t){return t.className;}).join(',')});
          if(a[0]&&a[0].length!==undefined){S({m:'  data.len='+a[0].length+' head='+hexOf(a[0],32)});}
          for(var j=1;j<a.length;j++){ if(typeof a[j]==='string'||a[j]&&a[j].length!==undefined) S({m:'  a'+j+'='+clip(String(a[j]).length>80?hexOf(a[j],40):String(a[j]),80)}); }
          var r=this.unlockData.apply(this,a);
          dumpRes('unlockData',r);
          return r;
        };
        S({m:'+ unlockData hooked'});
      });
    }catch(e){S({m:'- unlockData: '+String(e).slice(0,90)});}

    // uk([B,int,[B,int)
    try{
      F.uk.overload('[B','int','[B','int').implementation=function(d,dl,k,kl){
        S({m:'★★★ F.uk(len='+dl+', addKeyLen='+kl+')'});
        S({m:'  blob head='+hexOf(d,32)});
        S({m:'  addKey hex='+hexOf(k,48)+' ascii='+clip(String(Java.use('java.lang.String').$new(k,'UTF-8')),60)});
        var r=this.uk(d,dl,k,kl);
        dumpRes('uk',r);
        return r;
      };
      S({m:'+ uk hooked'});
    }catch(e){S({m:'- uk: '+String(e).slice(0,90)});}

    // it([B,int)
    try{
      F.it.overload('[B','int').implementation=function(b,l){
        S({m:'★★ F.it(len='+l+') ascii='+clip(String(Java.use('java.lang.String').$new(b,'UTF-8')),40)});
        return this.it(b,l);
      };
      S({m:'+ it hooked'});
    }catch(e){}

    // addKeypool(String,String) — 池子装载 (★ keypool 真值 + Version)
    try{
      F.addKeypool.overload('java.lang.String','java.lang.String').implementation=function(a,b){
        S({m:'★★★ F.addKeypool a='+clip(a,160)+' b='+clip(b,20)});
        var r=this.addKeypool(a,b);
        try{S({m:'  addedKeyVersions='+JSON.stringify(F.addedKeyVersions())});}catch(e){}
        return r;
      };
      S({m:'+ addKeypool hooked'});
    }catch(e){S({m:'- addKeypool: '+String(e).slice(0,90)});}

    try{ F.setup.overload('java.lang.String').implementation=function(k){S({m:'★ setup('+clip(k,40)+')'});return this.setup(k);}; }catch(e){}

    // ★ 464: Fock.add(String,String) (FockUtil.add 的底层, encryptedKeys复数)
    try{
      F.add.overload('java.lang.String','java.lang.String').implementation=function(a,b){
        S({m:'★★★ F.add(encryptedKeys,version)'});
        S({m:'  keys='+clip(a,180)+' ver='+clip(b,16)});
        return this.add(a,b);
      };
      S({m:'+ add hooked'});
    }catch(e){S({m:'- add: '+String(e).slice(0,90)});}

    // ★★ ErrorLogHandler.onError(JSONObject) — 464 自带诊断: k1/k2/k3/kp/data/addk/code 全量
    try{
      var H=Java.use('com.yuewen.fock.Fock$ErrorLogHandler');
      H.onError.overload('org.json.JSONObject').implementation=function(j){
        S({m:'███████ ErrorLogHandler.onError 诊断 JSON ███████'});
        try{
          var o=JSON.parse(String(j));
          for(var key in o){ S({m:'  ['+key+']='+clip(String(o[key]),300)}); }
        }catch(e){ S({m:'  raw='+clip(String(j),900)}); }
        return this.onError(j);
      };
      S({m:'+ ErrorLogHandler hooked'});
    }catch(e){S({m:'- ErrorLogHandler: '+String(e).slice(0,110)});}
  }catch(e){S({m:'✗ Fock 类: '+String(e).slice(0,140)});}

  // FockUtil 2参
  try{
    var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
    FU.unlock.overload('java.lang.String','java.lang.String').implementation=function(c,a){
      S({m:'★★★★ FockUtil.unlock addKey="'+clip(a,60)+'" cipher.len='+(c?c.length:0)});
      var r=this.unlock(c,a);
      dumpRes('FU.unlock',r);
      return r;
    };
    S({m:'+ FockUtil.unlock hooked'});
    // Fock.requestKeySync / requestKey (只观测, 不主动调)
    try{
      var ro=F.requestKeySync?F.requestKeySync.overloads:null;
    }catch(e){}
  }catch(e){S({m:'- FockUtil: '+String(e).slice(0,110)});}

  S({m:'=== hooks done ==='});
});
