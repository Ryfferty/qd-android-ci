// hook_v57.js — v17: 自省驱动正文矩阵 (不猜 API: 反射 dump 真签名 + 对每个候选方法通用实调)
function S(o){try{send(o);}catch(e){}}
function hx(b,n){try{var x=new Uint8Array(b);var s='';var m=n;if(!m)m=x.length;for(var i=0;i<m;i=i+1){var v=x[i].toString(16);if(v.length<2)v='0'+v;s+=v;}return s;}catch(e){return 'ERR';}}
function asc(a,n){try{var s='';var m=n;if(!m)m=80;if(a.length<m)m=a.length;for(var i=0;i<m;i=i+1){var c=a[i]&255;if(c>=32&&c<127){s+=String.fromCharCode(c);}else{s+='.';}}return s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var fis=Java.use('java.io.FileInputStream').$new(f);var bos=Java.use('java.io.ByteArrayOutputStream').$new();var buf=Java.array('byte',new Array(8192).fill(0));var r;while((r=fis.read(buf))>0)bos.write(buf,0,r);fis.close();return Java.use('java.lang.String').$new(bos.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
Java.perform(function(){
  var P={};try{P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');}catch(e){}
  var book=(P.book||'1049120379')+'', cid=(P.cid||'903350205')+'';
  var PAY=Java.use('android.util.Base64').decode(P.payload_b64,0);
  var B64=Java.use('android.util.Base64');
  var b64str=B64.encodeToString(PAY,2)+'';
  S({m:'=== v17 自省矩阵 nP='+P.nP+' ==='});
  function hex2arr(h){var a=[];for(var i=0;i<h.length;i=i+2)a.push(parseInt(h.substr(i,2),16));return a;}
  var mats={
    'K16':Java.array('byte',hex2arr((P.batch_key||'').replace(/-/g,'').slice(0,32))),
    'Kfull':Java.array('byte',hex2arr((P.batch_key||'').replace(/-/g,''))),
    'MD5':Java.array('byte',hex2arr(P.md5||'')),
    'dk':Java.array('byte',hex2arr(P.dk||'')),
    'PAYhead':Java.array('byte',Array.from(PAY.slice?PAY.slice(0,16):PAY).map(function(c){return c>127?c-256:c;})),
    'strBook':Java.array('byte',Array.from(book).map(function(ch){return ch.charCodeAt(0);}))
  };
  var strs={'book':book,'cid':cid,'pair':book+'_'+cid,'empty':'','md5':(P.md5||''),'b64':b64str};

  function dumpR(tag,r){
    if(r===null){S({m:tag+' → null'});return;}
    try{
      var st=(r.status&&r.status.value!==undefined)?r.status.value:(typeof r==='number'?r:'?');
      var d=(r.data&&r.data.value!==undefined)?r.data.value:null;
      if(typeof r==='number'){S({m:tag+' → int '+st});return;}
      if(d&&d.length>0){var arr=Array.from(d);
        var pr=arr.slice(0,200).filter(function(c){c=c&0xff;return (c>=32&&c<127)||c===9||c===10||c===13;}).length/Math.min(200,d.length);
        S({m:'★ '+tag+' status='+st+' len='+d.length+' print='+pr.toFixed(2)+' : '+asc(arr,100)});
        if(pr>0.85){var part=d.length>2048?Java.array('byte',Array.from(d).slice(0,2048)):d;S({m:'★PLAIN_B64='+B64.encodeToString(part,2)+''});}
      } else S({m:tag+' status='+st+' len=0/无data'});
    }catch(e){S({m:tag+' 解析失败 '+String(e).slice(0,80)});}
  }
  // 反射: 真类名/真方法签名
  function dumpClass(cn){
    try{
      var C=Java.use(cn);
      var ms=C.class.getDeclaredMethods();
      var names=[];
      for(var i=0;i<ms.length;i++){
        var mm=ms[i]; var nm=mm.getName()+'';
        if(nm.indexOf('unlock')>=0||nm.indexOf('uk')>=0||nm.indexOf('it')>=0){
          var ps=mm.getParameterTypes(); var sig=[];
          for(var j=0;j<ps.length;j++)sig.push(ps[j].getName());
          names.push(nm+'('+sig.join(',')+')→'+mm.getReturnType().getName());
        }
      }
      S({m:'◆ '+cn+' 候选方法: '+names.join(' | ')});
      return C;
    }catch(e){S({m:'◆ '+cn+' 反射失败: '+String(e).slice(0,90)});return null;}
  }
  var FK=dumpClass('com.yuewen.fock.Fock');
  var FUI=dumpClass('com.qidian.QDReader.component.util.FockUtil');
  // 通用实调: 遍历某类的每个 overload, 猜参数组合
  var matList=[mats['K16'],mats['MD5'],mats['dk'],mats['Kfull'],mats['PAYhead'],Java.array('byte',[])];
  var strList=[book,cid,book+'_'+cid,'',P.md5||'',b64str];
  function argFor(t,i,m){ // t=类型名, i=参数位, m=轮换种子
    if(t==='int'||t==='long')return i===1?PAY.length:0;
    if(t==='[B')return matList[m%matList.length];
    if(t==='java.lang.String')return strList[m%strList.length]+'';
    return null; // 未知类型(handler 等) → null
  }
  function sweep(C,tag,inst){
    if(!C)return;
    try{
      var ms=C.class.getDeclaredMethods();
      for(var i=0;i<ms.length;i++){
        var nm=ms[i].getName()+'';
        if(!(/unlock|uk|it$|decrypt/i.test(nm)))continue;
        try{
          var ov=C[nm].overloads;
          for(var k=0;k<ov.length;k++){
            var o=ov[k]; var types=o.argumentTypes.map(function(a){return a.className;});
            if(types.length<2||types.length>6)continue;
            for(var m=0;m<6;m++){
              var args=[]; var bpos=0;
              for(var a=0;a<types.length;a++){
                if(types[a]==='[B'){ args.push(bpos===0?PAY:matList[m%matList.length]); bpos++; }
                else args.push(argFor(types[a],a,m));
              }
              var label=tag+'.'+nm+'('+types.map(function(x){return x.replace('java.lang.','').replace('[B','b[]');}).join(',')+')m'+m;
              S({m:'~ pre '+label});
              try{ var r=inst?o.apply(inst,args):o.apply(C,args); dumpR(label,r); }
              catch(e){ var es=String(e); if(es.indexOf('ClassCast')>=0||es.indexOf('NullPointer')>=0){S({m:label+' NPE/cast'});break;}else S({m:label+' err '+es.slice(0,80)}); }
            }
          }
        }catch(e){S({m:tag+'.'+nm+' overload枚举 '+String(e).slice(0,60)});}
      }
    }catch(e){S({m:tag+' sweep 失败 '+String(e).slice(0,90)});}
  }
  sweep(FK,'F',null);
  if(FUI){ try{ var inst=FUI.INSTANCE.value; sweep(FUI,'FU',inst); }catch(e){S({m:'FU inst: '+String(e).slice(0,60)});} }
  S({m:'=== v17 done ==='});
});