// hook_v58.js — v18: uk/uksf 全交叉矩阵 (v17 真签名已锁, 这轮打遍材料组合)
function S(o){try{send(o);}catch(e){}}
function asc(a,n){try{var s='';var m=n;if(!m)m=80;if(a.length<m)m=a.length;for(var i=0;i<m;i=i+1){var c=a[i]&255;if(c>=32&&c<127){s+=String.fromCharCode(c);}else{s+='.';}}return s;}catch(e){return '?';}}
function readText(p){try{var f=Java.use('java.io.File').$new(p);if(!f.exists())return null;var fis=Java.use('java.io.FileInputStream').$new(f);var bos=Java.use('java.io.ByteArrayOutputStream').$new();var buf=Java.array('byte',new Array(8192).fill(0));var r;while((r=fis.read(buf))>0)bos.write(buf,0,r);fis.close();return Java.use('java.lang.String').$new(bos.toByteArray(),'UTF-8')+'';}catch(e){return null;}}
Java.perform(function(){
  var P={};try{P=JSON.parse(readText('/data/local/tmp/v16_params.json')||'{}');}catch(e){}
  var book=(P.book||'1049120379')+'', cid=(P.cid||'903350205')+'';
  var B64=Java.use('android.util.Base64');
  var PAY=B64.decode(P.payload_b64,0);
  function hex2arr(h){var a=[];for(var i=0;i<h.length;i=i+2)a.push(parseInt(h.substr(i,2),16));return a;}
  function ba(s){var out=[];for(var i=0;i<s.length;i++)out.push(s.charCodeAt(i)&255);return Java.array('byte',out);}
  var dkA=Java.array('byte',hex2arr(P.dk||''));
  var K16=Java.array('byte',hex2arr((P.batch_key||'').replace(/-/g,'').slice(0,32)));
  var MD5=Java.array('byte',hex2arr(P.md5||''));
  var TRL=Java.array('byte',hex2arr(P.trailer_hex||''));
  var EMPTY=Java.array('byte',[]);
  S({m:'=== v18 uk 全交叉 nP='+P.nP+' ==='});
  function dumpR(tag,r){
    if(r===null){S({m:tag+' → null'});return;}
    try{
      var st=(r.status&&r.status.value!==undefined)?r.status.value:'?';
      var d=(r.data&&r.data.value!==undefined)?r.data.value:null;
      if(d&&d.length>0){var arr=Array.from(d);
        var pr=arr.slice(0,200).filter(function(c){c=c&0xff;return (c>=32&&c<127)||c===9||c===10||c===13;}).length/Math.min(200,d.length);
        S({m:'★ '+tag+' status='+st+' len='+d.length+' print='+pr.toFixed(2)+' : '+asc(arr,100)});
        if(pr>0.85){var part=d.length>4096?Java.array('byte',Array.from(d).slice(0,4096).map(function(c){return c>127?c-256:c;})):d;S({m:'★PLAIN_B64='+B64.encodeToString(part,2)+''});}
      } else S({m:tag+' status='+st+' len0'});
    }catch(e){S({m:tag+' parse err '+String(e).slice(0,70)});}
  }
  var FK=Java.use('com.yuewen.fock.Fock');
  var UK=FK.uk.overload('[B','int','[B','int');
  var UKSF=FK.uksf.overload('[B','int','[B','int','[B');
  // addKey 字节候选: str 形态 + 材料形态
  var adds={'空':EMPTY,'book':ba(book),'cid':ba(cid),'b_c':ba(book+'_'+cid),'c_b':ba(cid+'_'+book),
            'K16':K16,'MD5':MD5,'dk8':Java.array('byte',hex2arr((P.dk||'').slice(0,16))),'ver':ba(String(P.version||'1639985422'))};
  var n=0,fail={};
  for(var an in adds){
    n++;
    try{ dumpR('uk(PAY|'+an+')', UK(PAY,PAY.length,adds[an],adds[an].length)); }
    catch(e){S({m:'uk|'+an+' 异常: '+String(e).slice(0,200)});}
    try{ dumpR('uksf(PAY|'+an+'|空)', UKSF(PAY,PAY.length,adds[an],adds[an].length,EMPTY)); }catch(e){S({m:'uksf1|'+an+' 异常: '+String(e).slice(0,140)});}
    try{ dumpR('uksf(PAY|空|'+an+')', UKSF(PAY,PAY.length,EMPTY,0,adds[an])); }catch(e){S({m:'uksf2|'+an+' 异常: '+String(e).slice(0,140)});}
  }
  S({m:'UK类型: '+(typeof UK)+' UKSF: '+(typeof UKSF)});
  // 头/尾特殊: 整 qd (含 8B 头) 当 data
  var QD=Java.array('byte',hex2arr((P.qd_full_hex||'').slice(0, 2*13000)));
  if(P.qd_full_hex){
    try{ dumpR('uk(QD|空)', UK(QD,QD.length,EMPTY,0)); }catch(e){S({m:'ukQD err '+String(e).slice(0,60)});}
    try{ var off=QD.slice?null:null; }catch(e){}
    // payload[8:] 变体 (跳过 u32 长度字段错位)
    try{ dumpR('uk(PAY|dk32)', UK(PAY,PAY.length,dkA,32)); }catch(e){}
  }
  // addKey=md5+trailer 组合 尾料提示 u32=4 可能选块索引
  try{ dumpR('uk(PAY|MD5)', UK(PAY,PAY.length,MD5,16)); }catch(e){}
  try{ dumpR('uk(PAY|TRL16)', UK(PAY,PAY.length,TRL.slice?Java.array('byte',Array.from(TRL).slice(0,16).map(function(c){return c>127?c-256:c;})):TRL,16)); }catch(e){}
  // trailer u32=4 → 池子第5块? uk(data,len,sel16,16)
  var POOLHEX='867f3f8c52916cba,b653750b67ca112a,bcfacdd59c862db0,a6b88e1324178bb6,89c99be68381f2f1';
  for(var bi=0;bi<5;bi++){
    var blk=Java.array('byte',hex2arr(POOLHEX.split(',')[bi]));
    try{ dumpR('uk(PAY|pool'+bi+')', UK(PAY,PAY.length,blk,16)); }catch(e){}
  }
  S({m:'=== v18 done ==='});
});