#!/usr/bin/env python3
# frida_win.py — 单会话编排：attach 一次 → 读 userKey → 取同源密文 → 解锁
import frida, time, json, subprocess, os, sys

PKG = 'com.qidian.QDReader'
BOOK = os.environ.get('BOOK', '1049120379')
CID  = os.environ.get('CID', '903350205')
PORT = '127.0.0.1:27042'

JS = r'''
function S(o){ try{ send(o); }catch(e){} }
function clip(s,n){ try{ s=String(s); return s.length>n ? s.slice(0,n)+'…[len='+s.length+']' : s; }catch(e){ return '?'; } }
function dumpRes(r, label){
  if(!r){ S({m:label+' → null'}); return null; }
  try{
    var fs=r.getClass().getDeclaredFields(), o={}, plain=null;
    for(var i=0;i<fs.length;i++){
      fs[i].setAccessible(true); var v=fs[i].get(r);
      if(v===null){ o[fs[i].getName()]=null; continue; }
      if(v.getClass().getName()==='[B'){
        var s2=''; try{ s2=Java.use('java.lang.String').$new(v,'UTF-8')+''; }catch(e){}
        o[fs[i].getName()]='len='+v.length;
        if(v.length>100){
          var cn=0; for(var k=0;k<s2.length;k++){ var c=s2.charCodeAt(k); if(c>=0x4e00&&c<=0x9fff) cn++; }
          S({m:'★★★★★★★ 明文！！！len='+v.length+' 中文字='+cn});
          S({m:'★★★ 正文', text:s2.slice(0,3000)});
          plain = s2;
        }
      } else o[fs[i].getName()]=clip(v,60);
    }
    S({m:label+' → '+JSON.stringify(o)});
    return plain;
  }catch(e){ S({m:label+' 读字段失败 '+String(e).slice(0,90)}); return null; }
}
rpc.exports = {
  getuserkey: function(){
    var r={};
    Java.perform(function(){
      try{
        var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
        var inst=FU.INSTANCE.value;
        r.userKey = String(inst.getPreUserKey()||'');
        r.getKey = String(inst.getKey());
        r.isHasKey = inst.isHasKey();
        r.ok = true;
      }catch(e){ r.err=String(e).slice(0,160); }
    });
    return r;
  },
  unlockall: function(blobB64, chId){
    var out=[];
    Java.perform(function(){
      try{
        var FU=Java.use('com.qidian.QDReader.component.util.FockUtil');
        var inst=FU.INSTANCE.value;
        var ctx=Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        var uk=String(inst.getPreUserKey()||'');
        try{ inst.init(ctx, uk); }catch(e){}
        try{ var m=inst.loadLocalKey(ctx); if(m) inst.addMap(Java.cast(m, Java.use('java.util.Map'))); }catch(e){}
        var cands=[['章节ID',chId],['userKey',uk],['空串','']];
        for(var i=0;i<cands.length;i++){
          try{
            var res=inst.unlock(blobB64, cands[i][1]);
            var p=dumpRes(res, 'FU.unlock['+cands[i][0]+']');
            out.push({tag:cands[i][0], plain:p||''});
          }catch(e){ S({m:'unlock['+cands[i][0]+'] 异常 '+String(e).slice(0,120)}); out.push({tag:cands[i][0],err:String(e).slice(0,120)}); }
        }
        // Fock 3 参重载
        try{
          var FK=Java.use('com.yuewen.fock.Fock');
          var ms=FK.class.getDeclaredMethods();
          for(var j=0;j<ms.length;j++){
            var nm=String(ms[j].getName());
            if(nm!=='unlock' && nm!=='unlockData') continue;
            var ps=ms[j].getParameterTypes(), pt=[];
            for(var q=0;q<ps.length;q++) pt.push(String(ps[q].getName()).split('.').pop());
            S({m:'Fock.'+nm+'('+pt.join(',')+')'});
            if(pt.length===3 && pt.join(',')==='String,String,String'){
              var combos=[[blobB64,uk,chId],[blobB64,chId,uk]];
              for(var c=0;c<combos.length;c++){
                try{ var r3=ms[j].invoke(null, Java.array('java.lang.Object', combos[c]));
                     var p3=dumpRes(r3, 'Fock.'+nm+'3[组合'+c+']');
                     out.push({tag:'Fock3_'+c, plain:p3||''});
                }catch(e){ S({m:' 3参组合'+c+' 异常 '+String(e).slice(0,100)}); }
              }
            }
          }
        }catch(e){ S({m:'Fock 反射失败 '+String(e).slice(0,110)}); }
      }catch(e){ S({m:'unlockall 顶层异常 '+String(e).slice(0,160)}); }
    });
    return out;
  }
};
S({m:'=== orchestrator payload 就绪 ==='});
'''

PLAIN_OUT = '/tmp/plain_464_WIN.txt'

def run(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)

def on_message(msg, data):
    if msg.get('type')=='send':
        p=msg.get('payload') or {}
        print('[J]', p.get('m') if isinstance(p,dict) else p, flush=True)
    elif msg.get('type')=='error':
        print('[ERR]', (msg.get('stack') or msg.get('description') or '')[:300], flush=True)

def main():
    dev = frida.get_device_manager().add_remote_device(PORT)
    P = run("adb -s localhost:5555 shell pidof com.qidian.QDReader").stdout.strip().split('\n')[0].strip()
    print('App PID =', P, flush=True)
    if not P:
        print('NO_APP'); return
    sess = dev.attach(int(P))
    scr = sess.create_script(JS)
    scr.on('message', on_message)
    scr.load()
    time.sleep(1)

    # ① 读 userKey
    r = scr.exports_sync.getuserkey()
    print('① getuserkey →', json.dumps(r, ensure_ascii=False), flush=True)
    uk = (r or {}).get('userKey') or ''
    if not uk:
        print('!! userKey 为空，无法同源'); return

    # ② 用同一身份取密文（同源）
    env = dict(os.environ)
    env.update({'DEV_ANDROID_ID': uk, 'DEV_IMEI': uk, 'DEV_MODEL': 'redroid11_arm64',
                'SESS': '/tmp/sess.json', 'BOOK': BOOK, 'CID': CID})
    o = run('python3 argus_fetch.py', env=env)
    print('② argus 输出尾部:', (o.stdout or '')[-400:], flush=True)
    blob = ''
    try:
        d = json.load(open('/tmp/params.json'))
        blob = d.get('blob_b64','')
        print('② 同源密文 len=%d  Key=%s…' % (len(blob), (d.get('Key') or '')[:24]), flush=True)
    except Exception as e:
        print('② 读 params 失败', e); return
    if not blob:
        print('!! 无密文'); return

    # ③ 同一会话里解锁
    print('③ 开始解锁…', flush=True)
    res = scr.exports_sync.unlockall(blob, CID)
    print('③ 结果:', json.dumps(res, ensure_ascii=False)[:800], flush=True)
    for item in (res or []):
        if item.get('plain'):
            open(PLAIN_OUT,'w',encoding='utf-8').write(item['plain'])
            print('★★★ 明文已保存 %s (%d 字符)' % (PLAIN_OUT, len(item['plain'])), flush=True)
            break
    try: sess.detach()
    except Exception: pass

if __name__ == '__main__':
    main()
