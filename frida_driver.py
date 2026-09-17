#!/usr/bin/env python3
# frida_driver.py — spawn → attach → 挂自杀点 → resume → 定时探测（绕开 CLI 管道崩溃）
import frida, sys, time, json, os

PKG = os.environ.get('TARGET_PKG', 'com.qidian.QDReader')
WAIT = int(os.environ.get('WAIT_SEC', '30'))
MODE = os.environ.get('MODE', 'd')

JS = r'''
var LOGS = [];
function S(o){ try{ send(o); }catch(e){} }
// ① 立刻挂自杀点（spawn 阶段，壳自检之前）
var FNS = ['android_set_abort_message','__android_log_assert','abort','exit','_exit','kill','pthread_kill','raise'];
FNS.forEach(function(nm){
  try{
    var p = Module.getExportByName(null, nm);
    if(!p) return;
    Interceptor.attach(p, { onEnter: function(a){
      var extra='';
      try{
        if(nm.indexOf('abort_message')>=0 || nm.indexOf('log_assert')>=0) extra=' msg='+a[0].readCString();
        else if(nm==='kill') extra=' sig='+a[1].toInt32();
        else if(nm==='pthread_kill'||nm==='raise') extra=' arg0='+a[0].toInt32();
      }catch(e){ extra=' (读失败)'; }
      S({m:'★★ ['+nm+'] 被调用'+extra});
    }});
    S({m:'✓ 已挂 '+nm});
  }catch(e){}
});
rpc.exports = {
  status: function(){
    var out = {alive:true, modules:[]};
    try{
      var ms = Process.enumerateModules();
      out.moduleCount = ms.length;
      ms.forEach(function(m){ if(/fock|nib|knobs|shell|jiagu|omg|stub/i.test(m.name)) out.modules.push(m.name); });
    }catch(e){ out.err = String(e); }
    return out;
  },
  probeFock: function(){
    var r = {ok:false};
    try{
      Java.perform(function(){
        try{
          var FU = Java.use('com.qidian.QDReader.component.util.FockUtil');
          var inst = FU.INSTANCE.value;
          r.hasFockUtil = true;
          try{ r.getKey = String(inst.getKey()).slice(0,40); }catch(e){ r.getKeyErr=String(e).slice(0,80); }
          try{ r.isHasKey = inst.isHasKey(); }catch(e){}
          var ms = FU.class.getDeclaredMethods(), names=[];
          for(var i=0;i<ms.length;i++) names.push(String(ms[i].getName()));
          r.methodCount = names.length;
          r.hasAddKeypool = names.indexOf('addKeypool') >= 0;
          r.hasAddMap = names.indexOf('addMap') >= 0;
          r.ok = true;
        }catch(e){ r.err = String(e).slice(0,160); }
      });
    }catch(e){ r.outer = String(e).slice(0,160); }
    return r;
  },
  tryNativeFock: function(){
    var r = {};
    try{
      ['libfock.so','libfockrt.so','libnib.so','libknobs.so'].forEach(function(n){
        var m = Process.findModuleByName(n);
        if(m){ r[n] = {base:''+m.base, size:m.size};
          try{ var ex = m.enumerateExports(); r[n].exports = ex.length; }catch(e){}
        }
      });
      Process.enumerateModules().forEach(function(m){
        if(/shell|jiagu|stub/i.test(m.name)) r['shell_'+m.name] = true;
      });
    }catch(e){ r.err = String(e); }
    return r;
  }
};
S({m:'=== payload 已加载，自杀点已挂 ==='});
'''

def on_message(msg, data):
    if msg.get('type') == 'send':
        p = msg.get('payload') or {}
        print('[J]', p.get('m') if isinstance(p, dict) else p, flush=True)
    elif msg.get('type') == 'error':
        print('[ERR]', msg.get('stack') or msg.get('description'), flush=True)

def main():
    print('=== 连接 frida-server ===', flush=True)
    dev = frida.get_device_manager().add_remote_device('127.0.0.1:27042')
    print('=== spawn', PKG, '===', flush=True)
    pid = dev.spawn([PKG])
    print('spawned pid=', pid, flush=True)
    sess = dev.attach(pid)
    scr = sess.create_script(JS)
    scr.on('message', on_message)
    scr.load()
    print('=== resume ===', flush=True)
    dev.resume(pid)
    # ② 分段观测
    for t in (5, 12, 25, 45, WAIT):
        time.sleep(max(1, t - (0 if t==5 else 0)) if t==5 else 8)
        try:
            st = scr.exports_sync.status()
            print('  [t~%ds] 存活=%s 模块数=%s 相关=%s' % (t, st.get('alive'), st.get('moduleCount'), st.get('modules')), flush=True)
        except Exception as e:
            print('  [t~%ds] status 失败: %s' % (t, str(e)[:100]), flush=True)
        if t >= 25:
            try:
                nf = scr.exports_sync.try_native_fock()
                print('  [t~%ds] native fock: %s' % (t, json.dumps(nf, ensure_ascii=False)[:300]), flush=True)
            except Exception as e:
                print('  [t~%ds] native 探测失败: %s' % (t, str(e)[:100]), flush=True)
    # ③ 最后读 Java 层（此时自杀点已挂，理论上能活）
    print('=== 最终 Fock 探测 ===', flush=True)
    try:
        r = scr.exports_sync.probe_fock()
        print('PROBE_RESULT ' + json.dumps(r, ensure_ascii=False), flush=True)
    except Exception as e:
        print('probe 失败:', str(e)[:200], flush=True)
    try: sess.detach()
    except Exception: pass

if __name__ == '__main__':
    main()
