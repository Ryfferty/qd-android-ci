// hook_regnative.js — hook RegisterNatives 找 unlock 对应的 native 函数地址
// 关键修复：用 Java.perform（不是 setImmediate），打印方法名+签名+fnPtr+模块偏移
function S(o) { try { send(o); } catch (e) { } }

// 把地址解析成"模块名+偏移"
function addrInfo(ptr) {
  try {
    var s = ptr.toString();
    // 遍历所有模块找包含该地址的
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      var start = mods[i].base;
      var end = start.add(mods[i].size);
      if (ptr.compare(start) >= 0 && ptr.compare(end) < 0) {
        var off = ptr.sub(start);
        return mods[i].name + '+0x' + off.toString(16);
      }
    }
    return s + ' (未知模块)';
  } catch (e) {
    return String(ptr) + ' (解析失败)';
  }
}

Java.perform(function () {
  S({ m: '=== RegisterNatives hook 开始 ===' });

  // 枚举当前已加载模块
  var mods = Process.enumerateModules();
  var fockMods = [];
  for (var i = 0; i < mods.length; i++) {
    var n = mods[i].name;
    if (/fock|nib|knobs|shell|jiagu|omg|star|ola|nywqmp|ostar/i.test(n)) {
      fockMods.push(n + '@' + mods[i].base + '(+0x' + mods[i].size.toString(16) + ')');
    }
  }
  S({ m: '当前相关模块: ' + (fockMods.join(' | ') || '（暂无）') });

  // hook RegisterNatives — 从 libart.so 找符号
  var rn = null;
  var art = Process.findModuleByName('libart.so');
  if (art) {
    var syms = [
      '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi',
      '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodj'
    ];
    for (var si = 0; si < syms.length; si++) {
      try { rn = art.getExportByName(syms[si]); if (rn) break; } catch (e) { }
    }
  }
  if (!rn) {
    try { rn = Module.getExportByName(null, 'RegisterNatives'); } catch (e) { }
  }

  if (rn) {
    S({ m: '✓ RegisterNatives @ ' + rn });

    Interceptor.attach(rn, {
      onEnter: function (args) {
        try {
          var env = args[0];
          var jclass = args[1];
          var methods = args[2];
          var count = args[3].toInt32();

          // 获取类名
          var clsName = '?';
          try { clsName = Java.vm.getEnv().getClassName(jclass); } catch (e) { }

          // 只关注 fock/FockUtil/nib/knobs 相关的类
          var lower = clsName.toLowerCase();
          var interesting = (lower.indexOf('fock') >= 0 ||
                             lower.indexOf('nib') >= 0 ||
                             lower.indexOf('knobs') >= 0 ||
                             lower.indexOf('foc') >= 0 ||
                             lower.indexOf('util') >= 0 && lower.indexOf('qidian') >= 0);

          // 也捕获所有类（不过滤），但只详细记录有趣的
          if (count > 0 && count < 500) {
            var entries = [];
            var ptrSize = Process.pointerSize;
            var structSize = ptrSize * 3; // name, sig, fnPtr

            for (var i = 0; i < count; i++) {
              var base = methods.add(i * structSize);
              var namePtr = base.readPointer();
              var sigPtr = base.add(ptrSize).readPointer();
              var fnPtr = base.add(ptrSize * 2).readPointer();

              var name = '?', sig = '?';
              try { name = namePtr.readCString(); } catch (e) { }
              try { sig = sigPtr.readCString(); } catch (e) { }

              var ai = addrInfo(fnPtr);

              // 对 unlock/add/it/uk/sn/ak/setup 等关键方法特别标记
              var keyMethod = /unlock|add|setup|it\b|uk\b|sn\b|ak\b|sign|getKey|requestKey|loadLocal|addMap|isHasKey|getPreUserKey|init\b/.test(name);

              entries.push({
                name: name,
                sig: sig,
                fn: String(fnPtr),
                mod: ai,
                key: keyMethod
              });

              // 关键方法立即发送
              if (keyMethod) {
                S({ m: '★★ [' + clsName + '] ' + name + sig + ' → ' + ai });
              }
            }

            // 发送完整注册表（类级别）
            if (interesting || entries.some(function (e) { return e.key; })) {
              var summary = entries.map(function (e) {
                return e.name + e.sig + '→' + e.mod;
              }).join('\n  ');
              S({ m: '>>> [' + clsName + '] count=' + count + '\n  ' + summary });
            } else if (count <= 20) {
              // 其他类只发方法名列表
              var names = entries.map(function (e) { return e.name; }).join(',');
              S({ m: '[' + clsName + '] count=' + count + ' names=' + names });
            }
          }
        } catch (e) {
          S({ m: '[RN err] ' + e });
        }
      }
    });
    S({ m: '✓ RegisterNatives hook 已挂载，等待 App 注册 native 方法...' });
  } else {
    S({ m: '✗ 找不到 RegisterNatives 符号' });
  }

  // 同时 hook JNI_OnLoad，确认 .so 何时加载
  var onLoadMods = ['libfock.so', 'libfockrt.so', 'libnib.so', 'libknobs.so', 'libshell-supervbasic.2019.so', 'libomg.so'];
  var seenLoaded = {};
  var checkInterval = setInterval(function () {
    for (var mi = 0; mi < onLoadMods.length; mi++) {
      var mn = onLoadMods[mi];
      if (seenLoaded[mn]) continue;
      var mod = Process.findModuleByName(mn);
      if (mod) {
        seenLoaded[mn] = true;
        S({ m: '★ ' + mn + ' 已加载 base=' + mod.base + ' size=0x' + mod.size.toString(16) });
      }
    }
  }, 2000);

  // 30 秒后停止轮询
  setTimeout(function () { clearInterval(checkInterval); S({ m: '模块轮询结束' }); }, 30000);
});
