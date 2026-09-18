// hook_regnative_v3.js — attach 模式 + 双 RegisterNatives hook + Java 反射兜底
function S(o) { try { send(o); } catch (e) { } }

function addrInfo(ptr) {
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      var start = mods[i].base;
      var end = start.add(mods[i].size);
      if (ptr.compare(start) >= 0 && ptr.compare(end) < 0) {
        return mods[i].name + '+0x' + ptr.sub(start).toString(16);
      }
    }
    return String(ptr) + ' (未知模块)';
  } catch (e) {
    return String(ptr) + ' (解析失败)';
  }
}

function hookRN(rnAddr, label) {
  try {
    Interceptor.attach(rnAddr, {
      onEnter: function (args) {
        try {
          var jclass = args[1];
          var methods = args[2];
          var count = args[3].toInt32();
          var clsName = '?';
          try { clsName = Java.vm.getEnv().getClassName(jclass); } catch (e) { }

          if (count <= 0 || count > 500) return;

          var ptrSize = Process.pointerSize;
          var structSize = ptrSize * 3;
          var entries = [];

          for (var i = 0; i < count; i++) {
            var base = methods.add(i * structSize);
            var namePtr = base.readPointer();
            var sigPtr = base.add(ptrSize).readPointer();
            var fnPtr = base.add(ptrSize * 2).readPointer();

            var name = '?', sig = '?';
            try { name = namePtr.readCString(); } catch (e) { }
            try { sig = sigPtr.readCString(); } catch (e) { }

            var ai = addrInfo(fnPtr);
            var keyMethod = /unlock|add|setup|it\b|uk\b|sn\b|ak\b|sign|getKey|requestKey|loadLocal|addMap|isHasKey|getPreUserKey|init\b|enc|dec/.test(name);

            entries.push({ name: name, sig: sig, mod: ai, key: keyMethod });

            if (keyMethod) {
              S({ m: '★★ [' + clsName + '] ' + name + sig + ' → ' + ai + ' (' + label + ')' });
            }
          }

          var lower = clsName.toLowerCase();
          if (lower.indexOf('fock') >= 0 || lower.indexOf('nib') >= 0 || lower.indexOf('knobs') >= 0 ||
              lower.indexOf('yuewen') >= 0 || entries.some(function (e) { return e.key; })) {
            var summary = entries.map(function (e) {
              return e.name + e.sig + ' → ' + e.mod;
            }).join('\n  ');
            S({ m: '>>> [' + clsName + '] count=' + count + ' (' + label + ')\n  ' + summary });
          }
        } catch (e) {
          S({ m: '[RN err ' + label + '] ' + e });
        }
      }
    });
    S({ m: '✓ ' + label + ' hook 已挂载 @ ' + rnAddr });
  } catch (e) {
    S({ m: '✗ ' + label + ' hook 失败: ' + e });
  }
}

Java.perform(function () {
  S({ m: '=== RegisterNatives hook v3 (attach + dual) ===' });

  // 枚举相关模块
  var mods = Process.enumerateModules();
  var fockMods = [];
  for (var i = 0; i < mods.length; i++) {
    if (/fock|nib|knobs|jiagu|shell|omg/i.test(mods[i].name)) {
      fockMods.push(mods[i].name + '@' + mods[i].base);
    }
  }
  S({ m: '相关模块: ' + (fockMods.join(' | ') || '（暂无）') });

  // 查找所有含 RegisterNatives 的符号
  var art = Process.findModuleByName('libart.so');
  if (art) {
    var found = 0;
    var symbols = art.enumerateSymbols();
    for (var i = 0; i < symbols.length; i++) {
      if (symbols[i].name.indexOf('RegisterNatives') >= 0) {
        S({ m: '符号: ' + symbols[i].name + ' @ ' + symbols[i].address });
        hookRN(symbols[i].address, symbols[i].name.substring(0, 40));
        found++;
        if (found >= 4) break; // 最多 hook 4 个变体
      }
    }
    S({ m: '共 hook ' + found + ' 个 RegisterNatives 变体' });
  }

  // ★ Java 层反射枚举（兜底——即使 hook 没抓到，也能看到 native 方法声明）
  setTimeout(function () {
    Java.perform(function () {
      S({ m: '=== Java 层 native 方法枚举 ===' });
      var classes = [
        'com.yuewen.fock.Fock',
        'com.yuewen.fock.FockUtil',
        'com.yuewen.fock.FockResult',
        'com.yuewen.fock.ErrorLogHandler'
      ];
      for (var ci = 0; ci < classes.length; ci++) {
        try {
          var cls = Java.use(classes[ci]);
          S({ m: '✓ ' + classes[ci] });
          var methods = cls.class.getDeclaredMethods();
          for (var mi = 0; mi < methods.length; mi++) {
            var m = methods[mi];
            var mods2 = m.getModifiers();
            var isNative = (mods2 & 0x100) !== 0;
            S({ m: '  ' + (isNative ? '★ native ' : '  ') + m.getName() + ' : ' + m.toGenericString() });
          }
          // 列出字段
          var fields = cls.class.getDeclaredFields();
          for (var fi = 0; fi < fields.length; fi++) {
            S({ m: '  field: ' + fields[fi].getType().getName() + ' ' + fields[fi].getName() });
          }
        } catch (e) {
          S({ m: '✗ ' + classes[ci] + ': ' + e });
        }
      }
    });
  }, 5000);

  // 轮询新模块
  var seen = {};
  setInterval(function () {
    var ms = Process.enumerateModules();
    for (var i = 0; i < ms.length; i++) {
      if (/fock|nib|knobs/.test(ms[i].name) && !seen[ms[i].name]) {
        seen[ms[i].name] = true;
        S({ m: '★ ' + ms[i].name + ' 已加载 base=' + ms[i].base + ' size=0x' + ms[i].size.toString(16) });
      }
    }
  }, 2000);
});
