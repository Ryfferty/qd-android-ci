// hook_regnative_v2.js — 修复版：spawn 模式 + 模糊匹配 RegisterNatives 符号
// 两个关键修复：
// 1. 用 enumerateSymbols 模糊匹配 RegisterNatives（不用硬编码 mangled name）
// 2. 同时 hook dlopen 等待 libfock.so 加载（catch 第二批注册）
function S(o) { try { send(o); } catch (e) { } }

function addrInfo(ptr) {
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      var start = mods[i].base;
      var end = start.add(mods[i].size);
      if (ptr.compare(start) >= 0 && ptr.compare(end) < 0) {
        var off = ptr.sub(start);
        return mods[i].name + '+0x' + off.toString(16);
      }
    }
    return String(ptr) + ' (未知模块)';
  } catch (e) {
    return String(ptr) + ' (解析失败)';
  }
}

// 方式1: 模糊搜索 libart.so 中含 RegisterNatives 的符号
function findRegisterNatives() {
  var art = Process.findModuleByName('libart.so');
  if (!art) { S({ m: '✗ libart.so 未加载' }); return null; }

  // 先试 exports
  var exports = art.enumerateExports();
  for (var i = 0; i < exports.length; i++) {
    if (exports[i].name.indexOf('RegisterNatives') >= 0) {
      S({ m: '✓ 找到 export: ' + exports[i].name + ' @ ' + exports[i].address });
      return exports[i].address;
    }
  }

  // 再试 symbols（很多 ART 函数不在 exports 表）
  var symbols = art.enumerateSymbols();
  for (var i = 0; i < symbols.length; i++) {
    if (symbols[i].name.indexOf('RegisterNatives') >= 0) {
      S({ m: '✓ 找到 symbol: ' + symbols[i].name + ' @ ' + symbols[i].address });
      return symbols[i].address;
    }
  }

  S({ m: '✗ RegisterNatives 符号未找到 (exports=' + exports.length + ' symbols=' + symbols.length + ')' });
  return null;
}

function hookRegisterNatives(rnAddr) {
  Interceptor.attach(rnAddr, {
    onEnter: function (args) {
      try {
        var env = args[0];
        var jclass = args[1];
        var methods = args[2];
        var count = args[3].toInt32();

        var clsName = '?';
        try { clsName = Java.vm.getEnv().getClassName(jclass); } catch (e) { }

        if (count > 0 && count < 500) {
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
            var keyMethod = /unlock|add|setup|it\b|uk\b|sn\b|ak\b|sign|getKey|requestKey|loadLocal|addMap|isHasKey|getPreUserKey|init\b/.test(name);

            entries.push({ name: name, sig: sig, mod: ai, key: keyMethod });

            if (keyMethod) {
              S({ m: '★★ [' + clsName + '] ' + name + sig + ' → ' + ai });
            }
          }

          // 发送含 fock/Fock 的类完整注册表
          var lower = clsName.toLowerCase();
          if (lower.indexOf('fock') >= 0 || lower.indexOf('nib') >= 0 || lower.indexOf('knobs') >= 0 ||
              entries.some(function (e) { return e.key; })) {
            var summary = entries.map(function (e) {
              return e.name + e.sig + '→' + e.mod;
            }).join('\n  ');
            S({ m: '>>> [' + clsName + '] count=' + count + '\n  ' + summary });
          } else if (count <= 20) {
            var names = entries.map(function (e) { return e.name; }).join(',');
            S({ m: '[' + clsName + '] count=' + count + ' names=' + names });
          }
        }
      } catch (e) {
        S({ m: '[RN err] ' + e });
      }
    }
  });
  S({ m: '✓ RegisterNatives hook 已挂载' });
}

Java.perform(function () {
  S({ m: '=== RegisterNatives hook v2 开始 ===' });

  // 枚举相关模块
  var mods = Process.enumerateModules();
  var fockMods = [];
  for (var i = 0; i < mods.length; i++) {
    var n = mods[i].name;
    if (/fock|nib|knobs|shell|jiagu|omg|star|ola|nywqmp|ostar/i.test(n)) {
      fockMods.push(n + '@' + mods[i].base + '(+0x' + mods[i].size.toString(16) + ')');
    }
  }
  S({ m: '当前相关模块: ' + (fockMods.join(' | ') || '（暂无）') });

  // 查找并 hook RegisterNatives
  var rn = findRegisterNatives();
  if (rn) {
    hookRegisterNatives(rn);
  } else {
    S({ m: '尝试备选方案：hook JNI_OnLoad 中的注册...' });
  }

  // 同时枚举所有已注册的 native 方法（Java 层遍历）
  // 如果 App 已经跑过了，RegisterNatives 可能已经调用完
  // 用 Java 反射找 FockUtil / Fock 的 native 方法声明
  setTimeout(function () {
    Java.perform(function () {
      S({ m: '=== Java 层枚举 native 方法 ===' });
      var classes = ['com.yuewen.fock.Fock', 'com.yuewen.fock.FockUtil'];
      for (var ci = 0; ci < classes.length; ci++) {
        try {
          var cls = Java.use(classes[ci]);
          S({ m: '✓ 找到类: ' + classes[ci] });

          // 列出所有方法
          var methods = cls.class.getDeclaredMethods();
          for (var mi = 0; mi < methods.length; mi++) {
            var m = methods[mi];
            var mods2 = m.getModifiers();
            var isNative = (mods2 & 0x100) !== 0; // ACC_NATIVE
            S({ m: '  ' + (isNative ? '★ native ' : '  ') + m.getName() + ' → ' + m.toGenericString() });
          }
        } catch (e) {
          S({ m: '✗ 类 ' + classes[ci] + ' 未找到: ' + e });
        }
      }

      // 也试 FockResult
      try {
        var fr = Java.use('com.yuewen.fock.FockResult');
        S({ m: '✓ FockResult 字段:' });
        var fields = fr.class.getDeclaredFields();
        for (var fi = 0; fi < fields.length; fi++) {
          S({ m: '  ' + fields[fi].getType().getName() + ' ' + fields[fi].getName() });
        }
      } catch (e) {
        S({ m: '✗ FockResult: ' + e });
      }
    });
  }, 3000);

  // 轮询新模块加载
  var seenLoaded = {};
  var checkInterval = setInterval(function () {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      var mn = mods[i].name;
      if (/fock|nib|knobs/.test(mn) && !seenLoaded[mn]) {
        seenLoaded[mn] = true;
        S({ m: '★ ' + mn + ' 已加载 base=' + mods[i].base + ' size=0x' + mods[i].size.toString(16) });
      }
    }
  }, 2000);

  setTimeout(function () { clearInterval(checkInterval); S({ m: '模块轮询结束' }); }, 30000);
});
