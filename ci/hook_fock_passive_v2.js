// hook_fock_passive_v2.js — 被动监听 v2：修复 deeplink + 更长等待
function S(o) { try { send(o); } catch (e) { } }

Java.perform(function () {
    S({ m: '=== Passive Hook v2 ===' });

    try {
        var Fock = Java.use('com.yuewen.fock.Fock');

        // ★ Hook unlock(4参数版)
        try {
            Fock.unlock.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'com.yuewen.fock.Fock$ErrorLogHandler').implementation = function (cipher, p2, userKey, handler) {
                S({ m: '★★★ unlock(4) 被调用!' });
                S({ m: '  cipher.len=' + cipher.length + ' param2=' + p2 + ' userKey=' + userKey });
                var result = this.unlock(cipher, p2, userKey, handler);
                if (result) {
                    try {
                        var rClass = result.getClass();
                        var stField = rClass.getDeclaredField('status'); stField.setAccessible(true);
                        S({ m: '  ★ status=' + stField.get(result) });
                        var dsField = rClass.getDeclaredField('dataSize'); dsField.setAccessible(true);
                        S({ m: '  ★ dataSize=' + dsField.get(result) });
                        var dField = rClass.getDeclaredField('data'); dField.setAccessible(true);
                        var dataVal = dField.get(result);
                        if (dataVal) {
                            try {
                                var StringCls = Java.use('java.lang.String');
                                var str = StringCls.$new(dataVal, 'UTF-8');
                                S({ m: '  ★★★ data(UTF8)=' + str.toString().substring(0, Math.min(500, str.toString().length())) });
                            } catch (e) { S({ m: '  data conv: ' + e }); }
                        } else { S({ m: '  data=null' }); }
                    } catch (e) { S({ m: '  reflect: ' + e }); }
                } else { S({ m: '  result=null' }); }
                return result;
            };
            S({ m: '✓ unlock(4) hook' });
        } catch (e) { S({ m: '✗ unlock(4): ' + e }); }

        // ★ Hook addKeys
        try {
            Fock.addKeys.implementation = function (a, b, c, h) {
                S({ m: '★★★ addKeys 被调用!' });
                S({ m: '  a=' + a.substring(0, 64) });
                S({ m: '  b=' + b.substring(0, 64) });
                S({ m: '  c=' + c });
                return this.addKeys(a, b, c, h);
            };
            S({ m: '✓ addKeys hook' });
        } catch (e) { S({ m: '✗ addKeys: ' + e }); }

        // ★ Hook uk
        try {
            Fock.uk.implementation = function (data, dataLen, key, keyLen) {
                S({ m: '★★★ uk 被调用!' });
                S({ m: '  data.len=' + data.length + ' dataLen=' + dataLen });
                S({ m: '  key.len=' + key.length + ' keyLen=' + keyLen });
                // key hex
                var keyHex = '';
                for (var i = 0; i < Math.min(64, key.length); i++) {
                    var b = key[i] & 0xff;
                    keyHex += (b < 16 ? '0' : '') + b.toString(16);
                }
                S({ m: '  key hex=' + keyHex });
                var result = this.uk(data, dataLen, key, keyLen);
                if (result) {
                    try {
                        var rClass = result.getClass();
                        var stField = rClass.getDeclaredField('status'); stField.setAccessible(true);
                        S({ m: '  ★ uk.status=' + stField.get(result) });
                        var dField = rClass.getDeclaredField('data'); dField.setAccessible(true);
                        var dataVal = dField.get(result);
                        if (dataVal) {
                            try {
                                var StringCls = Java.use('java.lang.String');
                                var str = StringCls.$new(dataVal, 'UTF-8');
                                S({ m: '  ★★★ uk.data=' + str.toString().substring(0, Math.min(500, str.toString().length())) });
                            } catch (e) { }
                        }
                    } catch (e) { }
                }
                return result;
            };
            S({ m: '✓ uk hook' });
        } catch (e) { S({ m: '✗ uk: ' + e }); }

        // ★ 修复 deeplink — 用正确的 Intent 构造
        S({ m: '--- 触发 deeplink ---' });
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var context = ActivityThread.currentApplication().getApplicationContext();
            var Intent = Java.use('android.content.Intent');
            var Uri = Java.use('android.net.Uri');
            
            // 用 Intent.$new(String action, Uri uri) overload
            var uri = Uri.parse('qdreader://bookdetail?bookId=1049120379');
            var intent = Intent.$new('android.intent.action.VIEW', uri);
            intent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
            context.startActivity(intent);
            S({ m: '✓ deeplink 已发送: qdreader://bookdetail?bookId=1049120379' });
        } catch (e) {
            S({ m: '⚠ deeplink Intent: ' + e });
            // 备选：用 am start 命令
            try {
                var Runtime = Java.use('java.lang.Runtime');
                var proc = Runtime.getRuntime().exec(['am', 'start', '-a', 'android.intent.action.VIEW', '-d', 'qdreader://bookdetail?bookId=1049120379']);
                S({ m: '✓ am start 已执行' });
            } catch (e2) {
                S({ m: '⚠ am start: ' + e2 });
            }
        }

        // ★ 也尝试直接打开章节阅读页
        try {
            var ActivityThread2 = Java.use('android.app.ActivityThread');
            var context2 = ActivityThread2.currentApplication().getApplicationContext();
            var Intent2 = Java.use('android.content.Intent');
            var Uri2 = Java.use('android.net.Uri');
            
            // qdreader://reader?bookId=1049120379&chapterId=903364446
            var uri2 = Uri2.parse('qdreader://reader?bookId=1049120379&chapterId=903364446');
            var intent2 = Intent2.$new('android.intent.action.VIEW', uri2);
            intent2.addFlags(0x10000000);
            context2.startActivity(intent2);
            S({ m: '✓ deeplink reader 已发送: qdreader://reader?bookId=1049120379&chapterId=903364446' });
        } catch (e) {
            S({ m: '⚠ reader deeplink: ' + e });
        }

    } catch (e) {
        S({ m: '✗ Fatal: ' + e });
    }

    S({ m: '=== Passive Hook v2 已挂载，等待 App 调用... ===' });
});
