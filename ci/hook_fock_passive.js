// hook_fock_passive.js — 被动监听：hook unlock/uk/addKeys，等 App 自然调用
function S(o) { try { send(o); } catch (e) { } }

Java.perform(function () {
    S({ m: '=== Passive Hook v1 ===' });

    try {
        var Fock = Java.use('com.yuewen.fock.Fock');

        // ★ Hook unlock(4参数版) — 拦截 App 自然调用
        try {
            Fock.unlock.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'com.yuewen.fock.Fock$ErrorLogHandler').implementation = function (cipher, p2, userKey, handler) {
                S({ m: '★★★ unlock 被调用!' });
                S({ m: '  cipher (前64) = ' + cipher.substring(0, 64) });
                S({ m: '  cipher.length = ' + cipher.length });
                S({ m: '  param2 = ' + p2 });
                S({ m: '  userKey = ' + userKey });

                var result = this.unlock(cipher, p2, userKey, handler);
                if (result) {
                    try {
                        var rClass = result.getClass();
                        var stField = rClass.getDeclaredField('status'); stField.setAccessible(true);
                        S({ m: '  ★ status = ' + stField.get(result) });
                        
                        var dsField = rClass.getDeclaredField('dataSize'); dsField.setAccessible(true);
                        S({ m: '  ★ dataSize = ' + dsField.get(result) });
                        
                        var dField = rClass.getDeclaredField('data'); dField.setAccessible(true);
                        var dataVal = dField.get(result);
                        if (dataVal) {
                            // byte[] → hex string
                            var hex = '';
                            for (var i = 0; i < Math.min(200, dataVal.length); i++) {
                                var b = dataVal[i] & 0xff;
                                hex += (b < 16 ? '0' : '') + b.toString(16);
                            }
                            S({ m: '  ★ data hex (前200B) = ' + hex });
                            
                            // 也尝试转文本
                            try {
                                var StringCls = Java.use('java.lang.String');
                                var str = StringCls.$new(dataVal, 'UTF-8');
                                S({ m: '  ★★★ data (UTF-8) = ' + str.toString().substring(0, Math.min(500, str.toString().length())) });
                            } catch (e) { }
                        } else {
                            S({ m: '  data = null' });
                        }
                    } catch (e) {
                        S({ m: '  反射失败: ' + e });
                    }
                } else {
                    S({ m: '  result = null' });
                }
                return result;
            };
            S({ m: '✓ unlock(4参数) hook 已挂载' });
        } catch (e) {
            S({ m: '✗ unlock hook: ' + e });
        }

        // ★ Hook unlock(5参数版)
        try {
            Fock.unlock.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'com.yuewen.fock.Fock$ErrorLogHandler').implementation = function (a, b, c, d, h) {
                S({ m: '★★★ unlock(5参数) 被调用!' });
                S({ m: '  a (前64) = ' + a.substring(0, 64) });
                S({ m: '  b = ' + b });
                S({ m: '  c = ' + c });
                S({ m: '  d = ' + d });
                var result = this.unlock(a, b, c, d, h);
                if (result) {
                    try {
                        var rClass = result.getClass();
                        var stField = rClass.getDeclaredField('status'); stField.setAccessible(true);
                        S({ m: '  ★ status = ' + stField.get(result) });
                        var dField = rClass.getDeclaredField('data'); dField.setAccessible(true);
                        var dataVal = dField.get(result);
                        if (dataVal) {
                            try {
                                var StringCls = Java.use('java.lang.String');
                                var str = StringCls.$new(dataVal, 'UTF-8');
                                S({ m: '  ★★★ data (UTF-8) = ' + str.toString().substring(0, Math.min(500, str.toString().length())) });
                            } catch (e) { }
                        }
                    } catch (e) { }
                }
                return result;
            };
            S({ m: '✓ unlock(5参数) hook 已挂载' });
        } catch (e) {
            S({ m: '✗ unlock(5参数) hook: ' + e });
        }

        // ★ Hook addKeys — 看 App 怎么调的
        try {
            Fock.addKeys.implementation = function (a, b, c, h) {
                S({ m: '★★★ addKeys 被调用!' });
                S({ m: '  a (前64) = ' + a.substring(0, 64) });
                S({ m: '  b (前64) = ' + b.substring(0, 64) });
                S({ m: '  c = ' + c });
                return this.addKeys(a, b, c, h);
            };
            S({ m: '✓ addKeys hook 已挂载' });
        } catch (e) {
            S({ m: '✗ addKeys hook: ' + e });
        }

        // ★ Hook unlockData(byte[], ...)
        try {
            Fock.unlockData.implementation = function (data, p2, userKey, h) {
                S({ m: '★★★ unlockData 被调用!' });
                S({ m: '  data.length = ' + data.length });
                S({ m: '  param2 = ' + p2 });
                S({ m: '  userKey = ' + userKey });
                var result = this.unlockData(data, p2, userKey, h);
                if (result) {
                    try {
                        var rClass = result.getClass();
                        var stField = rClass.getDeclaredField('status'); stField.setAccessible(true);
                        S({ m: '  ★ status = ' + stField.get(result) });
                        var dField = rClass.getDeclaredField('data'); dField.setAccessible(true);
                        var dataVal = dField.get(result);
                        if (dataVal) {
                            try {
                                var StringCls = Java.use('java.lang.String');
                                var str = StringCls.$new(dataVal, 'UTF-8');
                                S({ m: '  ★★★ data (UTF-8) = ' + str.toString().substring(0, Math.min(500, str.toString().length())) });
                            } catch (e) { }
                        }
                    } catch (e) { }
                }
                return result;
            };
            S({ m: '✓ unlockData hook 已挂载' });
        } catch (e) {
            S({ m: '✗ unlockData hook: ' + e });
        }

        // ★ 也 hook uk (底层 native)
        try {
            Fock.uk.implementation = function (data, dataLen, key, keyLen) {
                S({ m: '★★★ uk 被调用!' });
                S({ m: '  data.length = ' + data.length + ' dataLen = ' + dataLen });
                S({ m: '  key.length = ' + key.length + ' keyLen = ' + keyLen });
                var result = this.uk(data, dataLen, key, keyLen);
                if (result) {
                    try {
                        var rClass = result.getClass();
                        var stField = rClass.getDeclaredField('status'); stField.setAccessible(true);
                        S({ m: '  ★ uk.status = ' + stField.get(result) });
                        var dField = rClass.getDeclaredField('data'); dField.setAccessible(true);
                        var dataVal = dField.get(result);
                        if (dataVal) {
                            try {
                                var StringCls = Java.use('java.lang.String');
                                var str = StringCls.$new(dataVal, 'UTF-8');
                                S({ m: '  ★★★ uk.data = ' + str.toString().substring(0, Math.min(500, str.toString().length())) });
                            } catch (e) { }
                        }
                    } catch (e) { }
                }
                return result;
            };
            S({ m: '✓ uk hook 已挂载' });
        } catch (e) {
            S({ m: '✗ uk hook: ' + e });
        }

        // ★ 主动触发：用 deeplink 让 App 打开一个 VIP 章节
        S({ m: '--- 触发 App 读章节 ---' });
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var context = ActivityThread.currentApplication().getApplicationContext();
            var Intent = Java.use('android.content.Intent');
            var Uri = Java.use('android.net.Uri');
            
            // 起点 deep link: qdreader://bookdetail?bookId=1049120379
            var intent = Intent.$new(Intent.ACTION_VIEW, Uri.parse('qdreader://bookdetail?bookId=1049120379'));
            intent.addFlags(0x10000000); // FLAG_ACTIVITY_NEW_TASK
            context.startActivity(intent);
            S({ m: '✓ 已发送 deep link qdreader://bookdetail?bookId=1049120379' });
        } catch (e) {
            S({ m: '⚠ deep link: ' + e });
        }

    } catch (e) {
        S({ m: '✗ Fatal: ' + e });
    }

    S({ m: '=== Passive Hook 已挂载，等待 App 自然调用... ===' });
});
