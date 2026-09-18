// hook_fock_oracle_v2.js — 先收集信息，再逐步解密
function S(o) { try { send(o); } catch (e) { } }

Java.perform(function () {
    S({ m: '=== Fock Oracle v2 ===' });

    try {
        var Fock = Java.use('com.yuewen.fock.Fock');
        S({ m: '✓ Fock 类已获取' });

        // ★ 先看 ErrorLogHandler 接口有哪些方法
        try {
            var ELH = Java.use('com.yuewen.fock.Fock$ErrorLogHandler');
            var elhMethods = ELH.class.getDeclaredMethods();
            for (var i = 0; i < elhMethods.length; i++) {
                S({ m: '  ErrorLogHandler.method: ' + elhMethods[i].toGenericString() });
            }
        } catch (e) {
            S({ m: '✗ ErrorLogHandler: ' + e });
        }

        // ★ 看 FockResult 有哪些字段和方法
        try {
            var FR = Java.use('com.yuewen.fock.Fock$FockResult');
            var frFields = FR.class.getDeclaredFields();
            for (var i = 0; i < frFields.length; i++) {
                frFields[i].setAccessible(true);
                S({ m: '  FockResult.field: ' + frFields[i].getType().getName() + ' ' + frFields[i].getName() });
            }
            var frMethods = FR.class.getDeclaredMethods();
            for (var i = 0; i < frMethods.length; i++) {
                S({ m: '  FockResult.method: ' + frMethods[i].toGenericString() });
            }
        } catch (e) {
            S({ m: '✗ FockResult: ' + e });
        }

        // ★ Step 1: setup
        S({ m: '--- Step 1: setup ---' });
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var context = ActivityThread.currentApplication().getApplicationContext();
            Fock.setup(context);
            S({ m: '✓ setup(Context) OK' });
        } catch (e) {
            S({ m: '✗ setup: ' + e });
        }

        // ★ Step 2: 收集环境信息（不调用 addKeys，先看状态）
        S({ m: '--- Step 2: 环境信息 ---' });
        try {
            var uk = Fock.currentUserKey();
            S({ m: '★ currentUserKey() = [' + uk + ']' });
        } catch (e) {
            S({ m: '✗ currentUserKey: ' + e });
        }

        try {
            var urk = Fock.urk();
            S({ m: '★ urk() = [' + urk + ']' });
        } catch (e) {
            S({ m: '✗ urk: ' + e });
        }

        try {
            var av = Fock.av();
            S({ m: '★ av() = [' + av + ']' });
        } catch (e) {
            S({ m: '✗ av: ' + e });
        }

        try {
            var versions = Fock.addedKeyVersions();
            S({ m: '★ addedKeyVersions() = ' + JSON.stringify(versions) });
        } catch (e) {
            S({ m: '✗ addedKeyVersions: ' + e });
        }

        // ★ Step 3: 尝试创建 ErrorLogHandler
        S({ m: '--- Step 3: 创建 ErrorLogHandler ---' });
        var handler = null;
        try {
            var ELH = Java.use('com.yuewen.fock.Fock$ErrorLogHandler');
            // 看接口方法后决定实现
            var elhMs = ELH.class.getDeclaredMethods();
            var methodNames = [];
            for (var i = 0; i < elhMs.length; i++) {
                methodNames.push(elhMs[i].getName());
            }
            S({ m: 'ErrorLogHandler methods: ' + methodNames.join(', ') });

            // 动态创建实现
            if (methodNames.length > 0) {
                var impl = {};
                for (var i = 0; i < methodNames.length; i++) {
                    impl[methodNames[i]] = function () {
                        S({ m: 'ErrorLogHandler.' + methodNames[i] + ' called' });
                        return null;
                    };
                }
                // Java.registerClass 需要 methods 对象
                var HandlerClass = Java.registerClass({
                    name: 'com.qidian.FridaErrHandler',
                    implements: [ELH],
                    methods: impl
                });
                handler = HandlerClass.$new();
                S({ m: '✓ ErrorLogHandler 实例已创建' });
            }
        } catch (e) {
            S({ m: '⚠ ErrorLogHandler 创建失败: ' + e + ' — 将用 null' });
        }

        // ★ Step 4: addKeys（谨慎尝试）
        S({ m: '--- Step 4: addKeys ---' });
        var keyA = 'EocbvAo4OFd8AlitMzMh3d+tpPVxbxpLZdaVzCI9flkyRYnVKVsI+w0J0x7Vhc0bDdtU6VFJ/gntPjKWGhfJWf9z8vS3Clr81XfqRUI+M1QSndGQLnJHB1KOC+xazz4u';
        var keyB = 'vdk5v1Ia2FBOk+Bkna/cMM3A8nRoLJnODnwwhELtVknuxwYjnVW8iNa25uMEBcB+xnLTfeqWMUDTkC16yztYLsc0BUFaWAX0Gt25/dEfyNcji03jgeSxUfcDf2iyyhWd';

        try {
            Fock.addKeys(keyA, keyB, '1639985422', handler);
            S({ m: '✓ addKeys 完成' });
        } catch (e) {
            S({ m: '✗ addKeys(A,B,v,h): ' + e });
            // 试 null handler
            try {
                Fock.addKeys(keyA, keyB, '1639985422', null);
                S({ m: '✓ addKeys(null handler) 完成' });
            } catch (e2) {
                S({ m: '✗ addKeys(null): ' + e2 });
            }
        }

        // ★ Step 5: 再查 userKey（addKeys 后可能变了）
        S({ m: '--- Step 5: addKeys 后状态 ---' });
        try {
            var uk2 = Fock.currentUserKey();
            S({ m: '★ currentUserKey() = [' + uk2 + ']' });
        } catch (e) {
            S({ m: '✗ currentUserKey: ' + e });
        }
        try {
            var versions2 = Fock.addedKeyVersions();
            S({ m: '★ addedKeyVersions() = ' + JSON.stringify(versions2) });
        } catch (e) {
            S({ m: '✗ addedKeyVersions: ' + e });
        }

        // ★ Step 6: unlock 尝试
        S({ m: '--- Step 6: unlock ---' });

        // 短章密文 (blob_903364446.bin): blob[8:8+0x98]
        // 从 xxd 看到的 hex: 18c0f807 f952ec15 ... (152 字节)
        var cipherHex = '18c0f807f952ec1596f6b05b832e0cd110b723d9e948c5c72cc1c20494a6e143574b7776327bdffca81c51174026b63fee405095b6f841aeabf962bcdad30eeef582dbca805e768fea2a591ad14e92857d97384fdb4a661efa360bf6f23b4a934c78fd5010ba466c06812dfaa0da29e03c4f7ee04fcb88b0564f72111f04f8e1a3c7301946513 2eb8e2945f2c7340fb29b76c829d230445c';
        cipherHex = cipherHex.replace(/\s/g, '');
        S({ m: '密文 hex 长度: ' + cipherHex.length / 2 + ' 字节' });

        // hex → byte[]
        var cipherBytes = [];
        for (var b = 0; b < cipherHex.length; b += 2) {
            cipherBytes.push(parseInt(cipherHex.substring(b, b + 2), 16));
        }
        var jCipherBytes = Java.array('byte', cipherBytes);

        // byte[] → base64
        var Base64 = Java.use('android.util.Base64');
        var cipherB64 = Base64.encodeToString(jCipherBytes, 2); // NO_WRAP
        S({ m: '密文 b64 (前64): ' + cipherB64.substring(0, 64) });

        // 尝试 unlock(cipherB64, param2, userKey, handler)
        var userKeys = ['b3b295be58644158', ''];
        var param2s = ['903364446', '1639985422', ''];

        for (var ui = 0; ui < userKeys.length; ui++) {
            for (var si = 0; si < param2s.length; si++) {
                try {
                    S({ m: '尝试 unlock(b64, ' + param2s[si] + ', ' + userKeys[ui] + ', h)...' });
                    var result = Fock.unlock(cipherB64, param2s[si], userKeys[ui], handler);
                    if (result) {
                        S({ m: '★★★ unlock 返回对象!' });
                        // 反射获取所有字段
                        var rFields = result.getClass().getDeclaredFields();
                        for (var fi = 0; fi < rFields.length; fi++) {
                            rFields[fi].setAccessible(true);
                            var val = rFields[fi].get(result);
                            S({ m: '  ★ ' + rFields[fi].getName() + ' = ' + val });
                        }
                    } else {
                        S({ m: 'unlock 返回 null' });
                    }
                } catch (e) {
                    S({ m: 'unlock 异常: ' + e });
                }
            }
        }

        // 也尝试 unlockData(byte[], ...)
        S({ m: '--- Step 7: unlockData ---' });
        try {
            S({ m: '尝试 unlockData(byte[], 903364446, b3b295be58644158, h)...' });
            var result2 = Fock.unlockData(jCipherBytes, '903364446', 'b3b295be58644158', handler);
            if (result2) {
                S({ m: '★★★ unlockData 返回对象!' });
                var r2Fields = result2.getClass().getDeclaredFields();
                for (var fi2 = 0; fi2 < r2Fields.length; fi2++) {
                    r2Fields[fi2].setAccessible(true);
                    S({ m: '  ★ ' + r2Fields[fi2].getName() + ' = ' + r2Fields[fi2].get(result2) });
                }
            } else {
                S({ m: 'unlockData 返回 null' });
            }
        } catch (e) {
            S({ m: 'unlockData 异常: ' + e });
        }

    } catch (e) {
        S({ m: '✗ Fatal: ' + e });
    }

    S({ m: '=== Oracle v2 完成 ===' });
});
