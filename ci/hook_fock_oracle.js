// hook_fock_oracle.js — Frida oracle: 直接在 App 内调用 Fock.unlock 解密 VIP 章节
function S(o) { try { send(o); } catch (e) { } }

Java.perform(function () {
    S({ m: '=== Fock Oracle 启动 ===' });

    try {
        var Fock = Java.use('com.yuewen.fock.Fock');
        S({ m: '✓ Fock 类已获取' });

        // 列出所有方法签名
        var methods = Fock.class.getDeclaredMethods();
        for (var i = 0; i < methods.length; i++) {
            S({ m: '  method: ' + methods[i].toGenericString() });
        }

        // 获取 Fock$FockResult 内部类
        var FockResult = null;
        var FockResultCls = null;
        try {
            FockResult = Java.use('com.yuewen.fock.Fock$FockResult');
            FockResultCls = FockResult.class;
            S({ m: '✓ Fock$FockResult 已获取' });
            // 列出 FockResult 方法
            var frMethods = FockResult.class.getDeclaredMethods();
            for (var j = 0; j < frMethods.length; j++) {
                S({ m: '  FockResult.method: ' + frMethods[j].toGenericString() });
            }
        } catch (e) {
            S({ m: '✗ Fock$FockResult: ' + e });
        }

        // 获取 ErrorLogHandler
        var ErrorLogHandler = null;
        try {
            ErrorLogHandler = Java.use('com.yuewen.fock.Fock$ErrorLogHandler');
            S({ m: '✓ Fock$ErrorLogHandler 已获取' });
        } catch (e) {
            S({ m: '✗ Fock$ErrorLogHandler: ' + e });
        }

        // 创建一个空的 ErrorLogHandler
        var handler = null;
        try {
            // ErrorLogHandler 是接口，需要实现
            var HandlerImpl = Java.registerClass({
                name: 'com.qidian.FridaErrorHandler',
                implements: [ErrorLogHandler],
                methods: {
                    // 需要看接口有哪些方法——先试试空的
                }
            });
            handler = HandlerImpl.$new();
            S({ m: '✓ ErrorLogHandler 实例已创建' });
        } catch (e) {
            S({ m: '⚠ ErrorLogHandler 创建失败: ' + e + '，尝试用 null' });
        }

        // ★ Step 1: setup
        S({ m: '--- Step 1: Fock.setup ---' });
        try {
            // setup(Context) — 用 ActivityThread 获取 context
            var ActivityThread = Java.use('android.app.ActivityThread');
            var context = ActivityThread.currentApplication().getApplicationContext();
            S({ m: '✓ context 已获取' });

            // setup(Context)
            try {
                Fock.setup(context);
                S({ m: '✓ Fock.setup(Context) 完成' });
            } catch (e) {
                S({ m: '✗ Fock.setup(Context): ' + e });
            }

            // setup(String) — QIMEI16
            try {
                Fock.setup('b3b295be58644158');
                S({ m: '✓ Fock.setup(QIMEI16) 完成' });
            } catch (e) {
                S({ m: '✗ Fock.setup(QIMEI16): ' + e });
            }
        } catch (e) {
            S({ m: '✗ setup 失败: ' + e });
        }

        // ★ Step 2: addKeys — 装入两把 key
        S({ m: '--- Step 2: Fock.addKeys ---' });
        var keyA = 'EocbvAo4OFd8AlitMzMh3d+tpPVxbxpLZdaVzCI9flkyRYnVKVsI+w0J0x7Vhc0bDdtU6VFJ/gntPjKWGhfJWf9z8vS3Clr81XfqRUI+M1QSndGQLnJHB1KOC+xazz4u';
        var keyB = 'vdk5v1Ia2FBOk+Bkna/cMM3A8nRoLJnODnwwhELtVknuxwYjnVW8iNa25uMEBcB+xnLTfeqWMUDTkC16yztYLsc0BUFaWAX0Gt25/dEfyNcji03jgeSxUfcDf2iyyhWd';

        try {
            // addKeys(String, String, String, ErrorLogHandler)
            // 参数顺序不确定——可能 (keyA, keyB, version, handler)
            try {
                Fock.addKeys(keyA, keyB, '1639985422', handler);
                S({ m: '✓ Fock.addKeys(keyA, keyB, version, handler) 完成' });
            } catch (e) {
                S({ m: '✗ addKeys(A,B,ver,h): ' + e });
            }
        } catch (e) {
            S({ m: '✗ addKeys 失败: ' + e });
        }

        // ★ Step 3: 尝试各种 userKey 候选 + unlock
        S({ m: '--- Step 3: Fock.unlock ---' });

        // 短章密文：blob[8:8+0x98]
        // 需要从 blob 提取密文字符串
        // blob 格式: [4B版本][4B长度][payload][16B尾巴]
        // 密文 = blob[8:8+len] 作为 base64 或直接 hex？
        // 看 smali: unlock(String ciphertext, ...)  → 密文是 String 类型

        // 先看 currentUserKey 返回什么
        try {
            var userKey = Fock.currentUserKey();
            S({ m: '★ currentUserKey() = ' + userKey });
        } catch (e) {
            S({ m: '✗ currentUserKey(): ' + e });
        }

        // 看 urk() 返回什么
        try {
            var urkVal = Fock.urk();
            S({ m: '★ urk() = ' + urkVal });
        } catch (e) {
            S({ m: '✗ urk(): ' + e });
        }

        // 看 av() 返回什么
        try {
            var avVal = Fock.av();
            S({ m: '★ av() = ' + avVal });
        } catch (e) {
            S({ m: '✗ av(): ' + e });
        }

        // 短章 blob 的密文——需要确认 unlock 接收的是 base64 还是 hex
        // 从 smali 看：unlock(String, String, String, ErrorLogHandler)
        // 第一个参数是密文（String），第二个未知，第三个是 userKey
        var blobHex = '00000000 98000000 18c0f807 f952ec15 96f6b05b 832e0cd1 10b723d9 e948c5c7 2cc1c204 94a6e143 574b7776 327bdffc a81c5117 4026b63f ee405095 b6f841ae abf962bc dad30eee f582dbca 805e768f ea2a591a d14e9285 7d97384f db4a661e fa360bf6 f23b4a93 4c78fd50 10ba466c 06812dfa a0da29e0 3c4f7ee0 4fcb88b0 564f7211 1f04f8e1 a3c73019 465132eb 8e2945f2 c7340fb2 9b76c829 d230445c';
        // 去掉空格
        var blobRaw = '';
        var hexParts = blobHex.split(' ');
        for (var h = 0; h < hexParts.length; h++) {
            blobRaw += hexParts[h];
        }

        // 提取 payload: blob[8:8+0x98] = 从 offset 8 开始，长度 0x98=152
        var payloadHex = blobRaw.substring(16, 16 + 152 * 2); // hex string，每个字节 2 字符
        S({ m: '密文 hex (前32字符): ' + payloadHex.substring(0, 32) });
        S({ m: '密文 hex 长度: ' + payloadHex.length / 2 + ' 字节' });

        // 尝试把密文转成 base64
        var Base64 = Java.use('android.util.Base64');
        // 先 hex → byte[] → base64
        var payloadBytes = [];
        for (var b = 0; b < payloadHex.length; b += 2) {
            payloadBytes.push(parseInt(payloadHex.substring(b, b + 2), 16));
        }
        var jBytes = Java.array('byte', payloadBytes);
        var cipherB64 = Base64.encodeToString(jBytes, 2); // NO_WRAP
        S({ m: '密文 base64: ' + cipherB64.substring(0, 64) + '...' });

        // userKey 候选
        var userKeys = [
            'b3b295be58644158',  // QIMEI16
            '',
            null
        ];

        // 尝试 unlock(ciphertext, ?, userKey, handler)
        // 第二个参数未知——可能是 chapterId 或 keyVersion
        var secondParams = ['903364446', '1639985422', '', null];

        for (var ui = 0; ui < userKeys.length; ui++) {
            for (var si = 0; si < secondParams.length; si++) {
                try {
                    var result;
                    if (handler) {
                        result = Fock.unlock(cipherB64, secondParams[si], userKeys[ui], handler);
                    } else {
                        // 尝试传 null handler
                        result = Fock.unlock(cipherB64, secondParams[si], userKeys[ui], null);
                    }
                    if (result) {
                        S({ m: '★★★ unlock 成功! userKey=' + userKeys[ui] + ' param2=' + secondParams[si] });
                        // 尝试获取 result 的字段
                        try {
                            var status = result.getStatus();
                            S({ m: '  status = ' + status });
                        } catch (e) { }
                        try {
                            var data = result.getData();
                            if (data) {
                                S({ m: '  data = ' + data });
                            } else {
                                S({ m: '  data = null' });
                            }
                        } catch (e) { }
                        try {
                            var content = result.getContent();
                            if (content) {
                                S({ m: '  content = ' + content.substring(0, 200) });
                            }
                        } catch (e) { }
                        // 列出 result 的所有字段
                        try {
                            var fields = result.getClass().getDeclaredFields();
                            for (var fi = 0; fi < fields.length; fi++) {
                                fields[fi].setAccessible(true);
                                var val = fields[fi].get(result);
                                S({ m: '  field ' + fields[fi].getName() + ' = ' + val });
                            }
                        } catch (e) { }
                    } else {
                        S({ m: 'unlock 返回 null: userKey=' + userKeys[ui] + ' param2=' + secondParams[si] });
                    }
                } catch (e) {
                    S({ m: 'unlock 异常: userKey=' + userKeys[ui] + ' param2=' + secondParams[si] + ' : ' + e });
                }
            }
        }

        // ★ 也尝试 unlockData(byte[], String, String, ErrorLogHandler)
        S({ m: '--- Step 4: Fock.unlockData ---' });
        try {
            var result2 = Fock.unlockData(jBytes, '903364446', 'b3b295be58644158', null);
            if (result2) {
                S({ m: '★★★ unlockData 成功!' });
                try {
                    var fields2 = result2.getClass().getDeclaredFields();
                    for (var fi2 = 0; fi2 < fields2.length; fi2++) {
                        fields2[fi2].setAccessible(true);
                        S({ m: '  field ' + fields2[fi2].getName() + ' = ' + fields2[fi2].get(result2) });
                    }
                } catch (e) { }
            } else {
                S({ m: 'unlockData 返回 null' });
            }
        } catch (e) {
            S({ m: 'unlockData 异常: ' + e });
        }

    } catch (e) {
        S({ m: '✗ Fock 类获取失败: ' + e });
    }

    S({ m: '=== Oracle 完成 ===' });
});
