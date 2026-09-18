// hook_fock_oracle_v4.js — 等 App 完全加载 + 尝试 addKeys + unlock
function S(o) { try { send(o); } catch (e) { } }

Java.perform(function () {
    S({ m: '=== Fock Oracle v4 ===' });

    try {
        var Fock = Java.use('com.yuewen.fock.Fock');

        // ★ 先等 App 完全加载——用 sleep 让 App 有时间自己拉 key
        S({ m: '等待 15 秒让 App 完全加载...' });
        Java.use('java.lang.Thread').sleep(15000);
        S({ m: '等待结束' });

        // ★ 检查 keypool 状态
        try {
            var versions = Fock.addedKeyVersions();
            S({ m: '★ addedKeyVersions() = ' + JSON.stringify(versions) });
        } catch (e) { S({ m: '✗ addedKeyVersions: ' + e }); }

        try {
            var uk = Fock.currentUserKey();
            S({ m: '★ currentUserKey() = [' + uk + ']' });
        } catch (e) { S({ m: '✗ currentUserKey: ' + e }); }

        // ★ 确保 setup
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var context = ActivityThread.currentApplication().getApplicationContext();
            Fock.setup(context);
            S({ m: '✓ setup(Context) OK' });
        } catch (e) { S({ m: '⚠ setup: ' + e }); }

        // ★ 创建 ErrorLogHandler
        var handler = null;
        try {
            var ELH = Java.use('com.yuewen.fock.Fock$ErrorLogHandler');
            var HandlerClass = Java.registerClass({
                name: 'com.qidian.FErrH4',
                implements: [ELH],
                methods: {
                    onError: function (json) {
                        try { S({ m: 'ErrHandler: ' + json.toString() }); } catch (e) { }
                    }
                }
            });
            handler = HandlerClass.$new();
            S({ m: '✓ handler 已创建' });
        } catch (e) { S({ m: '⚠ handler: ' + e }); }

        // ★ 尝试 addKeys — 不同参数顺序
        var keyA = 'EocbvAo4OFd8AlitMzMh3d+tpPVxbxpLZdaVzCI9flkyRYnVKVsI+w0J0x7Vhc0bDdtU6VFJ/gntPjKWGhfJWf9z8vS3Clr81XfqRUI+M1QSndGQLnJHB1KOC+xazz4u';
        var keyB = 'vdk5v1Ia2FBOk+Bkna/cMM3A8nRoLJnODnwwhELtVknuxwYjnVW8iNa25uMEBcB+xnLTfeqWMUDTkC16yztYLsc0BUFaWAX0Gt25/dEfyNcji03jgeSxUfcDf2iyyhWd';
        var version = '1639985422';

        S({ m: '--- addKeys 尝试 ---' });
        
        // 尝试 (keyA, version, keyB, handler) — 可能是 (key, version, extraKey, handler)
        var orderings = [
            [keyA, keyB, version, 'A,B,ver'],
            [keyA, version, keyB, 'A,ver,B'],
            [version, keyA, keyB, 'ver,A,B'],
            [keyB, keyA, version, 'B,A,ver'],
        ];

        for (var oi = 0; oi < orderings.length; oi++) {
            var o = orderings[oi];
            try {
                S({ m: '尝试 addKeys(' + o[3] + ', h)...' });
                Fock.addKeys(o[0], o[1], o[2], handler);
                S({ m: '✓ addKeys(' + o[3] + ') 完成' });
                // 检查 keypool 是否装上了
                try {
                    var vs = Fock.addedKeyVersions();
                    S({ m: '  addedKeyVersions = ' + JSON.stringify(vs) });
                    if (vs && vs.length > 0 && vs[0] !== '') {
                        S({ m: '★★★ keypool 装上了! 顺序=' + o[3] });
                    }
                } catch (e) { }
                break; // 成功就跳出
            } catch (e) {
                S({ m: '✗ addKeys(' + o[3] + '): ' + e });
            }
        }

        // ★ 也试 addKeypool(String, String)
        S({ m: '--- addKeypool 尝试 ---' });
        try {
            Fock.addKeypool(keyA, version);
            S({ m: '✓ addKeypool(A, ver) 完成' });
        } catch (e) { S({ m: '✗ addKeypool(A,ver): ' + e }); }
        try {
            Fock.addKeypool(keyB, version);
            S({ m: '✓ addKeypool(B, ver) 完成' });
        } catch (e) { S({ m: '✗ addKeypool(B,ver): ' + e }); }

        // 检查 keypool
        try {
            var vs2 = Fock.addedKeyVersions();
            S({ m: '★ addedKeyVersions() after = ' + JSON.stringify(vs2) });
        } catch (e) { }

        // ★ userKey = currentUserKey
        var userKey = '';
        try { userKey = Fock.currentUserKey(); } catch (e) { }
        S({ m: 'userKey = [' + userKey + ']' });

        // ★ 短章密文
        var cipherHex = '18c0f807f952ec1596f6b05b832e0cd110b723d9e948c5c72cc1c20494a6e143574b7776327bdffca81c51174026b63fee405095b6f841aeabf962bcdad30eeef582dbca805e768fea2a591ad14e92857d97384fdb4a661efa360bf6f23b4a934c78fd5010ba466c06812dfaa0da29e03c4f7ee04fcb88b0564f72111f04f8e1a3c730194651 32eb8e2945f2c7340fb29b76c829d230445c';
        cipherHex = cipherHex.replace(/\s/g, '');
        var cipherBytes = [];
        for (var b = 0; b < cipherHex.length; b += 2) {
            cipherBytes.push(parseInt(cipherHex.substring(b, b + 2), 16));
        }
        var jCipherBytes = Java.array('byte', cipherBytes);
        var Base64 = Java.use('android.util.Base64');
        var cipherB64 = Base64.encodeToString(jCipherBytes, 2);

        // ★ unlock 尝试
        S({ m: '--- unlock ---' });
        try {
            var result = Fock.unlock(cipherB64, '903364446', userKey, handler);
            if (result) {
                S({ m: '★★★ unlock 返回对象!' });
                var rClass = result.getClass();
                var stField = rClass.getDeclaredField('status'); stField.setAccessible(true);
                S({ m: '  status = ' + stField.get(result) });
                var dsField = rClass.getDeclaredField('dataSize'); dsField.setAccessible(true);
                S({ m: '  dataSize = ' + dsField.get(result) });
                var dField = rClass.getDeclaredField('data'); dField.setAccessible(true);
                var dataVal = dField.get(result);
                if (dataVal) {
                    // byte[] → String，用正确的 overload
                    var StringCls = Java.use('java.lang.String');
                    var str = StringCls.$new(Java.array('byte', dataVal), 'UTF-8');
                    S({ m: '  ★★★ data (text) = ' + str.toString().substring(0, Math.min(500, str.toString().length())) });
                } else {
                    S({ m: '  data = null' });
                }
            } else {
                S({ m: 'unlock 返回 null' });
            }
        } catch (e) {
            S({ m: 'unlock 异常: ' + e });
        }

    } catch (e) {
        S({ m: '✗ Fatal: ' + e });
    }

    S({ m: '=== Oracle v4 完成 ===' });
});
