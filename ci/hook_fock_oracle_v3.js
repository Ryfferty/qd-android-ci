// hook_fock_oracle_v3.js — 等 App 完全加载后直接 unlock（不手动 addKeys）
function S(o) { try { send(o); } catch (e) { } }

Java.perform(function () {
    S({ m: '=== Fock Oracle v3 ===' });

    try {
        var Fock = Java.use('com.yuewen.fock.Fock');

        // ★ 先检查 App 是否已经自己装了 key
        try {
            var versions = Fock.addedKeyVersions();
            S({ m: '★ addedKeyVersions() = ' + JSON.stringify(versions) });
        } catch (e) { S({ m: '✗ addedKeyVersions: ' + e }); }

        try {
            var uk = Fock.currentUserKey();
            S({ m: '★ currentUserKey() = [' + uk + ']' });
        } catch (e) { S({ m: '✗ currentUserKey: ' + e }); }

        // ★ 确保 setup 已执行
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
                name: 'com.qidian.FErrH3',
                implements: [ELH],
                methods: {
                    onError: function (json) {
                        try { S({ m: 'ErrorHandler.onError: ' + json.toString() }); } catch (e) { }
                    }
                }
            });
            handler = HandlerClass.$new();
            S({ m: '✓ handler 已创建' });
        } catch (e) { S({ m: '⚠ handler: ' + e }); }

        // ★ userKey = currentUserKey 返回的 UUID
        var userKey = '182d7396-e0d9-4a36-b6a7-769b8b462566';

        // ★ 短章密文 (blob_903364446.bin): blob[8:8+0x98] = 152 字节
        var cipherHex = '18c0f807f952ec1596f6b05b832e0cd110b723d9e948c5c72cc1c20494a6e143574b7776327bdffca81c51174026b63fee405095b6f841aeabf962bcdad30eeef582dbca805e768fea2a591ad14e92857d97384fdb4a661efa360bf6f23b4a934c78fd5010ba466c06812dfaa0da29e03c4f7ee04fcb88b0564f72111f04f8e1a3c730194651 32eb8e2945f2c7340fb29b76c829d230445c';
        cipherHex = cipherHex.replace(/\s/g, '');

        // hex → byte[]
        var cipherBytes = [];
        for (var b = 0; b < cipherHex.length; b += 2) {
            cipherBytes.push(parseInt(cipherHex.substring(b, b + 2), 16));
        }
        var jCipherBytes = Java.array('byte', cipherBytes);

        // byte[] → base64
        var Base64 = Java.use('android.util.Base64');
        var cipherB64 = Base64.encodeToString(jCipherBytes, 2);
        S({ m: '密文 b64 长度: ' + cipherB64.length });

        // ★ 尝试 unlock — 第二个参数尝试各种值
        S({ m: '--- unlock 尝试 ---' });
        var param2s = ['903364446', '1049120379', '1639985422', '', null];
        
        for (var si = 0; si < param2s.length; si++) {
            try {
                S({ m: '尝试 unlock(b64, ' + param2s[si] + ', ' + userKey + ', h)...' });
                var result = Fock.unlock(cipherB64, param2s[si], userKey, handler);
                if (result) {
                    S({ m: '★★★ unlock 返回对象! param2=' + param2s[si] });
                    // 获取 status
                    var rClass = result.getClass();
                    var stField = rClass.getDeclaredField('status');
                    stField.setAccessible(true);
                    S({ m: '  status = ' + stField.get(result) });
                    
                    var dsField = rClass.getDeclaredField('dataSize');
                    dsField.setAccessible(true);
                    S({ m: '  dataSize = ' + dsField.get(result) });
                    
                    var dField = rClass.getDeclaredField('data');
                    dField.setAccessible(true);
                    var dataVal = dField.get(result);
                    if (dataVal) {
                        // byte[] → String
                        var StringCls = Java.use('java.lang.String');
                        var str = StringCls.$new(dataVal, 'UTF-8');
                        S({ m: '  ★★★ data (text) = ' + str.substring(0, Math.min(500, str.length())) });
                    } else {
                        S({ m: '  data = null' });
                    }
                    break; // 成功就跳出
                } else {
                    S({ m: 'unlock 返回 null: param2=' + param2s[si] });
                }
            } catch (e) {
                S({ m: 'unlock 异常: param2=' + param2s[si] + ' : ' + e });
            }
        }

        // ★ 也尝试 unlockData(byte[], ...)
        S({ m: '--- unlockData 尝试 ---' });
        var param2s2 = ['903364446', '1049120379', ''];
        for (var si2 = 0; si2 < param2s2.length; si2++) {
            try {
                S({ m: '尝试 unlockData(byte[], ' + param2s2[si2] + ', ' + userKey + ', h)...' });
                var result2 = Fock.unlockData(jCipherBytes, param2s2[si2], userKey, handler);
                if (result2) {
                    S({ m: '★★★ unlockData 返回对象! param2=' + param2s2[si2] });
                    var r2Class = result2.getClass();
                    var st2 = r2Class.getDeclaredField('status');
                    st2.setAccessible(true);
                    S({ m: '  status = ' + st2.get(result2) });
                    
                    var ds2 = r2Class.getDeclaredField('dataSize');
                    ds2.setAccessible(true);
                    S({ m: '  dataSize = ' + ds2.get(result2) });
                    
                    var d2 = r2Class.getDeclaredField('data');
                    d2.setAccessible(true);
                    var data2 = d2.get(result2);
                    if (data2) {
                        var StringCls2 = Java.use('java.lang.String');
                        var str2 = StringCls2.$new(data2, 'UTF-8');
                        S({ m: '  ★★★ data (text) = ' + str2.substring(0, Math.min(500, str2.length())) });
                    } else {
                        S({ m: '  data = null' });
                    }
                    break;
                } else {
                    S({ m: 'unlockData 返回 null: param2=' + param2s2[si2] });
                }
            } catch (e) {
                S({ m: 'unlockData 异常: param2=' + param2s2[si2] + ' : ' + e });
            }
        }

    } catch (e) {
        S({ m: '✗ Fatal: ' + e });
    }

    S({ m: '=== Oracle v3 完成 ===' });
});
