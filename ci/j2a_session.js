// j2a_session.js — 纯Java层捕获 Fock.sn 的输入/输出 (无 libart hook, 防VMP反制崩溃)
// 流程: getH#1 (warm-up, 触发 Fock/libfock 类加载) -> 挂 Fock.sn 等 hook -> getH#2 (捕获) -> 全map输出
(function() {
    var ACTIVE = false;
    function L(s) { console.log(s); }
    function jb2hex(b) {
        if (b === null) return "null";
        var s = "";
        for (var i = 0; i < b.length; i++) { var v = b[i]; if (v < 0) v += 256; s += ("0" + v.toString(16)).slice(-2); }
        return s;
    }
    function jb2str(b) {
        if (b === null) return "null";
        try { return String.fromCharCode.apply(null, b); } catch (e) { return "<big>"; }
    }
    function hexd(s) {
        var out = "";
        for (var i = 0; i < s.length; i++) out += ("0" + s.charCodeAt(i).toString(16)).slice(-2);
        return out;
    }

    Java.perform(function() {
        var Fock = null, hooked = false;

        function hookFock() {
            if (hooked) return true;
            try { Fock = Java.use("com.yuewen.fock.Fock"); } catch (e) { L("[E] Fock not loaded: " + e); return false; }
            try {
                var sn = Fock.sn.overload("[B", "int");
                sn.implementation = function(b, len) {
                    var r = sn.call(this, b, len);
                    console.log("[SN] IN len=" + (b === null ? "null" : b.length) + " hex=" + jb2hex(b));
                    console.log("[SN] IN str='" + (b === null ? "null" : jb2str(b)) + "'");
                    console.log("[SN] OUT='" + r + "'");
                    return r;
                };
                L("[H] sn hooked");
            } catch (e) { L("[E] sn hook: " + e); }
            try {
                var sg = Fock.sign.overload("java.lang.String");
                sg.implementation = function(s) {
                    var r = sg.call(this, s);
                    console.log("[SIGN] IN='" + s + "' OUT='" + r + "'");
                    return r;
                };
                L("[H] sign hooked");
            } catch (e) { L("[E] sign hook: " + e); }
            try {
                var lk = Fock.lock.overload("java.lang.String");
                lk.implementation = function(s) {
                    var r = lk.call(this, s);
                    console.log("[LOCK] IN='" + s + "' OUT='" + r + "'");
                    return r;
                };
                L("[H] lock hooked");
            } catch (e) { L("[E] lock hook: " + e); }
            try {
                var wn = Fock.wnid.overload("java.lang.String");
                wn.implementation = function(s) {
                    var r = wn.call(this, s);
                    console.log("[WNID] IN='" + s + "' OUT='" + r + "'");
                    return r;
                };
                L("[H] wnid hooked");
            } catch (e) { L("[E] wnid hook: " + e); }
            try {
                var ci2 = Fock.encodeId.overload("long");
                ci2.implementation = function(j) {
                    var r = ci2.call(this, j);
                    console.log("[IDE] IN=" + j + " OUT='" + r + "'");
                    return r;
                };
                L("[H] encodeId hooked");
            } catch (e) { L("[E] encodeId hook: " + e); }
            hooked = true;
            return true;
        }

        // Java crypto observers
        try {
            var MD = Java.use("java.security.MessageDigest");
            var gi = MD.getInstance.overload("java.lang.String");
            gi.implementation = function(a) {
                var r = gi.call(this, a);
                if (ACTIVE) console.log("[JMD] getInstance " + a);
                return r;
            };
            var dg0 = MD.digest.overload();
            dg0.implementation = function() {
                var r = dg0.call(this);
                if (ACTIVE) console.log("[JMD] digest() -> " + jb2hex(r) + " (this=" + this.getAlgorithm() + ")");
                return r;
            };
            var dg1 = MD.digest.overload("[B");
            dg1.implementation = function(b) {
                var r = dg1.call(this, b);
                if (ACTIVE) console.log("[JMD] digest(in) in=" + jb2hex(b).slice(0, 512) + " -> " + jb2hex(r) + " (this=" + this.getAlgorithm() + ")");
                return r;
            };
            var up1 = MD.update.overload("[B");
            up1.implementation = function(b) {
                if (ACTIVE) console.log("[JMD] update " + jb2hex(b).slice(0, 512));
                return up1.call(this, b);
            };
        } catch (e) { L("[E] MessageDigest hook: " + e); }
        try {
            var CI = Java.use("javax.crypto.Cipher");
            var cgi = CI.getInstance.overload("java.lang.String");
            cgi.implementation = function(a) {
                if (ACTIVE) console.log("[JCI] Cipher.getInstance " + a);
                return cgi.call(this, a);
            };
            var dfn = CI.doFinal.overload("[B");
            dfn.implementation = function(b) {
                var r = dfn.call(this, b);
                if (ACTIVE) console.log("[JCI] doFinal in=" + jb2hex(b).slice(0, 512) + " -> " + jb2hex(r).slice(0, 512));
                return r;
            };
            var dfn0 = CI.doFinal.overload();
            dfn0.implementation = function() {
                var r = dfn0.call(this);
                if (ACTIVE) console.log("[JCI] doFinal() -> " + jb2hex(r).slice(0, 512));
                return r;
            };
        } catch (e) { L("[E] Cipher hook: " + e); }
        try {
            var MC = Java.use("javax.crypto.Mac");
            var mdf = MC.doFinal.overload();
            mdf.implementation = function() {
                var r = mdf.call(this);
                if (ACTIVE) console.log("[JMC] Mac.doFinal -> " + jb2hex(r) + " (this=" + this.getAlgorithm() + ")");
                return r;
            };
        } catch (e) { L("[E] Mac hook: " + e); }

        // String.getBytes during ACTIVE window (the sn input assembly)
        try {
            var ST = Java.use("java.lang.String");
            var gb0 = ST.getBytes.overload();
            gb0.implementation = function() {
                var r = gb0.call(this);
                if (ACTIVE) console.log("[GETBYTES] '" + this + "' -> " + jb2hex(r).slice(0, 512));
                return r;
            };
        } catch (e) { L("[E] getBytes hook: " + e); }

        function callGetH(tag) {
            var FU = Java.use("com.qidian.QDReader.component.util.FockUtil");
            var inst = FU.INSTANCE.value;
            var RB = Java.use("okhttp3.RequestBody");
            var MT = Java.use("okhttp3.MediaType");
            var mt = MT.parse("application/x-www-form-urlencoded");
            var Map = Java.use("java.util.Map");
            var MapEntry = Java.use("java.util.Map$Entry");
            var body = RB.create(mt, "localLabels=&gender=0");
            var urlA = "https://bravev6.if.qidian.com/argus/api/v1/client/getconf";
            var res = inst.getH(urlA, "POST", body);
            var h = {};
            var it = Java.cast(res, Map).entrySet().iterator();
            while (it.hasNext()) {
                var en = Java.cast(it.next(), MapEntry);
                h[String(en.getKey())] = String(en.getValue());
            }
            console.log("[MAP" + tag + "]" + JSON.stringify(h));
            return h;
        }

        setTimeout(function() {
            try {
                L("=== warm-up getH #1 (loads Fock/libfock) ===");
                var h1 = callGetH("1");
                hookFock();
                L("=== capture getH #2 ===");
                ACTIVE = true;
                var h2 = callGetH("2");
                ACTIVE = false;
                L("[DONE2]");
            } catch (e) {
                ACTIVE = false;
                console.log("[ERROR] " + e + " stack=" + (e.stack || ""));
            }
        }, 4000);
    });
})();
