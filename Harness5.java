// Harness5.java — 库健康自检：checkEnvTraits / sign / sn / ets / av / urk
// 目的：定位 uk SIGABRT 的结构性原因（反调试/环境检查未通过？）
package com.fock;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Harness5 {

    static Class<?> fock;

    static void log(String s) { System.out.println("[H] " + s); }

    static String causes(Throwable t) {
        StringBuilder sb = new StringBuilder(); Throwable c = t; int n = 0;
        while (c != null && n++ < 6) {
            sb.append(" << ").append(c.getClass().getName());
            String m = c.getMessage();
            if (m != null) sb.append(": ").append(m.length() > 200 ? m.substring(0, 200) : m);
            c = c.getCause();
        }
        return sb.toString();
    }

    static String readFile(String p) {
        try {
            FileInputStream fis = new FileInputStream(p);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[16384]; int n;
            while ((n = fis.read(b)) > 0) bos.write(b, 0, n);
            fis.close();
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (Throwable t) { return null; }
    }

    static String jget(String json, String key) {
        if (json == null) return null;
        String k = "\"" + key + "\"";
        int i = json.indexOf(k);
        if (i < 0) return null;
        i = json.indexOf(':', i + k.length());
        if (i < 0) return null;
        i++;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length()) return null;
        if (json.charAt(i) == '"') {
            int j = i + 1; StringBuilder sb = new StringBuilder();
            while (j < json.length()) {
                char ch = json.charAt(j);
                if (ch == '\\' && j + 1 < json.length()) { sb.append(json.charAt(j + 1)); j += 2; continue; }
                if (ch == '"') break;
                sb.append(ch); j++;
            }
            return sb.toString();
        }
        int j = i;
        while (j < json.length() && ",}\n\r ".indexOf(json.charAt(j)) < 0) j++;
        return json.substring(i, j).trim();
    }

    static Object proxy(Class<?> iface, final String tag) {
        try {
            return Proxy.newProxyInstance(Harness5.class.getClassLoader(), new Class<?>[] { iface },
                    new InvocationHandler() {
                        public Object invoke(Object p, Method m, Object[] a) {
                            log("   >>> " + tag + "." + m.getName() + "(" + (a == null ? "" : Arrays.toString(a)) + ")");
                            Class<?> r = m.getReturnType();
                            if (r == int.class) return 0;
                            if (r == long.class) return 0L;
                            if (r == boolean.class) return false;
                            return null;
                        }
                    });
        } catch (Throwable t) { log("proxy 失败 " + causes(t)); return null; }
    }

    public static void main(String[] args) {
        String paramsPath = args.length > 0 ? args[0] : "/data/local/tmp/params.json";
        String soPath = args.length > 1 ? args[1] : "/data/local/tmp/libfock.so";

        for (String p : new String[] { "/data/local/tmp/libfockrt.so" }) {
            try { if (new java.io.File(p).exists()) { System.load(p); log("✓ 预加载 " + p); } } catch (Throwable t) { }
        }
        try { System.load(soPath); log("✓ System.load " + soPath); }
        catch (Throwable t) { log("✗ System.load" + causes(t)); return; }
        try { fock = Class.forName("com.yuewen.fock.Fock"); log("✓ 类可用"); }
        catch (Throwable t) { log("✗ 类" + causes(t)); return; }

        String P = readFile(paramsPath);
        String qimei = jget(P, "qimei16"); if (qimei == null) qimei = "b3b295be58644158";
        String ver = jget(P, "Version"); if (ver == null) ver = "1639985422";
        String keyA = jget(P, "Key");
        String ywg = jget(P, "ywguid"); if (ywg == null) ywg = "0";

        Method m;
        // ---------- 1) it ----------
        try {
            m = fock.getDeclaredMethod("it", byte[].class, int.class); m.setAccessible(true);
            byte[] b = qimei.getBytes(StandardCharsets.UTF_8);
            log("① it(qimei) = " + m.invoke(null, b, b.length));
            byte[] b2 = ywg.getBytes(StandardCharsets.UTF_8);
            log("① it(ywguid) = " + m.invoke(null, b2, b2.length));
        } catch (Throwable t) { log("① it" + causes(t)); }

        // ---------- 2) av / urk / ets ----------
        try { m = fock.getDeclaredMethod("av"); m.setAccessible(true); log("② av() = [" + m.invoke(null) + "]"); } catch (Throwable t) { log("② av" + causes(t)); }
        try { m = fock.getDeclaredMethod("urk"); m.setAccessible(true); log("② urk() = [" + m.invoke(null) + "]"); } catch (Throwable t) { log("② urk" + causes(t)); }
        try { m = fock.getDeclaredMethod("ets", boolean.class); m.setAccessible(true); log("② ets(true) = " + m.invoke(null, true)); } catch (Throwable t) { log("② ets" + causes(t)); }
        try { m = fock.getDeclaredMethod("currentUserKey"); m.setAccessible(true); log("② currentUserKey() = [" + m.invoke(null) + "]"); } catch (Throwable t) { log("② currentUserKey" + causes(t)); }

        // ---------- 3) checkEnvTraits（关键：环境检查）----------
        try {
            Class<?> iface = Class.forName("com.yuewen.fock.Fock$EnvTraitsHandler");
            Object h = proxy(iface, "EnvTraits");
            m = fock.getDeclaredMethod("checkEnvTraits", iface); m.setAccessible(true);
            m.invoke(null, h);
            log("③ checkEnvTraits 调用完成（看上面 >>> 输出）");
            Thread.sleep(1500);
        } catch (Throwable t) { log("③ checkEnvTraits" + causes(t)); }

        // ---------- 4) sign / sn（验证库活着）----------
        try {
            m = fock.getDeclaredMethod("sign", String.class); m.setAccessible(true);
            log("④ sign(\"clienttype=1\") = [" + m.invoke(null, "clienttype=1") + "]");
        } catch (Throwable t) { log("④ sign" + causes(t)); }
        try {
            m = fock.getDeclaredMethod("sn", byte[].class, int.class); m.setAccessible(true);
            byte[] d = "clienttype=1".getBytes(StandardCharsets.UTF_8);
            log("④ sn(\"clienttype=1\") = [" + m.invoke(null, d, d.length) + "]");
        } catch (Throwable t) { log("④ sn" + causes(t)); }
        try {
            m = fock.getDeclaredMethod("wnid", byte[].class, int.class); m.setAccessible(true);
            byte[] d = qimei.getBytes(StandardCharsets.UTF_8);
            log("④ wnid(qimei) = [" + m.invoke(null, d, d.length) + "]");
        } catch (Throwable t) { log("④ wnid" + causes(t)); }
        try {
            m = fock.getDeclaredMethod("lk", byte[].class, int.class); m.setAccessible(true);
            byte[] d = keyA == null ? new byte[0] : keyA.getBytes(StandardCharsets.UTF_8);
            Object r = m.invoke(null, d, d.length);
            log("④ lk(key) = " + (r instanceof byte[] ? "[B len=" + ((byte[]) r).length : String.valueOf(r)));
        } catch (Throwable t) { log("④ lk" + causes(t)); }

        // ---------- 5) ak（装密钥池）----------
        try {
            m = fock.getDeclaredMethod("ak", byte[].class, int.class, byte[].class); m.setAccessible(true);
            byte[] kb = java.util.Base64.getDecoder().decode(keyA);
            m.invoke(null, kb, kb.length, ver.getBytes(StandardCharsets.UTF_8));
            log("⑤ ak(96B, " + ver + ") OK（未崩溃）");
            byte[] kb2 = keyA.getBytes(StandardCharsets.UTF_8);
            m.invoke(null, kb2, kb2.length, ver.getBytes(StandardCharsets.UTF_8));
            log("⑤ ak(128B raw, " + ver + ") OK（未崩溃）");
        } catch (Throwable t) { log("⑤ ak" + causes(t)); }

        // ---------- 6) 最后才碰 uk（预期崩）----------
        log("⑥ 即将调 uk（如崩溃，logcat 会给出原因）");
        try {
            m = fock.getDeclaredMethod("uk", byte[].class, int.class, byte[].class, int.class); m.setAccessible(true);
            byte[] d = new byte[] { 1, 2, 3, 4 };
            Object r = m.invoke(null, d, 4, new byte[0], 0);
            log("⑥ uk(哑数据) 返回 = " + r);
        } catch (Throwable t) { log("⑥ uk" + causes(t)); }
        log("=== Harness5 结束（未崩溃）===");
    }
}
