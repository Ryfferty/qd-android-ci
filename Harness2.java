// Harness2.java — 签名驱动的组件直调（不猜方法名，按 JNI 签名精确匹配）
// 运行：CLASSPATH 或 -Djava.class.path 指定 harness2.dex + 含 Fock 类的 dex
package com.fock;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Harness2 {

    static void log(String s) { System.out.println("[H] " + s); }

    static String readFile(String p) {
        try {
            FileInputStream fis = new FileInputStream(p);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[16384]; int n;
            while ((n = fis.read(b)) > 0) bos.write(b, 0, n);
            fis.close();
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (Throwable t) { log("读文件失败 " + p + ": " + t); return null; }
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
        char c = json.charAt(i);
        if (c == '"') {
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

    // 把反射方法变成简洁签名串: ([BI)I 等
    static String sig(Method m) {
        StringBuilder sb = new StringBuilder("(");
        for (Class<?> p : m.getParameterTypes()) {
            if (p == byte[].class) sb.append("[B");
            else if (p == int.class) sb.append("I");
            else if (p == long.class) sb.append("J");
            else if (p == String.class) sb.append("Ljava/lang/String;");
            else if (p == Object.class) sb.append("Ljava/lang/Object;");
            else sb.append(p.getName());
        }
        sb.append(")");
        Class<?> r = m.getReturnType();
        if (r == int.class) sb.append("I");
        else if (r == void.class) sb.append("V");
        else if (r == String.class) sb.append("Ljava/lang/String;");
        else if (r == byte[].class) sb.append("[B");
        else sb.append(r.getName());
        return sb.toString();
    }

    static void dumpResult(String tag, Object r) {
        if (r == null) { log(tag + " => null"); return; }
        try {
            Field[] fs = r.getClass().getDeclaredFields();
            for (Field f : fs) {
                f.setAccessible(true);
                Object v = f.get(r);
                if (v instanceof byte[]) {
                    byte[] bb = (byte[]) v;
                    log(tag + " " + f.getName() + "=[B len=" + bb.length + "]");
                    if (bb.length > 50) {
                        String txt = new String(bb, StandardCharsets.UTF_8);
                        int cn = 0;
                        for (int i = 0; i < txt.length(); i++) if (txt.charAt(i) >= 0x4e00 && txt.charAt(i) <= 0x9fff) cn++;
                        log("★★★★★★ 明文 " + f.getName() + " len=" + bb.length + " 中文字=" + cn);
                        log("★★★★★★ 正文: " + txt.substring(0, Math.min(3000, txt.length())));
                    }
                } else {
                    log(tag + " " + f.getName() + "=" + v);
                }
            }
        } catch (Throwable t) { log(tag + " 反射失败 " + t); }
    }

    public static void main(String[] args) {
        String paramsPath = (args != null && args.length > 0) ? args[0] : "/data/local/tmp/params.json";
        String soPath = (args != null && args.length > 1) ? args[1] : "/data/local/tmp/libfock.so";
        log("=== Harness2 启动 (so=" + soPath + ") ===");

        // ① 加载 .so（真实 Android 加载器）
        try { System.load(soPath); log("✓ System.load " + soPath + " OK（JNI_OnLoad 成功）"); }
        catch (Throwable t) { log("✗ System.load 失败: " + t); return; }

        // ② 找类
        Class<?> fock = null;
        String[] cands = { "com.yuewen.fock.Fock", "com.qidian.QDReader.component.util.FockUtil" };
        for (String cn : cands) {
            try { fock = Class.forName(cn); log("✓ 找到类 " + cn); break; }
            catch (Throwable t) { log("✗ 类不存在 " + cn); }
        }
        if (fock == null) { log("=== 无可用类，结束 ==="); return; }

        // ③ 按签名索引所有 native 方法
        Method pSetup = null, pAddKey = null, pUnlock = null, pSign = null, pInt2Byte = null;
        log("--- 声明的方法 ---");
        for (Method m : fock.getDeclaredMethods()) {
            String s = sig(m);
            boolean nat = Modifier.isNative(m.getModifiers());
            log(String.format("  %-28s %-42s %s", m.getName(), s, nat ? "NATIVE" : ""));
            if (!nat) continue;
            if (s.equals("([BI)I")) pSetup = m;
            else if (s.equals("([BI[B)V")) pAddKey = m;
            else if (s.startsWith("([BI[BI)")) pUnlock = m;
            else if (s.equals("([BI)Ljava/lang/String;")) pSign = m;
            else if (s.equals("(I[B)V")) pInt2Byte = m;
        }
        log("定位: setup=" + (pSetup != null) + " addKey=" + (pAddKey != null)
                + " unlock=" + (pUnlock != null) + " sign=" + (pSign != null) + " int2byte=" + (pInt2Byte != null));

        // ④ 读参数
        String P = readFile(paramsPath);
        String qimei = jget(P, "qimei16"); if (qimei == null) qimei = "b3b295be58644158";
        String ver = jget(P, "Version"); if (ver == null) ver = "1639985422";
        String keyA = jget(P, "Key");
        String keyB = jget(P, "key_b");
        String blobB64 = jget(P, "blob_b64");
        log("qimei=" + qimei + " ver=" + ver + " keyA=" + (keyA == null ? 0 : keyA.length())
                + " keyB=" + (keyB == null ? 0 : keyB.length()) + " blob=" + (blobB64 == null ? 0 : blobB64.length()));

        try {
            if (pSetup != null) {
                byte[] app = qimei.getBytes(StandardCharsets.UTF_8);
                Object rc = pSetup.invoke(null, app, app.length);
                log("① setup(qimei) ret=" + rc);
                byte[] app2 = "0".getBytes(StandardCharsets.UTF_8);
                try { log("① setup(\"0\") ret=" + pSetup.invoke(null, app2, app2.length)); } catch (Throwable t) { }
            }

            String[] keys = { keyA, keyB };
            if (pAddKey != null) {
                for (int i = 0; i < keys.length; i++) {
                    if (keys[i] == null || keys[i].isEmpty()) continue;
                    try {
                        byte[] kb = Base64.getDecoder().decode(keys[i]);
                        byte[] vb = ver.getBytes(StandardCharsets.UTF_8);
                        pAddKey.invoke(null, kb, kb.length, vb);
                        log("② addKey(" + (i == 0 ? "A" : "B") + ", " + kb.length + "B) OK");
                    } catch (Throwable t) { log("② addKey(" + i + ") 异常 " + t); }
                }
            }

            if (pUnlock != null && blobB64 != null && !blobB64.isEmpty()) {
                byte[] blob = Base64.getDecoder().decode(blobB64);
                log("③ 密文 " + blob.length + "B");
                byte[][] inputs = { blob, java.util.Arrays.copyOfRange(blob, 8, blob.length),
                        java.util.Arrays.copyOfRange(blob, 4, blob.length),
                        java.util.Arrays.copyOfRange(blob, 16, blob.length) };
                String[] labels = { "完整", "去8头", "去4头", "去16头" };
                String[] aks = { "", qimei, "borgus", "ywfi01bqjwYv" };
                boolean done = false;
                for (int i = 0; i < inputs.length && !done; i++) {
                    for (String a : aks) {
                        if (done) break;
                        try {
                            byte[] ab = a.getBytes(StandardCharsets.UTF_8);
                            Object r = pUnlock.invoke(null, inputs[i], inputs[i].length, ab, ab.length);
                            log("③ unlock[" + labels[i] + "/ak=" + (a.isEmpty() ? "(空)" : a) + "]");
                            dumpResult("   →", r);
                            if (r != null) {
                                try {
                                    Field f = r.getClass().getDeclaredField("status");
                                    f.setAccessible(true);
                                    if (String.valueOf(f.get(r)).equals("0")) { log("★★★★★★★ status=0 解密成功！"); done = true; }
                                } catch (Throwable t2) { }
                            }
                        } catch (Throwable t) {
                            String msg = String.valueOf(t);
                            log("③ unlock[" + labels[i] + "/" + a + "] 异常 " + msg.substring(0, Math.min(140, msg.length())));
                        }
                    }
                }
            }

            if (pSign != null) {
                try {
                    byte[] d = "clienttype=1".getBytes(StandardCharsets.UTF_8);
                    log("④ sign(\"clienttype=1\")=" + pSign.invoke(null, d, d.length));
                } catch (Throwable t) { log("④ sign 异常 " + t); }
            }
        } catch (Throwable t) {
            log("主流程异常: " + t);
            t.printStackTrace(System.out);
        }
        log("=== Harness2 结束 ===");
    }
}
