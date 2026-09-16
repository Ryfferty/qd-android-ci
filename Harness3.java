// Harness3.java — 直接驱动 App 的 com.yuewen.fock.Fock（真实 API，来自 jadx 反编译）
// 关键：必须同 dex 内提供 com.stub.StubApp 桩类，否则 Fock.<clinit> 会因加固壳 native 失败而报 NoClassDefFoundError
package com.fock;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Harness3 {

    static void log(String s) { System.out.println("[H] " + s); }

    static String readFile(String p) {
        try {
            FileInputStream fis = new FileInputStream(p);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] b = new byte[16384]; int n;
            while ((n = fis.read(b)) > 0) bos.write(b, 0, n);
            fis.close();
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (Throwable t) { log("read fail " + p + ": " + t); return null; }
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

    static String sig(Method m) {
        StringBuilder sb = new StringBuilder("(");
        for (Class<?> p : m.getParameterTypes()) {
            if (p == byte[].class) sb.append("[B");
            else if (p == int.class) sb.append("I");
            else if (p == long.class) sb.append("J");
            else if (p == boolean.class) sb.append("Z");
            else if (p == String.class) sb.append("Ljava/lang/String;");
            else sb.append("L").append(p.getName().replace('.', '/')).append(";");
        }
        sb.append(")");
        Class<?> r = m.getReturnType();
        if (r == int.class) sb.append("I");
        else if (r == void.class) sb.append("V");
        else if (r == String.class) sb.append("Ljava/lang/String;");
        else if (r == byte[].class) sb.append("[B");
        else sb.append("L").append(r.getName().replace('.', '/')).append(";");
        return sb.toString();
    }

    static void dumpResult(String tag, Object r) {
        if (r == null) { log(tag + " => null"); return; }
        try {
            for (Field f : r.getClass().getDeclaredFields()) {
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
        } catch (Throwable t) { log(tag + " refl fail " + t); }
    }

    public static void main(String[] args) {
        String paramsPath = args.length > 0 ? args[0] : "/data/local/tmp/params.json";
        String soPath = args.length > 1 ? args[1] : "/data/local/tmp/libfock.so";
        log("=== Harness3 (so=" + soPath + ") ===");

        try { System.load(soPath); log("✓ System.load OK（JNI_OnLoad 成功）"); }
        catch (Throwable t) { log("✗ System.load: " + t); return; }

        Class<?> fock;
        try {
            fock = Class.forName("com.yuewen.fock.Fock");
            log("✓✓✓ 找到 com.yuewen.fock.Fock（<clinit> 已通过）");
        } catch (Throwable t) {
            log("✗ Class.forName: " + t.getClass().getName() + ": " + t.getMessage());
            Throwable c = t.getCause();
            while (c != null) { log("    caused by " + c.getClass().getName() + ": " + c.getMessage()); c = c.getCause(); }
            return;
        }

        log("--- 全部方法 ---");
        for (Method m : fock.getDeclaredMethods()) {
            log(String.format("  %-30s %-46s %s", m.getName(), sig(m), Modifier.isNative(m.getModifiers()) ? "NATIVE" : ""));
        }

        String P = readFile(paramsPath);
        String qimei = jget(P, "qimei16"); if (qimei == null) qimei = "b3b295be58644158";
        String ver = jget(P, "Version"); if (ver == null) ver = "1639985422";
        String keyA = jget(P, "Key");
        String keyB = jget(P, "key_b");
        String blobB64 = jget(P, "blob_b64");
        String ywg = jget(P, "ywguid"); if (ywg == null) ywg = "0";
        String ywk = jget(P, "ywkey"); if (ywk == null) ywk = "";
        log("qimei=" + qimei + " ver=" + ver + " keyA=" + (keyA == null ? 0 : keyA.length())
                + " keyB=" + (keyB == null ? 0 : keyB.length()) + " blob=" + (blobB64 == null ? 0 : blobB64.length())
                + " ywguid=" + ywg);

        // 反射工具
        Method setupS = null, addKeypool = null, it = null, ak = null, uk = null, unlock3 = null, unlock4 = null;
        Method addedVer = null, curUser = null, av = null, urk = null, sn = null;
        for (Method m : fock.getDeclaredMethods()) {
            String s = sig(m), n = m.getName();
            if (n.equals("setup") && s.equals("(Ljava/lang/String;)V")) setupS = m;
            else if (n.equals("addKeypool")) addKeypool = m;
            else if (n.equals("it")) it = m;
            else if (n.equals("ak")) ak = m;
            else if (n.equals("uk")) uk = m;
            else if (n.equals("unlock") && m.getParameterCount() == 4) unlock3 = m;
            else if (n.equals("unlock") && m.getParameterCount() == 5) unlock4 = m;
            else if (n.equals("addedKeyVersions")) addedVer = m;
            else if (n.equals("currentUserKey")) curUser = m;
            else if (n.equals("av")) av = m;
            else if (n.equals("urk")) urk = m;
            else if (n.equals("sn")) sn = m;
        }
        log("定位: setupS=" + (setupS != null) + " addKeypool=" + (addKeypool != null)
                + " it=" + (it != null) + " ak=" + (ak != null) + " uk=" + (uk != null)
                + " unlock3=" + (unlock3 != null) + " unlock4=" + (unlock4 != null));

        try {
            // ---- step 1: setup ----
            String[] userKeys = { ywg, ywg + ywk, ywk, qimei, "0" };
            for (String u : userKeys) {
                if (u == null || u.isEmpty()) continue;
                try {
                    if (setupS != null) { setupS.invoke(null, u); log("① setup(\"" + (u.length() > 24 ? u.substring(0, 24) + "…" : u) + "\") OK len=" + u.length()); }
                } catch (Throwable t) { log("① setup 异常 " + String.valueOf(t).substring(0, Math.min(120, String.valueOf(t).length()))); }
                if (it != null) {
                    byte[] b = u.getBytes(StandardCharsets.UTF_8);
                    try { log("① it(字节) ret=" + it.invoke(null, b, b.length)); } catch (Throwable t) { log("① it 异常"); }
                }
                break;
            }
            try { if (curUser != null) log("① currentUserKey()=" + curUser.invoke(null)); } catch (Throwable t) { }
            try { if (av != null) log("① av()=" + av.invoke(null)); } catch (Throwable t) { }
            try { if (urk != null) log("① urk()=" + urk.invoke(null)); } catch (Throwable t) { }

            // ---- step 2: 装密钥池 ----
            if (addKeypool != null && keyA != null && !keyA.isEmpty()) {
                try { addKeypool.invoke(null, keyA, ver); log("② addKeypool(KeyA, " + ver + ") OK"); }
                catch (Throwable t) { log("② addKeypool(KeyA) 异常 " + String.valueOf(t).substring(0, Math.min(120, String.valueOf(t).length()))); }
            }
            if (addKeypool != null && keyB != null && !keyB.isEmpty()) {
                try { addKeypool.invoke(null, keyB, ver); log("② addKeypool(KeyB, " + ver + ") OK"); }
                catch (Throwable t) { log("② addKeypool(KeyB) 异常"); }
            }
            if (ak != null && keyA != null && !keyA.isEmpty()) {
                try {
                    byte[] kb = Base64.getDecoder().decode(keyA);
                    byte[] vb = ver.getBytes(StandardCharsets.UTF_8);
                    ak.invoke(null, kb, kb.length, vb);
                    log("② ak(KeyA " + kb.length + "B, ver) OK");
                } catch (Throwable t) { log("② ak 异常 " + String.valueOf(t).substring(0, Math.min(120, String.valueOf(t).length()))); }
            }
            try { if (addedVer != null) log("② addedKeyVersions()=" + java.util.Arrays.toString((Object[]) addedVer.invoke(null))); } catch (Throwable t) { log("② addedKeyVersions 异常 " + t); }

            // ---- step 3: 解密 ----
            if (blobB64 == null || blobB64.isEmpty()) { log("⚠ 无密文，结束"); return; }
            byte[] blob = Base64.getDecoder().decode(blobB64);
            String blobStr = new String(blob, StandardCharsets.ISO_8859_1);
            log("③ 密文 " + blob.length + "B");

            String[][] sliceSpec = {
                { "完整", null }, { "去8头", "8" }, { "去4头", "4" }, { "去16头", "16" }
            };
            String[] addKeys = { "", qimei, ywg, "794290414", "903350205" };
            String[] labels = { "(空)", "qimei", "ywguid", "chapterId_1040025277", "chapterId_1049120379" };

            for (String[] sp : sliceSpec) {
                byte[] in = blob;
                if (sp[1] != null) {
                    int off = Integer.parseInt(sp[1]);
                    in = java.util.Arrays.copyOfRange(blob, off, blob.length);
                }
                String inStr = new String(in, StandardCharsets.ISO_8859_1);
                for (int a = 0; a < addKeys.length; a++) {
                    // uk(byte[], int, byte[], int)
                    if (uk != null) {
                        try {
                            byte[] ab = addKeys[a].getBytes(StandardCharsets.UTF_8);
                            Object r = uk.invoke(null, in, in.length, ab, ab.length);
                            log("③ uk[" + sp[0] + "/ak=" + labels[a] + "]");
                            dumpResult("   →", r);
                            if (isSuccess(r)) return;
                        } catch (Throwable t) { log("③ uk[" + sp[0] + "/" + labels[a] + "] 异常 " + String.valueOf(t).substring(0, Math.min(110, String.valueOf(t).length()))); }
                    }
                    // unlock(String, String, String, ErrorLogHandler)
                    if (unlock3 != null) {
                        try {
                            Object r = unlock3.invoke(null, inStr, addKeys[a], ywg, null);
                            log("③ unlock(密文,ak=" + labels[a] + ",ywguid)");
                            dumpResult("   →", r);
                            if (isSuccess(r)) return;
                        } catch (Throwable t) { log("③ unlock/" + labels[a] + " 异常 " + String.valueOf(t).substring(0, Math.min(110, String.valueOf(t).length()))); }
                    }
                }
            }
            try { if (sn != null) { byte[] d = "clienttype=1".getBytes(StandardCharsets.UTF_8); log("④ sn=" + sn.invoke(null, d, d.length)); } } catch (Throwable t) { }
        } catch (Throwable t) {
            log("主流程异常: " + t);
            t.printStackTrace(System.out);
        }
        log("=== Harness3 结束 ===");
    }

    static boolean isSuccess(Object r) {
        if (r == null) return false;
        try {
            Field f = r.getClass().getDeclaredField("status");
            f.setAccessible(true);
            Object v = f.get(r);
            log("   status=" + v);
            if ("0".equals(String.valueOf(v))) { log("★★★★★★★ status=0 解密成功！"); return true; }
        } catch (Throwable t) { }
        return false;
    }
}
