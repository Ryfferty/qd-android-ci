// Harness.java — 极简 Android 进程：加载 App 的 libfock.so + 调用真实的 Fock 类
// 运行方式（不需要起点 App、不需要 frida、不碰网页）：
//   app_process -Djava.class.path=/data/local/tmp/harness.dex:/data/local/tmp/classes8.dex \
//       /data/local/tmp com.fock.Harness /data/local/tmp/params.json
package com.fock;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Harness {

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

    // 极简 JSON 取值（只处理字符串/数字，够用）
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
        } else {
            int j = i;
            while (j < json.length() && ",}\n\r ".indexOf(json.charAt(j)) < 0) j++;
            return json.substring(i, j).trim();
        }
    }

    static void dumpResult(String tag, Object r) {
        if (r == null) { log(tag + " => null"); return; }
        try {
            Field[] fs = r.getClass().getDeclaredFields();
            StringBuilder sb = new StringBuilder(tag + " 字段: ");
            for (Field f : fs) {
                f.setAccessible(true);
                Object v = f.get(r);
                if (v == null) { sb.append(f.getName()).append("=null "); continue; }
                if (v instanceof byte[]) {
                    byte[] bb = (byte[]) v;
                    sb.append(f.getName()).append("=[B len=").append(bb.length).append("] ");
                    if (bb.length > 100) {
                        String txt = new String(bb, StandardCharsets.UTF_8);
                        int cn = 0;
                        for (int i = 0; i < txt.length(); i++) if (txt.charAt(i) >= 0x4e00 && txt.charAt(i) <= 0x9fff) cn++;
                        log("★★★★★★ 明文 " + f.getName() + " len=" + bb.length + " 中文字=" + cn);
                        log("★★★★★★ 正文: " + txt.substring(0, Math.min(3000, txt.length())));
                    }
                } else {
                    sb.append(f.getName()).append("=").append(String.valueOf(v)).append(" ");
                }
            }
            log(sb.toString());
        } catch (Throwable t) { log(tag + " 反射失败 " + t); }
    }

    public static void main(String[] args) {
        String paramsPath = (args != null && args.length > 0) ? args[0] : "/data/local/tmp/params.json";
        log("=== Harness 启动 ===");

        // ① 加载 App 的 native 库（真实 Android 加载器 → GOT 重定位/JNI_OnLoad 都正常）
        String[] sos = { "/data/local/tmp/libfock.so" };
        for (String so : sos) {
            try { System.load(so); log("✓ System.load " + so); }
            catch (Throwable t) { log("✗ System.load " + so + " : " + t); }
        }

        // ② 找真实的 Fock 类
        Class<?> fock = null;
        try { fock = Class.forName("com.yuewen.fock.Fock"); log("✓ com.yuewen.fock.Fock 已加载"); }
        catch (Throwable t) { log("✗ Fock 类未找到: " + t); return; }

        // dump 方法
        try {
            for (Method m : fock.getDeclaredMethods()) log("  F| " + m);
        } catch (Throwable t) { }

        // ③ 读参数
        String P = readFile(paramsPath);
        String qimei = jget(P, "qimei16"); if (qimei == null) qimei = "b3b295be58644158";
        String ver = jget(P, "Version"); if (ver == null) ver = "1639985422";
        String keyA = jget(P, "Key");
        String keyB = jget(P, "key_b");
        String blobB64 = jget(P, "blob_b64");
        log("qimei=" + qimei + " ver=" + ver
                + " keyA=" + (keyA == null ? 0 : keyA.length())
                + " keyB=" + (keyB == null ? 0 : keyB.length())
                + " blob=" + (blobB64 == null ? 0 : blobB64.length()));

        try {
            // ④ it(qimei) = setup
            byte[] app = qimei.getBytes(StandardCharsets.UTF_8);
            Method it = fock.getDeclaredMethod("it", byte[].class, int.class);
            it.setAccessible(true);
            Object rc = it.invoke(null, app, app.length);
            log("① it(qimei) ret=" + rc);

            // av() / urk()
            try { Method av = fock.getDeclaredMethod("av"); av.setAccessible(true); log("① av()=" + av.invoke(null)); } catch (Throwable t) { }
            try { Method urk = fock.getDeclaredMethod("urk"); urk.setAccessible(true); log("① urk()=" + urk.invoke(null)); } catch (Throwable t) { }

            // ⑤ ak(key, version)
            Method ak = fock.getDeclaredMethod("ak", byte[].class, int.class, byte[].class);
            ak.setAccessible(true);
            String[] keys = { keyA, keyB };
            for (int i = 0; i < keys.length; i++) {
                if (keys[i] == null || keys[i].isEmpty()) continue;
                try {
                    byte[] kb = Base64.getDecoder().decode(keys[i]);
                    byte[] vb = ver.getBytes(StandardCharsets.UTF_8);
                    ak.invoke(null, kb, kb.length, vb);
                    log("② ak(" + (i == 0 ? "A" : "B") + ", " + kb.length + "B) OK");
                } catch (Throwable t) { log("② ak(" + i + ") 异常 " + t); }
            }

            // ⑥ uk(cipher, additionalKey)
            if (blobB64 != null && !blobB64.isEmpty()) {
                byte[] blob = Base64.getDecoder().decode(blobB64);
                log("③ 密文 " + blob.length + "B");
                Method uk = fock.getDeclaredMethod("uk", byte[].class, int.class, byte[].class, int.class);
                uk.setAccessible(true);

                byte[][] inputs = { blob, java.util.Arrays.copyOfRange(blob, 8, blob.length) };
                String[] labels = { "完整", "去8头" };
                String[] aks = { "", qimei, "borgus", "ywfi01bqjwYv" };
                outer:
                for (int i = 0; i < inputs.length; i++) {
                    for (String a : aks) {
                        for (String kk : new String[]{"A", "B"}) {
                            try {
                                byte[] ab = a.getBytes(StandardCharsets.UTF_8);
                                Object r = uk.invoke(null, inputs[i], inputs[i].length, ab, ab.length);
                                log("③ uk[" + labels[i] + "/ak=" + (a.isEmpty() ? "(空)" : a) + "/key" + kk + "]");
                                dumpResult("   →", r);
                                String s = String.valueOf(r);
                                if (r != null) {
                                    try {
                                        Field f = r.getClass().getDeclaredField("status");
                                        f.setAccessible(true);
                                        if (String.valueOf(f.get(r)).equals("0")) { log("★★★★★★★ status=0 解密成功！"); break outer; }
                                    } catch (Throwable t2) { }
                                }
                            } catch (Throwable t) {
                                log("③ uk[" + labels[i] + "/" + a + "] 异常 " + String.valueOf(t).substring(0, Math.min(150, String.valueOf(t).length())));
                            }
                        }
                    }
                }
            } else {
                log("⚠ 无密文，跳过 uk");
            }

            // ⑦ sn（验证库活着）
            try {
                Method sn = fock.getDeclaredMethod("sn", byte[].class, int.class);
                sn.setAccessible(true);
                byte[] d = "clienttype=1".getBytes(StandardCharsets.UTF_8);
                log("④ sn(\"clienttype=1\")=" + sn.invoke(null, d, d.length));
            } catch (Throwable t) { log("④ sn 异常 " + t); }

        } catch (Throwable t) {
            log("主流程异常: " + t);
            t.printStackTrace(System.out);
        }
        log("=== Harness 结束 ===");
    }
}
