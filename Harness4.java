// Harness4.java — 崩溃隔离版：每次只跑一个组合，参数由命令行给出
// 用法: app_process ... com.fock.Harness4 <params.json> <libfock.so> <cfgIndex>
// cfgIndex = -1  → 只做状态自检（it/ak/urk/av），不碰 uk
// cfgIndex >= 0  → 按 (keyFormat, slice, additionalKey) 组合跑单次 uk
package com.fock;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Harness4 {

    static Method it, ak, uk, sn, av, urk, ets;
    static Class<?> fock;

    static void log(String s) { System.out.println("[H] " + s); }

    static String causes(Throwable t) {
        StringBuilder sb = new StringBuilder(); Throwable c = t; int n = 0;
        while (c != null && n++ < 6) {
            sb.append(" << ").append(c.getClass().getName());
            String m = c.getMessage();
            if (m != null) sb.append(": ").append(m.length() > 240 ? m.substring(0, 240) : m);
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

    static void dumpResult(String tag, Object r) {
        if (r == null) { log(tag + " => null"); return; }
        try {
            Field fs = r.getClass().getDeclaredField("status");
            fs.setAccessible(true);
            Object st = fs.get(r);
            log("   status=" + st);
            for (Field f : r.getClass().getDeclaredFields()) {
                f.setAccessible(true);
                Object v = f.get(r);
                if (v instanceof byte[]) {
                    byte[] bb = (byte[]) v;
                    log("   " + f.getName() + "=[B len=" + bb.length + "]");
                    if (bb.length > 50) {
                        String txt = new String(bb, StandardCharsets.UTF_8);
                        int cn = 0;
                        for (int i = 0; i < txt.length(); i++) if (txt.charAt(i) >= 0x4e00 && txt.charAt(i) <= 0x9fff) cn++;
                        log("★★★★★★ 明文 " + f.getName() + " len=" + bb.length + " 中文字=" + cn);
                        log("★★★★★★ 正文: " + txt.substring(0, Math.min(3000, txt.length())));
                    }
                } else if (!f.getName().equals("status")) {
                    log("   " + f.getName() + "=" + v);
                }
            }
        } catch (Throwable t) { log(tag + " refl fail " + causes(t)); }
    }

    static Method find(String name, Class<?>... ps) {
        try {
            Method m = fock.getDeclaredMethod(name, ps);
            m.setAccessible(true);
            return m;
        } catch (Throwable t) { return null; }
    }

    public static void main(String[] args) {
        String paramsPath = args.length > 0 ? args[0] : "/data/local/tmp/params.json";
        String soPath = args.length > 1 ? args[1] : "/data/local/tmp/libfock.so";
        int cfg = args.length > 2 ? Integer.parseInt(args[2]) : -1;

        // 先尝试加载 libfockrt.so（可能补齐 setup/addKeypool 等高端 native）
        String[] pre = { "/data/local/tmp/libfockrt.so" };
        for (String p : pre) {
            try {
                if (new java.io.File(p).exists()) { System.load(p); log("✓ 预加载 " + p); }
            } catch (Throwable t) { log("· 预加载失败 " + p + causes(t)); }
        }
        try { System.load(soPath); log("✓ System.load " + soPath); }
        catch (Throwable t) { log("✗ System.load" + causes(t)); return; }

        try { fock = Class.forName("com.yuewen.fock.Fock"); log("✓ 类可用"); }
        catch (Throwable t) { log("✗ Class" + causes(t)); return; }

        it = find("it", byte[].class, int.class);
        ak = find("ak", byte[].class, int.class, byte[].class);
        uk = find("uk", byte[].class, int.class, byte[].class, int.class);
        sn = find("sn", byte[].class, int.class);
        av = find("av");
        urk = find("urk");
        ets = find("ets", boolean.class);
        log("方法: it=" + (it != null) + " ak=" + (ak != null) + " uk=" + (uk != null)
                + " sn=" + (sn != null) + " av=" + (av != null) + " urk=" + (urk != null) + " ets=" + (ets != null));

        String P = readFile(paramsPath);
        String qimei = jget(P, "qimei16"); if (qimei == null) qimei = "b3b295be58644158";
        String ver = jget(P, "Version"); if (ver == null) ver = "1639985422";
        String keyA = jget(P, "Key");
        String blobB64 = jget(P, "blob_b64");
        String ywg = jget(P, "ywguid"); if (ywg == null) ywg = "0";
        String chId = jget(P, "chapter_id"); if (chId == null) chId = "903350205";

        // ---------- 组合表 ----------
        // keyFormat: 0 = base64 解码后字节(96B)  1 = 原始 128 字符串字节  2 = 不装密钥
        // slice:     0 = 完整  1 = 去8  2 = 去4  3 = 去16
        // addKey:    0 = 空  1 = qimei  2 = ywguid  3 = chapterId  4 = "0"
        int[] KF = { 0, 1, 0, 0, 0, 0, 2, 0, 0 };
        int[] SL = { 0, 0, 0, 1, 2, 3, 0, 0, 0 };
        int[] AK = { 0, 0, 1, 0, 0, 0, 0, 2, 3 };
        int n = KF.length;

        if (cfg < 0 || cfg >= n) {
            // 只做状态自检
            try { log("it(qimei) ret=" + it.invoke(null, qimei.getBytes(StandardCharsets.UTF_8), qimei.length())); } catch (Throwable t) { log("it" + causes(t)); }
            try { log("av()=" + av.invoke(null)); } catch (Throwable t) { }
            try { log("urk()=" + urk.invoke(null)); } catch (Throwable t) { }
            try { log("ets(true)=" + ets.invoke(null, true)); } catch (Throwable t) { }
            try { log("sn=\"clienttype=1\" -> " + sn.invoke(null, "clienttype=1".getBytes(StandardCharsets.UTF_8), 12)); } catch (Throwable t) { log("sn" + causes(t)); }
            log("cfgIndex 范围 0.." + (n - 1));
            return;
        }

        int kf = KF[cfg], sl = SL[cfg], aki = AK[cfg];
        log("=== cfg#" + cfg + " keyFormat=" + kf + " slice=" + sl + " addKey=" + aki + " ===");

        // setup
        try { log("it(qimei) ret=" + it.invoke(null, qimei.getBytes(StandardCharsets.UTF_8), qimei.length())); } catch (Throwable t) { log("it" + causes(t)); }

        // 装密钥
        if (kf != 2 && keyA != null && !keyA.isEmpty()) {
            byte[] kb;
            if (kf == 0) kb = Base64.getDecoder().decode(keyA);
            else kb = keyA.getBytes(StandardCharsets.UTF_8);
            try {
                ak.invoke(null, kb, kb.length, ver.getBytes(StandardCharsets.UTF_8));
                log("ak(" + kb.length + "B, ver) OK");
            } catch (Throwable t) { log("ak" + causes(t)); }
        }

        if (blobB64 == null || blobB64.isEmpty()) { log("无密文"); return; }
        byte[] blob = Base64.getDecoder().decode(blobB64);
        byte[] in = blob;
        if (sl == 1) in = java.util.Arrays.copyOfRange(blob, 8, blob.length);
        else if (sl == 2) in = java.util.Arrays.copyOfRange(blob, 4, blob.length);
        else if (sl == 3) in = java.util.Arrays.copyOfRange(blob, 16, blob.length);
        String[] akVals = { "", qimei, ywg, chId, "0" };
        String addKey = akVals[aki];
        log("密文 " + in.length + "B  addKey=\"" + (addKey.isEmpty() ? "" : addKey) + "\"");

        try {
            byte[] ab = addKey.getBytes(StandardCharsets.UTF_8);
            Object r = uk.invoke(null, in, in.length, ab, ab.length);
            dumpResult("uk 结果:", r);
        } catch (Throwable t) {
            log("uk 异常" + causes(t));
        }
        log("=== cfg#" + cfg + " 结束（未崩溃）===");
    }
}
