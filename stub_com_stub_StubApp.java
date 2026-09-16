// StubApp.java — 替代 360 加固壳的桩类
// Fock.<clinit> 会调用 StubApp.interface11(60372)；真实实现是 libjiagu_vip.so 的 native，
// 在极简进程里必然失败 ⇒ 用空实现替换，让 <clinit> 顺利跑完。
package com.stub;

public class StubApp {
    public static void interface11(int i) {
        System.out.println("[H] StubApp.interface11(" + i + ") 桩调用（空实现）");
    }
}
