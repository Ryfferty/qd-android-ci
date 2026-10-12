# borgus (FockUtil.getH) 确定性验证 — 2026-10-13

## ★★★ 终局：borgus 已 100% 纯Python破解 (2026-10-13 深夜)

```python
# ci/borgus_gen.py — 全量验证 41/41 真实向量 + 35/35 unidbg oracle 探针(长度1..300, 9种分派组合)
input = "clienttype=1&qimei=&tstamp=<ms>&versioncode=1906"   # qimei 真机非空, vc=版本号
v     = crc32(input)
h1    = [MD2, MD4, MD5][v % 3]
h2    = [MD2, MD4, MD5][(v >> 8) % 3]
borgus = hex(h2(h2(h1(input))))       # 32 lowercase hex
```

### 破解链 (5步):
1. **JNIEnv 函数表 trace** (ci/jni_session.js, run 38315392546): hook libart 的 JNI 表
   (FindClass/GetMethodID/GetStringUTFChars/NewStringUTF/Call*MethodA/RegisterNatives),
   只在 getH 调用窗口记录 → VMP'd Java 的全部 Java 交互暴露:
   QDInfo 走 Java Cipher(DESede/CBC), QDSign 走 t6/d.cihai, **borgus 走 Fock.sn([BI)String**!
2. **Fock.sn Java 层 hook** (ci/j2a_session.js, run 38316369988, 无libart hook零风险):
   `[SN] IN='clienttype=1&qimei=&tstamp=1791843905603&versioncode=1906' OUT='d7a65cdf...'`
   == MAP2.borgus → **borgus = Fock.sn(该串)** 铁证 (gorgon/cecelia 为空串)。
3. **libfock v7a 静态解码**: sn stub@0x61d5 → XOR槽 0x1b00c(checker fock_54668143=签名校验)+0x1b014(core fock_sn@0x6dd1);
   槽机制=管道/vfork 把 GOT 指针(0x1ac84..0x1ac94) XOR 编码搬运 → unidbg 手动填槽即激活。
4. **unidbg oracle** (unidbg-097/FockSn.java): 填槽+checker强制返回1 → sn 全向量 MATCH=YES。
5. **算法定型**: v=CRC32(input); TABLE@0x19fc8=[MD2,MD4,MD5]; d1=TABLE[v%3](input);
   d2=TABLE[(v>>8)%3](d1); d3=同(d2); hex(d3)。与 libnib lk() 同款 CRC32分派+{MD2,MD4,MD5}三件套!

### 附注:
- 分派组合 9 种全覆盖验证(探针); 输入长度 1..300 全对齐。
- VMP 的 libart-hook 反制: jni/j2b 两轮在 getH 尾部触发 "stack corruption" SIGABRT —
  libart 表 hook 可用但会被 360 壳检测; **Java 层 hook(Fock.sn) 零风险**, 优先用。

---

## 早期确定性验证 (2026-10-13 白天)

## 结论（先看这里）

1. **borgus 是确定性的** ✅ — 冻结时钟后同一输入连调 3 次输出完全一致；解冻→再冻结后仍复现（T8==T1, CAL0==CAL1）。
2. **borgus = F(设备状态, tstamp)** — 对 url / method / body **零依赖**（冻结时钟下改 url/method/body，borgus 不变）。
   - tstamp 1ms 粒度、全雪崩（ts+1ms → 16/16 字节变化）。
   - QDInfo 的内嵌 ts == tstamp（同源）；无法排除 F 的真实输入是 qdinfo（qdinfo=g(设备,ts)，模型等价）。
3. **tstamp 可完全控制** ✅ — hook `SystemClock.elapsedRealtime/uptimeMillis` 即可驱动 VMP 的平滑时钟：
   `tstamp = C + fakeElapsed`（C=进程常数，实测 delta=0）→ **可为任意未来 ts 预生成 borgus 银行**。
4. ~~纯 Python F 未实现~~ → ✅ 已实现 (见顶部, ci/borgus_gen.py)
   67k+ 标准构造（md5/sha1/sha256/hmac×组合×分隔符）全部不匹配；fockrt 三层链(MD2→MD5→H)也不匹配。
5. **服务端（getconf）不校验 borgus** — 本机直测：无borgus/垃圾borgus/过期borgus 全部 200 Result=0。
   前人记录的 "-3 签名错误" 根因是 **QDSign 的 md5 字段必须 = md5(canon(query参数))** 且请求需带 query，
   与 borgus 无关。borgus 真正起作用的场合在风控端（ostar 注册 / WolfEye 限免判定）。

## 证据链（4 次 ARM CI）

| run | 内容 | 关键结果 |
|---|---|---|
| det 38305869448 | 冻结时钟 (clock_gettime/gettimeofday/time + System.currentTimeMillis/SystemClock) | T1×3 同 borgus=b33e1fda...faf; T2改body/T3改method/T4改url/T6改冻结时间(+1h)/T9换host → 全同; T7解冻→变; T8再冻结→回到 T1 值 |
| det2 38307499479 | elapsed 扫描 + 未来 ts 银行 | ts=C+fakeElapsed 精确(delta=0); MS0-4 每 +1ms borgus 全变; CAL0==CAL1; 12组干净(ts→borgus)测试向量 |
| det3 38309016893 | fresh 时序服务端重放 | 复现控制 delta=0; 重放 4 变体全 -3 → 定位为 QDSign 构造错误而非 borgus |
| 本机验证 | argus 构造 ± borgus | POST+query+body, QDSign.md5=md5("gender=0&localLabels=") → 200/Result=0 ×4（无/stale/garbage/一致borgus） |

## tstamp 机制（破译）

VMP 不直接读时钟，而是维护平滑时钟：`(wall缓存, elapsed缓存)` 对，
`tstamp = wall缓存 + (elapsed_now − elapsed缓存)`。
- elapsed 走 Java `SystemClock.elapsedRealtime/uptimeMillis`（hook 生效）
- wall 更新走原生 raw syscall/vDSO（libc export hook 拦不到）
- 冻结 SystemClock → tstamp 冻结在 `wall缓存 + (fakeElapsed − elapsed缓存)`
- det-v1 实测: wall缓存=1791837802649(hook安装时刻), elapsed缓存=152416ms, fakeElapsed=123456789 → tstamp=1791961107022 精确吻合

## 纯 Python 复刻路线（后续）

- F 的宿主: VMP'd FockUtil.getH 调 Java 声明的 native Fock.sn (libfock.so) — Java 层可 hook, native 可 unidbg。
- 已备好测试向量集（同设备连续 ts → borgus，1ms/1s 步长）供未来实现比对：`borgus_pairs.json`（scratch）。
- 可行路径: ①继续黑盒拟合(需找到F的秘密输入) ②unidbg 跑 VMP ③oracle银行工程方案。
- QDInfo/QDSign 纯 Python 已可字节级复刻（3DES 密钥已知，getH 产出的头也能 1:1 重建）。

## 依赖变量清单（完整）

| 变量 | 依赖? | 证据 |
|---|---|---|
| tstamp | ✅ (1ms粒度) | MS 扫描全雪崩; 冻结ts→冻结borgus |
| 设备状态(IMEI/安装态) | ✅ (推断) | 不同run(不同设备)不同; QDInfo含设备字段 |
| url | ❌ | T4 改1字符→borgus不变 |
| method | ❌ | T3 POST→GET→不变 |
| body | ❌ | T2/T5→不变 |
| 随机数/计数器 | ❌ | CAL0==CAL1; T8==T1(中间隔真实时间调用) |
| 进程种子 | 待定 | det4 验证中(force-stop后app不复活的干扰已排除?) |

## 文件

- `.github/workflows/qd-borgus-det.yml` — v1 冻结实验
- `.github/workflows/qd-borgus-det2.yml` — v2 扫描+银行
- `.github/workflows/qd-borgus-det3.yml` — v3 服务端重放
- `.github/workflows/qd-borgus-det4.yml` — v4 跨进程
- `ci/borgus_replay.py` — 本机验证脚本(构造正确的重放器)
