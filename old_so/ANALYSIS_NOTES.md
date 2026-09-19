# libfock.so 静态逆向分析笔记 (2026-09-19)

## 重大发现：JNI 注册表泄露真实函数地址

`.data.rel.ro` 0x25388 起的 JNI RegisterNatives 表直接给出**真实实现地址**（非 OLLVM thunk）：
- `it([BI)I` → **0x8c3c**
- `ak([BI[B)V` → **0x8d24**
- `uk([BI[BI)Lcom/yuewen/fock/Fock$FockResult;` → **0x8e30** ← 核心解密入口
- `av()Ljava/lang/String;` → 0x8fcc
- `sn([BI)Ljava/lang/String;` → 0x9094
- `lk([BI[B)[B` → 0x92c8
- `uksf([BI[BI[B)Lcom/yuewen/fock/Fock$FockResult;` → 0x92d4
- `resf([BI[B)[B` → 0x9490
- `rmdk([B)V` → 0x9548
- `ide(J)Ljava/lang/String;` → 0x9600

## uk @ 0x8e30 反汇编逻辑

```
uk(env, clazz, cipher[], cipher_len, addkey[], addkey_len):
  0x8e6c bl 0x8c7c(env, cipher[])        → x23 = cipher_ptr (GetByteArrayRegion+malloc)
  0x8e7c bl 0x8c7c(env, addkey[])        → x21 = addkey_ptr
  0x8e90 ldr x10, [BSS+0x27030]
  0x8e94 ldr x11, [BSS+0x27038]
  0x8ea0 eor x8, x10, 0x27030            → funcA = BSS[0x27030]^0x27030
  0x8ea4 eor x25, x11, 0x27038           → funcB = BSS[0x27038]^0x27038
  0x8ea8 blr x8                          → call funcA → 返回 x0
  0x8eac mul x8, x25, x0                 → x8 = funcB * funcA_ret
  0x8ec8 blr x8                          → call (cipher_ptr, cipher_len, addkey_ptr, addkey_len, &out_data, &out_status)
  → 构造 FockResult(status, data)
```

**关键理解**：BSS 表是运行时填充的 XOR 加密指针。函数指针*返回值 的 mul 是反静态分析混淆；
更可能 funcA/funcB 不是"函数指针"而是**全局 key 指针**，通过 XOR-mul 链混淆后再调用真正的算法函数。

## keypool 数据结构（已完全破解）

### 0x9a68 = keypool 管理器（addKeypool 的 native 核心）
- 调 0x9b84 查找/分配槽位 → w9 = 索引
- 条目表在结构体+8，每条 24 字节
- 回填条目：+0=key_ptr, +8=key_len, +0xc=flag(=1 active), +0x10=version_ptr
- 写全局：BSS[0x27038]=key_ptr, BSS[0x27040]=version_ptr
- 结构体：+0=容量(pow2), +4=计数, +8=条目表指针

### 0x9b84 = keypool 查找（哈希表）
- **CRC32 哈希**：`hash = table[key[i] ^ (hash&0xff)] ^ (hash>>8)`，表在 .rodata+0x820
- 散列混合：`hash ^= hash>>22; hash += hash<<4; hash ^= hash>>9; hash += hash<<10; hash ^= hash>>2; hash += hash<<7; hash ^= hash>>12; hash >>= 3`
- 乘法哈希：`hash * 0x9e3779b1`，`mod 容量` 定槽
- 线性探测最多 8 槽（`cmp w26, #7; b.gt fail`）
- 找到后 `bl 0x7760` = 字节比较（memcmp）
- 失败则找空槽（entry+0xc==0）写入

### 0x9db0 = keypool 扩容/重建（cnt 增长时）
- 新容量 = old*2（`lsl w8, w20, #1`），popcount 检查（`cnt/uaddlv` = 容量须为 2 的幂）
- 重新分配 0x18*new_cap 字节，重哈希迁入

## 哈希算法（0x72e0-0x753c 区域）
- **SHA-512 压缩函数**特征：`ror x, #0xe` `ror #18` `ror #41`（=Σ1），
  `ror #0x1c`(28) `ror #34` `ror #39`（=Σ0），多轮 add/bic/and/orr 循环
- 0x72f0 是该压缩函数的一部分（从函数中间反汇编所致）
- .rodata 0x7400 附近也有 SHA-512（ror#14/18/41），0x7c80 有 SHA-256 常量
- .rodata 0x2015c 起字符串：`RIPEMD160 SHA1 SHA224 SHA256 SHA384 SHA512` = OpenSSL EVP 算法表

## ROOT 检测字符串（恶意性低，防逆向）
- `/sbin/su /system/bin/su /system/xbin/su /data/local/xbin/su /data/local/bin/su /system/sd/xbin/su /system/bin/failsafe/su /data/local/su /system/xbin/busybox`
- `localhost AUTH REJECT`、`/system/app/Superuser.apk`
- `RIPEMD160/SHA1/...` 命名

## 密文格式（sessions/ 样本分析）
```
blob_903364446.bin (176B):  [4B 0x00][4B LE 0x98=152][密文152B][4B 0x00][4B 0x04]["null"]
blob_903350205.bin (12528B): [4B 0x00][4B LE 0x30D8=12504][密文][4B 0x00][4B 0x04]["null"]
mch_794290414_cipher.bin: 16592B 纯密文（无 TLV 包装）
```
TLV: tag=0, len, payload; 尾部 tag=0,len=4,payload="null"

## fockkey（网络密钥）
- fockkey.json: `Key` = base64 → 96 字节, `V=2`, `Version=1639985422`
- mch_794290414_fkp.txt: `window.onkeyfocus("<b64:176B>", 1635757421)` JS 回调
- 两个 key 不同 → 96B 是 keypool 条目 key（可能含 AES key+IV 或直接作为哈希输入）

## 下一步
1. 反汇编 0x72e0（it/setup 核心）——确认 userKey 怎么进 keypool / 怎么参与解密
2. 反汇编 0x72a8 之前的 SHA-512 完整实现，确认 key 派生（HKDF? HMAC?）
3. 找 uk 内部逻辑：cipher 是 AES-CBC/CTR 还是自定义流密码（无 AES S-box → 可能 XOR/Salsa/自定义）
4. 用已知明文对（免费章可拿明文 + blob 密文）试算法
