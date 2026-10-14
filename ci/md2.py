#!/usr/bin/env python3
"""md2.py — 纯Python标准MD2 (RFC 1319) — libnib lk() hash链的第三种hash

libnib的hash链使用 MD2/MD4/MD5 三种hash(按CRC32(input)分派),
其中MD2未被早期hook发现,2026-10-13通过hex brute-force确认:
  lk('AA')  hex = MD2(MD2(MD2('AA')))          ✓
  lk('ABC') hex = MD2(MD2(MD2('ABC')))         ✓
  lk('test_device_id_12345') hex = MD2(MD2(MD4(input))) ✓
  lk('abcdefghijklmnopqrst') hex = MD5(MD5(MD2(input))) ✓

★ libnib的MD2 = 完全标准MD2(与pycryptodome逐字节一致,含V6 trace的
  1a9f7b16... block验证)。静态binary里0x8c50处的"PI表"是幌子——
  前42字节与标准一致、后面不同; 真表运行时生成(与AES S-box同一反扫描
  手法)。
"""
import struct

# 标准 PI_SUBST (RFC 1319 Appendix A.3, digits of pi)
PI = bytes([
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
    98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
    30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
    190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
    169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
    128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
    255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
    79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
    69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
    27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
    85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
    44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
    106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
    120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
    242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
    49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
])
assert len(PI) == 256


def md2(msg: bytes) -> bytes:
    """标准MD2 (RFC 1319, RSAREF md2c.c语义)"""
    # Step 1: padding — always ≥1 byte, completes to multiple of 16
    pad_len = 16 - (len(msg) % 16)
    data = msg + bytes([pad_len]) * pad_len

    # Step 2: checksum over the PADDED message (RSAREF: padding block
    # also flows through MD2Transform's checksum update)
    L = 0
    C = [0] * 16
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        for j in range(16):
            C[j] ^= PI[block[j] ^ L]
            L = C[j]

    # Steps 3-4: 48-byte state, CARRIES across blocks (RSAREF: x[0:16]=state)
    blocks = [data[i:i+16] for i in range(0, len(data), 16)] + [bytes(C)]
    state = [0] * 16
    for block in blocks:
        X = list(state) + list(block) + [state[j] ^ block[j] for j in range(16)]
        t = 0
        for j in range(18):
            for k in range(48):
                t = X[k] ^ PI[t]
                X[k] = t
            t = (t + j) % 256
        state = X[:16]

    return bytes(state)


if __name__ == '__main__':
    # RFC 1319 test suite
    tests = [
        (b'', '8350e5a3e24c153df2275c9f80692773'),
        (b'a', '32ec01ec4a6dac72c0ab96fb34c0b5d1'),
        (b'abc', 'da853b0d3f88d99b30283a69e6ded6bb'),
        (b'message digest', 'ab4f496bfb2a530b219ff33031fe06b0'),
        (b'abcdefghijklmnopqrstuvwxyz', '4e8ddff3650292ab5a4108c3aa47940b'),
    ]
    ok = True
    for m, h in tests:
        got = md2(m).hex()
        status = '✓' if got == h else '✗'
        if got != h:
            ok = False
        print(f"  {status} md2({m[:20]!r}) = {got}")
    # cross-check with pycryptodome
    try:
        from Crypto.Hash import MD2
        import os, random
        random.seed(1)
        for _ in range(300):
            m = os.urandom(random.randint(0, 150))
            assert md2(m) == MD2.new(m).digest(), f"mismatch on {m!r}"
        for m in [b'AA', b'ABC', b'test_device_id_12345', b'abcdefghijklmnopqrst',
                  b'0123456789012345678901234567890123456789']:
            assert md2(m) == MD2.new(m).digest()
        print("  ✓ 300+ random & known cross-checks vs pycryptodome")
    except ImportError:
        print("  (pycryptodome absent, skipped cross-check)")
    print("MD2", "PASS" if ok else "FAIL")
