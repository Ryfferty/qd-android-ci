#!/usr/bin/env python3
"""lk_full.py — libnib lk() 纯Python完整实现 ★全长度域100%★ (2026-10-13 V7终版)

算法(43个ARM runner trace输入byte-exact验证,1B..58B):
  1. crc1 = CRC32(input)                        ← nib_53453412(标准CRC32)
  2. H1 = HASHES[crc1 % 3]        (0:MD2, 1:MD4, 2:MD5)
     H2 = HASHES[(crc1 >> 8) % 3] (同上)
     digest = H2(H2(H1(input)));  hexpart = digest.hex() (32字符)
  3. key = hexpart ASCII (32B);  crc2 = CRC32(hexpart)
  4. cipher1 = C16 if (crc2 & 1) == 0 else C8    ← crc2 bit0
     cipher2 = C8  if (crc2 >> 4) & 1 else C16   ← crc2 bit4
  5. inter  = cipher1(pkcs7_pad(input))
     binary = cipher2(pkcs7_pad(inter))
       C8  = DES-CBC,   key = IV = key_ascii[:8]
       C16 = AES-256-CBC, key = key_ascii(32B), IV = key_ascii[:16]
  6. output = binary + hexpart → URL-safe Base64(保留padding)

★三大历史疑难的答案(全部解决):
  - 'AA'/'ABC'无hash调用 → 走MD2(未被hook的第三种hash) MD2×3链
  - 20B输入cipher反序   → 不是按长度分支! 按CRC32分派:
      'test_device_id_12345'  crc2 bit0=0 → C16先
      'abcdefghijklmnopqrst'  crc2 bit0=1 → C8先
  - 40B双DES            → crc2 bit0=1(C8先) + bit4=1(C8后)
  分派器在运行时解密区(静态全零), 逆向靠: hook CRC32+输入矩阵+hex反推。

依赖: pycryptodome(DES/AES), 本目录md2.py/md4.py(纯Python hash)。
"""
import base64
import zlib

from Crypto.Cipher import DES, AES

from md2 import md2 as _md2
from md4 import md4 as _md4
import hashlib


HASHES = {0: _md2, 1: _md4, 2: lambda m: hashlib.md5(m).digest()}


def hash_chain(input_bytes):
    """H1(input) → H2 → H2; H1/H2按CRC32(input)的字节分派"""
    crc1 = zlib.crc32(input_bytes)
    h1 = HASHES[crc1 % 3]
    h2 = HASHES[(crc1 >> 8) % 3]
    d = h1(input_bytes)
    d = h2(d)
    d = h2(d)
    return d.hex()


def pkcs7_pad(data, block_size):
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len]) * pad_len


def _c8(data, key):
    """第1种cipher: DES-CBC, key=IV=key_ascii[:8]"""
    k = key[:8]
    c = DES.new(k, DES.MODE_CBC, iv=k)
    return c.encrypt(pkcs7_pad(data, 8))


def _c16(data, key):
    """第2种cipher: AES-256-CBC, key=key_ascii(32B), IV=key_ascii[:16]"""
    c = AES.new(key[:32], AES.MODE_CBC, iv=key[:16])
    return c.encrypt(pkcs7_pad(data, 16))


def lk(input_str):
    """lk() 纯Python完整实现 ★43/43 trace验证★"""
    input_bytes = input_str.encode('utf-8') if isinstance(input_str, str) else input_str

    # hash链 → hexpart
    hexpart = hash_chain(input_bytes)
    key = hexpart.encode('ascii')  # 32B

    # cipher选择: crc2 = CRC32(hexpart)
    crc2 = zlib.crc32(key)
    cipher1 = _c16 if (crc2 & 1) == 0 else _c8
    cipher2 = _c8 if (crc2 >> 4) & 1 else _c16

    # 双层加密
    inter = cipher1(input_bytes, key)
    binary = cipher2(inter, key)

    # 输出 = binary + hexpart, URL-safe Base64
    output = binary + key
    b64 = base64.b64encode(output).decode('ascii')
    return b64.replace('+', '-').replace('/', '_')


# NativeWrapper.a() = lk() + Base64
def native_wrapper_a(input_str):
    return lk(input_str)


if __name__ == '__main__':
    import json
    import os

    # MD2/MD4自检
    from md2 import md2
    from md4 import md4
    assert md2(b'abc').hex() == 'da853b0d3f88d99b30283a69e6ded6bb'
    assert md4(b'abc').hex() == 'a448017aaf21d8525fc10ae87aa6729d'

    # 历史已知用例(V5/V6)
    legacy = [
        ("A", "F2fOrwzt_8d5jSf3ObJcaTYxNGY5NjRmYTAwMTVmM2Y1ZTdmMzNiZWMwYzA2OWIw"),
        ("AB", "JW63mLr6TylVCOPoWDg6xmY4NDc0MjY5YzM0YWQ0ZmEwOTBlZWNhZTAxNmMxNDEx"),
        ("AA", "85keNcKLO4ecAeOz1s4MiDU5MGRmMzYwZTU2ZDVkYzMzNmRjMGMyNGYyYWQxY2Uz"),
        ("test", "eWdO_2mM21pX30QIa1zFjGJhM2U5MjAwNjE2M2RkMDE5NWViMjA5NmNjNzMxZTkx"),
        ("hello", "V4c5l3adR53Y0OcDrwvDQTQ5ZmJmMWEzNGM1MmE2OTI5NjIxZDc1NDdmMmNhMWFl"),
    ]
    print("═══ lk() 纯Python完整验证 ═══")
    n_pass = n_total = 0
    for inp, expected in legacy:
        got = lk(inp)
        ok = got.rstrip('=') == expected.rstrip('=')
        n_pass += ok
        n_total += 1
        print(f"  {'✓' if ok else '✗'} lk({inp!r})")

    # 全量V7 trace用例(43个, 1B..58B)
    tcf = os.path.join(os.path.dirname(__file__), 'lk_testcases.json')
    if os.path.exists(tcf):
        cases = json.load(open(tcf))
        for c in cases:
            got = lk(c['input'])
            ok = got.rstrip('=') == c['result'].rstrip('=')
            n_pass += ok
            n_total += 1
            if not ok:
                print(f"  ✗ lk({c['input'][:30]!r}) len={c['len']}")
        print(f"  (V7 trace用例: {len(cases)}个)")

    print(f"\n{n_pass}/{n_total} 通过 {'★100%★' if n_pass == n_total else '有失败!'}")
