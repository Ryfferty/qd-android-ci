#!/usr/bin/env python3
"""md4.py — 纯Python MD4 (RFC 1320) — libnib lk() hash链用

与libnib的nib_65464522完全一致(标准MD4)。
验证: RFC 1320 test vectors。
"""
import struct


def md4(msg: bytes) -> bytes:
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    ml = len(msg)
    msg = msg + b'\x80'
    while len(msg) % 64 != 56:
        msg += b'\x00'
    msg += struct.pack('<Q', ml * 8)

    for bs in range(0, len(msg), 64):
        X = struct.unpack('<16I', msg[bs:bs + 64])
        a, b, c, d = h
        for i, s in [(0,3),(1,7),(2,11),(3,19),(4,3),(5,7),(6,11),(7,19),
                     (8,3),(9,7),(10,11),(11,19),(12,3),(13,7),(14,11),(15,19)]:
            a = rol((a + F(b,c,d) + X[i]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        for i, s in [(0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),
                     (2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13)]:
            a = rol((a + G(b,c,d) + X[i] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        for i, s in [(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),
                     (1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15)]:
            a = rol((a + H(b,c,d) + X[i] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c
        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF

    return struct.pack('<4I', *h)


if __name__ == '__main__':
    tests = [
        (b'', '31d6cfe0d16ae931b73c59d7e0c089c0'),
        (b'a', 'bde52cb31de33e46245e05fbdbd6fb24'),
        (b'abc', 'a448017aaf21d8525fc10ae87aa6729d'),
        (b'message digest', 'd9130a8164549fe818874806e1c7014b'),
        (b'abcdefghijklmnopqrstuvwxyz', 'd79e1c308aa5bbcdeea8ed63df412da9'),
    ]
    ok = True
    for m, h in tests:
        got = md4(m).hex()
        if got != h:
            ok = False
        print(f"  {'✓' if got == h else '✗'} md4({m[:20]!r}) = {got}")
    print("MD4", "PASS" if ok else "FAIL")
