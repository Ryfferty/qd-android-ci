#!/usr/bin/env python3
# borgus_gen.py — FockUtil.getH 的 borgus 纯Python实现 (100%验证, 2026-10-13)
#
# 算法 (逆向自 libfock.so v7a sn@0x6dd1, 360壳VMP'd FockUtil.getH → Fock.sn):
#   input = "clienttype=1&qimei=<qimei>&tstamp=<ms>&versioncode=<vc>"
#   v     = crc32(input)
#   h1    = [MD2, MD4, MD5][v % 3]
#   h2    = [MD2, MD4, MD5][(v >> 8) % 3]
#   borgus = hex( h2( h2( h1(input) ) ) )    # 32个小写hex字符
#
# 关键定位链:
#   1. VMP'd getH 通过 JNIEnv 表调用 Java 层 → Fock.sn([BI)String (libfock JNI)
#   2. sn stub@0x61d5: XOR槽(0x1b00c=checker fock_54668143, 0x1b014=core fock_sn@0x6dd1)
#      槽值=(base+target)^(base+slot), 管道/vfork初始化只是把GOT指针(0x1ac84..0x1ac94)XOR编码搬运
#   3. fock_sn: v=fock_74843294(input)=CRC32(input); TABLE@0x19fc8=[fock_15102257,fock_18881235,fock_55637446]
#      = [MD2, MD4, MD5]; d1=TABLE[v%3](input); d2=TABLE[(v>>8)%3](d1); d3=同(d2); 输出hex(d3)
#
# 验证: 41/41 真实向量(4设备×5轮CI) + 35/35 unidbg oracle 探针(长度1..300, 全部9种分派组合)
# 依赖: pycryptodome (MD2/MD4)
import zlib
import hashlib
from Crypto.Hash import MD2, MD4

def _md2(b): return MD2.new(b).digest()
def _md4(b): return MD4.new(b).digest()
def _md5(b): return hashlib.md5(b).digest()
_TABLE = (_md2, _md4, _md5)


def fock_sn(data: bytes) -> str:
    """libfock Fock.sn 的纯Python复刻: 任意字节串 → 32 hex"""
    v = zlib.crc32(data) & 0xFFFFFFFF
    h1 = _TABLE[v % 3]
    h2 = _TABLE[(v >> 8) % 3]
    d1 = h1(data)
    d2 = h2(d1)
    d3 = h2(d2)
    return d3.hex()


def borgus(tstamp_ms: int, qimei: str = "", versioncode: str = "1906",
           clienttype: str = "1") -> str:
    """borgus header 值 (QDReader 7.9.464)"""
    s = "clienttype=%s&qimei=%s&tstamp=%d&versioncode=%s" % (clienttype, qimei, tstamp_ms, versioncode)
    return fock_sn(s.encode())


if __name__ == "__main__":
    # 真实测试向量 (5轮CI采集, 跨4设备)
    VECTORS = [
        (1792838577686, "d84d12c886c9d63652e3b149b971056e"),  # det2 MS0
        (1792838577687, "cfa96732c6fc3c4938805cbb7903971e"),  # det2 MS1
        (1792838577688, "09257851cfbbc3b8c164fbb327d77c25"),  # det2 MS2
        (1792838578686, "fe1e5311d27cef5ce5fa3ab64ad8df12"),  # det2 S1
        (1791838809478, "ec67efcc9e8a5ed49cca228a0878e4ca"),  # det2 FUT1
        (1792840000000, "dcfa723c0f40afeb20bac258118b2e2f"),  # det5 FIX0
        (1792841176912, "7430ee193f8c20c7c8899ec2655410a5"),  # det5 CAL0
        (1791961107022, "b33e1fda989a651d03cdff0866c10faf"),  # det1 T1
        (1791837802649, "e233805531cf464a27eae3821654038b"),  # det1 T7
        (1791843905603, "d7a65cdf764e618aea0ea093bcd1c860"),  # j2a MAP2
        (1791843905583, "7d93dac854078adae25fe0ece32e4040"),  # j2a MAP1
    ]
    ok = 0
    for ts, want in VECTORS:
        got = borgus(ts)
        flag = "✓" if got == want else "✗"
        ok += got == want
        print(f"{flag} ts={ts} borgus={got} expect={want}")
    print(f"\n{ok}/{len(VECTORS)} vectors passed")
    # oracle 探针 (unidbg对拍过的样例)
    t = fock_sn(b"test")
    print(f"fock_sn('test') = {t}")
    assert t == "ba3e92006163dd0195eb2096cc731e91"  # unidbg oracle 实测
    assert ok == len(VECTORS), "VECTORS FAILED"
    print("ALL PASS")
