#!/usr/bin/env python3
# defscan.py — 扫描 alldex/*.dex，找出【真正定义】指定类的 dex
# 输出: 文件名|有class_data或空桩|class_data_off|大小
import struct, sys, glob, os


def uleb(d, o):
    v = 0; sh = 0
    while True:
        b = d[o]; o += 1; v |= (b & 0x7f) << sh; sh += 7
        if not (b & 0x80): break
    return v, o


tgt = sys.argv[1] if len(sys.argv) > 1 else 'Lcom/yuewen/fock/Fock;'
for p in sorted(glob.glob('alldex/*.dex')):
    d = open(p, 'rb').read()
    if d[:4] != b'dex\n':
        continue
    try:
        str_sz, str_off = struct.unpack('<II', d[56:64])
        typ_sz, typ_off = struct.unpack('<II', d[64:72])
        cls_sz, cls_off = struct.unpack('<II', d[96:104])
        S = []
        for i in range(str_sz):
            o = struct.unpack('<I', d[str_off + 4 * i:str_off + 4 * i + 4])[0]
            n, o2 = uleb(d, o)
            S.append(d[o2:o2 + n].decode('utf-8', 'replace'))
        T = [struct.unpack('<I', d[typ_off + 4 * i:typ_off + 4 * i + 4])[0] for i in range(typ_sz)]
        for i in range(cls_sz):
            b = d[cls_off + 32 * i:cls_off + 32 * i + 32]
            ci = struct.unpack('<I', b[0:4])[0]
            do = struct.unpack('<I', b[28:32])[0]
            if ci < len(T) and S[T[ci]] == tgt:
                kind = 'class_data' if do else 'stub'
                print('%s|%s|%d|%d' % (os.path.basename(p), kind, do, os.path.getsize(p)))
    except Exception as e:
        print('%s|ERR|%s' % (os.path.basename(p), str(e)[:60]))
