#!/usr/bin/env python3
"""
rc4_probe.py — 老版 libfock.so 静态探针
1. dump .rodata 派生常量（funcA 用的 0x6d0-0x860 区间）
2. dump RC4 置换表基址与 .data 表内容
3. 解析 keypool 结构
4. 已知明文验证: blob_903364446 (176B, 应含"欢迎收藏")
所有输出同时写 /tmp/rc4_probe.txt
"""
import struct, sys, os

OUT = open('/tmp/rc4_probe.txt', 'w', encoding='utf-8')
def log(*a):
    msg = ' '.join(str(x) for x in a)
    print(msg)
    OUT.write(msg + '\n')

SO = 'old_so/libfock_old_arm64.so' if os.path.exists('old_so/libfock_old_arm64.so') else 'libfock_old.so'
log(f"=== 探针目标: {SO} ({os.path.getsize(SO)}B) ===")

import lief
binary = lief.parse(SO)
sections = {s.name: s for s in binary.sections}

def read_va(addr, n):
    for sec in binary.sections:
        va = sec.virtual_address
        data = bytes(sec.content)
        if va <= addr < va + len(data):
            off = addr - va
            if off + n <= len(data):
                return data[off:off+n]
    # 尝试文件偏移（无段映射时）
    try:
        with open(SO, 'rb') as f:
            f.seek(addr)
            return f.read(n)
    except Exception:
        return None

text_va = sections['.text'].virtual_address
text = bytes(sections['.text'].content)
rodata_va = sections['.rodata'].virtual_address
rodata = bytes(sections['.rodata'].content)

# 1. 派生常量 dump（funcA @ 0x713c 引用的 rodata 区间）
log("\n=== 1. .rodata 派生常量区 (0x19d70-0x19e90) ===")
# 从反汇编: ldr q0, [x8, #0x6d0]  with x8=adrp 0x19000 → 0x196d0+0x6d0=0x19da0
# 老版 rodata va=0x196d0, funcA 引用 #0x6d0~#0x860
for off in range(0x6d0, 0x880, 0x10):
    va = rodata_va + off
    d = read_va(va, 16)
    if d:
        hx = d.hex()
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in d)
        log(f"  0x{va:04x} (+{off:#04x}): {hx}  |{asc}|")
    else:
        log(f"  0x{va:04x}: 读失败")

# 2. RC4 置换表（0xa968 引用 .data 0x24000+0x1b8/0x5b8/0x9b8/0xdb8 + BSS 同偏移）
log("\n=== 2. RC4 置换表（file 偏移视角, 0x24000 区域）===")
for base in (0x24000,):
    for off in (0x1b8, 0x5b8, 0x9b8, 0xdb8):
        va = base + off
        d = read_va(va, 16)
        if d:
            log(f"  [0x{va:x}] = {d.hex()}")
        else:
            # 尝试文件偏移读
            fo = va - 0x1000  # 老版 .got 前段?
            try:
                with open(SO, 'rb') as f:
                    f.seek(va - 0x1000)
                    d = f.read(16)
                    log(f"  [0x{va:x}] (file_off 0x{fo:x}) = {d.hex()}")
            except Exception as e:
                log(f"  [0x{va:x}] 读失败 {e}")

# 3. .data.rel.ro JNI 表确认
log("\n=== 3. JNI 注册表（.data.rel.ro @ 0x21590）===")
drr = sections.get('.data.rel.ro')
if drr:
    drr_va = drr.virtual_address
    drr_data = bytes(drr.content)
    for i in range(0, 128, 24):
        off = 0x21590 - drr_va + i
        if off + 24 <= len(drr_data):
            np_, sp_, fp_ = struct.unpack_from('<QQQ', drr_data, off)
            def ro_str(p):
                if rodata_va <= p < rodata_va + len(rodata):
                    off2 = p - rodata_va
                    end = rodata.find(b'\0', off2)
                    return rodata[off2:end].decode('ascii', 'replace') if end > off2 else None
                return None
            nm = ro_str(np_); sg = ro_str(sp_)
            if nm and sg:
                log(f"  {nm:12s} {sg:42s} → 0x{fp_:x}")
            else:
                log(f"  0x{np_:x} 0x{sp_:x} 0x{fp_:x}")
            if fp_ == 0 and np_ == 0 and sp_ == 0: break

# 4. blob 样本大小
log("\n=== 4. blob 样本 ===")
for f in ('old_so/blob_903364446.bin', 'old_so/blob_903350205.bin'):
    if os.path.exists(f):
        with open(f, 'rb') as fh:
            d = fh.read()
        log(f"  {f}: {len(d)}B  head={d[:32].hex()}  tail={d[-16:].hex()}")

# 5. 已知明文章节标题（来自 chlist）: 903364446 = "欢迎收藏" (W=30), 903350205 = "1.从香火开始"
log("\n=== 5. 验证锚点 ===")
log("  blob_903364446 → 章节 '欢迎收藏' (30 字符 W=30)")
log("  blob_903350205 → 章节 '1.从香火开始' (3620 字, 12504B 密文)")
log("  若解密成功, 明文应含 JSON 格式的 content")

OUT.close()
