#!/usr/bin/env python3
# ibex_template.py — 真值模板版ibex生成器 (2026-10-15)
#
# 背景: 旧ibex_gen.py产的ibex 440-448ch, 真值536-556ch — 字段集结构就是错的。
# 本生成器: 从CI登录态MITM真值(K, run 38600816609)解码出的64字段原文做模板,
# 参数化设备字段(ts/model/brand/qimei)后lk()重编码。lk确定性 ⇒ 模板不改时逐字节复现真值(验收)。
#
# 真值字段结构(lk_decode, 64字段):
#   [0]="5"(版本) [1]=ms时间戳 [2-11]空 [12]=4 [13]=0 [14]="00000001" [15-45]稀疏状态flag
#   [46]="redroid11_arm64 (redroid_arm64)"(model) [47][49]=brand [48]="unknown"
#   [50]="build0" [51]="arm64-v8a" [54][55]=qimei36 [56]="android" [57]=包名
#   [58]=fbf2d18b…(app签名哈希, 恒定) [60]=adf3951…(恒定) [61]=版本号 [63]=二进制尾(原样保留)
import sys, os, json, time, base64, zlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lk_full import lk
from Crypto.Cipher import DES, AES

# 模板来源: evidence/mitm-login-38600816609 真ibex解码 (fbt2生成时跑一次提取, 此处内联)
_RAW_TEMPLATE_HEX = None  # 惰性: 从 /tmp/real_ibex.json 或内置hex加载


def lk_decode(b64):
    data = base64.b64decode(b64.replace('-', '+').replace('_', '/'))
    binary, key = data[:-32], data[-32:]
    crc2 = zlib.crc32(key)
    use_c8_2 = (crc2 >> 4) & 1 == 1
    use_c8_1 = (crc2 & 1) == 1
    # 外层cipher2解密 → 去外层pad → 内层cipher1解密 → 去内层pad
    c = DES.new(key[:8], DES.MODE_CBC, iv=key[:8]) if use_c8_2 else AES.new(key[:32], AES.MODE_CBC, iv=key[:16])
    inter_raw = c.decrypt(binary)
    p2 = inter_raw[-1]
    inter = inter_raw[:-p2]
    c2 = DES.new(key[:8], DES.MODE_CBC, iv=key[:8]) if use_c8_1 else AES.new(key[:32], AES.MODE_CBC, iv=key[:16])
    padded = c2.decrypt(inter)
    p1 = padded[-1]
    return padded[:-p1]


def _load_template():
    """真值模板(bytes字段list)。优先内置hex, 退回/tmp/real_ibex.json解码。"""
    global _RAW_TEMPLATE_HEX
    if _RAW_TEMPLATE_HEX:
        return [bytes.fromhex(x) for x in _RAW_TEMPLATE_HEX]
    here = os.path.dirname(os.path.abspath(__file__))
    pj = os.path.join(here, 'ibex_template_data.json')
    if os.path.exists(pj):
        return [bytes.fromhex(x) for x in json.load(open(pj))['fields_hex']]
    src = '/tmp/real_ibex.json'
    if os.path.exists(src):
        ib = json.load(open(src))['ibex']
        return lk_decode(ib).split(b'|')
    raise RuntimeError('真值模板不在位: ci/ibex_template_data.json缺失')


def gen_ibex_real(qimei36, model='redroid11_arm64', brand='redroid', ts_ms=None,
                  package='com.qidian.QDReader', version='7.9.480', template=None):
    """真值模板版ibex: 参数化[1]ts [46]model [47][49]brand [54][55]qimei36 [57]包名 [61]版本"""
    tpl = template or _load_template()
    f = list(tpl)
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    f[1] = str(ts_ms).encode()
    f[46] = f'{model} ({brand}_arm64)'.encode() if 'arm64' in model else f'{model} ({brand})'.encode()
    f[47] = brand.encode()
    f[49] = brand.encode()
    f[54] = qimei36.encode()
    f[55] = qimei36.encode()
    f[57] = package.encode()
    f[61] = version.encode()
    return lk(b'|'.join(f))


if __name__ == '__main__':
    # 验收: 模板原样重编码 == 真值逐字节
    src = '/tmp/real_ibex.json'
    ib = json.load(open(src))['ibex']
    tpl = lk_decode(ib).split(b'|')
    rebuilt = lk(b'|'.join(tpl))
    print(f'验收 复现真值: {"PASS ✓" if rebuilt == ib else "FAIL ✗"} (len {len(rebuilt)} vs {len(ib)})')
    g = gen_ibex_real('864cc236f463a93cf5ad6ae4100018d1aa04', template=tpl)
    print(f'864cc身份版: len={len(g)} 前40: {g[:40]}')
    # 交叉解码验证
    pt = lk_decode(g)
    ff = pt.split(b'|')
    print(f'重解码字段数: {len(ff)} model={ff[46][:30]} q36={ff[54][:20]}…')
EOF_MARKER = True
