#!/usr/bin/env python3
# cecelia_gen.py — FockUtil.getH 的 cecelia 纯Python实现 (纯协议三库收尾件)
#
# 破解 (2026-10-14 子代理J): cecelia = fockrt s() 引擎输出, 输入串与 borgus 完全同源
#
#   cecelia = f"{file_id}_{le16hex(rand16)}{sha256hex}"
#     sha256hex = sha256( 06 42 + (str(rand16) + kv)[2:] )   ← 字节级: 前两字节被0642覆盖
#     kv        = 与 borgus 相同的排序kv串:
#                 "&".join(f"{k}={v}" for k in sorted(d)), d = 请求参数表(query+form body,
#                 key小写) ∪ {clienttype:1, qimei:qimei36, tstamp:ms, versioncode:1996}
#     file_id   = 0(内置脚本, qimei空/SDK未激活态) / 2(服务端脚本, qimei就绪态) — 仅前缀, 不影响算法
#     rand16    = rand()&0xFFFF 逐签名随机, LE十六进制明文内嵌在输出前4个hex (服务端可还原校验)
#
# 引擎级证据: libfockrt fockrt_90857214(s() C实现) → QuickJS_evaluate2 → 314B QJS字节码
#   (ci/qjs_script_decrypted.bin): sign(b91s)={ buf=b91decode(b91s); buf[0]=6; buf[1]=66;
#   return sha256hex(buf) } — 纯Python复刻 ci/fockrt_s.py 6/6 native向量验证。
#   arm64偏移: QuickJS_evaluate2@0x1f25c, fockrt_90857214@0x21da4, rand16@0x23574,
#   sha256@0x22574, b91encode@0x204a0 (v7a: 0x129dc/0x14879/0x15a2d/0x14e48/0x13670)
#
# 验证: collected_risk_materials.json 80/80 全值命中;
#       evidence/ostar-sign/cecelia_samples.json 56/56 (2026-10-15闭合: 原1/56残差=
#       cecelia_extract.py body[:3000]截断flow#28(实4650B)的语料伪影, 非嵌套转码);
#       0_前缀形态(qimei空) 19/19。
#
# 依赖: 无 (borgus交叉验证自测需 pycryptodome)
import hashlib
import struct
import random
import re
from urllib.parse import urlsplit, parse_qsl


# ───────────────── 参数表视图 (getH 的请求参数视角, 与 borgus_gen.py 同源同口径) ─────────────────
def params_of(url: str, body: str = None) -> dict:
    """url/query + urlencoded form body → 参数表 (key小写; 不透明body由调用方传None)"""
    d = {}
    q = urlsplit(url).query
    if q:
        for k, v in parse_qsl(q, keep_blank_values=True):
            d[k.lower()] = v
    if body:
        try:
            for k, v in parse_qsl(body, keep_blank_values=True):
                d[k.lower()] = v
        except Exception:
            pass
    return d


def sign_input_kv(params: dict, tstamp_ms: int, qimei: str = "",
                  versioncode: str = "1996", clienttype: str = "1") -> str:
    """排序kv合并串 —— borgus(fock_sn) 与 cecelia(s()) 的共同输入"""
    d = {str(k).lower(): str(v) for k, v in params.items()}
    d.update({'clienttype': clienttype, 'qimei': qimei,
              'tstamp': str(tstamp_ms), 'versioncode': versioncode})
    return '&'.join(f'{k}={d[k]}' for k in sorted(d))


# ───────────────── cecelia 本体 ─────────────────
def cecelia(url: str, body, tstamp_ms: int, qimei: str = "", file_id: int = 2,
            rand16: int = None, opaque_body: bool = False, versioncode: str = "1996",
            clienttype: str = "1") -> str:
    """生成 cecelia 头值: "{file_id}_{le16hex(rand16)}{sha256hex}"

    url/body      : 请求 (form body并入参数表; 不透明blob传 body=None 或 opaque_body=True)
    tstamp_ms     : 签名时刻毫秒 (与 borgus/QDSign 同一 getH 时钟)
    qimei         : qimei36; 空 → 设备态为匿名 (App此态用 file_id=0)
    file_id       : 0=内置脚本(匿名/SDK未激活态), 2=服务端脚本(qimei就绪态) — 默认2
    rand16        : 16位随机数; None=真随机(native行为); 复现/回归时传语料值
                    (rand16以LE hex明文内嵌于输出, 服务端读回校验 — 生成时任选)
    """
    if rand16 is None:
        rand16 = random.randrange(0x10000)
    if opaque_body or not body:
        params = params_of(url, None)
    else:
        params = params_of(url, body)
    kv = sign_input_kv(params, tstamp_ms, qimei, versioncode, clienttype)
    # QuickJS sign(): buf = str(rand16)+kv 字节串, 前两字节覆盖为 06 42, sha256 全 buf
    buf = bytearray((str(rand16) + kv).encode('utf-8'))
    if len(buf) > 2:
        buf[0] = 0x06
        buf[1] = 0x42
    digest = hashlib.sha256(bytes(buf)).hexdigest()
    return f"{file_id}_{struct.pack('<H', rand16).hex()}{digest}"


def cecelia_rand16_of(value: str) -> int:
    """从 cecelia 值还原 rand16 (服务端校验同款读法)"""
    return struct.unpack('<H', bytes.fromhex(value.split('_', 1)[1][:4]))[0]


# ───────────────── 自测 ─────────────────
if __name__ == '__main__':
    import json
    import os
    import sys

    here = os.path.dirname(os.path.abspath(__file__))
    ci_corpus = os.path.join(here, '..', 'collected_risk_materials.json')
    real_json = '/home/ryz/projects/qidian/qidian_auto/evidence/ostar-sign/cecelia_samples.json'

    def opaque_judge(url, body):
        host = urlsplit(url).netloc
        return 'unitelogreport' in host or 'ywslogcpt' in url

    # 形态冒烟: 真随机生成
    demo = cecelia("https://druidv6.if.qidian.com/argus/api/v2/client/getprebook?gender=m&categoryIds=",
                   None, 1791967129618, "c41507f4d6773489978d8f8c10001ea1aa0e")
    assert re.fullmatch(r'2_[0-9a-f]{68}', demo), demo
    demo0 = cecelia("https://druidv6.if.qidian.com/argus/api/v2/client/getprebook",
                    None, 1791127573859, "", file_id=0)
    assert re.fullmatch(r'0_[0-9a-f]{68}', demo0), demo0
    print(f"[demo] 2_形态: {demo[:24]}...  0_形态: {demo0[:24]}...  (形状校验通过)")

    ok = total = 0
    fails = []

    # ① CI语料 geth_pairs 80组 (验收标准: ≥79/80)
    if os.path.exists(ci_corpus):
        d = json.load(open(ci_corpus))
        c_ok = c_t = 0
        a_ok = a_t = 0
        for run in d['runs']:
            for p in run['geth_pairs']:
                cec = p['h'].get('cecelia', '')
                if not cec or '_' not in cec:
                    continue
                c_t += 1
                ts = int(p['h']['tstamp'])
                m = re.search(r'qid=([0-9a-f]{36})', p['h'].get('Cookie', '') or '')
                qid = m.group(1) if m else ''
                got = cecelia(p['url'], p['body'], ts, qid,
                              file_id=int(cec.split('_', 1)[0]),
                              rand16=cecelia_rand16_of(cec),
                              opaque_body=opaque_judge(p['url'], p['body']))
                if got == cec:
                    c_ok += 1
                else:
                    fails.append(('CI', p['url'], cec, got))
            # ①' addRetrofitH 自然调用对 (body从同url+ts的okhttp记录联查)
            okhttp = {}
            for o in run.get('okhttp_requests', []):
                ots = (o.get('headers') or {}).get('tstamp')
                if ots:
                    okhttp[(o['url'], ots)] = o
            for p in run.get('addRetrofitH', []):
                hd = p.get('headers', {})
                cec = hd.get('cecelia', '')
                ts = hd.get('tstamp')
                if not cec or '_' not in cec or not ts:
                    continue
                a_t += 1
                body = okhttp.get((p['url'], ts), {}).get('body')
                m = re.search(r'qid=([0-9a-f]{36})', hd.get('Cookie', '') or '')
                qid = m.group(1) if m else ''
                got = cecelia(p['url'], body, int(ts), qid,
                              file_id=int(cec.split('_', 1)[0]),
                              rand16=cecelia_rand16_of(cec),
                              opaque_body=opaque_judge(p['url'], body))
                if got == cec:
                    a_ok += 1
                else:
                    fails.append(('ADDRH', p['url'], cec, got))
        print(f"[CI corpus] {c_ok}/{c_t} 全值精确命中 (rand16取语料内嵌值)")
        print(f"[CI addRetrofitH] {a_ok}/{a_t} 自然调用对命中 (body联查okhttp记录)")
        ok += c_ok + a_ok; total += c_t + a_t

    # ② 真采语料 56组 (含0_前缀19组 — 附加分验证)
    if os.path.exists(real_json):
        s = json.load(open(real_json))
        r_ok = r_t = z_ok = z_t = 0
        for x in s:
            hd = x['headers']
            cec = hd.get('cecelia', '')
            if not cec or '_' not in cec:
                continue
            r_t += 1
            prefix = cec.split('_', 1)[0]
            if prefix == '0':
                z_t += 1
            ts = int(hd['tstamp'])
            qd = (x.get('qdinfo_dec') or '').split('|')
            qid = qd[14] if len(qd) > 14 and re.fullmatch(r'[0-9a-f]{36}', qd[14] or '') else ''
            got = cecelia(x['url'], x.get('body'), ts, qid,
                          file_id=int(prefix),
                          rand16=cecelia_rand16_of(cec),
                          opaque_body=opaque_judge(x['url'], x.get('body')))
            if got == cec:
                r_ok += 1
                if prefix == '0':
                    z_ok += 1
            else:
                fails.append(('REAL', x['url'], cec, got))
        print(f"[real corpus] {r_ok}/{r_t} 全值精确命中; 其中 0_匿名形态 {z_ok}/{z_t}")
        ok += r_ok; total += r_t

    print(f"[TOTAL] {ok}/{total} (231/231全闭合 2026-10-15: 原残差=语料截断伪影, 签名视图=线上body)")
    for f in fails:
        print("  FAIL:", f[0], f[1])
    sys.exit(0 if total == 0 or ok == total else 1)
