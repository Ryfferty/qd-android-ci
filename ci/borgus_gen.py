#!/usr/bin/env python3
# borgus_gen.py — FockUtil.getH 的 borgus 纯Python实现
#
# v2 (2026-10-14 子代理G): 双形态统一破解 —— borgus 输入 = "排序kv合并串"
#   input = "&".join(f"{k}={v}" for k in sorted(d))
#   d = {请求参数(query + urlencoded kv body, key小写)} ∪ {clienttype:1, qimei:qimei36,
#        tstamp:ms, versioncode:1996}   (同键去重; 无参数请求退化为标准四字段形态)
#   证据: 136组自然调用对(4次CI全新安装×80 + redroid抓包56) 135/136 精确复现
#         (唯一残差=ostar嵌套编码body, 线上body≠签名时所见形态)
#   旧结论修正: "标准形态只覆盖日志族" 不成立 —— 单一形态, 参数并入排序kv即覆盖全部端点
#
# v1 (2026-10-13): 算法逆向自 libfock.so v7a sn@0x6dd1 (360壳VMP'd FockUtil.getH→Fock.sn)
#   v = crc32(input); TABLE = [MD2, MD4, MD5]
#   h1 = TABLE[v%3]; h2 = TABLE[(v>>8)%3]; borgus = hex(h2(h2(h1(input))))
#   验证: 41/41 真实向量 + 35/35 unidbg oracle 探针
#
# 依赖: pycryptodome (MD2/MD4)
import zlib
import hashlib
from urllib.parse import urlsplit, parse_qsl
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
    """[v1兼容API] 标准四字段形态 (QDReader 7.9.464口径, oracle_verdict.py 在用)"""
    s = "clienttype=%s&qimei=%s&tstamp=%d&versioncode=%s" % (clienttype, qimei, tstamp_ms, versioncode)
    return fock_sn(s.encode())


def borgus_param_map(params: dict, tstamp_ms: int, qimei: str = "",
                     versioncode: str = "1996", clienttype: str = "1") -> str:
    """[v2核心] 排序kv合并形态 —— getH 实际签名口径 (7.9.480 实证 135/136)

    params: 请求参数表 (key会被小写化; query与form body参数合并; 不透明body传{})
    返回: fock_sn(排序kv串)
    """
    d = {str(k).lower(): str(v) for k, v in params.items()}
    d.update({'clienttype': clienttype, 'qimei': qimei,
              'tstamp': str(tstamp_ms), 'versioncode': versioncode})
    s = '&'.join(f'{k}={d[k]}' for k in sorted(d))
    return fock_sn(s.encode())


def params_of(url: str, body: str = None) -> dict:
    """从 url/query + urlencoded body 提取参数表 (getH 的 Java 层参数视角近似)

    注意: 不透明body(日志blob)不属于kv参数——此时应传 body=None (由调用方判定)。
    判定参考: ywslogcpt 族 body 是加密blob, 不是表单。
    """
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


def borgus_480(url: str, body, tstamp_ms: int, qimei: str,
               opaque_body: bool = False, versioncode: str = "1996") -> str:
    """[v2便捷] 7.9.480 请求级 borgus (双形态统一入口)

    opaque_body=True 表示 body 是不透明blob(如ywslogcpt日志) —— 不并入参数
    """
    if opaque_body or not body:
        params = params_of(url, None)   # 仅query参数
    else:
        params = params_of(url, body)   # query + form body参数
    return borgus_param_map(params, tstamp_ms, qimei, versioncode)


# ───────────────────────── 自测 ─────────────────────────
if __name__ == "__main__":
    # v1 真实测试向量 (5轮CI采集, 跨4设备) —— 兼容回归
    VECTORS = [
        (1792838577686, "d84d12c886c9d63652e3b149b971056e"),
        (1792838577687, "cfa96732c6fc3c4938805cbb7903971e"),
        (1792838577688, "09257851cfbbc3b8c164fbb327d77c25"),
        (1792838578686, "fe1e5311d27cef5ce5fa3ab64ad8df12"),
        (1791838809478, "ec67efcc9e8a5ed49cca228a0878e4ca"),
        (1792840000000, "dcfa723c0f40afeb20bac258118b2e2f"),
        (1792841176912, "7430ee193f8c20c7c8899ec2655410a5"),
        (1791961107022, "b33e1fda989a651d03cdff0866c10faf"),
        (1791837802649, "e233805531cf464a27eae3821654038b"),
        (1791843905603, "d7a65cdf764e618aea0ea093bcd1c860"),
        (1791843905583, "7d93dac854078adae25fe0ece32e4040"),
    ]
    ok = 0
    for ts, want in VECTORS:
        got = borgus(ts)
        ok += got == want
    print(f"[v1 vectors] {ok}/{len(VECTORS)} passed")
    t = fock_sn(b"test")
    assert t == "ba3e92006163dd0195eb2096cc731e91", "fock_sn oracle vector FAILED"
    print("[oracle] fock_sn('test') OK")

    # v2 全语料回归 (136组自然调用对: 4×CI + 56真采) —— 数据在位时执行
    import json, os, re, sys
    here = os.path.dirname(os.path.abspath(__file__))
    corpus = []
    ci_json = os.path.join(here, '..', 'collected_risk_materials.json')
    real_json = '/home/ryz/projects/qidian/qidian_auto/evidence/ostar-sign/cecelia_samples.json'
    if os.path.exists(ci_json):
        d = json.load(open(ci_json))
        for run in d['runs']:
            for p in run['geth_pairs']:
                m = re.search(r'qid=([0-9a-f]{36})', p['h'].get('Cookie', '') or '')
                corpus.append((p['url'], p['body'], int(p['h']['tstamp']),
                               m.group(1) if m else '', p['h'].get('borgus', '')))
    if os.path.exists(real_json):
        s = json.load(open(real_json))
        for x in s:
            hd = x['headers']
            qd = (x.get('qdinfo_dec') or '').split('|')
            qid = qd[14] if len(qd) > 14 and re.fullmatch(r'[0-9a-f]{36}', qd[14] or '') else ''
            corpus.append((x['url'], x.get('body'), int(hd['tstamp']), qid, hd.get('borgus', '')))
    if not corpus:
        print("[v2 corpus] 数据文件不在位, 跳过 (CI环境仅v1向量)")
        sys.exit(0)
    ok2 = 0
    for url, body, ts, qid, want in corpus:
        host = urlsplit(url).netloc
        opaque = 'unitelogreport' in host or 'ywslogcpt' in url  # 日志blob体不并入参数
        params = {} if opaque or not body else params_of(url, body)
        if not opaque and not body:
            params = params_of(url, None)
        got = borgus_param_map(params, ts, qid, '1996')
        ok2 += got == want
    print(f"[v2 corpus] {ok2}/{len(corpus)} passed (预期135/136, 残差=ostar嵌套编码body)")
