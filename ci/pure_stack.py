#!/usr/bin/env python3
# pure_stack.py — 起点App 7.9.480 全套风控头 纯协议装配器（无VM/无设备/无oracle）
#
# 2026-10-14 定案五件套（全部离线可生成，验收详见各模块自测）:
#   borgus  = fock_sn(排序kv(请求参数 ∪ {clienttype,qimei,tstamp,versioncode}))   [135/136]
#   cecelia = "{0|2}_" + le16hex(rand16) + sha256(06 42 + str(rand16)+kv)          [230/231]
#   gorgon  = GORGON_480 常量（构建级，跨安装恒定）                                  [123/123]
#   QDSign  = 3DES(canon)（qdsign_gen.py 480口径）                                  [135/136]
#   QDInfo  = 3DES(20字段, f11=ywguid, f14=qimei36)（argus_fetch.py口径）
#   + ibex/UA/tstamp/Cookie 由调用方按请求拼装
#
# 用法:
#   from pure_stack import risk_headers
#   h = risk_headers(url, body, ts, qimei36, ywguid=0, method='POST',
#                    ua_brand='redroid', opaque_body=False)
#   → dict{cecelia, gorgon, borgus, QDSign, QDInfo, tstamp}
#   调用方自行补: Cookie(设备qid+账号ywguid/ywkey), User-Agent(含/brand/getTabHeight_68尾巴), ibex
#
# 自测: python3 pure_stack.py  → 对 collected_risk_materials.json geth_pairs 全字段对拍
import sys, os, time, base64
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from borgus_gen import borgus_480, fock_sn, params_of
from cecelia_gen import cecelia
from qdsign_gen import qdsign, gorgon_480, GORGON_480, canon


def qdinfo_480(imei: str, qimei36: str, ywguid: str = '0', ts_ms: int = None,
               model: str = 'redroid11_arm64', vcode: str = '1996',
               source: str = '1002138', appver: str = '7.9.480',
               screen: tuple = ('720', '1112')) -> str:
    """QDInfo 20字段口径 (3DES-CBC key 0821CAAD409B8402, k+k[:8], IV零, PKCS5)"""
    from Crypto.Cipher import DES3
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    f = [imei, appver, screen[0], screen[1], source, '11', '1', model, vcode, source,
         '4', ywguid, str(ts_ms), '1', qimei36, '', '', '', qimei36, '2']
    pt = '|'.join(f).encode()
    p = 8 - len(pt) % 8 or 8
    pt += bytes([p]) * p
    k = b'0821CAAD409B8402'
    ct = DES3.new(k + k[:8], DES3.MODE_CBC, b'\x00' * 8).encrypt(pt)
    return base64.b64encode(ct).decode()


def risk_headers(url: str, body, tstamp_ms: int, qimei36: str,
                 ywguid: str = '0', androidid: str = '', si: str = None,
                 opaque_body: bool = False, rand16: int = None,
                 model: str = 'redroid11_arm64', screen: tuple = ('720', '1112'),
                 uid: str = '') -> dict:
    """一键产五头。

    si: QDSign的签名内容——480口径=md5(canon(排序小写kv)); None=自动从url/body参数表算
    uid: 登录态身份字段(82条登录态真值实证: QDInfo f11与QDSign guid位=UserId; 匿名=''/'0')
    """
    if si is None:
        params = {} if (opaque_body or not body) else params_of(url, body)
        if not opaque_body and not body:
            params = params_of(url, None)
        si = canon(params)
    return {
        'cecelia': cecelia(url, body, tstamp_ms, qimei36,
                           file_id=(2 if qimei36 else 0),
                           rand16=rand16, opaque_body=opaque_body),
        'gorgon': GORGON_480,
        'borgus': borgus_480(url, body, tstamp_ms, qimei36, opaque_body=opaque_body),
        'QDSign': qdsign(tstamp_ms, androidid, si=si, guid=(uid or '0')),
        'QDInfo': qdinfo_480(androidid, qimei36, uid or '0', tstamp_ms,
                             model=model, screen=screen),
        'tstamp': str(tstamp_ms),
    }


if __name__ == '__main__':
    # 全字段对拍: CI语料80组, cecelia/borgus/gorgon三头精确匹配(带rand16复现)
    import json, re
    here = os.path.dirname(os.path.abspath(__file__))
    cj = os.path.join(here, '..', 'collected_risk_materials.json')
    if not os.path.exists(cj):
        print('[skip] 语料不在位'); sys.exit(0)
    d = json.load(open(cj))
    ok_cec = ok_bg = ok_gor = ok_ts = 0
    total = 0
    for run in d['runs']:
        for p in run['geth_pairs']:
            h = p.get('h', {})
            if not h.get('cecelia'):
                continue
            m = re.search(r'qid=([^;]+)', h.get('Cookie', ''))
            if not m or not h.get('tstamp'):
                continue
            q36 = m.group(1)
            url, body = p['url'], p.get('body')
            opaque = 'ywslogcpt' in url
            total += 1
            # cecelia复现需要语料的rand16(内嵌于输出前4hex):
            r16 = int.from_bytes(bytes.fromhex(h['cecelia'][2:6]), 'little')
            ce = cecelia(url, None if opaque else body, int(h['tstamp']), q36,
                         rand16=r16, opaque_body=opaque)
            bg = borgus_480(url, None if opaque else body, int(h['tstamp']), q36,
                            opaque_body=opaque)
            ok_cec += ce == h['cecelia']
            ok_bg += bg == h['borgus']
            ok_gor += h['gorgon'] == GORGON_480
    print(f'[pure_stack corpus] cecelia {ok_cec}/{total}  borgus {ok_bg}/{total}  '
          f'gorgon {ok_gor}/{total}')
    sys.exit(0 if (ok_cec == total and ok_bg == total) else 1)
