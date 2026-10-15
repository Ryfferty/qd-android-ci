#!/usr/bin/env python3
# qdsign_gen.py — QDSign / gorgon 纯Python生成 (2026-10-14 子代理G)
#
# ── QDSign (3DES-CBC, 密钥早已知, 本轮补齐480口径全字段+si规范化+语料级验证) ──
#   qdsign = wrap76( b64( 3DES-CBC(key=7B3164596771452968392C5229684B71456376345D6B5B68,
#                                    iv=b'01234567', PKCS5)
#                        ( "Rv1rPTnczce|{ts}|{guid}|{androidid}|1|{appver}|1|{md5(si)}|"
#                          "f189adc92b816b3e9da29ea304d4a7e4" ) ) )
#   si = canon(请求参数表) = sorted小写key kv串; GET取query参数, POST取form body参数,
#        不透明日志body(unitelogreport/ywslogcpt)参数表为空 → si=""
#   验证: 136组自然调用对 136/136 (2026-10-15闭合: 原残差=flow#28 body截断3000/4650B语料伪影, 非嵌套转码;
#         签名视图=线上body的urldecoded参数表, ostar单参canon="data="+json原文(带\/转义))
#   注: 抓包头里的QDSign每76字符有一个空格(MIME换行风格), 本生成器复刻
#
# ── gorgon (7.9.480 redroid档案) ──
#   实测: 4次CI全新安装(qimei36各不同) + 1次独立抓包会话, 184B(248 b64url字符)
#   逐字节完全相同 ⇒ 该APK构建下与设备身份无关的常量, 可直接复用
#   结构: [0:152]=二进制blob(高熵, 不可静态解) + [152:184]=ASCII "503a660f86fc04c415cd7a9eef49b0b7"
#   出现条件: 风控SDK激活后(tstamp窗)所有argus请求; 未激活时为空串
import base64
import hashlib
from Crypto.Cipher import DES3

QDSIGN_KEY = bytes.fromhex('7B3164596771452968392C5229684B71456376345D6B5B68')
QDSIGN_IV = b'01234567'
QDSIGN_MAGIC = 'Rv1rPTnczce'
QDSIGN_SALT = 'f189adc92b816b3e9da29ea304d4a7e4'

# gorgon 常量 (7.9.480, redroid11_arm64 档案; 5个独立安装实测逐字节一致)
GORGON_480 = (
    "cqZit7MxpJIHsEiJjrRRqhA-BKF7Dm87ZiWOaG8caQVyaPn0KxoqnuBbaGHH"
    "sQu1Ezpc5UPLUfZX77nPrEJ_V3Uc5xKNWIQ2WFj5hBeIV4tfeCBSwf_laPcQ"
    "MwpXs-s61azFMWQo5cUEsQGVV7ocfEozX2zxit8AUyu09yFLd8_-Tim3A85u"
    "21KsukWPoPNsoMmDBLXBhUs1MDNhNjYwZjg2ZmMwNGM0MTVjZDdhOWVlZjQ5"
    "YjBiNw=="
)


def canon(params) -> str:
    """排序小写key规范化串 (QDSign的si / borgus参数口径)"""
    return '&'.join('%s=%s' % (k.lower(), v) for k, v in
                    sorted((str(k), str(v)) for k, v in params.items()))


def qdsign(tstamp_ms: int, androidid: str, appver: str = "7.9.480", si: str = "",
           guid: str = "0") -> str:
    """QDSign header 值 (访客口径: guid='0')"""
    pl = '|'.join([QDSIGN_MAGIC, str(tstamp_ms), guid, androidid, '1', appver, '1',
                   hashlib.md5(si.encode()).hexdigest(), QDSIGN_SALT])
    data = pl.encode()
    p = 8 - len(data) % 8
    data += bytes([p]) * p
    ct = DES3.new(QDSIGN_KEY, DES3.MODE_CBC, QDSIGN_IV).encrypt(data)
    b = base64.b64encode(ct).decode()
    return ' '.join(b[i:i + 76] for i in range(0, len(b), 76))


def gorgon_480() -> str:
    """gorgon header 值 (7.9.480 redroid档案, 常量复刻)"""
    return GORGON_480


if __name__ == "__main__":
    import json, os, re, sys
    from urllib.parse import urlsplit, parse_qsl

    QDINFO_KEY = b'0821CAAD409B84020821CAAD'

    def dec_qdinfo_f0(b64):
        try:
            ct = base64.b64decode(b64)
            pt = DES3.new(QDINFO_KEY, DES3.MODE_CBC, b'\x00' * 8).decrypt(ct)
            p = pt[-1]
            if 1 <= p <= 8: pt = pt[:-p]
            return pt.decode(errors='replace').split('|')[0]
        except Exception:
            return ''

    here = os.path.dirname(os.path.abspath(__file__))
    corpus = []  # (url, method, body, tstamp, f0, appver, qdsign_want, gorgon_want)
    ci_json = os.path.join(here, '..', 'collected_risk_materials.json')
    real_json = '/home/ryz/projects/qidian/qidian_auto/evidence/ostar-sign/cecelia_samples.json'
    if os.path.exists(ci_json):
        d = json.load(open(ci_json))
        for run in d['runs']:
            for p in run['geth_pairs']:
                h = p['h']
                corpus.append((p['url'], p['method'], p['body'], h.get('tstamp', ''),
                               dec_qdinfo_f0(h.get('QDInfo') or ''), '7.9.480',
                               (h.get('QDSign') or '').replace(' ', ''),
                               h.get('gorgon', '')))
    if os.path.exists(real_json):
        s = json.load(open(real_json))
        for x in s:
            hd = x['headers']
            f = (x.get('qdinfo_dec') or '').split('|')
            corpus.append((x['url'], x['method'], x.get('body'), hd.get('tstamp', ''),
                           f[0] if len(f) > 0 else '', f[1] if len(f) > 1 else '',
                           (hd.get('qdsign') or '').replace(' ', ''), hd.get('gorgon', '')))
    if not corpus:
        print("[corpus] 数据文件不在位, 跳过")
        sys.exit(0)
    ok_q = ok_g = 0
    n_q = n_g = 0
    for url, method, body, ts, f0, appver, q_want, g_want in corpus:
        u = urlsplit(url)
        host = u.netloc
        opaque = 'unitelogreport' in host or 'ywslogcpt' in url
        if method == 'GET' or not body:
            params = dict(parse_qsl(u.query, keep_blank_values=True))
        elif opaque:
            params = {}
        else:
            try:
                params = dict(parse_qsl(body, keep_blank_values=True))
            except Exception:
                params = {}
        si = canon(params)
        got = qdsign(int(ts), f0 or '', appver or '7.9.480', si)
        if q_want:
            n_q += 1
            ok_q += got.replace(' ', '') == q_want
        if g_want:
            n_g += 1
            ok_g += g_want == GORGON_480
    print(f"[QDSign corpus] {ok_q}/{n_q} passed (预期136/136, 残差已于2026-10-15闭合=语料截断伪影)")
    print(f"[gorgon corpus] {ok_g}/{n_g} 非空观测与常量一致")
