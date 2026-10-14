#!/usr/bin/env python3
# flows_extract.py — mitmproxy flows → 登录态headers结构化JSON (子代理K, 2026-10-15)
#
# 目的: 给风控头模板做"真值diff"——从 mitmdump -w 落盘的flows里逐请求提取完整headers,
#   输出与 qidian_auto/ci/app_qrlogin_chain.py 的 qd_headers / qd-android-ci/ci/pure_stack.py
#   可逐字段对拍的 JSON。
#
# 用法(runner上):
#   python3 ci/flows_extract.py /tmp/all.flows --out-dir out \
#       [--secrets-file /tmp/secrets.txt] [--scrub-flows] [--max-body 4096]
#   --secrets-file: 每行一个待脱敏的精确凭据值(ywKey/CmfuToken/UserInfo原文; 只在runner内存/tmp)
#   --scrub-flows:  额外重写一份脱敏flows文件(out/flows_scrubbed.mitm, headers+body双层scrub)
#
# 输出(out/):
#   headers_extract.json   ← 主交付: 全部qidian/yuewen请求逐条{url,method,headers(原序),body,...}
#                            + meta(header出现率/UA清单/Cookie字段清单/登录态证据)
#   extract_summary.json   ← 机器可读摘要(argus数/登录态cookie数/文件大小)
#
# 凭据纪律(repo=PUBLIC): 精确值替换(第一层) + 结构正则(ywkey=/cmfuToken=/UserInfo长串, 第二层);
#   masked形态=<SCRUBBED len=N>, 字段名与字段存在性保留(diff正是要字段集), 值长度保留供识别。
#   log只打计数, 不打值。
# 自测: python3 ci/flows_extract.py --selftest   (合成flows→提取→断言scrub+结构)
import io, json, sys, os, re, time, argparse

MASK = '<SCRUBBED>'

# 结构正则(与具体值无关的兜底; 精确secret替换先做)
RE_COOKIE_YWKEY = re.compile(r'(?i)(\bywkey=)[^;\s"&]+')
RE_COOKIE_CMFU = re.compile(r'(?i)(\bcmfutoken=)[^;\s"&]+')
RE_JSON_YWKEY = re.compile(r'(?i)("(?:ywkey|ywKey)"\s*:\s*")([^"]{8,})(")')
RE_JSON_CMFU = re.compile(r'(?i)("(?:cmfutoken|CmfuToken)"\s*:\s*")([^"]{8,})(")')
RE_JSON_USERINFO = re.compile(r'(?i)("(?:userinfo|UserInfo|userToken|UserToken)"\s*:\s*")([^"]{40,})(")')

# qd_headers(app_qrlogin_chain.py)构造的键集 + 常规传输头 → diff视图基准
QD_HEADER_NAMES = {'User-Agent', 'Accept-Encoding', 'QDInfo', 'QDSign', 'tstamp',
                   'borgus', 'cecelia', 'gorgon', 'ibex', 'Cookie',
                   'Content-Type', 'Connection', 'Host', 'Content-Length'}


def load_secrets(path):
    vals = []
    if path and os.path.exists(path):
        for line in open(path, encoding='utf-8', errors='replace'):
            v = line.strip()
            if len(v) >= 8:
                vals.append(v)
    return vals


def scrub(s, secrets):
    """str脱敏: 精确值→<SCRUBBED len=N>; 再跑结构正则。"""
    if not isinstance(s, str) or not s:
        return s
    for v in secrets:
        if v in s:
            s = s.replace(v, '%s len=%d' % (MASK, len(v)))
    s = RE_COOKIE_YWKEY.sub(r'\1' + MASK, s)
    s = RE_COOKIE_CMFU.sub(r'\1' + MASK, s)
    s = RE_JSON_YWKEY.sub(lambda m: m.group(1) + MASK + m.group(3), s)
    s = RE_JSON_CMFU.sub(lambda m: m.group(1) + MASK + m.group(3), s)
    s = RE_JSON_USERINFO.sub(lambda m: m.group(1) + MASK + m.group(3), s)
    return s


def scrub_bytes(b, secrets):
    """bytes脱敏: 文本可解→scrub后回编码; 二进制→只做精确secret字节替换。"""
    if not b:
        return b
    hit = any(v.encode() in b for v in secrets)
    try:
        s = b.decode('utf-8')
        return scrub(s, secrets).encode('utf-8')
    except UnicodeDecodeError:
        if hit:
            for v in secrets:
                b = b.replace(v.encode(), MASK.encode())
        return b


def cookie_analysis(cookie_val):
    """Cookie串→(字段顺序, 字段→值dict)。输入应已scrub。"""
    order, kv = [], {}
    for part in (cookie_val or '').split(';'):
        part = part.strip()
        if not part or '=' not in part:
            continue
        k, v = part.split('=', 1)
        if k not in kv:
            order.append(k)
            kv[k] = v
    return order, kv


def _scrub_flow(flow, secrets):
    """就地scrub一个flow(headers+请求体+响应体)——用于重写脱敏flows副本。"""
    try:
        for k, v in list(flow.request.headers.fields):
            vs = v.decode('latin-1', 'replace')
            sv = scrub(vs, secrets)
            if sv != vs:
                flow.request.headers[k] = sv
        try:
            b = flow.request.content
            if b:
                sb = scrub_bytes(b, secrets)
                if sb != b:
                    flow.request.content = sb
        except Exception:
            pass
        if flow.response is not None:
            for k, v in list(flow.response.headers.fields):
                vs = v.decode('latin-1', 'replace')
                sv = scrub(vs, secrets)
                if sv != vs:
                    flow.response.headers[k] = sv
            try:
                b = flow.response.content
                if b:
                    sb = scrub_bytes(b, secrets)
                    if sb != b:
                        flow.response.content = sb
            except Exception:
                pass
    except Exception:
        pass


def extract(fflows, out_dir, secrets, max_body, scrub_flows_out):
    from mitmproxy import io as mio
    from mitmproxy.http import HTTPFlow

    os.makedirs(out_dir, exist_ok=True)
    entries = []
    fout = None
    fw = None
    if scrub_flows_out:
        fout = open(scrub_flows_out, 'wb')
        fw = mio.FlowWriter(fout)

    stats = {'total': 0, 'http': 0, 'qd': 0, 'argus': 0, 'login_cookie_argus': 0,
             'login_cookie_all': 0, 'ts_min': None, 'ts_max': None, 'write_err': 0}
    ua_set, gth_set = set(), set()
    argus_header_counts, argus_extra_names = {}, {}
    cookie_orders, cookie_field_distinct = {}, {}
    hosts = {}

    n = 0
    try:
        reader = mio.FlowReader(open(fflows, 'rb'))
        for flow in reader.stream():
            n += 1
            stats['total'] += 1
            try:
                if fw is not None:
                    _scrub_flow(flow, secrets)
                    fw.add(flow)
            except Exception:
                stats['write_err'] += 1
            if not isinstance(flow, HTTPFlow):
                continue
            stats['http'] += 1
            try:
                req = flow.request
            except Exception:
                continue
            host = req.host or ''
            is_qd = ('qidian.com' in host) or ('yuewen.com' in host)
            hosts[host] = hosts.get(host, 0) + 1
            if not is_qd:
                continue
            stats['qd'] += 1
            is_argus = '/argus/' in (req.path or req.url)

            ts = None
            try:
                ts = req.timestamp_start
                stats['ts_min'] = ts if stats['ts_min'] is None else min(stats['ts_min'], ts)
                stats['ts_max'] = ts if stats['ts_max'] is None else max(stats['ts_max'], ts)
            except Exception:
                pass

            # headers: 原序原大小写(fields是(bytes,bytes))
            headers, header_order = {}, []
            try:
                for k, v in req.headers.fields:
                    ks = k.decode('latin-1', 'replace')
                    vs = scrub(v.decode('latin-1', 'replace'), secrets)
                    header_order.append(ks)
                    headers[ks] = vs
            except Exception:
                pass

            cookie = headers.get('Cookie') or headers.get('cookie') or ''
            # 登录态判定: scrub后ywkey=<SCRUBBED>仍算"字段非空"; 空值形态"ywkey=;"=匿名
            login_ck = bool(re.search(r'ywkey=[^;\s]+', cookie)) or \
                       bool(re.search(r'(?i)cmfuToken=[^;\s]+', cookie))
            if re.search(r'(?i)ywkey=;\s', cookie + ' ') and not re.search(r'(?i)cmfuToken=[^;\s]+', cookie):
                login_ck = False
            if login_ck:
                stats['login_cookie_all'] += 1

            ua = headers.get('User-Agent') or headers.get('user-agent') or ''
            if ua:
                ua_set.add(ua)
                m = re.search(r'getTabHeight_(\d+)', ua)
                if m:
                    gth_set.add(int(m.group(1)))

            body = ''
            try:
                b = req.content
                if b:
                    body = scrub(b.decode('utf-8', 'replace')[:max_body], secrets)
            except Exception:
                body = '(body_err)'

            status, resp_result = None, None
            try:
                if flow.response:
                    status = flow.response.status_code
                    try:
                        rc = flow.response.content or b''
                        j = json.loads(rc[:4096].decode('utf-8', 'replace')) if rc[:1] in (b'{', b'[') else None
                        if isinstance(j, dict):
                            resp_result = j.get('Result', j.get('code'))
                    except Exception:
                        pass
            except Exception:
                pass

            entry = {
                'seq': stats['qd'],
                'ts': round(ts, 1) if ts else None,
                'method': req.method,
                'host': host,
                'url': scrub(req.url, secrets),
                'path': scrub(req.path, secrets),
                'http_status': status,
                'resp_result': resp_result,
                'headers': headers,
                'header_order': header_order,
                'body': body,
                'body_len': len(body),
                'login_cookie': bool(login_ck),
                'is_argus': is_argus,
            }

            if is_argus:
                stats['argus'] += 1
                if login_ck:
                    stats['login_cookie_argus'] += 1
                for k in headers:
                    argus_header_counts[k] = argus_header_counts.get(k, 0) + 1
                    if k not in QD_HEADER_NAMES:
                        argus_extra_names[k] = argus_extra_names.get(k, 0) + 1
                order, kv = cookie_analysis(cookie)
                if order:
                    key = '|'.join(order)
                    cookie_orders[key] = cookie_orders.get(key, 0) + 1
                    for ck, cv in kv.items():
                        d = cookie_field_distinct.setdefault(ck, set())
                        d.add(cv[:64] + ('...' if len(cv) > 64 else ''))
                entry['qd_headers_view'] = {k: headers.get(k) for k in
                                            ('User-Agent', 'Accept-Encoding', 'QDInfo', 'QDSign',
                                             'tstamp', 'borgus', 'cecelia', 'gorgon', 'ibex', 'Cookie')
                                            if headers.get(k) is not None}
                entry['extra_headers_vs_qdheaders'] = [k for k in header_order
                                                       if k not in QD_HEADER_NAMES]
            entries.append(entry)
    except Exception as e:
        # 截断尾部(mitmdump被kill时未写完的最后一条): 已读部分照常出
        print('[EXTRACT] stream end (%s) — 保留已读 %d 条' % (type(e).__name__, n))

    if fout:
        fout.close()

    cf_distinct = {k: sorted(v) for k, v in cookie_field_distinct.items()}
    meta = {
        'flows_file_bytes': os.path.getsize(fflows) if os.path.exists(fflows) else 0,
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'counts': stats,
        'capture_window_s': round(stats['ts_max'] - stats['ts_min'], 1)
                            if stats['ts_min'] is not None and stats['ts_max'] is not None else None,
        'hosts': dict(sorted(hosts.items(), key=lambda kv: -kv[1])[:25]),
        'ua_distinct': sorted(ua_set),
        'gettabheight_values': sorted(gth_set),
        'argus_header_presence': dict(sorted(argus_header_counts.items(), key=lambda kv: -kv[1])),
        'argus_extra_header_names': dict(sorted(argus_extra_names.items(), key=lambda kv: -kv[1])),
        'cookie_orders_seen': dict(sorted(cookie_orders.items(), key=lambda kv: -kv[1])[:10]),
        'cookie_field_distinct': cf_distinct,
        'scrub': {'exact_secrets_loaded': len(secrets),
                  'note': 'values masked as <SCRUBBED len=N>; field names/order/lengths kept'},
    }
    with open(os.path.join(out_dir, 'headers_extract.json'), 'w', encoding='utf-8') as f:
        json.dump({'meta': meta, 'requests': entries}, f, ensure_ascii=False, indent=1)
    summary = {k: meta['counts'][k] for k in
               ('total', 'http', 'qd', 'argus', 'login_cookie_argus', 'login_cookie_all')}
    summary['flows_file_bytes'] = meta['flows_file_bytes']
    summary['gettabheight_values'] = meta['gettabheight_values']
    summary['ua_count'] = len(ua_set)
    summary['cookie_fields'] = sorted(cf_distinct.keys())
    with open(os.path.join(out_dir, 'extract_summary.json'), 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print('[EXTRACT] %s' % json.dumps(summary, ensure_ascii=False))
    return summary


# ───────────────── 自测: 合成flows → 提取 → 断言 ─────────────────
def selftest():
    from mitmproxy import io as mio
    from mitmproxy.http import HTTPFlow, Request, Response

    tmp = '/tmp/flows_selftest'
    os.makedirs(tmp, exist_ok=True)
    fpath = os.path.join(tmp, 'all.flows')
    SECRET_YWKEY = 'a' * 40
    SECRET_CMFU = 'b' * 292
    from mitmproxy.connection import Client, Server

    def mkflow(req, resp):
        fl = HTTPFlow(Client(peername=('172.17.0.2', 44444), sockname=('172.17.0.1', 8899)),
                      Server(peername=('93.0.0.1', 443), address=('93.0.0.1', 443)))
        fl.request = req
        fl.response = resp
        return fl

    with open(fpath, 'wb') as f:
        w = mio.FlowWriter(f)
        # ① 登录态argus请求(头+体含凭据)
        r = Request.make('POST', 'https://druidv6.if.qidian.com/argus/api/v1/client/getconf',
                         'localLabels=&gender=0',
                         {'User-Agent': 'Mozilla/mobile QDReaderAndroid/7.9.480/1996/1002138/redroid/getTabHeight_68',
                          'QDInfo': 'QDI=' * 30, 'QDSign': 'QS==', 'tstamp': '1760000000000',
                          'borgus': 'f' * 32, 'cecelia': '2_abcd', 'gorgon': 'g' * 130,
                          'ibex': 'ib', 'Cookie': 'cmfuToken=%s; QDInfo=x; ywkey=%s; ywguid=900074427064; '
                                 'appId=12; areaId=30; lang=cn; mode=normal; bar=63; qid=%s; qidth=%s; '
                                 % (SECRET_CMFU, SECRET_YWKEY, 'c' * 36, 'c' * 36),
                          'Content-Type': 'application/x-www-form-urlencoded'})
        w.add(mkflow(r, Response.make(200, b'{"Result":0,"Data":{}}', {'Content-Type': 'application/json'})))
        # ② 匿名argus(空ywkey)
        r2 = Request.make('GET', 'https://bravev6.if.qidian.com/argus/api/v1/young/getconf', b'',
                          {'User-Agent': 'Mozilla/mobile QDReaderAndroid/7.9.480/1996/1002138/redroid/getTabHeight_68',
                           'Cookie': 'QDInfo=x; ywkey=; ywguid=; appId=12; bar=36; qid=%s; ' % ('c' * 36)})
        w.add(mkflow(r2, Response.make(200, b'{"Result":0}', {})))
        # ③ 非qd域(应跳过)
        r3 = Request.make('GET', 'https://example.com/x', b'', {})
        w.add(mkflow(r3, Response.make(200, b'ok', {})))
        # ④ 响应体含凭据(login响应)
        r4 = Request.make('POST', 'https://bravev6.if.qidian.com/argus/api/v2/user/login', 'appId=12',
                          {'Cookie': 'ywkey=; ywguid=;'})
        w.add(mkflow(r4, Response.make(200, ('{"Result":0,"Data":{"LoginResult":{"CmfuToken":"%s",'
                                            '"UserInfo":"1|n|%s|t|2|x|y"}}}' % (SECRET_CMFU, SECRET_YWKEY)).encode(), {})))

    secf = os.path.join(tmp, 'secrets.txt')
    open(secf, 'w').write(SECRET_YWKEY + '\n' + SECRET_CMFU + '\n')
    s = extract(fpath, tmp, [SECRET_YWKEY, SECRET_CMFU], 4096,
                os.path.join(tmp, 'scrubbed.mitm'))
    assert s['total'] == 4 and s['qd'] == 3 and s['argus'] == 3, s
    assert s['login_cookie_argus'] == 1, s
    assert s['gettabheight_values'] == [68], s
    j = json.load(open(os.path.join(tmp, 'headers_extract.json')))
    rq = j['requests'][0]
    ck = rq['headers']['Cookie']
    assert SECRET_CMFU not in ck and SECRET_YWKEY not in ck, 'cookie泄漏!'
    assert 'cmfuToken=<SCRUBBED> len=292' in ck, ck
    assert 'ywkey=<SCRUBBED> len=40' in ck, ck
    assert 'bar=63' in ck and 'ywguid=900074427064' in ck, ck
    assert rq['qd_headers_view']['ibex'] == 'ib' and 'extra_headers_vs_qdheaders' in rq
    assert rq['resp_result'] == 0 and rq['login_cookie'] is True
    anon = [x for x in j['requests'] if 'young/getconf' in x['url']][0]
    assert anon['login_cookie'] is False, '空ywkey误判登录'
    # scrubbed flows副本不再含精确凭据字节
    raw = open(os.path.join(tmp, 'scrubbed.mitm'), 'rb').read()
    assert SECRET_CMFU.encode() not in raw and SECRET_YWKEY.encode() not in raw, 'scrubbed flows泄漏!'
    # 响应体里的CmfuToken也脱敏(重读scrubbed flows验证)
    got_login_resp = False
    for fl in mio.FlowReader(io.BytesIO(raw)).stream():
        try:
            if b'user/login' in fl.request.url.encode():
                got_login_resp = SECRET_CMFU.encode() not in (fl.response.content or b'') and \
                                 MASK.encode() in (fl.response.content or b'')
        except Exception:
            pass
    assert got_login_resp, 'login响应体未脱敏'
    meta = j['meta']
    assert meta['argus_header_presence'].get('ibex') == 1
    assert 'bar' in meta['cookie_field_distinct'] and '63' in meta['cookie_field_distinct']['bar']
    assert meta['cookie_field_distinct']['bar'] == ['36', '63'], meta['cookie_field_distinct']['bar']
    print('[SELFTEST] OK — %s' % json.dumps(s, ensure_ascii=False))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('flows', nargs='?')
    ap.add_argument('--out-dir', default='out')
    ap.add_argument('--secrets-file', default=None)
    ap.add_argument('--scrub-flows', action='store_true')
    ap.add_argument('--max-body', type=int, default=4096)
    ap.add_argument('--selftest', action='store_true')
    a = ap.parse_args()
    if a.selftest or not a.flows:
        sys.exit(selftest())
    secrets = load_secrets(a.secrets_file)
    scrub_out = os.path.join(a.out_dir, 'flows_scrubbed.mitm') if a.scrub_flows else None
    extract(a.flows, a.out_dir, secrets, a.max_body, scrub_out)
    if scrub_out and os.path.exists(scrub_out):
        print('[EXTRACT] scrubbed flows → %s (%d bytes)' % (scrub_out, os.path.getsize(scrub_out)))


if __name__ == '__main__':
    main()
