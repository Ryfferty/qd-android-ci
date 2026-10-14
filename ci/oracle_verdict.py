#!/usr/bin/env python3
# oracle_verdict.py — 活App风控头oracle终判链 (子代理F, 2026-10-14)
#
# 用法(runner上, 前置: redroid+q480 App已稳定启动, frida-server 14771已起且adb forward已通):
#   QD_BORN_SESSION=<base64(JSON)> python3 ci/oracle_verdict.py
#
# 流程:
#   1. attach hook_oracle.js (反检测盾+v7被动采集+Fock.sn捕获+rpc.geth)
#   2. 等qimei激活 (自然[GETH]对 cecelia 出现 2_ 前缀, stat.geth_cec2>0; 期限attach+180s)
#   3. oracle冒烟: geth(getconf URL) → 验证 cecelia 2_ / gorgon非空 / borgus 32hex / canon(md5)对拍
#   4. 真头终判链(9步, 请求从GitHub runner IP发出): getconf → limitfreepopup → tips → recFreshmanTask
#      → rewardFreshmanTask → autoreceive v2/v3 → 复查 limitfreepopup+getconf
#      每步: python拼好(url,method,body) → oracle geth拿全套头 → 修补 Cookie(ywguid/ywkey) +
#      QDInfo(f11=ywGuid, f12=当前ms) + QDSign(f2=uid, 保持oracle的ts与md5) → 发请求
#   5. 合成头对照链(同9步): python自算 QDInfo/QDSign(3DES, canon md5已与自然调用对拍一致) +
#      borgus_gen标准形态 + 无cecelia/gorgon —— 真头vs合成头 Result对比 = 风控头因果证据
#   6. (条件) 若真头reward≠0: 追加一发 verbatim oracle QDSign(uid=0) 的reward诊断
#   7. 汇总 verdict_summary.json + sn两形态样本提取(oracle.log → sn_pairs.txt)
#
# 纪律: QD_BORN_SESSION解码值只活在内存, 绝不echo到日志/绝不写文件/绝不进commit;
#       job log只打 Result码/Message/响应体摘要; 头值只落 /tmp/verdict/**(artifact, ywkey/CmfuToken已脱敏)。
import os, sys, json, time, base64, gzip, re, subprocess, threading, collections
import urllib.request, urllib.parse, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'ci'))

HOST = 'https://druidv6.if.qidian.com'
ADB_DEV = 'localhost:5555'
APP = 'com.qidian.QDReader'
HOOK = os.path.join(ROOT, 'hook_oracle.js')
EVID_DIR = '/tmp/verdict'
ORACLE_LOG = '/tmp/oracle.log'
SMOKE_URL = HOST + '/argus/api/v1/young/getconf'   # 自然App启动配置端点(GET, 无query)

K = b'0821CAAD409B8402'                              # QDInfo 3DES key (k + k[:8])
KS = bytes.fromhex('7B3164596771452968392C5229684B71456376345D6B5B68')  # QDSign 3DES key
QDINFO_IV = b'\x00' * 8
QDSIGN_IV = b'01234567'
F189 = 'f189adc92b816b3e9da29ea304d4a7e4'

SECRETS = []          # 待脱敏值(ywKey/CmfuToken)

def scrub(s):
    for sec in SECRETS:
        if sec and len(str(sec)) > 3:
            s = str(s).replace(str(sec), '<SCRUBBED>')
    return s

def L(msg):
    print(scrub(msg), flush=True)

def md5(s):
    import hashlib
    return hashlib.md5(s.encode() if isinstance(s, str) else s).hexdigest()

def des3_enc_b64(plain, key, iv):
    from Crypto.Cipher import DES3
    if isinstance(plain, str):
        plain = plain.encode()
    p = 8 - len(plain) % 8 or 8
    ct = DES3.new(key, DES3.MODE_CBC, iv).encrypt(plain + bytes([p]) * p)
    return base64.b64encode(ct).decode()

def des3_dec(b64s, key, iv):
    from Crypto.Cipher import DES3
    ct = base64.b64decode(b64s)
    pt = DES3.new(key, DES3.MODE_CBC, iv).decrypt(ct)
    if pt and 1 <= pt[-1] <= 16 and pt[-pt[-1]:] == bytes([pt[-1]]) * pt[-1]:
        pt = pt[:-pt[-1]]
    return pt.decode('utf-8', 'replace')

# ───────────────────────── 会话(secret只在内存) ─────────────────────────
def load_session():
    global SECRETS
    raw = os.environ.get('QD_BORN_SESSION') or ''
    if not raw:
        raise SystemExit('NO_SECRET: QD_BORN_SESSION env missing')
    d = json.loads(base64.b64decode(raw))
    if isinstance(d.get('resp'), dict):       # 兼容 newborn_session.json 嵌套形态
        flat = dict(d['resp'].get('data', {}))
        flat.update({k: v for k, v in d.items() if k != 'resp'})
        d = flat
    guid = str(d.get('ywGuid') or d.get('ywguid') or d.get('uid') or '')
    key = str(d.get('ywKey') or d.get('ywkey') or '')
    cmfu = str(d.get('CmfuToken') or d.get('cmfuToken') or '')
    SECRETS = [key, cmfu]
    if not guid or not key:
        raise SystemExit('SECRET_SCHEMA_ERR: no ywGuid/ywKey (keys=%s)' % list(d.keys()))
    L('[SESS] guid=%s ywKey=<len %d> CmfuToken=<len %d>' % (guid, len(key), len(cmfu)))
    return {'guid': guid, 'key': key, 'cmfu': cmfu}

# ───────────────────────── Oracle (frida RPC) ─────────────────────────
class Oracle:
    def __init__(self, host='127.0.0.1:14771'):
        import frida
        self.frida = frida
        self.host = host
        self.pid = None
        self.script = None
        self.exp = None
        self.logf = open(ORACLE_LOG, 'a')
        self.recent = collections.deque(maxlen=800)
        self.attach()

    def adb(self, *args, timeout=15):
        return subprocess.run(['adb', '-s', ADB_DEV] + list(args),
                              capture_output=True, text=True, timeout=timeout)

    def pidof(self):
        try:
            r = self.adb('shell', 'pidof', APP, timeout=10)
            out = (r.stdout or '').strip()
            return out.split()[0] if out else None
        except Exception:
            return None

    def attach(self):
        for attempt in range(6):
            try:
                pid = self.pidof()
                if not pid:
                    L('[ORACLE] no pid yet (attempt %d)' % attempt); time.sleep(5); continue
                dev = self.frida.get_device_manager().add_remote_device(self.host)
                self.session = dev.attach(int(pid))
                with open(HOOK) as f:
                    src = f.read()
                self.script = self.session.create_script(src)
                self.script.on('message', self._on_msg)
                self.script.load()
                self.exp = getattr(self.script, 'exports_sync', None) or self.script.exports
                self.pid = pid
                L('[ORACLE] attached pid=%s (ping=%s)' % (pid, self.exp.ping()))
                return True
            except Exception as e:
                L('[ORACLE] attach err (attempt %d): %s' % (attempt, scrub(str(e))[:200]))
                time.sleep(6)
        return False

    def _on_msg(self, message, data):
        try:
            if message.get('type') == 'log':
                line = str(message.get('payload'))
            elif message.get('type') == 'error':
                line = '[SCRIPT_ERR] ' + str(message.get('description'))[:400] + ' | ' + str(message.get('stack', ''))[:300]
            else:
                line = '[MSG] ' + json.dumps(message)[:300]
        except Exception:
            line = '[MSG_RAW] ' + str(message)[:300]
        self.logf.write(line + '\n'); self.logf.flush()
        self.recent.append(line)

    def stat(self):
        return self.exp.stat()

    def geth(self, url, method, body):
        """body: None(GET) / str(POST表单体原文, 可为'')。返回oracle Map dict。"""
        r = self._call_rpc('geth', url, method, body)
        if r is None or r.get('__err'):
            raise RuntimeError('rpc.geth err: %s' % (r or {}).get('__err'))
        return r.get('map') or {}

    def _call_rpc(self, fn, *args):
        box = {}
        def run():
            try:
                box['r'] = getattr(self.exp, fn)(*args)
            except Exception as e:
                box['e'] = str(e)
        t = threading.Thread(target=run, daemon=True)
        t.start(); t.join(40)
        if t.is_alive():
            raise RuntimeError('rpc.%s timeout(40s)' % fn)
        if 'e' in box:
            raise RuntimeError('rpc.%s exception: %s' % (fn, box['e']))
        return box.get('r')

# ───────────────────────── UI推进线程 (v7 tap battery同款) ─────────────────────────
TAPS = [(360, 580), (360, 1100), (180, 1100), (360, 350), (540, 1100), None,
        (360, 700), (360, 350), (360, 580), (360, 1100)]   # None = 上滑

def _find_bounds(xml, id_frag=None, text=None):
    if id_frag:
        pat = r'resource-id="[^"]*%s[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % re.escape(id_frag)
    else:
        pat = r'text="%s"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % re.escape(text)
    for m in re.finditer(pat, xml):
        x1, y1, x2, y2 = map(int, m.groups())
        return (x1 + x2) // 2, (y1 + y2) // 2
    return None

def ui_thread(stop, oracle):
    ti = 0
    while not stop.is_set():
        try:
            oracle.adb('shell', 'uiautomator', 'dump', '/sdcard/u.xml', timeout=15)
            r = oracle.adb('shell', 'cat', '/sdcard/u.xml', timeout=15)
            xml = r.stdout or ''
            xy = _find_bounds(xml, 'tvSkip') or _find_bounds(xml, 'btnAgree') or _find_bounds(xml, text='同意并继续')
            if xy:
                oracle.adb('shell', 'input', 'tap', str(xy[0]), str(xy[1]))
            else:
                t = TAPS[ti % len(TAPS)]; ti += 1
                if t is None:
                    oracle.adb('shell', 'input', 'swipe', '360', '900', '360', '300', '400')
                else:
                    oracle.adb('shell', 'input', 'tap', str(t[0]), str(t[1]))
        except Exception:
            pass
        stop.wait(12)

# ───────────────────────── 请求构造与patch ─────────────────────────
def patch_qdinfo(orig_b64, guid, now_ms):
    f = des3_dec(orig_b64, K + K[:8], QDINFO_IV).split('|')
    if len(f) < 13:
        raise RuntimeError('QDInfo字段数=%d(<13): %r' % (len(f), f[:5]))
    f[11] = guid          # f11 = uid (匿名设备=0)
    f[12] = str(now_ms)   # f12 = 时间戳ms
    return des3_enc_b64('|'.join(f), K + K[:8], QDINFO_IV)

def patch_qdsign_uid(orig_b64, guid):
    """oracle QDSign: Rv1rPTnczce|ts|uid|androidid|1|av|1|md5|f189...
    保持 oracle 的 ts 与 md5(对同一请求的签名), 只把 uid(=0) 换成账号 guid → 与Cookie/QDInfo一致。
    (App发送的QDSign含空格分块, python重编码无空格 — 两种格式服务端都收: App自然流/纯协议链均已实证)"""
    f = des3_dec(orig_b64.replace(' ', ''), KS, QDSIGN_IV).split('|')
    if len(f) != 9:
        raise RuntimeError('QDSign字段数=%d(!=9): %r' % (len(f), f[:4]))
    f[2] = guid
    return des3_enc_b64('|'.join(f), KS, QDSIGN_IV)

def patch_cookie(orig_ck, guid, key, cmfu):
    ck = orig_ck
    ck = re.sub(r'ywkey=;', 'ywkey=%s;' % key, ck, count=1)
    ck = re.sub(r'ywguid=;', 'ywguid=%s;' % guid, ck, count=1)
    if 'ywguid=%s' % guid not in ck:   # oracle Cookie缺槽位时兜底插入
        ck = ck.rstrip() + ' ywguid=%s; ywkey=%s; ' % (guid, key)
    if cmfu and 'cmfuToken=' not in ck:
        ck = ck.rstrip() + ' cmfuToken=%s; ' % cmfu
    return ck

def canon_of(url, method, body_bytes):
    """QDSign第8段md5的输入 (qd_newborn_chain同款, 已与App自然调用对拍一致:
    getprebook?gender=m&categoryIds= → md5('categoryids=&gender=m') == App QDSign f7 ✓)"""
    if method == 'GET':
        q = url.split('?', 1)[1] if '?' in url else ''
        if not q:
            return ''
        params = {}
        for kv in q.split('&'):
            if '=' in kv:
                k, v = kv.split('=', 1)
                params[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
        return '&'.join('%s=%s' % (k.lower(), v) for k, v in sorted(params.items()))
    if not body_bytes:
        return ''
    try:
        pf = dict(p.split('=', 1) for p in body_bytes.decode().split('&') if '=' in p)
        return '&'.join('%s=%s' % (k.lower(), urllib.parse.unquote_plus(v)) for k, v in sorted(pf.items()))
    except Exception:
        return ''

def send(url, method, body, headers, timeout=25):
    hh = dict(headers)
    if method == 'POST':
        hh.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        hh['Content-Length'] = str(len(body or b''))
    req = urllib.request.Request(url, data=body if method == 'POST' else None,
                                 headers=hh, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        raw, code = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, code = e.read(), e.code
    except Exception as e:
        raw, code = ('{"_local_error":"%s"}' % str(e)[:120]).encode(), 0
    try:
        raw = gzip.decompress(raw)
    except Exception:
        pass
    return raw, code

def mask_headers(h):
    m = dict(h)
    ck = m.get('Cookie')
    if ck:
        m['Cookie'] = re.sub(r'ywkey=[^;]+', 'ywkey=<SCRUBBED>', ck)
        m['Cookie'] = re.sub(r'cmfuToken=[^;]+', 'cmfuToken=<SCRUBBED>', m['Cookie'])
    return m

# ───────────────────────── 链定义 ─────────────────────────
def build_steps(tid):
    n0 = int(time.time() * 1000)
    rec_body = urllib.parse.urlencode({'taskId': tid, 'startTime': str(n0), 'endTime': str(n0 + 30000)})
    reward_body = urllib.parse.urlencode({'taskId': tid, 'mileStone': '-1', 'sessionKey': '',
                                          'banId': '0', 'captchaTicket': '', 'captchaRandStr': '',
                                          'challenge': '', 'validate': '', 'seccode': ''})
    return [
        ('getconf',     'GET',  '/argus/api/v1/young/getconf', None),
        ('limitfree',   'GET',  '/argus/api/v1/freshman/limitfreepopup', None),
        ('tips',        'GET',  '/argus/api/v1/freshman/getreadingtaskprocesstips', None),
        ('rec',         'POST', '/argus/api/v1/freshman/task/recFreshmanTask', rec_body),
        ('reward',      'POST', '/argus/api/v2/freshman/task/rewardFreshmanTask', reward_body),
        ('autorecv_v2', 'POST', '/argus/api/v2/freshman/autoreceive', ''),
        ('autorecv_v3', 'POST', '/argus/api/v3/freshman/autoreceive', ''),
        ('limitfree2',  'GET',  '/argus/api/v1/freshman/limitfreepopup', None),
        ('getconf2',    'GET',  '/argus/api/v1/young/getconf', None),
    ]

def extract_tid(raw_text):
    for pat in (r'"taskId"\s*:\s*"(\d+)"', r'"TaskId"\s*:\s*(\d+)'):
        m = re.search(pat, raw_text)
        if m:
            return m.group(1)
    return '0'

# ───────────────────────── 主流程 ─────────────────────────
SUMMARY = {'smoke': {}, 'real': [], 'synth': [], 'diag': [], 'sn_pairs': 0, 'notes': []}

def run_chain(tag, oracle, sess, steps, header_builder, dev):
    results = []
    for i, (label, method, path, body) in enumerate(steps):
        url = HOST + path
        body_bytes = body.encode() if isinstance(body, str) else body
        entry = {'tag': tag, 'step': label, 'method': method, 'url': url, 'body': body}
        try:
            headers = header_builder(url, method, body)
            entry['headers_masked'] = mask_headers(headers)
        except Exception as e:
            entry['error'] = 'header build: ' + scrub(str(e))[:300]
            L('[%s %02d %-12s] HDR_ERR %s' % (tag, i, label, entry['error']))
            results.append(entry)
            with open('%s/%s_%02d_%s.json' % (EVID_DIR, tag, i, label), 'w') as f:
                json.dump(entry, f, ensure_ascii=False, indent=1)
            time.sleep(2.5)
            continue
        raw, code = send(url, method, body_bytes, headers)
        entry['http_code'] = code
        text = raw.decode('utf-8', 'replace')
        entry['response'] = text[:20000]
        try:
            j = json.loads(text)
            entry['Result'] = j.get('Result')
            entry['Message'] = str(j.get('Message', ''))[:60]
            L('[%s %02d %-12s] HTTP %s Result=%s %s' % (tag, i, label, code, j.get('Result'), entry['Message']))
        except Exception:
            entry['Result'] = 'HTTP%d' % code
            L('[%s %02d %-12s] HTTP %s 非业务: %s' % (tag, i, label, code, text[:90].replace('\n', ' ')))
        results.append(entry)
        with open('%s/%s_%02d_%s.json' % (EVID_DIR, tag, i, label), 'w') as f:
            json.dump(entry, f, ensure_ascii=False, indent=1)
        time.sleep(2.5)
    return results

def real_header_builder(oracle, sess):
    def build(url, method, body):
        try:
            m = oracle.geth(url, method, body)   # body: None or str
        except Exception as e:
            L('[REAL] geth失败(%s) — 重挂oracle后重试一次' % scrub(str(e))[:120])
            if oracle.attach():
                m = oracle.geth(url, method, body)
            else:
                raise
        now_ms = int(time.time() * 1000)
        h = {'User-Agent': m.get('User-Agent', ''),
             'Accept-Encoding': 'gzip',
             'Connection': 'Keep-Alive',
             'QDInfo': patch_qdinfo(m['QDInfo'], sess['guid'], now_ms),
             'tstamp': m.get('tstamp', str(now_ms)),
             'QDSign': patch_qdsign_uid(m['QDSign'], sess['guid']),
             'Cookie': patch_cookie(m['Cookie'], sess['guid'], sess['key'], sess['cmfu'])}
        for k in ('cecelia', 'gorgon', 'borgus'):   # ★全套真风控头, verbatim
            if m.get(k):
                h[k] = m[k]
        return h
    return build

def synth_header_builder(sess, dev):
    def build(url, method, body):
        now_ms = int(time.time() * 1000)
        ts = str(now_ms)
        f = list(dev['qdinfo_fields'])
        f[11] = sess['guid']; f[12] = ts
        qdi = des3_enc_b64('|'.join(f), K + K[:8], QDINFO_IV)
        mm = md5(canon_of(url, method, body.encode() if isinstance(body, str) else body))
        qds = des3_enc_b64('|'.join(['Rv1rPTnczce', ts, sess['guid'], dev['androidid'],
                                     '1', dev['appver'], '1', mm, F189]), KS, QDSIGN_IV)
        from borgus_gen import borgus as borgus_std
        bor = borgus_std(now_ms, dev['qimei36'], dev['vcode'])
        ck = patch_cookie(dev['cookie_template'], sess['guid'], sess['key'], sess['cmfu'])
        ck = re.sub(r'QDInfo=[^;]+', 'QDInfo=%s' % qdi, ck, count=1)
        return {'User-Agent': dev['ua'], 'Accept-Encoding': 'gzip', 'Connection': 'Keep-Alive',
                'QDInfo': qdi, 'tstamp': ts, 'QDSign': qds, 'borgus': bor,
                'Cookie': ck}   # 无cecelia/gorgon = 纯协议出生条件
    return build

def main():
    os.makedirs(EVID_DIR, exist_ok=True)
    t_start = time.time()
    L('=== oracle verdict chain start (pid=%d) ===' % os.getpid())
    sess = load_session()

    oracle = Oracle()
    if not oracle.exp:
        L('[FATAL] oracle attach失败 — 如实报告, 不编造')
        SUMMARY['notes'].append('oracle attach failed')
        json.dump(SUMMARY, open(EVID_DIR + '/verdict_summary.json', 'w'), ensure_ascii=False, indent=1)
        return 0

    stop = threading.Event()
    th = threading.Thread(target=ui_thread, args=(stop, oracle), daemon=True)
    th.start()

    # 1. 等qimei激活: 自然[GETH]对 cecelia 2_ 前缀 (attach+180s期限)
    L('[WAIT] 等qimei激活 (stat.geth_cec2>0, 期限180s)...')
    t0 = time.time()
    activated = False
    while time.time() - t0 < 180:
        try:
            st = oracle.stat()
            if st.get('geth_cec2', 0) > 0:
                activated = True
                L('[WAIT] qimei激活 ✓ (attach+%ds, stat=%s)' % (time.time() - t0, json.dumps(st)))
                break
            if st.get('geth', 0) == 0 and int(time.time() - t0) % 30 < 6:
                L('[WAIT] t+%ds 尚无自然getH (stat=%s)' % (time.time() - t0, json.dumps(st)))
        except Exception as e:
            L('[WAIT] stat err: %s — 尝试重挂' % scrub(str(e))[:150])
            if not oracle.attach():
                time.sleep(8)
        time.sleep(5)
    if not activated:
        L('[WAIT] 180s内未见自然2_ cecelia — 仍尝试直调冒烟并如实报告')

    # 2. 冒烟测试
    smoke = {}
    try:
        m = oracle.geth(SMOKE_URL, 'GET', None)
        cec = m.get('cecelia') or ''
        gorg = m.get('gorgon') or ''
        bor = m.get('borgus') or ''
        smoke = {'url': SMOKE_URL, 'keys': sorted(m.keys()),
                 'cecelia_prefix': cec[:4], 'cecelia_len': len(cec),
                 'gorgon_len': len(gorg), 'borgus_len': len(bor),
                 'cecelia_2': cec.startswith('2_'), 'gorgon_nonempty': len(gorg) > 100,
                 'borgus_32hex': bool(re.fullmatch(r'[0-9a-f]{32}', bor))}
        # canon对拍: 无query GET → md5('')
        try:
            qf = des3_dec(m['QDSign'].replace(' ', ''), KS, QDSIGN_IV).split('|')
            smoke['qdsign_f7'] = qf[7]
            smoke['canon_md5_empty'] = md5('')
            smoke['canon_match_empty'] = qf[7] == md5('')
            smoke['qdsign_f2_uid'] = qf[2]
            smoke['qdsign_f5_av'] = qf[5]
        except Exception as e:
            smoke['qdsign_decode_err'] = str(e)[:120]
        # 设备档案(供合成头对照链)
        try:
            qdi_f = des3_dec(m['QDInfo'], K + K[:8], QDINFO_IV).split('|')
            smoke['qdinfo_fields_n'] = len(qdi_f)
        except Exception as e:
            qdi_f = []
            smoke['qdinfo_decode_err'] = str(e)[:120]
        smoke['ok'] = bool(smoke.get('cecelia_2') and smoke.get('gorgon_nonempty') and smoke.get('borgus_32hex'))
        L('[SMOKE] %s' % json.dumps(smoke, ensure_ascii=False))
        SUMMARY['smoke'] = smoke
        json.dump(smoke, open(EVID_DIR + '/smoke.json', 'w'), ensure_ascii=False, indent=1)
        if not smoke['ok']:
            L('[SMOKE] oracle直调头不完整 — 如实报告并诊断: cecelia=%r gorgon=%r borgus=%r (可能需更久等待/str2签名问题, 对照oracle.log自然[GETH]对)' % (cec[:8], gorg[:8], bor[:8]))
    except Exception as e:
        L('[SMOKE] oracle直调失败: %s' % scrub(str(e))[:300])
        SUMMARY['smoke'] = {'error': scrub(str(e))[:300]}

    dev = {}
    try:
        m0 = oracle.geth(SMOKE_URL, 'GET', None)
        qdi_f = des3_dec(m0['QDInfo'], K + K[:8], QDINFO_IV).split('|')
        qf = des3_dec(m0['QDSign'].replace(' ', ''), KS, QDSIGN_IV).split('|')
        dev = {'qdinfo_fields': qdi_f, 'androidid': qdi_f[0], 'appver': qf[5], 'vcode': qdi_f[8],
               'qimei36': qdi_f[14] if len(qdi_f) > 14 else '', 'ua': m0.get('User-Agent', ''),
               'cookie_template': m0.get('Cookie', '')}
        L('[DEV] oracle设备档案: androidid=%s model=%s vcode=%s qimei36=%s' % (qdi_f[0], qdi_f[7], qdi_f[8], qdi_f[14][:16] + '…'))
        SUMMARY['device'] = {'androidid': qdi_f[0], 'model': qdi_f[7], 'vcode': qdi_f[8],
                             'qimei36': qdi_f[14], 'ua': dev['ua']}
    except Exception as e:
        L('[DEV] 设备档案提取失败: %s — 合成头对照链将退化' % scrub(str(e))[:200])

    # 3. 真头终判链
    if dev:
        L('════ 真头终判链 (oracle全套真风控头) ════')
        steps = build_steps('0')
        SUMMARY['real'] = run_chain('real', oracle, sess, steps, real_header_builder(oracle, sess), dev)
        # tips响应里提taskId重跑rec/reward? 链内已按'0'跑 — 用tips响应提取的tid补一发reward(若tid非0)
        try:
            tips_raw = next((r['response'] for r in SUMMARY['real'] if r.get('step') == 'tips'), '')
            tid = extract_tid(tips_raw)
            if tid != '0':
                L('[TID] tips响应提取taskId=%s ≠ 0 — 用真taskId补跑rec+reward' % tid)
                sub = build_steps(tid)[3:5]
                SUMMARY['real'].extend(run_chain('real', oracle, sess, sub, real_header_builder(oracle, sess), dev))
        except Exception as e:
            L('[TID] %s' % scrub(str(e))[:150])

        # 4. 合成头对照链 (borgus_gen标准形态, 无cecelia/gorgon)
        L('════ 合成头对照链 (纯协议合成头) ════')
        SUMMARY['synth'] = run_chain('synth', oracle, sess, build_steps('0'),
                                     synth_header_builder(sess, dev), dev)
        try:
            tips_raw = next((r['response'] for r in SUMMARY['synth'] if r.get('step') == 'tips'), '')
            tid = extract_tid(tips_raw)
            if tid != '0':
                sub = build_steps(tid)[3:5]
                SUMMARY['synth'].extend(run_chain('synth', oracle, sess, sub,
                                                  synth_header_builder(sess, dev), dev))
        except Exception:
            pass

        # 5. 条件诊断: 真头reward≠0 → verbatim oracle QDSign(uid=0)再发一发reward
        real_reward = [r for r in SUMMARY['real'] if r.get('step') in ('reward',)]
        if real_reward and real_reward[-1].get('Result') not in (0, '0'):
            L('[DIAG] 真头reward≠0 — 追加verbatim-QDSign(uid=0)诊断发')
            try:
                def vb_build(url, method, body):
                    m = oracle.geth(url, method, body)
                    now_ms = int(time.time() * 1000)
                    h = {'User-Agent': m.get('User-Agent', ''), 'Accept-Encoding': 'gzip',
                         'Connection': 'Keep-Alive',
                         'QDInfo': patch_qdinfo(m['QDInfo'], sess['guid'], now_ms),
                         'tstamp': m.get('tstamp', str(now_ms)),
                         'QDSign': m['QDSign'],          # verbatim(含空格分块, uid=0)
                         'Cookie': patch_cookie(m['Cookie'], sess['guid'], sess['key'], sess['cmfu'])}
                    for k in ('cecelia', 'gorgon', 'borgus'):
                        if m.get(k):
                            h[k] = m[k]
                    return h
                sub = build_steps('0')[4:5]
                SUMMARY['diag'] = run_chain('diag', oracle, sess, sub, vb_build, dev)
            except Exception as e:
                L('[DIAG] err %s' % scrub(str(e))[:200])

    # 6. sn两形态样本提取
    sn_pairs = []
    try:
        cur = None
        for line in open(ORACLE_LOG, encoding='utf-8', errors='replace'):
            if line.startswith('[SNIN]'):
                cur = {'in': line.strip()}
            elif line.startswith('[SNOUT]') and cur is not None:
                cur['out'] = line.strip()
                sn_pairs.append(cur); cur = None
    except Exception as e:
        L('[SN] 读取oracle.log失败: %s' % e)
    with open(EVID_DIR + '/sn_pairs.txt', 'w') as f:
        for p in sn_pairs:
            f.write(p.get('in', '') + '\n' + p.get('out', '') + '\n\n')
    SUMMARY['sn_pairs'] = len(sn_pairs)
    L('[SN] Fock.sn捕获 %d 对 (输入串原文=两形态ground truth):' % len(sn_pairs))
    for p in sn_pairs[:12]:
        L('  %s' % p.get('in', '')[:240])
        L('  %s' % p.get('out', '')[:120])

    stop.set()
    json.dump(SUMMARY, open(EVID_DIR + '/verdict_summary.json', 'w'), ensure_ascii=False, indent=1)

    # 7. 终判摘要
    L('════════ 终判摘要 ════════')
    L('smoke: %s' % json.dumps(SUMMARY.get('smoke', {}), ensure_ascii=False)[:300])
    for tag in ('real', 'synth', 'diag'):
        for r in SUMMARY.get(tag, []):
            L('%-5s %-12s Result=%s %s' % (tag, r.get('step'), r.get('Result', r.get('error', '?')), r.get('Message', '')))
    L('耗时 %ds; 证据 %s/; sn对 %d; oracle.log %s' % (time.time() - t_start, EVID_DIR, len(sn_pairs), ORACLE_LOG))
    return 0

if __name__ == '__main__':
    # 硬看门狗: 14分钟无论如何落summary退出(artifact照常上传)
    def _watchdog():
        time.sleep(840)
        try:
            SUMMARY['notes'].append('watchdog_timeout')
            json.dump(SUMMARY, open(EVID_DIR + '/verdict_summary.json', 'w'), ensure_ascii=False, indent=1)
        except Exception:
            pass
        os._exit(3)
    threading.Thread(target=_watchdog, daemon=True).start()
    sys.exit(main())
