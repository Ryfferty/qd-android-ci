#!/usr/bin/env python3
# qr_born_oracle.py — QR出生×oracle真头 终局实验链 (子代理H, 2026-10-14)
#
# 用法(runner上, 前置: redroid+q480 App已稳定启动, frida-server 14771已起且adb forward已通):
#   QD_BORN_MODE=full   QD_BORN_SESSION=<base64(JSON)> python3 ci/qr_born_oracle.py  # 真扫码(≥25min窗)
#   QD_BORN_MODE=verify ...  # 短窗验证: QR生成/轮询/过期重生成/超时退出 + 死号半真实验
#   环境变量: QD_QR_WAIT=<秒> 覆盖轮询窗口(默认 full=1500 / verify=300)
#
# 一次CI运行内完成: 活App当oracle → 协议链用oracle真头做QR出生 → 等用户扫码 →
#   出生即判 → 带标即领取 → 终判。用户扫码是唯一人工环节。
#
# 链路(出处逐条):
#   Phase 0-1 oracle attach + 等真头成熟(cecelia 2_+gorgon+borgus, 同oracle_verdict.py冒烟循环)
#             设备身份全部取自oracle活App(自洽——服务器在CI上见过这台设备活着的流量, 不用合成设备):
#             qimei36=oracle Cookie qid(退QDInfo f14), imei/androidid=QDInfo f0, model=f7, UA=oracle UA
#   Phase 2 QR出生: POST ptlogin.yuewen.com/sdkv2/scanQRCode (SDK表单+3DES签名+ibex,
#             头按app_qrlogin_chain.py原样——ptlogin非argus族, 该形态当年成功出生过)
#             → sessionKey+image → qr.png+qr_url.txt+[QR_URL]echo到run log(ASCII QR也进log, 可直接扫)
#   Phase 3 轮询 POST sdkv2/scanQRCodeLogin: 0/1继续轮询; 会话过期(scanStatus=3/code!=0)→
#             重新调scanQRCode换新QR(刷新artifact+log); scanStatus=5→ywGuid/ywKey
#   Phase 4 user/login (bravev6 b.e表单: {appId:12,areaId:30,ywguid,ywkey,loginfrom:0,
#             fromSource:1002138,isFirstRegister:false} — app_qrlogin_chain.py ⑤ 同款):
#             头全走oracle: rpc.geth(url,'POST',form表单)FormBody姿势(RequestBody.create会退化
#             四字段borgus, F run38555894670实证) + QDSign=python重签md5(canon(body))
#             (getH的QDSign只签query不签body, F run38548441945实证) + QDInfo f12刷新 +
#             Cookie=oracle Cookie覆写ywguid/ywkey
#   Phase 5 出生即判: client/getconf(POST, IsFreshman/IsNewDevice) + limitfreepopup +
#             safegetcontent(bookId=1040025277/chapterId=794290414两步getkey→content) +
#             tips→真taskId + recFreshmanTask
#   Phase 6 rec Result=0(带标) → 立即claim v2/freshman/task/rewardFreshmanTask
#             (FormBody 10字段, oracle_verdict.py reward_body同款) — oracle真头
#   Phase 7 终判: claim响应原文 + claim后limitfree/getconf/safegetcontent对比 → evidence
#   verify模式加料: 旧sessionkey(2026-10-13码)注入验证过期重生成分支;
#             半真实验: 死号900074388329(ywGuid/ywKey在secret QD_BORN_SESSION)走
#             user/login→判→rec→claim全链, 预期claim=-10021但login/rec管道通 —
#             证明扫码后半段(user/login→判→领)的代码+头注入不是全未测
#
# 凭据纪律: ywKey/CmfuToken/UserInfo-token只在runner内存(SECRETS scrub); job log只打
#   Result/Message/IsFreshman等业务字段; evidence JSON落盘前scrub; 号一次性(出生→判→领同run)
# 超时: full模式25min无人扫码→正常结束(artifact留QR样张+链路日志); 硬看门狗2400s兜底
import os, sys, json, time, base64, gzip, re, subprocess, threading, collections
import urllib.request, urllib.parse, urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'ci'))
from ibex_gen import gen_ibex                 # SDK表单ibex(nib三件套, qidian_auto/ci同源拷贝)
from Crypto.Cipher import DES3

HOST = 'https://druidv6.if.qidian.com'
LOGIN_HOST = 'https://bravev6.if.qidian.com'     # b.e反编译定案+app_qrlogin_chain出生实证
PTLOGIN = 'https://ptlogin.yuewen.com'
ADB_DEV = 'localhost:5555'
APP = 'com.qidian.QDReader'
HOOK = os.path.join(ROOT, 'hook_oracle.js')
EVID_DIR = '/tmp/qrborn'
ORACLE_LOG = '/tmp/oracle.log'
SMOKE_URL = HOST + '/argus/api/v1/young/getconf'

AV, VC, SRC = "7.9.480", "1996", "1002138"
K3, IV3 = b"sewxf03hhz3ew9qcCXMHiDMk", b"sh331nt1"      # SDK表单signature 3DES
K = b'0821CAAD409B8402'                              # QDInfo 3DES key (k + k[:8])
KS = bytes.fromhex('7B3164596771452968392C5229684B71456376345D6B5B68')  # QDSign 3DES key
QDINFO_IV = b'\x00' * 8
QDSIGN_IV = b'01234567'
F189 = 'f189adc92b816b3e9da29ea304d4a7e4'

BOOK_ID, CHAPTER_ID = '1040025277', '794290414'       # safegetcontent真实书籍/章节
STALE_SK = 'qr7c57c73ad51444e9abca0d90ed627af9'       # 2026-10-13旧码, verify模式过期分支注入用

MODE = (os.environ.get('QD_BORN_MODE') or 'full').strip().lower()
_env_wait = (os.environ.get('QD_QR_WAIT') or '').strip()
QR_WAIT = int(_env_wait) if _env_wait.isdigit() and int(_env_wait) > 0 else \
    (1500 if MODE == 'full' else 300)

SECRETS = []          # 待脱敏值(ywKey/CmfuToken/UserInfo-token)
SUMMARY = {'mode': MODE, 'qr_wait': QR_WAIT, 'notes': [], 'qr': {}, 'born': [], 'halfreal': []}

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
    p = 8 - len(plain) % 8
    ct = DES3.new(key, DES3.MODE_CBC, iv).encrypt(plain + bytes([p]) * p)
    return base64.b64encode(ct).decode()

def des3_dec(b64s, key, iv):
    from Crypto.Cipher import DES3
    ct = base64.b64decode(b64s)
    pt = DES3.new(key, DES3.MODE_CBC, iv).decrypt(ct)
    if pt and 1 <= pt[-1] <= 16 and pt[-pt[-1]:] == bytes([pt[-1]]) * pt[-1]:
        pt = pt[:-pt[-1]]
    return pt.decode('utf-8', 'replace')

# ───────────────────────── Oracle (frida RPC, 同oracle_verdict.py) ─────────────────────────
class Oracle:
    def __init__(self, host='127.0.0.1:14771'):
        import frida
        self.frida = frida
        self.host = host
        self.pid = None
        self.script = None
        self.exp = None
        self.logf = open(ORACLE_LOG, 'a')
        self.recent = collections.deque(maxlen=1000)
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

    def ensure_app(self):
        pid = self.pidof()
        if pid:
            return pid
        L('[ORACLE] App死亡 — force-stop清僵尸后重启')
        try:
            self.adb('shell', 'am', 'force-stop', APP, timeout=10)
        except Exception:
            pass
        time.sleep(2)
        try:
            self.adb('shell', 'am', 'start', '-n', APP + '/.ui.activity.SplashActivity', timeout=10)
        except Exception:
            pass
        for _ in range(12):
            time.sleep(5)
            pid = self.pidof()
            if pid:
                L('[ORACLE] App已重启 pid=%s' % pid)
                return pid
        return None

    def restart_frida_server(self):
        """fs-srv僵死(App ANR死后attach超时) → pkill -9硬杀+重启+重forward
        (38560808112实证: 单次pkill不够, 僵尸fs-srv占端口时新fs-srv起不来→attach螺旋失败)"""
        L('[ORACLE] 重启frida-server(硬)...')
        try:
            self.adb('shell', 'pkill -9 -f fs-srv', timeout=8)
        except Exception:
            pass
        time.sleep(3)
        try:
            self.adb('shell', 'setsid /data/local/tmp/fs-srv -D -l 127.0.0.1:14771 >/dev/null 2>&1 &', timeout=8)
        except Exception:
            pass
        time.sleep(12)
        try:
            r = self.adb('shell', 'pidof', 'fs-srv', timeout=8)
            fs_pid = (r.stdout or '').strip()
            L('[ORACLE] fs-srv pid=%s' % (fs_pid or '(未起!)'))
        except Exception:
            pass
        try:
            self.adb('forward', 'tcp:14771', 'tcp:14771', timeout=8)
        except Exception:
            pass

    def attach(self):
        fs_restarts = 0
        for attempt in range(8):
            try:
                pid = self.pidof()
                if not pid:
                    pid = self.ensure_app()
                if not pid:
                    L('[ORACLE] no pid (attempt %d)' % attempt); time.sleep(5); continue
                dev = self.frida.get_device_manager().add_remote_device(self.host)
                self.session = dev.attach(int(pid))
                with open(HOOK) as f:
                    src = f.read()
                self.script = self.session.create_script(src)
                self.script.on('message', self._on_msg)
                try:
                    self.script.set_log_handler(self._on_log)   # frida console.log进oracle.log
                except Exception as e:
                    L('[ORACLE] set_log_handler不可用: %s' % str(e)[:80])
                self.script.load()
                self.exp = getattr(self.script, 'exports_sync', None) or self.script.exports
                self.pid = pid
                L('[ORACLE] attached pid=%s (ping=%s)' % (pid, self.exp.ping()))
                return True
            except Exception as e:
                L('[ORACLE] attach err (attempt %d): %s' % (attempt, scrub(str(e))[:200]))
                if attempt % 2 == 1 and fs_restarts < 4:   # ★每2次失败硬重启fs-srv(38560808112教训)
                    self.restart_frida_server()
                    fs_restarts += 1
                time.sleep(6)
        return False

    def _on_log(self, level, message):
        self._emit(str(message))

    def _on_msg(self, message, data):
        try:
            if message.get('type') == 'error':
                self._emit('[SCRIPT_ERR] ' + str(message.get('description'))[:400])
            else:
                self._emit('[MSG] ' + json.dumps(message)[:300])
        except Exception:
            pass

    def _emit(self, line):
        try:
            self.logf.write(line + '\n'); self.logf.flush()
            self.recent.append(line)
        except Exception:
            pass

    def stat(self):
        return self.exp.stat()

    def setquiet(self, q):
        """hook静默开关(门控重dump降App主线程负载 — 38563552056 ANR根因); 旧hook无此export则忽略"""
        try:
            return self._call_rpc('setquiet', bool(q))
        except Exception as e:
            L('[ORACLE] setquiet不可用(旧hook?): %s' % str(e)[:80])
            return None

    def geth(self, url, method, body):
        """body: None(GET) / str(POST表单体原文, 可为'')。返回oracle Map dict。"""
        r = self._call_rpc('geth', url, method, body)
        if r is None or r.get('__err'):
            raise RuntimeError('rpc.geth err: %s' % (r or {}).get('__err'))
        return r.get('map') or {}

    def geth_retry(self, url, method, body):
        try:
            return self.geth(url, method, body)
        except Exception as e:
            L('[ORACLE] geth失败(%s) — 重挂后重试' % scrub(str(e))[:120])
            if self.attach():
                return self.geth(url, method, body)
            raise

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

# ───────────────────────── UI推进线程 (oracle_verdict.py v3 + H静默模式) ─────────────────────────
# ★38560808112实证: 真头成熟后battery乱点会点开主页面重负载→MainGroupActivity ANR→App死→
#   fs-srv僵死→attach螺旋失败。QR等待期设QUIET: 只守前台(非qd包→BACK), 不点不滑。
TAPS = [(360, 580), (360, 1100), (180, 1100), (360, 350), (540, 1100), None,
        (360, 700), (360, 350), (360, 580), (360, 1100)]
SKIP_IDS = ('tvSkip', 'ivSkip', 'btnAgree')
SKIP_TEXTS = ('跳过', '立即体验', '开始使用', '同意并继续')
QUIET = threading.Event()

def _find_bounds(xml, id_frag=None, text=None):
    if id_frag:
        pat = r'resource-id="[^"]*%s[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % re.escape(id_frag)
    else:
        pat = r'text="[^"]*%s[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % re.escape(text)
    for m in re.finditer(pat, xml):
        x1, y1, x2, y2 = map(int, m.groups())
        return (x1 + x2) // 2, (y1 + y2) // 2
    return None

def _foreground(oracle):
    try:
        r = oracle.adb('shell', 'dumpsys', 'window', timeout=12)
        for line in (r.stdout or '').splitlines():
            if 'mCurrentFocus' in line or 'mFocusedApp' in line:
                return line.strip()[:200]
        return '?'
    except Exception:
        return '?'

def ui_thread(stop, oracle):
    ti = 0
    n = 0
    while not stop.is_set():
        n += 1
        act = ''
        try:
            fg = _foreground(oracle)
            if fg != '?' and 'com.qidian.QDReader' not in fg and 'mCurrentFocus' in fg:
                oracle.adb('shell', 'input', 'keyevent', '4', timeout=8)
                act = 'BACK(fg=%s)' % fg.split('u0')[0].strip()[-40:]
            elif QUIET.is_set():
                act = 'quiet(只守前台, 不点不滑)'
            else:
                oracle.adb('shell', 'uiautomator', 'dump', '/sdcard/u.xml', timeout=15)
                r = oracle.adb('shell', 'cat', '/sdcard/u.xml', timeout=15)
                xml = r.stdout or ''
                if len(xml) > 200:
                    xy = None
                    for i in SKIP_IDS:
                        xy = _find_bounds(xml, i)
                        if xy:
                            break
                    if not xy:
                        for t in SKIP_TEXTS:
                            xy = _find_bounds(xml, text=t)
                            if xy:
                                break
                    if xy:
                        act = 'tap(%d,%d)' % xy
                        oracle.adb('shell', 'input', 'tap', str(xy[0]), str(xy[1]))
                    else:
                        t = TAPS[ti % len(TAPS)]; ti += 1
                        if t is None:
                            act = 'hswipe(轮播)'
                            oracle.adb('shell', 'input', 'swipe', '680', '600', '60', '600', '300')
                        else:
                            act = 'battery(%d,%d)' % t
                            oracle.adb('shell', 'input', 'tap', str(t[0]), str(t[1]))
                else:
                    act = 'dump空(%d)' % len(xml)
        except Exception as e:
            act = 'err:%s' % str(e)[:40]
        if n % 8 == 1:
            L('[UI] cycle#%d %s' % (n, act))
        stop.wait(11)

# ───────────────────────── 头构造与patch (同oracle_verdict.py) ─────────────────────────
def patch_qdinfo(orig_b64, f11, now_ms):
    f = des3_dec(orig_b64, K + K[:8], QDINFO_IV).split('|')
    if len(f) < 13:
        raise RuntimeError('QDInfo字段数=%d(<13)' % len(f))
    f[11] = str(f11)     # f11 = uid (登录时刻=0, 登录后=UserId)
    f[12] = str(now_ms)  # f12 = 时间戳ms
    return des3_enc_b64('|'.join(f), K + K[:8], QDINFO_IV)

def patch_cookie(orig_ck, guid, key, cmfu):
    ck = orig_ck
    ck = re.sub(r'ywkey=;', 'ywkey=%s;' % key, ck, count=1)
    ck = re.sub(r'ywguid=;', 'ywguid=%s;' % guid, ck, count=1)
    if 'ywguid=%s' % guid not in ck:   # oracle Cookie缺槽位时兜底插入
        ck = ck.rstrip() + ' ywguid=%s; ywkey=%s; ' % (guid, key)
    if cmfu and 'cmfuToken=' not in ck:
        ck = ck.rstrip() + ' cmfuToken=%s; ' % cmfu
    return ck

def canon_from_params(params):
    """QDSign第8段md5输入 — 小写key排序kv串(GET=query参数/POST=form参数)。
    口径: qdsign_gen.canon语料135/136 + borgus v2公式(sorted(小写key)) +
    app_qrlogin_chain出生实测(safegetcontent含Key/bookId混合大小写, 小写排序→业务响应非-3)。
    (F run38548441945实证: getH的QDSign只签query, POST body由python重签md5(canon))"""
    if not params:
        return ''
    return '&'.join('%s=%s' % (str(k).lower(), v) for k, v in
                    sorted(params.items(), key=lambda kv: str(kv[0]).lower()))

def build_qdsign(ts, guid, androidid, appver, canon_str):
    return des3_enc_b64('|'.join(['Rv1rPTnczce', str(ts), guid, androidid, '1', appver, '1',
                                  md5(canon_str), F189]), KS, QDSIGN_IV)

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

def save_evid(name, entry):
    entry = json.loads(scrub(json.dumps(entry, ensure_ascii=False)))
    with open('%s/%s.json' % (EVID_DIR, name), 'w') as f:
        json.dump(entry, f, ensure_ascii=False, indent=1)

# ───────────────────────── argus请求: oracle真头 (F real_header_builder模式) ─────────────────────────
def argus_call(oracle, dev, sess, name, method, url, params=None, form=None,
               raw_body=None, phase='born'):
    """oracle真头argus请求。
    sess: {'uid'(QDSign/QDInfo f11口径), 'ywGuid'(Cookie ywguid), 'ywKey', 'cmfu'}
    GET→params dict; POST→form dict; raw_body=POST原文(canon仍由form dict算)。
    头: oracle Map(UA/QDInfo/tstamp/Cookie/cecelia/gorgon/borgus verbatim) + python QDSign重签
        (md5(canon(params_or_form))) + QDInfo f11/f12 patch + Cookie ywkey/ywguid/QDInfo覆写"""
    if method == 'GET':
        if params:
            full_url = url + '?' + urllib.parse.urlencode(params)
        else:
            full_url = url
        body_str, canon = None, canon_from_params(params)
    else:
        body_str = raw_body if raw_body is not None else (
            urllib.parse.urlencode(form) if form is not None else '')
        canon = canon_from_params(form if form is not None else {})
        full_url = url
    entry = {'phase': phase, 'step': name, 'method': method, 'url': full_url,
             'form': form or params or ''}
    try:
        m = oracle.geth_retry(full_url, method, body_str)
        ts = m.get('tstamp') or str(int(time.time() * 1000))
        now_ms = int(time.time() * 1000)
        qdi = patch_qdinfo(m['QDInfo'], sess.get('uid', '0'), now_ms)
        qds = build_qdsign(ts, sess.get('uid', '0'), dev['androidid'], dev['appver'], canon)
        ck = patch_cookie(m['Cookie'], sess.get('ywGuid', ''), sess.get('ywKey', ''), sess.get('cmfu', ''))
        if 'QDInfo=' in ck:   # cookie里的QDInfo槽位同步成patch后值(app_qrlogin_chain同款姿势)
            ck = re.sub(r'QDInfo=[^;]*', 'QDInfo=%s' % qdi, ck, count=1)
        h = {'User-Agent': m.get('User-Agent', dev['ua']),
             'Accept-Encoding': 'gzip',
             'Connection': 'Keep-Alive',
             'QDInfo': qdi,
             'tstamp': ts,
             'QDSign': qds,
             'Cookie': ck}
        for k in ('cecelia', 'gorgon', 'borgus'):   # ★全套真风控头 verbatim
            if m.get(k):
                h[k] = m[k]
        if 'gorgon' not in h:   # ★App重启后风控SDK未再激活时gorgon空 → GORGON_480常量兜底
            try:                #   (F实证: 活App现算值==GORGON_480逐字节相同, 构建级常量)
                from qdsign_gen import GORGON_480
                h['gorgon'] = GORGON_480
                entry['gorgon_fallback_const'] = True
            except Exception:
                pass
        entry['headers_masked'] = mask_headers(h)
        entry['oracle_map_keys'] = sorted(m.keys())
    except Exception as e:
        entry['error'] = 'header build: ' + scrub(str(e))[:300]
        L('[%s %-12s] HDR_ERR %s' % (phase, name, entry['error']))
        save_evid('%s_%s' % (phase, name), entry)
        return entry
    body_bytes = body_str.encode() if isinstance(body_str, str) else None
    raw, code = send(full_url, method, body_bytes, h)
    entry['http_code'] = code
    text = raw.decode('utf-8', 'replace')
    entry['response'] = text[:200000]   # ★getconf响应>20KB, 2万字符截断会砍JSON致Freshman解析失败(38563552056)
    try:
        j = json.loads(text)
        entry['Result'] = j.get('Result') if 'Result' in j else j.get('code')
        entry['Message'] = str(j.get('Message', ''))[:60]
        L('[%s %-12s] HTTP %s Result=%s %s' % (phase, name, code, entry['Result'], entry['Message']))
    except Exception:
        entry['Result'] = 'HTTP%d' % code
        L('[%s %-12s] HTTP %s 非业务: %s' % (phase, name, code, text[:90].replace('\n', ' ')))
    save_evid('%s_%s' % (phase, name), entry)
    time.sleep(2.5)
    return entry

# ───────────────────────── ptlogin SDK表单 (app_qrlogin_chain.py 原样) ─────────────────────────
def sdk_form(dev, extra=None):
    ts = int(time.time())
    sig_in = f"{dev['imei']}|{dev['qimei16']}|{ts}|{dev['qimei36']}"
    pad = 8 - len(sig_in) % 8
    sig = base64.b64encode(DES3.new(K3, DES3.MODE_CBC, IV3).encrypt(
        sig_in.encode() + bytes([pad]) * pad)).decode()
    d = {'appid': '12', 'areaid': '30', 'auto': '1', 'autotime': '30',
         'source': SRC, 'ticket': '0',
         'imei': dev['imei'], 'qimei': dev['qimei16'], 'qimei36': dev['qimei36'],
         'osversion': 'Android11_7.9.480_1996', 'version': VC, 'sdkversion': '401',
         'devicename': dev.get('model', 'redroid11_arm64'),
         'devicetype': f"{dev.get('brand', 'redroid')}_{dev.get('model', 'redroid11_arm64')}",
         'ibex': gen_ibex(qimei16=dev['qimei16'], qimei36=dev['qimei36'],
                          model=dev.get('model'), brand=dev.get('brand'),
                          board=dev.get('board'), manufact=dev.get('manufact')),
         'signature': sig,
         'returnurl': 'http://www.qidian.com', 'format': 'json', 'referer': 'http://android.qidian.com'}
    if extra:
        d.update(extra)
    return d

SDK_UA = f'Mozilla/mobile QDReaderAndroid/{AV}/{VC}/{SRC}'
SDK_HEADERS = {'User-Agent': SDK_UA, 'Referer': 'http://android.qidian.com'}

def ptlogin_json(path, form):
    body = urllib.parse.urlencode(form).encode()
    h = dict(SDK_HEADERS)
    h['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(PTLOGIN + path, data=body, headers=h)
    r = urllib.request.urlopen(req, timeout=30)
    raw = r.read()
    try:
        raw = gzip.decompress(raw)
    except Exception:
        pass
    return json.loads(raw)

def scan_qr_create(dev):
    return ptlogin_json('/sdkv2/scanQRCode', sdk_form(dev))

def scan_qr_poll(dev, sk):
    return ptlogin_json('/sdkv2/scanQRCodeLogin', sdk_form(dev, {'sessionKey': sk}))

# ───────────────────────── QR产物: png+url+ascii (转交机制) ─────────────────────────
def decode_png_url(path):
    """pyzbar解码server PNG → 权威QR内容URL (失败返回None→用sessionKey重构)"""
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
        r = decode(Image.open(path))
        return r[0].data.decode() if r else None
    except Exception:
        return None

def qr_ascii(url):
    try:
        import qrcode, io
        qr = qrcode.QRCode(border=2)
        qr.add_data(url)
        qr.make(fit=True)
        buf = io.StringIO()
        qr.print_ascii(out=buf, tty=False)
        return buf.getvalue()
    except Exception as e:
        return '(ASCII QR渲染失败: %s)\n' % str(e)[:80]

def gen_qr(dev, n):
    """出码: scanQRCode → server PNG + 本地渲染QR + [QR_URL]echo(实时转交通道=run log)"""
    j = scan_qr_create(dev)
    if j.get('code') != 0 or not (j.get('data') or {}).get('sessionKey'):
        L('[QR] scanQRCode失败: %s' % json.dumps(j, ensure_ascii=False)[:250])
        return None
    d = j['data']
    sk = d['sessionKey']
    server_png = None
    if d.get('image'):
        try:
            server_png = base64.b64decode(d['image'].split(',', 1)[1])
            open('%s/qr_server.png' % EVID_DIR, 'wb').write(server_png)
        except Exception as e:
            L('[QR] server image解码失败: %s' % e)
    recon = 'https://passport.yuewen.com/plus/qrlogin?sessionkey=%s&appid=12&areaid=30' % sk
    url = (decode_png_url('%s/qr_server.png' % EVID_DIR) if server_png else None) or recon
    url_src = 'decoded(server png)' if url != recon else 'reconstructed(sessionkey)'
    # 固定artifact: qr.png(优先server原图=真App同款; 无图时本地qrcode渲染)
    try:
        if server_png:
            open('%s/qr.png' % EVID_DIR, 'wb').write(server_png)
        else:
            import qrcode
            qrcode.make(url).save('%s/qr.png' % EVID_DIR)
    except Exception as e:
        L('[QR] qr.png写失败: %s' % e)
    try:
        open('%s/qr_url.txt' % EVID_DIR, 'w').write(url + '\n')
        with open('%s/qr_history.txt' % EVID_DIR, 'a') as f:
            f.write('%s #%d %s\n' % (time.strftime('%H:%M:%S'), n, sk))
    except Exception:
        pass
    L('[QR] ★出码成功 #%d sessionKey=%s (%s)' % (n, sk, url_src))
    L('[QR_URL] %s' % url)                       # ← 实时取QR给用户: gh run view --log | grep QR_URL
    L('[QR] ASCII二维码(log内直接扫):\n' + qr_ascii(url))
    return {'sessionKey': sk, 'url': url, 'url_src': url_src, 'gen_ts': time.time()}

# ───────────────────────── 设备档案(oracle) ─────────────────────────
def extract_dev(m):
    qf = des3_dec(m['QDSign'].replace(' ', ''), KS, QDSIGN_IV).split('|')
    qdi_f = des3_dec(m['QDInfo'], K + K[:8], QDINFO_IV).split('|')
    ck = m.get('Cookie', '')
    qm = re.search(r'qid=([0-9a-f]{36})', ck)
    qimei36 = qm.group(1) if qm else ''
    if not qimei36 and len(qdi_f) > 14 and re.fullmatch(r'[0-9a-f]{36}', qdi_f[14] or ''):
        qimei36 = qdi_f[14]
    return {'qdinfo_fields': qdi_f, 'imei': qdi_f[0], 'androidid': qdi_f[0],
            'model': qdi_f[7], 'appver': qf[5], 'vcode': qdi_f[8],
            'qimei36': qimei36, 'qimei16': qimei36[:16], 'ua': m.get('User-Agent', ''),
            'cookie_template': ck}

def getprops(oracle):
    out = {}
    for p in ('ro.product.brand', 'ro.product.model', 'ro.product.manufacturer',
              'ro.product.board', 'ro.product.cpu.abi'):
        try:
            r = oracle.adb('shell', 'getprop', p, timeout=10)
            out[p] = (r.stdout or '').strip()
        except Exception:
            out[p] = ''
    return out

def wait_headers_ready(oracle, timeout_s, label='WAIT'):
    """等真头成熟: cecelia 2_ + gorgon>100 + borgus 32hex + qimei36非空 (oracle_verdict冒烟循环)"""
    t0 = time.time()
    last_log = 0
    while time.time() - t0 < timeout_s:
        try:
            m = oracle.geth(SMOKE_URL, 'GET', None)
            cec = m.get('cecelia') or ''
            gorg = m.get('gorgon') or ''
            bor = m.get('borgus') or ''
            qm = re.search(r'qid=([0-9a-f]{36})', m.get('Cookie', ''))
            ok = cec.startswith('2_') and len(gorg) > 100 and \
                bool(re.fullmatch(r'[0-9a-f]{32}', bor)) and bool(qm)
            if ok:
                L('[%s] 真头成熟 ✓ t+%ds (cecelia 2_%dch, gorgon %dch, borgus 32hex, qid在)' % (
                    label, time.time() - t0, len(cec), len(gorg)))
                return m
            if time.time() - last_log > 30:
                last_log = time.time()
                L('[%s] t+%ds 未齐: cecelia=%s gorgon=%d borgus=%s qid=%s' % (
                    label, time.time() - t0, cec[:4] or '无', len(gorg),
                    bor[:8] or '无', '在' if qm else '无'))
        except Exception as e:
            L('[%s] 冒烟异常: %s — 重挂' % (label, scrub(str(e))[:150]))
            if not oracle.attach():
                time.sleep(10)
        time.sleep(8)
    L('[%s] %ds内真头未全齐 — 继续跑链并如实报告(头以实际拿到的为准)' % (label, timeout_s))
    return None

# ───────────────────────── 会话(secret只在内存, 同oracle_verdict.load_session) ─────────────────────────
def load_dead_session():
    global SECRETS
    raw = os.environ.get('QD_BORN_SESSION') or ''
    if not raw:
        return None
    try:
        d = json.loads(base64.b64decode(raw))
    except Exception as e:
        L('[HALF] QD_BORN_SESSION解码失败: %s' % str(e)[:80])
        return None
    if isinstance(d.get('resp'), dict):
        flat = dict(d['resp'].get('data', {}))
        flat.update({k: v for k, v in d.items() if k != 'resp'})
        d = flat
    guid = str(d.get('ywGuid') or d.get('ywguid') or '')
    key = str(d.get('ywKey') or d.get('ywkey') or '')
    cmfu = str(d.get('CmfuToken') or d.get('cmfuToken') or '')
    if not guid or not key:
        L('[HALF] secret无ywGuid/ywKey (keys=%s)' % list(d.keys()))
        return None
    SECRETS.extend([key, cmfu])
    L('[HALF] 死号会话装载: guid=%s ywKey=<len %d> CmfuToken=<len %d>' % (guid, len(key), len(cmfu)))
    return {'guid': guid, 'key': key, 'cmfu': cmfu}

# ───────────────────────── 出生链(扫码后半段) ─────────────────────────
def do_user_login(oracle, dev, ywguid, ywkey, phase='born'):
    """user/login: b.e表单(bravev6), oracle真头FormBody姿势, 登录时刻匿名(f11=0/uid=0)"""
    sess = {'uid': '0', 'ywGuid': ywguid, 'ywKey': ywkey, 'cmfu': ''}
    e = argus_call(oracle, dev, sess, 'login', 'POST',
                   LOGIN_HOST + '/argus/api/v2/user/login',
                   form={'appId': '12', 'areaId': '30', 'ywguid': ywguid, 'ywkey': ywkey,
                         'loginfrom': '0', 'fromSource': SRC, 'isFirstRegister': 'false'},
                   phase=phase)
    out = {'entry': e}
    try:
        j = json.loads(e.get('response', '') or '{}')
        d = j.get('Data', {}) or {}
        lr = d.get('LoginResult', {}) or {}
        out['Result'] = j.get('Result')
        out['UserId'] = str(d.get('UserId', ''))
        out['IsNewUser'] = d.get('IsNewUser')
        out['RegisterTime'] = d.get('RegisterTime')
        out['cmfu'] = lr.get('CmfuToken', '')
        userinfo = str(lr.get('UserInfo', ''))
        out['userinfo_token'] = userinfo.split('|')[2] if userinfo.count('|') >= 3 else ''
    except Exception as ex:
        out['parse_err'] = str(ex)[:120]
    for k in ('cmfu', 'userinfo_token'):
        if out.get(k):
            SECRETS.append(out[k])
    L('[LOGIN] Result=%s UserId=%s IsNewUser=%s RegisterTime=%s CmfuToken=%s' % (
        out.get('Result'), out.get('UserId'), out.get('IsNewUser'), out.get('RegisterTime'),
        bool(out.get('cmfu'))))
    return out

def run_born_chain(oracle, dev, ywguid, ywkey, phase='born'):
    """扫码授权后: user/login → 出生即判 → 带标即claim → 终判复查。返回summary dict"""
    chain = {'phase': phase, 'steps': []}
    # 0. 链路期恢复hook重dump(收sn/geth证据) + oracle真头确认成熟(等待期App可能死过, 先复活+重等)
    oracle.setquiet(False)
    wait_headers_ready(oracle, 180, label=phase.upper() + '-PRE')
    # 1. user/login
    login = do_user_login(oracle, dev, ywguid, ywkey, phase=phase)
    chain['login'] = {k: login.get(k) for k in ('Result', 'UserId', 'IsNewUser', 'RegisterTime')}
    chain['steps'].append('login')
    if login.get('Result') != 0 or not login.get('UserId'):
        L('[%s] user/login失败 — 出生链中止(如实报告)' % phase)
        chain['notes'] = 'login failed'
        return chain
    uid = login['UserId']
    sess = {'uid': uid, 'ywGuid': ywguid, 'ywKey': ywkey, 'cmfu': login.get('cmfu', '')}
    chain['sess_uid'] = uid
    # 2. 出生即判: getconf(Freshman) + limitfreepopup + safegetcontent + tips
    e1 = argus_call(oracle, dev, sess, 'getconf', 'POST', HOST + '/argus/api/v1/client/getconf',
                    form={'localLabels': '', 'gender': '0'}, phase=phase)
    try:
        fm = (json.loads(e1.get('response', '') or '{}').get('Data', {}) or {}).get('Freshman', {})
        chain['getconf_Freshman'] = {k: fm.get(k) for k in
                                     ('IsFreshman', 'ShowLimitFreePopup', 'IsNewDevice',
                                      'IsNewQimei', 'FreshmanVersion') if k in fm}
        L('[%s] getconf Freshman: %s' % (phase, json.dumps(chain['getconf_Freshman'])))
    except Exception as ex:
        chain['getconf_err'] = str(ex)[:100]
    chain['steps'].append('getconf')
    e2 = argus_call(oracle, dev, sess, 'limitfree', 'GET',
                    HOST + '/argus/api/v1/freshman/limitfreepopup', phase=phase)
    chain['limitfree_Result'] = e2.get('Result')
    chain['steps'].append('limitfree')
    # safegetcontent两步(getkey→content, 真实bookId/chapterId)
    key = ''
    try:
        key = str(((json.loads(
            argus_call(oracle, dev, sess, 'getkey', 'GET',
                       HOST + '/argus/api/v4/bookcontent/getkey',
                       params={'bookId': BOOK_ID, 'ui': '0'}, phase=phase).get('response', '') or '{}')
            .get('Data', {}) or {}).get('Key', '')))
    except Exception as ex:
        L('[%s] getkey解析失败: %s' % (phase, str(ex)[:80]))
    e3 = argus_call(oracle, dev, sess, 'safeget', 'GET',
                    HOST + '/argus/api/v2/bookcontent/safegetcontent',
                    params={'bookId': BOOK_ID, 'chapterId': CHAPTER_ID, 'Key': key, 'chapterPwd': ''}, phase=phase)
    chain['safeget_Result'] = e3.get('Result')
    chain['steps'] += ['getkey', 'safeget']
    # tips → 真taskId
    tid = '0'
    et = argus_call(oracle, dev, sess, 'tips', 'GET',
                    HOST + '/argus/api/v1/freshman/getreadingtaskprocesstips', phase=phase)
    for pat in (r'"taskId"\s*:\s*"(\d+)"', r'"TaskId"\s*:\s*"(\d+)"',
                r'"taskId"\s*:\s*(\d+)', r'"TaskId"\s*:\s*(\d+)'):
        mm = re.search(pat, et.get('response', '') or '')
        if mm:
            tid = mm.group(1)
            break
    chain['taskId'] = tid
    L('[%s] tips提取taskId=%s' % (phase, tid))
    chain['steps'].append('tips')
    # rec
    n0 = int(time.time() * 1000)
    er = argus_call(oracle, dev, sess, 'rec', 'POST',
                    HOST + '/argus/api/v1/freshman/task/recFreshmanTask',
                    form={'taskId': tid, 'startTime': str(n0), 'endTime': str(n0 + 30000)}, phase=phase)
    chain['rec_Result'] = er.get('Result')
    chain['steps'].append('rec')
    # 带标即claim (rec Result=0)
    if er.get('Result') == 0:
        ec = argus_call(oracle, dev, sess, 'claim', 'POST',
                        HOST + '/argus/api/v2/freshman/task/rewardFreshmanTask',
                        form={'taskId': tid, 'mileStone': '-1', 'sessionKey': '', 'banId': '0',
                              'captchaTicket': '', 'captchaRandStr': '', 'challenge': '',
                              'validate': '', 'seccode': ''}, phase=phase)
        chain['claim_Result'] = ec.get('Result')
        chain['claim_Message'] = ec.get('Message', '')
        chain['claim_response_raw'] = (ec.get('response', '') or '')[:3000]
        chain['steps'].append('claim')
        L('[%s] ★claim终判: Result=%s %s' % (phase, chain['claim_Result'], chain['claim_Message']))
    else:
        chain['claim_skipped'] = 'rec Result=%s (非0不带标, 不claim)' % er.get('Result')
        L('[%s] rec Result=%s 非带标 — 不claim' % (phase, er.get('Result')))
    # 终判复查: claim后limitfree/getconf/safeget对比
    e4 = argus_call(oracle, dev, sess, 'limitfree2', 'GET',
                    HOST + '/argus/api/v1/freshman/limitfreepopup', phase=phase)
    chain['limitfree2_Result'] = e4.get('Result')
    e5 = argus_call(oracle, dev, sess, 'getconf2', 'POST', HOST + '/argus/api/v1/client/getconf',
                    form={'localLabels': '', 'gender': '0'}, phase=phase)
    try:
        fm2 = (json.loads(e5.get('response', '') or '{}').get('Data', {}) or {}).get('Freshman', {})
        chain['getconf2_Freshman'] = {k: fm2.get(k) for k in
                                      ('IsFreshman', 'ShowLimitFreePopup', 'IsNewDevice',
                                       'IsNewQimei') if k in fm2}
    except Exception:
        pass
    key2 = ''
    try:
        key2 = str(((json.loads(
            argus_call(oracle, dev, sess, 'getkey2', 'GET',
                       HOST + '/argus/api/v4/bookcontent/getkey',
                       params={'bookId': BOOK_ID, 'ui': '0'}, phase=phase).get('response', '') or '{}')
            .get('Data', {}) or {}).get('Key', '')))
    except Exception:
        pass
    e6 = argus_call(oracle, dev, sess, 'safeget2', 'GET',
                    HOST + '/argus/api/v2/bookcontent/safegetcontent',
                    params={'bookId': BOOK_ID, 'chapterId': CHAPTER_ID, 'Key': key2, 'chapterPwd': ''}, phase=phase)
    chain['safeget2_Result'] = e6.get('Result')
    chain['steps'] += ['limitfree2', 'getconf2', 'getkey2', 'safeget2']
    return chain

# ───────────────────────── QR等待主循环 ─────────────────────────
def qr_wait_loop(oracle, dev, deadline_s, stale_test=False):
    """轮询scanQRCodeLogin; 过期重生成; 超时干净退出。返回(creds or None, 统计)"""
    t0 = time.time()
    stats = {'gens': 0, 'polls': 0, 'status_seen': set(), 'regens_expired': 0,
             'qr_lifetimes': [], 'regen_times': []}
    cur = None          # 当前QR {'sessionKey','url','gen_ts'}
    sess = None
    last_st = None
    last_hb = 0
    stale_injected = False
    stale_seen_result = None
    while time.time() - t0 < deadline_s:
        # 出码(或过期后重出码)
        if cur is None:
            qr = gen_qr(dev, stats['gens'] + 1)
            if qr is None:
                L('[QR] 出码失败 — 10s后重试')
                time.sleep(10)
                continue
            cur = qr
            stats['gens'] += 1
        # verify模式: 60s后注入2026-10-13旧sessionkey验证过期重生成分支
        if stale_test and not stale_injected and time.time() - t0 > 60:
            L('[QR] ★verify注入: 换用旧sessionkey(%s, 2026-10-13过期码)观察过期分支' % STALE_SK)
            cur = dict(cur, sessionKey=STALE_SK, gen_ts=time.time(), stale=True)
            stale_injected = True
        # 轮询
        try:
            j = scan_qr_poll(dev, cur['sessionKey'])
            stats['polls'] += 1
        except Exception as e:
            L('[POLL] 轮询异常(3s后继续): %s' % str(e)[:120])
            time.sleep(3)
            continue
        code = j.get('code')
        data = j.get('data') or {}
        st = data.get('scanStatus')
        stats['status_seen'].add(st)
        # verify模式: 旧sessionkey观察一个完整响应后, 无论服务端报不报过期, 都走一次重新出码分支
        if cur.get('stale'):
            resp = json.dumps(j, ensure_ascii=False)[:300]
            L('[QR] ★verify旧码轮询响应: %s' % resp)
            if stale_seen_result is None:
                stale_seen_result = {'code': code, 'scanStatus': st, 'resp': resp}
            if code != 0 or st == 3:
                L('[QR] ★verify: 旧码确认失效(code=%s scanStatus=%s) — 过期分支命中' % (code, st))
            else:
                L('[QR] ★verify: 旧码未报过期 — 人工强制走重新出码分支(重生成机制本身)')
            cur = None
            time.sleep(2)
            continue
        # 会话过期/未知会话 → 重新出码 (3=过期; 4=未知会话(38560808112旧码实测), 同样换码)
        if code != 0 or st in (3, 4):
            life = time.time() - cur['gen_ts']
            stats['qr_lifetimes'].append(round(life, 1))
            stats['regens_expired'] += 1
            stats['regen_times'].append(round(time.time() - t0, 1))
            L('[POLL] 会话失效(code=%s scanStatus=%s, 存活%.0fs) → 重新出码(刷新artifact+log)' % (
                code, st, life))
            cur = None
            time.sleep(2)
            continue
        if st == 5:
            yw, ywk = str(data.get('ywGuid', '')), str(data.get('ywKey', ''))
            if yw and ywk:
                SECRETS.append(ywk)
                L('[QR] ★★★ 扫码授权成功! ywGuid=%s ywKey=<len %d> (只进内存)' % (yw, len(ywk)))
                sess = {'ywGuid': yw, 'ywKey': ywk}
                break
            L('[POLL] scanStatus=5但凭据缺(data keys=%s) — 重新出码' % sorted(data.keys()))
            cur = None
            continue
        if st == 1 and last_st != 1:
            L('[POLL] 已扫码待授权(scanStatus=1) — 手机上点[授权登录]')
        if st not in (0, 1) and st != last_st:
            L('[POLL] scanStatus=%s (0待扫 1已扫 3过期 5成功)' % st)
        last_st = st
        # 30s心跳: 重复[QR_URL](实时通道) + App/oracle存活检查(主线程内联, 避免并发RPC)
        if time.time() - last_hb > 30:
            last_hb = time.time()
            L('[QR] 心跳 t+%ds/%ds QR#%d scanStatus=%s | [QR_URL] %s' % (
                time.time() - t0, deadline_s, stats['gens'], st, cur['url']))
            try:
                if not oracle.pidof():
                    L('[QR] 心跳: App无pid — 复活')
                    oracle.ensure_app()
                oracle.stat()
            except Exception:
                L('[QR] 心跳: oracle stat失败 — 重挂')
                try:
                    oracle.attach()
                except Exception:
                    pass
        time.sleep(3)
    stats['status_seen'] = sorted(x for x in stats['status_seen'] if x is not None)
    stats['stale_inject_result'] = stale_seen_result
    if sess is None:
        L('[QR] %ds窗口内无人扫码 — 正常结束(artifact留QR样张+链路日志, 重跑即再战)' % deadline_s)
    return sess, stats

# ───────────────────────── main ─────────────────────────
def main():
    os.makedirs(EVID_DIR, exist_ok=True)
    t_start = time.time()
    L('=== qr_born_oracle start (pid=%d, mode=%s, qr_wait=%ds) ===' % (
        os.getpid(), MODE, QR_WAIT))

    oracle = Oracle()
    if not oracle.exp:
        L('[FATAL] oracle attach失败 — 如实报告, 不编造')
        SUMMARY['notes'].append('oracle attach failed')
        json.dump(SUMMARY, open(EVID_DIR + '/qr_born_summary.json', 'w'), ensure_ascii=False, indent=1)
        return 0

    stop = threading.Event()
    th = threading.Thread(target=ui_thread, args=(stop, oracle), daemon=True)
    th.start()

    # Phase 1: 等真头成熟(cecelia 2_在scanQRCode前就绪) + 捕获oracle设备档案
    m = wait_headers_ready(oracle, 300, label='WAIT')
    if m is None:
        for attempt in range(3):
            try:
                m = oracle.geth(SMOKE_URL, 'GET', None)
                break
            except Exception as e:
                L('[SMOKE] 直调失败(尝试%d): %s' % (attempt, scrub(str(e))[:150]))
                if not oracle.attach():
                    time.sleep(8)
    if m is None:
        L('[FATAL] oracle拿不到冒烟头 — 无法构造oracle设备档案, 如实退出')
        SUMMARY['notes'].append('no oracle smoke')
        stop.set()
        json.dump(SUMMARY, open(EVID_DIR + '/qr_born_summary.json', 'w'), ensure_ascii=False, indent=1)
        return 0
    dev = extract_dev(m)
    props = getprops(oracle)
    dev['brand'] = props.get('ro.product.brand') or 'redroid'
    dev['board'] = props.get('ro.product.board') or 'redroid'
    dev['manufact'] = props.get('ro.product.manufacturer') or 'redroid'
    SUMMARY['device'] = {'imei': dev['imei'], 'model': dev['model'], 'brand': dev['brand'],
                         'qimei36': (dev['qimei36'][:16] + '…') if dev['qimei36'] else '(无)',
                         'appver': dev['appver'], 'ua': dev['ua'][:80]}
    SUMMARY['props'] = props
    L('[DEV] oracle设备档案: imei=%s model=%s brand=%s qimei36=%s' % (
        dev['imei'], dev['model'], dev['brand'],
        (dev['qimei36'][:16] + '…') if dev['qimei36'] else '(无, 将用QDInfo f14兜底)'))
    if not dev['qimei36']:
        SUMMARY['notes'].append('qimei36 missing at smoke time')

    # Phase 2-3: QR出生+轮询 (full=真等25min; verify=短窗+旧码注入)
    # ★从现在起UI线程进静默模式(只守前台不点不滑) + hook重dump门控 — 双静默防ANR
    #   (38560808112/38563552056实证: 乱点与hook重dump都会拖死App主线程→ANR)
    QUIET.set()
    oracle.setquiet(True)
    L('════ Phase 2-3: QR出生(scanQRCode) → 轮询scanQRCodeLogin(窗口%ds, UI+hook已切静默) ════' % QR_WAIT)
    stale_test = (MODE == 'verify')
    creds, qstats = qr_wait_loop(oracle, dev, QR_WAIT, stale_test=stale_test)
    SUMMARY['qr'] = {k: qstats[k] for k in ('gens', 'polls', 'status_seen', 'regens_expired',
                                            'qr_lifetimes', 'regen_times')}
    SUMMARY['qr']['stale_inject_result'] = qstats.get('stale_inject_result')

    # Phase 4-7: 扫码授权成功 → 出生链(login→判→rec→claim→复查)
    if creds:
        L('════ Phase 4-7: user/login → 出生即判 → 带标即claim → 终判 ════')
        chain = run_born_chain(oracle, dev, creds['ywGuid'], creds['ywKey'], phase='born')
        SUMMARY['born'] = chain
        L('════ 出生链摘要 ════')
        for k in ('login', 'getconf_Freshman', 'limitfree_Result', 'safeget_Result', 'taskId',
                  'rec_Result', 'claim_Result', 'claim_Message', 'claim_skipped',
                  'limitfree2_Result', 'safeget2_Result'):
            if k in chain:
                L('  born.%s = %s' % (k, json.dumps(chain[k], ensure_ascii=False)[:200]))
        if chain.get('claim_Result') == 0:
            L('★★★★★ 领取成功! claim Result=0 ★★★★★')
        if chain.get('safeget2_Result') == 0:
            L('★★★★★ safegetcontent Result=0 = VIP章节可读 = 真实限免权限! ★★★★★')
    elif MODE == 'verify':
        # verify模式半真实验: 死号900074388329走login→判→rec→claim(预期claim=-10021, 管道+头注入验证)
        L('════ verify半真实验: 死号900074388329 (QD_BORN_SESSION) 走user/login→rec→claim ════')
        dead = load_dead_session()
        if dead:
            chain = run_born_chain(oracle, dev, dead['guid'], dead['key'], phase='halfreal')
            SUMMARY['halfreal'] = chain
            L('════ 半真实验摘要(预期: login=0, rec=0, claim=-10021 → 管道+头注入正确) ════')
            for k in ('login', 'limitfree_Result', 'safeget_Result', 'taskId', 'rec_Result',
                      'claim_Result', 'claim_Message', 'limitfree2_Result', 'safeget2_Result'):
                if k in chain:
                    L('  half.%s = %s' % (k, json.dumps(chain[k], ensure_ascii=False)[:200]))
            if chain.get('login', {}).get('Result') == 0:
                L('[HALF] ★user/login管道通(Result=0) — 扫码后半段的login代码+oracle头注入已实测')
            if chain.get('claim_Result') == -10021:
                L('[HALF] ★claim=-10021与F四臂终判一致 — 头注入形态正确(账号级粘性复现)')
        else:
            SUMMARY['notes'].append('halfreal skipped: no secret')

    stop.set()
    SUMMARY['elapsed_s'] = round(time.time() - t_start, 1)
    json.dump(SUMMARY, open(EVID_DIR + '/qr_born_summary.json', 'w'), ensure_ascii=False, indent=1)
    L('════════ 终局摘要 ════════')
    L(json.dumps(SUMMARY, ensure_ascii=False)[:1500])
    L('耗时 %ds; 证据 %s/; oracle.log %s' % (time.time() - t_start, EVID_DIR, ORACLE_LOG))
    return 0

if __name__ == '__main__':
    # 硬看门狗: 43min无论如何落summary退出(artifact照常上传; full模式预算: 冒烟300+轮询1500+链路~400s)
    def _watchdog():
        time.sleep(2600)
        try:
            SUMMARY['notes'].append('watchdog_timeout')
            SUMMARY['elapsed_s'] = 2600
            json.dump(SUMMARY, open(EVID_DIR + '/qr_born_summary.json', 'w'),
                      ensure_ascii=False, indent=1)
        except Exception:
            pass
        os._exit(3)
    threading.Thread(target=_watchdog, daemon=True).start()
    sys.exit(main())
