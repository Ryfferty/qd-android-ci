#!/usr/bin/env python3
# mitm_login_capture.py — 会话注入×MITM登录态流量采集驱动 (子代理K, 2026-10-15)
#
# 前置(runner上已由workflow bash步骤完成):
#   redroid(localhost:5555) + q480已安装 + MITM管道已接线
#   (宿主iptables DNAT 172.17.0.0/16→宿主:8899 + 封UDP443 + mitmproxy CA进系统证书
#    + settings global http_proxy + mitmdump --set confdir=/tmp/mitm -w /tmp/all.flows 已在跑)
#
# 链路(全部反编译定案, 见 jadx480_full):
#   Phase A 匿名首启: 预写隐私同意(app_sp.xml) → am start → 等databases/QDConfig出现
#            + 点掉登录屏(tvSkip) → 匿名自然流量短窗(顺便当匿名基线) → force-stop
#   Phase B 注入: pull databases/QDConfig(we.judian: 表setting(Key text primary key,Value text),
#            写入用SQLiteDatabase.replace()=INSERT OR REPLACE) → 本地sqlite3插4行:
#            SettingYWKey/SettingYWGuid/SettingCmfuToken/SettingUserToken
#            (QDUserManager.J(ywkey,ywguid,cmfuToken,userToken)同款写集)
#            → push回+chown+删-wal/-shm → force-stop状态下生效
#   Phase C 复启验证: am start → logcat等QDConfig"loadUserSettingFromDB done...ywKeyEmpty:false"
#            (App从DB装载登录态的确定性日志) + 监视登出信号(OKR_401/ACTION_LOGIN_OUT/cleanLogin)
#   Phase D 自然流量: 5分钟书城/发现滑动+tab切换+进书详情+福利中心尝试(adb input swipe/tap)
#            + 截图序列 + App存活看门狗
#   Phase E 收尾: pkill mitmdump → flows_extract.py提取(headers JSON+scrubbed flows) → VERDICT
#
# 凭据纪律(repo=PUBLIC): QD_E7_SESSION(secret)只在runner内存+/tmp;
#   ywKey/CmfuToken/UserInfo值绝不进log(只打长度)、绝不进artifact
#   (flows_extract精确值scrub+结构正则兜底, scrubbed flows副本上传, 原始flows不上传);
#   QDConfig DB本身(含注入行)不上传, 只上scrub后的行清单(Key+值长度)。
#
# 用法: QD_E7_SESSION=base64(json) QD_MITM_MODE=login python3 ci/mitm_login_capture.py
#   QD_MITM_MODE=verify → 跳过注入(纯匿名管道验证); QD_TRAFFIC_SECS=300 覆盖流量窗
import os, sys, json, time, base64, re, sqlite3, subprocess, threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'ci'))

ADB_DEV = 'localhost:5555'
APP = 'com.qidian.QDReader'
DB = '/data/data/%s/databases/QDConfig' % APP
FLOWS = '/tmp/all.flows'
OUT = '/tmp/out'
SECRETS_FILE = '/tmp/e7_secrets.txt'   # runner /tmp, 只写值不写名

MODE = (os.environ.get('QD_MITM_MODE') or 'login').strip().lower()
TRAFFIC_SECS = int(os.environ.get('QD_TRAFFIC_SECS') or '300')

VERDICT = {'mode': MODE}
SECRETS = []          # 精确待脱敏值(只在内存+/tmp)


def L(msg):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)


def adb(*args, timeout=20):
    return subprocess.run(['adb', '-s', ADB_DEV] + list(args),
                          capture_output=True, text=True, timeout=timeout)


def sh(*args, timeout=20):
    return adb('shell', *args, timeout=timeout)


# ── UI 输入安全层 (第一轮教训: `input swipe` TimeoutExpired 未兜底直接崩掉整个 driver,
#    登录态段(Phase B/C/D)全没跑到, 而 r1 648B 形态只在登录窗出现) ──
# 兜底链: input(30s) → 重试1次 input → sendevent 裸协议 → 放弃并如实记录。任何一级都不抛。
_TOUCH_DEV = None       # /dev/input/eventX (带 ABS_MT_POSITION_X 的设备), 懒探测
_UI_FAILS = {'input': 0, 'sendevent': 0}


def _find_touch_dev():
    global _TOUCH_DEV
    if _TOUCH_DEV is not None:
        return _TOUCH_DEV or None
    _TOUCH_DEV = ''
    try:
        r = sh('getevent', '-pl', timeout=15)
        cur = None
        for line in (r.stdout or '').splitlines():
            line = line.strip()
            m = re.match(r'add device \d+: (/dev/input/event\d+)', line)
            if m:
                cur = m.group(1)
            if cur and 'ABS_MT_POSITION_X' in line:
                _TOUCH_DEV = cur
                break
    except Exception:
        pass
    return _TOUCH_DEV or None


def _sendevent_seq(cmds):
    """把一串 sendevent 三元组打包成单次 adb shell 调用(减少往返), 失败不抛。"""
    dev = _find_touch_dev()
    if not dev:
        _UI_FAILS['sendevent'] += 1
        return False
    script = ' && '.join('sendevent %s %d %d %d' % (dev, t, c, v) for t, c, v in cmds)
    try:
        sh(script, timeout=25)      # 单串传远端shell
        return True
    except Exception:
        _UI_FAILS['sendevent'] += 1
        return False


def _sendevent_swipe(x1, y1, x2, y2, steps=8):
    """type-B MT 滑动: TRACKING_ID=57, POSITION_X=53, POSITION_Y=54, BTN_TOUCH=330"""
    cmds = [(3, 57, 100), (3, 53, x1), (3, 54, y1), (1, 330, 1), (0, 0, 0)]
    for i in range(1, steps + 1):
        x = x1 + (x2 - x1) * i // steps
        y = y1 + (y2 - y1) * i // steps
        cmds += [(3, 53, x), (3, 54, y), (0, 0, 0)]
    cmds += [(3, 57, -1 & 0xffffffff), (1, 330, 0), (0, 0, 0)]
    return _sendevent_seq(cmds)


def _sendevent_tap(x, y):
    return _sendevent_seq([(3, 57, 101), (3, 53, x), (3, 54, y),
                           (1, 330, 1), (0, 0, 0),
                           (3, 57, -1 & 0xffffffff), (1, 330, 0), (0, 0, 0)])


def ui_swipe(x1, y1, x2, y2, ms=300):
    """永不抛的滑动: input×2 → sendevent → 放弃(返回False)"""
    for attempt in (1, 2):
        try:
            sh('input', 'swipe', str(x1), str(y1), str(x2), str(y2), str(ms), timeout=30)
            return True
        except Exception as e:
            _UI_FAILS['input'] += 1
            L('[UI] input swipe 第%d次失败(%s) — %s' % (attempt, type(e).__name__,
              '转sendevent' if attempt == 2 else '重试'))
    ok = _sendevent_swipe(x1, y1, x2, y2)
    L('[UI] sendevent swipe 兜底: %s' % ('OK' if ok else '也失败(跳过本轮, 不中断)'))
    return ok


def ui_tap(x, y):
    """永不抛的点按: input×2 → sendevent → 放弃"""
    for attempt in (1, 2):
        try:
            sh('input', 'tap', str(x), str(y), timeout=30)
            return True
        except Exception as e:
            _UI_FAILS['input'] += 1
            L('[UI] input tap 第%d次失败(%s) — %s' % (attempt, type(e).__name__,
              '转sendevent' if attempt == 2 else '重试'))
    ok = _sendevent_tap(x, y)
    L('[UI] sendevent tap 兜底: %s' % ('OK' if ok else '也失败(跳过, 不中断)'))
    return ok


def ui_key(code):
    try:
        sh('input', 'keyevent', str(code), timeout=25)
        return True
    except Exception:
        _UI_FAILS['input'] += 1
        L('[UI] keyevent %s 失败(跳过)' % code)
        return False


def pidof():
    try:
        out = (sh('pidof', APP, timeout=10).stdout or '').strip()
        return out.split()[0] if out else None
    except Exception:
        return None


def foreground():
    try:
        for line in (sh('dumpsys', 'window', timeout=12).stdout or '').splitlines():
            if 'mCurrentFocus' in line:
                return line.strip()[:160]
    except Exception:
        pass
    return '?'


def dump_ui():
    try:
        sh('uiautomator', 'dump', '/sdcard/u.xml', timeout=15)
        r = sh('cat', '/sdcard/u.xml', timeout=15)
        return r.stdout or ''
    except Exception:
        return ''


def find_bounds(xml, id_frag=None, text=None):
    if id_frag:
        pat = r'resource-id="[^"]*%s[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % re.escape(id_frag)
    else:
        pat = r'text="[^"]*%s[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % re.escape(text)
    for m in re.finditer(pat, xml):
        x1, y1, x2, y2 = map(int, m.groups())
        return (x1 + x2) // 2, (y1 + y2) // 2
    return None


def tap_text(xml, *texts):
    for t in texts:
        xy = find_bounds(xml, text=t)
        if xy:
            ui_tap(xy[0], xy[1])
            return t
    return None


def tap_id(xml, *ids):
    for i in ids:
        xy = find_bounds(xml, id_frag=i)
        if xy:
            ui_tap(xy[0], xy[1])
            return i
    return None


def screenshot(name):
    try:
        os.makedirs(OUT, exist_ok=True)
        p = os.path.join(OUT, name)
        with open(p, 'wb') as f:
            f.write(subprocess.run(['adb', '-s', ADB_DEV, 'exec-out', 'screencap', '-p'],
                                   capture_output=True, timeout=30).stdout)
        return os.path.getsize(p)
    except Exception:
        return 0


def app_uid():
    for attempt in (0, 1):
        try:
            r = sh('stat', '-c', '%u', '/data/data/%s' % APP, timeout=10)
            uid = (r.stdout or '').strip()
            if uid.isdigit() and int(uid) > 10000:
                return uid
            r = sh('cmd', 'package', 'list', 'packages', '-U', APP, timeout=10)
            m = re.search(r'uid:(\d+)', r.stdout or '')
            if m and int(m.group(1)) > 10000:
                return m.group(1)
        except Exception:
            pass
    return None


def wait_db(path, timeout_s=180):
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        try:
            r = sh('ls', path, timeout=10)
            if (r.stdout or '').strip().endswith('QDConfig'):
                return True
        except Exception:
            pass
        time.sleep(5)
    return False


def load_session():
    """QD_E7_SESSION(base64 JSON)→(ywGuid,ywKey,CmfuToken,UserInfo)。兼容resp.data嵌套与多拼写。"""
    raw = os.environ.get('QD_E7_SESSION') or ''
    if not raw:
        return None
    try:
        d = json.loads(base64.b64decode(raw))
    except Exception as e:
        L('[SESSION] secret解码失败: %s' % str(e)[:80])
        return None
    if isinstance(d.get('resp'), dict):
        flat = dict(d['resp'].get('data', {}))
        flat.update({k: v for k, v in d.items() if k != 'resp'})
        d = flat

    def gv(*names):
        for n in names:
            for k in d:
                if k.lower() == n.lower():
                    v = d[k]
                    if isinstance(v, (dict, list)):
                        continue
                    return str(v) if v is not None else ''
        return ''
    guid = gv('ywGuid', 'ywguid', 'guid')
    key = gv('ywKey', 'ywkey', 'key')
    cmfu = gv('CmfuToken', 'cmfuToken', 'cmfutoken')
    userinfo = gv('UserInfo', 'userInfo', 'userToken', 'UserToken')
    if not guid or not key:
        L('[SESSION] secret缺ywGuid/ywKey (keys=%s) — 无法注入' % sorted(d.keys()))
        return None
    return {'guid': guid, 'key': key, 'cmfu': cmfu, 'userinfo': userinfo}


# ═════════════ Phase A: 匿名首启 ═════════════
def phase_first_launch():
    L('═══ Phase A: 匿名首启(consent预写+登录屏跳过+匿名短窗) ═══')
    # 隐私同意预写(qr-born v7实证, 免弹窗)
    uid = app_uid()
    sh('mkdir', '-p', '/data/data/%s/shared_prefs' % APP)
    # 单串传远端shell(引号保真; 多参数会被远端shell拆掉XML引号)
    sh("echo '<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?><map>"
       "<boolean name=\"is_agree_privacy\" value=\"true\" /></map>' "
       "> /data/data/%s/shared_prefs/app_sp.xml" % APP)
    if uid:
        sh('chown', '%s:%s' % (uid, uid), '/data/data/%s/shared_prefs/app_sp.xml' % APP)
        sh('chmod', '660', '/data/data/%s/shared_prefs/app_sp.xml' % APP)
    L('[A] consent预写完成 uid=%s' % uid)

    sh('am', 'start', '-n', '%s/.ui.activity.SplashActivity' % APP, timeout=15)
    # 等稳定pid
    stable = None
    for i in range(20):
        time.sleep(4)
        p1 = pidof()
        if p1:
            time.sleep(4)
            if pidof() == p1:
                stable = p1
                break
    L('[A] App稳定 pid=%s fg=%s' % (stable, foreground()[:80]))
    if not stable:
        L('[A] ⚠ App未稳定起来 — 继续(可能慢启动)')

    # QDConfig DB出现(登录态注入的目标文件)
    ok = wait_db(DB, 180)
    L('[A] databases/QDConfig %s' % ('存在✓' if ok else '未出现⚠(注入将尝试创建)'))

    # 登录屏跳过(E实证: tvSkip; 1080x2340下兜底坐标=(63,104))
    for attempt in range(6):
        xml = dump_ui()
        if not xml:
            time.sleep(6)
            continue
        hit = tap_id(xml, 'tvSkip', 'ivSkip', 'btnAgree') or \
              tap_text(xml, '跳过', '立即体验', '同意并继续', '开始使用')
        if not hit:
            hit = 'coord(63,104)'
            ui_tap(63, 104)
        L('[A] 登录屏轮%d 点了%s fg=%s' % (attempt, hit, foreground()[:60]))
        time.sleep(8)
        fg = foreground()
        if 'Main' in fg or 'Home' in fg or ('qidian' in fg and 'Login' not in fg and 'Guidance' not in fg):
            L('[A] 已到主界面(匿名)')
            break

    # 匿名短窗60s(匿名基线流量; ostar/qimei初始化收尾)
    _fb = lambda: os.path.getsize(FLOWS) if os.path.exists(FLOWS) else 0
    L('[A] 匿名窗60s(顺带匿名基线) flows=%dB' % _fb())
    t0 = time.time()
    while time.time() - t0 < 60:
        ui_swipe(540, 1700, 540, 700)   # 第一轮崩点: 原 sh('input','swipe',...,timeout=10) 无兜底
        time.sleep(9)
    L('[A] 匿名窗结束 flows=%dB' % _fb())

    # force-stop(DB干净关闭再改)
    sh('am', 'force-stop', APP, timeout=15)
    for i in range(10):
        if not pidof():
            break
        time.sleep(2)
    L('[A] App已停(准备注入)')


# ═════════════ Phase B: setting表注入 ═════════════
INJECT_ROWS = ('SettingYWKey', 'SettingYWGuid', 'SettingCmfuToken', 'SettingUserToken')


def phase_inject(sess):
    L('═══ Phase B: QDConfig.setting 注入(INSERT OR REPLACE×4) ═══')
    L('[B] secret装载: ywGuid=%s ywKey=<len %d> CmfuToken=<len %d> UserInfo=<len %d>' % (
        sess['guid'], len(sess['key']), len(sess['cmfu']), len(sess['userinfo'])))
    global SECRETS
    SECRETS = [v for v in (sess['key'], sess['cmfu'], sess['userinfo']) if len(v) >= 8]
    with open(SECRETS_FILE, 'w') as f:
        f.write('\n'.join(SECRETS) + '\n')
    # UserToken格式防御检查(ParseToken: 管道≥7字段, [0]可int)
    parts = sess['userinfo'].split('|')
    fmt_ok = len(parts) >= 7 and parts[0].strip().lstrip('-').isdigit()
    L('[B] UserInfo格式: %d字段 [0]=%s %s' % (len(parts), parts[0][:12], '✓' if fmt_ok else '⚠(可能解析失败→登录判定w()=false)'))

    uid = app_uid()
    # 原权限(mode)
    mode0 = '660'
    try:
        r = sh('stat', '-c', '%a', DB, timeout=10)
        m = (r.stdout or '').strip()
        if m.isdigit():
            mode0 = m
    except Exception:
        pass
    # pull(连wal/shm一起, 有则恢复)
    local = '/tmp/QDConfig_inject'
    for suf in ('', '-wal', '-shm'):
        try:
            adb('pull', DB + suf, local + suf, timeout=30)
        except Exception:
            pass
    if not os.path.exists(local):
        L('[B] ⚠ pull失败且DB不存在 — 本地新建空库建表')
    # 本地sqlite3写入(replace语义=we.search.q())
    con = sqlite3.connect(local)
    con.execute('CREATE TABLE IF NOT EXISTS setting (Key text primary key ,Value text);')
    vals = {'SettingYWKey': sess['key'], 'SettingYWGuid': sess['guid'],
            'SettingCmfuToken': sess['cmfu'], 'SettingUserToken': sess['userinfo']}
    for k, v in vals.items():
        con.execute('INSERT OR REPLACE INTO setting (Key, Value) VALUES (?, ?)', (k, v))
    con.commit()
    try:
        con.execute('PRAGMA wal_checkpoint(TRUNCATE);')
        con.commit()
    except Exception:
        pass
    # verify(本地)
    rows = con.execute("SELECT Key, length(Value) FROM setting WHERE Key IN "
                       "('SettingYWKey','SettingYWGuid','SettingCmfuToken','SettingUserToken')").fetchall()
    con.close()
    got = {k: n for k, n in rows}
    L('[B] 本地verify: %s' % json.dumps({k: got.get(k, -1) for k in INJECT_ROWS}))
    # scrub后的行清单(可上传)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 'injected_rows_scrubbed.txt'), 'w') as f:
        for k in INJECT_ROWS:
            v = got.get(k, -1)
            f.write('%s value_len=%s\n' % (k, v))
        f.write('note: values in runner memory only; QDConfig DB NOT uploaded\n')

    # push回
    sh('rm', '-f', DB + '-wal', DB + '-shm', timeout=10)
    adb('push', local, '/data/local/tmp/QDConfig.new', timeout=30)
    sh('mkdir', '-p', '/data/data/%s/databases' % APP, timeout=10)
    sh('cp', '/data/local/tmp/QDConfig.new', DB, timeout=10)
    sh('rm', '-f', '/data/local/tmp/QDConfig.new', timeout=10)
    if uid:
        sh('chown', '%s:%s' % (uid, uid), DB)
    sh('chmod', mode0, DB)
    r = sh('ls', '-la', DB, timeout=10)
    L('[B] 设备侧: %s' % ((r.stdout or '').strip().split('databases')[-1]))
    L('[B] ★注入完成(4行INSERT OR REPLACE, 设备uid=%s mode=%s)' % (uid, mode0))
    return True


# ═════════════ Phase C: 复启+登录态验证 ═════════════
LOGOUT_SIG = re.compile(r'OKR_401|LOGIN_OUT|LOGOUT_BY_USER|cleanLogin|kickLogout|setUserInfo enter, ywkeyEmpty:true', re.I)
LOAD_SIG = re.compile(r'loadUserSettingFromDB done.*ywKeyEmpty:(\w+)', re.I)


def phase_verify_login():
    L('═══ Phase C: 复启→logcat等"ywKeyEmpty:false" ═══')
    sh('logcat', '-c', timeout=10)
    sh('am', 'start', '-n', '%s/.ui.activity.SplashActivity' % APP, timeout=15)
    t0 = time.time()
    load_line, logout_seen = None, False
    while time.time() - t0 < 100:
        time.sleep(8)
        try:
            r = sh('logcat', '-d', '-v', 'time', timeout=20)
        except Exception:
            continue
        for line in (r.stdout or '').splitlines():
            if 'loadUserSettingFromDB' in line:
                load_line = line.strip()[:200]
            if LOGOUT_SIG.search(line):
                logout_seen = True
                L('[C] ⚠登出信号: %s' % line.strip()[:150])
        if load_line:
            break
    L('[C] QDConfig装载日志: %s' % (load_line or '(未见——可能格式变化, 看flows Cookie判定)'))
    m = LOAD_SIG.search(load_line or '')
    ok_log = bool(m and m.group(1) == 'false')
    fg = foreground()
    L('[C] 复启后前台: %s' % fg[:100])
    if m:
        VERDICT['login_logcat_ywkeyempty'] = m.group(1)
    VERDICT['login_logcat_ok'] = ok_log
    VERDICT['logout_signal_seen'] = logout_seen
    VERDICT['foreground_after_relaunch'] = fg[:100]
    # 再登一次登录屏跳过兜底(如又弹)
    xml = dump_ui()
    if xml:
        hit = tap_id(xml, 'tvSkip', 'ivSkip') or tap_text(xml, '跳过', '立即体验')
        if hit:
            L('[C] 复启后又见登录屏, 点了%s' % hit)
            time.sleep(6)
    L('[C] %s' % ('★logcat登录态装载成功(ywKeyEmpty:false)' if ok_log else
                  'logcat未确认 — 以flows登录Cookie为准(Phase E判定)'))
    return ok_log


# ═════════════ Phase D: 5分钟自然流量 ═════════════
def phase_traffic(secs):
    L('═══ Phase D: 自然流量%d秒(滑动+tab+书详情+福利尝试) ═══' % secs)
    t0 = time.time()
    n = 0
    tab_cycle = ['书城', '发现', '书架', '书城', '发现']
    did_book = did_welfare = False
    while time.time() - t0 < secs:
        n += 1
        el = time.time() - t0
        try:
            if not pidof():
                L('[D] t+%ds App死→重启' % el)
                sh('am', 'start', '-n', '%s/.ui.activity.SplashActivity' % APP, timeout=15)
                time.sleep(12)
                continue
            # 滑动刷新(书城/发现列表)
            ui_swipe(540, 1700, 540, 650)
            # tab轮换(~40s一次)
            if n % 4 == 0:
                xml = dump_ui()
                want = tab_cycle[(n // 4 - 1) % len(tab_cycle)]
                if tap_text(xml, want):
                    L('[D] t+%ds tab→%s' % (el, want))
            # t+100s: 进一本书详情(v200模式: content-desc可点, 排除导航)
            if not did_book and el > 100:
                xml = dump_ui()
                xy = None
                for mm in re.finditer(
                        r'content-desc="([^"]{2,24})"[^>]*clickable="true"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
                        xml):
                    desc, x1, y1, x2, y2 = mm.group(1), *map(int, mm.groups()[1:])
                    if re.search(r'书城|发现|书架|我的|签到|搜索|消息', desc):
                        continue
                    xy = ((x1 + x2) // 2, (y1 + y2) // 2)
                    break
                if xy:
                    ui_tap(xy[0], xy[1])
                    L('[D] t+%ds 进书详情 tap(%d,%d)' % (el, xy[0], xy[1]))
                    time.sleep(12)
                    ui_key(4)
                    did_book = True
            # t+220s: 福利中心尝试(我的tab→福利)
            if not did_welfare and el > 220:
                xml = dump_ui()
                tap_text(xml, '我的')
                time.sleep(6)
                xml = dump_ui()
                hit = tap_text(xml, '福利中心', '福利', '任务', '签到')
                if hit:
                    L('[D] t+%ds 福利入口: %s' % (el, hit))
                    time.sleep(8)
                    screenshot('shot_welfare.png')
                    ui_key(4)
                did_welfare = True
            # 截图序列(~30s一张)
            if n % 3 == 1:
                screenshot('shot_%03d.png' % n)
            if n % 6 == 0:
                L('[D] t+%ds/%ds flows=%dB fg=%s' % (
                    el, secs, os.path.getsize(FLOWS) if os.path.exists(FLOWS) else 0,
                    foreground()[:60]))
        except Exception as e:
            L('[D] t+%ds err: %s' % (el, str(e)[:60]))
        time.sleep(8)
    screenshot('shot_final.png')
    L('[D] 流量窗结束 flows=%dB' % (os.path.getsize(FLOWS) if os.path.exists(FLOWS) else 0))


# ═════════════ Phase E: 收尾提取 ═════════════
def phase_extract():
    L('═══ Phase E: 停mitmdump → flows提取(scrub) → VERDICT ═══')
    subprocess.run(['pkill', '-f', 'mitmdump'], capture_output=True)
    time.sleep(3)
    try:
        r = subprocess.run(['sudo', 'iptables', '-t', 'nat', '-L', 'PREROUTING', '-n', '-v'],
                           capture_output=True, text=True, timeout=15)
        open(os.path.join(OUT, 'dnat_counters.txt'), 'w').write(r.stdout or '')
    except Exception:
        pass
    sz = os.path.getsize(FLOWS) if os.path.exists(FLOWS) else 0
    L('[E] flows文件 %d bytes' % sz)
    VERDICT['flows_bytes'] = sz
    if sz == 0:
        L('[E] ⚠ flows为空 — MITM管道未捕获(看out/mitm.log与iptables计数)')
    # logcat存证(截关键段)
    try:
        r = sh('logcat', '-d', '-v', 'time', timeout=25)
        open(os.path.join(OUT, 'logcat_capture.txt'), 'w').write((r.stdout or '')[-400000:])
        key = [l for l in (r.stdout or '').splitlines()
               if re.search(r'loadUserSettingFromDB|QDUserManager|QDConfig|OKR_401|LOGIN_OUT', l)]
        open(os.path.join(OUT, 'logcat_login_lines.txt'), 'w').write('\n'.join(key[:200]))
    except Exception as e:
        L('[E] logcat存证失败: %s' % str(e)[:60])
    from flows_extract import extract
    s = extract(FLOWS, OUT, SECRETS or (load_secret_values() if os.path.exists(SECRETS_FILE) else []),
                4096, os.path.join(OUT, 'flows_scrubbed.mitm'))
    VERDICT.update(s)
    # 判定行(验收硬标准)
    L('════ VERDICT ════')
    L('FLOWS_SIZE=%d %s' % (sz, '✓(>100KB)' if sz > 102400 else '✗(<100KB)'))
    L('ARGUS_TOTAL=%d ARGUS_LOGIN=%d %s' % (
        s.get('argus', 0), s.get('login_cookie_argus', 0),
        '✓(登录态argus≥30)' if s.get('login_cookie_argus', 0) >= 30 else '✗(<30)'))
    L('LOGIN_LOGCAT=%s LOGOUT_SIGNAL=%s' % (
        VERDICT.get('login_logcat_ok'), VERDICT.get('logout_signal_seen')))
    L('UA_GH=%s COOKIE_FIELDS=%s' % (s.get('gettabheight_values'), s.get('cookie_fields')))
    try:
        meta = json.load(open(os.path.join(OUT, 'headers_extract.json')))['meta']
        VERDICT['argus_header_presence'] = meta['argus_header_presence']
        VERDICT['ua_distinct'] = meta['ua_distinct']
        VERDICT['cookie_field_distinct'] = meta['cookie_field_distinct']
        L('ARGUS_HEADER_PRESENCE=%s' % json.dumps(meta['argus_header_presence']))
    except Exception as e:
        L('[E] meta读取失败: %s' % str(e)[:80])
    json.dump(VERDICT, open(os.path.join(OUT, 'driver_verdict.json'), 'w'), ensure_ascii=False, indent=1)


def load_secret_values():
    from flows_extract import load_secrets
    return load_secrets(SECRETS_FILE)


def run_phase(name, fn, *args):
    """阶段隔离: 任何一Phase崩(含未预料的TimeoutExpired)都不能挡住后续Phase —
    第一轮事故根因: Phase A 匿名窗一个 swipe 超时 → 整个 driver 死 → 登录态段(648B r1)没跑到。"""
    try:
        return fn(*args)
    except Exception as e:
        L('[%s] ★阶段异常被隔离: %s: %s (继续后续阶段)' % (name, type(e).__name__, str(e)[:200]))
        VERDICT['phase_%s_crash' % name] = '%s: %s' % (type(e).__name__, str(e)[:120])
        return None


def main():
    global MODE
    os.makedirs(OUT, exist_ok=True)
    L('=== mitm_login_capture start (pid=%d mode=%s traffic=%ds) ===' % (
        os.getpid(), MODE, TRAFFIC_SECS))
    sess = None
    if MODE == 'login':
        sess = load_session()
        if sess is None:
            L('[FATAL] mode=login但QD_E7_SESSION不可用 — 降级为verify(匿名), 如实报告')
            MODE = 'verify'
            VERDICT['downgraded_to_verify'] = True
    run_phase('A', phase_first_launch)
    if MODE == 'login' and sess:
        if run_phase('B', phase_inject, sess):
            run_phase('C', phase_verify_login)
    else:
        L('[B/C] verify模式: 跳过注入(匿名管道验证)')
        # verify模式下直接复启继续(无需stop/start循环)
        try:
            sh('am', 'start', '-n', '%s/.ui.activity.SplashActivity' % APP, timeout=15)
        except Exception as e:
            L('[B/C] am start 失败(隔离): %s' % str(e)[:80])
    run_phase('D', phase_traffic, TRAFFIC_SECS)
    run_phase('E', phase_extract)
    VERDICT['ui_input_fails'] = dict(_UI_FAILS)
    L('[UI] 输入兜底统计: %s (touch_dev=%s)' % (_UI_FAILS, _TOUCH_DEV or '未探测/不可用'))
    L('=== done (verdict: %s) ===' % json.dumps(VERDICT, ensure_ascii=False)[:400])
    return 0


if __name__ == '__main__':
    sys.exit(main())
