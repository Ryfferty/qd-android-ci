#!/usr/bin/env python3
# qqread_fock_driver.py — QQ阅读 fock hook 采集的 UI 驱动 (子代理, 2026-10-19)
#
# 前置(runner 上由 workflow bash 完成):
#   redroid(localhost:5555) + com.qq.reader 已安装 + MITM 已接线(mitmdump -w /tmp/all.flows)
#   + fs-srv(frida-server, 127.0.0.1:14771 已 forward) + App 已 am start(裸跑, 无 frida)。
#   本 driver: A 裸跑 consent → A2 attach frida → C/D/E 读章 → G 收尾停 frida。
#
# 链路(r4: attach 时机改为 driver 内控 — r2/r3 实证 app init 期(attach后+23~35s)有反frida扫描
#   会杀进程; 而 r2 流量实证 /sk→addKeys 与 ChapBat→unlockData 都在"阅读器启动时"才触发
#   (reader activity start), 远晚于 init 扫描。⇒ Phase A 先裸跑 consent(init 扫描以无frida状态
#   通过), Phase A2 再 attach(r1-r3 弹窗白名单点/黑名单绝不点同 qqread_driver.py):
#   Phase A 等 pid(冷启动>80s) → 隐私/权限弹窗点掉 → A2 attach frida(等 FOCKHOOK_READY)
#   Phase B 静置 ~25s
#   Phase C deeplink 书详情(大生意人 bid=54425396)
#   Phase D 点 开始阅读 → 进阅读页(兜底 readepage deeplink) ← /sk+addKeys+ChapBat+unlockData 触发窗
#   Phase E1 第1章: 翻页×3 每页截图
#   Phase E2 菜单→目录→第2章: 翻页×4(第2章明文样本)
#   Phase G 收尾: logcat + hook 事件计数 + verdict + 停frida
#
# 凭据纪律: 游客态无个人凭据; 与 hook 产物(flk 密钥材料)只落 artifact, 不入 log 明文。
import os, sys, json, time, re, subprocess

ADB_DEV = 'localhost:5555'
APP = 'com.qq.reader'
FLOWS = '/tmp/all.flows'
COLLECT = '/tmp/fock_collect.log'
OUT = '/tmp/out'
DUMPS = os.path.join(OUT, 'ui_dumps')
BID = os.environ.get('QQREAD_BID') or '54425396'
HOOK = os.environ.get('FOCK_HOOK') or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'hook_qqread_fock.js')
FRIDA_HOST = os.environ.get('FOCK_FRIDA_HOST') or '127.0.0.1:14771'

VERDICT = {'bid': BID, 'phases': {}}
_FRIDA_PROC = []   # [Popen] — driver 拉住的 frida CLI 会话

CONSENT_OK = ['同意并继续', '同意并进入', '同意', '允许', '仅在使用中允许', '我知道了', '知道了',
              '稍后再说', '以后再说', '暂不', '跳过', '立即体验', '开始使用', '进入书城', '不了，谢谢',
              '我都爱看']   # r1实证: 冷启动中途弹"选择阅读口味"推荐浮层(挡阅读页), 点"我都爱看"即收起
LOGIN_BLACK = ['登录', '注册', '手机号', '一键开通', '购买', '支付', '开通会员', '立即充值', '充值',
               '扫码登录', '阅文账号']
TASTE_MARKS = ('选择阅读口味', '我都爱看', '为你推荐专属好书')   # 推荐浮层特征(r1: 挡在阅读页之上)

_UI_FAILS = {'input': 0, 'sendevent': 0}


def L(msg):
    print('[%s] %s' % (time.strftime('%H:%M:%S'), msg), flush=True)


def adb(*args, timeout=20):
    return subprocess.run(['adb', '-s', ADB_DEV] + list(args),
                          capture_output=True, text=True, timeout=timeout)


def sh(*args, timeout=20):
    return adb('shell', *args, timeout=timeout)


def _find_touch_dev():
    global _TD
    try:
        r = sh('getevent', '-pl', timeout=15)
        cur = None
        for line in (r.stdout or '').splitlines():
            line = line.strip()
            m = re.match(r'add device \d+: (/dev/input/event\d+)', line)
            if m:
                cur = m.group(1)
            if cur and 'ABS_MT_POSITION_X' in line:
                _TD = cur
                return cur
    except Exception:
        pass
    return None


_TD = None


def _sendevent_seq(cmds):
    dev = _find_touch_dev()
    if not dev:
        _UI_FAILS['sendevent'] += 1
        return False
    script = ' && '.join('sendevent %s %d %d %d' % (dev, t, c, v) for t, c, v in cmds)
    try:
        sh(script, timeout=25)
        return True
    except Exception:
        _UI_FAILS['sendevent'] += 1
        return False


def _swipe_ev(x1, y1, x2, y2, steps=8):
    cmds = [(3, 57, 100), (3, 53, x1), (3, 54, y1), (1, 330, 1), (0, 0, 0)]
    for i in range(1, steps + 1):
        cmds += [(3, 53, x1 + (x2 - x1) * i // steps), (3, 54, y1 + (y2 - y1) * i // steps), (0, 0, 0)]
    cmds += [(3, 57, -1 & 0xffffffff), (1, 330, 0), (0, 0, 0)]
    return _sendevent_seq(cmds)


def _tap_ev(x, y):
    return _sendevent_seq([(3, 57, 101), (3, 53, x), (3, 54, y), (1, 330, 1), (0, 0, 0),
                           (3, 57, -1 & 0xffffffff), (1, 330, 0), (0, 0, 0)])


def ui_swipe(x1, y1, x2, y2, ms=300):
    for attempt in (1, 2):
        try:
            sh('input', 'swipe', str(x1), str(y1), str(x2), str(y2), str(ms), timeout=30)
            return True
        except Exception:
            _UI_FAILS['input'] += 1
    return _swipe_ev(x1, y1, x2, y2)


def ui_tap(x, y):
    for attempt in (1, 2):
        try:
            sh('input', 'tap', str(x), str(y), timeout=30)
            return True
        except Exception:
            _UI_FAILS['input'] += 1
    return _tap_ev(x, y)


def ui_key(code):
    try:
        sh('input', 'keyevent', str(code), timeout=25)
        return True
    except Exception:
        _UI_FAILS['input'] += 1
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


def dump_name(tag):
    return os.path.join(DUMPS, '%s.xml' % tag)


def dump_ui(tag=''):
    xml = ''
    try:
        sh('uiautomator', 'dump', '/sdcard/u.xml', timeout=15)
        r = sh('cat', '/sdcard/u.xml', timeout=15)
        xml = r.stdout or ''
    except Exception:
        pass
    if xml and tag:
        try:
            open(dump_name(tag), 'w', encoding='utf-8', errors='replace').write(xml)
        except Exception:
            pass
    return xml


def nodes(xml):
    out = []
    for m in re.finditer(r'<node[^>]*>', xml or ''):
        seg = m.group(0)
        def attr(n):
            mm = re.search(r'%s="([^"]*)"' % n, seg)
            return mm.group(1) if mm else ''
        b = attr('bounds')
        bm = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', b)
        if not bm:
            continue
        x1, y1, x2, y2 = map(int, bm.groups())
        t, d, rid = attr('text'), attr('content-desc'), attr('resource-id')
        if t or d:
            out.append((t, d, rid, (x1 + x2) // 2, (y1 + y2) // 2, x2 - x1, y2 - y1))
    return out


def find_text(xml, *texts, contains=True):
    for t, d, rid, cx, cy, w, h in nodes(xml):
        for want in texts:
            hay = t or d
            if (want in hay) if contains else (hay == want):
                return want, cx, cy
    return None


def tap_text(xml, *texts, contains=True):
    hit = find_text(xml, *texts, contains=contains)
    if hit:
        want, x, y = hit
        ui_tap(x, y)
        return want
    return None


def tap_id(xml, *ids):
    for t, d, rid, cx, cy, w, h in nodes(xml):
        if not rid:
            continue
        for want in ids:
            if want in rid:
                ui_tap(cx, cy)
                return want
    return None


def screenshot(name):
    try:
        p = os.path.join(OUT, name)
        with open(p, 'wb') as f:
            f.write(subprocess.run(['adb', '-s', ADB_DEV, 'exec-out', 'screencap', '-p'],
                                   capture_output=True, timeout=30).stdout)
        return os.path.getsize(p)
    except Exception:
        return 0


def hook_events():
    """collect log 里 [FOCKEV] 事件计数(证据进度)。"""
    n = {'h1': 0, 'h2': 0, 'h3': 0, 'h4': 0, 'setup': 0}
    try:
        txt = open(COLLECT, 'r', errors='replace').read()
        for k in n:
            n[k] = len(re.findall(r'"ev": *"%s"' % k, txt))
    except Exception:
        pass
    return n


def am_start():
    """确定性拉起(主 Launcher activity)。r4 实证: monkey 复活会随机解析 LAUNCHER 类别里的
    非活动组件(logcat: Start proc …{com.qq.reader/com.qq.reader.TypeContext})→秒崩死循环。"""
    sh('am', 'start', '-n', '%s/%s' % (APP, 'com.qq.reader.activity.DefaultAliasActivity'), timeout=20)


def keep_alive():
    ensure_frida()
    if not pidof():
        L('[WD] App死→am start复活')
        am_start()
        time.sleep(12)


# ═══ Phase A: 等 pid + 弹窗处理(frida 已 spawn App) ═══
PRIVACY_MARK = '欢迎使用QQ阅读'


def phase_waitpid():
    L('═══ Phase A: 等 App pid(frida spawn, 冷启动>80s) + 弹窗处理 ═══')
    pid = None
    i = 0
    for i in range(60):
        pid = pidof()
        if pid:
            break
        time.sleep(5)
    L('[A] pid=%s (等了%d轮) fg=%s' % (pid, i, foreground()[:90]))
    VERDICT['phases']['A_pid'] = str(pid)
    if not pid:
        L('[A] ★pid 5min 未出现 — spawn 可能被壳杀')
        VERDICT['phases']['A_spawn'] = 'PID_TIMEOUT'

    dismissed = []
    quiet_rounds = 0
    main_seen = False
    for rnd in range(40):
        xml = dump_ui('consent%d' % rnd)
        if rnd % 3 == 0:
            screenshot('shot_consent_%02d.png' % rnd)
        if not xml:
            time.sleep(8)
            continue
        ns = nodes(xml)
        texts = [t for t, d, *_ in ns if t][:25]
        if rnd % 4 == 0:
            L('[A] 弹窗轮%d 可见文本: %s' % (rnd, json.dumps(texts, ensure_ascii=False)[:400]))
        hit = None
        for t, d, rid, cx, cy, w, h in ns:
            hay = (t or d).strip()
            if not hay:
                continue
            if any(b in hay for b in LOGIN_BLACK):
                continue
            for okw in CONSENT_OK:
                if hay == okw or (len(okw) <= 3 and okw in hay and len(hay) <= 8):
                    hit = (hay, cx, cy)
                    break
            if hit:
                break
        if hit:
            L('[A] 弹窗轮%d 点[%s] @(%d,%d)' % (rnd, hit[0], hit[1], hit[2]))
            ui_tap(hit[1], hit[2])
            dismissed.append(hit[0])
            quiet_rounds = 0
            time.sleep(8)
            continue
        fg = foreground()
        if PRIVACY_MARK in (xml or '') or '隐私政策' in (xml or '')[:3000]:
            quiet_rounds = 0
            time.sleep(6)
            continue
        if not pidof():
            L('[A] 弹窗轮%d App死→am start复活' % rnd)
            am_start()
            time.sleep(12)
            continue
        main_hint = any(k in (t or d) for t, d, *_ in ns for k in ('书城', '书架', '搜索', '排行', '免费', '限免'))
        if main_hint:
            main_seen = True
            L('[A] ✓主界面已到(轮%d) fg=%s' % (rnd, fg[:80]))
            break
        quiet_rounds += 1
        if quiet_rounds >= 6:
            L('[A] 6轮无弹窗无主界面特征 → 视为可继续')
            break
        time.sleep(7)
    VERDICT['consent_tapped'] = dismissed
    VERDICT['main_seen'] = main_seen
    L('[A] 弹窗处理完成: %s main=%s hook=%s' % (json.dumps(dismissed, ensure_ascii=False), main_seen, hook_events()))
    screenshot('shot_after_consent.png')
    return main_seen or pidof() is not None


# ═══ Phase A2: consent 后 attach frida ═══
# r2/r3 实证: attach 于 app init 期 → +23~35s 被反frida扫描杀; r2 流量实证 /sk→addKeys 与
#   ChapBat→unlockData 都在阅读器启动(reader activity start)才触发 — attach 放在 consent 之后、
#   开书之前, 既躲过 init 扫描又盖住全部 DRM 事件窗。
# r4 实证: consent 后有"死循环窗"(app 反复死-复活数分钟才稳定) — A2 必须等一个存活≥20s 的稳定
#   pid 才 attach(死循环期里 attach=白挂); pid 消失>25s 就 am start 复活再等。
def _wait_stable_pid(timeout_s=240):
    """等一个存活≥20s 的稳定 pid; 期间 pid 消失超过 25s → am start 拉起。返回 pid 或 None。"""
    t0 = time.time()
    cand, cand_t = None, 0.0
    last_seen = time.time()
    while time.time() - t0 < timeout_s:
        pid = pidof()
        now = time.time()
        if pid:
            last_seen = now
            if cand == pid:
                if now - cand_t >= 20:
                    L('[A2] 稳定 pid=%s (存活%.0fs)' % (pid, now - cand_t))
                    return pid
            else:
                cand, cand_t = pid, now
                L('[A2] 新 pid=%s — 观察稳定性' % pid)
        else:
            cand = None
            if now - last_seen > 25:
                L('[A2] pid 消失>25s → am start 复活')
                am_start()
                last_seen = now
        time.sleep(2)
    return cand


def _spawn_frida_cli(pid):
    try:
        lf = open(COLLECT, 'a', buffering=1)
        lf.write('[DRIVER] attach frida pid=%s t=%s\n' % (pid, time.strftime('%H:%M:%S')))
        # stdin=PIPE 且不写不关 — 拉住 frida REPL 会话(driver 存活期间 hook 常驻)
        proc = subprocess.Popen(['frida', '-H', FRIDA_HOST, '-p', str(pid), '-l', HOOK],
                                stdout=lf, stderr=lf, stdin=subprocess.PIPE,
                                cwd=os.path.dirname(HOOK))
        _FRIDA_PROC.append(proc)
        return proc
    except Exception as e:
        L('[A2] ✗frida CLI 启动失败: %s' % str(e)[:150])
        VERDICT['phases']['A2'] = 'cli_fail: %s' % str(e)[:80]
        return None


def _frida_alive():
    return bool(_FRIDA_PROC and _FRIDA_PROC[-1].poll() is None)


def attach_frida():
    L('═══ Phase A2: consent 后 attach frida(init 扫描已裸跑通过; 等稳定 pid) ═══')
    pid = _wait_stable_pid()
    if not pid:
        L('[A2] ✗无稳定 pid, 无法 attach')
        VERDICT['phases']['A2'] = 'no_stable_pid'
        return False
    proc = _spawn_frida_cli(pid)
    if not proc:
        return False
    for i in range(90):
        time.sleep(1)
        try:
            txt = open(COLLECT, 'r', errors='replace').read()
        except Exception:
            txt = ''
        if 'FOCKHOOK_READY' in txt:
            L('[A2] ✓frida attach + hooks armed (等了%ds) pid=%s' % (i + 1, pid))
            VERDICT['phases']['A2'] = 'armed pid=%s +%ds' % (pid, i + 1)
            return True
        if proc.poll() is not None:
            L('[A2] ✗frida CLI 提前退出(rc=%s) — app可能又被杀' % proc.returncode)
            VERDICT['phases']['A2'] = 'cli_exit rc=%s' % proc.returncode
            return False
    L('[A2] ⚠90s 无 READY(脚本装载慢/Java VM 未起) — 继续驱动, 诚实记录')
    VERDICT['phases']['A2'] = 'ready_timeout'
    return False


def ensure_frida():
    """frida 会话死了但 app 活着 → 重挂一次(最多3次)。仅 A2 已 attach 过之后生效;
    app 也死则走 am start 复活(下一轮 keep_alive 再挂)。"""
    if not _FRIDA_PROC:
        return
    global _REATTACH_N
    if _frida_alive() or not pidof():
        return
    if _REATTACH_N >= 3:
        return
    _REATTACH_N += 1
    pid = pidof()
    L('[WD] frida 会话已死而 app(pid=%s)活着 → 重挂#%d' % (pid, _REATTACH_N))
    _spawn_frida_cli(pid)
    time.sleep(8)


_REATTACH_N = 0


def stop_frida():
    if not _FRIDA_PROC:
        return
    proc = _FRIDA_PROC[0]
    if proc.poll() is None:
        try:
            proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass
        time.sleep(2)


# ═══ Phase B: 静置(密钥池窗) ═══
def phase_settle():
    L('═══ Phase B: 静置 25s (/sk→addKeys 注入窗) ═══')
    time.sleep(25)
    L('[B] hook=%s fg=%s' % (hook_events(), foreground()[:60]))
    VERDICT['phases']['B'] = str(hook_events())


# ═══ Phase C/D: deeplink 书详情 → 开始阅读 ═══
def deeplink(uri):
    r = sh('am', 'start', '-a', 'android.intent.action.VIEW', '-d', uri, APP, timeout=20)
    L('[DL] %s → %s' % (uri, (r.stdout or r.stderr).strip()[:120]))
    time.sleep(8)


def phase_book():
    L('═══ Phase C: 书详情 deeplink bid=%s ═══' % BID)
    keep_alive()
    deeplink('uniteqqreader://nativepage/book/detail?bid=%s' % BID)
    xml = dump_ui('book_detail')
    screenshot('shot_book_detail.png')
    ok = find_text(xml, '大生意人') is not None
    L('[C] 书详情=%s fg=%s' % (ok, foreground()[:80]))
    VERDICT['phases']['C'] = 'detail=%s' % ok

    L('═══ Phase D: 开始阅读 → 进第1章 ═══')
    hit = tap_text(xml, '开始阅读', '免费阅读', '立即阅读', '继续阅读', '免费读')
    time.sleep(12)
    fg = foreground()
    if 'ReaderPage' not in fg:
        if not hit:
            L('[D] 文本未命中 → 坐标兜底 (540,2200)')
            ui_tap(540, 2200)
            hit = 'coord(540,2200)'
        time.sleep(12)
        fg = foreground()
    if 'ReaderPage' not in fg:
        L('[D] 仍未进阅读页 → deeplink readepage?bid=%s' % BID)
        deeplink('uniteqqreader://nativepage/client/readepage?bid=%s' % BID)
        time.sleep(14)
        fg = foreground()
        hit = (hit or '') + '+readepage_dl'
    L('[D] 进阅读后 fg=%s hook=%s' % (fg[:100], hook_events()))
    dump_ui('reader_entered')
    screenshot('shot_reader_entered.png')
    VERDICT['phases']['D'] = 'tap=%s fg=%s' % (hit, fg[:80])
    return 'ReaderPage' in fg or 'reader' in fg.lower()


def dismiss_taste(xml):
    """r1 实证: "选择阅读口味"推荐浮层会挡在阅读页上吃掉翻页手势 — 见到就点掉。"""
    if xml and any(m in xml for m in TASTE_MARKS):
        got = tap_text(xml, '我都爱看', '进入书城', '知道了')
        if got:
            L('[TASTE] 点掉推荐浮层[%s]' % got)
            time.sleep(4)
            return True
    return False


# ═══ Phase E1: 第1章翻页 ═══
def phase_read_ch1():
    L('═══ Phase E1: 第1章 翻页×3 (解密触发窗) ═══')
    for i in range(3):
        keep_alive()
        dismiss_taste(dump_ui('ch1_p%d' % (i + 1)))
        ui_swipe(900, 1170, 150, 1170)
        time.sleep(6)
        screenshot('shot_ch1_page%d.png' % (i + 1))
        if i == 1:
            dump_ui('ch1_mid')
    L('[E1] 翻页完 hook=%s' % hook_events())
    VERDICT['phases']['E1'] = str(hook_events())


# ═══ Phase E2: 目录→第2章 翻页 ═══
# r1 教训: 点"目录"后落在登录页(QRLoginActivity) — 目录点进了登录入口。本轮: dump 一见登录词
#   立即 BACK 退出绝不点, 换菜单"下一章"或直接翻页兜底; 目标节点也按 LOGIN_BLACK 过滤。
def _on_login_page(xml):
    hits = [t for t, d, rid, cx, cy, w, h in nodes(xml) if any(b in (t or d) for b in LOGIN_BLACK)]
    return hits[:4]


def phase_read_ch2():
    L('═══ Phase E2: 菜单→目录→第2章 翻页×4 ═══')
    keep_alive()
    dismiss_taste(dump_ui('e2_start'))
    ui_tap(540, 1170)
    time.sleep(3)
    xml = dump_ui('reader_menu')
    screenshot('shot_reader_menu.png')
    logins = _on_login_page(xml)
    if logins:
        L('[E2] 菜单页有登录词%s → BACK 退出' % logins)
        ui_key(4)
        time.sleep(3)
    hit = tap_text(xml, '目录') or tap_id(xml, 'tvCatalog', 'btnCatalog')
    L('[E2] 点目录[%s]' % hit)
    target = None
    if hit:
        time.sleep(5)
        xml = dump_ui('chapter_list')
        screenshot('shot_chapter_list.png')
        logins = _on_login_page(xml)
        if logins:
            L('[E2] ✗目录页=登录页%s → BACK 退出, 不点任何项' % logins)
            ui_key(4)
            time.sleep(3)
            xml = ''
        else:
            ns = [(t, d, cx, cy) for t, d, rid, cx, cy, w, h in nodes(xml)
                  if not any(b in (t or d) for b in LOGIN_BLACK)]
            L('[E2] 目录前30项: %s' % json.dumps([t for t, *_ in ns][:30], ensure_ascii=False)[:600])
            for t, d, cx, cy in ns:
                hay = (t or d).strip()
                if re.match(r'^第\s*2\s*章', hay) or re.match(r'^0?2[\s\.、]', hay):
                    target = (cx, cy)
                    break
            if target is None:
                items = sorted(cy for t, d, cx, cy in ns if t and 250 < cy < 1600)
                if len(items) >= 2:
                    target = (540, items[1])
    if target is None:
        # 兜底1: 菜单里点"下一章"
        ui_tap(540, 1170)
        time.sleep(2)
        xml = dump_ui('nextch_menu')
        if _on_login_page(xml):
            L('[E2] 菜单又有登录词 → 不点, 走翻页兜底')
        else:
            hit2 = tap_text(xml, '下一章', '下一页') or tap_id(xml, 'tvNextChapter', 'btnNext')
            L('[E2] 下一章兜底: %s' % hit2)
            target = (0, 0) if hit2 else None
    if target is None:
        # 兜底2: 直接翻页(章末翻页通常自动进下一章)
        L('[E2] 翻页兜底(不依赖菜单)')
        target = (0, 0)
    if target:
        if target != (0, 0):
            L('[E2] 点第2章 @%s' % (target,))
            ui_tap(*target)
        time.sleep(10)
        for i in range(4):
            keep_alive()
            dismiss_taste(dump_ui('ch2_p%d' % (i + 1)))
            ui_swipe(900, 1170, 150, 1170)
            time.sleep(6)
            screenshot('shot_ch2_page%d.png' % (i + 1))
        dump_ui('ch2_after')
        VERDICT['phases']['E2'] = 'ok fg=%s hook=%s' % (foreground()[:60], hook_events())
    else:
        L('[E2] ✗没找到第2章入口')
        VERDICT['phases']['E2'] = 'no_entry'
    L('[E2] 完 hook=%s' % hook_events())


# ═══ Phase G: 收尾 ═══
def phase_teardown():
    L('═══ Phase G: 收尾(logcat + hook 计数 + verdict) ═══')
    try:
        r = sh('logcat', '-d', '-v', 'time', timeout=40)
        open(os.path.join(OUT, 'logcat_capture.txt'), 'w', errors='replace').write((r.stdout or '')[-400000:])
        key = [l for l in (r.stdout or '').splitlines()
               if re.search(r'qq\.reader|FATAL|AndroidRuntime|fock|yuewen|StubApp|libmsaoaidsec', l)]
        open(os.path.join(OUT, 'logcat_key_lines.txt'), 'w', errors='replace').write('\n'.join(key[:400]))
        L('[G] logcat: 全量%d行 关键%d行' % (len((r.stdout or '').splitlines()), len(key)))
    except Exception as e:
        L('[G] logcat 失败: %s' % str(e)[:80])
    VERDICT['hook_events_final'] = hook_events()
    VERDICT['foreground_final'] = foreground()[:120]
    VERDICT['ui_input_fails'] = dict(_UI_FAILS)
    VERDICT['frida_alive_at_teardown'] = bool(_FRIDA_PROC and _FRIDA_PROC[0].poll() is None)
    try:
        v = open(COLLECT, 'r', errors='replace').read()
        VERDICT['collect_log_bytes'] = len(v)
        VERDICT['collect_markers'] = {
            'script_loaded': v.count('[FOCK] script loaded'),
            'ready': v.count('[FOCKHOOK_READY]'),
            'exit_swallowed': v.count('"ev": "exit_swallowed"') + v.count('"ev":"exit_swallowed"'),
            'hook_fail': v.count('"ev": "hook_fail"') + v.count('"ev":"hook_fail"'),
        }
    except Exception:
        pass
    json.dump(VERDICT, open(os.path.join(OUT, 'driver_verdict.json'), 'w'), ensure_ascii=False, indent=1)
    L('════ VERDICT ════ %s' % json.dumps(VERDICT, ensure_ascii=False)[:800])


def run_phase(name, fn):
    try:
        return fn()
    except Exception as e:
        L('[%s] ★阶段异常被隔离: %s: %s (继续)' % (name, type(e).__name__, str(e)[:200]))
        VERDICT['phases'][name] = 'CRASH %s: %s' % (type(e).__name__, str(e)[:120])
        return None


def main():
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(DUMPS, exist_ok=True)
    L('=== qqread_fock_driver start (pid=%d bid=%s) ===' % (os.getpid(), BID))
    run_phase('A', phase_waitpid)
    run_phase('A2', attach_frida)
    run_phase('B', phase_settle)
    run_phase('CD', phase_book)
    run_phase('E1', phase_read_ch1)
    run_phase('E2', phase_read_ch2)
    stop_frida()
    run_phase('G', phase_teardown)
    L('=== done hook=%s ===' % hook_events())
    return 0


if __name__ == '__main__':
    sys.exit(main())
