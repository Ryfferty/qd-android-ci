#!/usr/bin/env python3
# qqread_fock_driver.py — QQ阅读 fock hook 采集的 UI 驱动 (子代理, 2026-10-19)
#
# 前置(runner 上由 workflow bash 完成):
#   redroid(localhost:5555) + com.qq.reader 已安装 + MITM 已接线(mitmdump -w /tmp/all.flows)
#   + fs-srv(frida-server, 127.0.0.1:14771 已 forward) + spawn 门控 frida 会话已在跑
#   (frida -H 127.0.0.1:14771 -f com.qq.reader -l hook_qqread_fock.js, 输出 → /tmp/fock_collect.log)
#   本 driver 只负责 UI: App 由 frida spawn 拉起(无需 am start), 只等 pid。
#
# 链路(全程不登录, 游客态是实验条件; 弹窗白名单点/黑名单绝不点同 qqread_driver.py):
#   Phase A 等 pid(frida spawn resume 后出现; 冷启动>80s, 最长等5min) → 隐私/权限弹窗点掉
#   Phase B 静置 ~25s(/sk 密钥池拉取 + addKeys 注入窗, hook 在旁记录)
#   Phase C deeplink 书详情(大生意人 bid=54425396)
#   Phase D 点 开始阅读 → 进阅读页(兜底 readepage deeplink)
#   Phase E1 第1章: 翻页×3 每页截图(unlockData/qdaf.search 触发窗)
#   Phase E2 菜单→目录→第2章: 翻页×4(第2章明文样本)
#   Phase G 收尾: logcat + hook 事件计数 + verdict
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

VERDICT = {'bid': BID, 'phases': {}}

CONSENT_OK = ['同意并继续', '同意并进入', '同意', '允许', '仅在使用中允许', '我知道了', '知道了',
              '稍后再说', '以后再说', '暂不', '跳过', '立即体验', '开始使用', '进入书城', '不了，谢谢']
LOGIN_BLACK = ['登录', '注册', '手机号', '一键开通', '购买', '支付', '开通会员', '立即充值', '充值']

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


def keep_alive():
    if not pidof():
        L('[WD] App死→monkey复活(注意: 复活进程不在 frida 钩内)')
        sh('monkey', '-p', APP, '-c', 'android.intent.category.LAUNCHER', '1', timeout=20)
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
            L('[A] 弹窗轮%d App死→monkey复活' % rnd)
            sh('monkey', '-p', APP, '-c', 'android.intent.category.LAUNCHER', '1', timeout=20)
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


# ═══ Phase E1: 第1章翻页 ═══
def phase_read_ch1():
    L('═══ Phase E1: 第1章 翻页×3 (解密触发窗) ═══')
    for i in range(3):
        keep_alive()
        ui_swipe(900, 1170, 150, 1170)
        time.sleep(6)
        screenshot('shot_ch1_page%d.png' % (i + 1))
        if i == 1:
            dump_ui('ch1_mid')
    L('[E1] 翻页完 hook=%s' % hook_events())
    VERDICT['phases']['E1'] = str(hook_events())


# ═══ Phase E2: 目录→第2章 翻页 ═══
def phase_read_ch2():
    L('═══ Phase E2: 菜单→目录→第2章 翻页×4 ═══')
    keep_alive()
    ui_tap(540, 1170)
    time.sleep(3)
    xml = dump_ui('reader_menu')
    screenshot('shot_reader_menu.png')
    hit = tap_text(xml, '目录') or tap_id(xml, 'tvCatalog', 'btnCatalog')
    L('[E2] 点目录[%s]' % hit)
    target = None
    if hit:
        time.sleep(5)
        xml = dump_ui('chapter_list')
        screenshot('shot_chapter_list.png')
        ns = [(t, d, cx, cy) for t, d, rid, cx, cy, w, h in nodes(xml)]
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
        # 兜底: 菜单里点"下一章"
        ui_tap(540, 1170)
        time.sleep(2)
        xml = dump_ui('nextch_menu')
        hit2 = tap_text(xml, '下一章', '下一页') or tap_id(xml, 'tvNextChapter', 'btnNext')
        L('[E2] 下一章兜底: %s' % hit2)
        target = (0, 0) if hit2 else None
    if target:
        if target != (0, 0):
            L('[E2] 点第2章 @%s' % (target,))
            ui_tap(*target)
        time.sleep(10)
        for i in range(4):
            keep_alive()
            ui_swipe(900, 1170, 150, 1170)
            time.sleep(6)
            screenshot('shot_ch2_page%d.png' % (i + 1))
        dump_ui('ch2_after')
        VERDICT['phases']['E2'] = 'ok hook=%s' % hook_events()
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
    run_phase('B', phase_settle)
    run_phase('CD', phase_book)
    run_phase('E1', phase_read_ch1)
    run_phase('E2', phase_read_ch2)
    run_phase('G', phase_teardown)
    L('=== done hook=%s ===' % hook_events())
    return 0


if __name__ == '__main__':
    sys.exit(main())
